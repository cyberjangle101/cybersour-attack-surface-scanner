package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- certificate helpers

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA"}, NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testCA{cert: c, key: key, pool: pool}
}

// leaf issues a certificate for the names. before/after are relative to now.
func (ca *testCA) leaf(t *testing.T, before, after time.Duration, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(before), NotAfter: time.Now().Add(after), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---- lab

type webLab struct {
	t          *testing.T
	h          *harness
	ca         *testCA
	routes     map[string]string // "ip:port" -> real address
	bucketBase string
}

// serve starts a server and routes ip:port to it.
func (l *webLab) serve(ip string, port int, handler http.Handler, cert *tls.Certificate, minV uint16) {
	srv := httptest.NewUnstartedServer(handler)
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: minV}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	l.t.Cleanup(srv.Close)
	l.routes[ip+":"+strconv.Itoa(port)] = strings.TrimPrefix(srv.URL, "https://")
	l.routes[ip+":"+strconv.Itoa(port)] = strings.TrimPrefix(l.routes[ip+":"+strconv.Itoa(port)], "http://")
}

func (l *webLab) host(name, ip string) {
	l.h.dns.add(l.t, fmt.Sprintf("%s. 60 IN A %s", name, ip))
	l.h.dns.addIP(l.t, ip, 64500, "203.0.113.0/24", "EXAMPLE-NET")
	l.h.src.addAnubis(name)
}

func newWebLab(t *testing.T) *webLab {
	h := newHarness(t)
	h.seedExample()
	l := &webLab{t: t, h: h, ca: newTestCA(t), routes: map[string]string{}}
	st, _ := h.store.LoadSettings()
	st.ActiveChecks, st.ActiveTimeoutSeconds, st.RemovalMisses = true, 3, 3
	st.InternetDBEnabled, st.RDAPEnabled = false, false
	h.saveSettings(st)
	l.setProber()
	return l
}

func (l *webLab) setProber() {
	st, _ := l.h.store.LoadSettings()
	cfg := st.Runtime("")
	p := NewProber(cfg.Active)
	p.allow = func(net.IP) bool { return true } // the lab is on loopback
	p.roots = l.ca.pool
	p.to = func(ip string, port int) string {
		if a, ok := l.routes[ip+":"+strconv.Itoa(port)]; ok {
			return a
		}
		return "127.0.0.1:1"
	}
	p.urls = bucketURLs{s3: func(b string) string { return l.bucketBase + "/s3/" + b + "/" }, gcs: func(b string) string { return l.bucketBase + "/gcs/" + b + "/" }}
	l.h.probe = p
}

func page(title, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", title, body)
	})
}

func (l *webLab) openKinds() map[string]int {
	out := map[string]int{}
	list, _ := l.h.store.ListFindings("example.test", "open")
	for _, f := range list {
		out[f.Kind]++
	}
	return out
}

func (l *webLab) findingFor(kind, hostPart string) *Finding {
	list, _ := l.h.store.ListFindings("example.test", "open")
	for i := range list {
		if list[i].Kind == kind && strings.Contains(list[i].Host+list[i].Detail, hostPart) {
			return &list[i]
		}
	}
	return nil
}

func TestActiveChecksFindProblems(t *testing.T) {
	l := newWebLab(t)
	good := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "www.example.test", "example.test")
	// www: healthy HTTPS, redirecting HTTP
	l.serve("203.0.113.10", 443, page("Home", "hello"), &good, tls.VersionTLS12)
	l.serve("203.0.113.10", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.test/", http.StatusMovedPermanently)
	}), nil, 0)

	// old: expired certificate
	l.host("old.example.test", "203.0.113.31")
	exp := l.ca.leaf(t, -72*time.Hour, -time.Hour, "old.example.test")
	l.serve("203.0.113.31", 443, page("Old", "x"), &exp, tls.VersionTLS12)
	// soon: expires in 5 days
	l.host("soon.example.test", "203.0.113.32")
	soon := l.ca.leaf(t, -time.Hour, 5*24*time.Hour, "soon.example.test")
	l.serve("203.0.113.32", 443, page("Soon", "x"), &soon, tls.VersionTLS12)
	// wrong: certificate for another name
	l.host("wrong.example.test", "203.0.113.33")
	wrong := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "other.example.net")
	l.serve("203.0.113.33", 443, page("Wrong", "x"), &wrong, tls.VersionTLS12)
	// self: self-signed
	l.host("self.example.test", "203.0.113.34")
	ss := selfSigned(t, "self.example.test")
	l.serve("203.0.113.34", 443, page("Self", "x"), &ss, tls.VersionTLS12)
	// legacy: accepts TLS 1.0
	l.host("legacy.example.test", "203.0.113.35")
	lg := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "legacy.example.test")
	l.serve("203.0.113.35", 443, page("Legacy", "x"), &lg, tls.VersionTLS10)

	// plain: HTTP and HTTPS both serve pages, HTTP does not redirect
	l.host("plain.example.test", "203.0.113.36")
	pl := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "plain.example.test")
	l.serve("203.0.113.36", 443, page("Plain", "x"), &pl, tls.VersionTLS12)
	l.serve("203.0.113.36", 80, page("Plain", "x"), nil, 0)

	// dev: default page, .git and .env exposed, directory listing in a sub-case below
	l.host("dev.example.test", "203.0.113.37")
	l.serve("203.0.113.37", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>")
		case "/.git/HEAD":
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n")
		default:
			http.NotFound(w, r)
		}
	}), nil, 0)
	// spa: answers 200 with the same page for every path: must produce no exposed-path findings
	l.host("spa.example.test", "203.0.113.38")
	l.serve("203.0.113.38", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>App</title></head><body>ref: refs/heads/main\nDB_PASSWORD=x</body></html>")
	}), nil, 0)
	// idx: directory listing
	l.host("idx.example.test", "203.0.113.39")
	l.serve("203.0.113.39", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>Index of /</title></head><body><h1>Index of /</h1></body></html>")
	}), nil, 0)

	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if tg2, _ := l.h.store.GetTarget(tg.ID); tg2.LastStatus != "ok" {
		t.Fatalf("scan: %s", tg2.LastError)
	}

	want := []struct{ kind, host string }{
		{"tls-expired", "old.example.test"}, {"tls-expiring", "soon.example.test"}, {"tls-hostname", "wrong.example.test"},
		{"tls-untrusted", "self.example.test"}, {"tls-legacy", "legacy.example.test"}, {"no-https-redirect", "plain.example.test"},
		{"default-page", "dev.example.test"}, {"exposed-path", "/.git/HEAD"}, {"exposed-path", "/.env"}, {"exposed-path", "idx.example.test"},
	}
	for _, w := range want {
		if l.findingFor(w.kind, w.host) == nil {
			t.Errorf("missing %s for %s; open: %v", w.kind, w.host, l.openKinds())
		}
	}
	if f := l.findingFor("tls-expiring", "soon.example.test"); f != nil && f.Severity != "high" {
		t.Errorf("5 days left should be high, got %s", f.Severity)
	}
	// things that are fine produce nothing
	all, _ := l.h.store.ListFindings("example.test", "open")
	for _, f := range all {
		for _, ok := range []string{"www.example.test", "spa.example.test"} {
			if f.Host == ok && (isWebKind(f.Kind)) {
				t.Errorf("false positive on %s: %s %s", ok, f.Kind, f.Detail)
			}
		}
	}
	// the env finding must not leak the secret values
	if f := l.findingFor("exposed-path", "/.env"); f != nil && (strings.Contains(f.Detail, "hunter2") || strings.Contains(f.Detail, "base64")) {
		t.Errorf("secret content copied into a finding: %s", f.Detail)
	}
	// inventory: web services are recorded
	ws, _ := l.h.store.ListWeb("example.test")
	have := map[string]WebService{}
	for _, w := range ws {
		have[fmt.Sprintf("%s:%d", w.Host, w.Port)] = w
	}
	if w := have["www.example.test:443"]; w.Status != 200 || w.Title != "Home" || w.TLSProblem != "" || w.TLSVersion == "" {
		t.Errorf("www web service: %+v", w)
	}
	if w := have["www.example.test:80"]; w.Status != 301 || !strings.HasPrefix(w.Location, "https://") {
		t.Errorf("www:80: %+v", w)
	}
	if len(l.h.eventsOfKind("web-service")) == 0 {
		t.Error("no web-service events")
	}
	// the asset browser and detail page know them
	if as, _, err := l.h.store.ListAssets("example.test", "web", ""); err != nil || len(as) < 8 {
		t.Errorf("web assets: %d %v", len(as), err)
	}

	// ---- fixing things resolves findings; an unreachable server does not
	renewed := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "old.example.test")
	l.serve("203.0.113.31", 443, page("Old", "x"), &renewed, tls.VersionTLS12)
	delete(l.routes, "203.0.113.37:80") // dev goes dark: cannot be checked
	l.h.scanN(tg.ID, 1)
	if l.findingFor("tls-expired", "old.example.test") != nil {
		t.Error("renewed certificate should resolve the finding")
	}
	if l.findingFor("default-page", "dev.example.test") == nil || l.findingFor("exposed-path", "/.env") == nil {
		t.Error("findings on an unreachable server must stay open, not be 'fixed' by silence")
	}
}

func isWebKind(k string) bool {
	switch k {
	case "tls-expired", "tls-expiring", "tls-hostname", "tls-untrusted", "tls-legacy", "default-page", "exposed-path", "no-https-redirect":
		return true
	}
	return false
}

func TestActiveChecksOffByDefaultAndOwnershipScoped(t *testing.T) {
	l := newWebLab(t)
	hits := 0
	l.host("www.example.test", "203.0.113.10")
	l.serve("203.0.113.10", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, "<title>Welcome to nginx!</title>")
	}), nil, 0)
	// a vendor-hosted name outside the expected networks
	l.h.dns.add(t, "api.example.test. 60 IN A 198.51.100.7")
	l.serve("198.51.100.7", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits += 1000; fmt.Fprint(w, "<title>vendor</title>") }), nil, 0)

	// off => no probes at all
	st, _ := l.h.store.LoadSettings()
	st.ActiveChecks = false
	l.h.saveSettings(st)
	l.setProber()
	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if hits != 0 {
		t.Fatalf("active checks ran while switched off (%d)", hits)
	}
	// on => only the declared networks
	st.ActiveChecks = true
	l.h.saveSettings(st)
	l.setProber()
	l.h.scanN(tg.ID, 1)
	if hits == 0 || hits >= 1000 {
		t.Fatalf("expected only the owned host to be probed, hits=%d", hits)
	}
	// opting in to foreign addresses probes the vendor too
	st.ActiveForeign = true
	l.h.saveSettings(st)
	l.setProber()
	l.h.scanN(tg.ID, 1)
	if hits < 1000 {
		t.Errorf("foreign probing was enabled but did not happen (%d)", hits)
	}
}

func TestProbeRefusesInternalAddresses(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700:4700::1111": true, "203.0.113.10": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false, "224.0.0.1": false,
		"64:ff9b::a00:1": false, "2002:a00:1::": false, "240.0.0.1": false, "198.18.0.1": false, "::ffff:10.0.0.1": false,
	} {
		if got := probeAllowed(net.ParseIP(ip)); got != want {
			t.Errorf("probeAllowed(%s) = %v, want %v", ip, got, want)
		}
	}
	// the real dialer, with the default policy, will not connect to a local server even if told to
	srv := httptest.NewServer(page("secret internal service", "x"))
	defer srv.Close()
	p := NewProber(ActiveCfg{Timeout: 2 * time.Second})
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	if wr := p.probeWeb(t.Context(), "evil.example.test", "127.0.0.1", n, "http"); wr.Reached || !strings.Contains(wr.Err, "not a public") {
		t.Errorf("connected to a loopback address: %+v", wr)
	}
	// a hostname that resolves internally cannot be reached through a redirect either: redirects are not followed
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, srv.URL, http.StatusFound) }))
	defer redir.Close()
	p.allow = func(net.IP) bool { return true }
	_, rport, _ := net.SplitHostPort(redir.Listener.Addr().String())
	rn, _ := strconv.Atoi(rport)
	wr := p.probeWeb(t.Context(), "x.example.test", "127.0.0.1", rn, "http")
	if wr.Status != 302 || wr.Title != "" {
		t.Errorf("redirect was followed: %+v", wr)
	}
}

func TestBucketChecks(t *testing.T) {
	l := newWebLab(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/s3/open-bkt/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><ListBucketResult><Name>open-bkt</Name></ListBucketResult>`)
	})
	mux.HandleFunc("/s3/gone-bkt/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
	})
	mux.HandleFunc("/s3/private-bkt/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `<Error><Code>AccessDenied</Code></Error>`)
	})
	mux.HandleFunc("/gcs/files.example.test/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
	})
	bs := httptest.NewServer(mux)
	defer bs.Close()
	l.bucketBase = bs.URL
	l.setProber()
	for h, target := range map[string]string{"open": "open-bkt.s3.amazonaws.com.", "gone": "gone-bkt.s3.eu-west-1.amazonaws.com.", "priv": "private-bkt.s3.amazonaws.com.", "files": "c.storage.googleapis.com."} {
		l.h.dns.add(t, fmt.Sprintf("%s.example.test. 60 IN CNAME %s", h, target))
		l.h.src.addAnubis(h + ".example.test")
	}
	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if l.findingFor("bucket-public", "open-bkt") == nil || l.findingFor("bucket-takeover", "gone-bkt") == nil || l.findingFor("bucket-takeover", "files.example.test") == nil {
		t.Fatalf("bucket findings missing: %v", l.openKinds())
	}
	if l.findingFor("bucket-public", "private-bkt") != nil || l.findingFor("bucket-takeover", "private-bkt") != nil {
		t.Error("a private bucket was reported")
	}
	// the bucket is made private => resolved
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	bs.Config.Handler = mux2
	l.h.scanN(tg.ID, 1)
	if l.findingFor("bucket-public", "open-bkt") != nil {
		t.Error("finding should resolve once the bucket is private")
	}
}

func TestBucketNameParsing(t *testing.T) {
	cases := map[string]string{
		"b.s3.amazonaws.com":                   "s3/b",
		"my.bucket.s3.us-east-1.amazonaws.com": "s3/my.bucket",
		"b.s3-website-us-east-1.amazonaws.com": "s3/b",
		"c.storage.googleapis.com":             "gcs/files.example.test",
		"example.github.io":                    "",
		"s3.amazonaws.com":                     "",
	}
	for cname, want := range cases {
		got := ""
		if b := bucketsFor("files.example.test", []string{cname}); len(b) > 0 {
			got = b[0].Provider + "/" + b[0].Name
		}
		if got != want {
			t.Errorf("%s -> %q, want %q", cname, got, want)
		}
	}
}

func TestScreenshotsUseVettedAddressOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the fake browser")
	}
	l := newWebLab(t)
	l.host("www.example.test", "203.0.113.10")
	l.serve("203.0.113.10", 80, page("Home", "hi"), nil, 0)
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nfor a in \"$@\"; do case \"$a\" in --screenshot=*) f=\"${a#--screenshot=}\";; esac; done\nprintf '\\211PNG\\r\\n\\032\\n' > \"$f\"\ni=0; while [ $i -lt 40 ]; do printf 'xxxxxxxxxx' >> \"$f\"; i=$((i+1)); done\n"
	fake := filepath.Join(dir, "fakechrome")
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	st, _ := l.h.store.LoadSettings()
	st.Screenshots, st.ChromePath, st.ScreenshotMax = true, fake, 5
	l.h.saveSettings(st)
	l.setProber()
	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	png, _, ok := l.h.store.GetShot("www.example.test", 80)
	if !ok || len(png) < 100 || string(png[1:4]) != "PNG" {
		t.Fatalf("no screenshot stored (ok=%v len=%d)", ok, len(png))
	}
	raw, _ := os.ReadFile(argsFile)
	args := string(raw)
	for _, want := range []string{"--host-resolver-rules=MAP www.example.test 203.0.113.10, MAP * ~NOTFOUND", "--headless", "http://www.example.test:80/"} {
		if !strings.Contains(args, want) {
			t.Errorf("browser arguments lack %q:\n%s", want, args)
		}
	}
}
