package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func sigNamed(t *testing.T, name string) portalSig {
	t.Helper()
	for _, s := range portalSigs {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no portal signature %q", name)
	return portalSig{}
}

func TestPortalSignatures(t *testing.T) {
	html := hdr("Content-Type", "text/html")
	cases := []struct {
		sig    string
		status int
		h      http.Header
		body   string
		want   bool
	}{
		{"Fortinet FortiGate SSL-VPN", 200, html, `<html><script>var fgt_lang = {}</script>`, true},
		{"Palo Alto GlobalProtect", 200, html, `<title>GlobalProtect Portal</title>`, true},
		{"Ivanti / Pulse Connect Secure", 200, html, `<title>Ivanti Connect Secure</title>`, true},
		{"Citrix Gateway (NetScaler)", 200, html, `<title>Citrix Gateway</title>`, true},
		{"Cisco ASA / AnyConnect", 200, html, `<form action="/+webvpn+/index.html">`, true},
		{"Microsoft RD Web Access", 200, html, `<title>RD Web Access</title>`, true},
		{"Outlook on the web (Exchange)", 200, html, `<link href="/owa/auth/15.2/themes/resources/logon.css">`, true},
		{"phpMyAdmin", 200, html, `<title>phpMyAdmin</title>`, true},
		{"Apache Tomcat Manager", 401, hdr("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`), ``, true},
		{"Jenkins", 403, hdr("X-Jenkins", "2.440"), ``, false}, // only 200/401 answers count
		{"Jenkins", 200, hdr("X-Jenkins", "2.440"), ``, true},
		{"WordPress login", 200, html, `<input type="submit" name="wp-submit">`, true},
		{"Grafana", 200, html, `<title>Grafana</title>`, true},
		{"Kibana", 200, hdr("kbn-name", "kibana"), ``, true},
		// Not the product: a 404, an empty page, someone else's wording.
		{"phpMyAdmin", 404, html, `<title>phpMyAdmin</title>`, false},
		{"Fortinet FortiGate SSL-VPN", 200, html, `<title>Welcome</title>`, false},
		{"Apache Tomcat Manager", 401, hdr("WWW-Authenticate", `Basic realm="Restricted"`), ``, false},
	}
	for _, c := range cases {
		if got := matchPortal(sigNamed(t, c.sig), c.status, c.h, []byte(c.body)); got != c.want {
			t.Errorf("%s on %d %q: got %v, want %v", c.sig, c.status, c.body, got, c.want)
		}
	}
}

// The home page is matched only by title-level signatures and product headers: a site
// that mentions a product in its text is not that product's sign-in page.
func TestPortalsOnHomePage(t *testing.T) {
	html := hdr("Content-Type", "text/html")
	if hits := portalsOnPage(200, html, []byte(`<title>Grafana</title>`)); len(hits) != 1 || hits[0].Name != "Grafana" || hits[0].Path != "/" {
		t.Errorf("Grafana home page: %+v", hits)
	}
	if hits := portalsOnPage(200, hdr("X-Jenkins", "2.4"), []byte(`<title>Dashboard</title>`)); len(hits) != 1 || hits[0].Name != "Jenkins" {
		t.Errorf("Jenkins by header: %+v", hits)
	}
	blog := `<title>Acme blog</title><p>We moved to Drupal. Connect with AnyConnect or our FortiGate VPN, then open your Jupyter Notebook. Use wp-submit.</p>`
	if hits := portalsOnPage(200, html, []byte(blog)); len(hits) != 0 {
		t.Errorf("a page that mentions products is not a portal: %+v", hits)
	}
	if s := portalSlug("Ivanti / Pulse Connect Secure"); s != "ivanti-pulse-connect-secure" {
		t.Errorf("portalSlug = %q", s)
	}
}

func TestSensitiveFileTests(t *testing.T) {
	text, htm := hdr("Content-Type", "text/plain"), hdr("Content-Type", "text/html")
	check := func(path string) func([]byte, http.Header) bool {
		for _, p := range sensitivePaths {
			if p.Path == path {
				return p.Test
			}
		}
		t.Fatalf("no sensitive path %s", path)
		return nil
	}
	cases := []struct {
		path string
		h    http.Header
		body string
		want bool
	}{
		{"/.svn/wc.db", text, "SQLite format 3\x00rest", true},
		{"/.svn/wc.db", text, "<html>not found</html>", false},
		{"/.hg/requires", text, "dotencode\nfncache\nrevlogv1\nstore\n", true},
		{"/.htpasswd", text, "admin:$apr1$xyz$abcdefghijklmnop\n", true},
		{"/.htpasswd", htm, "admin:$apr1$xyz$abcdefghijklmnop\n", false},
		{"/.htpasswd", text, "nothing here", false},
		{"/.aws/credentials", text, "[default]\naws_access_key_id = X\n", true},
		{"/.npmrc", text, "//registry.npmjs.org/:_authToken=x\n", true},
		{"/sftp-config.json", hdr("Content-Type", "application/json"), `{"host": "h", "password": "p"}`, true},
		{"/web.config", hdr("Content-Type", "application/xml"), `<?xml version="1.0"?><configuration></configuration>`, true},
		{"/web.config", htm, `<configuration>`, false},
		{"/docker-compose.yml", text, "services:\n  db:\n    image: postgres\n", true},
		{"/backup.sql", text, "-- dump\nCREATE TABLE `users` (id int);\n", true},
		{"/backup.sql", htm, "CREATE TABLE users", false},
		{"/elmah.axd", htm, "<h1>Error Log for /LM/W3SVC/1</h1>", true},
		{"/trace.axd", htm, "<h1>Application Trace</h1>", true},
		{"/debug/pprof/", htm, "Types of profiles available:", true},
		{"/swagger.json", hdr("Content-Type", "application/json"), `{"swagger":"2.0","paths":{}}`, true},
		{"/swagger.json", htm, `{"swagger":"2.0","paths":{}}`, false},
		{"/crossdomain.xml", text, `<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`, true},
		{"/crossdomain.xml", text, `<allow-access-from domain="www.example.test"/>`, false},
	}
	for _, c := range cases {
		if got := check(c.path)([]byte(c.body), c.h); got != c.want {
			t.Errorf("%s with %q: got %v, want %v", c.path, c.body, got, c.want)
		}
	}
}

func TestWeakCertificates(t *testing.T) {
	small := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	key, sig := weakCert(&x509.Certificate{PublicKey: small, SignatureAlgorithm: x509.SHA1WithRSA})
	if key != "a 1024-bit RSA key" || sig != "SHA-1" {
		t.Errorf("weak certificate: %q %q", key, sig)
	}
	big2048 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	if key, sig := weakCert(&x509.Certificate{PublicKey: big2048, SignatureAlgorithm: x509.SHA256WithRSA}); key != "" || sig != "" {
		t.Errorf("a sound certificate was judged weak: %q %q", key, sig)
	}
}

// A scan raises the new web findings, and a catch-all site raises none of them.
func TestNewWebRules(t *testing.T) {
	l := newWebLab(t)
	www := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "www.example.test", "example.test")
	l.serve("203.0.113.10", 443, page("Home", "hello"), &www, tls.VersionTLS12) // no HSTS, no security.txt

	// vpn: a FortiGate whose home page redirects to the login, plus a WordPress login and a password file
	l.host("vpn.example.test", "203.0.113.41")
	l.serve("203.0.113.41", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/remote/login", http.StatusFound)
		case "/remote/login":
			_, _ = fmt.Fprint(w, `<html><head><title>Please Login</title><script>var fgt_lang={}</script></head></html>`)
		case "/wp-login.php":
			_, _ = fmt.Fprint(w, `<form><input name="wp-submit"></form>`)
		case "/manager/html":
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/.htpasswd":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "admin:$apr1$abc$0123456789abcdef\n")
		default:
			http.NotFound(w, r)
		}
	}), nil, 0)
	// ops: Grafana on its home page
	l.host("ops.example.test", "203.0.113.42")
	l.serve("203.0.113.42", 80, page("Grafana", `<div class="grafana-app"></div>`), nil, 0)
	// catch: answers every path with the same page full of product words
	l.host("catch.example.test", "203.0.113.43")
	l.serve("203.0.113.43", 80, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<title>Shop</title> fgt_lang wp-submit GlobalProtect Portal admin:$apr1$x$y`)
	}), nil, 0)

	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if tg2, _ := l.h.store.GetTarget(tg.ID); tg2.LastStatus != "ok" {
		t.Fatalf("scan: %s", tg2.LastError)
	}
	for _, w := range []struct{ kind, part, sev string }{
		{"login-portal", "Fortinet FortiGate SSL-VPN", "medium"},
		{"login-portal", "WordPress login", "low"},
		{"login-portal", "Apache Tomcat Manager", "high"},
		{"login-portal", "Grafana", "medium"},
		{"exposed-path", "/.htpasswd", "high"},
		{"hsts-missing", "www.example.test", "low"},
		{"no-security-txt", "www.example.test", "low"},
	} {
		f := l.findingFor(w.kind, w.part)
		if f == nil {
			t.Errorf("missing %s for %s; open: %v", w.kind, w.part, l.openKinds())
			continue
		}
		if f.Severity != w.sev {
			t.Errorf("%s %s: severity %s, want %s", w.kind, w.part, f.Severity, w.sev)
		}
	}
	all, _ := l.h.store.ListFindings("example.test", "open")
	for _, f := range all {
		if f.Host == "catch.example.test" && (f.Kind == "login-portal" || f.Kind == "exposed-path") {
			t.Errorf("false positive on a catch-all site: %s %s", f.Kind, f.Detail)
		}
		if f.Kind == "exposed-path" && strings.Contains(f.Detail, "0123456789abcdef") {
			t.Errorf("secret content copied into a finding: %s", f.Detail)
		}
	}
	// Fixing the problem resolves the finding on the next scan.
	l.serve("203.0.113.41", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }), nil, 0)
	l.h.scanN(tg.ID, 1)
	if f := l.findingFor("login-portal", "Fortinet"); f != nil {
		t.Errorf("a portal that is gone must resolve: %s", f.Detail)
	}
}
