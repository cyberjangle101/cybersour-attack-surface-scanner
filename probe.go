package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Active checks talk to the monitored organisation's own servers. Everything here is opt-in,
// read-only (GET and TLS handshakes only) and refuses to connect to non-public addresses, so
// a DNS record that points at an internal address cannot turn the agent into a way into the
// network it runs on.

// ActiveCfg is the runtime form of the active-check settings.
type ActiveCfg struct {
	Enabled     bool
	Foreign     bool // also probe addresses outside the expected ownership
	Paths       bool // look for well-known exposed files
	Buckets     bool // check cloud storage that names point to
	Shots       bool
	MaxShots    int
	ChromePath  string
	MaxHosts    int
	Concurrency int
	Timeout     time.Duration
}

// nonRoutable lists ranges that isPublicIP does not cover and that must never be probed.
var nonRoutable = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
		"64:ff9b::/96", "2002::/16", "100::/64", "::/128"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// probeAllowed is the default address policy: public, routable unicast addresses only.
func probeAllowed(ip net.IP) bool {
	if ip == nil || !isPublicIP(ip) {
		return false
	}
	for _, n := range nonRoutable {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// Prober performs the probes.
type Prober struct {
	cfg   ActiveCfg
	allow func(net.IP) bool // address policy; tests widen it to reach local servers
	roots *x509.CertPool    // trust anchors (nil = the system's)
	urls  bucketURLs
	to    func(ip string, port int) string // test hook: where to really connect for an address (nil = the address itself)
}

// bucketURLs are the cloud-storage endpoints (overridden in tests).
type bucketURLs struct {
	s3  func(bucket string) string
	gcs func(bucket string) string
}

// NewProber creates a prober with the safe address policy.
func NewProber(cfg ActiveCfg) *Prober {
	return &Prober{cfg: cfg, allow: probeAllowed, urls: bucketURLs{
		s3:  func(b string) string { return "https://" + b + ".s3.amazonaws.com/" },
		gcs: func(b string) string { return "https://storage.googleapis.com/" + b + "/" },
	}}
}

var errBlockedAddr = errors.New("address is not a public, routable address")

// dialer connects only to addresses the policy accepts. The check runs on the address that is
// actually being connected to, after any DNS lookup, so rebinding tricks do not get around it.
func (p *Prober) dialer() *net.Dialer {
	return &net.Dialer{Timeout: p.cfg.Timeout, Control: func(_, address string, _ syscall.RawConn) error {
		h, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if !p.allow(net.ParseIP(h)) {
			return errBlockedAddr
		}
		return nil
	}}
}

// WebResult is what one probe of a web service found.
type WebResult struct {
	Host, IP   string
	Port       int
	Scheme     string
	Reached    bool // a protocol answer was received (so absence of problems is meaningful)
	Status     int
	Server     string
	Title      string
	Location   string
	HSTS       bool
	Powered    string
	TLS        *TLSInfo
	DefaultPg  string // name of the default page that is shown, if any
	Listing    bool   // directory listing on /
	Hits       []PathHit
	BodyHash   string
	Err        string
	TLSChecked bool
}

// URL returns the address of the service.
func (w *WebResult) URL() string {
	d := 80
	if w.Scheme == "https" {
		d = 443
	}
	if w.Port == d {
		return w.Scheme + "://" + w.Host + "/"
	}
	return fmt.Sprintf("%s://%s:%d/", w.Scheme, w.Host, w.Port)
}

// PathHit is a sensitive file or page that answered.
type PathHit struct {
	Path, Why, Severity string
}

// TLSInfo is what a TLS handshake showed.
type TLSInfo struct {
	Version     string
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Names       []string
	Problem     string // "", "expired", "hostname", "untrusted", "selfsigned", "invalid"
	ProblemText string
	DaysLeft    int
	Legacy      []string // protocol versions below TLS 1.2 that the server still accepts
	LegacyKnown bool     // the legacy check completed
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// handshake connects to ip:port and completes a TLS handshake offering the given versions.
func (p *Prober) handshake(ctx context.Context, host, ip string, port int, minV, maxV uint16) (*tls.Conn, error) {
	raw, err := p.dialer().DialContext(ctx, "tcp", p.addr(ip, port))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV} //nolint:gosec // the certificate is judged separately, below, so a bad one can be reported instead of failing the probe
	c := tls.Client(raw, cfg)
	_ = c.SetDeadline(time.Now().Add(p.cfg.Timeout))
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

// tlsInfo inspects the certificate and protocol support of a TLS service.
func (p *Prober) tlsInfo(ctx context.Context, host, ip string, port int) (*TLSInfo, error) {
	c, err := p.handshake(ctx, host, ip, port, tls.VersionTLS10, tls.VersionTLS13)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	st := c.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, errors.New("no certificate presented")
	}
	leaf := st.PeerCertificates[0]
	ti := &TLSInfo{Version: tlsVersionName(st.Version), Subject: leaf.Subject.CommonName, Issuer: leaf.Issuer.CommonName,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Names: leaf.DNSNames}
	if ti.Subject == "" && len(leaf.DNSNames) > 0 {
		ti.Subject = leaf.DNSNames[0]
	}
	if ti.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		ti.Issuer = leaf.Issuer.Organization[0]
	}
	ti.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: p.roots, CurrentTime: time.Now()})
	if verr != nil {
		ti.Problem, ti.ProblemText = classifyCertError(verr, leaf)
	}
	// Which old protocol versions does it still speak?
	ti.LegacyKnown = true
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		lc, err := p.handshake(ctx, host, ip, port, v, v)
		if err == nil {
			_ = lc.Close()
			ti.Legacy = append(ti.Legacy, tlsVersionName(v))
		}
	}
	return ti, nil
}

// classifyCertError turns a verification failure into a short code and sentence.
func classifyCertError(err error, leaf *x509.Certificate) (code, text string) {
	var inv x509.CertificateInvalidError
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		if time.Now().Before(leaf.NotBefore) {
			return "invalid", "the certificate is not valid yet"
		}
		return "expired", "the certificate has expired"
	case errors.As(err, &hn):
		return "hostname", "the certificate does not cover this host name (it is for " + strings.Join(leaf.DNSNames, ", ") + ")"
	case errors.As(err, &ua):
		if leaf.Issuer.String() == leaf.Subject.String() && leaf.CheckSignatureFrom(leaf) == nil {
			return "selfsigned", "the certificate is self-signed, so browsers do not trust it"
		}
		return "untrusted", "the certificate was issued by an authority browsers do not trust, or the chain is incomplete"
	}
	return "invalid", "the certificate is not valid: " + err.Error()
}

// fetched is a small HTTP answer.
type fetched struct {
	Status int
	Header http.Header
	Body   []byte
}

const probeBody = 64 << 10

// fetch performs one GET against ip:port, presenting host as the server name. Redirects are not followed.
func (p *Prober) fetch(ctx context.Context, scheme, host, ip string, port int, path string) (*fetched, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return p.dialer().DialContext(ctx, "tcp", p.addr(ip, port))
		},
		TLSClientConfig:       &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec // see handshake
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   p.cfg.Timeout,
		ResponseHeaderTimeout: p.cfg.Timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: p.cfg.Timeout + 2*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := url.URL{Scheme: scheme, Host: host, Path: path}
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		u.Host = net.JoinHostPort(host, fmt.Sprint(port))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "easm-agent/"+version+" (+defensive attack-surface monitoring)")
	req.Header.Set("Accept", "*/*")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBody))
	return &fetched{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	if len(t) > 120 {
		t = t[:120]
	}
	return strings.ToValidUTF8(t, "")
}

// defaultPages are server "it works" pages that mean a service was installed and never set up.
var defaultPages = []struct{ Name, Needle string }{
	{"nginx welcome page", "Welcome to nginx!"},
	{"Apache default page", "Apache2 Ubuntu Default Page"},
	{"Apache default page", "Apache2 Debian Default Page"},
	{"Apache test page", "Test Page for the Apache HTTP Server"},
	{"Apache test page", "Test Page for the HTTP Server on"},
	{"IIS default page", "IIS Windows Server"},
	{"IIS default page", "Welcome to Internet Information Services"},
	{"Tomcat default page", "If you're seeing this, you've successfully installed Tomcat"},
	{"Apache \"It works!\" page", "<html><body><h1>It works!</h1>"},
	{"Plesk default page", "Web Server's Default Page"},
	{"cPanel default page", "Default Web Site Page"},
	{"LiteSpeed default page", "Congratulations! Your website is up and running"},
	{"Caddy default page", "Caddy web server"},
	{"Jenkins sign-in", "Sign in [Jenkins]"},
}

func detectDefaultPage(title string, body []byte) string {
	b := string(body)
	for _, d := range defaultPages {
		if d.Name == "Jenkins sign-in" || d.Name == "Caddy default page" {
			continue // not a default page: a real application, or too ambiguous
		}
		if strings.Contains(b, d.Needle) || strings.Contains(title, d.Needle) {
			return d.Name
		}
	}
	return ""
}

// sensitivePaths are files that should never be public. Each has a content check so a
// catch-all page that answers 200 for everything does not produce a finding.
var sensitivePaths = []struct {
	Path, Why, Severity string
	Test                func(b []byte, h http.Header) bool
}{
	{"/.git/HEAD", "a Git repository's HEAD file is readable, so source code and secrets can be downloaded", "high",
		func(b []byte, _ http.Header) bool {
			return strings.HasPrefix(strings.TrimSpace(string(b)), "ref: refs/")
		}},
	{"/.git/config", "a Git repository's configuration is readable, so source code and secrets can be downloaded", "high",
		func(b []byte, _ http.Header) bool {
			return strings.Contains(string(b), "[core]") && strings.Contains(string(b), "repositoryformatversion")
		}},
	{"/.env", "an environment file with settings and likely passwords or keys is readable", "high",
		func(b []byte, h http.Header) bool {
			return !strings.Contains(strings.ToLower(h.Get("Content-Type")), "html") && envFileRe.Match(b)
		}},
	{"/wp-config.php.bak", "a backup of the WordPress configuration, with database credentials, is readable", "high",
		func(b []byte, _ http.Header) bool { return strings.Contains(string(b), "DB_PASSWORD") }},
	{"/actuator/env", "a Spring Boot management endpoint shows the application's environment and configuration", "high",
		func(b []byte, _ http.Header) bool { return strings.Contains(string(b), `"propertySources"`) }},
	{"/server-status", "the Apache status page is public and shows requests and clients", "medium",
		func(b []byte, _ http.Header) bool { return strings.Contains(string(b), "Apache Server Status") }},
	{"/phpinfo.php", "a PHP information page is public and shows the server's configuration", "medium",
		func(b []byte, _ http.Header) bool {
			return strings.Contains(string(b), "phpinfo()") || strings.Contains(string(b), "PHP Version")
		}},
	{"/.DS_Store", "a macOS folder index file is public and lists file names on the server", "low",
		func(b []byte, _ http.Header) bool { return len(b) > 8 && string(b[4:8]) == "Bud1" }},
}

var envFileRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=.*$`)

// probeWeb examines one web service.
func (p *Prober) probeWeb(ctx context.Context, host, ip string, port int, scheme string) *WebResult {
	wr := &WebResult{Host: host, IP: ip, Port: port, Scheme: scheme}
	if scheme == "https" {
		ti, err := p.tlsInfo(ctx, host, ip, port)
		if err != nil {
			wr.Err = "TLS: " + err.Error()
			return wr
		}
		wr.TLS, wr.TLSChecked = ti, true
	}
	root, err := p.fetch(ctx, scheme, host, ip, port, "/")
	if err != nil {
		wr.Err = err.Error()
		return wr
	}
	wr.Reached = true
	wr.Status = root.Status
	wr.Server = truncate(root.Header.Get("Server"), 80)
	wr.Powered = truncate(root.Header.Get("X-Powered-By"), 80)
	wr.Location = truncate(root.Header.Get("Location"), 200)
	wr.HSTS = root.Header.Get("Strict-Transport-Security") != ""
	wr.Title = pageTitle(root.Body)
	wr.DefaultPg = detectDefaultPage(wr.Title, root.Body)
	wr.Listing = strings.Contains(string(root.Body), "<title>Index of /") || strings.Contains(string(root.Body), "<h1>Index of /")
	if wr.Listing {
		wr.Hits = append(wr.Hits, PathHit{Path: "/", Why: "directory listing is switched on, so anyone can browse and download the files in this folder", Severity: "medium"})
	}
	sum := sha256.Sum256(root.Body)
	wr.BodyHash = fmt.Sprintf("%x", sum[:8])
	if p.cfg.Paths {
		for _, sp := range sensitivePaths {
			if ctx.Err() != nil {
				break
			}
			r, err := p.fetch(ctx, scheme, host, ip, port, sp.Path)
			if err != nil || r.Status != http.StatusOK {
				continue
			}
			if s := sha256.Sum256(r.Body); fmt.Sprintf("%x", s[:8]) == wr.BodyHash {
				continue // same page as "/": a catch-all, not the file
			}
			if sp.Test(r.Body, r.Header) {
				wr.Hits = append(wr.Hits, PathHit{Path: sp.Path, Why: sp.Why, Severity: sp.Severity})
			}
		}
	}
	return wr
}

// ---------------------------------------------------------------- cloud storage

// BucketResult is what a storage check found.
type BucketResult struct {
	Provider, Name string
	Public         bool // anyone can list the contents
	Missing        bool // the bucket does not exist: anyone could create it and serve content under this name
	Checked        bool // the provider answered, so a clean result means something
}

var s3HostRe = regexp.MustCompile(`^(.+?)\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com\.?$`)

// bucketsFor derives the storage buckets that DNS names point to.
func bucketsFor(host string, cnames []string) []struct{ Provider, Name string } {
	var out []struct{ Provider, Name string }
	seen := map[string]bool{}
	add := func(p, n string) {
		if k := p + "/" + n; n != "" && !seen[k] {
			seen[k] = true
			out = append(out, struct{ Provider, Name string }{p, n})
		}
	}
	for _, c := range cnames {
		c = strings.ToLower(strings.TrimSuffix(c, "."))
		if m := s3HostRe.FindStringSubmatch(c + "."); m != nil {
			add("s3", m[1])
		}
		if c == "c.storage.googleapis.com" {
			add("gcs", strings.ToLower(host))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider+out[i].Name < out[j].Provider+out[j].Name })
	return out
}

// checkBucket asks the provider about a bucket without credentials.
func (p *Prober) checkBucket(ctx context.Context, provider, name string) BucketResult {
	br := BucketResult{Provider: provider, Name: name}
	var u string
	switch provider {
	case "s3":
		u = p.urls.s3(name)
	case "gcs":
		u = p.urls.gcs(name)
	default:
		return br
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return br
	}
	req.Header.Set("User-Agent", "easm-agent/"+version+" (+defensive attack-surface monitoring)")
	cl := &http.Client{Timeout: p.cfg.Timeout + 2*time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return p.dialer().DialContext(ctx, n, a)
	}, TLSClientConfig: &tls.Config{RootCAs: p.roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return br
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBody))
	b := string(body)
	switch {
	case resp.StatusCode == 200 && strings.Contains(b, "<ListBucketResult"):
		br.Checked, br.Public = true, true
	case resp.StatusCode == 404 && strings.Contains(b, "NoSuchBucket"):
		br.Checked, br.Missing = true, true
	case resp.StatusCode == 403 || resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 307:
		br.Checked = true // exists, and is not listable
	}
	return br
}

// addr is where to connect for an address and port.
func (p *Prober) addr(ip string, port int) string {
	if p.to != nil {
		return p.to(ip, port)
	}
	return net.JoinHostPort(ip, fmt.Sprint(port))
}
