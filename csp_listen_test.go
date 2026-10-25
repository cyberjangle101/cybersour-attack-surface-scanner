package main

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestContentSecurityPolicyIsComplete checks every directive the policy must carry and
// that nothing weakens it.
func TestContentSecurityPolicyIsComplete(t *testing.T) {
	e := newWebEnv(t)
	_, _, r := e.browser().get("/login")
	csp := r.Header.Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "font-src 'none'",
		"connect-src 'self'", "media-src 'none'", "object-src 'none'", "frame-src 'none'", "child-src 'none'", "worker-src 'none'",
		"manifest-src 'none'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'", "require-trusted-types-for 'script'",
		"report-uri /csp-report", "report-to csp"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP lacks %q: %s", d, csp)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes", "*", "http:", "https:"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP must not contain %q: %s", bad, csp)
		}
	}
	if strings.Contains(csp, "upgrade-insecure-requests") {
		t.Error("upgrade-insecure-requests must only be sent over TLS")
	}
	if contentSecurityPolicy(true) == csp || !strings.Contains(contentSecurityPolicy(true), "upgrade-insecure-requests") {
		t.Error("TLS policy must add upgrade-insecure-requests")
	}
	for _, h := range []string{"Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy", "Reporting-Endpoints"} {
		if r.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	// report-to names the endpoint group; it must point at the same handler as report-uri
	if got := r.Header.Get("Reporting-Endpoints"); got != `csp="/csp-report"` {
		t.Errorf("Reporting-Endpoints = %q", got)
	}
}

// TestTemplatesNeedNoRelaxedPolicy proves the pages work under the strict policy:
// no inline script, inline style, event-handler attribute or javascript: link.
func TestTemplatesNeedNoRelaxedPolicy(t *testing.T) {
	files, _ := filepath.Glob("web/templates/*.html")
	bad := regexp.MustCompile(`(?is)<script\b[^>]*>|<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:`)
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		for _, m := range bad.FindAllString(string(raw), -1) {
			if strings.HasPrefix(strings.ToLower(m), "<script") && strings.Contains(m, "src=") {
				continue
			}
			t.Errorf("%s: %q would be blocked by the Content Security Policy", f, m)
		}
	}
}

// TestCSPReportEndpoint checks browsers can report violations without signing in, and
// that a huge or hostile report is harmless.
func TestCSPReportEndpoint(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	req, _ := http.NewRequest("POST", b.base+"/csp-report", strings.NewReader(`{"csp-report":{"blocked-uri":"inline"}}`+strings.Repeat("A", 1<<20)+"\x1b[31m"))
	req.Header.Set("Content-Type", "application/csp-report")
	if code, _, _ := b.do(req); code != 204 {
		t.Errorf("csp-report = %d, want 204", code)
	}
	// browsers using report-to send the Reporting API format
	req, _ = http.NewRequest("POST", b.base+"/csp-report", strings.NewReader(`[{"type":"csp-violation","body":{"blockedURL":"inline"}}]`))
	req.Header.Set("Content-Type", "application/reports+json")
	if code, _, _ := b.do(req); code != 204 {
		t.Errorf("reports+json = %d, want 204", code)
	}
	if code, _, _ := b.get("/csp-report"); code != 405 {
		t.Errorf("GET /csp-report = %d, want 405", code)
	}
}

func TestResolveListen(t *testing.T) {
	for _, c := range []struct{ host, port, want string }{
		{"127.0.0.1", "8080", "127.0.0.1:8080"}, {"*", "443", "0.0.0.0:443"}, {"", "9000", "0.0.0.0:9000"}, {"all", "9000", "0.0.0.0:9000"},
		{"localhost", "8443", "127.0.0.1:8443"}, {"::1", "8443", "[::1]:8443"}, {" 10.1.2.3 ", " 8443 ", "10.1.2.3:8443"},
	} {
		got, err := ResolveListen(c.host, c.port)
		if err != nil || got != c.want {
			t.Errorf("ResolveListen(%q,%q) = %q, %v; want %q", c.host, c.port, got, err, c.want)
		}
	}
	for _, c := range [][2]string{{"127.0.0.1", "0"}, {"127.0.0.1", "65536"}, {"127.0.0.1", "abc"}, {"127.0.0.1", ""}, {"no-such-interface0", "80"}, {"evil.example.com", "80"}, {"1.2.3.4; rm", "80"}} {
		if got, err := ResolveListen(c[0], c[1]); err == nil {
			t.Errorf("ResolveListen(%q,%q) = %q, want an error", c[0], c[1], got)
		}
	}
	if ifs, _ := net.Interfaces(); len(ifs) > 0 {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagLoopback != 0 {
				if got, err := ResolveListen(ifc.Name, "8080"); err != nil || !strings.HasSuffix(got, ":8080") {
					t.Errorf("interface name %q: %q %v", ifc.Name, got, err)
				}
			}
		}
	}
}

func TestAllowedHostsFollowTheListenAddress(t *testing.T) {
	if m := buildAllowedHosts("127.0.0.1:8080", nil); !m["localhost"] || !m["127.0.0.1"] {
		t.Error("loopback must allow localhost names")
	}
	if buildAllowedHosts("0.0.0.0:8080", nil) != nil {
		t.Error("a public bind has no Host restriction unless allowed_hosts is set")
	}
	if m := buildAllowedHosts("0.0.0.0:8080", []string{"EASM.example"}); !m["easm.example"] {
		t.Error("allowed_hosts must be honoured")
	}
}

type fakeListen struct {
	addr   string
	locked bool
	fail   error
	calls  []string
}

func (f *fakeListen) Address() string { return f.addr }
func (f *fakeListen) Locked() bool    { return f.locked }
func (f *fakeListen) Change(a string) (string, error) {
	f.calls = append(f.calls, a)
	if f.fail != nil {
		return "", f.fail
	}
	f.addr = a
	return "https://" + a, nil
}

// TestSettingsListenForm drives the Settings page: validation, failure leaves things
// unchanged, success shows the new address, a locked address and viewers are refused.
func TestSettingsListenForm(t *testing.T) {
	e := newWebEnv(t)
	f := &fakeListen{addr: "127.0.0.1:8080"}
	e.web.listen = f
	b := e.browser()
	b.setup("admin", "a-long-password-1")

	if _, body, _ := b.get("/settings"); !strings.Contains(body, "Web interface address") || !strings.Contains(body, "127.0.0.1") {
		t.Fatal("settings page must show the listen address form")
	}
	if code, _, _ := b.post("/settings/listen", url.Values{"host": {"127.0.0.1"}, "port": {"99999"}}); code != 303 || len(f.calls) != 0 {
		t.Errorf("an invalid port must be rejected before anything is bound: %d %v", code, f.calls)
	}
	f.fail = errors.New("address already in use")
	b.post("/settings/listen", url.Values{"host": {"127.0.0.1"}, "port": {"9090"}})
	if f.addr != "127.0.0.1:8080" {
		t.Error("a failed change must leave the old address")
	}
	_, body, _ := b.get("/settings")
	if !strings.Contains(body, "address already in use") || !strings.Contains(body, "Nothing was changed") {
		t.Errorf("failure must be explained: %.300s", body)
	}
	f.fail = nil
	code, body, _ := b.post("/settings/listen", url.Values{"host": {"*"}, "port": {"9443"}})
	if code != 200 || !strings.Contains(body, "0.0.0.0:9443") || !strings.Contains(body, `href="https://0.0.0.0:9443"`) {
		t.Errorf("success must show the new address: %d %.300s", code, body)
	}
	f.locked = true
	b.post("/settings/listen", url.Values{"host": {"127.0.0.1"}, "port": {"7000"}})
	if f.addr != "0.0.0.0:9443" {
		t.Error("a locked address must not change")
	}
	if code, _, _ := b.postRaw("/settings/listen", url.Values{"host": {"127.0.0.1"}, "port": {"7000"}}); code != 403 {
		t.Errorf("a post without the CSRF token = %d, want 403", code)
	}
}
