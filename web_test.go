package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type webEnv struct {
	*harness
	srv *httptest.Server
	web *Server
}

func newWebEnv(t testing.TB) *webEnv {
	t.Helper()
	h := newHarness(t)
	web, err := NewServer(h.store, h.eng, h.log, &Bootstrap{Listen: "127.0.0.1:8080", PlainHTTP: true}) // the test server speaks plain HTTP
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(web.Handler())
	t.Cleanup(srv.Close)
	return &webEnv{harness: h, srv: srv, web: web}
}

type browser struct {
	t    testing.TB
	base string
	c    *http.Client
	csrf string
	code func() string // the server's current setup code
}

func (e *webEnv) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: e.t, base: e.srv.URL, code: e.web.SetupCode, c: &http.Client{Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (b *browser) do(req *http.Request) (int, string, *http.Response) {
	b.t.Helper()
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp
}

func (b *browser) get(path string) (int, string, *http.Response) {
	b.t.Helper()
	req, _ := http.NewRequest("GET", b.base+path, nil)
	return b.do(req)
}

func (b *browser) postRaw(path string, v url.Values) (int, string, *http.Response) {
	b.t.Helper()
	req, _ := http.NewRequest("POST", b.base+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

// post adds the session CSRF token automatically.
func (b *browser) post(path string, v url.Values) (int, string, *http.Response) {
	if v == nil {
		v = url.Values{}
	}
	if v.Get("csrf") == "" {
		v.Set("csrf", b.csrf)
	}
	return b.postRaw(path, v)
}

func (b *browser) refreshCSRF() {
	b.t.Helper()
	_, body, _ := b.get("/account")
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		b.csrf = m[1]
	} else {
		b.t.Fatalf("no csrf token on /account: %.200s", body)
	}
}

func (b *browser) loginPre(path string) string {
	_, body, _ := b.get(path)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no pre-auth csrf on %s", path)
	}
	return m[1]
}

func (b *browser) setup(user, pw string) {
	b.t.Helper()
	tok := b.loginPre("/setup")
	code, body, _ := b.postRaw("/setup", url.Values{"csrf": {tok}, "code": {b.code()}, "username": {user}, "password": {pw}, "confirm": {pw}})
	if code != 303 {
		b.t.Fatalf("setup failed: %d %.300s", code, body)
	}
	b.refreshCSRF()
}

func (b *browser) login(user, pw string) int {
	tok := b.loginPre("/login")
	code, _, _ := b.postRaw("/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pw}})
	if code == 303 {
		b.refreshCSRF()
	}
	return code
}

func loc(r *http.Response) string { return r.Header.Get("Location") }

func TestWebFirstRunAndAuth(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	if code, _, r := b.get("/"); code != 303 || loc(r) != "/setup" {
		t.Fatalf("first visit should go to setup: %d %s", code, loc(r))
	}
	if code, _, r := b.get("/login"); code != 303 || loc(r) != "/setup" {
		t.Fatalf("login before setup: %d %s", code, loc(r))
	}
	// POST /setup without the pre-auth cookie/token is rejected
	if code, _, _ := e.browser().postRaw("/setup", url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "confirm": {"correct horse battery"}}); code != 403 {
		t.Errorf("setup without CSRF token: %d", code)
	}
	tok := b.loginPre("/setup")
	for name, v := range map[string]url.Values{
		"short password": {"username": {"admin"}, "password": {"short"}, "confirm": {"short"}},
		"mismatch":       {"username": {"admin"}, "password": {"correct horse battery"}, "confirm": {"different horse battery"}},
		"bad username":   {"username": {"a b"}, "password": {"correct horse battery"}, "confirm": {"correct horse battery"}},
	} {
		v.Set("csrf", tok)
		if code, body, _ := b.postRaw("/setup", v); code != 400 || !strings.Contains(body, "flash bad") {
			t.Errorf("%s accepted or no message: %d", name, code)
		}
	}
	b.setup("admin", "correct horse battery")
	code, body, _ := b.get("/")
	if code != 200 || !strings.Contains(body, "Add an entity to monitor") {
		t.Fatalf("dashboard after setup: %d", code)
	}
	if code, _, r := b.get("/setup"); code != 303 || loc(r) != "/login" {
		t.Errorf("setup must be closed once a user exists: %d %s", code, loc(r))
	}
	// session cookie hardening
	var sc *http.Cookie
	tok2 := e.browser().loginPre("/login")
	_ = tok2
	b2 := e.browser()
	t2 := b2.loginPre("/login")
	_, _, r := b2.postRaw("/login", url.Values{"csrf": {t2}, "username": {"admin"}, "password": {"correct horse battery"}})
	for _, c := range r.Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie not hardened: %+v", sc)
	}
	// logout needs CSRF
	if code, _, _ := b.postRaw("/logout", url.Values{"csrf": {"nope"}}); code != 403 {
		t.Errorf("logout with bad CSRF: %d", code)
	}
	if code, _, r := b.post("/logout", nil); code != 303 || loc(r) != "/login" {
		t.Errorf("logout: %d %s", code, loc(r))
	}
	if code, _, r := b.get("/"); code != 303 || loc(r) != "/login" {
		t.Errorf("after logout: %d %s", code, loc(r))
	}
	// wrong password, then throttling
	b3 := e.browser()
	tk := b3.loginPre("/login")
	for i := 0; i < 5; i++ {
		if code, _, _ := b3.postRaw("/login", url.Values{"csrf": {tk}, "username": {"admin"}, "password": {"wrong-wrong-wrong"}}); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, body, _ := b3.postRaw("/login", url.Values{"csrf": {tk}, "username": {"admin"}, "password": {"correct horse battery"}}); code != 429 || !strings.Contains(body, "Too many") {
		t.Errorf("brute force not throttled: %d", code)
	}
	// login without the CSRF cookie
	if code, _, _ := e.browser().postRaw("/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}}); code != 403 {
		t.Errorf("login without CSRF: %d", code)
	}
}

func TestWebSessionExpiry(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	e.web.mu.Lock()
	for _, s := range e.web.sessions {
		s.Expires = time.Now().Add(-time.Minute)
	}
	e.web.mu.Unlock()
	if code, _, r := b.get("/"); code != 303 || loc(r) != "/login" {
		t.Errorf("expired session still valid: %d", code)
	}
	if code, _, _ := b.post("/targets", url.Values{"domain": {"example.com"}}); code != 401 {
		t.Errorf("POST with expired session: %d", code)
	}
}

func TestWebHeadersHostCheckAndHealth(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	code, body, r := b.get("/healthz")
	if code != 200 || strings.TrimSpace(body) != "ok" {
		t.Errorf("healthz: %d %q", code, body)
	}
	for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if r.Header.Get(k) != want {
			t.Errorf("header %s=%q", k, r.Header.Get(k))
		}
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP: %q", csp)
	}
	req, _ := http.NewRequest("GET", b.base+"/login", nil)
	req.Host = "evil.example"
	if code, _, _ := b.do(req); code != 421 {
		t.Errorf("DNS-rebinding style Host header accepted: %d", code)
	}
	if code, body, _ := b.get("/static/app.css"); code != 200 || !strings.Contains(body, "--accent") {
		t.Errorf("static css: %d", code)
	}
	if code, _, _ := b.get("/static/../web.go"); code == 200 {
		t.Error("path traversal served a source file")
	}
}

func TestWebTargetLifecycle(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")

	if code, _, _ := b.postRaw("/targets", url.Values{"domain": {"example.com"}}); code != 403 {
		t.Errorf("POST /targets without CSRF: %d", code)
	}
	// invalid input: flash + the form is refilled
	code, _, r := b.post("/targets", url.Values{"domain": {"bad_domain!"}, "notes": {"keep me"}})
	if code != 303 || loc(r) != "/#add" {
		t.Fatalf("invalid add: %d %s", code, loc(r))
	}
	_, body, _ := b.get("/")
	if !strings.Contains(body, "flash bad") || !strings.Contains(body, "not a valid domain") || !strings.Contains(body, "keep me") {
		t.Errorf("no error/refill after invalid add")
	}
	// valid add with ownership rules, XSS-laden notes
	xss := `<script>alert(1)</script>`
	code, _, r = b.post("/targets", url.Values{"domain": {"Example.TEST"}, "asns": {"AS64500"}, "keywords": {"EXAMPLE-NET"}, "notes": {xss}})
	if code != 303 || !strings.HasPrefix(loc(r), "/targets/") {
		t.Fatalf("add: %d %s", code, loc(r))
	}
	tpath := loc(r)
	code, body, _ = b.get(tpath)
	if code != 200 || !strings.Contains(body, "example.test") || !strings.Contains(body, "Queued") {
		t.Fatalf("target page: %d", code)
	}
	if strings.Contains(body, xss) || !strings.Contains(body, "&lt;script&gt;") {
		t.Error("notes were not HTML-escaped")
	}
	// overlap rejected
	b.post("/targets", url.Values{"domain": {"deep.sub.example.test"}})
	if _, body, _ = b.get("/"); !strings.Contains(body, "already covered") {
		t.Error("overlapping subdomain not rejected with an explanation")
	}
	// edit
	id := strings.TrimPrefix(tpath, "/targets/")
	if code, _, _ = b.post(tpath+"/edit", url.Values{"asns": {"AS1, AS2"}, "interval": {"120"}, "notes": {"ok"}}); code != 303 {
		t.Fatalf("edit: %d", code)
	}
	if _, body, _ = b.get(tpath); !strings.Contains(body, "1,2") || !strings.Contains(body, `value="120"`) {
		t.Error("edit not persisted")
	}
	b.post(tpath+"/edit", url.Values{"interval": {"3"}}) // invalid: too small
	if _, body, _ = b.get(tpath); !strings.Contains(body, "between 15 and 43200") {
		t.Error("invalid interval accepted")
	}
	// pause / resume / scan
	b.post(tpath+"/pause", nil)
	if _, body, _ = b.get(tpath); !strings.Contains(body, "Paused") || !strings.Contains(body, "Resume") {
		t.Error("pause not reflected")
	}
	b.post(tpath+"/scan", nil)
	if _, body, _ = b.get(tpath); !strings.Contains(body, "paused") {
		t.Error("scan-now on a paused target should explain why it did nothing")
	}
	b.post(tpath+"/resume", nil)
	n, _ := strconv.ParseInt(id, 10, 64)
	if tg, _ := e.store.GetTarget(n); !tg.Enabled {
		t.Error("resume failed")
	}
	// delete requires typing the domain
	b.post(tpath+"/delete", url.Values{"confirm": {"wrong.test"}})
	if code, _, _ = b.get(tpath); code != 200 {
		t.Error("deleted without confirmation")
	}
	if code, _, r = b.post(tpath+"/delete", url.Values{"confirm": {"EXAMPLE.test"}}); code != 303 || loc(r) != "/" {
		t.Errorf("delete: %d %s", code, loc(r))
	}
	if code, _, _ = b.get(tpath); code != 404 {
		t.Errorf("deleted target page: %d", code)
	}
	if code, _, _ = b.get("/targets/abc"); code != 404 {
		t.Errorf("bad id: %d", code)
	}
}

func TestWebViewerIsReadOnly(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/targets", url.Values{"domain": {"example.test"}})
	if code, _, _ := admin.post("/users", url.Values{"username": {"viewer1"}, "password": {"viewer password 1"}, "role": {"viewer"}}); code != 303 {
		t.Fatalf("create viewer: %d", code)
	}
	v := e.browser()
	if v.login("viewer1", "viewer password 1") != 303 {
		t.Fatal("viewer cannot sign in")
	}
	code, body, _ := v.get("/")
	if code != 200 || strings.Contains(body, "Add an entity") || strings.Contains(body, ">Settings<") || strings.Contains(body, "Scan now") {
		t.Errorf("viewer sees admin controls (code %d)", code)
	}
	for _, p := range []string{"/settings", "/users"} {
		if code, _, _ := v.get(p); code != 403 {
			t.Errorf("viewer GET %s: %d", p, code)
		}
	}
	for _, p := range []string{"/targets", "/targets/1/scan", "/targets/1/delete", "/settings", "/users", "/settings/test-email", "/findings/1/ack"} {
		if code, _, _ := v.post(p, url.Values{"domain": {"x.example"}, "confirm": {"example.test"}}); code != 403 {
			t.Errorf("viewer POST %s: %d", p, code)
		}
	}
	if tg, err := e.store.GetTarget(1); err != nil || tg.Domain != "example.test" {
		t.Error("viewer changed data")
	}
	for _, p := range []string{"/findings", "/events", "/report", "/report/inventory.csv", "/report.json", "/targets/1", "/account"} {
		if code, _, _ := v.get(p); code != 200 {
			t.Errorf("viewer GET %s: %d", p, code)
		}
	}
}

func settingsForm(s Settings) url.Values {
	v := url.Values{}
	set := func(k string, n int) { v.Set(k, strconv.Itoa(n)) }
	set("interval_minutes", s.IntervalMinutes)
	set("jitter_minutes", s.JitterMinutes)
	set("target_timeout_minutes", s.TargetTimeoutMinutes)
	set("concurrent_scans", s.ConcurrentScans)
	set("event_retention_days", s.EventRetentionDays)
	set("alert_min_events", s.AlertMinEvents)
	set("alert_max_rows", s.AlertMaxRows)
	set("digest_hour", s.DigestHour)
	set("crtsh_timeout_seconds", s.CrtShTimeoutSeconds)
	set("crtsh_max_attempts", s.CrtShMaxAttempts)
	set("dns_workers", s.DNSWorkers)
	set("dns_qps", s.DNSQPS)
	set("dns_timeout_seconds", s.DNSTimeoutSeconds)
	set("dns_retries", s.DNSRetries)
	set("smtp_port", s.SMTPPort)
	set("enrich_max_ips", s.EnrichMaxIPs)
	set("removal_misses", s.RemovalMisses)
	set("active_max_hosts", s.ActiveMaxHosts)
	set("active_timeout_seconds", s.ActiveTimeoutSeconds)
	set("active_concurrency", s.ActiveConcurrency)
	set("screenshot_max", s.ScreenshotMax)
	set("lookalike_max", s.LookalikeMax)
	v.Set("chrome_path", s.ChromePath)
	v.Set("censys_org_id", s.CensysOrgID)
	v.Set("alert_immediate_severity", s.AlertImmediateSeverity)
	v.Set("digest_frequency", s.DigestFrequency)
	v.Set("public_url", s.PublicURL)
	v.Set("org_name", s.OrgName)
	if s.UpdateCheck {
		v.Set("update_check", "on")
	}
	v.Set("smtp_host", s.SMTPHost)
	v.Set("smtp_security", s.SMTPSecurity)
	v.Set("smtp_username", s.SMTPUsername)
	v.Set("smtp_from", s.SMTPFrom)
	v.Set("smtp_subject_prefix", s.SMTPSubjectPrefix)
	v.Set("dns_resolvers", strings.Join(s.DNSResolvers, "\n"))
	v.Set("smtp_to", strings.Join(s.SMTPTo, "\n"))
	for k, on := range map[string]bool{"alert_baseline_summary": s.AlertBaselineSummary, "alert_certs": s.AlertCerts, "alert_removals": s.AlertRemovals, "require_2fa": s.Require2FA, "hibp_enabled": s.HIBPEnabled, "github_enabled": s.GitHubEnabled, "lookalike_enabled": s.LookalikeEnabled, "related_enabled": s.RelatedEnabled, "reverseip_enabled": s.ReverseIPEnabled, "active_checks": s.ActiveChecks, "active_foreign": s.ActiveForeign, "active_paths": s.ActivePaths, "active_buckets": s.ActiveBuckets, "screenshots": s.Screenshots, "alert_txt": s.AlertTXT,
		"crtsh_enabled": s.CrtShEnabled, "hackertarget_enabled": s.HackerTargetEnabled, "otx_enabled": s.OTXEnabled, "anubis_enabled": s.AnubisEnabled,
		"asn_enabled": s.ASNEnabled, "asn_bgpview_fallback": s.ASNBGPViewFallback, "smtp_enabled": s.SMTPEnabled, "smtp_insecure_skip_verify": s.SMTPInsecureSkipVerify,
		"internetdb_enabled": s.InternetDBEnabled, "rdap_enabled": s.RDAPEnabled, "shodan_enabled": s.ShodanEnabled,
		"shodan_domain_lookup": s.ShodanDomainLookup, "censys_enabled": s.CensysEnabled, "virustotal_enabled": s.VirusTotalEnabled} {
		if on {
			v.Set(k, "on")
		}
	}
	return v
}

func TestWebSettings(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	cur, _ := e.store.LoadSettings()
	if code, body, _ := b.get("/settings"); code != 200 || !strings.Contains(body, `name="interval_minutes"`) {
		t.Fatalf("settings page: %d", code)
	}
	// valid change incl. SMTP password
	form := settingsForm(cur)
	form.Set("interval_minutes", "720")
	form.Set("alert_min_events", "5")
	form.Set("smtp_password", "pa55-word-pa55")
	if code, _, _ := b.post("/settings", form); code != 303 {
		t.Fatalf("save: %d", code)
	}
	got, _ := e.store.LoadSettings()
	if got.IntervalMinutes != 720 || got.AlertMinEvents != 5 || got.SMTPHost != "127.0.0.1" {
		t.Errorf("settings not saved: %+v", got)
	}
	if e.eng.SMTPPassword() != "pa55-word-pa55" {
		t.Error("SMTP password not stored")
	}
	_, body, _ := b.get("/settings")
	if strings.Contains(body, "pa55-word") || !strings.Contains(body, "saved; leave blank to keep") {
		t.Error("password echoed back or saved-state not shown")
	}
	// leaving the password blank keeps it
	b.post("/settings", settingsForm(got))
	if e.eng.SMTPPassword() != "pa55-word-pa55" {
		t.Error("blank password field wiped the saved password")
	}
	// invalid values are rejected and nothing changes
	bad := settingsForm(got)
	bad.Set("interval_minutes", "2")
	b.post("/settings", bad)
	if _, body, _ = b.get("/settings"); !strings.Contains(body, "between 15") {
		t.Error("no validation message")
	}
	if g, _ := e.store.LoadSettings(); g.IntervalMinutes != 720 {
		t.Error("invalid settings were saved")
	}
	bad = settingsForm(got)
	bad.Set("interval_minutes", "abc")
	b.post("/settings", bad)
	if _, body, _ = b.get("/settings"); !strings.Contains(body, "whole number") {
		t.Error("non-numeric accepted")
	}
	// explicit removal
	rm := settingsForm(got)
	rm.Set("smtp_password_clear", "on")
	b.post("/settings", rm)
	if e.eng.SMTPPassword() != "" {
		t.Error("password not cleared")
	}
	// test email goes out through the fake server
	before := e.smtp.count()
	b.post("/settings/test-email", nil)
	if _, body, _ = b.get("/settings"); !strings.Contains(body, "Test email sent") || e.smtp.count() != before+1 {
		t.Error("test email not delivered")
	}
}

func TestWebReportFindingsEventsAndExports(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	tg := e.scan(1)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan: %q %q", tg.LastStatus, tg.LastError)
	}
	code, body, _ := b.get("/")
	if code != 200 || !strings.Contains(body, "example.test") || !strings.Contains(body, "Monitoring") {
		t.Errorf("dashboard after scan: %d", code)
	}
	if !strings.Contains(body, "1 open") {
		t.Error("dashboard does not show the open finding")
	}
	_, body, _ = b.get("/targets/1")
	for _, want := range []string{"www.example.test", "AS64500", "EXAMPLE-NET", "api.example.test", "asn-unexpected", "Scan history"} {
		if !strings.Contains(body, want) {
			t.Errorf("target page missing %q", want)
		}
	}
	if _, body, _ = b.get("/targets/1?q=www"); strings.Contains(body, "api.example.test</td>") && !strings.Contains(body, "asn-unexpected") {
		t.Error("host filter ignored")
	}
	// report page + exports
	code, body, _ = b.get("/report?target=example.test&days=30")
	if code != 200 || !strings.Contains(body, "<h1>example.test</h1>") || !strings.Contains(body, "Domains: example.test") ||
		!strings.Contains(body, "Prepared by admin (admin)") || !strings.Contains(body, "www.example.test") || !strings.Contains(body, "Open findings (1)") {
		t.Errorf("report page: %d", code)
	}
	code, body, r := b.get("/report/inventory.csv?target=example.test")
	if code != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(body, "target,host,addresses") ||
		!strings.Contains(body, `www.example.test,203.0.113.10,"AS64500 EXAMPLE-NET`) {
		t.Errorf("inventory csv: %d\n%s", code, body)
	}
	if _, body, _ = b.get("/report/findings.csv"); !strings.Contains(body, "high,asn-unexpected,Address outside expected ownership,example.test,api.example.test") {
		t.Errorf("findings csv:\n%s", body)
	}
	_, body, r = b.get("/report.json?target=example.test")
	var rep struct {
		Scope    string
		Findings []struct{ Type, Host string }
		Targets  []struct{ Target string }
	}
	if err := json.Unmarshal([]byte(body), &rep); err != nil || rep.Scope != "example.test" || len(rep.Findings) != 1 || rep.Findings[0].Host != "api.example.test" {
		t.Errorf("report json: %v %+v", err, rep)
	}
	if !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Error("json not served as a download")
	}
	// findings page: filter, acknowledge, reopen
	if _, body, _ = b.get("/findings?severity=high"); !strings.Contains(body, "api.example.test") {
		t.Error("high finding not listed")
	}
	if code, _, r = b.post("/findings/1/ack", url.Values{"next": {"/findings"}, "reason": {"vendor patch scheduled"}}); code != 303 || loc(r) != "/findings" {
		t.Errorf("ack redirect: %d %s", code, loc(r))
	}
	if _, _, r = b.post("/findings/1/reopen", url.Values{"next": {"https://evil.example/"}}); loc(r) != "/findings" {
		t.Errorf("open redirect via next: %s", loc(r))
	}
	b.post("/findings/1/ack", url.Values{"next": {"//evil.example"}, "reason": {"vendor patch scheduled"}})
	if _, body, _ = b.get("/findings"); strings.Contains(body, "api.example.test") {
		t.Error("acknowledged finding should leave the open list")
	}
	if _, body, _ = b.get("/findings?status=ack"); !strings.Contains(body, "api.example.test") {
		t.Error("acknowledged finding not in the ack list")
	}
	// events: baseline hidden by default, shown on request; injection attempts are inert
	if _, body, _ = b.get("/events"); strings.Contains(body, "discovered via") {
		t.Error("baseline inventory shown by default")
	}
	if _, body, _ = b.get("/events?baseline=1"); !strings.Contains(body, "discovered via") {
		t.Error("baseline events missing when requested")
	}
	for _, q := range []string{"target=' OR 1=1--", "kind=x';DROP TABLE events;--", "severity=high' OR '1'='1", "page=-5", "page=zzz"} {
		kv := strings.SplitN(q, "=", 2)
		if code, _, _ := b.get("/events?" + kv[0] + "=" + url.QueryEscape(kv[1])); code != 200 {
			t.Errorf("events%s: %d", q, code)
		}
	}
	var n int
	if err := e.store.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil || n == 0 {
		t.Errorf("events table damaged: %d %v", n, err)
	}
}

func TestWebAccountAndUserAdmin(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	flashOf := func(path string) string {
		_, body, _ := b.get(path)
		if m := regexp.MustCompile(`class="flash (\w+)"[^>]*>([^<]*)<`).FindStringSubmatch(body); m != nil {
			return m[1] + ": " + m[2]
		}
		return ""
	}
	b.post("/account/password", url.Values{"current": {"wrong password!"}, "password": {"another long pass"}, "confirm": {"another long pass"}})
	if f := flashOf("/account"); !strings.HasPrefix(f, "bad") {
		t.Errorf("wrong current password accepted: %q", f)
	}
	b.post("/account/password", url.Values{"current": {"correct horse battery"}, "password": {"another long pass"}, "confirm": {"mismatch long pass"}})
	if f := flashOf("/account"); !strings.HasPrefix(f, "bad") {
		t.Errorf("mismatch accepted: %q", f)
	}
	b.post("/account/password", url.Values{"current": {"correct horse battery"}, "password": {"short"}, "confirm": {"short"}})
	if f := flashOf("/account"); !strings.HasPrefix(f, "bad") {
		t.Errorf("short accepted: %q", f)
	}
	b.post("/account/password", url.Values{"current": {"correct horse battery"}, "password": {"another long pass"}, "confirm": {"another long pass"}})
	if f := flashOf("/account"); !strings.HasPrefix(f, "good") {
		t.Errorf("valid change failed: %q", f)
	}
	if e.browser().login("admin", "correct horse battery") != 401 {
		t.Error("old password still works")
	}
	if e.browser().login("admin", "another long pass") != 303 {
		t.Error("new password does not work")
	}
	// user admin rules
	b.post("/users", url.Values{"username": {"bob"}, "password": {"bobs long password"}, "role": {"admin"}})
	b.post("/users", url.Values{"username": {"BOB"}, "password": {"bobs long password"}, "role": {"viewer"}})
	if f := flashOf("/users"); !strings.Contains(f, "already exists") {
		t.Errorf("case-insensitive duplicate user allowed: %q", f)
	}
	b.post("/users", url.Values{"username": {"eve"}, "password": {"short"}, "role": {"viewer"}})
	if f := flashOf("/users"); !strings.HasPrefix(f, "bad") {
		t.Errorf("short password for new user accepted: %q", f)
	}
	users, _ := e.store.ListUsers()
	var adminID, bobID int64
	for _, u := range users {
		if u.Username == "admin" {
			adminID = u.ID
		}
		if u.Username == "bob" {
			bobID = u.ID
		}
	}
	b.post("/users/"+strconv.FormatInt(adminID, 10)+"/delete", nil)
	if f := flashOf("/users"); !strings.Contains(f, "own account") {
		t.Errorf("self-delete allowed: %q", f)
	}
	// bob is signed in elsewhere; resetting his password ends that session
	bob := e.browser()
	bob.login("bob", "bobs long password")
	if code, _, _ := bob.get("/"); code != 200 {
		t.Fatal("bob cannot browse")
	}
	b.post("/users/"+strconv.FormatInt(bobID, 10)+"/password", url.Values{"password": {"bobs NEW long password"}})
	if code, _, _ := bob.get("/"); code != 303 {
		t.Error("reset did not end the user's existing session")
	}
	// deleting bob works; now admin is the last admin (cannot be removed by anyone else either)
	b.post("/users/"+strconv.FormatInt(bobID, 10)+"/delete", nil)
	if _, err := e.store.GetUserByName("bob"); err == nil {
		t.Error("bob not deleted")
	}
	if n, _ := e.store.CountAdmins(); n != 1 {
		t.Errorf("admins: %d", n)
	}
}

func TestWebFindingsShowSourceRiskAndFix(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	e.scan(1)
	_, body, _ := b.get("/findings")
	for _, want := range []string{"Source of evidence", "Risk", "Recommended fix", "Address outside expected ownership",
		"Team Cymru", "shadow IT", "add its ASN or organisation keyword"} {
		if !strings.Contains(body, want) {
			t.Errorf("findings page lacks %q", want)
		}
	}
	for _, p := range []string{"/targets/1", "/report"} {
		if _, body, _ = b.get(p); !strings.Contains(body, "Recommended fix") || !strings.Contains(body, "shadow IT") {
			t.Errorf("%s lacks the explanation columns", p)
		}
	}
	_, body, _ = b.get("/report/findings.csv")
	if !strings.Contains(body, ",source,risk,solution,") {
		t.Errorf("findings CSV header:\n%.300s", body)
	}
}

func TestWebHealthPage(t *testing.T) {
	e := newWebEnv(t)
	e.eng.reachFn = func(host string) func(context.Context) error {
		return func(context.Context) error {
			if host == "crt.sh" {
				return errors.New("tls handshake timeout")
			}
			return nil
		}
	}
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/users", url.Values{"username": {"viewer1"}, "password": {"viewer password 1"}, "role": {"viewer"}})

	_, body, _ := admin.get("/health")
	for _, want := range []string{"System health", "Check connections now", "Subdomain discovery", "Exposure intelligence", "Alert delivery", "Not used yet", "Database", "Idle"} {
		if !strings.Contains(body, want) {
			t.Errorf("health page lacks %q", want)
		}
	}
	if code, _, _ := admin.postRaw("/health/check", url.Values{}); code != 403 {
		t.Errorf("health check without CSRF: %d", code)
	}
	if code, _, r := admin.post("/health/check", nil); code != 303 || loc(r) != "/health" {
		t.Fatalf("health check: %d %s", code, loc(r))
	}
	_, body, _ = admin.get("/health")
	for _, want := range []string{"Connected", "Failing", "tls handshake timeout"} {
		if !strings.Contains(body, want) {
			t.Errorf("health page after check lacks %q", want)
		}
	}
	v := e.browser()
	if v.login("viewer1", "viewer password 1") != 303 {
		t.Fatal("viewer login")
	}
	if code, _, _ := v.get("/health"); code != 200 {
		t.Errorf("viewer should see health: %d", code)
	}
	if _, body, _ = v.get("/health"); strings.Contains(body, "Check connections now") {
		t.Error("viewer sees the check button")
	}
	if code, _, _ := v.post("/health/check", nil); code != 403 {
		t.Errorf("viewer POST /health/check: %d", code)
	}
}

func TestWebAssetsPage(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	e.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 3389}, []string{"CVE-2021-41773"}, []string{"self-signed"})
	e.intel.rdap["example.test"] = rdapBody(time.Now().Add(200 * 24 * time.Hour))
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	e.scan(1)

	code, body, _ := b.get("/assets")
	if code != 200 {
		t.Fatalf("assets: %d", code)
	}
	for _, want := range []string{"Domains &amp; subdomains", "IP addresses", "Open services", "Certificates", "DNS records", "Vulnerabilities", "Registration",
		"www.example.test", "203.0.113.10", "AS64500", "open ports 80/tcp, 3389/tcp", "CVE-2021-41773", "Example Registrar Inc", "RDP (sensitive service)", "Shodan InternetDB"} {
		if !strings.Contains(body, want) {
			t.Errorf("assets page lacks %q", want)
		}
	}
	// type tab, search, entity filter
	_, body, _ = b.get("/assets?type=ip")
	if !strings.Contains(body, "203.0.113.10") || strings.Contains(body, "www.example.test</td>") {
		t.Error("type filter not applied")
	}
	if _, body, _ = b.get("/assets?q=" + url.QueryEscape("cve-2021")); !strings.Contains(body, "CVE-2021-41773") || strings.Contains(body, "Registrar") {
		t.Error("search not applied")
	}
	if _, body, _ = b.get("/assets?target=nope.example&type=bogus&page=-4"); !strings.Contains(body, "www.example.test") {
		t.Error("bad filters should fall back to showing everything")
	}
	// CSV export
	code, body, r := b.get("/assets.csv?type=service")
	if code != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/csv") || !strings.HasPrefix(body, "type,asset,entity,details,sources,first_seen,last_seen") ||
		!strings.Contains(body, "203.0.113.10:3389/tcp") || strings.Contains(body, "www.example.test,") {
		t.Errorf("assets csv: %d\n%.400s", code, body)
	}
	// injection attempts are inert
	for _, q := range []string{"' OR 1=1--", "<script>alert(1)</script>", strings.Repeat("A", 500)} {
		if code, body, _ := b.get("/assets?q=" + url.QueryEscape(q)); code != 200 || strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("q=%.20q: %d", q, code)
		}
	}
	// pagination with many assets
	for i := 0; i < 130; i++ {
		_, err := e.store.db.Exec(`INSERT INTO subdomains(root,host,sources,first_seen,last_seen) VALUES('example.test',?,?,?,?)`,
			fmt.Sprintf("bulk%03d.example.test", i), "test", nowUTC(), nowUTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, body, _ = b.get("/assets?type=domain"); !strings.Contains(body, "Page 1 of 2") || !strings.Contains(body, "page=2") {
		t.Error("pagination missing")
	}
	if _, body, _ = b.get("/assets?type=domain&page=2"); !strings.Contains(body, "Page 2 of 2") {
		t.Error("page 2 missing")
	}
	// read-only users can browse
	b.post("/users", url.Values{"username": {"viewer1"}, "password": {"viewer password 1"}, "role": {"viewer"}})
	v := e.browser()
	v.login("viewer1", "viewer password 1")
	if code, _, _ := v.get("/assets"); code != 200 {
		t.Errorf("viewer assets: %d", code)
	}
	// deleting the entity removes its intelligence too
	b.post("/targets/1/delete", url.Values{"confirm": {"example.test"}})
	_, counts, _ := e.store.ListAssets("", "", "")
	for typ, n := range counts {
		if n != 0 {
			t.Errorf("%d %s assets survived deleting the entity", n, typ)
		}
	}
	var n int
	_ = e.store.db.QueryRow(`SELECT (SELECT COUNT(*) FROM services)+(SELECT COUNT(*) FROM intel)+(SELECT COUNT(*) FROM domain_info)`).Scan(&n)
	if n != 0 {
		t.Errorf("%d orphaned intelligence rows", n)
	}
}

func TestWebAPIKeys(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	cur, _ := e.store.LoadSettings()
	flash := func() string {
		_, body, _ := b.get("/settings")
		if m := regexp.MustCompile(`class="flash (\w+)"[^>]*>([^<]*)<`).FindStringSubmatch(body); m != nil {
			return m[1] + ": " + m[2]
		}
		return ""
	}
	const key = "SHODAN-SECRET-KEY-98765"

	// enabling a keyed source without a key is refused
	f := settingsForm(cur)
	f.Set("shodan_enabled", "on")
	b.post("/settings", f)
	if m := flash(); !strings.HasPrefix(m, "bad") || !strings.Contains(m, "no API key") {
		t.Errorf("enabled without key: %q", m)
	}
	if got, _ := e.store.LoadSettings(); got.ShodanEnabled {
		t.Error("settings saved despite the missing key")
	}
	// malformed keys (header/URL injection attempts) are refused and nothing is stored
	for _, bad := range []string{"has space in it 123", "abc\r\nX-Evil: 1", "short", "key&other=1_______", strings.Repeat("a", 300)} {
		f = settingsForm(cur)
		f.Set("shodan_enabled", "on")
		f.Set("shodan_key", bad)
		b.post("/settings", f)
		if e.eng.HasSecret(secretShodan) {
			t.Fatalf("bad key %q was stored", bad)
		}
	}
	// a good key is accepted, encrypted at rest, and never echoed
	f = settingsForm(cur)
	f.Set("shodan_enabled", "on")
	f.Set("shodan_key", key)
	f.Set("censys_enabled", "on")
	f.Set("censys_token", "censys-token-abc123456")
	f.Set("censys_org_id", "org-1234")
	f.Set("virustotal_enabled", "on")
	f.Set("virustotal_key", "vt-key-abcdef123456")
	f.Set("otx_enabled", "on")
	f.Set("otx_key", "otx-key-abcdef123456")
	if code, _, _ := b.post("/settings", f); code != 303 {
		t.Fatalf("save: %d", code)
	}
	got, _ := e.store.LoadSettings()
	if !got.ShodanEnabled || !got.CensysEnabled || !got.VirusTotalEnabled || !got.OTXEnabled || got.CensysOrgID != "org-1234" {
		t.Errorf("settings not saved: %+v", got)
	}
	if e.eng.Secret(secretShodan) != key {
		t.Error("shodan key not retrievable")
	}
	raw, _, _ := e.store.getMeta(secretShodan)
	dump, _ := json.Marshal(got)
	if raw == "" || strings.Contains(raw, key) || strings.Contains(string(dump), key) {
		t.Errorf("key stored in clear (raw=%q)", raw)
	}
	_, body, _ := b.get("/settings")
	for _, secret := range []string{key, "censys-token-abc123456", "vt-key-abcdef123456", "otx-key-abcdef123456"} {
		if strings.Contains(body, secret) {
			t.Errorf("settings page echoes a secret: %s", secret)
		}
	}
	if strings.Count(body, "saved; leave blank to keep") < 3 {
		t.Error("saved-key placeholders missing")
	}
	// leaving fields blank keeps the keys
	b.post("/settings", settingsFormWith(got, map[string]string{"shodan_enabled": "on", "censys_enabled": "on", "virustotal_enabled": "on"}))
	if e.eng.Secret(secretShodan) != key || e.eng.Secret(secretVT) == "" {
		t.Error("blank key field wiped the stored key")
	}
	// the runtime config only activates a source when its key exists
	cfg, _, _ := e.eng.config()
	if !cfg.Intel.Shodan.Enabled || cfg.Intel.Shodan.Key != key || !cfg.Intel.Censys.Enabled || cfg.Intel.Censys.OrgID != "org-1234" {
		t.Errorf("runtime intel config: %+v", cfg.Intel)
	}
	if !cfg.Sources.OTX.Enabled || cfg.Sources.OTX.Key != "otx-key-abcdef123456" {
		t.Errorf("runtime OTX config: %+v", cfg.Sources.OTX)
	}
	// clearing a key while the source stays enabled is refused; disabling and clearing works
	f = settingsFormWith(got, map[string]string{"shodan_enabled": "on", "shodan_key_clear": "on", "censys_enabled": "on", "virustotal_enabled": "on"})
	b.post("/settings", f)
	if !e.eng.HasSecret(secretShodan) {
		t.Error("key removed even though the source is still enabled")
	}
	f = settingsFormWith(got, map[string]string{"shodan_key_clear": "on", "censys_enabled": "on", "virustotal_enabled": "on"})
	b.post("/settings", f)
	if e.eng.HasSecret(secretShodan) {
		t.Error("key not removed")
	}
	cfg, _, _ = e.eng.config()
	if cfg.Intel.Shodan.Enabled {
		t.Error("shodan still active without a key")
	}
	// viewers cannot touch settings
	b.post("/users", url.Values{"username": {"viewer1"}, "password": {"viewer password 1"}, "role": {"viewer"}})
	v := e.browser()
	v.login("viewer1", "viewer password 1")
	if code, _, _ := v.post("/settings", settingsFormWith(got, map[string]string{"shodan_key": "ATTACKER-KEY-123456"})); code != 403 || e.eng.HasSecret(secretShodan) {
		t.Errorf("viewer changed keys: %d", code)
	}
}

func settingsFormWith(s Settings, extra map[string]string) url.Values {
	v := settingsForm(s)
	for _, k := range []string{"shodan_enabled", "censys_enabled", "virustotal_enabled"} {
		v.Del(k)
	}
	for k, val := range extra {
		v.Set(k, val)
	}
	return v
}
