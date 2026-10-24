package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func rdapBody(expires time.Time) string {
	return fmt.Sprintf(`{"events":[{"eventAction":"expiration","eventDate":%q},{"eventAction":"registration","eventDate":"2010-01-01T00:00:00Z"}],
	"status":["active"],"nameservers":[{"ldhName":"NS1.EXAMPLE.NET"}],
	"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar Inc"]]]}]}`,
		expires.UTC().Format(time.RFC3339))
}

func idbBody(ip string, ports []int, vulns, tags []string) string {
	q := func(v []string) string {
		var o []string
		for _, s := range v {
			o = append(o, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(o, ",") + "]"
	}
	var ps []string
	for _, p := range ports {
		ps = append(ps, fmt.Sprint(p))
	}
	return fmt.Sprintf(`{"cpes":[],"hostnames":["www.example.test"],"ip":%q,"ports":[%s],"tags":%s,"vulns":%s}`, ip, strings.Join(ps, ","), q(tags), q(vulns))
}

// expireCaches pretends the cached third-party answers are old, forcing a refetch.
func (h *harness) expireCaches() {
	h.t.Helper()
	for _, q := range []string{`UPDATE intel SET fetched='2000-01-01T00:00:00Z'`, `UPDATE domain_info SET fetched='2000-01-01T00:00:00Z'`} {
		if _, err := h.store.db.Exec(q); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *harness) findingsOf(status string) map[string]Finding {
	h.t.Helper()
	list, err := h.store.ListFindings("example.test", status)
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]Finding{}
	for _, f := range list {
		out[f.Key] = f
	}
	return out
}

func TestIntelFindingsLifecycle(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443, 3389}, []string{"CVE-2021-41773", "CVE-2021-42013"}, []string{"self-signed"})
	// api.example.test lives on a network the entity does not own: its exposure is somebody else's problem
	h.intel.idb["198.51.100.7"] = idbBody("198.51.100.7", []int{22, 445}, []string{"CVE-2020-0001"}, nil)
	h.intel.rdap["example.test"] = rdapBody(time.Now().Add(10 * 24 * time.Hour))
	tg := h.addTarget("example.test", "AS64500")

	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan failed: %q %q", tg.LastStatus, tg.LastError)
	}
	open := h.findingsOf("open")
	rdp, ok := open["svc:203.0.113.10:3389"]
	if !ok || rdp.Kind != "exposed-service" || rdp.Severity != "high" || rdp.Source != "Shodan InternetDB" || !strings.Contains(rdp.Detail, "RDP") {
		t.Fatalf("RDP finding missing/wrong: %+v (all: %v)", rdp, keysOf(open))
	}
	if v := open["vuln:203.0.113.10"]; v.Kind != "known-vuln" || !strings.Contains(v.Detail, "CVE-2021-41773") || v.Severity != "medium" {
		t.Errorf("vuln finding: %+v", v)
	}
	if e := open["expiry:example.test"]; e.Kind != "domain-expiry" || e.Severity != "high" || e.Source != "RDAP" || !strings.Contains(e.Detail, "Example Registrar") {
		t.Errorf("expiry finding: %+v", e)
	}
	// A name under the domain pointing at a foreign network is still reported (that is where
	// shadow IT and hijacks show up) and the finding says the network is outside the expected ownership.
	for _, k := range []string{"svc:198.51.100.7:445", "vuln:198.51.100.7"} {
		f, ok := open[k]
		if !ok || !strings.Contains(f.Detail, "outside the expected ownership") {
			t.Errorf("finding %s for a foreign address missing or not explained: %+v", k, f)
		}
	}
	// no 80/443 findings: only sensitive services are findings
	if _, bad := open["svc:203.0.113.10:443"]; bad {
		t.Error("ordinary HTTPS must not be a finding")
	}
	// every finding explains itself
	for _, f := range open {
		i := describeFinding(f)
		if i.Title == "" || i.Source == "" || i.Risk == "" || i.Solution == "" {
			t.Errorf("finding %s lacks an explanation: %+v", f.Key, i)
		}
	}
	// the services are inventory: recorded, but silent during the baseline
	for _, m := range h.mails() {
		if strings.Contains(m.Plain, "open on 203.0.113.10") {
			t.Errorf("baseline service inventory was emailed:\n%s", m.Plain)
		}
	}
	evs, _, _ := h.store.ListEvents(EventFilter{Root: "example.test", Limit: 500, IncludeBaseline: true})
	seenService := false
	for _, e := range evs {
		if e.Kind == "service" {
			seenService = true
			if !e.Baseline {
				t.Errorf("baseline service event is not marked baseline: %+v", e)
			}
		}
	}
	if !seenService {
		t.Error("services were not recorded as events")
	}
	assets, counts, err := h.store.ListAssets("example.test", "service", "")
	if err != nil || counts["service"] != 5 && counts["service"] != 3 {
		t.Fatalf("service assets: %v %v", counts, err)
	}
	if n := len(assets); n != 3 { // 198.51.100.7 hosts api.example.test, which belongs to the entity
		// api.example.test is part of the entity, so its two ports are listed too
		if n != 5 {
			t.Errorf("unexpected number of service assets: %d", n)
		}
	}

	// ---- scan 2: a new port appears after the baseline -> change alert; RDP closed -> finding resolves
	before := len(h.mails())
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443, 8443}, []string{"CVE-2021-41773", "CVE-2021-42013"}, []string{"self-signed"})
	h.expireCaches()
	h.scan(tg.ID)
	if st := h.findingsOf("resolved")["svc:203.0.113.10:3389"]; st.Status != "resolved" {
		t.Errorf("closed RDP port should auto-resolve: %+v", h.findingsOf(""))
	}
	mails := h.mails()
	if len(mails) <= before {
		t.Fatal("new open port after baseline should alert")
	}
	if last := mails[len(mails)-1]; !strings.Contains(last.Plain, "8443") || !strings.Contains(last.Plain, "service") {
		t.Errorf("alert lacks the new service:\n%s", last.Plain)
	}

	// ---- scan 3: the intelligence service is down. Stale cache must not "fix" findings.
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 3389}, nil, nil)
	h.scan(tg.ID) // cache still fresh from scan 2 -> RDP stays unseen (cache says 8443)
	h.expireCaches()
	if _, err := h.store.db.Exec(`DELETE FROM intel`); err != nil { // no cached answer to fall back on
		t.Fatal(err)
	}
	h.intel.mu.Lock()
	h.intel.forceCode["internetdb"] = 503
	h.intel.mu.Unlock()
	h.scan(tg.ID)
	if v := h.findingsOf("open")["vuln:203.0.113.10"]; v.Key == "" {
		t.Error("vulnerability finding was resolved during a source outage")
	}
	// ---- and when the data source recovers with no vulns, the finding resolves
	h.intel.mu.Lock()
	delete(h.intel.forceCode, "internetdb")
	h.intel.mu.Unlock()
	h.expireCaches()
	h.scan(tg.ID)
	if h.findingsOf("open")["vuln:203.0.113.10"].Key != "" {
		t.Error("vulnerability finding should resolve once the source reports none")
	}
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key == "" {
		t.Error("RDP finding should reopen when the port is reported again")
	}
}

func keysOf(m map[string]Finding) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func TestIntelCDNAddressesAreNotFindings(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{443, 3389}, []string{"CVE-2020-1"}, []string{"cdn"})
	tg := h.addTarget("example.test", "") // no ownership rules
	h.scan(tg.ID)
	for k := range h.findingsOf("open") {
		if strings.HasPrefix(k, "svc:") || strings.HasPrefix(k, "vuln:") {
			t.Errorf("CDN edge address raised %s", k)
		}
	}
	if _, c, _ := h.store.ListAssets("example.test", "", ""); c["service"] == 0 {
		t.Error("CDN services should still be inventoried")
	}
}

func TestRDAPFallsBackToParentDomainAndExpiryThresholds(t *testing.T) {
	h := newHarness(t)
	e := NewEnricher(IntelCfg{RDAP: true}, h.log, "test")
	e.urls = h.intel.urls()
	h.intel.rdap["example.test"] = rdapBody(time.Now().Add(100 * 24 * time.Hour))
	di, err := e.RDAPDomain(context.Background(), "corp.eu.example.test")
	if err != nil || di.Domain != "example.test" || di.Registrar != "Example Registrar Inc" || len(di.Nameservers) != 1 {
		t.Fatalf("parent fallback failed: %+v %v", di, err)
	}
	if _, err := e.RDAPDomain(context.Background(), "nothing.test"); !errors.Is(err, errNoData) {
		t.Errorf("unknown domain should be errNoData, got %v", err)
	}
	now := time.Now()
	for _, c := range []struct {
		days int
		want string
	}{{-3, "high"}, {10, "high"}, {20, "medium"}, {45, "low"}, {90, ""}} {
		got, _, ok := expiryRisk(now.Add(time.Duration(c.days)*24*time.Hour).Format(time.RFC3339), now)
		if !ok || got != c.want {
			t.Errorf("expiry in %d days: got %q want %q", c.days, got, c.want)
		}
	}
}

func TestShodanCensysVirusTotalSources(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	st, _ := h.store.LoadSettings()
	st.InternetDBEnabled = false
	st.ShodanEnabled, st.ShodanDomainLookup, st.CensysEnabled, st.VirusTotalEnabled = true, true, true, true
	h.saveSettings(st)
	for name, v := range map[string]string{secretShodan: "SHODAN-KEY-0123456789", secretCensys: "censys-pat-abcdef123456", secretVT: "vt-key-abcdef123456"} {
		if err := h.eng.SetSecret(name, v); err != nil {
			t.Fatal(err)
		}
	}
	h.intel.shodanKey, h.intel.censysTok, h.intel.vtKey = "SHODAN-KEY-0123456789", "censys-pat-abcdef123456", "vt-key-abcdef123456"
	h.intel.shodan["203.0.113.10"] = `{"org":"Example Net","os":"Windows","hostnames":["www.example.test"],"tags":["eol-os"],"vulns":["CVE-2019-0708"],
		"data":[{"port":3389,"transport":"tcp","product":"Microsoft Terminal Services"},{"port":443,"transport":"tcp","product":"nginx","version":"1.18"}]}`
	h.intel.censys["203.0.113.10"] = `{"result":{"resource":{"services":[{"port":3389,"protocol":"RDP","transport_protocol":"tcp"},{"port":5900,"protocol":"VNC","transport_protocol":"tcp"}]}}}`
	h.intel.shodanDNS = []string{"vpn"}
	h.intel.vtSubs = []string{"staging.example.test", "evil.other.test"} // out-of-scope names must be ignored
	tg := h.addTarget("example.test", "AS64500")
	// VirusTotal is paced at one request per 16 s in production; the test only makes one request.
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan: %q %q", tg.LastStatus, tg.LastError)
	}
	hosts := map[string]string{}
	inv, _, _ := h.store.Inventory("example.test", "", 100)
	for _, r := range inv {
		hosts[r.Host] = r.Sources
	}
	if !strings.Contains(hosts["staging.example.test"], "virustotal") || !strings.Contains(hosts["vpn.example.test"], "shodan-dns") {
		t.Errorf("keyed subdomain sources missing: %v", hosts)
	}
	if _, bad := hosts["evil.other.test"]; bad {
		t.Error("out-of-scope VirusTotal name was accepted")
	}
	open := h.findingsOf("open")
	rdp := open["svc:203.0.113.10:3389"]
	if !strings.Contains(rdp.Source, "Shodan") || !strings.Contains(rdp.Source, "Censys") {
		t.Errorf("source should list both services that saw the port: %q", rdp.Source)
	}
	if vnc := open["svc:203.0.113.10:5900"]; vnc.Kind != "exposed-service" || vnc.Source != "Censys" {
		t.Errorf("Censys-only VNC finding: %+v", vnc)
	}
	if e := open["eol:203.0.113.10"]; e.Kind != "eol-software" {
		t.Errorf("eol tag finding missing: %v", keysOf(open))
	}
	if v := open["vuln:203.0.113.10"]; !strings.Contains(v.Detail, "CVE-2019-0708") {
		t.Errorf("shodan vuln missing: %+v", v)
	}
	if h.intel.hitCount("shodan-badkey") != 0 {
		t.Error("the stored Shodan key was not used")
	}
	// Shodan IPs were enumerated; services carry product names into the inventory
	all, _, _ := h.store.ListAssets("example.test", "service", "")
	_ = all
	svc, _, _ := h.store.ListAssets("example.test", "service", "terminal")
	if len(svc) != 1 || !strings.Contains(svc[0].Details, "Microsoft Terminal Services") {
		t.Errorf("product name missing from assets: %+v", svc)
	}
}

func TestKeysNeverLeakIntoErrorsOrLogs(t *testing.T) {
	const key = "TOPSECRETKEY123456"
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	board := NewHealthBoard()
	cfg := IntelCfg{MaxIPs: 10, CacheTTL: time.Hour}
	cfg.Shodan.Enabled, cfg.Shodan.Key = true, key
	e := NewEnricher(cfg, log, "test")
	e.health = board

	// 1. server rejects the key (401)
	h := newHarness(t)
	h.intel.shodanKey = "a-different-key-entirely"
	e.urls = h.intel.urls()
	e.LookupIPs(context.Background(), []string{"203.0.113.10", "203.0.113.11"}, nil)
	// 2. connection refused: Go's *url.Error would normally print the full URL, key included
	e.urls.shodan = "http://127.0.0.1:1/"
	res := e.LookupIPs(context.Background(), []string{"203.0.113.12"}, nil)
	if len(res.OK) != 0 {
		t.Error("lookup against a dead server must not look successful")
	}
	if _, err := e.ShodanSubdomains(context.Background(), "example.test"); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("subdomain error missing or leaks the key: %v", err)
	}
	all := logs.String() + board.Marshal()
	if strings.Contains(all, key) {
		t.Fatalf("API key leaked into logs/health state:\n%s", all)
	}
	it, ok := board.Get("shodan")
	if !ok || it.FailCount == 0 || it.LastError == "" {
		t.Errorf("failures not recorded: %+v", it)
	}
	// a rejected key stops further requests in the same scan instead of hammering the API
	if n := h.intel.hitCount("shodan-badkey"); n != 1 {
		t.Errorf("expected exactly 1 rejected request before backing off, got %d", n)
	}
}

func TestHealthChecksAndStatuses(t *testing.T) {
	h := newHarness(t)
	h.eng.reachFn = func(host string) func(context.Context) error {
		return func(context.Context) error {
			if host == "otx.alienvault.com" {
				return errors.New("connection refused")
			}
			return nil
		}
	}
	st, _ := h.store.LoadSettings()
	st.ShodanEnabled, st.CensysEnabled = true, true // enabled, but only Shodan gets a key
	st.AnubisEnabled = false
	h.saveSettings(st)
	if err := h.eng.SetSecret(secretShodan, "SHODAN-KEY-0123456789"); err != nil {
		t.Fatal(err)
	}
	h.intel.shodanKey = "SHODAN-KEY-0123456789"
	mailsBefore := len(h.smtp.all())

	h.eng.RunHealthChecks(testCtx(t))

	if got := len(h.smtp.all()); got != mailsBefore {
		t.Errorf("the SMTP check must not send mail (%d -> %d)", mailsBefore, got)
	}
	cur, _ := h.store.LoadSettings()
	have := map[string]bool{secretShodan: true}
	state := map[string]string{}
	for _, c := range Connectors(cur, have) {
		it, seen := h.eng.Health().Get(c.ID)
		if c.ID == "dns" {
			it, seen = h.eng.Health().Get("dns:" + cur.DNSResolvers[0])
		}
		s, _ := c.Status(it, seen)
		state[c.ID] = s
	}
	want := map[string]string{"crtsh": "good", "otx": "bad", "anubis": "off", "dns": "good", "asn-cymru": "good", "internetdb": "good",
		"shodan": "good", "censys": "warn", "smtp": "good", "rdap": "good"}
	for id, w := range want {
		if state[id] != w {
			t.Errorf("connector %s: got %q want %q (item %+v)", id, state[id], w, h.eng.Health().Snapshot())
		}
	}
	if it, _ := h.eng.Health().Get("shodan"); !strings.Contains(it.Note, "plan dev") {
		t.Errorf("shodan plan note missing: %q", it.Note)
	}
	if it, _ := h.eng.Health().Get("otx"); !strings.Contains(it.LastError, "refused") {
		t.Errorf("failure reason not kept: %+v", it)
	}
	// health survives a restart
	h2 := NewEngine(h.store, h.vault, h.log)
	if it, ok := h2.Health().Get("otx"); !ok || it.FailCount == 0 {
		t.Error("connector health was not persisted")
	}
	// a resolver outage shows up as failing
	h.dns.stop()
	h.eng.RunHealthChecks(testCtx(t))
	it, _ := h.eng.Health().Get("dns:" + cur.DNSResolvers[0])
	if it.LastFail.IsZero() || !it.LastFail.After(it.LastOK) {
		t.Errorf("dead resolver not reported: %+v", it)
	}
}

// A failure persisted by the last session must not stay on the Health page after a
// restart: the scheduler re-checks the connectors on its own, once, then waits.
func TestHealthCheckedAutomaticallyAfterStart(t *testing.T) {
	h := newHarness(t)
	var probes atomic.Int32
	h.eng.reachFn = func(string) func(context.Context) error {
		return func(context.Context) error { probes.Add(1); return nil }
	}
	stale := NewHealthBoard()
	stale.items["crtsh"] = &HealthItem{Name: "crtsh", LastFail: time.Now().Add(-time.Hour), LastError: "timeout from last session", FailCount: 1}
	h.eng.Health().Load(stale.Marshal()) // as restored from the database at start-up
	h.eng.healthEvery = time.Hour

	h.eng.maybeHealthCheck(testCtx(t))
	h.eng.wg.Wait()
	h.eng.maybeHealthCheck(testCtx(t)) // within the interval: no second run
	h.eng.wg.Wait()

	cur, _ := h.store.LoadSettings()
	for _, c := range Connectors(cur, nil) {
		if c.ID != "crtsh" {
			continue
		}
		it, seen := h.eng.Health().Get("crtsh")
		if s, _ := c.Status(it, seen); s != "good" {
			t.Errorf("stale failure still shown after the automatic check: %s %+v", s, it)
		}
	}
	first := probes.Load()
	if first == 0 {
		t.Fatal("the automatic check did not run")
	}
	h.eng.maybeHealthCheck(testCtx(t))
	h.eng.wg.Wait()
	if probes.Load() != first {
		t.Error("connectors were re-checked before the interval elapsed")
	}
	h.eng.healthEvery = 0
	h.eng.lastHealth = time.Time{}
	h.eng.maybeHealthCheck(testCtx(t))
	h.eng.wg.Wait()
	if probes.Load() != first {
		t.Error("healthEvery=0 must disable automatic checks")
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := findingIP("svc:2001:db8::1:3389"); got != "2001:db8::1" {
		t.Errorf("v6 service key: %q", got)
	}
	if findingIP("svc:203.0.113.10:22") != "203.0.113.10" || findingIP("vuln:203.0.113.10") != "203.0.113.10" {
		t.Error("ip extraction")
	}
	if mergeSources("Censys", "Shodan, Censys") != "Censys, Shodan" || mergeSources("", "RDAP") != "RDAP" || mergeSources("A", "") != "A" {
		t.Error("mergeSources")
	}
	f := Finding{Kind: "email-auth", Key: "email:example.test:no-dmarc"}
	if i := describeFinding(f); !strings.Contains(i.Title, "DMARC") || !strings.Contains(i.Solution, "p=") {
		t.Errorf("email finding catalog: %+v", i)
	}
	if i := describeFinding(Finding{Kind: "mystery", Source: "x"}); i.Risk == "" || i.Source != "x" {
		t.Errorf("unknown kinds still need text: %+v", i)
	}
	for k := range findingKinds {
		if _, ok := findingCatalog[k]; !ok && k != "email-auth" {
			t.Errorf("finding kind %q has no catalog entry", k)
		}
	}
	if !redactTest() {
		t.Error("redact")
	}
}

func redactTest() bool {
	return redact(errors.New("GET https://x/?key=abcd1234 failed"), "abcd1234").Error() == "GET https://x/?key=*** failed" && redact(nil, "x") == nil
}

func TestStaleCacheDoesNotResolveFindings(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{3389}, nil, nil)
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key == "" {
		t.Fatal("setup: RDP finding missing")
	}
	// the cached copy is old and no longer lists the port, and the service is unreachable
	if _, err := h.store.db.Exec(`DELETE FROM services WHERE port=3389`); err != nil {
		t.Fatal(err)
	}
	h.expireCaches()
	h.intel.mu.Lock()
	h.intel.forceCode["internetdb"] = 500
	h.intel.mu.Unlock()
	h.scan(tg.ID)
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key == "" {
		t.Error("a stale cached answer must not be trusted to close a finding")
	}
}
