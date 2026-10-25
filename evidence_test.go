package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// evidenceEnv scans a domain whose address InternetDB reports with SMB and RDP open.
func evidenceEnv(t *testing.T) (*webEnv, *browser, Finding) {
	t.Helper()
	e := newWebEnv(t)
	e.seedDomain("evid.test", "203.0.113.77", 64577)
	e.intel.idb["203.0.113.77"] = idbBody("203.0.113.77", []int{443, 445, 3389}, []string{"CVE-2020-0796"}, []string{"eol-os"})
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	tg := e.addTarget("evid.test", "")
	if got := e.scan(tg.ID); got.LastStatus != "ok" {
		t.Fatalf("scan: %s", got.LastError)
	}
	fs, _ := e.store.ListFindings("evid.test", "open")
	for _, f := range fs {
		if f.Key == "svc:203.0.113.77:445" {
			return e, admin, f
		}
	}
	t.Fatalf("no SMB finding among %d", len(fs))
	return nil, nil, Finding{}
}

func TestFindingEvidencePage(t *testing.T) {
	e, admin, f := evidenceEnv(t)

	// The raw InternetDB answer is kept with the cached intelligence.
	raws, err := e.store.IntelRaw("203.0.113.77")
	if err != nil || len(raws) != 1 || raws[0].Source != "internetdb" || !strings.Contains(raws[0].Raw, "445") {
		t.Fatalf("raw answer not stored: %+v %v", raws, err)
	}

	_, list, _ := admin.get("/findings")
	if !strings.Contains(list, fmt.Sprintf(`href="/findings/%d/evidence"`, f.ID)) {
		t.Error("findings table should link to the evidence page")
	}
	code, page, _ := admin.get(fmt.Sprintf("/findings/%d/evidence", f.ID))
	if code != 200 {
		t.Fatalf("evidence page: %d", code)
	}
	for _, want := range []string{
		"https://www.shodan.io/host/203.0.113.77",
		"https://internetdb.shodan.io/203.0.113.77",
		"https://search.censys.io/hosts/203.0.113.77",
		"Raw answers from the exposure sources",
		"&#34;ports&#34;", // the pretty-printed JSON, escaped by html/template
		"445/tcp",
		"Not verified yet",
		`/findings/` + fmt.Sprint(f.ID) + `/evidence.json`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("evidence page lacks %q", want)
		}
	}
	if strings.Contains(page, "3389/tcp") {
		t.Error("the SMB finding's port table should show port 445 only")
	}

	// JSON download: finding, services and the source's answer as real JSON.
	code, body, resp := admin.get(fmt.Sprintf("/findings/%d/evidence.json", f.ID))
	if code != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), "easm-evidence-") {
		t.Fatalf("evidence.json: %d %v", code, resp.Header)
	}
	var out struct {
		Address  string
		Services []ServiceRec
		Sources  []struct {
			Source string
			Answer map[string]any
		}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Address != "203.0.113.77:445" || len(out.Services) == 0 || len(out.Sources) != 1 || out.Sources[0].Answer["ports"] == nil {
		t.Fatalf("evidence.json content: %v %+v", err, out)
	}

	// Viewers may read evidence; unknown findings are 404.
	vw := e.signedIn("vera", RoleViewer)
	if code, _, _ := vw.get(fmt.Sprintf("/findings/%d/evidence", f.ID)); code != 200 {
		t.Errorf("viewer evidence: %d", code)
	}
	if code, _, _ := admin.get("/findings/999999/evidence"); code != 404 {
		t.Errorf("unknown finding: %d", code)
	}

	// The CVE finding links to NVD.
	fs, _ := e.store.ListFindings("evid.test", "open")
	for _, v := range fs {
		if v.Kind == "known-vuln" {
			if _, p, _ := admin.get(fmt.Sprintf("/findings/%d/evidence", v.ID)); !strings.Contains(p, "https://nvd.nist.gov/vuln/detail/CVE-2020-0796") {
				t.Error("known-vuln evidence should link the CVE record")
			}
		}
	}
}

func TestRawAnswerKeptWhenCacheReused(t *testing.T) {
	e, _, _ := evidenceEnv(t)
	tg, _ := e.store.GetTarget(1)
	e.scan(tg.ID) // answers are reused from the cache this time
	raws, _ := e.store.IntelRaw("203.0.113.77")
	if len(raws) != 1 || !strings.Contains(raws[0].Raw, "445") {
		t.Errorf("a cached rescan must keep the stored raw answer: %+v", raws)
	}
}

// API keys never end up in the stored raw answer, even if a service echoes them.
func TestRawAnswerRedactsKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ports":[22],"note":"you used key %s"}`, r.URL.Query().Get("key")) // nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter -- test fake API echoing the key as JSON to prove it is redacted
	}))
	defer srv.Close()
	enr := NewEnricher(IntelCfg{}, testLogger(t), "t")
	enr.cfg.Shodan.Key = "SHODANKEY-1234567890"
	raw, err := enr.getJSONRaw(testCtx(t), srv.URL+"/?key="+url.QueryEscape(enr.cfg.Shodan.Key), nil, nil)
	if err != nil || strings.Contains(raw, "SHODANKEY") || !strings.Contains(raw, "[redacted]") {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func TestEvidenceLinksForDomainFindings(t *testing.T) {
	links := evidenceLinks(&Finding{Kind: "domain-expiry", Host: "acme.test"}, "", nil)
	var hrefs []string
	for _, l := range links {
		hrefs = append(hrefs, l.Href)
	}
	all := strings.Join(hrefs, " ")
	if !strings.Contains(all, "https://rdap.org/domain/acme.test") || !strings.Contains(all, "https://crt.sh/?q=acme.test") || strings.Contains(all, "shodan") {
		t.Errorf("domain-expiry links: %v", hrefs)
	}
	for key, want := range map[string]string{"vuln:203.0.113.5": "203.0.113.5", "asn:acme.test:2001:db8::5": "2001:db8::5", "priv:x.acme.test:10.0.0.1": "10.0.0.1", "email:acme.test:spf": ""} {
		if ip, _ := findingAddress(&Finding{Key: key}); ip != want {
			t.Errorf("findingAddress(%s) = %q, want %q", key, ip, want)
		}
	}
}

func TestAddDomainFirstScanOptions(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	_, dash, _ := admin.get("/")
	for _, want := range []string{"First scan", `name="first_active"`, `name="first_shots"`, `name="first_verify"`, "Active scanning enabled", "Screenshots enabled", "Confirm open ports"} {
		if !strings.Contains(dash, want) {
			t.Errorf("add form lacks %q", want)
		}
	}
	admin.post("/targets", url.Values{"domain": {"opts.test"}, "first_active": {"1"}, "first_shots": {"1"}, "first_verify": {"1"}})
	_, page, _ := admin.get("/targets")
	if !strings.Contains(page, "First scan: active scanning, screenshots, confirm open ports.") {
		t.Errorf("the confirmation should list the first-scan options")
	}
	if !e.store.PeekVerifyOnce("opts.test") || !e.store.TakeShotsOnce("opts.test") || !e.store.TakeActiveOnce("opts.test") {
		t.Error("first-scan requests not recorded")
	}
	if _, au, _ := admin.get("/audit"); !strings.Contains(au, "active scanning, screenshots, confirm open ports") {
		t.Error("first-scan options should be audited with the new domain")
	}

	admin.post("/targets", url.Values{"domain": {"plain.test"}})
	if e.store.TakeActiveOnce("plain.test") || e.store.TakeShotsOnce("plain.test") || e.store.PeekVerifyOnce("plain.test") {
		t.Error("unticked boxes must request nothing")
	}

	// When Settings already run active checks on every scan the box says so.
	st, _ := e.store.LoadSettings()
	st.ActiveChecks = true
	e.saveSettings(st)
	if _, dash, _ = admin.get("/"); !strings.Contains(dash, "on for every scan in Settings") {
		t.Error("the form should say active checks are already on")
	}
}

func TestConfirmOpenPortsAfterFirstScan(t *testing.T) {
	e := newWebEnv(t)
	e.addTarget("example.test", "")
	ip, port := listen(t, "SSH-2.0-test\r\n")
	open := insertFinding(t, e, fmt.Sprintf("svc:%s:%d", ip, port), "exposed-service", "ssh.example.test", "SSH (port 22) is reachable", "Shodan InternetDB")
	far := insertFinding(t, e, "svc:198.51.100.9:3306", "exposed-service", "db.example.test", "MySQL (port 3306) is reachable on db.example.test (198.51.100.9, on a network outside the expected ownership)", "Shodan InternetDB")
	tg, _ := e.store.GetTarget(1)
	e.eng.confirmOpenPorts(testCtx(t), tg, false, confirmFirstScan)
	fs, _ := e.store.ListFindings("example.test", "")
	for _, f := range fs {
		switch f.ID {
		case open:
			if f.VerifyState != verifyOpen || f.VerifyBanner != "SSH-2.0-test" || f.VerifyBy != "first scan" {
				t.Errorf("open port not confirmed: %+v", f)
			}
		case far:
			if f.VerifyState != "" {
				t.Error("an address outside the expected ownership must not be contacted")
			}
		}
	}
	if au, _, _ := e.store.ListAudit(AuditFilter{}); !strings.Contains(fmt.Sprint(au), "finding.verify") {
		t.Error("automatic checks must be audited")
	}
}
