package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCorroborationRules(t *testing.T) {
	cases := []struct {
		kind, sources, verify, confirm string
		want                           string
	}{
		{"exposed-service", "Shodan InternetDB", "", "", trustUnconfirmed},
		{"exposed-service", "Shodan InternetDB, Shodan", "", "", trustUnconfirmed}, // one dataset, two views
		{"exposed-service", "Shodan InternetDB, Censys", "", "", trustTrusted},
		{"exposed-service", "Shodan InternetDB", verifyOpen, "", trustTrusted},
		{"exposed-service", "Shodan InternetDB", verifyFiltered, "", trustDisputed},
		{"exposed-service", "Shodan InternetDB", verifyClosed, "", trustDisputed},
		{"exposed-service", "Shodan InternetDB, Censys", verifyClosed, "", trustTrusted}, // two sources still agree
		{"known-vuln", "Shodan InternetDB, Shodan", "", "", trustUnconfirmed},
		{"known-vuln", "Shodan InternetDB", verifyOpen, "", trustUnconfirmed}, // an open port does not prove a CVE
		{"known-vuln", "Shodan InternetDB", "", "alice", trustTrusted},
		{"ip-flagged", "Shodan tags", "", "", trustUnconfirmed},
		{"eol-software", "Shodan tags", "", "bob", trustTrusted},
		{"dns-spf-missing", "", "", "", ""}, // first-hand: nothing to corroborate
		{"domain-expiry", "RDAP", "", "", ""},
	}
	for _, c := range cases {
		got, fams := corroborate(c.kind, c.sources, c.verify, c.confirm)
		if got != c.want {
			t.Errorf("%s from %q (check %q, confirmed by %q) = %q (%v), want %q", c.kind, c.sources, c.verify, c.confirm, got, fams, c.want)
		}
	}
}

// A port reported by Shodan alone is unconfirmed: not counted and, once an active check
// agrees, trusted, counted and alerted. An analyst can confirm what no check can (a CVE).
func TestUnconfirmedFindingsAreHeldBack(t *testing.T) {
	e := newWebEnv(t)
	e.addTarget("example.test", "")
	ip, port := listen(t, "")
	svcKey := fmt.Sprintf("svc:%s:%d", ip, port)

	tx, err := e.store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][3]string{{svcKey, "exposed-service", "Shodan InternetDB"}, {"vuln:" + ip, "known-vuln", "Shodan InternetDB, Shodan"}} {
		if _, err := tx.UpsertFinding("example.test", f[0], f[1], "high", "host.example.test", "detail of "+f[0], f[2], nowUTC()); err != nil {
			t.Fatal(err)
		}
		if level, _, err := tx.UpdateTrust(f[0], f[2]); err != nil || level != trustUnconfirmed {
			t.Fatalf("%s: %q %v", f[0], level, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	st, _ := e.store.Stats()
	if st.OpenFindings != 0 || st.HighFindings != 0 || st.UnconfirmedFindings != 2 {
		t.Fatalf("unconfirmed findings must not be counted: %+v", st)
	}
	if _, counts, _ := e.store.TargetCounts(); counts["example.test"]["high"] != 0 {
		t.Errorf("per-domain counts include unconfirmed findings: %v", counts)
	}

	// The automatic check after a scan connects to the port: two sources now agree.
	tg, _ := e.store.GetTarget(1)
	e.eng.confirmOpenPorts(testCtx(t), tg, false, confirmAuto)
	byKey := map[string]Finding{}
	fs, _ := e.store.ListFindings("example.test", "")
	for _, f := range fs {
		byKey[f.Key] = f
	}
	if f := byKey[svcKey]; f.Trust != trustTrusted || f.TrustSources != "Shodan, Active check" || f.VerifyBy != confirmAuto {
		t.Fatalf("port not corroborated: %+v", f)
	}
	if st, _ = e.store.Stats(); st.OpenFindings != 1 || st.UnconfirmedFindings != 1 {
		t.Errorf("a trusted finding must be counted: %+v", st)
	}
	var queued int
	_ = e.store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE notified=0 AND muted=0 AND detail LIKE 'Now confirmed by a second source%'`).Scan(&queued)
	if queued != 1 {
		t.Errorf("becoming trusted must queue one alert, got %d", queued)
	}

	// Trusted ports and ports checked recently are not contacted again.
	e.eng.confirmOpenPorts(testCtx(t), tg, false, confirmAuto)
	if au, _, _ := e.store.ListAudit(AuditFilter{}); strings.Count(fmt.Sprint(au), "finding.verify") != 1 {
		t.Errorf("the automatic check should run once per unconfirmed port: %v", au)
	}

	// No check can prove a CVE: an analyst confirms it, saying how, and can take it back.
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	vid := byKey["vuln:"+ip].ID
	_, page, _ := admin.get("/findings")
	for _, want := range []string{"Unconfirmed", "only Shodan", "Mark as confirmed", "Trusted", "Shodan, Active check agree", `name="trust"`} {
		if !strings.Contains(page, want) {
			t.Errorf("findings page lacks %q", want)
		}
	}
	if _, page, _ = admin.get("/findings?trust=unconfirmed"); strings.Contains(page, svcKey) || !strings.Contains(page, "Mark as confirmed") {
		t.Error("the unconfirmed filter should show only the vulnerability finding")
	}
	admin.post(fmt.Sprintf("/findings/%d/confirm", vid), url.Values{"note": {"short"}})
	if f := trustFinding(t, e, vid); f.Trust != trustUnconfirmed {
		t.Error("a confirmation without a proper note must be refused")
	}
	admin.post(fmt.Sprintf("/findings/%d/confirm", vid), url.Values{"note": {"Apache 2.4.49 is installed; CVE-2021-41773 applies"}})
	if f := trustFinding(t, e, vid); f.Trust != trustTrusted || f.ConfirmBy != "admin" || !strings.Contains(f.TrustSources, "Analyst (admin)") {
		t.Errorf("analyst confirmation not recorded: %+v", f)
	}
	if au, _, _ := e.store.ListAudit(AuditFilter{}); !strings.Contains(fmt.Sprint(au), "finding.confirm") {
		t.Error("confirmations must be audited")
	}
	admin.post(fmt.Sprintf("/findings/%d/confirm", vid), url.Values{"action": {"remove"}})
	if f := trustFinding(t, e, vid); f.Trust != trustUnconfirmed || f.ConfirmBy != "" {
		t.Errorf("confirmation not removed: %+v", f)
	}
}

func trustFinding(t *testing.T, e *webEnv, id int64) Finding {
	t.Helper()
	fs, err := e.store.ListFindings("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %d not found", id)
	return Finding{}
}

// A scan that finds a port in InternetDB alone records it without alerting.
func TestScanHoldsBackSingleSourceFindings(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{3389}, []string{"CVE-2021-41773"}, nil)
	tg := h.addTarget("example.test", "AS64500")
	if tg = h.scan(tg.ID); tg.LastStatus != "ok" {
		t.Fatalf("scan failed: %q %q", tg.LastStatus, tg.LastError)
	}
	open := h.findingsOf("open")
	for _, k := range []string{"svc:203.0.113.10:3389", "vuln:203.0.113.10"} {
		if f := open[k]; f.Trust != trustUnconfirmed {
			t.Errorf("%s: trust %q, want unconfirmed", k, f.Trust)
		}
	}
	for _, m := range h.mails() {
		if strings.Contains(m.Plain, "3389") || strings.Contains(m.Plain, "CVE-2021-41773") {
			t.Errorf("a single-source finding was alerted:\n%s", m.Plain)
		}
	}
	var muted int
	_ = h.store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE muted=1 AND detail LIKE 'Unconfirmed, one source only%'`).Scan(&muted)
	if muted != 2 {
		t.Errorf("single-source findings should be in the change log, unalerted: %d", muted)
	}
}

// Findings stored by an earlier version get a trust level when the database is opened.
func TestTrustBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := nowUTC()
	for _, f := range [][3]string{{"svc:203.0.113.5:445", "exposed-service", "Shodan InternetDB, Censys"}, {"vuln:203.0.113.5", "known-vuln", "Shodan InternetDB"}, {"spf:example.test", "spf-missing", ""}} {
		if _, err := s.db.Exec(`INSERT INTO findings(key,root,kind,severity,scan_sev,host,detail,first_seen,last_seen,source) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			f[0], "example.test", f[1], "high", "high", "h", "d", now, now, f[2]); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	if s, err = OpenStore(path); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	fs, _ := s.ListFindings("", "")
	want := map[string]string{"svc:203.0.113.5:445": trustTrusted, "vuln:203.0.113.5": trustUnconfirmed, "spf:example.test": ""}
	for _, f := range fs {
		if f.Trust != want[f.Key] {
			t.Errorf("%s: trust %q, want %q", f.Key, f.Trust, want[f.Key])
		}
	}
}

// Once the agent leaves its console, log lines go to a file instead.
func TestLogSinkLeavesConsole(t *testing.T) {
	var console strings.Builder
	s := &logSink{console: &console}
	_, _ = s.Write([]byte("before\n"))
	file := filepath.Join(t.TempDir(), "easm.log")
	got, err := s.leaveConsole(file)
	if err != nil || got != file {
		t.Fatalf("leaveConsole = %q, %v", got, err)
	}
	_, _ = s.Write([]byte("after\n"))
	s.close()
	b, _ := os.ReadFile(file)
	if console.String() != "before\n" || string(b) != "after\n" {
		t.Errorf("console %q, file %q", console.String(), b)
	}
}

func TestOpenLogFileRotates(t *testing.T) {
	file := filepath.Join(t.TempDir(), "easm.log")
	if err := os.WriteFile(file, make([]byte, maxLogBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openLogFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if st, err := os.Stat(file + ".1"); err != nil || st.Size() != maxLogBytes+1 {
		t.Errorf("the full log should be kept as .1: %v", err)
	}
	if st, _ := os.Stat(file); st.Size() != 0 {
		t.Error("a fresh log should be started")
	}
}
