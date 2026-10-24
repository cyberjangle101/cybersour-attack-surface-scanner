package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// cleanMailDNS publishes everything the email and DNS hygiene checks look for, so a fixture domain has no such findings.
func cleanMailDNS(t testing.TB, d *fakeDNS, domain string) {
	t.Helper()
	d.add(t, fmt.Sprintf(`_dmarc.%s. 60 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@%s"`, domain, domain))
	d.add(t, fmt.Sprintf(`default._domainkey.%s. 60 IN TXT "v=DKIM1; k=rsa; p=AAAA"`, domain))
	d.add(t, fmt.Sprintf(`_mta-sts.%s. 60 IN TXT "v=STSv1; id=1"`, domain))
	d.add(t, fmt.Sprintf(`_smtp._tls.%s. 60 IN TXT "v=TLSRPTv1; rua=mailto:tls@%s"`, domain, domain))
	d.add(t, fmt.Sprintf(`%s. 60 IN CAA 0 issue "ca.test"`, domain))
	d.add(t, fmt.Sprintf(`%s. 60 IN DS 12345 13 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC1234`, domain))
}

func (h *harness) seedExample() {
	t := h.t
	d := h.dns
	d.add(t, "example.test. 60 IN A 203.0.113.10")
	d.add(t, `example.test. 60 IN TXT "v=spf1 include:_spf.example.net -all"`)
	d.add(t, "example.test. 60 IN MX 10 mail.example.test.")
	cleanMailDNS(t, d, "example.test")
	d.add(t, "www.example.test. 60 IN A 203.0.113.10")
	d.add(t, "api.example.test. 60 IN A 198.51.100.7")
	d.addIP(t, "203.0.113.10", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	d.addIP(t, "198.51.100.7", 64999, "198.51.100.0/24", "OTHER-HOSTING")
	h.src.addCert("example.test", "www.example.test")
	h.src.addAnubis("api.example.test")
}

func TestEndToEndDeltaAlerting(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")

	// ---- 1. baseline: inventory silent, ownership finding still alerts
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" || !tg.Baselined() {
		t.Fatalf("after first scan: status=%q err=%q baselined=%v", tg.LastStatus, tg.LastError, tg.Baselined())
	}
	inv, total, err := h.store.Inventory("example.test", "", 100)
	if err != nil || total != 3 {
		t.Fatalf("inventory total=%d err=%v rows=%+v", total, err, inv)
	}
	for _, row := range inv {
		if row.Host == "www.example.test" {
			if len(row.Addrs) != 1 || row.Addrs[0].ASN != 64500 || !strings.Contains(row.Addrs[0].Org, "EXAMPLE-NET") {
				t.Errorf("www addr/ASN mapping wrong: %+v", row.Addrs)
			}
		}
	}
	mails := h.mails()
	if len(mails) != 2 {
		t.Fatalf("baseline should send the summary + one finding alert, got %d mails", len(mails))
	}
	var alert parsedMail
	for _, m := range mails {
		if strings.Contains(m.Subject, "baseline established") {
			continue
		}
		alert = m
	}
	if !strings.Contains(alert.Plain, "api.example.test") || !strings.Contains(alert.Plain, "asn-unexpected") ||
		strings.Contains(alert.Plain, "www.example.test") {
		t.Errorf("baseline alert should only contain the api ASN finding:\n%s", alert.Plain)
	}
	if !strings.Contains(alert.HTML, "<table") {
		t.Error("alert has no HTML table")
	}
	if pend, _ := h.store.PendingEvents(); len(pend) != 0 {
		t.Errorf("events still pending after successful send: %d", len(pend))
	}
	if evs, _, _ := h.store.ListEvents(EventFilter{Root: "example.test", Limit: 100}); len(evs) != 1 {
		t.Errorf("only the finding should be a visible (non-baseline) event, got %d", len(evs))
	}

	// ---- 2. delta: new subdomain, new IP on an existing host, dangling CNAME takeover candidate
	h.dns.add(t, "new.example.test. 60 IN A 203.0.113.20")
	h.dns.addIP(t, "203.0.113.20", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.dns.add(t, "www.example.test. 60 IN A 203.0.113.11")
	h.dns.addIP(t, "203.0.113.11", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.dns.add(t, "old.example.test. 60 IN CNAME dead-app.github.io.")
	h.src.addAnubis("new.example.test", "old.example.test")
	h.src.addCert("new.example.test")
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("second scan: %q %q", tg.LastStatus, tg.LastError)
	}
	mails = h.mails()
	if len(mails) != 3 {
		t.Fatalf("delta scan should send exactly one more mail, total=%d", len(mails))
	}
	d := mails[2].Plain
	for _, want := range []string{"new.example.test", "203.0.113.11", "dangling-cname", "github.io", "cert"} {
		if !strings.Contains(d, want) {
			t.Errorf("delta alert missing %q:\n%s", want, d)
		}
	}
	if strings.Contains(d, "api.example.test") {
		t.Errorf("old finding was re-alerted:\n%s", d)
	}
	if !strings.Contains(mails[2].Subject, "HIGH") {
		t.Errorf("subject should show highest severity: %q", mails[2].Subject)
	}

	// ---- 3. nothing changed => silence
	h.scan(tg.ID)
	if n := h.smtp.count(); n != 3 {
		t.Fatalf("unchanged scan sent mail (total %d)", n)
	}

	// ---- 4. dangling alias fixed => finding auto-resolves, no alert
	h.dns.remove("old.example.test", dns.TypeCNAME)
	h.dns.add(t, "old.example.test. 60 IN A 203.0.113.30")
	h.dns.addIP(t, "203.0.113.30", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.scan(tg.ID)
	fs, _ := h.store.ListFindings("example.test", "resolved")
	if len(fs) != 1 || fs[0].Kind != "dangling-cname" {
		t.Errorf("dangling finding should be resolved, got %+v", fs)
	}
	open, _ := h.store.ListFindings("example.test", "open")
	if len(open) != 1 || open[0].Kind != "asn-unexpected" {
		t.Errorf("the ASN finding should remain open, got %+v", open)
	}
	// the new A record on old.example.test is itself a delta and may mail; record the count
	base := h.smtp.count()

	// ---- 5. SMTP outage: events queue, scan still succeeds, nothing is lost
	h.smtp.stop()
	h.dns.add(t, "late.example.test. 60 IN A 203.0.113.40")
	h.dns.addIP(t, "203.0.113.40", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.src.addAnubis("late.example.test")
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan must survive SMTP outage: %q %q", tg.LastStatus, tg.LastError)
	}
	if pend, _ := h.store.PendingEvents(); len(pend) == 0 {
		t.Fatal("events should stay queued while SMTP is down")
	}
	h.smtp.restart(t)
	h.scan(tg.ID) // no new changes; the flush at the end of the scan delivers the backlog
	if pend, _ := h.store.PendingEvents(); len(pend) != 0 {
		t.Errorf("backlog not delivered after SMTP recovery: %d pending", len(pend))
	}
	all := h.mails()
	if len(all) != base+1 || !strings.Contains(all[len(all)-1].Plain, "late.example.test") {
		t.Errorf("recovery mail missing late.example.test (mails %d, base %d)", len(all), base)
	}
}

func TestCrtShOutageKeepsBaselineOpen(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.src.setCrtStatus(500) // crt.sh down: other sources still answer
	tg := h.addTarget("example.test", "")
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan should degrade gracefully: %q %q", tg.LastStatus, tg.LastError)
	}
	if tg.Baselined() {
		t.Fatal("baseline must NOT be finalised while crt.sh is failing")
	}
	// while not baselined, new hosts are recorded silently
	before := h.smtp.count()
	h.src.addAnubis("surprise.example.test")
	h.dns.add(t, "surprise.example.test. 60 IN A 203.0.113.50")
	h.dns.addIP(t, "203.0.113.50", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.scan(tg.ID)
	if h.smtp.count() != before {
		t.Errorf("silent baseline mode leaked an alert")
	}
	h.src.setCrtStatus(0)
	tg = h.scan(tg.ID)
	if !tg.Baselined() {
		t.Fatal("baseline should complete once crt.sh recovers")
	}
	// still silent about everything that existed when baseline completed
	for _, m := range h.mails()[before:] {
		if strings.Contains(m.Plain, "surprise.example.test") && !strings.Contains(m.Subject, "baseline") {
			t.Errorf("baseline flood: %s", m.Subject)
		}
	}
}

func TestAllSourcesFailRecordsErrorAndRetriesSoon(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.src.setCrtStatus(500)
	st, _ := h.store.LoadSettings()
	st.HackerTargetEnabled, st.OTXEnabled, st.AnubisEnabled = false, false, false
	h.saveSettings(st)
	tg := h.addTarget("example.test", "")
	tg = h.scan(tg.ID)
	if tg.LastStatus != "error" || !strings.Contains(tg.LastError, "all discovery sources failed") {
		t.Fatalf("expected a recorded error, got %q / %q", tg.LastStatus, tg.LastError)
	}
	next, _ := time.Parse(time.RFC3339, tg.NextScan)
	if time.Until(next) > 36*time.Minute {
		t.Errorf("failed scans should retry within ~30m, next scan in %v", time.Until(next))
	}
	if _, total, _ := h.store.Inventory("example.test", "", 10); total != 0 {
		t.Errorf("a failed scan must store nothing, got %d hosts", total)
	}
}

func TestSchedulerRunsDueTargetsAndReschedules(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "")
	h.runDueAndWait(t)
	got, _ := h.store.GetTarget(tg.ID)
	if got.LastStatus != "ok" {
		t.Fatalf("due target not scanned: %q %q", got.LastStatus, got.LastError)
	}
	next, _ := time.Parse(time.RFC3339, got.NextScan)
	if d := time.Until(next); d < 5*time.Hour || d > 7*time.Hour {
		t.Errorf("next scan should be ~6h out (default interval + jitter), got %v", d)
	}
	if due, _ := h.store.DueTargets(nowUTC()); len(due) != 0 {
		t.Errorf("target is still due right after scanning")
	}
	// per-target interval override
	tg2, _ := TargetFromForm("other.test", "", "", "", "30", "")
	id2, _ := h.store.AddTarget(tg2)
	h.src.addCert("other.test")
	h.dns.add(t, "other.test. 60 IN A 203.0.113.60")
	h.dns.addIP(t, "203.0.113.60", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.runDueAndWait(t)
	g2, _ := h.store.GetTarget(id2)
	n2, _ := time.Parse(time.RFC3339, g2.NextScan)
	if d := time.Until(n2); d < 25*time.Minute || d > 40*time.Minute {
		t.Errorf("30-minute override ignored: next scan in %v", d)
	}
	// RequestScan + pause semantics
	if ok, _ := h.store.RequestScan(tg.ID); !ok {
		t.Error("RequestScan should succeed for an idle enabled target")
	}
	if due, _ := h.store.DueTargets(nowUTC()); len(due) != 1 {
		t.Errorf("requested scan should be due, got %d", len(due))
	}
	_ = h.store.SetTargetEnabled(tg.ID, false)
	if due, _ := h.store.DueTargets(nowUTC()); len(due) != 0 {
		t.Error("paused targets must never be due")
	}
}

func TestRecoverFromCrashMidScan(t *testing.T) {
	h := newHarness(t)
	tg := h.addTarget("example.test", "")
	_ = h.store.MarkRunning(tg.ID, nowUTC()) // simulate the process dying mid-scan
	if due, _ := h.store.DueTargets(nowUTC()); len(due) != 0 {
		t.Fatal("a running target must not be picked up twice")
	}
	_ = h.store.ResetRunning()
	got, _ := h.store.GetTarget(tg.ID)
	if got.LastStatus != "interrupted" {
		t.Errorf("status %q", got.LastStatus)
	}
	if due, _ := h.store.DueTargets(nowUTC()); len(due) != 1 {
		t.Error("interrupted target should be due again")
	}
}

func TestDeleteTargetRemovesEverything(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")
	h.scan(tg.ID)
	if err := h.store.DeleteTarget(tg.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"subdomains", "records", "certs", "findings", "events", "scans"} {
		var n int
		if err := h.store.db.QueryRow("SELECT COUNT(*) FROM " + q).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows left (err %v)", q, n, err)
		}
	}
	if _, ok, _ := h.store.getMeta("baselined:example.test"); ok {
		t.Error("baseline marker left behind")
	}
	// re-adding starts from a fresh baseline
	tg2 := h.addTarget("example.test", "")
	if tg2.Baselined() {
		t.Error("re-added target should not be baselined")
	}
}

func TestOverlappingTargetsRejected(t *testing.T) {
	h := newHarness(t)
	h.addTarget("example.test", "")
	for _, d := range []string{"example.test", "sub.example.test"} {
		tg, _ := TargetFromForm(d, "", "", "", "", "")
		if _, err := h.store.AddTarget(tg); err == nil {
			t.Errorf("%s should be rejected as duplicate/overlap", d)
		}
	}
	tg, _ := TargetFromForm("test", "", "", "", "", "")
	if tg != nil {
		t.Error("single-label domain accepted")
	}
}

func TestIgnoreSubdomainsAndWildcard(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.src.addAnubis("ci-123.example.test")
	h.dns.add(t, "ci-123.example.test. 60 IN A 203.0.113.70")
	tg, err := TargetFromForm("example.test", "", "", `^ci-\d+\.example\.test$`, "", "")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := h.store.AddTarget(tg)
	h.scan(id)
	if _, total, _ := h.store.Inventory("example.test", "ci-", 10); total != 0 {
		t.Errorf("ignored subdomain was recorded")
	}
	// wildcard DNS: random names resolve; wildcard answers must not create records/alerts
	h.dns.add(t, "*.wild.test. 60 IN A 203.0.113.80")
}
