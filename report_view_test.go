package main

import (
	"bytes"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// seedReportData inserts a spread of findings across states, hosts and ages.
func seedReportData(t *testing.T, h *harness) {
	t.Helper()
	now := time.Now().UTC()
	ago := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	h.seedExample()
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	h.addTarget("second.test", "")
	type f struct{ key, kind, sev, host, detail, status, first, last string }
	rows := []f{
		{"k1", "dangling-cname", "high", "old.example.test", "old.example.test has a CNAME to missing.github.io, which does not exist", "open", ago(30 * time.Hour), ago(time.Hour)},
		{"k2", "dangling-cname", "high", "shop.example.test", "shop.example.test has a CNAME to gone.herokuapp.com", "open", ago(20 * 24 * time.Hour), ago(time.Hour)},
		{"k3", "asn-unexpected", "high", "api.example.test", "A 198.51.100.7 is announced by AS64999 OTHER-HOSTING outside the expected ownership", "open", ago(3 * 24 * time.Hour), ago(time.Hour)},
		{"k4", "email-auth", "medium", "example.test", "DMARC policy is p=none", "open", ago(40 * 24 * time.Hour), ago(time.Hour)},
		{"k5", "tls-expiring", "medium", "www.example.test", "certificate expires in 12 days", "open", ago(2 * 24 * time.Hour), ago(time.Hour)},
		{"k6", "default-page", "low", "test.example.test", "default web server page", "open", ago(5 * 24 * time.Hour), ago(time.Hour)},
		{"k7", "exposed-service", "medium", "db.example.test", "port 3306 (MySQL) is open to the internet", "resolved", ago(10 * 24 * time.Hour), ago(2 * time.Hour)},
		{"k8", "lookalike-domain", "low", "examp1e.test", "examp1e.test is registered", "ack", ago(60 * 24 * time.Hour), ago(time.Hour)},
		{"k9", "known-vuln", "high", "www.example.test", "nginx 1.14 has known vulnerabilities (CVE-2021-23017)", "resolved", ago(3 * 24 * time.Hour), ago(5 * time.Hour)},
		{"k10", "email-auth", "info", "example.test", "no MTA-STS policy", "open", ago(time.Hour), ago(time.Hour)},
	}
	for _, r := range rows {
		root := "example.test"
		if _, err := h.store.db.Exec(`INSERT INTO findings(key,root,kind,severity,host,detail,status,first_seen,last_seen,source) VALUES(?,?,?,?,?,?,?,?,?,'')`,
			"seed:"+r.key, root, r.kind, r.sev, r.host, r.detail, r.status, r.first, r.last); err != nil {
			t.Fatal(err)
		}
	}
	// the seeded email-auth rows need keys that the catalog understands
	_, _ = h.store.db.Exec(`UPDATE findings SET key='email:example.test:dmarc-p-none' WHERE key='seed:k4'`)
	_, _ = h.store.db.Exec(`UPDATE findings SET key='email:example.test:no-mta-sts' WHERE key='seed:k10'`)
}

func TestReportManagementView(t *testing.T) {
	h := newHarness(t)
	seedReportData(t, h)
	since := time.Now().Add(-7 * 24 * time.Hour)
	rep, err := BuildReportOpts(h.store, "", since, 100, ReportOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ex := rep.Exec
	// open: 3 high, 2 medium (dmarc, tls), 1 low, 1 info (the scan itself may add real findings, so check lower bounds)
	if ex.OpenBySev["high"] < 3 || ex.Rating != "Poor" || ex.RatingClass != "bad" {
		t.Errorf("exec summary = %+v", ex)
	}
	if ex.Resolved != 2 {
		t.Errorf("resolved this week = %d, want 2", ex.Resolved)
	}
	if ex.NewCount < 5 {
		t.Errorf("new this week = %d", ex.NewCount)
	}
	if ex.Accepted != 1 {
		t.Errorf("accepted = %d", ex.Accepted)
	}
	if len(ex.TopRisks) == 0 || ex.TopRisks[0].Severity != "high" || len(ex.Actions) == 0 || ex.Headline == "" {
		t.Errorf("top risks/actions missing: %+v", ex.TopRisks)
	}
	if len(ex.Trend) != 7 {
		t.Errorf("a one-week report should have daily buckets, got %d", len(ex.Trend))
	}
	newTotal, fixed := 0, 0
	for _, b := range ex.Trend {
		newTotal += b.New
		fixed += b.Resolved
	}
	if fixed != 2 || newTotal != ex.NewCount {
		t.Errorf("trend totals new=%d (want %d) fixed=%d (want 2)", newTotal, ex.NewCount, fixed)
	}
	// grouped views
	var dang *FindingGroup
	for i := range rep.ByFinding {
		if strings.Contains(rep.ByFinding[i].Title, "alias") || strings.Contains(strings.ToLower(rep.ByFinding[i].Title), "dangling") || rep.ByFinding[i].Items[0].Kind == "dangling-cname" {
			dang = &rep.ByFinding[i]
		}
	}
	if dang == nil || dang.Assets != 2 || len(dang.Items) != 2 || dang.Severity != "high" {
		t.Fatalf("group by finding wrong: %+v", dang)
	}
	if rep.ByFinding[0].Severity != "high" {
		t.Error("groups must be ordered worst first")
	}
	hostsSeen := map[string]bool{}
	for _, g := range rep.ByAsset {
		hostsSeen[g.Host] = true
	}
	if !hostsSeen["old.example.test"] || !hostsSeen["www.example.test"] {
		t.Errorf("group by asset wrong: %v", hostsSeen)
	}
	if len(rep.ResolvedFindings) != 2 {
		t.Errorf("resolved list = %d", len(rep.ResolvedFindings))
	}

	// the severity filter narrows the detail sections only
	high, err := BuildReportOpts(h.store, "", since, 100, ParseSeverityFilter([]string{"high"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range append(append(high.Findings, high.NewFindings...), high.ResolvedFindings...) {
		if f.Severity != "high" {
			t.Errorf("filter leaked a %s finding", f.Severity)
		}
	}
	for _, g := range high.ByAsset {
		for _, f := range g.Findings {
			if f.Severity != "high" {
				t.Errorf("by-asset leaked %s", f.Severity)
			}
		}
	}
	if high.Exec.Open != rep.Exec.Open || high.Exec.OpenBySev["medium"] != rep.Exec.OpenBySev["medium"] {
		t.Error("the executive summary must not change with the filter")
	}
	if len(high.Findings) >= len(rep.Findings) || high.Filter.Label() != "High only" {
		t.Errorf("filter had no effect: %d vs %d (%s)", len(high.Findings), len(rep.Findings), high.Filter.Label())
	}
	if all := ParseSeverityFilter([]string{"high", "medium", "low", "info"}); all.Sev != nil {
		t.Error("selecting everything means no filter")
	}
	if ParseSeverityFilter([]string{"bogus"}).Sev != nil {
		t.Error("unknown values must be ignored")
	}
}

func TestReportPDF(t *testing.T) {
	h := newHarness(t)
	seedReportData(t, h)
	rep, err := BuildReportOpts(h.store, "", time.Now().Add(-7*24*time.Hour), 100, ReportOpts{})
	if err != nil {
		t.Fatal(err)
	}
	rep.Days = 7
	pdf, err := RenderReportPDF(rep, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf[len(pdf)-64:], []byte("%%EOF")) || len(pdf) < 5000 {
		t.Fatalf("not a plausible PDF (%d bytes)", len(pdf))
	}
	if out := os.Getenv("EASM_PDF_OUT"); out != "" {
		_ = os.WriteFile(out, pdf, 0o600)
	}
	// hostile text must not break the document
	rep.Findings = append(rep.Findings, Finding{Kind: "dangling-cname", Severity: "high", Host: "xn--bcher-kva.example.test", Root: "example.test",
		Detail: strings.Repeat("Ünïcödé ✓ 日本語 <script>alert(1)</script> ", 60), Status: "open"})
	rep.ByFinding = groupByFinding(rep.Findings)
	if _, err := RenderReportPDF(rep, "test"); err != nil {
		t.Fatalf("odd characters broke the PDF: %v", err)
	}
	// an empty report still renders
	empty := newHarness(t)
	er, _ := BuildReportOpts(empty.store, "", time.Now().Add(-24*time.Hour), 10, ReportOpts{})
	er.Days = 1
	if _, err := RenderReportPDF(er, "test"); err != nil {
		t.Fatalf("empty report: %v", err)
	}
}

func TestReportPageAndPDFDownload(t *testing.T) {
	e := newWebEnv(t)
	seedReportData(t, e.harness)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	code, body, _ := b.get("/report?days=30")
	if code != 200 {
		t.Fatalf("report: %d", code)
	}
	for _, want := range []string{"Executive summary", "Biggest risks", "Priority actions", `class="chart donut"`, `class="chart trend"`, `class="chart hbar"`,
		"New findings in the last 30 day(s)", "Resolved findings in the last 30 day(s)", "Grouped by finding", "Grouped by asset", `name="sev" value="high"`, "Download PDF"} {
		if !strings.Contains(body, want) {
			t.Errorf("report page is missing %q", want)
		}
	}
	if out := os.Getenv("EASM_HTML_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(body), 0o600)
	}
	// filtered view: low/medium findings vanish from the detail but the summary stays
	_, hi, _ := b.get("/report?days=30&sev=high")
	if !strings.Contains(hi, "High only") || strings.Contains(hi, "default web server page") {
		t.Error("high-only filter not applied to the detail sections")
	}
	if !strings.Contains(hi, `value="high" checked`) || strings.Contains(hi, `value="low" checked`) {
		t.Error("filter checkboxes do not reflect the selection")
	}
	// PDF download
	code, pdf, resp := b.get("/report.pdf?days=30&sev=high")
	if code != 200 || resp.Header.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(pdf, "%PDF-") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "easm-report-all-") {
		t.Fatalf("pdf: %d %v", code, resp.Header)
	}
	// target scoped
	if code, _, _ = b.get("/report.pdf?target=" + url.QueryEscape("example.test") + "&days=7"); code != 200 {
		t.Errorf("scoped pdf: %d", code)
	}
	// the filter also reaches the CSV export
	_, csvAll, _ := b.get("/report/findings.csv?days=30")
	_, csvHigh, _ := b.get("/report/findings.csv?days=30&sev=high")
	if strings.Count(csvHigh, "\n") >= strings.Count(csvAll, "\n") {
		t.Errorf("severity filter should reduce the CSV (%d vs %d lines)", strings.Count(csvHigh, "\n"), strings.Count(csvAll, "\n"))
	}
}
