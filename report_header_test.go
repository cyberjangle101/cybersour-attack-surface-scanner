package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Every report says whose it is (organisation, domains) and who prepared it.
func TestReportHeaderNamesOwnerAndPreparer(t *testing.T) {
	e := newWebEnv(t)
	seedReportData(t, e.harness)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")

	// No organisation set: a single-domain report is headed by the domain.
	_, body, _ := admin.get("/report?target=example.test&days=7")
	if !strings.Contains(body, "<h1>example.test</h1>") || !strings.Contains(body, "Prepared by admin (admin)") {
		t.Error("report without an organisation should be headed by its domain and name the preparer")
	}

	// The organisation is set through the Settings form.
	if _, page, _ := admin.get("/settings"); !strings.Contains(page, `name="org_name"`) {
		t.Fatal("Settings has no organisation name field")
	}
	cur, _ := e.store.LoadSettings()
	if code, _, _ := admin.post("/settings", settingsFormWith(cur, map[string]string{"org_name": "  Acme   Widgets Ltd "})); code != 303 {
		t.Fatalf("saving the organisation name: %d", code)
	}
	if got, _ := e.store.LoadSettings(); got.OrgName != "Acme Widgets Ltd" {
		t.Fatalf("organisation name stored as %q", got.OrgName)
	}

	_, body, _ = admin.get("/report?days=7")
	for _, want := range []string{"<h1>Acme Widgets Ltd</h1>", "Domains: example.test", "Prepared by admin (admin)"} {
		if !strings.Contains(body, want) {
			t.Errorf("report page lacks %q", want)
		}
	}

	// JSON export carries the same header fields.
	_, raw, _ := admin.get("/report.json?days=7")
	var rep struct {
		Organisation string   `json:"organisation"`
		Domains      []string `json:"domains"`
		PreparedBy   string   `json:"prepared_by"`
	}
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Organisation != "Acme Widgets Ltd" || len(rep.Domains) == 0 || rep.PreparedBy != "admin (admin)" {
		t.Errorf("JSON header: %+v", rep)
	}

	// A viewer's copy names the viewer.
	v := e.signedIn("vic", RoleViewer)
	if _, vb, _ := v.get("/report?days=7"); !strings.Contains(vb, "Prepared by vic (viewer)") {
		t.Error("viewer's report does not name the viewer")
	}

	// The PDF renders with the header (text checked by UAT with pdftotext).
	code, pdf, r := admin.get("/report.pdf?days=7")
	if code != 200 || !strings.HasPrefix(pdf, "%PDF-") || r.Header.Get("Content-Type") != "application/pdf" {
		t.Errorf("PDF with organisation header: %d", code)
	}
	if out := os.Getenv("EASM_PDF_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(pdf), 0o600)
	}

	// The scheduled digest has no person behind it.
	full, err := BuildReport(e.store, "", time.Now().Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := e.store.LoadSettings()
	_, plain, html := renderDigest(full, st.Runtime(""))
	for _, part := range []string{plain, html} {
		if !strings.Contains(part, "Acme Widgets Ltd") || !strings.Contains(part, "prepared by EASM Agent (scheduled digest)") {
			t.Errorf("digest header lacks organisation or preparer:\n%.400s", part)
		}
	}
}

func TestOrgNameValidation(t *testing.T) {
	for name, ok := range map[string]bool{
		"Acme Ltd":               true,
		"Société Générale":       true,
		"":                       true,
		strings.Repeat("a", 120): true,
		strings.Repeat("a", 121): false,
		"Acme\u202eetaroproC":    false, // right-to-left override would disguise the name
		"Acme\x00Ltd":            false,
		"Acme\nInjected: header": true, // newlines are folded into spaces
	} {
		s := DefaultSettings()
		s.OrgName = name
		err := s.Normalize()
		if (err == nil) != ok {
			t.Errorf("OrgName %q: err=%v, want ok=%v", name, err, ok)
		}
		if err == nil && strings.ContainsAny(s.OrgName, "\r\n\t") {
			t.Errorf("OrgName %q kept a line break: %q", name, s.OrgName)
		}
	}
}
