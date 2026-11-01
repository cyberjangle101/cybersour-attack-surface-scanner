package main

import (
	"strings"
	"testing"
)

// Threat-intelligence checks (look-alikes, public code, leaked accounts) look outside the
// organisation's own attack surface, so they are off by default and grouped apart in Settings.

func TestThreatIntelOffByDefault(t *testing.T) {
	d := DefaultSettings()
	for _, c := range threatIntelChecks {
		if c.on(d) {
			t.Errorf("%s must be off by default", c.label)
		}
	}
	for _, kind := range []string{"lookalike-domain", "repo-exposure", "leaked-credentials"} {
		if r, ok := ruleIndex[kind]; !ok || r.Category != "Threat intelligence (off by default)" {
			t.Errorf("%s: rule category %q", kind, r.Category)
		}
	}
}

func TestSettingsGroupThreatIntel(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	_, body, _ := b.get("/settings")
	i := strings.Index(body, `id="threatintel"`)
	if i < 0 {
		t.Fatal("no Threat intelligence section")
	}
	section := body[i:]
	if j := strings.Index(section[1:], `<section`); j > 0 {
		section = section[:j+1]
	}
	for _, field := range []string{`name="lookalike_enabled"`, `name="github_enabled"`, `name="hibp_enabled"`, "off by default"} {
		if !strings.Contains(section, field) {
			t.Errorf("Threat intelligence section lacks %s", field)
		}
		if field != "off by default" && strings.Count(body, field) != 1 {
			t.Errorf("%s appears %d times on the page", field, strings.Count(body, field))
		}
	}
}

func TestSwitchingOffThreatIntelClosesItsFindings(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	st, _ := e.store.LoadSettings()
	st.LookalikeEnabled = true
	if err := e.store.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	open := insertFinding(t, e, "lookalike:example.test:exmaple.test", "lookalike-domain", "exmaple.test", "registered", "")
	accepted := insertFinding(t, e, "lookalike:example.test:examp1e.test", "lookalike-domain", "examp1e.test", "ours", "")
	if err := e.store.AcceptRisk(accepted, "admin", "our own defensive registration", ""); err != nil {
		t.Fatal(err)
	}
	other := insertFinding(t, e, "svc:203.0.113.5:3389", "exposed-service", "203.0.113.5", "RDP", "Shodan InternetDB")
	status := func(id int64) string {
		var s string
		_ = e.store.db.QueryRow(`SELECT status FROM findings WHERE id=?`, id).Scan(&s)
		return s
	}

	// Saving with it still on changes nothing.
	b.post("/settings", settingsForm(st))
	if status(open) != "open" {
		t.Fatal("a save that left the check on closed its findings")
	}

	form := settingsForm(st)
	form.Del("lookalike_enabled")
	if code, _, _ := b.post("/settings", form); code != 303 {
		t.Fatalf("save: %d", code)
	}
	if got, _ := e.store.LoadSettings(); got.LookalikeEnabled {
		t.Fatal("look-alike check not switched off")
	}
	if status(open) != "resolved" || status(accepted) != "ack" || status(other) != "open" {
		t.Errorf("after switching off: open=%s accepted=%s other=%s", status(open), status(accepted), status(other))
	}
	if _, page, _ := b.get("/settings"); !strings.Contains(page, "Closed 1 look-alike domains finding(s) because their check is now off") {
		t.Error("the save message should say what was closed")
	}
	if _, au, _ := b.get("/audit"); !strings.Contains(au, "findings.resolve") || !strings.Contains(au, "the look-alike domains check was switched off") {
		t.Error("closing findings must be audited")
	}
}
