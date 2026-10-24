package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestIDNIsConvertedToPunycode(t *testing.T) {
	for in, want := range map[string]string{
		"bücher.example":        "xn--bcher-kva.example",
		"BÜCHER.Example.":       "xn--bcher-kva.example",
		"www.bücher.example":    "www.xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"plain.example":         "plain.example",
		"пример.example":        "xn--e1afmkfd.example",
		"bad‮name.example":      "",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
	tg, err := TargetFromForm("bücher.example", "", "", "", "", "")
	if err != nil || tg.Domain != "xn--bcher-kva.example" {
		t.Fatalf("target from form: %v %+v", err, tg)
	}
	if root, ok := splitRegistrableOK("xn--bcher-kva.example"); !ok {
		t.Errorf("punycode root not registrable: %q", root)
	}
}

func splitRegistrableOK(d string) (string, bool) { l, _, ok := splitRegistrable(d); return l, ok }

func TestAlertEmailGroupsByHostAndLinks(t *testing.T) {
	cfg := &Config{PublicURL: "https://easm.example/", Alerts: AlertsCfg{MaxRows: 100}}
	cfg.SMTP.SubjectPrefix = "[EASM]"
	ev := []Event{
		{Root: "a.test", Host: "www.a.test", Kind: "tls-expiring", Severity: "medium", Detail: "cert soon"},
		{Root: "a.test", Host: "api.a.test", Kind: "exposed-path", Severity: "high", Detail: "/.git"},
		{Root: "a.test", Host: "www.a.test", Kind: "default-page", Severity: "low", Detail: "welcome page"},
		{Root: "a.test", Host: "lookalike.test", Kind: "lookalike-domain", Severity: "low", Detail: "registered"},
	}
	_, plain, html := renderAlert(ev, cfg)
	if i, j := strings.Index(plain, "api.a.test"), strings.Index(plain, "www.a.test"); i < 0 || j < 0 || i > j {
		t.Errorf("the host with the worst finding should come first:\n%s", plain)
	}
	if strings.Count(plain, "\nwww.a.test\n") != 1 {
		t.Errorf("a host should be named once, with its changes below it:\n%s", plain)
	}
	for _, w := range []string{"https://easm.example/events", "https://easm.example/findings",
		"https://easm.example/assets/view?id=api.a.test&type=domain"} {
		if !strings.Contains(plain, w) {
			t.Errorf("plain text lacks %s", w)
		}
	}
	if !regexp.MustCompile(`<a href="https://easm.example/assets/view\?id=www.a.test&amp;type=domain">www.a.test</a>`).MatchString(html) {
		t.Errorf("html lacks a host link:\n%s", html)
	}
	if strings.Contains(plain+html, "assets/view?id=lookalike.test") {
		t.Error("a domain that is not an asset must not get a link")
	}
	cfg.PublicURL = ""
	if _, p, h := renderAlert(ev, cfg); strings.Contains(p+h, "http") {
		t.Error("links appear although no public address is configured")
	}
}

func TestDashboardHasHeadingAndFindingsGroup(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)
	b := e.signedIn("boss", RoleAdmin)
	if _, body, _ := b.get("/"); strings.Count(body, "<h1") != 1 {
		t.Errorf("dashboard should have exactly one h1:\n%.300s", body)
	}
	_, flat, _ := b.get("/findings?group=host")
	if !strings.Contains(flat, `class="group"`) || !strings.Contains(flat, "finding(s)") {
		t.Errorf("grouped view lacks host headings:\n%s", flat)
	}
	_, plain, _ := b.get("/findings")
	if strings.Contains(plain, `class="group"`) {
		t.Error("group headings shown without asking")
	}
	_ = url.Values{}
}
