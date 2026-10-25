package main

import (
	"net/url"
	"strings"
	"testing"
)

// A report for a domain that is not monitored is refused, not silently widened to all targets.
func TestReportUnknownTarget(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)
	admin := e.signedIn("boss", RoleAdmin)

	for _, p := range []string{"/report", "/report.json", "/report.pdf", "/report/findings.csv",
		"/report/inventory.csv", "/report/findings.sarif", "/report/findings.stix.json"} {
		for _, bad := range []string{"nope.test", "EXAMPLE.TEST", "example.test'--", "x"} {
			code, body, _ := admin.get(p + "?target=" + url.QueryEscape(bad) + "&days=7")
			if code != 404 || !strings.Contains(body, "Unknown domain") {
				t.Errorf("%s?target=%s: want 404 Unknown domain, got %d %.120s", p, bad, code, body)
			}
		}
		// the known domain and the empty (all domains) selection still work
		for _, q := range []string{"?target=example.test&days=7", "?days=7", "?target=&days=7"} {
			if code, _, _ := admin.get(p + q); code != 200 {
				t.Errorf("%s%s: %d", p, q, code)
			}
		}
	}

	tok := makeToken(t, e, admin, "rep", RoleViewer, "")
	if c, b := apiDo(t, e, "GET", "/api/v1/report?target=nope.test", tok, ""); c != 404 || !strings.Contains(b, "unknown domain") {
		t.Errorf("API unknown target: %d %s", c, b)
	}
	for _, q := range []string{"", "?target=example.test"} {
		if c, b := apiDo(t, e, "GET", "/api/v1/report"+q, tok, ""); c != 200 {
			t.Errorf("API report%s: %d %.120s", q, c, b)
		}
	}
}
