package main

import (
	"net/http"
	"testing"
)

// hostile lists strings that would break out of a quoted SQL value or abuse LIKE.
var hostile = []string{
	"' OR '1'='1", "'; DROP TABLE subdomains; --", `" OR ""="`, "x' UNION SELECT password_hash,2,3,4,5 FROM users --",
	"%", "_", `\`, "a%b_c", "\x00", "1; DELETE FROM targets", "') OR 1=1 --",
}

// TestHostileInputCannotAlterQueries pushes injection payloads through every
// filtered store query and checks the data and schema are untouched afterwards.
func TestHostileInputCannotAlterQueries(t *testing.T) {
	h := newHarness(t)
	s := h.store
	if _, err := s.AddTarget(&Target{Domain: "example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range hostile {
		if _, _, err := s.Inventory(p, p, 50); err != nil {
			t.Errorf("Inventory(%q): %v", p, err)
		}
		if _, _, err := s.ListCerts(p, 50); err != nil {
			t.Errorf("ListCerts(%q): %v", p, err)
		}
		if _, err := s.ListFindings(p, p); err != nil {
			t.Errorf("ListFindings(%q): %v", p, err)
		}
		if _, _, err := s.ListEvents(EventFilter{Root: p, Kind: p, MinSeverity: p, Since: p, Limit: 10}); err != nil {
			t.Errorf("ListEvents(%q): %v", p, err)
		}
		if _, err := s.ListScans(p, 10); err != nil {
			t.Errorf("ListScans(%q): %v", p, err)
		}
		for _, typ := range []string{"", "domain", "ip", "service", "certificate", "dns", "vulnerability", "registration"} {
			if _, _, err := s.ListAssets(p, typ, p); err != nil {
				t.Errorf("ListAssets(%q,%q): %v", p, typ, err)
			}
		}
		if _, err := s.LoadIntel([]string{p}); err != nil {
			t.Errorf("LoadIntel(%q): %v", p, err)
		}
		if _, err := s.GetUserByName(p); err == nil {
			t.Errorf("GetUserByName(%q) found a user", p)
		}
	}
	// The payloads must not have dropped, emptied or altered anything.
	ts, err := s.ListTargets()
	if err != nil || len(ts) != 1 || ts[0].Domain != "example.com" {
		t.Fatalf("targets changed after hostile input: %v %v", ts, err)
	}
	for _, tbl := range []string{"subdomains", "records", "certs", "findings", "events", "users", "targets"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n); err != nil { //nolint:gosec // G202: fixed table names in a test
			t.Errorf("table %s unreadable after hostile input: %v", tbl, err)
		}
	}
}

// TestLikeWildcardsAreLiteral checks that % and _ typed into a search box match
// only themselves, so they cannot be used to enumerate the inventory.
func TestLikeWildcardsAreLiteral(t *testing.T) {
	h := newHarness(t)
	tx, err := h.store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"www.example.com", "a_b.example.com"} {
		if _, err := tx.AddSubdomain("example.com", host, "test", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{"%": 0, "_": 1, "a_b": 1, "www": 1} {
		rows, _, err := h.store.Inventory("", q, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != want {
			t.Errorf("search %q matched %d hosts, want %d", q, len(rows), want)
		}
	}
}

// TestSafeNextRejectsOffSiteTargets covers the open-redirect bypasses browsers accept.
func TestSafeNextRejectsOffSiteTargets(t *testing.T) {
	for _, bad := range []string{"//evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "http://evil.example", "evil.example", "/ok\x00", ""} {
		if got := safeNext(bad, "/home"); got != "/home" {
			t.Errorf("safeNext(%q) = %q, want the default", bad, got)
		}
	}
	if got := safeNext("/assets?type=ip", "/home"); got != "/assets?type=ip" {
		t.Errorf("a normal local path was rejected: %q", got)
	}
}

// TestStaticFolderIsNotListable checks that /static/ answers 404 while files still load.
func TestStaticFolderIsNotListable(t *testing.T) {
	e := newWebEnv(t)
	srv := e.srv
	for path, want := range map[string]int{"/static/": 404, "/static/app.js": 200} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}
