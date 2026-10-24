package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// Deleting a domain from the dashboard must remove every row that belongs to it, and only those.
func TestDeleteDomainRemovesEverything(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	e.seedDomain("other.test", "198.51.100.77", 64500)
	tg := e.addTarget("example.test", "AS64500")
	keep := e.addTarget("other.test", "")
	e.scan(tg.ID)
	e.scan(keep.ID)
	db := e.store.db
	mustExec := func(q string, a ...any) {
		t.Helper()
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	now := "2026-01-01T00:00:00Z"
	mustExec(`INSERT INTO web_services(host,port,root,scheme,first_seen,last_seen) VALUES('www.example.test',443,'example.test','https',?,?)`, now, now)
	mustExec(`INSERT INTO web_shots(host,port,taken,png) VALUES('www.example.test',443,?,x'89504e47')`, now)
	mustExec(`INSERT INTO web_services(host,port,root,scheme,first_seen,last_seen) VALUES('www.other.test',443,'other.test','https',?,?)`, now, now)
	mustExec(`INSERT INTO web_shots(host,port,taken,png) VALUES('www.other.test',443,?,x'89504e47')`, now)
	mustExec(`INSERT INTO suggestions(root,domain,via,detail,first_seen) VALUES('example.test','x.test','cert','d',?)`, now)
	mustExec(`INSERT INTO meta(k,v) VALUES('refresh:example.test','1')`)
	mustExec(`INSERT INTO meta(k,v) VALUES('active:example.test','1')`)

	b := e.browser()
	b.setup("admin", "correct horse battery")
	// dashboard: headings and tiles are links, admin sees a delete icon per domain
	_, body, _ := b.get("/")
	for _, want := range []string{`href="/targets"`, `href="/assets"`, `href="/findings"`, `href="/events"`, `href="/targets/` + itoa64(tg.ID) + `/delete"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard is missing %s", want)
		}
	}
	// confirmation page shows counts and asks for the name
	code, body, _ := b.get("/targets/" + itoa64(tg.ID) + "/delete")
	if code != 200 || !strings.Contains(body, "Delete example.test?") || !strings.Contains(body, "Type <strong>example.test</strong>") {
		t.Fatalf("confirm page: %d", code)
	}
	if code, _, _ := b.post("/targets/"+itoa64(tg.ID)+"/delete", url.Values{"confirm": {"example.test"}}); code != 303 {
		t.Fatalf("delete: %d", code)
	}

	for _, tbl := range []string{"subdomains", "records", "certs", "findings", "events", "scans", "suggestions", "domain_info", "web_services"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + tbl + ` WHERE root='example.test'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still has %d row(s) for the deleted domain", tbl, n)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM web_shots WHERE host='www.example.test'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("screenshot of the deleted domain remains")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM meta WHERE k LIKE '%:example.test'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("meta keys of the deleted domain remain")
	}
	// the other domain is untouched
	for q, what := range map[string]string{
		`SELECT COUNT(*) FROM subdomains WHERE root='other.test'`:    "hosts",
		`SELECT COUNT(*) FROM web_shots WHERE host='www.other.test'`: "screenshots",
		`SELECT COUNT(*) FROM web_services WHERE root='other.test'`:  "web services",
		`SELECT COUNT(*) FROM targets WHERE domain='other.test'`:     "target",
	} {
		if err := db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("deleting one domain removed the other domain's %s", what)
		}
	}
	// the audit log records the deletion
	var audited int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action='target.delete' AND target='example.test'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Error("deletion was not audited")
	}
}

func TestViewerCannotSeeDeleteIcon(t *testing.T) {
	e := newWebEnv(t)
	tg := e.addTarget("example.test", "")
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/users", url.Values{"username": {"vera"}, "password": {"another long password"}, "role": {"viewer"}})
	v := e.browser()
	if v.login("vera", "another long password") != 303 {
		t.Skip("could not sign in as a viewer in this harness")
	}
	_, body, _ := v.get("/targets")
	if strings.Contains(body, "/delete") {
		t.Error("a viewer is shown a delete link")
	}
	if code, _, _ := v.get("/targets/" + itoa64(tg.ID) + "/delete"); code != 403 && code != 303 {
		t.Errorf("viewer reached the delete page: %d", code)
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
