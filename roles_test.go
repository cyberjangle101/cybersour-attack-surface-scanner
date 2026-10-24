package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signedIn creates a local user with the role and returns a browser signed in as them.
func (e *webEnv) signedIn(name, role string) *browser {
	e.t.Helper()
	hash, err := hashPassword("correct horse battery")
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.store.CreateUser(name, hash, role); err != nil {
		e.t.Fatal(err)
	}
	b := e.browser()
	if code := b.login(name, "correct horse battery"); code != 303 {
		e.t.Fatalf("login %s: %d", name, code)
	}
	return b
}

func TestRolesMatrix(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	e.scan(1)
	analyst := e.signedIn("ana", RoleAnalyst)
	viewer := e.signedIn("vic", RoleViewer)

	reasonForm := func() url.Values { return url.Values{"reason": {"owner confirmed, patch next month"}} }

	// viewer: read only
	for _, p := range []string{"/", "/findings", "/events", "/report"} {
		if code, _, _ := viewer.get(p); code != 200 {
			t.Errorf("viewer GET %s = %d", p, code)
		}
	}
	for _, p := range []string{"/findings/1/ack", "/findings/1/reopen", "/findings/1/severity", "/settings", "/users", "/targets"} {
		if code, _, _ := viewer.post(p, reasonForm()); code != 403 {
			t.Errorf("viewer POST %s = %d, want 403", p, code)
		}
	}
	if code, _, _ := viewer.get("/audit"); code != 403 {
		t.Errorf("viewer audit = %d", code)
	}
	if _, body, _ := viewer.get("/findings"); strings.Contains(body, "Accept risk") {
		t.Error("viewer is shown triage controls")
	}

	// analyst: triage yes, admin things no
	if _, body, _ := analyst.get("/findings"); !strings.Contains(body, "Accept risk") {
		t.Error("analyst is not shown triage controls")
	}
	for _, p := range []string{"/settings", "/users", "/audit", "/audit.csv"} {
		if code, _, _ := analyst.get(p); code != 403 {
			t.Errorf("analyst GET %s = %d, want 403", p, code)
		}
	}
	for _, p := range []string{"/settings", "/users", "/targets", "/users/1/role", "/targets/1/delete"} {
		if code, _, _ := analyst.post(p, reasonForm()); code != 403 {
			t.Errorf("analyst POST %s = %d, want 403", p, code)
		}
	}
	if code, _, _ := analyst.post("/targets/1/scan", nil); code != 303 {
		t.Errorf("analyst may start a scan now: %d", code)
	}
	if code, _, _ := analyst.post("/targets/1/scan", url.Values{"refresh": {"1"}}); code != 303 {
		t.Errorf("analyst refresh scan: %d", code)
	}
	if _, body, _ := analyst.get("/targets/1"); !strings.Contains(body, "refresh exposure data") {
		t.Error("analyst is not offered the refresh scan")
	}
	if code, _, _ := viewer.post("/targets/1/scan", nil); code != 403 {
		t.Errorf("viewer scan = %d", code)
	}
	// accept needs a reason
	if _, _, r := analyst.post("/findings/1/ack", url.Values{}); loc(r) != "/findings" {
		t.Fatal("unexpected redirect")
	}
	if f := findingByID(t, e, 1); f.Status != "open" {
		t.Fatal("risk accepted without a reason")
	}
	// bad / past review dates are refused
	for _, d := range []string{"2001-01-01", "tomorrow", "2999-01-01"} {
		f := reasonForm()
		f.Set("until", d)
		analyst.post("/findings/1/ack", f)
		if findingByID(t, e, 1).Status != "open" {
			t.Fatalf("review date %q accepted", d)
		}
	}
	f := reasonForm()
	f.Set("until", time.Now().UTC().AddDate(0, 1, 0).Format("2006-01-02"))
	analyst.post("/findings/1/ack", f)
	got := findingByID(t, e, 1)
	if got.Status != "ack" || got.AckBy != "ana" || got.AckReason == "" || got.AckUntil == "" {
		t.Fatalf("acceptance not recorded: %+v", got)
	}
	// shown on the page, including who and why
	if _, body, _ := admin.get("/findings?status=ack"); !strings.Contains(body, "Accepted by ana") || !strings.Contains(body, "patch next month") {
		t.Error("acceptance details not displayed")
	}
	// severity override with reason; scanner value is kept
	analyst.post("/findings/1/severity", url.Values{"severity": {"low"}, "reason": {"test host"}})
	got = findingByID(t, e, 1)
	if got.Severity != "low" || got.ScanSev != "high" || got.SevBy != "ana" {
		t.Fatalf("override: %+v", got)
	}
	analyst.post("/findings/1/severity", url.Values{"severity": {"bogus"}, "reason": {"x y z"}})
	if findingByID(t, e, 1).Severity != "low" {
		t.Error("invalid severity accepted")
	}
	analyst.post("/findings/1/severity", url.Values{"severity": {"scanner"}, "reason": {"restore"}})
	if got = findingByID(t, e, 1); got.Severity != "high" || got.SevOverride != "" {
		t.Fatalf("restore: %+v", got)
	}
	analyst.post("/findings/1/reopen", nil)
	if findingByID(t, e, 1).Status != "open" {
		t.Error("reopen failed")
	}

	// audit trail has all of it, attributed
	_, body, _ := admin.get("/audit?actor=ana")
	for _, want := range []string{"finding.accept", "finding.severity", "finding.reopen"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit missing %s", want)
		}
	}
	if _, csv, r := admin.get("/audit.csv"); !strings.HasPrefix(csv, "time_utc,actor") || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Error("audit csv")
	}
	if _, body, _ = admin.get("/audit?actor=ana&days=1&page=1"); !strings.Contains(body, "ana") {
		t.Error("audit filter")
	}
}

func findingByID(t *testing.T, e *webEnv, id int64) Finding {
	t.Helper()
	all, err := e.store.ListFindings("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %d not found", id)
	return Finding{}
}

func TestUserAdminControls(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	e.signedIn("vic", RoleViewer)
	vic, _ := e.store.GetUserByName("vic")
	me, _ := e.store.GetUserByName("admin")

	// promote, demote
	admin.post("/users/"+itoa(vic.ID)+"/role", url.Values{"role": {"analyst"}})
	if u, _ := e.store.GetUser(vic.ID); u.Role != RoleAnalyst {
		t.Error("role not changed")
	}
	admin.post("/users/"+itoa(vic.ID)+"/role", url.Values{"role": {"root"}})
	if u, _ := e.store.GetUser(vic.ID); u.Role != RoleAnalyst {
		t.Error("unknown role accepted")
	}
	// last administrator is protected, from demotion, disabling and deletion
	admin.post("/users/"+itoa(me.ID)+"/role", url.Values{"role": {"viewer"}})
	admin.post("/users/"+itoa(me.ID)+"/disable", url.Values{"disable": {"1"}})
	admin.post("/users/"+itoa(me.ID)+"/delete", nil)
	if u, _ := e.store.GetUser(me.ID); u.Role != RoleAdmin || u.Disabled {
		t.Error("last administrator was changed")
	}
	// a disabled account cannot sign in and its session ends
	vb := e.browser()
	if vb.login("vic", "correct horse battery") != 303 {
		t.Fatal("vic cannot sign in")
	}
	admin.post("/users/"+itoa(vic.ID)+"/disable", url.Values{"disable": {"1"}})
	if code, _, _ := vb.get("/"); code != 303 {
		t.Errorf("disabled user's session survived: %d", code)
	}
	if vb2 := e.browser(); vb2.login("vic", "correct horse battery") == 303 {
		t.Error("disabled user signed in")
	}
	admin.post("/users/"+itoa(vic.ID)+"/disable", url.Values{"disable": {"0"}})
	if vb3 := e.browser(); vb3.login("vic", "correct horse battery") != 303 {
		t.Error("re-enabled user cannot sign in")
	}
	if _, body, _ := admin.get("/audit"); !strings.Contains(body, "user.role") || !strings.Contains(body, "user.disable") || !strings.Contains(body, "login.fail") {
		t.Error("audit missing user events")
	}
}

func TestAcceptanceExpiry(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	e.addTarget("example.test", "AS64500")
	e.scan(1)
	if err := e.store.AcceptRisk(1, "ana", "temporary", time.Now().UTC().AddDate(0, 0, 3).Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.store.ExpireAcceptances(time.Now().UTC()); n != 0 {
		t.Error("expired too early")
	}
	n, err := e.store.ExpireAcceptances(time.Now().UTC().AddDate(0, 0, 10))
	if err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	if f := findingByID(t, e, 1); f.Status != "open" || f.AckReason != "" {
		t.Errorf("not reopened: %+v", f)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
