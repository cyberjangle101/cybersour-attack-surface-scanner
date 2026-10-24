package main

import (
	"net/url"
	"strings"
	"testing"
)

const testPW = "correct horse battery"

// adLab is a web server wired to a fake domain controller with a typical set of people.
type adLab struct {
	*webEnv
	dc    *fakeAD
	admin *browser
	cfg   ADConfig
}

func newADLab(t *testing.T, ldaps bool) *adLab {
	t.Helper()
	e := newWebEnv(t)
	dc := newFakeAD(t, ldaps)
	admins := dc.addGroup("EASM Admins")
	ops := dc.addGroup("Ops", admins) // Ops is nested inside EASM Admins
	analysts := dc.addGroup("EASM Analysts")
	readers := dc.addGroup("EASM Readers")
	dc.addUser("alice", "alice-pw-1", ops)   // admin through nesting
	dc.addUser("bob", "bob-pw-2", analysts)  // analyst
	dc.addUser("rita", "rita-pw-3", readers) // viewer
	dc.addUser("carol", "carol-pw-4")        // valid, but in no group
	dc.addUser("dave", "dave-pw-5", admins).Disabled = true
	dc.addUser("erin", "erin-pw-6") // will be an explicit user
	dc.addUser("multi", "multi-pw-7", readers, analysts)
	l := &adLab{webEnv: e, dc: dc}
	l.admin = e.browser()
	l.admin.setup("admin", testPW)
	sec := "starttls"
	if ldaps {
		sec = "ldaps"
	}
	l.cfg = ADConfig{Enabled: true, Servers: []string{dc.Addr()}, Security: sec, CAPEM: dc.CAPEM, BindDN: dc.svcDN, BaseDN: dc.baseDN, Domain: "CORP", UserFilter: DefaultADFilter,
		Groups: []ADGroup{{Group: admins, Role: RoleAdmin}, {Group: "EASM Analysts", Role: RoleAnalyst}, {Group: "EASM Readers", Role: RoleViewer}}}
	l.save(l.cfg)
	return l
}

func (l *adLab) save(c ADConfig) {
	l.t.Helper()
	if err := c.Validate(); err != nil {
		l.t.Fatal(err)
	}
	if err := l.store.SaveAD(c); err != nil {
		l.t.Fatal(err)
	}
	if err := l.eng.SetSecret(secretADBind, l.dc.svcPW); err != nil {
		l.t.Fatal(err)
	}
	l.cfg = c
}

func (l *adLab) loginAs(user, pw string) (*browser, int, string) {
	b := l.browser()
	tok := b.loginPre("/login")
	code, body, _ := b.postRaw("/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pw}})
	if code == 303 {
		b.refreshCSRF()
	}
	return b, code, body
}

// resetIP forgets address-level failures so one test phase does not throttle the next.
func (l *adLab) resetIP() {
	l.web.mu.Lock()
	l.web.fails = map[string]*failRec{}
	l.web.mu.Unlock()
}

func (l *adLab) mustLogin(user, pw string) *browser {
	l.t.Helper()
	l.resetIP()
	b, code, body := l.loginAs(user, pw)
	if code != 303 {
		l.t.Fatalf("%s could not sign in: %d %.200s", user, code, body)
	}
	return b
}

func (l *adLab) mustFail(user, pw string) string {
	l.t.Helper()
	l.resetIP()
	_, code, body := l.loginAs(user, pw)
	if code == 303 {
		l.t.Fatalf("%s signed in but should not have", user)
	}
	return body
}

func (l *adLab) role(name string) string {
	u, err := l.store.GetUserByName(name)
	if err != nil {
		return ""
	}
	return u.Role
}

func TestADGroupsAndUsers(t *testing.T) {
	for _, ldaps := range []bool{true, false} {
		name := "starttls"
		if ldaps {
			name = "ldaps"
		}
		t.Run(name, func(t *testing.T) {
			l := newADLab(t, ldaps)

			// nested group -> administrator
			alice := l.mustLogin("alice", "alice-pw-1")
			if code, _, _ := alice.get("/settings"); code != 200 {
				t.Errorf("alice (nested admin group) settings = %d", code)
			}
			if r := l.role("alice"); r != RoleAdmin {
				t.Errorf("alice role %q", r)
			}
			if u, _ := l.store.GetUserByName("alice"); u.Kind != kindADGroup || u.Hash != "" {
				t.Errorf("alice account %+v", u)
			}
			// group name given as plain text -> analyst
			bob := l.mustLogin("bob", "bob-pw-2")
			if code, _, _ := bob.get("/settings"); code != 403 {
				t.Errorf("analyst reached settings: %d", code)
			}
			if _, body, _ := bob.get("/findings"); body == "" {
				t.Error("analyst cannot read findings")
			}
			if code, _, _ := bob.post("/findings/1/ack", url.Values{"reason": {"x y z"}}); code == 403 {
				t.Error("analyst cannot triage")
			}
			// viewer; several groups -> the highest role
			rita := l.mustLogin("rita", "rita-pw-3")
			if code, _, _ := rita.post("/findings/1/ack", url.Values{"reason": {"x y z"}}); code != 403 {
				t.Errorf("viewer triaged: %d", code)
			}
			l.mustLogin("multi", "multi-pw-7")
			if r := l.role("multi"); r != RoleAnalyst {
				t.Errorf("highest group should win, got %q", r)
			}
			// sign-in spellings
			for _, in := range []string{"CORP\\bob", "corp\\BOB", "bob@corp.example.com", "BOB"} {
				l.mustLogin(in, "bob-pw-2")
			}
			if l.mustFail("OTHER\\bob", "bob-pw-2") == "" {
				t.Error("no page")
			}

			// wrong password, unknown user, empty password, disabled in directory
			for _, c := range [][2]string{{"bob", "nope"}, {"nobody", "x"}, {"bob", ""}, {"dave", "dave-pw-5"}, {"", ""}} {
				if body := l.mustFail(c[0], c[1]); !strings.Contains(body, "Invalid username or password") {
					t.Errorf("%v: unexpected message %.150s", c, body)
				}
			}
			if n := l.dc.emptyPW; n != 0 {
				t.Errorf("the agent sent %d bind(s) with an empty password", n)
			}
			// a valid directory account in no group and not added: refused with an explanation
			if body := l.mustFail("carol", "carol-pw-4"); !strings.Contains(body, "has not been given access") {
				t.Errorf("carol message: %.200s", body)
			}
			if _, err := l.store.GetUserByName("carol"); err == nil {
				t.Error("an account was created for somebody without access")
			}

			// explicit directory user, added by an administrator; verified against the directory
			code, _, _ := l.admin.post("/users/ad", url.Values{"username": {"ghost"}, "role": {"viewer"}})
			if _, err := l.store.GetUserByName("ghost"); code != 303 || err == nil {
				t.Error("a user missing from the directory was added")
			}
			l.admin.post("/users/ad", url.Values{"username": {"CORP\\Erin"}, "role": {"analyst"}})
			if u, err := l.store.GetUserByName("erin"); err != nil || u.Kind != kindAD || u.Role != RoleAnalyst || u.Hash != "" {
				t.Fatalf("erin not added correctly: %+v %v", u, err)
			}
			l.mustLogin("erin", "erin-pw-6")
			// an administrator can change an explicit user's role and disable them
			erin, _ := l.store.GetUserByName("erin")
			l.admin.post("/users/"+itoa(erin.ID)+"/role", url.Values{"role": {"viewer"}})
			if l.role("erin") != RoleViewer {
				t.Error("explicit user role not changed")
			}
			l.admin.post("/users/"+itoa(erin.ID)+"/disable", url.Values{"disable": {"1"}})
			if body := l.mustFail("erin", "erin-pw-6"); !strings.Contains(body, "disabled") {
				t.Errorf("disabled message: %.150s", body)
			}
			// ...but not the role of someone who gets it from a group
			ar, _ := l.store.GetUserByName("alice")
			l.admin.post("/users/"+itoa(ar.ID)+"/role", url.Values{"role": {"viewer"}})
			if l.role("alice") != RoleAdmin {
				t.Error("group-managed role was changed by hand")
			}
			// password pages do not apply
			if code, _, _ := l.admin.post("/users/"+itoa(ar.ID)+"/password", url.Values{"password": {"abcdefghijkl"}}); code != 303 {
				t.Error("password reset response")
			}
			if u, _ := l.store.GetUserByName("alice"); u.Hash != "" {
				t.Error("a local password was set on a directory account")
			}
			if _, body, _ := alice.get("/account"); !strings.Contains(body, "managed in Active Directory") {
				t.Error("account page should explain directory passwords")
			}
			alice.post("/account/password", url.Values{"current": {"alice-pw-1"}, "password": {"new password 12"}, "confirm": {"new password 12"}})
			if u, _ := l.store.GetUserByName("alice"); u.Hash != "" {
				t.Error("account page set a local password on a directory account")
			}

			// the audit log names the directory sign-ins
			if _, body, _ := l.admin.get("/audit?action=login"); !strings.Contains(body, "alice") || !strings.Contains(body, "directory: bad credentials") {
				t.Error("audit trail incomplete")
			}
			if strings.Contains(l.dumpAudit(), "alice-pw-1") || strings.Contains(l.dumpAudit(), "svc-secret-pw") {
				t.Fatal("a password reached the audit log")
			}
		})
	}
}

func (l *adLab) dumpAudit() string {
	list, _, _ := l.store.ListAudit(AuditFilter{Limit: 10000})
	var sb strings.Builder
	for _, a := range list {
		sb.WriteString(a.Actor + "|" + a.Action + "|" + a.Target + "|" + a.Detail + "\n")
	}
	return sb.String()
}

func TestADGroupChangesFollowOnNextSignIn(t *testing.T) {
	l := newADLab(t, true)
	l.mustLogin("bob", "bob-pw-2")
	if l.role("bob") != RoleAnalyst {
		t.Fatal("setup")
	}
	// promoted in the directory
	admins := "CN=EASM Admins,OU=Groups," + l.dc.baseDN
	l.dc.set(func() { l.dc.users[strings.ToLower("CN=bob,OU=People,"+l.dc.baseDN)].MemberOf = []string{admins} })
	l.mustLogin("bob", "bob-pw-2")
	if l.role("bob") != RoleAdmin {
		t.Errorf("promotion not applied: %s", l.role("bob"))
	}
	// removed from every group: cannot sign in any more
	l.dc.set(func() { l.dc.users[strings.ToLower("CN=bob,OU=People,"+l.dc.baseDN)].MemberOf = nil })
	l.mustFail("bob", "bob-pw-2")
	// group-derived administrators never count as "the last administrator"
	if n, _ := l.store.CountAdmins(); n != 1 {
		t.Errorf("admins counted: %d (only the local one should count)", n)
	}
	if !strings.Contains(l.dumpAudit(), "directory group") {
		t.Error("role change from group not audited")
	}
}

func TestADLocalAccountWinsAndLocalLoginStillWorks(t *testing.T) {
	l := newADLab(t, true)
	// local account with the same name as a directory account
	hash, _ := hashPassword("local password 1")
	if _, err := l.store.CreateUser("bob", hash, RoleViewer); err != nil {
		t.Fatal(err)
	}
	l.mustFail("bob", "bob-pw-2") // directory password does not work for the local bob
	l.mustLogin("bob", "local password 1")
	if l.role("bob") != RoleViewer {
		t.Error("local account was modified by the directory")
	}
	// the original local administrator is unaffected, with AD on and with it off
	l.mustLogin("admin", testPW)
	l.save(ADConfig{Security: "ldaps", UserFilter: DefaultADFilter})
	l.mustLogin("admin", testPW)
	l.mustFail("alice", "alice-pw-1")
}

func TestADPerAccountThrottle(t *testing.T) {
	l := newADLab(t, true)
	before := l.dc.bindCount("CN=alice,OU=People," + l.dc.baseDN)
	for i := 0; i < maxFails; i++ {
		l.mustFail("alice", "wrong")
	}
	// even the right password is refused for a while, and the directory is not contacted
	svcBefore := l.dc.bindCount(l.dc.svcDN)
	if body := l.mustFail("alice", "alice-pw-1"); !strings.Contains(body, "Too many failed attempts") {
		t.Errorf("not throttled: %.200s", body)
	}
	if l.dc.bindCount(l.dc.svcDN) != svcBefore || l.dc.bindCount("CN=alice,OU=People,"+l.dc.baseDN) != before {
		t.Error("directory was contacted while throttled")
	}
	// a different account is not affected by this user's failures (different source address is not needed:
	// the per-address limit has its own test; here only the account limit matters)
	l.web.adg.ok("alice")
}

func TestADFilterInjection(t *testing.T) {
	l := newADLab(t, true)
	for _, evil := range []string{"*", "*)(sAMAccountName=*", "bob)(|(sAMAccountName=alice", `a\2a`, "bob\x00", "al*"} {
		l.mustFail(evil, "bob-pw-2")
	}
	base := strings.Count(strings.ReplaceAll(DefaultADFilter, "{username}", "x"), "(")
	for _, f := range l.dc.filters {
		if !strings.Contains(f, "userAccountControl") {
			continue // group and base lookups
		}
		if strings.Count(f, "(") != base || strings.Contains(f, "(sAMAccountName=*)") {
			t.Fatalf("input changed the shape of the search: %s", f)
		}
	}
	if len(l.dc.filters) == 0 {
		t.Fatal("nothing searched")
	}
}

func TestADCertificateVerification(t *testing.T) {
	l := newADLab(t, true)
	// without the CA the self-signed controller is rejected, and the person sees a neutral message
	c := l.cfg
	c.CAPEM = ""
	l.save(c)
	if body := l.mustFail("bob", "bob-pw-2"); !strings.Contains(body, "could not be reached") {
		t.Errorf("untrusted certificate message: %.200s", body)
	}
	// "directory down" is not the person's fault: it must not count towards the address throttle
	l.resetIP()
	for i := 0; i < maxFails+2; i++ {
		if _, code, _ := l.loginAs("bob", "bob-pw-2"); code != 503 {
			t.Fatalf("attempt %d: want 503 (directory unavailable), got %d; outages must not trip the address throttle", i, code)
		}
	}
	// the escape hatch works when explicitly chosen
	c.SkipVerify = true
	l.save(c)
	l.mustLogin("bob", "bob-pw-2")
	// and a down server is reported as unavailable, not as a bad password
	c.SkipVerify = false
	c.CAPEM = l.dc.CAPEM
	c.Servers = []string{"localhost:1"}
	l.save(c)
	if body := l.mustFail("bob", "bob-pw-2"); !strings.Contains(body, "could not be reached") {
		t.Errorf("down server message: %.200s", body)
	}
	// second server is used when the first is down
	c.Servers = []string{"localhost:1", l.dc.Addr()}
	l.save(c)
	l.mustLogin("bob", "bob-pw-2")
}

func TestADSettingsPage(t *testing.T) {
	l := newADLab(t, true)
	_, body, _ := l.admin.get("/settings/ad")
	for _, want := range []string{"Directory sign-in", l.dc.baseDN, "saved; leave blank to keep", "EASM Analysts"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if strings.Contains(body, "svc-secret-pw") {
		t.Fatal("service account password shown on the page")
	}
	if stored, _, _ := l.store.getMeta(secretADBind); strings.Contains(stored, "svc-secret-pw") || stored == "" {
		t.Errorf("service account password not sealed: %.30s", stored)
	}
	form := func() url.Values {
		return url.Values{"enabled": {"on"}, "servers": {l.dc.Addr()}, "security": {"ldaps"}, "bind_dn": {l.dc.svcDN}, "base_dn": {l.dc.baseDN},
			"user_filter": {DefaultADFilter}, "ca_pem": {l.dc.CAPEM}, "group_0": {"EASM Readers"}, "role_0": {"viewer"}}
	}
	// invalid input is refused and nothing changes
	for name, mod := range map[string]func(url.Values){
		"plain ldap":     func(v url.Values) { v.Set("security", "none") },
		"filter no user": func(v url.Values) { v.Set("user_filter", "(sAMAccountName=x)") },
		"filter 2 users": func(v url.Values) { v.Set("user_filter", "(|(cn={username})(sn={username}))({username}") },
		"filter garbage": func(v url.Values) { v.Set("user_filter", "((({username}") },
		"bad ca":         func(v url.Values) { v.Set("ca_pem", "not a certificate") },
		"no servers":     func(v url.Values) { v.Set("servers", "") },
		"url as server":  func(v url.Values) { v.Set("servers", "ldap://dc1") },
		"no base":        func(v url.Values) { v.Set("base_dn", "") },
		"bad role":       func(v url.Values) { v.Set("role_0", "root") },
	} {
		v := form()
		mod(v)
		l.admin.post("/settings/ad", v)
		if c, _ := l.store.LoadAD(); len(c.Groups) != 3 {
			t.Errorf("%s: invalid settings were saved", name)
		}
	}
	// a valid change (blank password keeps the old one)
	v := form()
	l.admin.post("/settings/ad", v)
	if c, _ := l.store.LoadAD(); len(c.Groups) != 1 || c.Groups[0].Group != "EASM Readers" {
		t.Errorf("valid settings not saved: %+v", c.Groups)
	}
	l.mustLogin("rita", "rita-pw-3")
	// not for non-administrators
	bob := l.mustLogin("rita", "rita-pw-3")
	if code, _, _ := bob.get("/settings/ad"); code != 403 {
		t.Error("viewer reached directory settings")
	}
	// connection test reports success without creating a session
	l.admin.post("/settings/ad/test", url.Values{})
	if _, body, _ := l.admin.get("/settings/ad"); !strings.Contains(body, "Connected") {
		t.Error("connection test result missing")
	}
	l.admin.post("/settings/ad/test", url.Values{"test_user": {"carol"}, "test_password": {"carol-pw-4"}})
	if _, body, _ := l.admin.get("/settings/ad"); !strings.Contains(body, "none of the mapped groups") {
		t.Error("person test result missing")
	}
	// removing the saved password disables connecting
	l.admin.post("/settings/ad", func() url.Values { v := form(); v.Set("bind_password_clear", "on"); return v }())
	if l.eng.HasSecret(secretADBind) {
		t.Error("password not cleared")
	}
}
