package main

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := newSetupCode()
		if err != nil || len(c) != 20 || strings.Trim(c, setupAlphabet) != "" || seen[c] {
			t.Fatalf("bad setup code %q (%v)", c, err)
		}
		seen[c] = true
	}
	if g := groupCode("ABCDEFGHJKMNPQRSTUVW"); g != "ABCDE-FGHJK-MNPQR-STUVW" {
		t.Errorf("groupCode = %q", g)
	}
	if n := normaliseCode(" abcde-fghjk mnpqr\tstuvw "); n != "ABCDEFGHJKMNPQRSTUVW" {
		t.Errorf("normaliseCode = %q", n)
	}
}

// The first administrator can only be created with the code from the data folder.
func TestFirstAdminNeedsSetupCode(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	web, err := NewServer(h.store, h.eng, h.log, &Bootstrap{Listen: "127.0.0.1:8080", PlainHTTP: true, DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(web.Handler())
	t.Cleanup(srv.Close)
	e := &webEnv{harness: h, srv: srv, web: web}

	file := filepath.Join(dir, setupCodeFile)
	raw, err := os.ReadFile(file)
	code := web.SetupCode()
	if err != nil || code == "" || !strings.Contains(string(raw), code) || web.SetupCodeFile() != file {
		t.Fatalf("setup code file: %v %q", err, raw)
	}

	b := e.browser()
	_, page, _ := b.get("/setup")
	if !strings.Contains(page, `name="code"`) || strings.Contains(page, code) {
		t.Fatal("the setup page must ask for the code and never show it")
	}
	try := func(c string) int {
		tok := b.loginPre("/setup")
		status, _, _ := b.postRaw("/setup", url.Values{"csrf": {tok}, "code": {c}, "username": {"admin"}, "password": {"correct horse battery"}, "confirm": {"correct horse battery"}})
		return status
	}
	for _, bad := range []string{"", "AAAAA-AAAAA-AAAAA-AAAAA", code + "X"} {
		if status := try(bad); status != 400 {
			t.Errorf("setup with code %q: status %d, want 400", bad, status)
		}
	}
	if n, _ := h.store.CountUsers(); n != 0 {
		t.Fatal("an administrator was created without the right code")
	}
	if status := try(strings.ToLower(strings.ReplaceAll(code, "-", " "))); status != 303 {
		t.Fatalf("setup with the right code (typed loosely): status %d", status)
	}
	if n, _ := h.store.CountUsers(); n != 1 {
		t.Fatal("administrator not created")
	}
	if fileExists(file) || web.SetupCode() != "" || web.SetupCodeFile() != "" {
		t.Error("the setup code must be retired once the administrator exists")
	}
	// A restart with an administrator makes no new code.
	web2, err := NewServer(h.store, h.eng, h.log, &Bootstrap{Listen: "127.0.0.1:8080", PlainHTTP: true, DataDir: dir})
	if err != nil || web2.SetupCode() != "" || fileExists(file) {
		t.Errorf("no setup code once set up: %v", err)
	}
}

func TestRecoveryCopyOpensWithItsPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easm.key")
	v, err := OpenVault(path)
	if err != nil || v.Protection() != keyPlain {
		t.Fatalf("new key: %v", err)
	}
	if _, err := v.RecoveryCopy("short"); err == nil {
		t.Error("a short recovery passphrase must be refused")
	}
	rc, err := v.RecoveryCopy("a long recovery passphrase")
	if err != nil || !strings.HasPrefix(string(rc), wrappedMagic) {
		t.Fatalf("recovery copy: %v", err)
	}
	k, err := unwrapKey(rc, "a long recovery passphrase")
	if err != nil || string(k) != string(v.master) {
		t.Fatalf("the recovery copy must hold the same key: %v", err)
	}
	if _, err := unwrapKey(rc, "another passphrase!!"); err == nil {
		t.Error("the recovery copy must need its passphrase")
	}
}

func TestEncryptionKeyPanel(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	_, page, _ := admin.get("/health")
	for _, want := range []string{`id="key"`, "Encryption key", "Download a recovery copy"} {
		if !strings.Contains(page, want) {
			t.Errorf("System health lacks %q", want)
		}
	}
	form := url.Values{"passphrase": {"a long recovery passphrase"}, "confirm": {"a long recovery passphrase"}, "current": {"wrong password!!"}}
	if code, body, _ := admin.post("/system/key/recovery", form); code != 303 || strings.Contains(body, wrappedMagic) {
		t.Fatalf("a recovery copy without the right password: %d", code)
	}
	form.Set("current", "correct horse battery")
	form.Set("confirm", "something else entirely")
	if code, _, _ := admin.post("/system/key/recovery", form); code != 303 {
		t.Fatalf("mismatched passphrases: %d", code)
	}
	form.Set("confirm", "a long recovery passphrase")
	code, body, resp := admin.post("/system/key/recovery", form)
	if code != 200 || !strings.HasPrefix(body, wrappedMagic) || !strings.Contains(resp.Header.Get("Content-Disposition"), "easm-key-recovery-") {
		t.Fatalf("recovery copy not downloaded: %d %.80q", code, body)
	}
	if k, err := unwrapKey([]byte(body), "a long recovery passphrase"); err != nil || string(k) != string(e.eng.vault.master) {
		t.Fatalf("the download must be the agent's key: %v", err)
	}
	if v, _, _ := e.store.getMeta(metaKeyRecovery); !strings.Contains(v, "by admin") {
		t.Errorf("recovery copy not recorded: %q", v)
	}
	au, _, _ := e.store.ListAudit(AuditFilter{})
	if s := strings.Join(auditActions(au), " "); !strings.Contains(s, "key.recovery-copy") {
		t.Errorf("recovery copies must be audited: %s", s)
	}
	e.addUser("ana", "correct horse battery", RoleAnalyst)
	an := e.browser()
	an.login("ana", "correct horse battery")
	if code, _, _ := an.post("/system/key/recovery", form); code != 403 {
		t.Errorf("an analyst must not get the key: %d", code)
	}
}

func auditActions(au []AuditEntry) []string {
	var out []string
	for _, a := range au {
		out = append(out, a.Action)
	}
	return out
}
