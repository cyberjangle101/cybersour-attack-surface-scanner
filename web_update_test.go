package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// webUpdateEnv is a web test environment whose release source is a fake GitHub and
// whose "program file" is a temp file, so installs can be checked without touching
// the test binary.
func webUpdateEnv(t *testing.T, current string) (*webEnv, *fakeReleases, string) {
	t.Helper()
	e := newWebEnv(t)
	f := newFakeReleases(t)
	e.eng.newUpdater = func() *Updater { return f.updater(current) }
	e.eng.dataDir = e.dir
	exe := filepath.Join(t.TempDir(), "easm-agent.exe")
	if err := os.WriteFile(exe, []byte("running "+current), 0o700); err != nil {
		t.Fatal(err)
	}
	e.web.exePath = func() (string, error) { return exe, nil }
	return e, f, exe
}

func TestUpdateFromSystemHealth(t *testing.T) {
	e, f, exe := webUpdateEnv(t, "1.8.0")
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("signed v1.9.0")}, true)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	an := e.signedIn("ana", RoleAnalyst)

	// Not checked yet: no banner, card offers a check.
	if _, body, _ := admin.get("/health"); !strings.Contains(body, "Not checked yet") || strings.Contains(body, "is available. <a") {
		t.Error("before a check the card should say so and show no banner")
	}
	if code, _, _ := an.post("/system/update/check", nil); code != 403 {
		t.Errorf("analyst update check: %d", code)
	}
	if code, _, _ := admin.postRaw("/system/update/check", url.Values{}); code != 403 {
		t.Errorf("update check without CSRF: %d", code)
	}
	if code, _, r := admin.post("/system/update/check", nil); code != 303 || !strings.HasPrefix(loc(r), "/health") {
		t.Fatalf("update check: %d %s", code, loc(r))
	}
	_, body, _ := admin.get("/")
	if !strings.Contains(body, "EASM Agent 1.9.0 is available.") {
		t.Error("admins should see the update banner on every page")
	}
	if _, ab, _ := an.get("/"); strings.Contains(ab, "is available.") {
		t.Error("the banner is for administrators only")
	}
	_, body, _ = admin.get("/health")
	for _, want := range []string{"Version 1.9.0 available", "notes for v1.9.0", "Back up and install 1.9.0", "signed checksums"} {
		if !strings.Contains(body, want) {
			t.Errorf("updates card lacks %q", want)
		}
	}

	// Analysts cannot install; a stale version in the form is refused.
	if code, _, _ := an.post("/system/update/install", url.Values{"version": {"1.9.0"}}); code != 403 {
		t.Errorf("analyst install: %d", code)
	}
	if code, _, _ := admin.post("/system/update/install", url.Values{"version": {"1.8.5"}}); code != 303 {
		t.Errorf("stale version: %d", code)
	}
	if b, _ := os.ReadFile(exe); string(b) != "running 1.8.0" {
		t.Fatal("program replaced by a refused request")
	}

	var restarts atomic.Int32
	e.web.restart = func() { restarts.Add(1) }
	code, body, _ := admin.post("/system/update/install", url.Values{"version": {"1.9.0"}})
	if code != 200 || !strings.Contains(body, "Updated to 1.9.0") || restarts.Load() != 1 {
		t.Fatalf("install: %d restarts=%d\n%.300s", code, restarts.Load(), body)
	}
	if b, _ := os.ReadFile(exe); string(b) != "signed v1.9.0" {
		t.Errorf("program not replaced: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "running 1.8.0" {
		t.Errorf("previous version not kept for rollback: %q", b)
	}
	if backups := ListBackups(filepath.Join(e.dir, "backups")); len(backups) != 1 {
		t.Errorf("expected one backup before the update, found %d", len(backups))
	}
	_, au, _ := admin.get("/audit")
	for _, want := range []string{"update.start", "update.installed", "backup.written"} {
		if !strings.Contains(au, want) {
			t.Errorf("audit trail lacks %s", want)
		}
	}
}

func TestUpdateRefusesTamperedRelease(t *testing.T) {
	e, f, exe := webUpdateEnv(t, "1.8.0")
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("signed v1.9.0")}, true)
	f.files["/dl/v1.9.0/"+winAsset] = []byte("swapped after signing")
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/system/update/check", nil)
	code, body, _ := admin.post("/system/update/install", url.Values{"version": {"1.9.0"}})
	if code != 502 || !strings.Contains(body, "does not match its signed checksum") || !strings.Contains(body, "unchanged") {
		t.Fatalf("tampered install: %d\n%.300s", code, body)
	}
	if b, _ := os.ReadFile(exe); string(b) != "running 1.8.0" {
		t.Error("tampered release replaced the program")
	}
	if entries, _ := os.ReadDir(filepath.Dir(exe)); len(entries) != 1 {
		t.Errorf("a refused update left files next to the program: %v", entries)
	}
	if _, au, _ := admin.get("/audit"); !strings.Contains(au, "update.failed") {
		t.Error("failed update not audited")
	}
}

func TestUpdateWithoutKeyOnlyReports(t *testing.T) {
	e, f, _ := webUpdateEnv(t, "1.8.0")
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("x")}, true)
	e.eng.newUpdater = func() *Updater { u := f.updater("1.8.0"); u.PublicKey = nil; return u }
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/system/update/check", nil)
	_, body, _ := admin.get("/health")
	if !strings.Contains(body, "Version 1.9.0 available") || strings.Contains(body, "Back up and install") || !strings.Contains(body, "no release signing key") {
		t.Error("a keyless build should report the update but offer no install")
	}
}

func TestDailyUpdateCheckFollowsSetting(t *testing.T) {
	e, f, _ := webUpdateEnv(t, "1.8.0")
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("x")}, true)
	e.eng.updateEvery = 1 // due immediately
	st, _ := e.store.LoadSettings()
	st.UpdateCheck = false
	e.saveSettings(st)
	e.eng.maybeUpdateCheck(testCtx(t))
	e.eng.wg.Wait()
	f.mu.Lock()
	hits := f.hits["/repo/releases"]
	f.mu.Unlock()
	if hits != 0 {
		t.Fatal("checked GitHub although Settings turn the daily check off")
	}
	st.UpdateCheck = true
	e.saveSettings(st)
	e.eng.maybeUpdateCheck(testCtx(t))
	e.eng.wg.Wait()
	if s := e.eng.UpdateState(); !s.Available || s.Latest.Version != "1.9.0" {
		t.Errorf("daily check did not record the update: %+v", s)
	}
	if DefaultSettings().UpdateCheck != true {
		t.Error("daily update check should default to on")
	}
}
