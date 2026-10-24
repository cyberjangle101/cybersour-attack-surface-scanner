package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readZip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		out[f.Name], _ = io.ReadAll(rc)
		_ = rc.Close()
	}
	return out
}

func TestBackupRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.addTarget("alpha.test", "AS64500")
	h.addTarget("beta.test", "")
	st := DefaultSettings()
	st.DNSResolvers = []string{h.dns.addr}
	st.IntervalMinutes = 123
	h.saveSettings(st)

	var buf bytes.Buffer
	m, err := WriteBackup(h.store, h.vault, h.dir, false, &buf, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, buf.Bytes())
	if m.KeyIncluded || files["easm.key"] != nil {
		t.Fatal("the key must not be in a backup unless asked for")
	}
	db := files["easm.db"]
	if len(db) == 0 || bytes.HasPrefix(db, sqliteMagic) || bytes.Contains(db, []byte("alpha.test")) {
		t.Fatal("the database inside the backup must stay encrypted")
	}
	if !strings.Contains(string(files[manifestName]), m.DBSHA256) {
		t.Error("manifest does not carry the checksum")
	}

	// restore into an empty folder together with the key, then read the data back
	dst := t.TempDir()
	zp := filepath.Join(t.TempDir(), "b.zip")
	_ = os.WriteFile(zp, buf.Bytes(), 0o600)
	done, err := RestoreBackup(zp, dst, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(done, "|"), "NOTE: this backup does not contain easm.key") {
		t.Errorf("the missing key must be pointed out: %v", done)
	}
	key, _ := os.ReadFile(filepath.Join(h.dir, "easm.key"))
	_ = os.WriteFile(filepath.Join(dst, "easm.key"), key, 0o600)
	if err := VerifyRestored(dst, nil); err != nil {
		t.Fatal(err)
	}
	v, _ := OpenVault(filepath.Join(dst, "easm.key"))
	rs, err := OpenEncryptedStore(filepath.Join(dst, "easm.db"), v.DBKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	ts, _ := rs.ListTargets()
	if len(ts) != 2 {
		t.Errorf("restored %d targets, want 2", len(ts))
	}
	if got, _ := rs.LoadSettings(); got.IntervalMinutes != 123 {
		t.Errorf("settings not restored: %d", got.IntervalMinutes)
	}
}

func TestBackupKeyOnlyWhenProtected(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	if _, err := WriteBackup(h.store, h.vault, h.dir, true, &buf, time.Now()); err == nil || !strings.Contains(err.Error(), "not protected by a passphrase") {
		t.Fatalf("an unprotected key must be refused, got %v", err)
	}
	if err := ProtectKeyFile(filepath.Join(h.dir, "easm.key"), "a long enough passphrase"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	m, err := WriteBackup(h.store, h.vault, h.dir, true, &buf, time.Now())
	if err != nil || !m.KeyIncluded {
		t.Fatal(err)
	}
	files := readZip(t, buf.Bytes())
	if !bytes.HasPrefix(files["easm.key"], []byte(wrappedMagic)) {
		t.Error("the key in the backup must be the passphrase-locked form")
	}
	// full restore from a single file, with the passphrase
	zp := filepath.Join(t.TempDir(), "b.zip")
	_ = os.WriteFile(zp, buf.Bytes(), 0o600)
	dst := t.TempDir()
	if _, err := RestoreBackup(zp, dst, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestored(dst, func() (string, error) { return "a long enough passphrase", nil }); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestored(dst, func() (string, error) { return "the wrong passphrase!", nil }); err == nil {
		t.Error("a wrong passphrase must not verify")
	}
}

func TestRestoreSafety(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	if _, err := WriteBackup(h.store, h.vault, h.dir, false, &buf, time.Now()); err != nil {
		t.Fatal(err)
	}
	zp := filepath.Join(t.TempDir(), "b.zip")
	_ = os.WriteFile(zp, buf.Bytes(), 0o600)

	dst := t.TempDir()
	_ = os.WriteFile(filepath.Join(dst, "easm.db"), []byte("existing"), 0o600)
	if _, err := RestoreBackup(zp, dst, false, time.Now()); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("must not overwrite without -force: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "easm.db")); string(b) != "existing" {
		t.Fatal("the existing database was touched")
	}
	if _, err := RestoreBackup(zp, dst, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	kept, _ := filepath.Glob(filepath.Join(dst, "easm.db.before-restore-*"))
	if len(kept) != 1 {
		t.Errorf("the previous database must be kept aside, found %v", kept)
	}

	// a corrupted backup is rejected before anything is changed
	bad := append([]byte(nil), buf.Bytes()...)
	files := readZip(t, bad)
	var tam bytes.Buffer
	zw := zip.NewWriter(&tam)
	for n, c := range files {
		if n == "easm.db" {
			c = append([]byte(nil), c...)
			c[len(c)/2] ^= 0xff
		}
		w, _ := zw.Create(n)
		_, _ = w.Write(c)
	}
	_ = zw.Close()
	tp := filepath.Join(t.TempDir(), "tampered.zip")
	_ = os.WriteFile(tp, tam.Bytes(), 0o600)
	fresh := t.TempDir()
	if _, err := RestoreBackup(tp, fresh, false, time.Now()); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("a tampered backup must be rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fresh, "easm.db")); err == nil {
		t.Error("nothing may be written for a rejected backup")
	}
	// not a backup at all
	np := filepath.Join(t.TempDir(), "x.zip")
	_ = os.WriteFile(np, []byte("hello"), 0o600)
	if _, err := RestoreBackup(np, t.TempDir(), false, time.Now()); err == nil {
		t.Error("garbage accepted")
	}
}

func TestBackupRetentionTouchesOnlyBackups(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "easm-backup-old.txt"), []byte("mine too"), 0o600)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if _, _, err := WriteBackupFile(h.store, h.vault, h.dir, dir, false, 3, base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	got := ListBackups(dir)
	if len(got) != 3 || got[0].Name != BackupFileName(base.Add(4*time.Hour)) {
		t.Fatalf("expected the 3 newest, got %+v", got)
	}
	for _, keep := range []string{"notes.txt", "easm-backup-old.txt"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("retention deleted %s", keep)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.partial")); len(left) != 0 {
		t.Error("partial files left behind")
	}
}

func TestScheduledBackupRuns(t *testing.T) {
	h := newHarness(t)
	h.eng.dataDir = h.dir
	dir := filepath.Join(t.TempDir(), "bk")
	if err := h.store.SaveBackupConfig(BackupConfig{Enabled: true, Dir: dir, EveryHours: 24, Keep: 2}); err != nil {
		t.Fatal(err)
	}
	h.eng.maybeBackup()
	deadline := time.Now().Add(10 * time.Second)
	for len(ListBackups(dir)) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if len(ListBackups(dir)) != 1 {
		t.Fatal("the scheduled backup did not run")
	}
	for h.eng.backing.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// not due again for 24 hours
	h.eng.lastBkTry = time.Time{}
	h.eng.maybeBackup()
	time.Sleep(200 * time.Millisecond)
	if n := len(ListBackups(dir)); n != 1 {
		t.Errorf("ran again too soon: %d backups", n)
	}
	if c := h.store.LoadBackupConfig(h.dir); !strings.HasPrefix(c.LastResult, "ok") {
		t.Errorf("result not recorded: %q", c.LastResult)
	}
	// invalid settings are refused
	for _, bad := range []BackupConfig{{EveryHours: 0, Keep: 3}, {EveryHours: 5, Keep: 0}, {EveryHours: 5, Keep: 3, Dir: "relative/dir"}} {
		if err := h.store.SaveBackupConfig(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestBackupDownloadFromSettings(t *testing.T) {
	e := newWebEnv(t)
	e.eng.dataDir = e.dir
	b := e.browser()
	b.setup("admin", "correct horse battery")
	_, body, _ := b.get("/settings")
	if !strings.Contains(body, "Download a backup") || !strings.Contains(body, "Scheduled backups") {
		t.Fatal("backup card missing")
	}
	code, zbody, resp := b.post("/settings/backup/download", url.Values{})
	if code != 200 || resp.Header.Get("Content-Type") != "application/zip" || !strings.Contains(resp.Header.Get("Content-Disposition"), "easm-backup-") {
		t.Fatalf("download: %d %v", code, resp.Header)
	}
	files := readZip(t, []byte(zbody))
	if files["easm.db"] == nil || files["easm.key"] != nil {
		t.Error("unexpected archive contents")
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, ".download-*")); len(left) != 0 {
		t.Error("temporary download file left behind")
	}
	// asking for the key while it is unprotected is refused with an explanation
	b.post("/settings/backup/download", url.Values{"include_key": {"1"}})
	_, body, _ = b.get("/settings")
	if !strings.Contains(body, "not protected by a passphrase") {
		t.Error("refusal not explained")
	}
	if _, au, _ := b.get("/audit"); !strings.Contains(au, "backup.download") {
		t.Error("download not audited")
	}
}
