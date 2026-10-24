package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 64) }

// readAllDBFiles returns the concatenated bytes of the database and any journal/WAL files.
func readAllDBFiles(t *testing.T, path string) []byte {
	t.Helper()
	var all []byte
	for _, s := range []string{"", "-wal", "-journal"} {
		if b, err := os.ReadFile(path + s); err == nil {
			all = append(all, b...)
		}
	}
	return all
}

func TestEncryptedStoreIsUnreadableOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easm.db")
	st, err := OpenEncryptedStore(path, testKey(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "TOP-SECRET-HOSTNAME-vpn.internal.example"
	if err := st.setMeta("note", marker); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ { // enough rows to span many pages and exercise the journal/WAL
		if _, err := st.db.Exec(`INSERT INTO subdomains(root,host,sources,first_seen,last_seen) VALUES(?,?,?,?,?)`,
			"example.test", fmt.Sprintf("%s-%d", marker, i), "x", nowUTC(), nowUTC()); err != nil {
			t.Fatal(err)
		}
	}
	raw := readAllDBFiles(t, path) // while still open: WAL/journal included
	if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte("example.test")) || bytes.HasPrefix(raw, sqliteMagic) {
		t.Fatal("plaintext is visible in the database files")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	raw = readAllDBFiles(t, path)
	if bytes.Contains(raw, []byte("subdomains")) || bytes.Contains(raw, []byte(marker)) || bytes.HasPrefix(raw, sqliteMagic) {
		t.Fatal("plaintext (even table names) visible after close")
	}

	// right key reads it back
	st2, err := OpenEncryptedStore(path, testKey(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := st2.getMeta("note"); !ok || v != marker {
		t.Fatalf("data lost: %q %v", v, ok)
	}
	_ = st2.Close()

	// wrong key is refused with advice, and cannot be used to read anything
	if _, err := OpenEncryptedStore(path, testKey(2), nil); err == nil || !strings.Contains(err.Error(), "easm.key") {
		t.Fatalf("wrong key must be rejected with guidance, got %v", err)
	}
	// and the unencrypted driver cannot open it
	if p, _ := isPlainSQLite(path); p {
		t.Fatal("file still looks like plain SQLite")
	}
	if plain, err := OpenStore(path); err == nil {
		_ = plain.Close()
		t.Fatal("encrypted file opened without a key")
	}
}

func TestPlainDatabaseIsMigratedAndShredded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easm.db")
	old, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "enc-secret-value-12345"
	_ = old.setMeta("secret:shodan_key", secret)
	hash, _ := hashPassword("correct horse battery")
	if _, err := old.CreateUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := old.AddTarget(mustTarget(t, "migrate.example")); err != nil {
		t.Fatal(err)
	}
	// leave the plain DB open with a live WAL, as a crashed v1.3 process would
	if !bytes.Contains(readAllDBFiles(t, path), []byte("migrate.example")) {
		t.Fatal("test precondition: plaintext should be visible before migration")
	}
	_ = old.Close()

	st, err := OpenEncryptedStore(path, testKey(7), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if n, _ := st.CountUsers(); n != 1 {
		t.Fatalf("user lost in migration (%d)", n)
	}
	if ts, _ := st.ListTargets(); len(ts) != 1 || ts[0].Domain != "migrate.example" {
		t.Fatalf("targets lost: %+v", ts)
	}
	if v, _, _ := st.getMeta("secret:shodan_key"); v != secret {
		t.Fatal("meta lost")
	}
	raw := readAllDBFiles(t, path)
	if bytes.Contains(raw, []byte("migrate.example")) || bytes.Contains(raw, []byte(secret)) || bytes.HasPrefix(raw, sqliteMagic) {
		t.Fatal("plaintext still on disk after migration")
	}
	if _, err := os.Stat(path + ".encrypting"); err == nil {
		t.Error("temporary migration file left behind")
	}
	// a second start is a no-op
	_ = st.Close()
	st2, err := OpenEncryptedStore(path, testKey(7), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = st2.Close()
}

func TestInterruptedMigrationIsCompleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easm.db")
	st, err := OpenEncryptedStore(path, testKey(3), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.setMeta("k", "v")
	_ = st.Close()
	// simulate: the verified encrypted copy exists under the temp name, the original is gone
	if err := os.Rename(path, path+".encrypting"); err != nil {
		t.Fatal(err)
	}
	st, err = OpenEncryptedStore(path, testKey(3), nil)
	if err != nil {
		t.Fatalf("did not recover: %v", err)
	}
	defer func() { _ = st.Close() }()
	if v, _, _ := st.getMeta("k"); v != "v" {
		t.Fatal("data missing after recovery")
	}
}

func TestDBKeyIsDerivedAndDistinct(t *testing.T) {
	dir := t.TempDir()
	v1, _ := OpenVault(filepath.Join(dir, "a.key"))
	v2, _ := OpenVault(filepath.Join(dir, "b.key"))
	if len(v1.DBKey()) != 64 || bytes.Equal(v1.DBKey(), v2.DBKey()) || bytes.Equal(v1.DBKey()[:32], v1.master) {
		t.Fatal("database key must be 64 bytes, unique per master key and not equal to it")
	}
	if !bytes.Equal(v1.DBKey(), v1.DBKey()) {
		t.Fatal("derivation must be deterministic")
	}
}

func mustTarget(t *testing.T, domain string) *Target {
	t.Helper()
	tg, err := TargetFromForm(domain, "", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestPassphraseProtectedKeyFile(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "easm.key")
	v0, err := OpenVault(kp)
	if err != nil {
		t.Fatal(err)
	}
	want := v0.DBKey()
	sealed, _ := v0.Seal("secret")

	if err := ProtectKeyFile(kp, "a long passphrase here"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(kp)
	if !strings.HasPrefix(string(raw), wrappedMagic) || bytes.Contains(raw, []byte(hexOf(v0.master))) {
		t.Fatal("key file is not protected")
	}
	old := PassphraseSource
	defer func() { PassphraseSource = old }()

	PassphraseSource = func() (string, error) { return "wrong passphrase!!", nil }
	if _, err := OpenVault(kp); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("wrong passphrase accepted: %v", err)
	}
	PassphraseSource = func() (string, error) { return "a long passphrase here", nil }
	v1, err := OpenVault(kp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v1.DBKey(), want) {
		t.Fatal("unwrapped key differs")
	}
	if p, err := v1.Open(sealed); err != nil || p != "secret" {
		t.Fatal("previously sealed data no longer readable")
	}
	if err := UnprotectKeyFile(kp); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(kp)
	if strings.HasPrefix(string(raw), wrappedMagic) {
		t.Fatal("still protected")
	}
	if v2, err := OpenVault(kp); err != nil || !bytes.Equal(v2.DBKey(), want) {
		t.Fatal("round trip changed the key")
	}
	// corrupted protected file is an error, not a panic
	_ = os.WriteFile(kp, []byte(wrappedMagic+"!!!notbase64"), 0o600)
	if _, err := OpenVault(kp); err == nil {
		t.Fatal("corrupt protected key accepted")
	}
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }
