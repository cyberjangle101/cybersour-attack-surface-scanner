package main

import (
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The first admin survives a restart, is stored encrypted, and API keys are never plaintext on disk.
func TestUserAndSecretsPersistEncrypted(t *testing.T) {
	dir := t.TempDir()
	open := func() (*Store, *Vault, *Engine) {
		v, err := OpenVault(filepath.Join(dir, "easm.key"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := OpenEncryptedStore(filepath.Join(dir, "easm.db"), v.DBKey(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetVault(v); err != nil {
			t.Fatal(err)
		}
		return st, v, NewEngine(st, v, testLogger(t))
	}
	st, _, eng := open()
	hash, _ := hashPassword("correct horse battery")
	if _, err := st.CreateUser("admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	const shodanKey = "SHODANKEYSHODANKEYSHODANKEY123456"
	if err := eng.SetSecret(secretShodan, shodanKey); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// raw database file: no plaintext bcrypt hash, no plaintext key
	raw, _ := os.ReadFile(filepath.Join(dir, "easm.db"))
	if wal, err := os.ReadFile(filepath.Join(dir, "easm.db-wal")); err == nil {
		raw = append(raw, wal...)
	}
	if strings.Contains(string(raw), shodanKey) || strings.Contains(string(raw), "$2a$") || strings.Contains(string(raw), "$2b$") {
		t.Fatal("secrets or password hashes are readable in the database file")
	}
	keyRaw, _ := os.ReadFile(filepath.Join(dir, "easm.key"))
	if len(strings.TrimSpace(string(keyRaw))) != 64 {
		t.Fatal("key file should hold a 256-bit key (64 hex chars)")
	}

	// "restart": reopen everything and log in again
	st2, _, eng2 := open()
	defer func() { _ = st2.Close() }()
	u, err := st2.GetUserByName("admin")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte("correct horse battery")) != nil {
		t.Fatalf("admin cannot sign in after restart: %v", err)
	}
	if eng2.Secret(secretShodan) != shodanKey {
		t.Fatal("API key not recoverable after restart")
	}
	var stored string
	if err := st2.db.QueryRow(`SELECT hash FROM users WHERE username='admin'`).Scan(&stored); err != nil || !strings.HasPrefix(stored, sealedPrefix) {
		t.Fatalf("stored password hash is not sealed: %.12s", stored)
	}
}

// Databases from older versions hold plain bcrypt hashes; they are sealed on upgrade and still work.
func TestLegacyPlainHashesAreUpgraded(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "easm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	hash, _ := hashPassword("correct horse battery")
	if _, err := st.CreateUser("old", hash, "admin"); err != nil { // no vault yet: stored plain
		t.Fatal(err)
	}
	v, _ := OpenVault(filepath.Join(dir, "easm.key"))
	if err := st.SetVault(v); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := st.db.QueryRow(`SELECT hash FROM users WHERE username='old'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, sealedPrefix) || strings.Contains(stored, "$2") {
		t.Fatalf("hash not sealed: %.20s", stored)
	}
	u, err := st.GetUserByName("old")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte("correct horse battery")) != nil {
		t.Fatal("upgraded user can no longer sign in")
	}
}

// Full web round-trip: set up the first admin, "restart" the server on the same data, sign in again.
func TestWebLoginSurvivesRestart(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")

	web2, err := NewServer(e.store, NewEngine(e.store, e.vault, e.log), e.log, &Bootstrap{Listen: "127.0.0.1:8080", PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	srv2 := newTestServer(t, web2)
	b2 := &browser{t: t, base: srv2.URL, c: e.browser().c}
	if code, _, r := b2.get("/"); code != 303 || loc(r) != "/login" {
		t.Fatalf("after restart the app must ask for login, not setup: %d %s", code, loc(r))
	}
	tok := b2.loginPre("/login")
	if code, bd, _ := b2.postRaw("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {"correct horse battery"}}); code != 303 {
		t.Fatalf("login after restart failed: %d %.200s", code, bd)
	}
}

func testLogger(t testing.TB) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func newTestServer(t *testing.T, s *Server) *httptest.Server {
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}
