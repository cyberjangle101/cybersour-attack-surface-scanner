package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func firstRunBoot(t *testing.T) *Bootstrap {
	t.Helper()
	return &Bootstrap{DataDir: t.TempDir()}
}

// TestFirstRunCreatesPassphraseLockedKey checks an unattended first start with a
// passphrase makes a locked key file that opens only with that passphrase.
func TestFirstRunCreatesPassphraseLockedKey(t *testing.T) {
	b := firstRunBoot(t)
	t.Setenv("EASM_KEY_PASSPHRASE", "correct horse battery")
	orig := PassphraseSource
	defer func() { PassphraseSource = orig }()
	if err := ensureKeyFile(b, slog.Default()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(b.KeyPath())
	if !strings.HasPrefix(string(raw), wrappedMagic) {
		t.Fatal("key file must be stored locked with the passphrase")
	}
	if _, err := OpenVault(b.KeyPath()); err != nil {
		t.Fatalf("opening with the passphrase failed: %v", err)
	}
	PassphraseSource = func() (string, error) { return "wrong passphrase!!", nil }
	if _, err := OpenVault(b.KeyPath()); err == nil {
		t.Fatal("a wrong passphrase must not open the key")
	}
}

// TestFirstRunRefusesWithoutPassphrase covers the unattended cases that must not silently weaken security.
func TestFirstRunRefusesWithoutPassphrase(t *testing.T) {
	t.Setenv("EASM_KEY_PASSPHRASE", "")
	b := firstRunBoot(t)
	err := ensureKeyFile(b, slog.Default())
	if dpapiSupported {
		// Windows (a service): the key is tied to the account instead of being left unprotected.
		v, oerr := OpenVault(b.KeyPath())
		if err != nil || oerr != nil || v.Protection() != keyWindows {
			t.Fatalf("an unattended first start on Windows must protect the key with the account: %v / %v", err, oerr)
		}
		_ = os.Remove(b.KeyPath())
	} else if err == nil || fileExists(b.KeyPath()) {
		t.Fatalf("a first start with no terminal and no passphrase must stop, got %v", err)
	}
	t.Setenv("EASM_KEY_PASSPHRASE", "short")
	if err := ensureKeyFile(b, slog.Default()); err == nil {
		t.Fatal("a too-short passphrase must be refused")
	}
	b.NoPassphrase = true
	t.Setenv("EASM_KEY_PASSPHRASE", "")
	if err := ensureKeyFile(b, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(b.KeyPath()); strings.HasPrefix(string(raw), wrappedMagic) {
		t.Fatal("-no-passphrase must store a plain key")
	}
}

// TestFirstRunNeverReplacesAKeyOrOrphansADatabase guards against making a key that cannot open existing data.
func TestFirstRunNeverReplacesAKeyOrOrphansADatabase(t *testing.T) {
	b := firstRunBoot(t)
	t.Setenv("EASM_KEY_PASSPHRASE", "correct horse battery")
	if err := os.WriteFile(b.DBPath(), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeyFile(b, slog.Default()); err == nil || fileExists(b.KeyPath()) {
		t.Fatalf("a database without its key must not get a new key: %v", err)
	}
	b2 := firstRunBoot(t)
	if err := os.WriteFile(filepath.Join(b2.DataDir, "easm.key"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeyFile(b2, slog.Default()); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(b2.KeyPath()); string(raw) != "keep me" {
		t.Fatal("an existing key file must never be overwritten")
	}
}
