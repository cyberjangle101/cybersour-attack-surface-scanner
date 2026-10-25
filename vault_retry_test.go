package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// lockedKey makes a passphrase-protected key file and swaps in a terminal-like
// passphrase source that returns answers in turn.
func lockedKey(t *testing.T, interactive bool, answers ...string) (path string, calls *int, out *bytes.Buffer) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "easm.key")
	if _, err := OpenVault(path); err != nil {
		t.Fatal(err)
	}
	if err := ProtectKeyFile(path, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	oldSrc, oldInt, oldOut := PassphraseSource, passphraseInteractive, promptOut
	t.Cleanup(func() { PassphraseSource, passphraseInteractive, promptOut = oldSrc, oldInt, oldOut })
	calls, out = new(int), new(bytes.Buffer)
	PassphraseSource = func() (string, error) {
		*calls++
		if *calls > len(answers) {
			t.Fatalf("asked %d times", *calls)
		}
		return answers[*calls-1], nil
	}
	passphraseInteractive = func() bool { return interactive }
	promptOut = out
	return path, calls, out
}

func TestPassphraseRetryAtTerminal(t *testing.T) {
	path, calls, out := lockedKey(t, true, "typo one", "typo two", "correct horse battery")
	if _, err := OpenVault(path); err != nil {
		t.Fatalf("third attempt should unlock: %v", err)
	}
	if *calls != 3 || strings.Count(out.String(), "Incorrect Password, try again.") != 2 || strings.Contains(out.String(), "Aborting") {
		t.Errorf("calls=%d output=%q", *calls, out)
	}
}

func TestPassphraseAbortsAfterThreeAttempts(t *testing.T) {
	path, calls, out := lockedKey(t, true, "wrong 1", "wrong 2", "wrong 3")
	_, err := OpenVault(path)
	if !errors.Is(err, errWrongPassphrase) || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("want a wrong-passphrase error after 3 attempts, got %v", err)
	}
	if *calls != 3 || !strings.HasSuffix(out.String(), "Incorrect Password. Aborting.\n") {
		t.Errorf("calls=%d output=%q", *calls, out)
	}
}

func TestPassphraseFromEnvironmentGetsOneAttempt(t *testing.T) {
	path, calls, out := lockedKey(t, false, "wrong passphrase!!")
	if _, err := OpenVault(path); !errors.Is(err, errWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	if *calls != 1 || out.Len() != 0 {
		t.Errorf("a non-interactive source must not be retried: calls=%d output=%q", *calls, out)
	}
}

func TestPrintDataLocation(t *testing.T) {
	boot := &Bootstrap{DataDir: filepath.Join("C:", "data")}
	var b bytes.Buffer
	printDataLocation(&b, boot)
	for _, want := range []string{"Data folder: " + boot.DataDir, "Database:    " + boot.DBPath(), "Key file:    " + boot.KeyPath()} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("start-up banner lacks %q:\n%s", want, b.String())
		}
	}
}
