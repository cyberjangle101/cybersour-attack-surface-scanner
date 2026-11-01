package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Container support: the passphrase from a mounted secret file, and managed mode (no self-update).

func TestPassphraseFromFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("EASM_KEY_PASSPHRASE", "")

	t.Setenv("EASM_KEY_PASSPHRASE_FILE", "")
	if _, ok, _ := envPassphrase(); ok {
		t.Fatal("neither variable set: nothing given")
	}
	for name, body := range map[string]string{"lf": "correct horse battery\n", "crlf": "correct horse battery\r\n", "bare": "correct horse battery"} {
		t.Setenv("EASM_KEY_PASSPHRASE_FILE", write(name, body))
		if p, ok, err := envPassphrase(); !ok || err != nil || p != "correct horse battery" {
			t.Errorf("%s: got %q ok=%v err=%v", name, p, ok, err)
		}
	}
	// Spaces inside or at the ends are part of the passphrase; only the line ending goes.
	t.Setenv("EASM_KEY_PASSPHRASE_FILE", write("spaces", " two  spaces \n"))
	if p, _, _ := envPassphrase(); p != " two  spaces " {
		t.Errorf("spaces: %q", p)
	}
	for name, path := range map[string]string{
		"empty":      write("empty", "\n"),
		"missing":    filepath.Join(dir, "nope"),
		"huge":       write("huge", strings.Repeat("x", maxPassphraseFile+1)),
		"two lines":  write("two", "first line xxxx\nsecond line\n"),
		"blank line": write("blank", "passphrase xxxx\n\r\n"),
	} {
		t.Setenv("EASM_KEY_PASSPHRASE_FILE", path)
		if _, ok, err := envPassphrase(); !ok || err == nil {
			t.Errorf("%s: want an error, got ok=%v err=%v", name, ok, err)
		} else if strings.Contains(err.Error(), "xxxx") {
			t.Errorf("%s: the error must not echo the file's contents", name)
		}
	}
	// The variable wins over the file.
	t.Setenv("EASM_KEY_PASSPHRASE_FILE", write("file", "from the file 123\n"))
	t.Setenv("EASM_KEY_PASSPHRASE", "from the variable 123")
	if p, _, _ := envPassphrase(); p != "from the variable 123" {
		t.Errorf("precedence: %q", p)
	}
	if passphraseInteractive() {
		t.Error("a configured passphrase means no prompt")
	}
}

func TestFirstRunAndUnlockFromPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASM_KEY_PASSPHRASE", "")
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("tooshort\n"), 0o600)
	t.Setenv("EASM_KEY_PASSPHRASE_FILE", short)
	if _, err := firstRunPassphrase(&Bootstrap{}); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Errorf("a short passphrase must be refused: %v", err)
	}

	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte("a long enough passphrase\n"), 0o600)
	t.Setenv("EASM_KEY_PASSPHRASE_FILE", good)
	p, err := firstRunPassphrase(&Bootstrap{})
	if err != nil || p != "a long enough passphrase" {
		t.Fatalf("first run: %q %v", p, err)
	}
	// The same file unlocks the key on later starts.
	key := filepath.Join(dir, "easm.key")
	if err := createKeyFile(key, p); err != nil {
		t.Fatal(err)
	}
	prev := PassphraseSource
	t.Cleanup(func() { PassphraseSource = prev })
	if got, err := PassphraseSource(); err != nil || got != p {
		t.Errorf("unlock: %q %v", got, err)
	}
}

// -show-setup-code reads back exactly the code the running agent wrote, and fails clearly after setup.
func TestShowSetupCode(t *testing.T) {
	e := newWebEnv(t)
	dir := t.TempDir()
	e.web.boot.DataDir = dir
	shown, err := e.web.prepareSetupCode() // what the agent writes at start-up
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSetupCode(dir)
	if err != nil || got != shown || len(got) != 23 {
		t.Fatalf("read back %q (%v), the agent shows %q", got, err, shown)
	}
	e.browser().setup("admin", "correct horse battery")
	if _, err := readSetupCode(dir); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("after setup: %v", err)
	}
}

// Both new file readers take arbitrary bytes: never panic, never return a line break.
func FuzzContainerFiles(f *testing.F) {
	f.Add([]byte("EASM Agent first-administrator setup code:\r\n\r\n    ABCDE-FGHJK-MNPQR-STUVW\r\n"))
	f.Add([]byte("correct horse battery\n"))
	f.Add([]byte("\x00\xff    \n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, setupCodeFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, err := readSetupCode(dir); err == nil && (code == "" || strings.ContainsAny(code, "\r\n")) {
			t.Errorf("setup code %q", code)
		}
		p := filepath.Join(dir, "passphrase")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("EASM_KEY_PASSPHRASE", "")
		t.Setenv("EASM_KEY_PASSPHRASE_FILE", p)
		if pass, ok, err := envPassphrase(); !ok || (err == nil && (pass == "" || strings.HasSuffix(pass, "\n"))) {
			t.Errorf("passphrase %q ok=%v err=%v", pass, ok, err)
		}
	})
}

func TestManagedModeSwitch(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "false": false, "FALSE": false, "1": true, "true": true, "yes": true} {
		t.Setenv("EASM_MANAGED", v)
		if got := managedMode(); got != want {
			t.Errorf("EASM_MANAGED=%q: %v, want %v", v, got, want)
		}
	}
}

// In managed mode the agent still reports a new release but never installs over itself.
func TestManagedModeNeverSelfUpdates(t *testing.T) {
	t.Setenv("EASM_MANAGED", "1")
	e, f, exe := webUpdateEnv(t, "1.8.0")
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("signed v1.9.0")}, true)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/system/update/check", nil)

	_, body, _ := admin.get("/health")
	if !strings.Contains(body, "Version 1.9.0 available") || strings.Contains(body, "Back up and install") || !strings.Contains(body, "runs from a container image") {
		t.Errorf("managed: report the release, offer no install, say why\n%.400s", body)
	}
	code, _, r := admin.post("/system/update/install", url.Values{"version": {"1.9.0"}})
	if code != 303 || !strings.HasPrefix(loc(r), "/health") {
		t.Fatalf("managed install: %d %s", code, loc(r))
	}
	if _, after, _ := admin.get("/health"); !strings.Contains(after, "deploy the new image tag") {
		t.Error("the refusal should explain what to do")
	}
	if b, _ := os.ReadFile(exe); string(b) != "running 1.8.0" {
		t.Error("managed mode replaced the program")
	}
	if backups := ListBackups(filepath.Join(e.dir, "backups")); len(backups) != 0 {
		t.Errorf("a refused update must not take a backup: %d", len(backups))
	}
}
