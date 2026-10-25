//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsKeyProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easm.key")
	v, err := OpenVault(path) // a new, plain key
	if err != nil {
		t.Fatal(err)
	}
	if err := v.ProtectWithWindows(path); err != nil || v.Protection() != keyWindows {
		t.Fatalf("protect with Windows: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), dpapiMagic) || strings.Contains(string(raw), string(v.master)) {
		t.Fatal("the key file must hold only the protected key")
	}
	v2, err := OpenVault(path)
	if err != nil || v2.Protection() != keyWindows || string(v2.master) != string(v.master) {
		t.Fatalf("reopening the protected key: %v", err)
	}
	// A damaged blob (or one from another account) is refused with a clear explanation.
	bad := []byte(dpapiMagic + "AAAA" + strings.TrimPrefix(string(raw), dpapiMagic)[4:])
	if _, err := unwrapWindows(bad); err == nil || !strings.Contains(err.Error(), "recovery copy") {
		t.Errorf("a damaged protected key must be refused with advice: %v", err)
	}
	// It can still be turned back into a plain key or a passphrase key from the running vault.
	if err := ProtectKeyFile(path, "a long passphrase here"); err != nil {
		t.Fatal(err)
	}
}

func TestRestrictDirGrantsOwnAccount(t *testing.T) {
	dir := t.TempDir()
	if err := restrictDir(dir); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("icacls", dir).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	acl := string(out)
	acct := windowsAccount()
	if !strings.Contains(strings.ToLower(acl), strings.ToLower(acct)) || strings.Contains(acl, `BUILTIN\Users`) || strings.Contains(acl, "Everyone") {
		t.Errorf("the data folder must be limited to %s, SYSTEM and Administrators:\n%s", acct, acl)
	}
}

func TestServiceHelpers(t *testing.T) {
	if a := restrictArgs(`C:\d`, "S-1-5-80-1"); a[len(a)-1] != "*S-1-5-80-1:(OI)(CI)F" {
		t.Errorf("a SID is granted with *: %v", a)
	}
	if a := restrictArgs(`C:\d`, `NT SERVICE\easm-agent`); a[len(a)-1] != `NT SERVICE\easm-agent:(OI)(CI)F` {
		t.Errorf("an account name is granted as is: %v", a)
	}
	if a := restrictArgs(`C:\d`, ""); len(a) != 6 {
		t.Errorf("no extra account: %v", a)
	}
	for in, want := range map[string]string{"": `NT SERVICE\easm-agent`, "LocalSystem": "", `CORP\easm-gmsa$`: `CORP\easm-gmsa$`} {
		if got := serviceAccountFor(in); got != want {
			t.Errorf("serviceAccountFor(%q) = %q, want %q", in, got, want)
		}
	}
	cmd := `"C:\Program Files\EASM Agent\easm-agent.exe" -data-dir "C:\ProgramData\EASM Agent" -listen 10.0.0.5:8443`
	if got := addressFromCommandLine(cmd); got != "https://10.0.0.5:8443" {
		t.Errorf("service address = %q", got)
	}
	if got := addressFromCommandLine(`easm-agent.exe -plain-http`); got != "http://127.0.0.1:8080" {
		t.Errorf("default service address = %q", got)
	}
	if d := serviceDataDir(); !strings.HasSuffix(d, dataDirName) || !strings.EqualFold(filepath.Dir(d), os.Getenv("ProgramData")) {
		t.Errorf("service data folder = %q", d)
	}
}
