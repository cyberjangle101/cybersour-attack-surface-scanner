package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformDataDir(t *testing.T) {
	home := func() (string, error) { return "/home/ann", nil }
	cases := []struct {
		goos string
		env  map[string]string
		euid int
		want string
	}{
		{"windows", map[string]string{"LOCALAPPDATA": `C:\Users\ann\AppData\Local`}, 0, filepath.Join(`C:\Users\ann\AppData\Local`, "EASM Agent")},
		{"windows", map[string]string{"APPDATA": `C:\Users\ann\AppData\Roaming`}, 0, filepath.Join(`C:\Users\ann\AppData\Roaming`, "EASM Agent")},
		{"linux", nil, 0, "/var/lib/easm-agent"},
		{"linux", nil, 1000, "/home/ann/.local/share/easm-agent"},
		{"linux", map[string]string{"XDG_DATA_HOME": "/data/xdg"}, 1000, "/data/xdg/easm-agent"},
		{"linux", map[string]string{"XDG_DATA_HOME": "relative"}, 1000, "/home/ann/.local/share/easm-agent"},
	}
	for _, c := range cases {
		got, err := platformDataDir(c.goos, func(k string) string { return c.env[k] }, c.euid, home)
		if err != nil || got != c.want {
			t.Errorf("%s %v euid=%d: got %q, %v want %q", c.goos, c.env, c.euid, got, err, c.want)
		}
	}
	if _, err := platformDataDir("windows", func(string) string { return "" }, 0, home); err == nil {
		t.Error("no environment at all should be an error")
	}
}

func TestLegacyDataIsKeptAndCanBeMigrated(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "new")
	if dir, legacy, _ := defaultDataDir(src); legacy || dir == src {
		t.Fatalf("an empty program folder must not count as an installation (dir=%q legacy=%v)", dir, legacy)
	}
	for n, c := range map[string]string{"easm.db": "db", "easm.key": "key", "server.crt": "crt", "unrelated.txt": "x"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if dir, legacy, _ := defaultDataDir(src); !legacy || dir != src {
		t.Fatalf("an existing installation must keep working where it is (dir=%q legacy=%v)", dir, legacy)
	}
	moved, err := migrateLegacyData(src, dst)
	if err != nil || len(moved) != 3 {
		t.Fatalf("moved=%v err=%v", moved, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "easm.key")); string(b) != "key" {
		t.Error("key not copied")
	}
	if _, err := os.Stat(filepath.Join(src, "easm.db")); err == nil {
		t.Error("old database should be gone after a successful move")
	}
	if _, err := os.Stat(filepath.Join(src, "unrelated.txt")); err != nil {
		t.Error("unrelated files must be left alone")
	}
	if _, err := migrateLegacyData(src, dst); err == nil {
		t.Error("a second migration with nothing left must fail")
	}
	// never overwrite an existing installation at the destination
	if err := os.WriteFile(filepath.Join(src, "easm.db"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateLegacyData(src, dst); err == nil {
		t.Error("must refuse to overwrite an installation")
	}
}
