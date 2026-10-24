package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// dataDirName is the folder name used inside the per-user / per-machine data location.
const dataDirName = "EASM Agent"

// legacyFiles are the files older versions kept next to the program. A folder that
// holds one of the first two is treated as an existing installation.
var legacyFiles = []string{"easm.db", "easm.key", "easm.db-wal", "easm.db-shm", "easm.db-journal",
	"server.crt", "server.key", "custom.crt", "custom.key.sealed", "easm.log"}

// defaultDataDir picks where the database, key and log live when nothing was configured.
//
//	Windows: %LocalAppData%\EASM Agent   (not "Roaming": a database must not sync between PCs)
//	Linux:   /var/lib/easm-agent when running as root (a service), otherwise
//	         $XDG_DATA_HOME/easm-agent or ~/.local/share/easm-agent
//
// An installation made by an older version (easm.db or easm.key next to the program) keeps
// working where it is; legacy is true then so the agent can tell the administrator how to move it.
func defaultDataDir(exeDir string) (dir string, legacy bool, err error) {
	if hasLegacyData(exeDir) {
		return exeDir, true, nil
	}
	dir, err = platformDataDir(runtime.GOOS, os.Getenv, os.Geteuid(), os.UserHomeDir)
	return dir, false, err
}

func hasLegacyData(dir string) bool {
	for _, n := range []string{"easm.db", "easm.key"} {
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// platformDataDir is defaultDataDir without the file system checks, so it can be tested.
func platformDataDir(goos string, env func(string) string, euid int, home func() (string, error)) (string, error) {
	switch goos {
	case "windows":
		if v := env("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, dataDirName), nil
		}
		if v := env("APPDATA"); v != "" {
			return filepath.Join(v, dataDirName), nil
		}
		if v := env("ProgramData"); v != "" {
			return filepath.Join(v, dataDirName), nil
		}
	default: // Unix paths: built with path, not filepath, so the result is right whatever OS computes it
		if euid == 0 {
			return "/var/lib/easm-agent", nil
		}
		if v := env("XDG_DATA_HOME"); v != "" && path.IsAbs(v) {
			return path.Join(v, "easm-agent"), nil
		}
		if h, err := home(); err == nil && h != "" {
			return path.Join(h, ".local", "share", "easm-agent"), nil
		}
	}
	return "", errors.New("cannot work out a data folder for this account; start the agent with -data-dir <folder>")
}

// platformDataDirNow is the default folder for this machine and account, ignoring any older installation.
func platformDataDirNow() (string, bool, error) {
	dir, err := platformDataDir(runtime.GOOS, os.Getenv, os.Geteuid(), os.UserHomeDir)
	return dir, false, err
}

// prepareDataDir creates the data folder and limits it to the current user (and, on
// Windows, SYSTEM and Administrators so the service can still use it).
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return restrictDir(dir)
}

// migrateLegacyData moves an installation from the program's folder into dst.
// Nothing is deleted until the copy of every file has been written.
func migrateLegacyData(src, dst string) ([]string, error) {
	if sameDir(src, dst) {
		return nil, errors.New("the data is already in the default folder")
	}
	if !hasLegacyData(src) {
		return nil, fmt.Errorf("no easm.db or easm.key found next to the program (%s)", src)
	}
	if hasLegacyData(dst) {
		return nil, fmt.Errorf("%s already holds an installation; refusing to overwrite it", dst)
	}
	if err := prepareDataDir(dst); err != nil {
		return nil, err
	}
	var moved []string
	for _, n := range legacyFiles {
		from := filepath.Join(src, n)
		if st, err := os.Stat(from); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if err := copyFile(from, filepath.Join(dst, n)); err != nil {
			return nil, fmt.Errorf("copying %s: %w (nothing was removed)", n, err)
		}
		moved = append(moved, n)
	}
	for _, n := range moved {
		_ = os.Remove(filepath.Join(src, n))
	}
	return moved, nil
}

func sameDir(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
}

func copyFile(from, to string) error {
	in, err := os.Open(from) //nolint:gosec // G304: the agent's own data file
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: destination inside the new data folder
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
