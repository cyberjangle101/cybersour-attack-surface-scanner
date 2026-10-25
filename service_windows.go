//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Installing the agent as a Windows service for a shared server.
//
// A service runs as its own low-privilege account, NT SERVICE\easm-agent (a "virtual
// account": Windows manages it and there is no password), not as LocalSystem: the agent
// fetches internet data and drives a headless browser, so a flaw in it must not hand over
// the whole server. Its data lives in %ProgramData%\EASM Agent, which only that account,
// SYSTEM and Administrators can open, not in the installing administrator's profile. The
// program itself is copied to %ProgramFiles%\EASM Agent, where the service account can run
// it but not change it.

// serviceName is the Windows service name (and the virtual account's name).
const serviceName = "easm-agent"

// defaultServiceAccount is the account a new service runs as.
const defaultServiceAccount = `NT SERVICE\` + serviceName

// serviceDataDir is where a service keeps its data ("" when ProgramData is unknown).
func serviceDataDir() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return filepath.Join(v, dataDirName)
	}
	return ""
}

// serviceAccountFor turns the -service-account value into the service's logon name:
// "" means the default virtual account, "LocalSystem" the built-in SYSTEM account.
func serviceAccountFor(flagValue string) string {
	switch strings.ToLower(strings.TrimSpace(flagValue)) {
	case "":
		return defaultServiceAccount
	case "localsystem", "system", `nt authority\system`:
		return ""
	}
	return strings.TrimSpace(flagValue)
}

// installProgram copies this program to %ProgramFiles%\EASM Agent and returns the copy's
// path, so the service does not run from a Downloads folder its account cannot read.
func installProgram() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		return self, nil
	}
	dir := filepath.Join(pf, dataDirName)
	dst := filepath.Join(dir, "easm-agent.exe")
	if strings.EqualFold(filepath.Clean(self), dst) {
		return dst, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: Program Files inherits its own ACL (users read, administrators write)
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	in, err := os.Open(self) //nolint:gosec // G304: this program's own file
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	tmp := dst + ".new"
	out, err := os.Create(tmp) //nolint:gosec // G304: a fixed name in the program folder
	if err != nil {
		return "", fmt.Errorf("copying the program to %s: %w", dir, err)
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Close()
	} else {
		_ = out.Close()
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("copying the program to %s: %w", dir, err)
	}
	return dst, nil
}

// grantServiceData limits the data folder to the service account, SYSTEM and Administrators.
func grantServiceData(dir, account string) error {
	return restrictDirFor(dir, account)
}

// installedServiceAddress returns the web address of an installed easm-agent service
// ("https://127.0.0.1:8080"), read from its command line, or "" when there is none.
func installedServiceAddress() string {
	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return ""
	}
	defer func() { _ = s.Close() }()
	cfg, err := s.Config()
	if err != nil {
		return ""
	}
	return addressFromCommandLine(cfg.BinaryPathName)
}

// addressFromCommandLine finds -listen in a service command line.
func addressFromCommandLine(cmd string) string {
	args, err := windows.DecomposeCommandLine(cmd)
	if err != nil {
		return ""
	}
	listen, scheme := "127.0.0.1:8080", "https"
	for i, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "listen":
			if i+1 < len(args) {
				listen = args[i+1]
			}
		case "plain-http":
			scheme = "http"
		}
	}
	return scheme + "://" + displayAddr(listen)
}
