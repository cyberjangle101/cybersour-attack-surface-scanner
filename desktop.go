package main

import (
	"errors"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

// browserCommand returns the command that opens rawURL in the default browser,
// or an error when there is none (no desktop session on Linux, unsupported OS).
// Only http(s) URLs built by the agent itself are accepted.
func browserCommand(rawURL string, getenv func(string) string) (*exec.Cmd, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("not a web address")
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()), nil
	case "darwin":
		return exec.Command("open", u.String()), nil
	case "linux", "freebsd", "openbsd", "netbsd":
		if getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
			return nil, errors.New("no desktop session")
		}
		return exec.Command("xdg-open", u.String()), nil
	}
	return nil, errors.New("opening a browser is not supported on " + runtime.GOOS)
}

// openBrowser starts the default browser on rawURL without waiting for it.
func openBrowser(rawURL string) error {
	cmd, err := browserCommand(rawURL, os.Getenv)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
