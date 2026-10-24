package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// findBrowser returns a Chromium-based browser able to take screenshots: the configured path,
// or one found in the usual places (Edge ships with Windows, so servers usually have one).
func findBrowser(configured string) (string, error) {
	if configured != "" {
		if _, err := os.Stat(configured); err != nil {
			return "", fmt.Errorf("the configured browser %q cannot be used: %w", configured, err)
		}
		return configured, nil
	}
	var names []string
	if runtime.GOOS == "windows" {
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if base == "" {
				continue
			}
			names = append(names, filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
		}
		for _, n := range names {
			if _, err := os.Stat(n); err == nil {
				return n, nil
			}
		}
		return "", errors.New("no Chrome or Edge found; set its path in Settings")
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no Chrome, Chromium or Edge found; set its path in Settings")
}

// takeShot renders a page to PNG with a headless browser. The browser is only allowed to
// resolve the one host being shown, mapped to the address the agent already vetted.
func takeShot(ctx context.Context, browser, scheme, host, ip string, port int, timeout time.Duration) ([]byte, error) {
	dir, err := os.MkdirTemp("", "easm-shot-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out := filepath.Join(dir, "page.png")
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	args := []string{"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--hide-scrollbars",
		"--disable-extensions", "--disable-background-networking", "--ignore-certificate-errors",
		"--window-size=1280,800", "--virtual-time-budget=5000",
		"--host-resolver-rules=MAP " + host + " " + ip + ", MAP * ~NOTFOUND",
		"--user-data-dir=" + filepath.Join(dir, "profile"), "--screenshot=" + out}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		args = append(args, "--no-sandbox") // Chromium refuses to start as root otherwise
	}
	args = append(args, url)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, browser, args...) //nolint:gosec // the browser path is an administrator setting; arguments are fixed apart from a vetted host name and address
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && cctx.Err() != nil {
		return nil, fmt.Errorf("browser timed out")
	}
	png, err := os.ReadFile(out) //nolint:gosec // G304: a file we just had the browser write into our own temporary folder
	if err != nil || len(png) < 100 || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		return nil, errors.New("the browser did not produce a screenshot")
	}
	if len(png) > 4<<20 {
		return nil, errors.New("screenshot too large")
	}
	return png, nil
}
