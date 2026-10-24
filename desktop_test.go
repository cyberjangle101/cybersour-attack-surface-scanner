package main

import (
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBrowserCommand(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	desktop := env(map[string]string{"DISPLAY": ":0"})
	for _, bad := range []string{"", "file:///etc/passwd", "javascript:alert(1)", "https://", "calc.exe", "ftp://x"} {
		if _, err := browserCommand(bad, desktop); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	cmd, err := browserCommand("https://127.0.0.1:8080", desktop)
	if err != nil {
		t.Fatalf("local https address refused: %v", err)
	}
	if got := cmd.Args[len(cmd.Args)-1]; got != "https://127.0.0.1:8080" {
		t.Errorf("browser gets %q", got)
	}
	if runtime.GOOS == "linux" {
		if _, err := browserCommand("https://127.0.0.1:8080", env(nil)); err == nil {
			t.Error("a headless Linux server must not try to open a browser")
		}
	}
}

func TestStopAgentFromWeb(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/users", url.Values{"username": {"analyst1"}, "password": {"analyst password 1"}, "role": {"analyst"}})

	// Under a service manager (no stop hook) the button is absent and the route refuses.
	if _, body, _ := admin.get("/health"); strings.Contains(body, "Stop agent") {
		t.Error("Stop agent offered without a stop hook")
	}
	if code, _, _ := admin.post("/system/stop", nil); code != 409 {
		t.Errorf("stop without a hook: %d", code)
	}

	var stops atomic.Int32
	e.web.stop = func() { stops.Add(1) }
	if _, body, _ := admin.get("/health"); !strings.Contains(body, "Stop agent") {
		t.Error("admin is not offered Stop agent on an interactive run")
	}
	an := e.browser()
	if an.login("analyst1", "analyst password 1") != 303 {
		t.Fatal("analyst login")
	}
	if _, body, _ := an.get("/health"); strings.Contains(body, "Stop agent") {
		t.Error("analyst must not see Stop agent")
	}
	if code, _, _ := an.post("/system/stop", nil); code != 403 {
		t.Errorf("analyst stop: %d", code)
	}
	if code, _, _ := admin.postRaw("/system/stop", url.Values{}); code != 403 {
		t.Errorf("stop without CSRF: %d", code)
	}
	if stops.Load() != 0 {
		t.Fatal("agent stopped by a forbidden request")
	}
	code, body, _ := admin.post("/system/stop", nil)
	if code != 200 || !strings.Contains(body, "Agent stopped") || stops.Load() != 1 {
		t.Errorf("admin stop: %d stops=%d", code, stops.Load())
	}
	if _, au, _ := admin.get("/audit"); !strings.Contains(au, "agent.stop") {
		t.Error("stopping the agent is not in the audit trail")
	}
}
