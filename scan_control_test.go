package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// runningScanEnv starts the scheduler with a target whose crt.sh answer takes
// long enough that the test can act while the scan is in flight.
func runningScanEnv(t *testing.T, domain string) (*webEnv, *browser, *Target) {
	t.Helper()
	e := newWebEnv(t)
	e.seedDomain(domain, "203.0.113.90", 64590)
	e.src.mu.Lock()
	e.src.crtDelay = map[string]time.Duration{domain: 20 * time.Second}
	e.src.mu.Unlock()
	admin := e.browser()
	admin.setup("admin", "correct horse battery")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	tg := e.addTarget(domain, "")
	e.eng.Wake()
	waitFor(t, "scan to start", 5*time.Second, func() bool { return e.eng.Progress().Get(tg.ID) != nil })
	return e, admin, tg
}

// UAT defect: pausing a domain while it was being scanned left the scan running.
func TestPauseStopsRunningScan(t *testing.T) {
	e, admin, tg := runningScanEnv(t, "pause.test")
	path := fmt.Sprintf("/targets/%d", tg.ID)

	if code, _, _ := admin.post(path+"/pause", nil); code != 303 {
		t.Fatalf("pause: %d", code)
	}
	_, body, _ := admin.get(path)
	if !strings.Contains(body, "running scan was stopped") {
		t.Error("pausing during a scan should say the scan was stopped")
	}
	waitFor(t, "scan to stop", 5*time.Second, func() bool {
		got, _ := e.store.GetTarget(tg.ID)
		return got.LastStatus != "running" && !e.eng.Scanning(tg.ID)
	})
	if e.eng.Progress().Get(tg.ID) != nil {
		t.Error("a stopped scan must leave the progress board")
	}
	recs, _ := e.store.ListScans("pause.test", 5)
	if len(recs) == 0 || recs[0].Status != "interrupted" || !strings.Contains(recs[0].Error, "paused") {
		t.Fatalf("scan history should record the stop: %+v", recs)
	}
	// Paused stays paused: the scheduler must not start it again.
	e.eng.Wake()
	time.Sleep(500 * time.Millisecond)
	if got, _ := e.store.GetTarget(tg.ID); got.Enabled || got.LastStatus == "running" || e.eng.Scanning(tg.ID) {
		t.Errorf("a paused target was scanned again: enabled=%v status=%s", got.Enabled, got.LastStatus)
	}
	if it, seen := e.eng.Health().Get("crtsh"); seen && it.FailCount > 0 {
		t.Errorf("stopping a scan must not count as a connector failure: %+v", it)
	}
	if hosts, _ := e.store.KnownHosts("pause.test", 100); len(hosts) != 0 {
		t.Errorf("a stopped scan must store nothing, found %v", hosts)
	}

	// Resume starts a fresh scan.
	e.src.mu.Lock()
	e.src.crtDelay = nil
	e.src.mu.Unlock()
	admin.post(path+"/resume", nil)
	waitFor(t, "resumed scan to finish", 15*time.Second, func() bool {
		got, _ := e.store.GetTarget(tg.ID)
		return got.LastStatus == "ok"
	})
}

// UAT defect: "Scan now with active checks" during a passive scan only showed a
// warning, and the passive scan carried on.
func TestActiveScanRestartsRunningPassiveScan(t *testing.T) {
	e, admin, tg := runningScanEnv(t, "restart.test")
	if p := e.eng.Progress().Get(tg.ID); p.Active {
		t.Fatal("the first scan is passive")
	}
	path := fmt.Sprintf("/targets/%d", tg.ID)

	// Only administrators may restart with active checks.
	an := e.signedIn("ana", RoleAnalyst)
	if code, _, _ := an.post(path+"/scan", url.Values{"active": {"1"}}); code != 403 {
		t.Errorf("analyst active scan: %d", code)
	}
	if !e.eng.Scanning(tg.ID) {
		t.Fatal("a refused request must not stop the scan")
	}

	if code, _, _ := admin.post(path+"/scan", url.Values{"active": {"1"}}); code != 303 {
		t.Fatalf("active scan: %d", code)
	}
	_, body, _ := admin.get(path)
	if !strings.Contains(body, "starting again with active checks") {
		t.Error("the page should say the scan is restarting with active checks")
	}
	waitFor(t, "scan to restart with active checks", 10*time.Second, func() bool {
		p := e.eng.Progress().Get(tg.ID)
		return p != nil && p.Active
	})
	recs, _ := e.store.ListScans("restart.test", 5)
	if len(recs) == 0 || recs[0].Status != "interrupted" || !strings.Contains(recs[0].Error, "active checks") {
		t.Fatalf("scan history should record the restart: %+v", recs)
	}
	if e.store.TakeActiveOnce("restart.test") {
		t.Error("the restarted scan should have used the one-shot active request")
	}
	if _, au, _ := admin.get("/audit"); !strings.Contains(au, "running scan restarted with active checks") {
		t.Error("restart not audited")
	}
	if _, js, _ := admin.get("/progress.json"); !strings.Contains(js, `"active":true`) {
		t.Errorf("progress.json should mark the active scan: %s", js)
	}
	if _, page, _ := admin.get(path); !strings.Contains(page, "Active checks ·") {
		t.Error("the progress bar should show that active checks are on")
	}
}

// Without a scan in flight, a pause or a plain scan-now behaves as before.
func TestStopScanIdleTarget(t *testing.T) {
	h := newHarness(t)
	tg := h.addTarget("idle.test", "")
	if h.eng.StopScan(tg.ID, errScanPaused) || h.eng.Scanning(tg.ID) {
		t.Error("nothing to stop on an idle target")
	}
}

// A stop asked for in the moment between a scan being claimed and it registering
// its cancel function must still take effect.
func TestStopBeforeScanRegisters(t *testing.T) {
	h := newHarness(t)
	h.seedDomain("early.test", "203.0.113.91", 64591)
	tg := h.addTarget("early.test", "")
	if !h.eng.claim(tg, 1) {
		t.Fatal("claim")
	}
	if !h.eng.StopScan(tg.ID, errScanPaused) {
		t.Fatal("a claimed scan should accept a stop")
	}
	h.eng.scan(testCtx(t), tg)
	h.eng.release(tg)
	got, _ := h.store.GetTarget(tg.ID)
	if got.LastStatus != "interrupted" || !strings.Contains(got.LastError, "paused") {
		t.Errorf("early stop ignored: %s %q", got.LastStatus, got.LastError)
	}
}
