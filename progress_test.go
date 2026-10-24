package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProgressBoardNeverGoesBackwards(t *testing.T) {
	b := NewProgressBoard()
	b.Start(1, "a.test")
	b.Update(1, "x", 40, "")
	b.Update(1, "y", 10, "late, smaller value")
	if p := b.Get(1); p.Percent != 40 || p.Stage != "y" {
		t.Fatalf("percent must be monotonic but stage should follow: %+v", p)
	}
	b.Update(1, "z", 500, "")
	if b.Get(1).Percent != 100 {
		t.Fatal("percent must clamp at 100")
	}
	b.Done(1)
	if b.Get(1) != nil || len(b.Snapshot()) != 0 {
		t.Fatal("finished scans must leave the board")
	}
	var nilBoard *ProgressBoard // must be a safe no-op
	nilBoard.Start(1, "x")
	nilBoard.Update(1, "x", 1, "")
	nilBoard.Done(1)
	_ = nilBoard.Snapshot()
}

// A real scan reports several stages, in order, with a rising percentage, and cleans up.
func TestScanReportsRisingProgress(t *testing.T) {
	h := newHarness(t)
	h.seedDomain("prog.test", "203.0.113.50", 64500)
	h.src.mu.Lock()
	h.src.crtDelay = map[string]time.Duration{"prog.test": 500 * time.Millisecond}
	h.src.mu.Unlock()
	tg := h.addTarget("prog.test", "")

	var mu sync.Mutex
	var samples []ScanProgress
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				if p := h.eng.Progress().Get(tg.ID); p != nil {
					mu.Lock()
					samples = append(samples, *p)
					mu.Unlock()
				}
			}
		}
	}()
	got := h.scan(tg.ID)
	close(stop)
	wg.Wait()
	if got.LastStatus != "ok" {
		t.Fatalf("scan failed: %s", got.LastError)
	}
	mu.Lock()
	defer mu.Unlock()
	stages, last := map[string]bool{}, -1
	for _, s := range samples {
		if s.Percent < last {
			t.Fatalf("progress went backwards: %d -> %d", last, s.Percent)
		}
		last = s.Percent
		stages[s.Stage] = true
	}
	if len(stages) < 3 || last < 60 {
		t.Errorf("expected several stages and a high final percent, got stages=%v last=%d", stages, last)
	}
	if h.eng.Progress().Get(tg.ID) != nil {
		t.Error("progress must be cleared when the scan ends")
	}
}

// A slow domain must not hold up the others, and every domain finishes with exactly one alert flow.
func TestSlowDomainDoesNotBlockOthers(t *testing.T) {
	h := newHarness(t)
	for i, d := range []string{"slow.test", "fast1.test", "fast2.test"} {
		h.seedDomain(d, fmt.Sprintf("203.0.113.%d", 70+i), 64510+i)
	}
	h.src.mu.Lock()
	h.src.crtDelay = map[string]time.Duration{"slow.test": 9 * time.Second}
	h.src.mu.Unlock()
	st, _ := h.store.LoadSettings()
	st.ConcurrentScans = 2
	h.saveSettings(st)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.eng.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	slow := h.addTarget("slow.test", "")
	h.eng.Wake()
	waitFor(t, "slow scan to start", 5*time.Second, func() bool { return h.eng.Progress().Get(slow.ID) != nil })
	f1, f2 := h.addTarget("fast1.test", ""), h.addTarget("fast2.test", "")
	h.eng.Wake()
	// both fast domains finish while the slow one is STILL running (they share the one free slot)
	waitFor(t, "fast domains to finish", 7*time.Second, func() bool {
		a, _ := h.store.GetTarget(f1.ID)
		b, _ := h.store.GetTarget(f2.ID)
		return a.LastStatus == "ok" && b.LastStatus == "ok"
	})
	if s, _ := h.store.GetTarget(slow.ID); s.LastStatus != "running" {
		t.Fatalf("the slow domain should still be running, is %q", s.LastStatus)
	}
	waitFor(t, "slow domain to finish", 30*time.Second, func() bool {
		s, _ := h.store.GetTarget(slow.ID)
		return s.LastStatus == "ok"
	})
	seen := map[string]int{}
	for _, m := range h.mails() {
		seen[m.Subject+"|"+m.Plain]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("duplicate alert email sent %d times: %.80s", n, k)
		}
	}
}

func TestConcurrencyLimitIsHonoured(t *testing.T) {
	h := newHarness(t)
	st, _ := h.store.LoadSettings()
	st.ConcurrentScans = 1
	h.saveSettings(st)
	a, b := &Target{ID: 1, Domain: "a.test"}, &Target{ID: 2, Domain: "b.test"}
	if !h.eng.claim(a, 1) || h.eng.claim(b, 1) || h.eng.claim(a, 5) {
		t.Fatal("claim must enforce the pool size and refuse a target that is already running")
	}
	h.eng.release(a)
	if !h.eng.claim(b, 1) {
		t.Fatal("slot should be free after release")
	}
	if bad := (Settings{}); bad.Normalize() == nil {
		t.Fatal("zero settings should be invalid")
	}
	d := DefaultSettings()
	d.ConcurrentScans = 99
	if d.Normalize() == nil {
		t.Fatal("concurrent scans above 8 must be rejected")
	}
}

// If no DNS resolver answers at all, the scan fails fast with a clear reason instead of grinding.
func TestDeadDNSFailsFast(t *testing.T) {
	h := newHarness(t)
	h.seedDomain("dead.test", "203.0.113.90", 64520)
	h.dns.stop()
	tg := h.addTarget("dead.test", "")
	t0 := time.Now()
	got := h.scan(tg.ID)
	if got.LastStatus != "error" || !strings.Contains(got.LastError, "no DNS resolver is reachable") {
		t.Fatalf("want a clear DNS error, got %q / %q", got.LastStatus, got.LastError)
	}
	if time.Since(t0) > 20*time.Second {
		t.Errorf("took %v; should fail fast", time.Since(t0))
	}
	if _, total, _ := h.store.Inventory("dead.test", "", 10); total != 0 {
		t.Error("a failed scan must store nothing")
	}
}

func TestProgressEndpointAndBars(t *testing.T) {
	e := newWebEnv(t)
	anon := e.browser()
	if code, _, _ := anon.get("/progress.json"); code != 303 && code != 401 {
		t.Fatalf("progress must require login, got %d", code)
	}
	b := e.browser()
	b.setup("admin", "correct horse battery")
	tg := e.addTarget("bar.test", "")
	if err := e.store.MarkRunning(tg.ID, nowUTC()); err != nil {
		t.Fatal(err)
	}
	e.eng.Progress().Start(tg.ID, "bar.test")
	e.eng.Progress().Update(tg.ID, "Resolving DNS", 47, "20 of 40 hosts")

	code, body, resp := b.get("/progress.json")
	if code != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		t.Fatalf("progress.json: %d %s", code, body)
	}
	var list []struct {
		ID      int64
		Stage   string
		Percent int
		Detail  string
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list) != 1 || list[0].Percent != 47 || list[0].Stage != "Resolving DNS" {
		t.Fatalf("bad progress payload %q (%v)", body, err)
	}
	for _, path := range []string{"/", fmt.Sprintf("/targets/%d", tg.ID)} {
		_, page, _ := b.get(path)
		if !strings.Contains(page, `<progress max="100" value="47">`) || !strings.Contains(page, "Resolving DNS") || !strings.Contains(page, "20 of 40 hosts") {
			t.Errorf("%s does not show the progress bar", path)
		}
	}
	_, hdrs, r := b.get("/")
	_ = hdrs
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP must allow same-origin fetch for live progress: %s", csp)
	}
	e.eng.Progress().Done(tg.ID)
}
