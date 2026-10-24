package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func (h *harness) seedDomain(domain, ip string, asn int) {
	t, d := h.t, h.dns
	d.add(t, fmt.Sprintf("%s. 60 IN A %s", domain, ip))
	d.add(t, fmt.Sprintf("www.%s. 60 IN A %s", domain, ip))
	d.add(t, fmt.Sprintf(`%s. 60 IN TXT "v=spf1 -all"`, domain))
	cleanMailDNS(t, d, domain)
	d.addIP(t, ip, asn, ip+"/32", "NET-"+domain)
	h.src.addCert(domain, "www."+domain)
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	_ = os.WriteFile(os.TempDir()+"/easm-goroutines.txt", buf[:n], 0o644)
	t.Fatalf("timed out waiting for %s; goroutine dump in %s/easm-goroutines.txt", what, os.TempDir())
}

// Several domains, added while another scan is still running, must all finish.
func TestSchedulerFinishesEveryDomain(t *testing.T) {
	h := newHarness(t)
	domains := []string{"one.test", "two.test", "three.test", "four.test"}
	for i, d := range domains {
		h.seedDomain(d, fmt.Sprintf("203.0.113.%d", 10+i), 64500+i)
	}
	h.src.mu.Lock()
	h.src.crtDelay = map[string]time.Duration{"one.test": 800 * time.Millisecond}
	h.src.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.eng.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	first := h.addTarget("one.test", "")
	h.eng.Wake()
	waitFor(t, "first scan to start", 5*time.Second, func() bool { return h.eng.Current() != "" })
	// add the rest while the first (slow) scan is in flight
	var ids []int64
	for _, d := range domains[1:] {
		tg := h.addTarget(d, "")
		ids = append(ids, tg.ID)
		h.eng.Wake()
	}
	ids = append([]int64{first.ID}, ids...)
	waitFor(t, "all domains to finish", 30*time.Second, func() bool {
		for _, id := range ids {
			tg, _ := h.store.GetTarget(id)
			if tg.LastStatus != "ok" {
				return false
			}
		}
		return true
	})
	for i, id := range ids {
		tg, _ := h.store.GetTarget(id)
		if !tg.Baselined() {
			t.Errorf("%s was not baselined", domains[i])
		}
		inv, total, _ := h.store.Inventory(domains[i], "", 100)
		if total != 2 {
			t.Errorf("%s: want 2 hosts, got %d (%+v)", domains[i], total, inv)
		}
	}
	// they ran, they did not just mark themselves ok
	for _, d := range domains {
		if recs, _ := h.store.ListScans(d, 5); len(recs) != 1 || recs[0].Status != "ok" {
			t.Errorf("%s scan history: %+v", d, recs)
		}
	}
	_ = strings.TrimSpace
}
