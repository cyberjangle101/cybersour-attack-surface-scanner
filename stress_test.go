package main

import (
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStressManyHostsWhileBrowsing pushes 150 hosts through the scan path with the
// lab resolver while 50 signed-in requests hit the UI at once, then checks that
// the scan completed, no page failed or took more than 2s, the single SQLite
// connection never reported "database is locked", and no goroutines leaked.
func TestStressManyHostsWhileBrowsing(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	e := newWebEnv(t)
	e.seedExample()
	const hosts = 150
	for i := 0; i < hosts; i++ {
		name := fmt.Sprintf("h%03d.example.test", i)
		ip := fmt.Sprintf("203.0.113.%d", 1+i%250)
		e.dns.add(t, fmt.Sprintf("%s. 60 IN A %s", name, ip))
		e.src.addAnubis(name)
	}
	e.dns.addIP(t, "203.0.113.1", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	tg := e.addTarget("example.test", "AS64500")

	runtime.GC()
	before := runtime.NumGoroutine()

	done := make(chan struct{})
	go func() { defer close(done); e.scan(tg.ID) }()

	pages := []string{"/", "/targets", fmt.Sprintf("/targets/%d", tg.ID), "/assets", "/findings", "/events", "/health", "/report", "/audit", "/progress.json"}
	base, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cookies := admin.c.Jar.Cookies(base)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		bad  []string
		slow []string
	)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, e.srv.URL+p, nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			t0 := time.Now()
			resp, err := http.DefaultClient.Do(req)
			d := time.Since(t0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				bad = append(bad, p+": "+err.Error())
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				bad = append(bad, fmt.Sprintf("%s: %d", p, resp.StatusCode))
			}
			if d > 2*time.Second {
				slow = append(slow, fmt.Sprintf("%s: %v", p, d))
			}
		}(pages[i%len(pages)])
	}
	wg.Wait()
	<-done
	if len(bad) > 0 {
		t.Errorf("%d request(s) failed during the scan: %v", len(bad), bad)
	}
	if len(slow) > 0 {
		t.Errorf("pages slower than 2s under load: %v", slow)
	}

	got, _ := e.store.GetTarget(tg.ID)
	if got.LastStatus != "ok" {
		t.Fatalf("scan of %d hosts ended %q: %s", hosts, got.LastStatus, got.LastError)
	}
	var n int
	if err := e.store.db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE root='example.test'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < hosts {
		t.Errorf("only %d of %d hosts stored", n, hosts)
	}
	if strings.Contains(got.LastError, "database is locked") {
		t.Error("database is locked under load")
	}

	// Goroutines started by the scan and the requests must wind down.
	deadline := time.Now().Add(5 * time.Second)
	for {
		http.DefaultClient.CloseIdleConnections()
		runtime.GC()
		after := runtime.NumGoroutine()
		if after <= before+5 {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutines grew from %d to %d after the stress run", before, after)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}
