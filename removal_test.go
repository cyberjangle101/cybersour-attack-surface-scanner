package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func (h *harness) eventsOfKind(kind string) []Event {
	h.t.Helper()
	evs, _, err := h.store.ListEvents(EventFilter{Root: "example.test", Kind: kind, IncludeBaseline: true, Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	return evs
}

func (h *harness) scanN(id int64, n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		if tg := h.scan(id); tg.LastStatus != "ok" {
			h.t.Fatalf("scan %d: %q %q", i+1, tg.LastStatus, tg.LastError)
		}
	}
}

func TestRemovedRecordsNeedRepeatedMisses(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "www.example.test. 60 IN A 203.0.113.11")
	h.dns.addIP(t, "203.0.113.11", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1) // baseline
	if n := len(h.eventsOfKind("dns-removed")); n != 0 {
		t.Fatalf("removal events during baseline: %d", n)
	}

	removeSecond := func() {
		h.dns.remove("www.example.test", dns.TypeA)
		h.dns.add(t, "www.example.test. 60 IN A 203.0.113.10")
	}
	removeSecond()
	h.scanN(tg.ID, 2)
	if n := len(h.eventsOfKind("dns-removed")); n != 0 {
		t.Fatalf("reported after only 2 missed scans: %d", n)
	}
	mailsBefore := h.smtp.count()
	h.scanN(tg.ID, 1)
	ev := h.eventsOfKind("dns-removed")
	if len(ev) != 1 || ev[0].Host != "www.example.test" || !strings.Contains(ev[0].Detail, "A 203.0.113.11 removed") {
		t.Fatalf("expected one removal event, got %+v", ev)
	}
	if h.smtp.count() != mailsBefore+1 {
		t.Errorf("removal was not emailed (%d -> %d)", mailsBefore, h.smtp.count())
	}
	if m := h.mails(); !strings.Contains(m[len(m)-1].Plain, "removed") {
		t.Errorf("mail does not mention the removal:\n%s", m[len(m)-1].Plain)
	}
	h.scanN(tg.ID, 3)
	if n := len(h.eventsOfKind("dns-removed")); n != 1 {
		t.Errorf("removal repeated: %d events", n)
	}
	// it comes back
	h.dns.add(t, "www.example.test. 60 IN A 203.0.113.11")
	h.scanN(tg.ID, 1)
	back := h.eventsOfKind("dns-a")
	found := false
	for _, e := range back {
		found = found || strings.Contains(e.Detail, "returned: A 203.0.113.11")
	}
	if !found {
		t.Errorf("return not reported: %+v", back)
	}
	// flapping that never reaches the threshold in a row is never reported
	for round := 0; round < 3; round++ {
		removeSecond()
		h.scanN(tg.ID, 2)
		h.dns.add(t, "www.example.test. 60 IN A 203.0.113.11")
		h.scanN(tg.ID, 1)
	}
	if n := len(h.eventsOfKind("dns-removed")); n != 1 {
		t.Errorf("a flapping record was reported as removed: %d events", n)
	}
}

func TestFailedLookupsAreNeverRemovals(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	h.dns.setServfail(true)
	for i := 0; i < 5; i++ {
		h.scan(tg.ID) // may well fail as a whole; that is fine
	}
	h.dns.setServfail(false)
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM records WHERE gone<>''`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("records marked gone during a DNS outage: %d %v", n, err)
	}
	if got := len(h.eventsOfKind("dns-removed")) + len(h.eventsOfKind("host-gone")); got != 0 {
		t.Fatalf("removal events during a DNS outage: %d", got)
	}
}

func TestHostDisappearingIsReportedAndFindingsResolve(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	if h.findingsOf("open")["asn:example.test:198.51.100.7"].Key == "" {
		t.Fatal("setup: the ownership finding should exist")
	}
	// api.example.test vanishes from DNS and from every passive source
	h.dns.remove("api.example.test", dns.TypeA)
	h.src.mu.Lock()
	h.src.anubis = nil
	h.src.mu.Unlock()
	h.src.addAnubis("www.example.test")
	h.scanN(tg.ID, 2)
	if n := len(h.eventsOfKind("host-gone")); n != 0 {
		t.Fatalf("host-gone after 2 scans: %d", n)
	}
	h.scanN(tg.ID, 1)
	gone := h.eventsOfKind("host-gone")
	if len(gone) != 1 || gone[0].Host != "api.example.test" || !strings.Contains(gone[0].Detail, "no longer exists") {
		t.Fatalf("host-gone: %+v", gone)
	}
	if res := h.eventsOfKind("finding-resolved"); len(res) != 1 || !strings.Contains(res[0].Detail, "asn-unexpected") {
		t.Errorf("finding-resolved: %+v", res)
	}
	if len(h.findingsOf("open")) != 0 {
		t.Errorf("finding should be resolved: %+v", h.findingsOf("open"))
	}
	// once reported it is not checked or reported again
	h.scanN(tg.ID, 3)
	if n := len(h.eventsOfKind("host-gone")); n != 1 {
		t.Errorf("host-gone repeated: %d", n)
	}
	// and if it returns, that is visible
	h.dns.add(t, "api.example.test. 60 IN A 198.51.100.7")
	h.src.addAnubis("api.example.test")
	h.scanN(tg.ID, 1)
	ret := false
	for _, e := range h.eventsOfKind("dns-a") {
		ret = ret || (e.Host == "api.example.test" && strings.Contains(e.Detail, "returned:"))
	}
	if !ret {
		t.Error("return of the host not reported")
	}
}

func TestRemovalAlertsCanBeSwitchedOff(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	st, _ := h.store.LoadSettings()
	st.AlertRemovals, st.RemovalMisses = false, 1
	h.saveSettings(st)
	h.dns.add(t, "www.example.test. 60 IN A 203.0.113.11")
	h.dns.addIP(t, "203.0.113.11", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	mails := h.smtp.count()
	h.dns.remove("www.example.test", dns.TypeA)
	h.dns.add(t, "www.example.test. 60 IN A 203.0.113.10")
	h.scanN(tg.ID, 1)
	if n := len(h.eventsOfKind("dns-removed")); n != 1 {
		t.Fatalf("removal not recorded: %d", n)
	}
	if h.smtp.count() != mails {
		t.Error("removal emailed although alerts for removals are off")
	}
	if pend, _ := h.store.PendingEvents(); len(pend) != 0 {
		t.Errorf("silenced events left pending: %d", len(pend))
	}
	// still shown on the Events page without ticking "baseline"
	evs, _, _ := h.store.ListEvents(EventFilter{Root: "example.test", Kind: "dns-removed", Limit: 10})
	if len(evs) != 1 {
		t.Error("removal hidden from the default event list")
	}
}

func TestClosedPortIsReported(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443, 3389}, nil, nil)
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key == "" {
		t.Fatal("setup: RDP finding missing")
	}
	h.intel.mu.Lock()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443}, nil, nil)
	h.intel.mu.Unlock()
	h.expireCaches()
	h.scanN(tg.ID, 1)
	ev := h.eventsOfKind("service-removed")
	if len(ev) != 1 || !strings.Contains(ev[0].Detail, "tcp/3389") {
		t.Fatalf("closed port not reported: %+v", ev)
	}
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key != "" {
		t.Error("finding for the closed port should be resolved")
	}
	if r := h.eventsOfKind("finding-resolved"); len(r) == 0 {
		t.Error("resolution not reported")
	}
}

func TestRefreshBypassesIntelCacheOnce(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443}, nil, nil)
	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	hits := func() int { h.intel.mu.Lock(); defer h.intel.mu.Unlock(); return h.intel.hits["internetdb"] }
	first := hits()
	if first == 0 {
		t.Fatal("setup: the source was never asked")
	}
	h.scanN(tg.ID, 1)
	if hits() != first {
		t.Fatalf("a normal scan should use the saved answer (%d -> %d)", first, hits())
	}
	// a new exposure appears at the source; a normal scan does not see it yet
	h.intel.mu.Lock()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443, 3389}, nil, nil)
	h.intel.mu.Unlock()
	h.scanN(tg.ID, 1)
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key != "" {
		t.Fatal("setup: the cached answer should still hide the new port")
	}
	if err := h.store.SetRefresh("example.test", true); err != nil {
		t.Fatal(err)
	}
	h.scanN(tg.ID, 1)
	if h.findingsOf("open")["svc:203.0.113.10:3389"].Key == "" {
		t.Error("a refresh scan did not pick up the new exposure")
	}
	// the request is one-shot
	after := hits()
	h.scanN(tg.ID, 1)
	if hits() != after {
		t.Error("the refresh request was not cleared")
	}
}
