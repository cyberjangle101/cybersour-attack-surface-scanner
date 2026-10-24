package main

import (
	"fmt"
	"testing"
)

// TestOwnershipChecks drives the real form parser and a full scan for the
// "Expected ASNs / Expected organisation keywords" fields on the add-entity form.
// Every host below resolves to a network run by "OTHER-HOSTING" (AS64999) unless noted.
func TestOwnershipChecks(t *testing.T) {
	cases := []struct {
		name     string
		asns     string
		keywords string
		wantOpen bool // should an asn-unexpected finding be raised?
		wantErr  bool
	}{
		{"no rules: check skipped", "", "", false, false},
		{"matching ASN, 'AS' prefix", "AS64999", "", false, false},
		{"matching ASN, bare number", "64999", "", false, false},
		{"several ASNs, separators mixed", "AS13335, 16509;AS64999\n8075", "", false, false},
		{"wrong ASN", "AS13335", "", true, false},
		{"matching keyword, case-insensitive", "", "other-hosting", false, false},
		{"keyword is a substring", "", "HOSTING", false, false},
		{"wrong keyword", "", "EXAMPLE-CORP", true, false},
		{"ASN wrong, keyword right (either is enough)", "AS13335", "OTHER-HOSTING", false, false},
		{"both wrong", "AS13335", "MICROSOFT", true, false},
		{"not an AS number", "AS-banana", "", false, true},
		{"zero", "AS0", "", false, true},
		{"too large", "AS99999999999", "", false, true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dom := fmt.Sprintf("own%d.test", i)
			if c.wantErr {
				if _, err := TargetFromForm(dom, c.asns, c.keywords, "", "", ""); err == nil {
					t.Fatal("expected the form to be rejected")
				}
				return
			}
			h := newHarness(t)
			h.dns.add(t, dom+". 60 IN A 198.51.100.7")
			h.dns.addIP(t, "198.51.100.7", 64999, "198.51.100.0/24", "OTHER-HOSTING")
			cleanMailDNS(t, h.dns, dom)
			h.src.addCert(dom)
			tg, err := TargetFromForm(dom, c.asns, c.keywords, "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			id, err := h.store.AddTarget(tg)
			if err != nil {
				t.Fatal(err)
			}
			h.scan(id)
			open, _ := h.store.ListFindings(dom, "open")
			got := false
			for _, f := range open {
				if f.Kind == "asn-unexpected" {
					got = true
				}
			}
			if got != c.wantOpen {
				t.Errorf("asn-unexpected raised = %v, want %v (open: %+v)", got, c.wantOpen, open)
			}
		})
	}
}

// A fix (adding the right ASN) must clear the finding on the next scan.
func TestOwnershipFixResolves(t *testing.T) {
	h := newHarness(t)
	dom := "fixown.test"
	h.dns.add(t, dom+". 60 IN A 198.51.100.7")
	h.dns.addIP(t, "198.51.100.7", 64999, "198.51.100.0/24", "OTHER-HOSTING")
	cleanMailDNS(t, h.dns, dom)
	h.src.addCert(dom)
	tg := h.addTarget(dom, "AS13335")
	h.scan(tg.ID)
	if open, _ := h.store.ListFindings(dom, "open"); len(open) == 0 {
		t.Fatal("expected a finding first")
	}
	tg.ExpectedASNs = []int{64999}
	if err := h.store.UpdateTarget(tg); err != nil {
		t.Fatal(err)
	}
	h.scan(tg.ID)
	for _, f := range mustFindings(t, h, dom, "open") {
		if f.Kind == "asn-unexpected" {
			t.Fatalf("finding should have auto-resolved: %+v", f)
		}
	}
}

func mustFindings(t *testing.T, h *harness, dom, status string) []Finding {
	t.Helper()
	f, err := h.store.ListFindings(dom, status)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
