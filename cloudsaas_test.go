package main

import (
	"path/filepath"
	"testing"
)

func TestDetectCloud(t *testing.T) {
	res := map[string]*HostResult{
		"example.test": {Host: "example.test", Records: map[string][]string{
			"TXT": {"v=spf1 include:_spf.google.com include:sendgrid.net -all", "atlassian-domain-verification=abc", "stripe-verification=zz", "random text"},
			"MX":  {"1 aspmx.l.google.com."},
		}},
		"api.example.test":  {Host: "api.example.test", Records: map[string][]string{"CNAME": {"abc123.execute-api.eu-west-1.amazonaws.com."}}},
		"db.example.test":   {Host: "db.example.test", Records: map[string][]string{"CNAME": {"prod.cluster-x.eu-west-1.rds.amazonaws.com."}}},
		"shop.example.test": {Host: "shop.example.test", Records: map[string][]string{"CNAME": {"shops.myshopify.com."}}},
		"gone.example.test": {Host: "gone.example.test", NX: true, Records: map[string][]string{"CNAME": {"x.herokuapp.com."}}},
	}
	hosts := []string{"example.test", "api.example.test", "db.example.test", "shop.example.test", "gone.example.test"}
	got := map[string]CloudService{}
	for _, c := range detectCloud("example.test", hosts, res) {
		got[c.Provider] = c
	}
	for _, want := range []string{"Google Workspace", "SendGrid", "Atlassian Cloud", "Stripe", "AWS API Gateway", "AWS RDS", "Shopify"} {
		if _, ok := got[want]; !ok {
			t.Errorf("provider %q not detected; got %v", want, got)
		}
	}
	if !got["AWS RDS"].Data || got["AWS API Gateway"].Data {
		t.Error("only the RDS name should be flagged as a datastore")
	}
	if _, ok := got["Heroku"]; ok {
		t.Error("a non-existent host must not count as a service")
	}
	if c := matchSuffix(cnameSigs, "evilgithub.io"); c != nil {
		t.Errorf("suffix must match on a label boundary, got %v", c)
	}
}

func TestApplyCloudEventsAndFinding(t *testing.T) {
	st := testStore(t)
	res := map[string]*HostResult{"db.example.test": {Host: "db.example.test", Records: map[string][]string{"CNAME": {"p.rds.amazonaws.com."}}}}
	cur := detectCloud("example.test", []string{"db.example.test"}, res)
	tx, err := st.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var evs, fs []string
	s := &Scanner{}
	err = s.applyCloud(tx, "example.test", cur, nil,
		func(kind, _, _, _ string, _ bool) { evs = append(evs, kind) },
		func(_, kind, _, _, _, _ string) { fs = append(fs, kind) })
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0] != "cloud-service" || len(fs) != 1 || fs[0] != "cloud-datastore" {
		t.Fatalf("events %v findings %v", evs, fs)
	}
	prev := loadCloudInventory(st, "example.test")
	if len(prev) != 1 {
		t.Fatalf("inventory not saved: %v", prev)
	}
	evs = nil
	tx, _ = st.Begin()
	_ = s.applyCloud(tx, "example.test", cur, prev, func(kind, _, _, _ string, _ bool) { evs = append(evs, kind) }, func(_, _, _, _, _, _ string) {})
	_ = tx.Commit()
	if len(evs) != 0 {
		t.Fatalf("a known service must not raise a second event: %v", evs)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "easm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func FuzzDetectCloud(f *testing.F) {
	f.Add("a.b.rds.amazonaws.com.", "v=spf1 include:_spf.google.com -all", "1 mx.google.com.")
	f.Add("", "include:", "")
	f.Fuzz(func(t *testing.T, cname, txt, mx string) {
		res := map[string]*HostResult{"x.test": {Host: "x.test", Records: map[string][]string{"CNAME": {cname}, "TXT": {txt}, "MX": {mx}}}}
		_ = detectCloud("x.test", []string{"x.test"}, res)
	})
}
