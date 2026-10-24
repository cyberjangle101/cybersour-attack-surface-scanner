package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func detailEnv(t *testing.T) (*webEnv, *browser) {
	e := newWebEnv(t)
	e.seedExample()
	e.dns.add(t, "10.113.0.203.in-addr.arpa. 60 IN PTR www.example.test.")
	e.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 3389}, []string{"CVE-2021-41773"}, []string{"self-signed"})
	e.intel.rdap["example.test"] = rdapBody(time.Now().Add(200 * 24 * time.Hour))
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	e.scan(1)
	return e, b
}

// The category tabs used to render as "?type%3dip" (html/template escaped the query), so every tab showed "All".
func TestAssetTabsAreRealLinks(t *testing.T) {
	_, b := detailEnv(t)
	_, body, _ := b.get("/assets")
	for _, want := range []string{`href="/assets?type=ip"`, `href="/assets?type=certificate"`, `href="/assets?type=registration"`, `href="/assets.csv"`} {
		if !strings.Contains(body, want) {
			t.Errorf("assets page lacks working link %s", want)
		}
	}
	if strings.Contains(body, "%3d") || strings.Contains(body, "%3D") {
		t.Error("query string is being percent-encoded in links")
	}
	_, ipTab, _ := b.get("/assets?type=ip")
	if !strings.Contains(ipTab, `class="on" href="/assets?type=ip"`) || strings.Contains(ipTab, "does not resolve") {
		t.Error("IP tab not selected / filtered")
	}
	// other filters survive tab switching and paging links
	_, filtered, _ := b.get("/assets?target=example.test&q=203")
	if !strings.Contains(filtered, "target=example.test") || !strings.Contains(filtered, "q=203") {
		t.Error("filters lost in tab links")
	}
	_, ev, _ := b.get("/events")
	if strings.Contains(ev, "%3d") {
		t.Error("events links are encoded")
	}
}

func TestAssetDetailPages(t *testing.T) {
	e, b := detailEnv(t)
	certs, _ := e.store.scanCerts(`SELECT ` + certCols + ` FROM certs`)
	if len(certs) == 0 {
		t.Fatal("no certificate seeded")
	}
	get := func(typ, id string) string {
		t.Helper()
		code, body, _ := b.get("/assets/view?" + url.Values{"type": {typ}, "id": {id}}.Encode())
		if code != 200 {
			t.Fatalf("%s %q: HTTP %d", typ, id, code)
		}
		return body
	}
	cases := []struct {
		typ, id string
		want    []string
	}{
		{"domain", "www.example.test", []string{"DNS records", "203.0.113.10", "Reverse DNS", "www.example.test", "AS64500", "Certificates covering this name"}},
		{"ip", "203.0.113.10", []string{"Reverse DNS (PTR)", "www.example.test", "AS64500", "Open ports and services", "3389/tcp", "RDP", "CVE-2021-41773", "Host names that resolve here", "Shodan InternetDB"}},
		{"service", "203.0.113.10:3389/tcp", []string{"3389/tcp", "RDP", "Shodan InternetDB", "203.0.113.10"}},
		{"certificate", certs[0].Key, []string{"Issuer", "Valid from", "Expires", "Status", "Names on the certificate"}},
		{"dns", "TXT|example.test", []string{"Values", "v=spf1"}},
		{"vulnerability", "CVE-2021-41773", []string{"nvd.nist.gov/vuln/detail/CVE-2021-41773", "203.0.113.10"}},
		{"registration", "example.test", []string{"Example Registrar Inc", "Registered", "ns1.example.net", "in 19"}},
	}
	for _, c := range cases {
		body := get(c.typ, c.id)
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s detail lacks %q", c.typ, w)
			}
		}
	}
	// the asset list links to these pages
	_, list, _ := b.get("/assets?type=ip")
	if !strings.Contains(list, `/assets/view?type=ip&amp;id=203.0.113.10`) && !strings.Contains(list, `/assets/view?type=ip&id=203.0.113.10`) {
		t.Errorf("asset list does not link to the detail page")
	}
	// unknown / hostile input
	for _, q := range []string{"type=bogus&id=x", "type=ip", "type=ip&id=999.1.1.1", "type=domain&id=" + url.QueryEscape("<script>alert(1)</script>"), "type=service&id=garbage", "type=certificate&id=nope"} {
		code, body, _ := b.get("/assets/view?" + q)
		if code != 404 || strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s: want 404, got %d", q, code)
		}
	}
	// reverse-DNS results are cached; a lookup failure is shown, not fatal
	if ptr, ok := e.store.GetRDNS("203.0.113.10", time.Hour); !ok || ptr != "www.example.test" {
		t.Errorf("PTR not cached: %q %v", ptr, ok)
	}
	e.dns.stop()
	if body := get("ip", "203.0.113.10"); !strings.Contains(body, "www.example.test") { // served from cache
		t.Error("cached PTR should survive a DNS outage")
	}
	// anonymous users are bounced to login
	anon := e.browser()
	if code, _, _ := anon.get("/assets/view?type=ip&id=203.0.113.10"); code != http.StatusSeeOther {
		t.Errorf("anonymous access: %d", code)
	}
}

func TestEOLEvidenceNamesTheSoftware(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = `{"cpes":["cpe:/a:apache:http_server:2.2.15","cpe:/o:centos:centos:6"],"hostnames":[],"ip":"203.0.113.10","ports":[80],"tags":["eol-product","eol-os"],"vulns":[]}`
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	fs, _ := h.store.ListFindings("example.test", "open")
	for _, f := range fs {
		if f.Kind == "eol-software" {
			for _, w := range []string{"apache http_server 2.2.15", "centos centos 6", "operating system is end-of-life", "endoflife.date"} {
				if !strings.Contains(f.Detail, w) {
					t.Errorf("EOL evidence lacks %q: %s", w, f.Detail)
				}
			}
			return
		}
	}
	t.Fatalf("no eol finding raised: %+v", fs)
}

func TestDanglingCNAMEExplainsItself(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "old.example.test. 60 IN CNAME gone.nowhere-at-all.test.")
	h.src.addCert("example.test", "old.example.test")
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	fs, _ := h.store.ListFindings("example.test", "open")
	for _, f := range fs {
		if f.Kind == "dangling-cname" {
			if f.Severity != "low" || !strings.Contains(f.Detail, "published CNAME record") || !strings.Contains(f.Detail, "nslookup") {
				t.Errorf("unhelpful dangling evidence (sev %s): %s", f.Severity, f.Detail)
			}
			return
		}
	}
	t.Fatal("dangling CNAME not detected")
}

func TestConnectorsWithoutKeysAreCounted(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	// defaults: keyed sources are switched off, but they still cannot work without a key
	_, body, _ := b.get("/health")
	if !strings.Contains(body, `<div class="n">6</div><div class="l">Need an API key</div>`) {
		t.Errorf("keyed connectors without a key are not counted:\n%.0s", body)
	}
	if !strings.Contains(body, "Add the API key in Settings") {
		t.Error("no pointer to Settings")
	}
	if err := e.eng.SetSecret(secretShodan, "SHODANKEYSHODANKEYSHODANKEY1234"); err != nil {
		t.Fatal(err)
	}
	_, body2, _ := b.get("/health")
	if strings.Count(body2, "No API key") >= strings.Count(body, "No API key") {
		t.Error("saving a key should reduce the 'No API key' count")
	}
}

func TestConnectionLog(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	hb := e.eng.Health()
	hb.Record("otx", "scan", false, 150*time.Millisecond, errString(`Get "https://otx.alienvault.com/x": dial tcp: lookup otx.alienvault.com: no such host`))
	for i := 0; i < 50; i++ { // a burst of identical results collapses into one line
		hb.Record("dns:1.1.1.1:53", "scan", true, time.Millisecond, nil)
	}
	hb.Record("hackertarget", "check", false, time.Second, errString("HTTP 429"))
	_, body, _ := b.get("/health")
	for _, w := range []string{"Connection log", "no such host", "could not resolve the service", "Rate limited", "×50"} {
		if !strings.Contains(body, w) {
			t.Errorf("log lacks %q", w)
		}
	}
	_, f, _ := b.get("/health?failed=1")
	if strings.Contains(f, "×50") {
		t.Error("failures-only filter shows successes")
	}
	_, one, _ := b.get("/health?connector=otx")
	if strings.Contains(one, "Rate limited") || !strings.Contains(one, "no such host") {
		t.Error("connector filter wrong")
	}
	// survives a restart (persisted with the health data)
	e.eng.saveHealth()
	h2 := NewHealthBoard()
	v, _, _ := e.store.getMeta("health")
	h2.Load(v)
	if len(h2.Log("", false, 0)) != 3 || h2.Log("otx", true, 0)[0].Error == "" {
		t.Errorf("log not persisted: %+v", h2.Log("", false, 0))
	}
	// old (v1.1/1.2) stored format still loads
	h3 := NewHealthBoard()
	h3.Load(`[{"Name":"otx","OKCount":2}]`)
	if it, ok := h3.Get("otx"); !ok || it.OKCount != 2 {
		t.Error("legacy health format not loaded")
	}
	if Hint("something unexpected") != "" {
		t.Error("unknown errors should not invent advice")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRIPEstatFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") == "198.51.100.9" {
			_, _ = w.Write([]byte(`{"data":{"resource":"198.51.100.0/24","asns":[{"asn":64500,"holder":"EXAMPLE-NET - Example Networks"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"resource":"192.0.2.0/24","asns":[]}}`))
	}))
	defer srv.Close()
	h := newHarness(t)
	// Team Cymru unreachable (dead resolver) => RIPEstat answers
	res := NewResolver(testCtx(t), DNSCfg{Resolvers: []string{"127.0.0.1:1"}, QPS: 100, Timeout: 200 * time.Millisecond, Retries: 0})
	a := NewASNResolver(ASNCfg{Enabled: true, BGPViewFallback: true, CacheTTL: time.Hour}, res, h.store, h.log)
	a.ripeURL = srv.URL
	info, err := a.Lookup(testCtx(t), "198.51.100.9")
	if err != nil || info.ASN != 64500 || info.Prefix != "198.51.100.0/24" || !strings.Contains(info.Org, "Example Networks") {
		t.Fatalf("fallback failed: %+v %v", info, err)
	}
	if got := info.String(); !strings.HasPrefix(got, "AS64500") || strings.HasSuffix(got, ", ") {
		t.Errorf("odd rendering %q", got)
	}
	if _, err := a.ripestat(testCtx(t), "192.0.2.1"); err == nil {
		t.Error("an unannounced address must be an error")
	}
}
