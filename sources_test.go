package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---- feed fixtures (plausible sizes: the parsers refuse feeds that look truncated) ----

func kevFixture(extra ...string) []byte {
	type v struct {
		CVE        string `json:"cveID"`
		Vendor     string `json:"vendorProject"`
		Product    string `json:"product"`
		Name       string `json:"vulnerabilityName"`
		Added      string `json:"dateAdded"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	}
	var list []v
	for i := 0; i < 600; i++ {
		list = append(list, v{CVE: fmt.Sprintf("CVE-2015-%05d", i), Vendor: "Acme", Product: "Thing", Added: "2022-01-01", Ransomware: "Unknown"})
	}
	for _, c := range extra {
		list = append(list, v{CVE: c, Name: "Apache HTTP Server Path Traversal", Added: "2021-11-03", Ransomware: "Known"})
	}
	b, _ := json.Marshal(map[string]any{"title": "CISA Catalog of Known Exploited Vulnerabilities", "vulnerabilities": list})
	return b
}

func torFixture(extra ...string) []byte {
	var b strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&b, "185.220.101.%d\n", i)
	}
	for _, ip := range extra {
		b.WriteString(ip + "\n")
	}
	return []byte(b.String())
}

func takeoverFixture() []byte {
	type row struct {
		Service     string   `json:"service"`
		CNAME       []string `json:"cname"`
		Fingerprint string   `json:"fingerprint"`
		NXDomain    bool     `json:"nxdomain"`
		Vulnerable  bool     `json:"vulnerable"`
	}
	rows := []row{
		{Service: "PageSvc", CNAME: []string{"pagesvc.test"}, Fingerprint: "There isn't a PageSvc site here.", Vulnerable: true},
		{Service: "GoneSvc", CNAME: []string{"gonesvc.test"}, Fingerprint: "NXDOMAIN", NXDomain: true, Vulnerable: true},
		{Service: "SafeSvc", CNAME: []string{"safesvc.test"}, Fingerprint: "Nothing here", Vulnerable: false}, // not claimable: ignored
		{Service: "Junk", CNAME: []string{"not a host!"}, Fingerprint: "xxxxxxxx", Vulnerable: true},          // unusable: ignored
	}
	for i := 0; i < 12; i++ {
		rows = append(rows, row{Service: fmt.Sprintf("Filler%d", i), CNAME: []string{fmt.Sprintf("filler%d.test", i)}, Fingerprint: "Unclaimed page text", Vulnerable: true})
	}
	b, _ := json.Marshal(rows)
	return b
}

func TestFeedParsers(t *testing.T) {
	kev, err := parseKEV(kevFixture("CVE-2021-41773"))
	if err != nil || len(kev) != 601 || !kev["CVE-2021-41773"].Ransomware {
		t.Fatalf("KEV: %d %v", len(kev), err)
	}
	if _, err := parseKEV([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-1"}]}`)); err == nil {
		t.Error("a truncated KEV catalogue must be refused")
	}
	if _, err := parseTorList([]byte("1.2.3.4\nnot-an-ip\n")); err == nil {
		t.Error("a Tor list with garbage must be refused")
	}
	tp, err := parseTakeoverPrints(takeoverFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tp {
		if p.Service == "SafeSvc" || p.Service == "Junk" {
			t.Errorf("unusable or non-vulnerable entry kept: %+v", p)
		}
	}
	samples := map[string]string{
		feedAWS:        `{"prefixes":[{"ip_prefix":"3.0.0.0/15","region":"eu-west-1","service":"EC2"},{"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},{"ip_prefix":"3.2.0.0/16","region":"x","service":"S3"},{"ip_prefix":"3.4.0.0/16","region":"x","service":"S3"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","region":"x","service":"EC2"}]}`,
		feedGCP:        `{"prefixes":[{"ipv4Prefix":"34.0.0.0/15","service":"Google Cloud","scope":"us-east1"},{"ipv4Prefix":"34.2.0.0/16"},{"ipv4Prefix":"34.3.0.0/16"},{"ipv4Prefix":"34.4.0.0/16"},{"ipv6Prefix":"2600:1900::/28"}]}`,
		feedCloudflare: `{"result":{"ipv4_cidrs":["104.16.0.0/13","104.24.0.0/14","172.64.0.0/13"],"ipv6_cidrs":["2606:4700::/32","2803:f800::/32"]}}`,
		feedFastly:     `{"addresses":["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}`,
		feedOracle:     `{"regions":[{"region":"uk-london-1","cidrs":[{"cidr":"132.145.0.0/16","tags":["OCI"]},{"cidr":"132.146.0.0/16"},{"cidr":"132.147.0.0/16"},{"cidr":"132.148.0.0/16"},{"cidr":"132.149.0.0/16"}]}]}`,
		feedGitHub:     `{"pages":["185.199.108.0/22","2606:50c0:8000::/46"],"hooks":["192.30.252.0/22"],"web":["140.82.112.0/20"],"api":["140.82.113.0/24"]}`,
	}
	for name, body := range samples {
		r, err := parseCloudRanges(name, []byte(body))
		if err != nil || len(r) < 5 {
			t.Errorf("%s: %d ranges, %v", name, len(r), err)
		}
	}
	if _, err := parseCloudRanges(feedCloudflare, []byte(`{"result":{"ipv4_cidrs":["104.16.0.0/13"]}}`)); err == nil {
		t.Error("a near-empty range list must be refused")
	}
}

// feedServer serves every feed; fail switches all of them to HTTP 500.
type feedServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	fail bool
	hits map[string]int
	body map[string][]byte
}

func newFeedServer(t *testing.T) *feedServer {
	fs := &feedServer{hits: map[string]int{}, body: map[string][]byte{
		feedKEV: kevFixture("CVE-2021-41773"), feedTor: torFixture("203.0.113.10"), feedTakeover: takeoverFixture(),
		feedCloudflare: []byte(`{"result":{"ipv4_cidrs":["104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","141.101.64.0/18"],"ipv6_cidrs":[]}}`),
		feedAWS:        []byte(`{"prefixes":[{"ip_prefix":"198.51.100.0/24","region":"eu-west-2","service":"EC2"},{"ip_prefix":"3.0.0.0/15","region":"x","service":"EC2"},{"ip_prefix":"3.2.0.0/16","region":"x","service":"S3"},{"ip_prefix":"3.4.0.0/16","region":"x","service":"S3"},{"ip_prefix":"3.5.0.0/16","region":"x","service":"S3"}]}`),
	}}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		name := strings.TrimPrefix(r.URL.Path, "/")
		fs.hits[name]++
		if fs.fail || fs.body[name] == nil {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(fs.body[name]) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- test fake serving fixed feed fixtures
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) urls() feedURLs {
	u := feedURLs{}
	for _, n := range append([]string{feedKEV, feedTor, feedTakeover}, cloudFeeds...) {
		u[n] = fs.srv.URL + "/" + n
	}
	return u
}

func TestFeedsRefreshCacheAndFallback(t *testing.T) {
	h := newHarness(t)
	fs := newFeedServer(t)
	f := NewFeeds(h.store, h.log, NewHealthBoard())
	f.urls = fs.urls()
	ctx := testCtx(t)
	f.Refresh(ctx, feedKEV, feedTor, feedTakeover, feedCloudflare, feedAWS)
	if e, ok := f.KEV("cve-2021-41773"); !ok || !e.Ransomware {
		t.Errorf("KEV lookup: %+v %v", e, ok)
	}
	if !f.TorExit("203.0.113.10") || f.TorExit("203.0.113.11") {
		t.Error("Tor exit lookup wrong")
	}
	if c, ok := f.Cloud("104.16.1.1"); !ok || !c.CDN || c.Provider != "Cloudflare" {
		t.Errorf("Cloudflare range: %+v %v", c, ok)
	}
	if c, ok := f.Cloud("198.51.100.7"); !ok || c.Provider != "AWS" || cloudLabel(c) != "AWS (EC2, eu-west-2)" {
		t.Errorf("AWS range: %+v %q", c, cloudLabel(c))
	}
	if p, ok := f.TakeoverFor("abc.pagesvc.test."); !ok || p.Fingerprint == "" {
		t.Errorf("takeover print: %+v %v", p, ok)
	}
	if _, ok := f.TakeoverFor("abc.safesvc.test"); ok {
		t.Error("a service that is not claimable must not match")
	}
	// Fresh copies are not downloaded again.
	f.Refresh(ctx, feedKEV)
	if fs.hits[feedKEV] != 1 {
		t.Errorf("KEV downloaded %d times", fs.hits[feedKEV])
	}
	// A restarted agent reads the stored copy instead of downloading.
	f2 := NewFeeds(h.store, h.log, NewHealthBoard())
	f2.urls = fs.urls()
	f2.Refresh(ctx, feedTor)
	if fs.hits[feedTor] != 1 || !f2.TorExit("203.0.113.10") {
		t.Errorf("stored Tor list not reused: hits %d", fs.hits[feedTor])
	}
	// When the stored copy is due and the download fails, the last good copy stays in use.
	f3 := NewFeeds(h.store, h.log, NewHealthBoard())
	f3.urls = fs.urls()
	old, _ := json.Marshal(storedFeed{Fetched: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339), Data: mustJSON(t, []string{"203.0.113.99"})})
	if err := h.store.setMeta("feed:"+feedTor, string(old)); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	fs.fail = true
	fs.mu.Unlock()
	f3.Refresh(ctx, feedTor)
	if !f3.TorExit("203.0.113.99") {
		t.Error("a failed download must keep the last good copy in use")
	}
	var nilFeeds *Feeds
	if nilFeeds.TorExit("1.2.3.4") || nilFeeds.Loaded(feedKEV) != (time.Time{}) {
		t.Error("a nil feed set must answer nothing")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewDiscoverySources(t *testing.T) {
	var csCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/certspotter", func(w http.ResponseWriter, r *http.Request) {
		csCalls++
		switch r.URL.Query().Get("after") {
		case "":
			_, _ = io.WriteString(w, `[{"id":"10","dns_names":["a.example.test","*.wild.example.test"]},{"id":"11","dns_names":["b.example.test"]}]`)
		case "11":
			_, _ = io.WriteString(w, `[{"id":"12","dns_names":["c.example.test","other.test"]}]`)
		default:
			_, _ = io.WriteString(w, `[]`)
		}
	})
	mux.HandleFunc("/urlscan", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"page":{"domain":"d.example.test"},"task":{"domain":"e.example.test"}}]}`)
	})
	mux.HandleFunc("/wayback", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[["original"],["http://old.example.test/login.php"],["https://old.example.test:8443/x"],["f.example.test/path"]]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cfg := DefaultSettings()
	cfg.CrtShEnabled, cfg.HackerTargetEnabled, cfg.CertSpotterEnabled, cfg.URLScanEnabled, cfg.WaybackEnabled = false, false, true, true, true
	d := NewDiscoverer(cfg.Runtime(""), slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.health = NewHealthBoard()
	d.urls = sourceURLs{certspotter: srv.URL + "/certspotter", urlscan: srv.URL + "/urlscan", wayback: srv.URL + "/wayback"}
	out := d.Discover(testCtx(t), "example.test")
	for _, h := range []string{"a.example.test", "wild.example.test", "b.example.test", "c.example.test", "d.example.test", "e.example.test", "old.example.test", "f.example.test"} {
		if _, ok := out.Hosts[h]; !ok {
			t.Errorf("missing %s; got %d hosts", h, len(out.Hosts))
		}
	}
	if _, ok := out.Hosts["other.test"]; ok {
		t.Error("an out-of-scope name was kept")
	}
	if !out.Complete {
		t.Error("CertSpotter answering must make the scan complete without crt.sh")
	}
	if csCalls != 3 {
		t.Errorf("CertSpotter pages fetched: %d, want 3 (two with data, one empty)", csCalls)
	}
}

// A resolver that cannot be reached falls back to DNS-over-HTTPS and still gets the real answer.
func TestDNSOverHTTPSFallback(t *testing.T) {
	var asked int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Name == "gone.example.test." {
			m.Rcode = dns.RcodeNameError
		} else {
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 203.0.113.80")
			m.Answer = append(m.Answer, rr)
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- test fake answering with a binary DNS message
	}))
	t.Cleanup(srv.Close)
	// A local UDP port nothing answers on stands in for a blocked resolver.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	_ = pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := NewResolver(ctx, DNSCfg{Resolvers: []string{dead}, DoHFallback: []string{srv.URL + "/dns-query"}, QPS: 100, Timeout: 500 * time.Millisecond, Retries: 1})
	r.hc = srv.Client()
	r.hc.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	r.health = NewHealthBoard()
	hr := r.ResolveHost(ctx, "www.example.test")
	if got := hr.Records["A"]; len(got) != 1 || got[0] != "203.0.113.80" {
		t.Fatalf("A over DoH fallback: %+v (asked %d)", hr, asked)
	}
	if hr2 := r.ResolveHost(ctx, "gone.example.test"); !hr2.NX {
		t.Error("NXDOMAIN must survive the DoH fallback")
	}
	if it, seen := r.health.Get("dns:" + srv.URL + "/dns-query"); !seen || it.OKCount == 0 {
		t.Error("the DoH fallback must show on System health")
	}
}

// intelLab is a harness with SANS ISC, EPSS and the feeds served locally.
func intelLab(t *testing.T) (*harness, *feedServer) {
	h := newHarness(t)
	fs := newFeedServer(t)
	h.eng.feeds.urls = fs.urls()
	mux := http.NewServeMux()
	mux.HandleFunc("/isc/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "203.0.113.10") {
			recent := time.Now().AddDate(0, 0, -5).Format("2006-01-02")
			_, _ = io.WriteString(w, `{"ip":{"number":"203.0.113.10","count":"12","attacks":7,"maxdate":"`+recent+`","asname":"EXAMPLE","threatfeeds":{"ciarmy":{"lastseen":"`+recent+`"}}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ip":{"count":null,"attacks":null}}`)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		var data []map[string]string
		for _, c := range strings.Split(r.URL.Query().Get("cve"), ",") {
			score := "0.01"
			if c == "CVE-2020-0001" {
				score = "0.62"
			}
			data = append(data, map[string]string{"cve": c, "epss": score})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "OK", "data": data})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	prev := h.eng.newScanner
	h.eng.newScanner = func(cfg *Config, res *Resolver) *Scanner {
		sc := prev(cfg, res)
		sc.enr.urls.isc, sc.enr.urls.epss = srv.URL+"/isc/", srv.URL+"/epss"
		return sc
	}
	st, _ := h.store.LoadSettings()
	st.ISCEnabled, st.EPSSEnabled, st.KEVEnabled, st.TorExitEnabled, st.CloudRangesEnabled, st.TakeoverFeedEnabled = true, true, true, true, true, true
	h.saveSettings(st)
	return h, fs
}

func TestFreeIntelInScans(t *testing.T) {
	h, _ := intelLab(t)
	h.seedExample()
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{3389}, []string{"CVE-2020-0001", "CVE-2021-41773"}, []string{"compromised"})
	// cdn.example.test sits on Cloudflare: InternetDB reports MySQL open there, but that is Cloudflare's edge.
	h.dns.add(t, "cdn.example.test. 60 IN A 104.16.5.5")
	h.dns.addIP(t, "104.16.5.5", 13335, "104.16.0.0/13", "CLOUDFLARENET")
	h.src.addAnubis("cdn.example.test")
	h.intel.idb["104.16.5.5"] = idbBody("104.16.5.5", []int{3306}, nil, nil)
	tg := h.addTarget("example.test", "")
	if tg = h.scan(tg.ID); tg.LastStatus != "ok" {
		t.Fatalf("scan: %s %s", tg.LastStatus, tg.LastError)
	}
	open := h.findingsOf("open")
	flag := open["flag:203.0.113.10"]
	if flag.Kind != "ip-flagged" || !strings.Contains(flag.Detail, "SANS ISC has 12 report(s)") || flag.Trust != trustTrusted || flag.Severity != "high" {
		t.Errorf("Shodan tag + SANS ISC must give a trusted flag: %+v", flag)
	}
	vuln := open["vuln:203.0.113.10"]
	if vuln.Severity != "high" || !strings.Contains(vuln.Detail, "Known Exploited Vulnerabilities") || !strings.Contains(vuln.Detail, "used by ransomware") ||
		!strings.Contains(vuln.Detail, "Highest EPSS: CVE-2020-0001, a 62%") || !strings.HasPrefix(strings.SplitN(vuln.Detail, ": ", 2)[1], "CVE-2021-41773") {
		t.Errorf("KEV and EPSS must grade and order the CVEs: %+v", vuln)
	}
	if tor := open["tor:203.0.113.10"]; tor.Kind != "tor-exit" || tor.Trust != "" {
		t.Errorf("Tor exit: %+v", tor)
	}
	for k := range open {
		if strings.HasPrefix(k, "svc:104.16.5.5") {
			t.Errorf("an open port on a CDN edge must not be a finding: %s", k)
		}
	}
	// Leaving the Tor exit list resolves the finding at the next scan once the list is refreshed.
	h.eng.feeds.mu.Lock()
	h.eng.feeds.tor = map[string]bool{}
	h.eng.feeds.mu.Unlock()
	h.scan(tg.ID)
	if _, still := h.findingsOf("open")["tor:203.0.113.10"]; still {
		t.Error("an address no longer on the exit list must resolve")
	}
}

// Takeover fingerprints: a dangling CNAME to a service the community lists as claimable
// is High, and an active check catches a name that resolves but shows the "unclaimed" page.
func TestTakeoverFingerprints(t *testing.T) {
	l := newWebLab(t)
	fs := newFeedServer(t)
	l.h.eng.feeds.urls = fs.urls()
	st, _ := l.h.store.LoadSettings()
	st.TakeoverFeedEnabled = true
	l.h.saveSettings(st)
	// dangling: CNAME to a gonesvc.test name that does not exist
	l.h.dns.add(t, "old.example.test. 60 IN CNAME acme.gonesvc.test.")
	l.h.src.addAnubis("old.example.test")
	// pages: CNAME to pagesvc.test, which resolves and shows the unclaimed page
	l.h.dns.add(t, "pages.example.test. 60 IN CNAME acme.pagesvc.test.")
	l.h.dns.add(t, "acme.pagesvc.test. 60 IN A 203.0.113.45")
	l.h.dns.addIP(t, "203.0.113.45", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	l.h.src.addAnubis("pages.example.test")
	l.serve("203.0.113.45", 80, page("404", "There isn't a PageSvc site here."), nil, 0)
	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if f := l.findingFor("dangling-cname", "old.example.test"); f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "GoneSvc") {
		t.Errorf("dangling CNAME to a claimable service must be High: %+v (open %v)", f, l.openKinds())
	}
	if f := l.findingFor("subdomain-takeover", "pages.example.test"); f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "PageSvc (via acme.pagesvc.test)") {
		t.Errorf("unclaimed-service page not detected: %+v (open %v)", f, l.openKinds())
	}
	// Claiming the name again resolves it.
	l.serve("203.0.113.45", 80, page("Acme docs", "Welcome"), nil, 0)
	l.h.scanN(tg.ID, 1)
	if f := l.findingFor("subdomain-takeover", "pages.example.test"); f != nil {
		t.Errorf("a claimed name must resolve: %s", f.Detail)
	}
}

func TestISCSignals(t *testing.T) {
	day := func(ago int) string { return time.Now().AddDate(0, 0, -ago).Format("2006-01-02") }
	answers := map[string]string{
		// only Tor and spam feeds: evidence, not a flag
		"198.51.100.1": `{"ip":{"count":null,"attacks":null,"threatfeeds":{"torexit":{"lastseen":"` + day(1) + `"},"forumspam":{}}}}`,
		// a compromised-host feed listing from this week: a flag
		"198.51.100.2": `{"ip":{"count":"0","attacks":"","threatfeeds":{"emergincompromised":{"lastseen":"` + day(3) + `"}}}}`,
		// the same feed, but last seen years ago (the address has likely changed hands): evidence only
		"198.51.100.3": `{"ip":{"threatfeeds":{"ciarmy":{"lastseen":"2017-10-14"}}}}`,
		// an undated listing cannot show the address is bad now
		"198.51.100.4": `{"ip":{"threatfeeds":{"ciarmy":{}}}}`,
		// a few recent reports, as shared infrastructure collects: evidence only
		"198.51.100.5": `{"ip":{"count":186,"attacks":49,"maxdate":"` + day(12) + `"}}`,
		// many sensors, recently: a host scanning the internet, a flag
		"198.51.100.6": `{"ip":{"count":5400,"attacks":"812","maxdate":"` + day(2) + `"}}`,
		// many sensors, but long ago: evidence only
		"198.51.100.7": `{"ip":{"count":5400,"attacks":812,"maxdate":"2021-03-01"}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for ip, body := range answers {
			if strings.Contains(r.URL.Path, "/"+ip) {
				_, _ = io.WriteString(w, body)
				return
			}
		}
		_, _ = io.WriteString(w, `{"ip":{"count":null}}`)
	}))
	t.Cleanup(srv.Close)
	e := NewEnricher(IntelCfg{ISC: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	e.health = NewHealthBoard()
	e.urls.isc = srv.URL + "/"
	ctx := testCtx(t)
	for ip, want := range map[string]bool{"198.51.100.1": false, "198.51.100.2": true, "198.51.100.3": false, "198.51.100.4": false,
		"198.51.100.5": false, "198.51.100.6": true, "198.51.100.7": false} {
		in, err := e.iscHost(ctx, ip)
		if err != nil {
			t.Fatal(err)
		}
		if got := hasTag(in.Tags, "isc-attacker"); got != want {
			t.Errorf("%s: flagged=%v, want %v (tags %v)", ip, got, want, in.Tags)
		}
	}
	listed, _ := e.iscHost(ctx, "198.51.100.2")
	if s := iscSummary(listed.Tags); !strings.Contains(s, "Emerging Threats compromised hosts") {
		t.Errorf("listed summary: %q", s)
	}
	old, _ := e.iscHost(ctx, "198.51.100.3")
	if !hasTag(old.Tags, "isc-feed:ciarmy") || hasTag(old.Tags, "isc-listed:CINS Army bad actors") {
		t.Errorf("an old listing stays as evidence only: %v", old.Tags)
	}
	scanner, _ := e.iscHost(ctx, "198.51.100.6")
	if s := iscSummary(scanner.Tags); s != "SANS ISC has 5400 report(s) of it attacking DShield sensors, most recently "+day(2) {
		t.Errorf("attack summary: %q", s)
	}
}

// An address flagged by SANS ISC alone is Medium (attacking sensors), not High (compromised).
func TestISCOnlyFlagIsMedium(t *testing.T) {
	h, _ := intelLab(t)
	h.seedExample()
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	f, ok := findingKeys(t, h, "ip-flagged", "open")["flag:203.0.113.10"]
	if !ok {
		t.Fatal("no ISC flag raised")
	}
	if f.Severity != "medium" || f.Trust == trustTrusted {
		t.Errorf("ISC alone: want medium and not trusted, got %s / %s", f.Severity, f.Trust)
	}
}
