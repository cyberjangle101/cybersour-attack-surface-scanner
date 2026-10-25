package main

// Native Go fuzz targets. Run one with, e.g.
//
//	go test -run xxx -fuzz FuzzParseCrtSh -fuzztime 60s
//
// Plain `go test` runs only the seed corpus (and any crashers saved in testdata/fuzz), so these
// double as regression tests. Every target asserts "never panics" plus a security invariant
// where one exists (e.g. discovered hosts always stay inside the monitored domain).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func FuzzParseCrtSh(f *testing.F) {
	f.Add(`[{"id":1,"issuer_ca_id":2,"issuer_name":"C=US, O=LE","common_name":"a.example.test","name_value":"a.example.test\nb.example.test","not_before":"2024-01-01T00:00:00","not_after":"2025-01-01T00:00:00","serial_number":"ab"}]`)
	f.Add(`[`)
	f.Add(`{}`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, body string) {
		hosts, _, err := parseCrtSh(strings.NewReader(body), "example.test")
		if err != nil {
			return
		}
		for _, h := range hosts {
			if !inScope(h, "example.test") {
				t.Fatalf("out-of-scope host accepted: %q", h)
			}
		}
	})
}

func FuzzParseHostLists(f *testing.F) {
	f.Add("www.example.test,1.2.3.4\nmail.example.test,5.6.7.8\n")
	f.Add("error check your search parameter")
	f.Add(`{"passive_dns":[{"hostname":"x.example.test"}]}`)
	f.Add(`["a.example.test","b.example.test"]`)
	f.Add(`{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`)
	f.Add(`<title>Attention Required! | Cloudflare</title>`)
	f.Fuzz(func(t *testing.T, body string) {
		_, _ = parseHackerTarget(strings.NewReader(body))
		_, _ = parseOTX(strings.NewReader(body))
		_, _ = parseAnubis(strings.NewReader(body))
		for _, status := range []int{403, 429, 503} {
			_ = otxRefused(status, []byte(body))
			_ = anubisRefused(status, []byte(body))
		}
	})
}

// One shared stub server answers every exposure-intelligence call with the fuzz payload.
func FuzzIntelResponses(f *testing.F) {
	var payload atomic.Value
	payload.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload.Load().(string)))
	}))
	f.Cleanup(srv.Close)
	cfg := DefaultSettings().RuntimeWith(Secrets{Shodan: "SHODANKEY1234", Censys: "CENSYSTOKEN1234", VirusTotal: "VTKEY123456"}).Intel
	e := NewEnricher(cfg, testLogger(f), "fuzz")
	e.urls = intelURLs{internetdb: srv.URL + "/", shodan: srv.URL + "/", censys: srv.URL + "/", virustotal: srv.URL + "/", rdap: srv.URL + "/"}
	f.Add(`{"cpes":["cpe:/a:x:y:1"],"hostnames":["a"],"ip":"1.1.1.1","ports":[80,443],"tags":["eol-os"],"vulns":["CVE-2021-1","x"]}`)
	f.Add(`{"ports":[1,2,3],"data":[{"port":80,"transport":"tcp","product":"nginx"}],"vulns":{"CVE-2020-1":{}}}`)
	f.Add(`{"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}],"nameservers":[{"ldhName":"ns1.x"}]}`)
	f.Add(`{"resource":{"services":[{"port":22,"protocol":"ssh"}]}}`)
	f.Add(`{"data":[{"id":"a.example.test"}],"links":{"next":""}}`)
	f.Fuzz(func(t *testing.T, body string) {
		payload.Store(body)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if in, err := e.internetDB(ctx, "203.0.113.5"); err == nil {
			for _, v := range in.Vulns {
				if !strings.HasPrefix(v, "CVE-") {
					t.Fatalf("non-CVE identifier kept: %q", v)
				}
			}
		}
		_, _ = e.shodanHost(ctx, "203.0.113.5")
		_, _ = e.censysHost(ctx, "203.0.113.5")
		_, _ = e.RDAPDomain(ctx, "example.test")
		_, _ = e.shodanInfo(ctx)
	})
}

func FuzzCymruAndEmailPolicy(f *testing.F) {
	f.Add("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11")
	f.Add("v=spf1 include:_spf.google.com ~all")
	f.Add("v=DMARC1; p=none; rua=mailto:a@b.c")
	f.Fuzz(func(t *testing.T, s string) {
		if asn, prefix, _, err := parseCymruOrigin(s); err == nil && (asn < 0 || strings.Contains(prefix, "|")) {
			t.Fatalf("bad parse: %d %q", asn, prefix)
		}
		_ = spfIssues([]string{s})
		_ = dmarcIssues([]string{s})
		_ = cpeName(s)
		_ = Hint(s)
		_ = truncate(s, 5)
		if out := csvSafe(s); out != "" && strings.ContainsRune("=+-@\t\r", rune(out[0])) {
			t.Fatalf("csv formula not neutralised: %q", out)
		}
		_ = nameCovers(s, "www.example.test")
		_, _ = parseASNList(s)
	})
}

func FuzzTargetFromForm(f *testing.F) {
	f.Add("Example.COM", "AS13335, 16509", "cloudflare", "^ci-\\d+\\.example\\.com$", "60", "note")
	f.Add("  http://evil.test/path ", "", "", "(", "x", "")
	f.Add("1.2.3.4", "AS0", "", "", "-5", "")
	f.Fuzz(func(t *testing.T, domain, asns, kw, ignore, interval, notes string) {
		tg, err := TargetFromForm(domain, asns, kw, ignore, interval, notes)
		if err != nil {
			return
		}
		if tg.Domain != strings.ToLower(tg.Domain) || strings.ContainsAny(tg.Domain, " /\\:@\t\r\n") || !strings.Contains(tg.Domain, ".") || looksLikeIP(tg.Domain) {
			t.Fatalf("unsafe domain accepted: %q", tg.Domain)
		}
		_ = tg.ignored("www." + tg.Domain) // stored regexes must be safe to evaluate
		_ = tg.owns(&ASNInfo{ASN: 64500, Org: notes})
	})
}

func FuzzSettingsJSON(f *testing.F) {
	b, _ := json.Marshal(DefaultSettings())
	f.Add(string(b))
	f.Add(`{"IntervalMinutes":-1,"DNSResolvers":["x"]}`)
	f.Fuzz(func(t *testing.T, body string) {
		s := DefaultSettings()
		if json.Unmarshal([]byte(body), &s) != nil {
			return
		}
		if s.Normalize() == nil {
			cfg := s.RuntimeWith(Secrets{})
			if cfg.DNS.Workers < 1 || cfg.Schedule.TargetTimeout <= 0 {
				t.Fatalf("validated settings produced an unusable config: %+v", cfg.DNS)
			}
		}
	})
}

func FuzzStoredStateLoaders(f *testing.F) {
	f.Add(`{"Items":[{"Name":"otx","OKCount":2}],"Log":[{"Name":"otx","OK":true}]}`)
	f.Add(`[{"Name":"x"}]`)
	f.Fuzz(func(t *testing.T, body string) {
		h := NewHealthBoard()
		h.Load(body)
		_ = h.Marshal()
		_ = h.Log("", false, 10)
		h.Record("x", "scan", false, time.Millisecond, errString(body))
	})
}

func FuzzKeyFile(f *testing.F) {
	f.Add("0000000000000000000000000000000000000000000000000000000000000000\n")
	f.Add(wrappedMagic + "AAAA")
	f.Fuzz(func(t *testing.T, content string) {
		old := PassphraseSource
		PassphraseSource = func() (string, error) { return "irrelevant passphrase", nil }
		defer func() { PassphraseSource = old }()
		p := filepath.Join(t.TempDir(), "easm.key")
		if os.WriteFile(p, []byte(content), 0o600) != nil {
			return
		}
		if v, err := OpenVault(p); err == nil && len(v.DBKey()) != 64 {
			t.Fatal("accepted key file without a usable key")
		}
	})
}

// A DNS reply is attacker-influenced data: unpacking and record collection must never panic.
func FuzzDNSWire(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("a.example.test.", dns.TypeA)
	rr, _ := dns.NewRR("a.example.test. 60 IN CNAME b.example.test.")
	m.Answer = append(m.Answer, rr)
	wire, _ := m.Pack()
	f.Add(wire)
	f.Fuzz(func(t *testing.T, data []byte) {
		var in dns.Msg
		if in.Unpack(data) != nil {
			return
		}
		for _, qt := range []uint16{dns.TypeA, dns.TypeCNAME, dns.TypeTXT, dns.TypeMX, dns.TypeNS} {
			_ = collectRRs(&in, "a.example.test", qt)
		}
	})
}

// Hostile query strings against the logged-in web UI must never produce a server error.
func FuzzWebQueries(f *testing.F) {
	e := newWebEnv(f)
	e.seedExample()
	b := e.browser()
	b.setup("admin", "correct horse battery")
	b.post("/targets", url.Values{"domain": {"example.test"}})
	e.scan(1)
	f.Add("assets", "ip", "203.0.113.10", "")
	f.Add("assets/view", "domain", "www.example.test", "x")
	f.Add("findings", "", "", "' OR 1=1--")
	f.Fuzz(func(t *testing.T, _, typ, id, q string) {
		for _, p := range []string{"assets", "assets/view", "findings", "events", "health", "report", "targets/" + id} {
			v := url.Values{"type": {typ}, "id": {id}, "q": {q}, "target": {id}, "page": {q}, "connector": {id}, "status": {typ}}
			req, err := http.NewRequest("GET", b.base+"/"+p+"?"+v.Encode(), nil)
			if err != nil {
				return
			}
			resp, err := b.c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 500 {
				t.Fatalf("GET /%s?%s -> %d", p, v.Encode(), resp.StatusCode)
			}
		}
	})
}

// FuzzUpdateMetadata: versions and signed checksum files come from the network.
// Whatever arrives, parsing never panics, versions round-trip, and a checksum is
// only ever returned for a file whose signature is valid.
func FuzzUpdateMetadata(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := []byte("# easm-agent 1.9.0\n" + strings.Repeat("a", 64) + "  easm-agent-windows-amd64.exe\n")
	f.Add("v1.9.0", good, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, good)))
	f.Add("Windows", []byte("garbage"), "!!")
	f.Add("1.2.3-rc.1", []byte("# easm-agent 1.2.3\n"), "")
	f.Fuzz(func(t *testing.T, tag string, sums []byte, sig string) {
		if v, ok := parseVersion(tag); ok {
			if again, ok2 := parseVersion(v.String()); !ok2 || again != v {
				t.Fatalf("%q -> %v does not round-trip", tag, v)
			}
		}
		h, err := verifySums(pub, sums, []byte(sig), "1.9.0", "easm-agent-windows-amd64.exe")
		if err == nil {
			raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
			if derr != nil || !ed25519.Verify(pub, sums, raw) || len(h) != 64 {
				t.Fatalf("checksum %q accepted without a valid signature", h)
			}
		}
	})
}

// FuzzBrowserCommand: whatever address reaches the browser launcher, only an
// http(s) URL with a host is ever handed to the OS, as one argument.
func FuzzBrowserCommand(f *testing.F) {
	for _, s := range []string{"https://127.0.0.1:8080", "http://[::1]:8080", "file:///etc/passwd", "javascript:alert(1)",
		"https://x\" & calc.exe", "https://a.example/?q=1 --flag", "\\\\host\\share", ""} {
		f.Add(s)
	}
	desktop := func(string) string { return ":0" }
	f.Fuzz(func(t *testing.T, raw string) {
		cmd, err := browserCommand(raw, desktop)
		if err != nil {
			return
		}
		u, perr := url.Parse(cmd.Args[len(cmd.Args)-1])
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			t.Fatalf("%q reached the browser as %q", raw, cmd.Args[len(cmd.Args)-1])
		}
	})
}
