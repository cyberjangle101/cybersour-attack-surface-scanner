package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service is one open port reported by an exposure-intelligence source.
type Service struct {
	Port      int
	Transport string // tcp | udp
	Product   string // product / protocol name, e.g. "OpenSSH 8.9" or "HTTP"
}

// IPIntel is what one source knows about one IP address.
type IPIntel struct {
	IP, Source string
	Hostnames  []string
	Tags       []string
	CPEs       []string
	Vulns      []string // CVE IDs
	Org, OS    string
	Services   []Service
	Fetched    string // RFC3339
	Fresh      bool   // fetched during this scan (as opposed to reused from the cache)
}

// DomainInfo is registration data from RDAP.
type DomainInfo struct {
	Domain, Registrar, Created, Expires, Updated string
	Status, Nameservers                          []string
	Fetched                                      string
	Fresh                                        bool
}

// intelURLs holds the base URLs of the exposure-intelligence services (overridable in tests).
type intelURLs struct{ internetdb, shodan, censys, virustotal, rdap, hibp, github, reverseip string }

// Enricher queries optional exposure-intelligence services. It never touches your
// own infrastructure; it asks third parties what they already know about an IP.
type Enricher struct {
	cfg         IntelCfg
	log         *slog.Logger
	hc          *http.Client
	health      *HealthBoard
	via         string        // "scan" or "check", recorded with each health result
	gapOverride time.Duration // tests shorten the pause between GitHub searches
	urls        intelURLs
	ua          string

	vtMu   sync.Mutex
	vtLast time.Time
}

// NewEnricher creates the client for the optional exposure-intelligence sources.
func NewEnricher(cfg IntelCfg, log *slog.Logger, ua string) *Enricher {
	return &Enricher{cfg: cfg, log: log, ua: ua, via: "scan",
		hc: &http.Client{Timeout: 30 * time.Second},
		urls: intelURLs{
			internetdb: "https://internetdb.shodan.io/",
			shodan:     "https://api.shodan.io/",
			censys:     "https://api.platform.censys.io/v3/global/asset/host/",
			virustotal: "https://www.virustotal.com/api/v3/",
			rdap:       "https://rdap.org/domain/",
			hibp:       "https://haveibeenpwned.com/api/v3/",
			github:     "https://api.github.com/",
			reverseip:  "https://api.hackertarget.com/reverseiplookup/",
		}}
}

// Sources lists the per-IP sources that are active right now.
func (e *Enricher) IPSources() []string {
	var s []string
	if e.cfg.InternetDB {
		s = append(s, "internetdb")
	}
	if e.cfg.Shodan.Enabled {
		s = append(s, "shodan")
	}
	if e.cfg.Censys.Enabled {
		s = append(s, "censys")
	}
	return s
}

var errNoData = errors.New("no data")

// errAuth marks a rejected key: remaining lookups for that source are skipped this scan.
type errAuth struct{ msg string }

// Error implements error for authentication failures.
func (e errAuth) Error() string { return e.msg }

func (e *Enricher) secrets() []string {
	return []string{e.cfg.Shodan.Key, e.cfg.Censys.Token, e.cfg.VirusTotal.Key, e.cfg.HIBP.Key, e.cfg.GitHub.Key}
}

// getJSON performs a GET and decodes JSON. Keys may travel in the URL (Shodan), so
// every returned error is scrubbed of secrets and never contains the URL itself.
func (e *Enricher) getJSON(ctx context.Context, u string, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("bad request")
	}
	req.Header.Set("User-Agent", e.ua)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drops the URL (and any key in it)
		}
		return redact(err, e.secrets()...)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNoData
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return errAuth{fmt.Sprintf("HTTP %d: key rejected or plan does not allow this call", resp.StatusCode)}
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("HTTP 429: rate limited")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return errors.New("unreadable response")
		}
	}
	return nil
}

// ---- per-IP sources ----

// internetDB queries Shodan InternetDB (free, no key) for an address's open ports, CVEs and tags.
func (e *Enricher) internetDB(ctx context.Context, ip string) (*IPIntel, error) {
	var r struct {
		Ports     []int    `json:"ports"`
		CPEs      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if err := e.getJSON(ctx, e.urls.internetdb+url.PathEscape(ip), nil, &r); err != nil {
		if errors.Is(err, errNoData) {
			return &IPIntel{IP: ip, Source: "internetdb"}, nil // known to the service, nothing exposed
		}
		return nil, err
	}
	in := &IPIntel{IP: ip, Source: "internetdb", Hostnames: r.Hostnames, Tags: r.Tags, CPEs: r.CPEs, Vulns: cleanCVEs(r.Vulns)}
	for _, p := range r.Ports {
		in.Services = append(in.Services, Service{Port: p, Transport: "tcp"})
	}
	return in, nil
}

// shodanHost queries the Shodan API (key required) for banners, software and vulnerabilities on an address.
func (e *Enricher) shodanHost(ctx context.Context, ip string) (*IPIntel, error) {
	var r struct {
		Org       string   `json:"org"`
		OS        string   `json:"os"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
		Data      []struct {
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			Module    string `json:"_shodan.module"`
		} `json:"data"`
	}
	u := e.urls.shodan + "shodan/host/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(e.cfg.Shodan.Key)
	if err := e.getJSON(ctx, u, nil, &r); err != nil {
		if errors.Is(err, errNoData) {
			return &IPIntel{IP: ip, Source: "shodan"}, nil
		}
		return nil, err
	}
	in := &IPIntel{IP: ip, Source: "shodan", Hostnames: r.Hostnames, Tags: r.Tags, Vulns: cleanCVEs(r.Vulns), Org: r.Org, OS: r.OS}
	seen := map[string]bool{}
	for _, d := range r.Data {
		tr := strings.ToLower(d.Transport)
		if tr != "udp" {
			tr = "tcp"
		}
		k := fmt.Sprintf("%d/%s", d.Port, tr)
		if seen[k] || d.Port <= 0 {
			continue
		}
		seen[k] = true
		prod := strings.TrimSpace(d.Product + " " + d.Version)
		in.Services = append(in.Services, Service{Port: d.Port, Transport: tr, Product: truncate(prod, 80)})
	}
	return in, nil
}

// censysHost queries the Censys Platform API (token required) for services on an address.
func (e *Enricher) censysHost(ctx context.Context, ip string) (*IPIntel, error) {
	var r struct {
		Result struct {
			Resource struct {
				Services []struct {
					Port      int    `json:"port"`
					Protocol  string `json:"protocol"`
					Transport string `json:"transport_protocol"`
				} `json:"services"`
			} `json:"resource"`
		} `json:"result"`
	}
	u := e.urls.censys + url.PathEscape(ip)
	hdr := map[string]string{"Authorization": "Bearer " + e.cfg.Censys.Token}
	if e.cfg.Censys.OrgID != "" {
		hdr["X-Organization-ID"] = e.cfg.Censys.OrgID
	}
	if err := e.getJSON(ctx, u, hdr, &r); err != nil {
		if errors.Is(err, errNoData) {
			return &IPIntel{IP: ip, Source: "censys"}, nil
		}
		return nil, err
	}
	in := &IPIntel{IP: ip, Source: "censys"}
	seen := map[string]bool{}
	for _, s := range r.Result.Resource.Services {
		tr := strings.ToLower(s.Transport)
		if tr != "udp" {
			tr = "tcp"
		}
		k := fmt.Sprintf("%d/%s", s.Port, tr)
		if seen[k] || s.Port <= 0 {
			continue
		}
		seen[k] = true
		in.Services = append(in.Services, Service{Port: s.Port, Transport: tr, Product: truncate(strings.ToUpper(s.Protocol), 40)})
	}
	return in, nil
}

// cleanCVEs keeps only well-formed CVE identifiers, upper-cased and de-duplicated.
func cleanCVEs(in []string) []string {
	var out []string
	for _, v := range in {
		v = strings.ToUpper(strings.TrimSpace(v))
		if strings.HasPrefix(v, "CVE-") && len(v) < 24 {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// IPResult is the outcome of LookupIPs.
type IPResult struct {
	Intel   map[string]map[string]*IPIntel // ip -> source -> data (fresh or cached)
	OK      map[string]bool                // "ip|source" -> the data is current (fetched now or still within the cache TTL)
	Skipped int                            // IPs not looked up because of the per-scan cap
}

// LookupIPs asks every active source about the IPs, reusing cached answers younger
// than the TTL. cached[ip][source] comes from the database.
func (e *Enricher) LookupIPs(ctx context.Context, ips []string, cached map[string]map[string]*IPIntel) *IPResult {
	res := &IPResult{Intel: map[string]map[string]*IPIntel{}, OK: map[string]bool{}}
	var mu sync.Mutex
	put := func(in *IPIntel, ok bool) {
		mu.Lock()
		defer mu.Unlock()
		if in != nil {
			if res.Intel[in.IP] == nil {
				res.Intel[in.IP] = map[string]*IPIntel{}
			}
			res.Intel[in.IP][in.Source] = in
		}
		if ok && in != nil {
			res.OK[in.IP+"|"+in.Source] = true
		}
	}
	for _, src := range e.IPSources() {
		var todo []string
		fetched := 0
		for _, ip := range ips {
			if c := cached[ip][src]; c != nil {
				if t, err := time.Parse(time.RFC3339, c.Fetched); err == nil && time.Since(t) < e.cfg.CacheTTL {
					put(c, true)
					continue
				}
				put(c, false) // stale: still shown, but not trusted for auto-resolve
			}
			if fetched >= e.cfg.MaxIPs {
				res.Skipped++
				continue
			}
			fetched++
			todo = append(todo, ip)
		}
		if len(todo) == 0 {
			continue
		}
		var fn func(context.Context, string) (*IPIntel, error)
		var workers int
		var gap time.Duration
		switch src {
		case "internetdb":
			fn, workers, gap = e.internetDB, 4, 50*time.Millisecond
		case "shodan":
			fn, workers, gap = e.shodanHost, 1, 1100*time.Millisecond // Shodan allows ~1 request/second
		case "censys":
			fn, workers, gap = e.censysHost, 1, 1000*time.Millisecond
		}
		e.runSource(ctx, src, todo, workers, gap, fn, put)
	}
	return res
}

// runSource looks up many IPs with one source using a small worker pool, honouring per-source delays, the IP cap and stop-on-auth/rate-limit rules.
func (e *Enricher) runSource(ctx context.Context, src string, ips []string, workers int, gap time.Duration,
	fn func(context.Context, string) (*IPIntel, error), put func(*IPIntel, bool)) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	var stopMu sync.Mutex
	stopped := false
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				stopMu.Lock()
				s := stopped
				stopMu.Unlock()
				if s || ctx.Err() != nil {
					continue
				}
				t0 := time.Now()
				in, err := fn(ctx, ip)
				e.health.Record(src, e.via, err == nil, time.Since(t0), err)
				if err != nil {
					e.log.Warn("intel lookup failed", "source", src, "ip", ip, "err", err)
					var ea errAuth
					if errors.As(err, &ea) || strings.Contains(err.Error(), "429") {
						stopMu.Lock()
						stopped = true // bad key / rate limit: stop hammering for the rest of this scan
						stopMu.Unlock()
					}
					continue
				}
				in.Fetched, in.Fresh = nowUTC(), true
				put(in, true)
				time.Sleep(gap)
			}
		}()
	}
feed:
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
}

// ---- subdomain sources that need a key ----

// ShodanSubdomains lists subdomains Shodan knows for a domain (costs one query credit).
func (e *Enricher) ShodanSubdomains(ctx context.Context, root string) ([]string, error) {
	var hosts []string
	for page := 1; page <= 3; page++ {
		var r struct {
			Subdomains []string `json:"subdomains"`
			More       bool     `json:"more"`
		}
		u := e.urls.shodan + "dns/domain/" + url.PathEscape(root) + "?page=" + strconv.Itoa(page) + "&key=" + url.QueryEscape(e.cfg.Shodan.Key)
		if err := e.getJSON(ctx, u, nil, &r); err != nil {
			if errors.Is(err, errNoData) {
				break
			}
			return hosts, err
		}
		for _, s := range r.Subdomains {
			if s != "" {
				hosts = append(hosts, s+"."+root)
			}
		}
		if !r.More {
			break
		}
	}
	return hosts, nil
}

// VirusTotalSubdomains pages through /domains/{d}/subdomains. The free key allows 4
// requests per minute, so requests are spaced 16 s apart and capped at 3 pages.
func (e *Enricher) VirusTotalSubdomains(ctx context.Context, root string) ([]string, error) {
	var hosts []string
	cursor := ""
	for page := 0; page < 3; page++ {
		e.vtMu.Lock()
		if wait := 16*time.Second - time.Since(e.vtLast); wait > 0 && !e.vtLast.IsZero() {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				e.vtMu.Unlock()
				return hosts, ctx.Err()
			}
		}
		e.vtLast = time.Now()
		e.vtMu.Unlock()

		var r struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}
		u := e.urls.virustotal + "domains/" + url.PathEscape(root) + "/subdomains?limit=40"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		if err := e.getJSON(ctx, u, map[string]string{"x-apikey": e.cfg.VirusTotal.Key}, &r); err != nil {
			if errors.Is(err, errNoData) {
				break
			}
			return hosts, err
		}
		for _, d := range r.Data {
			hosts = append(hosts, d.ID)
		}
		if r.Meta.Cursor == "" {
			break
		}
		cursor = r.Meta.Cursor
	}
	return hosts, nil
}

// ---- RDAP ----

// RDAPDomain looks up registration data. It tries the name itself and then its
// parents (never a bare TLD) because a monitored name may be a subdomain.
func (e *Enricher) RDAPDomain(ctx context.Context, domain string) (*DomainInfo, error) {
	labels := strings.Split(domain, ".")
	var lastErr = errNoData
	for i := 0; i+2 <= len(labels) && i < 4; i++ {
		name := strings.Join(labels[i:], ".")
		var r struct {
			Events []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
			Status      []string `json:"status"`
			Nameservers []struct {
				Name string `json:"ldhName"`
			} `json:"nameservers"`
			Entities []struct {
				Roles []string `json:"roles"`
				VCard []any    `json:"vcardArray"`
			} `json:"entities"`
		}
		t0 := time.Now()
		err := e.getJSON(ctx, e.urls.rdap+url.PathEscape(name), nil, &r)
		if errors.Is(err, errNoData) {
			e.health.Record("rdap", e.via, true, time.Since(t0), nil) // the service answered
			lastErr = err
			continue
		}
		e.health.Record("rdap", e.via, err == nil, time.Since(t0), err)
		if err != nil {
			return nil, err
		}
		di := &DomainInfo{Domain: name, Status: r.Status, Fetched: nowUTC(), Fresh: true}
		for _, ev := range r.Events {
			switch strings.ToLower(ev.Action) {
			case "expiration":
				di.Expires = ev.Date
			case "registration":
				di.Created = ev.Date
			case "last changed":
				di.Updated = ev.Date
			}
		}
		for _, n := range r.Nameservers {
			di.Nameservers = append(di.Nameservers, strings.ToLower(n.Name))
		}
		for _, en := range r.Entities {
			for _, role := range en.Roles {
				if role == "registrar" {
					di.Registrar = vcardName(en.VCard)
				}
			}
		}
		return di, nil
	}
	return nil, lastErr
}

// vcardName extracts the display name from an RDAP vCard array.
func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		arr, _ := p.([]any)
		if len(arr) >= 4 && arr[0] == "fn" {
			if s, ok := arr[3].(string); ok {
				return truncate(s, 120)
			}
		}
	}
	return ""
}

// ---- classification helpers ----

// riskyPorts are services that should rarely face the internet.
var riskyPorts = map[int]string{
	21: "FTP", 23: "Telnet", 69: "TFTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS", 445: "SMB",
	1433: "Microsoft SQL Server", 1521: "Oracle DB", 2375: "Docker API (unencrypted)", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch transport",
	11211: "Memcached", 27017: "MongoDB", 5601: "Kibana", 2049: "NFS", 111: "RPC portmapper", 161: "SNMP", 389: "LDAP", 5985: "WinRM (HTTP)",
}

// isRiskyPort says whether a TCP port is a sensitive service (RDP, SMB, databases...) and names it.
func isRiskyPort(p int) (string, bool) { s, ok := riskyPorts[p]; return s, ok }

// hasTag reports whether any of the wanted tags is present (case-insensitive).
func hasTag(tags []string, want ...string) bool {
	for _, t := range tags {
		for _, w := range want {
			if strings.EqualFold(t, w) {
				return true
			}
		}
	}
	return false
}

func publicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && isPublicIP(ip)
}

// shodanInfo calls the free /api-info endpoint: it validates the key without using credits.
func (e *Enricher) shodanInfo(ctx context.Context) (string, error) {
	var r struct {
		Plan         string `json:"plan"`
		QueryCredits int    `json:"query_credits"`
		ScanCredits  int    `json:"scan_credits"`
	}
	if err := e.getJSON(ctx, e.urls.shodan+"api-info?key="+url.QueryEscape(e.cfg.Shodan.Key), nil, &r); err != nil {
		return "", err
	}
	return fmt.Sprintf("plan %s, %d query credits, %d scan credits", r.Plan, r.QueryCredits, r.ScanCredits), nil
}

// virusTotalPing makes one request to confirm the key works.
func (e *Enricher) virusTotalPing(ctx context.Context) error {
	err := e.getJSON(ctx, e.urls.virustotal+"domains/example.com", map[string]string{"x-apikey": e.cfg.VirusTotal.Key}, nil)
	return err
}
