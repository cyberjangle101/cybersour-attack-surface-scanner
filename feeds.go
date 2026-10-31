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
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Bulk reference feeds.
//
// Some free sources publish a whole dataset instead of answering per-item queries: the
// cloud providers' IP ranges, CISA's Known Exploited Vulnerabilities catalogue, the Tor
// Project's exit list and the community's subdomain-takeover fingerprints. The agent
// downloads each at most once per its refresh period, checks that it parses and is
// plausibly complete, keeps a compact copy in the (encrypted) database and keeps using
// the last good copy when a download fails, so one bad day upstream changes nothing.
// Nothing about the monitored organisation is sent: these are plain downloads.

// Feed names (also their System health connector IDs).
const (
	feedKEV        = "feed-kev"
	feedTor        = "feed-tor"
	feedTakeover   = "feed-takeover"
	feedAWS        = "feed-aws"
	feedGCP        = "feed-gcp"
	feedCloudflare = "feed-cloudflare"
	feedFastly     = "feed-fastly"
	feedOracle     = "feed-oracle"
	feedGitHub     = "feed-github"
)

// cloudFeeds are the provider IP-range feeds, in lookup order.
var cloudFeeds = []string{feedCloudflare, feedFastly, feedAWS, feedGCP, feedOracle, feedGitHub}

// feedURLs are the download locations (tests point them at local servers).
type feedURLs map[string]string

func defaultFeedURLs() feedURLs {
	return feedURLs{
		feedKEV:        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		feedTor:        "https://check.torproject.org/torbulkexitlist",
		feedTakeover:   "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json",
		feedAWS:        "https://ip-ranges.amazonaws.com/ip-ranges.json",
		feedGCP:        "https://www.gstatic.com/ipranges/cloud.json",
		feedCloudflare: "https://api.cloudflare.com/client/v4/ips",
		feedFastly:     "https://api.fastly.com/public-ip-list",
		feedOracle:     "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
		feedGitHub:     "https://api.github.com/meta",
	}
}

// feedRefresh is how long a downloaded feed is used before it is fetched again.
var feedRefresh = map[string]time.Duration{
	feedKEV: 24 * time.Hour, feedTor: 6 * time.Hour, feedTakeover: 7 * 24 * time.Hour,
	feedAWS: 24 * time.Hour, feedGCP: 24 * time.Hour, feedCloudflare: 7 * 24 * time.Hour,
	feedFastly: 7 * 24 * time.Hour, feedOracle: 7 * 24 * time.Hour, feedGitHub: 7 * 24 * time.Hour,
}

// feedStale is how old the last good copy may get before it is no longer used at all.
const feedStale = 30 * 24 * time.Hour

const feedMaxBody = 16 << 20

// CloudRange is one provider network.
type CloudRange struct {
	Prefix   string `json:"p"`
	Provider string `json:"v"`
	Service  string `json:"s,omitempty"` // EC2, CLOUDFRONT, Pages... ("" when the feed does not say)
	Region   string `json:"r,omitempty"`
	CDN      bool   `json:"c,omitempty"` // a shared edge network: open ports there are the provider's, not yours
}

// KEVEntry is one actively exploited vulnerability from CISA's catalogue.
type KEVEntry struct {
	Name       string `json:"n"`
	Added      string `json:"a"`
	Ransomware bool   `json:"r,omitempty"`
}

// TakeoverPrint is one service from can-i-take-over-xyz that is known to be claimable.
type TakeoverPrint struct {
	Service     string   `json:"s"`
	CNAMEs      []string `json:"c"`
	Fingerprint string   `json:"f,omitempty"` // text the service shows for an unclaimed name ("" = only NXDOMAIN matters)
	NXDomain    bool     `json:"n,omitempty"`
}

// storedFeed is a parsed feed as kept in the database.
type storedFeed struct {
	Fetched string          `json:"fetched"`
	Data    json.RawMessage `json:"data"`
}

// Feeds downloads, validates, caches and serves the bulk feeds.
type Feeds struct {
	store  *Store
	log    *slog.Logger
	health *HealthBoard
	hc     *http.Client
	ua     string
	urls   feedURLs

	mu       sync.Mutex
	loaded   map[string]time.Time // when the in-memory copy was fetched upstream
	kev      map[string]KEVEntry
	tor      map[string]bool
	takeover []TakeoverPrint
	ranges   map[string][]cloudNet // per cloud feed
}

type cloudNet struct {
	net netip.Prefix
	CloudRange
}

// NewFeeds creates the feed cache. store may be nil in tests that only parse.
func NewFeeds(store *Store, log *slog.Logger, health *HealthBoard) *Feeds {
	return &Feeds{store: store, log: log, health: health, urls: defaultFeedURLs(),
		ua: "easm-agent/" + version + " (+defensive attack-surface monitoring)",
		hc: &http.Client{Timeout: 90 * time.Second}, loaded: map[string]time.Time{}, ranges: map[string][]cloudNet{}}
}

// Refresh brings the named feeds up to date: from memory, else the database, else a
// download. A failed download keeps the last good copy (up to feedStale old).
func (f *Feeds) Refresh(ctx context.Context, names ...string) {
	for _, name := range names {
		if ctx.Err() != nil {
			return
		}
		f.mu.Lock()
		at, have := f.loaded[name]
		f.mu.Unlock()
		if have && time.Since(at) < feedRefresh[name] {
			continue
		}
		if !have {
			if st, ok := f.loadStored(name); ok {
				if t, err := time.Parse(time.RFC3339, st.Fetched); err == nil && f.install(name, st.Data, t) == nil && time.Since(t) < feedRefresh[name] {
					continue
				}
			}
		}
		t0 := time.Now()
		data, err := f.download(ctx, name)
		f.health.Record(name, "scan", err == nil, time.Since(t0), err)
		if err != nil {
			f.log.Warn("feed download failed; the last good copy stays in use", "feed", name, "err", err)
			continue
		}
		now := time.Now().UTC()
		if err := f.install(name, data, now); err != nil {
			f.log.Warn("feed rejected", "feed", name, "err", err)
			continue
		}
		f.saveStored(name, storedFeed{Fetched: now.Format(time.RFC3339), Data: data})
	}
}

// download fetches and parses one feed into its compact stored form.
func (f *Feeds) download(ctx context.Context, name string) (json.RawMessage, error) {
	u := f.urls[name]
	if u == "" {
		return nil, errors.New("unknown feed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, feedMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > feedMaxBody {
		return nil, errors.New("feed larger than expected")
	}
	var v any
	switch name {
	case feedKEV:
		v, err = parseKEV(body)
	case feedTor:
		v, err = parseTorList(body)
	case feedTakeover:
		v, err = parseTakeoverPrints(body)
	default:
		v, err = parseCloudRanges(name, body)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// install makes a parsed feed the one in use.
func (f *Feeds) install(name string, data json.RawMessage, fetched time.Time) error {
	if time.Since(fetched) > feedStale {
		return errors.New("stored copy is too old")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case feedKEV:
		var m map[string]KEVEntry
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		f.kev = m
	case feedTor:
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		f.tor = map[string]bool{}
		for _, ip := range list {
			f.tor[ip] = true
		}
	case feedTakeover:
		var p []TakeoverPrint
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		f.takeover = p
	default:
		var rs []CloudRange
		if err := json.Unmarshal(data, &rs); err != nil {
			return err
		}
		nets := make([]cloudNet, 0, len(rs))
		for _, r := range rs {
			if p, err := netip.ParsePrefix(r.Prefix); err == nil {
				nets = append(nets, cloudNet{p.Masked(), r})
			}
		}
		// Most specific first, so a service range wins over the provider's catch-all.
		sort.SliceStable(nets, func(i, j int) bool { return nets[i].net.Bits() > nets[j].net.Bits() })
		f.ranges[name] = nets
	}
	f.loaded[name] = fetched
	return nil
}

func (f *Feeds) loadStored(name string) (storedFeed, bool) {
	var st storedFeed
	if f.store == nil {
		return st, false
	}
	v, ok, err := f.store.getMeta("feed:" + name)
	if err != nil || !ok || json.Unmarshal([]byte(v), &st) != nil {
		return st, false
	}
	return st, true
}

func (f *Feeds) saveStored(name string, st storedFeed) {
	if f.store == nil {
		return
	}
	b, err := json.Marshal(st)
	if err == nil {
		err = f.store.setMeta("feed:"+name, string(b))
	}
	if err != nil {
		f.log.Warn("could not keep the feed", "feed", name, "err", err)
	}
}

// ---- lookups (all safe on a nil *Feeds or an empty feed) ----

// KEV returns the catalogue entry for a CVE, if CISA lists it as exploited in the wild.
func (f *Feeds) KEV(cve string) (KEVEntry, bool) {
	if f == nil {
		return KEVEntry{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.kev[strings.ToUpper(cve)]
	return e, ok
}

// TorExit reports whether ip is a current Tor exit node.
func (f *Feeds) TorExit(ip string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tor[ip]
}

// Cloud returns the provider range an address belongs to, if any.
func (f *Feeds) Cloud(ip string) (CloudRange, bool) {
	a, err := netip.ParseAddr(ip)
	if f == nil || err != nil {
		return CloudRange{}, false
	}
	a = a.Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range cloudFeeds {
		for _, n := range f.ranges[name] {
			if n.net.Contains(a) {
				return n.CloudRange, true
			}
		}
	}
	return CloudRange{}, false
}

// TakeoverFor returns the claimable service a CNAME target belongs to, if the feed knows one.
func (f *Feeds) TakeoverFor(target string) (TakeoverPrint, bool) {
	if f == nil {
		return TakeoverPrint{}, false
	}
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.takeover {
		for _, c := range p.CNAMEs {
			if t == c || strings.HasSuffix(t, "."+c) {
				return p, true
			}
		}
	}
	return TakeoverPrint{}, false
}

// Loaded says when a feed was last fetched upstream (zero when it is not in use).
func (f *Feeds) Loaded(name string) time.Time {
	if f == nil {
		return time.Time{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded[name]
}

// ---- parsers: each checks the feed is plausible before it replaces the last good copy ----

var cveIDRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`) // a whole CVE identifier

func parseKEV(body []byte) (map[string]KEVEntry, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Vendor     string `json:"vendorProject"`
			Product    string `json:"product"`
			Name       string `json:"vulnerabilityName"`
			Added      string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("unreadable KEV catalogue")
	}
	out := map[string]KEVEntry{}
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !cveIDRe.MatchString(id) {
			continue
		}
		name := v.Name
		if name == "" {
			name = strings.TrimSpace(v.Vendor + " " + v.Product)
		}
		out[id] = KEVEntry{Name: truncate(name, 120), Added: truncate(v.Added, 10), Ransomware: strings.EqualFold(v.Ransomware, "Known")}
	}
	if len(out) < 500 { // the catalogue has well over a thousand entries
		return nil, fmt.Errorf("KEV catalogue has only %d entries", len(out))
	}
	return out, nil
}

func parseTorList(body []byte) ([]string, error) {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, errors.New("the Tor exit list contains something that is not an address")
		}
		out = append(out, ip.String())
	}
	if len(out) < 100 {
		return nil, fmt.Errorf("the Tor exit list has only %d addresses", len(out))
	}
	return out, nil
}

var hostLabelsRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func parseTakeoverPrints(body []byte) ([]TakeoverPrint, error) {
	var rows []struct {
		Service     string   `json:"service"`
		CNAME       []string `json:"cname"`
		Fingerprint string   `json:"fingerprint"`
		NXDomain    bool     `json:"nxdomain"`
		Vulnerable  bool     `json:"vulnerable"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, errors.New("unreadable takeover fingerprints")
	}
	var out []TakeoverPrint
	for _, r := range rows {
		if !r.Vulnerable {
			continue // only services the community confirmed can be claimed
		}
		p := TakeoverPrint{Service: truncate(strings.TrimSpace(r.Service), 60), NXDomain: r.NXDomain}
		for _, c := range r.CNAME {
			c = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c), "."))
			if hostLabelsRe.MatchString(c) && strings.Count(c, ".") >= 1 {
				p.CNAMEs = append(p.CNAMEs, c)
			}
		}
		if fp := strings.TrimSpace(r.Fingerprint); fp != "" && fp != "NXDOMAIN" && len(fp) >= 8 && len(fp) <= 300 {
			p.Fingerprint = fp
		}
		if p.Service != "" && len(p.CNAMEs) > 0 && (p.Fingerprint != "" || p.NXDomain) {
			out = append(out, p)
		}
	}
	if len(out) < 10 {
		return nil, fmt.Errorf("takeover fingerprints list has only %d usable entries", len(out))
	}
	return out, nil
}

// parseCloudRanges reads one provider's published ranges.
func parseCloudRanges(name string, body []byte) ([]CloudRange, error) {
	var out []CloudRange
	add := func(prefix, provider, service, region string, cdn bool) {
		if _, err := netip.ParsePrefix(strings.TrimSpace(prefix)); err == nil {
			out = append(out, CloudRange{Prefix: strings.TrimSpace(prefix), Provider: provider, Service: service, Region: region, CDN: cdn})
		}
	}
	switch name {
	case feedAWS:
		var raw struct {
			Prefixes []struct {
				IP      string `json:"ip_prefix"`
				Region  string `json:"region"`
				Service string `json:"service"`
			} `json:"prefixes"`
			IPv6 []struct {
				IP      string `json:"ipv6_prefix"`
				Region  string `json:"region"`
				Service string `json:"service"`
			} `json:"ipv6_prefixes"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable AWS ranges")
		}
		for _, p := range raw.Prefixes {
			add(p.IP, "AWS", p.Service, p.Region, p.Service == "CLOUDFRONT")
		}
		for _, p := range raw.IPv6 {
			add(p.IP, "AWS", p.Service, p.Region, p.Service == "CLOUDFRONT")
		}
	case feedGCP:
		var raw struct {
			Prefixes []struct {
				V4      string `json:"ipv4Prefix"`
				V6      string `json:"ipv6Prefix"`
				Service string `json:"service"`
				Scope   string `json:"scope"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable Google Cloud ranges")
		}
		for _, p := range raw.Prefixes {
			add(p.V4, "Google Cloud", p.Service, p.Scope, false)
			add(p.V6, "Google Cloud", p.Service, p.Scope, false)
		}
	case feedCloudflare:
		var raw struct {
			Result struct {
				V4 []string `json:"ipv4_cidrs"`
				V6 []string `json:"ipv6_cidrs"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable Cloudflare ranges")
		}
		for _, p := range append(raw.Result.V4, raw.Result.V6...) {
			add(p, "Cloudflare", "CDN", "", true)
		}
	case feedFastly:
		var raw struct {
			V4 []string `json:"addresses"`
			V6 []string `json:"ipv6_addresses"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable Fastly ranges")
		}
		for _, p := range append(raw.V4, raw.V6...) {
			add(p, "Fastly", "CDN", "", true)
		}
	case feedOracle:
		var raw struct {
			Regions []struct {
				Region string `json:"region"`
				CIDRs  []struct {
					CIDR string   `json:"cidr"`
					Tags []string `json:"tags"`
				} `json:"cidrs"`
			} `json:"regions"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable Oracle Cloud ranges")
		}
		for _, r := range raw.Regions {
			for _, c := range r.CIDRs {
				add(c.CIDR, "Oracle Cloud", strings.Join(c.Tags, "/"), r.Region, false)
			}
		}
	case feedGitHub:
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, errors.New("unreadable GitHub ranges")
		}
		for _, svc := range []string{"pages", "hooks", "web", "api", "actions"} {
			var list []string
			if json.Unmarshal(raw[svc], &list) == nil {
				for _, p := range list {
					add(p, "GitHub", svc, "", svc == "pages")
				}
			}
		}
	default:
		return nil, errors.New("unknown cloud feed")
	}
	if len(out) < 5 {
		return nil, fmt.Errorf("%s has only %d usable ranges", name, len(out))
	}
	return out, nil
}

// enabledFeeds lists the feeds the scan's settings switch on.
func (s *Scanner) enabledFeeds() []string {
	if s.feeds == nil {
		return nil
	}
	in := s.cfg.Intel
	var out []string
	if in.KEV {
		out = append(out, feedKEV)
	}
	if in.TorExits {
		out = append(out, feedTor)
	}
	if in.Takeover {
		out = append(out, feedTakeover)
	}
	if in.Cloud {
		out = append(out, cloudFeeds...)
	}
	return out
}
