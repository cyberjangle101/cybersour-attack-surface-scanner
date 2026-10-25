package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ASNInfo is the network-ownership record for one IP address (origin AS number, announced prefix, country and organisation).
type ASNInfo struct {
	IP      string
	ASN     int
	Prefix  string
	Country string
	Org     string
	Private bool
}

// String renders the owner as "AS<n> <org>, <country>" (or "non-public address").
func (a *ASNInfo) String() string {
	if a.Private {
		return "non-public address"
	}
	if a.Country == "" {
		return fmt.Sprintf("AS%d %s", a.ASN, a.Org)
	}
	return fmt.Sprintf("AS%d %s, %s", a.ASN, a.Org, a.Country)
}

// ASNResolver maps IP addresses to their owning network. It asks Team Cymru's DNS WHOIS first, falls back to RIPEstat, and caches answers in the database.
type ASNResolver struct {
	cfg   ASNCfg
	res   *Resolver
	store *Store
	log   *slog.Logger
	hc    *http.Client

	health   *HealthBoard
	progress func(done, total int) // optional
	ripeURL  string                // test seam
	bgFails  atomic.Int32          // consecutive BGPView failures; fallback skipped once clearly down
	mu       sync.Mutex
	names    map[int]string
}

// NewASNResolver builds a resolver that uses res for DNS WHOIS lookups and store for the cache.
func NewASNResolver(cfg ASNCfg, res *Resolver, store *Store, log *slog.Logger) *ASNResolver {
	return &ASNResolver{cfg: cfg, res: res, store: store, log: log,
		hc: &http.Client{Timeout: 20 * time.Second}, names: map[int]string{}}
}

func isPublicIP(ip net.IP) bool {
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() && !ip.IsUnspecified()
}

// LookupMany resolves many addresses concurrently (8 at a time) and returns the ones it could resolve; failures are logged and skipped.
func (a *ASNResolver) LookupMany(ctx context.Context, ips []string) map[string]*ASNInfo {
	out := make(map[string]*ASNInfo, len(ips))
	if !a.cfg.Enabled {
		return out
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var doneN atomic.Int64
	sem := make(chan struct{}, 8)
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if a.progress != nil {
					a.progress(int(doneN.Add(1)), len(ips))
				}
			}()
			info, err := a.Lookup(ctx, ip)
			if err != nil {
				a.log.Debug("asn lookup failed", "ip", ip, "err", err)
				return
			}
			mu.Lock()
			out[ip] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// Lookup returns the owner of one address: cache first, then Team Cymru, then the RIPEstat fallback. Private/reserved addresses are reported as such without a network call.
func (a *ASNResolver) Lookup(ctx context.Context, ip string) (*ASNInfo, error) {
	p := net.ParseIP(ip)
	if p == nil {
		return nil, fmt.Errorf("bad ip %q", ip)
	}
	if !isPublicIP(p) {
		return &ASNInfo{IP: ip, Private: true}, nil
	}
	if c, ok := a.store.GetASN(ip, a.cfg.CacheTTL); ok {
		return c, nil
	}
	t0 := time.Now()
	info, err := a.cymru(ctx, ip, p)
	// "no origin data" is a valid answer for an unannounced prefix, not an outage.
	a.health.Record("asn-cymru", "scan", err == nil || err.Error() == "no origin data", time.Since(t0), err)
	if err != nil && a.cfg.BGPViewFallback && a.bgFails.Load() < 5 {
		a.log.Debug("cymru lookup failed, trying ripestat", "ip", ip, "err", err)
		t1 := time.Now()
		info, err = a.ripestat(ctx, ip)
		a.health.Record("asn-ripestat", "scan", err == nil, time.Since(t1), err)
		if err != nil {
			a.bgFails.Add(1)
		} else {
			a.bgFails.Store(0)
		}
	}
	if err != nil {
		return nil, err
	}
	a.store.PutASN(info)
	return info, nil
}

// cymruOriginName builds the reversed-address DNS name used by Team Cymru's origin service (IPv4: d.c.b.a.origin.asn.cymru.com; IPv6: nibble form).
func cymruOriginName(p net.IP) string {
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}
	h := hex.EncodeToString(p.To16())
	nib := make([]string, 0, 32)
	for i := len(h) - 1; i >= 0; i-- {
		nib = append(nib, string(h[i]))
	}
	return strings.Join(nib, ".") + ".origin6.asn.cymru.com"
}

// parseCymruOrigin parses "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11".
func parseCymruOrigin(s string) (asn int, prefix, cc string, err error) {
	parts := strings.Split(s, "|")
	if len(parts) < 3 {
		return 0, "", "", fmt.Errorf("unexpected cymru origin record %q", s)
	}
	f := strings.Fields(parts[0])
	if len(f) == 0 {
		return 0, "", "", errors.New("empty ASN field")
	}
	// MOAS prefixes list several ASNs; take the first. ASNs are unsigned 32-bit, so a sign or overflow means a malformed record.
	n, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return 0, "", "", fmt.Errorf("bad ASN in cymru origin record: %w", err)
	}
	if n > uint64(math.MaxInt) {
		return 0, "", "", fmt.Errorf("ASN out of range for int: %d", n)
	}
	return int(n), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), nil
}

// cymru asks Team Cymru's DNS WHOIS which AS announces ip and resolves the AS name.
func (a *ASNResolver) cymru(ctx context.Context, ip string, p net.IP) (*ASNInfo, error) {
	txts, nx, err := a.res.TXT(ctx, cymruOriginName(p))
	if err != nil {
		return nil, err
	}
	if nx || len(txts) == 0 {
		return nil, errors.New("no origin data")
	}
	asn, prefix, cc, err := parseCymruOrigin(txts[0])
	if err != nil {
		return nil, err
	}
	return &ASNInfo{IP: ip, ASN: asn, Prefix: prefix, Country: cc, Org: a.asnName(ctx, asn)}, nil
}

// asnName resolves "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US".
func (a *ASNResolver) asnName(ctx context.Context, asn int) string {
	a.mu.Lock()
	if n, ok := a.names[asn]; ok {
		a.mu.Unlock()
		return n
	}
	a.mu.Unlock()
	name := ""
	if txts, _, err := a.res.TXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn)); err == nil && len(txts) > 0 {
		if parts := strings.Split(txts[0], "|"); len(parts) >= 5 {
			name = strings.TrimSpace(parts[4])
		}
	}
	if name != "" {
		a.mu.Lock()
		a.names[asn] = name
		a.mu.Unlock()
	}
	return name
}

// ripestat is the fallback when Team Cymru's DNS WHOIS cannot be reached. RIPEstat is run by the
// RIPE NCC, needs no key and covers every region. (BGPView, used by earlier versions, has been
// discontinued, so its hostname no longer resolves.)
func (a *ASNResolver) ripestat(ctx context.Context, ip string) (*ASNInfo, error) {
	base := a.ripeURL
	if base == "" {
		base = "https://stat.ripe.net"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/data/prefix-overview/data.json?resource="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ripestat HTTP %d", resp.StatusCode)
	}
	var p struct {
		Data struct {
			Resource string `json:"resource"`
			ASNs     []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&p); err != nil {
		return nil, err
	}
	if len(p.Data.ASNs) == 0 {
		return nil, errors.New("ripestat: address is not announced by any AS")
	}
	x := p.Data.ASNs[0]
	return &ASNInfo{IP: ip, ASN: x.ASN, Prefix: p.Data.Resource, Org: strings.TrimSpace(x.Holder)}, nil
}
