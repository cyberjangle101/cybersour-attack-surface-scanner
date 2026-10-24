package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver issues raw DNS queries (miekg/dns) straight at the configured public
// resolvers, behind a global QPS limiter. Raw queries (vs. net.Resolver) let us see
// real RCODEs and CNAME targets, which dangling-CNAME detection depends on.
type Resolver struct {
	addrs   []string
	timeout time.Duration
	retries int
	tokens  chan struct{}
	next    atomic.Uint64
	health  *HealthBoard
	via     string

	okAnswers  atomic.Int64 // answers received (any RCODE)
	failStreak atomic.Int64 // consecutive transport failures
}

// resolverDeadStreak is how many consecutive transport failures, with no answer ever received,
// prove that none of the configured resolvers can be reached from this machine.
const resolverDeadStreak = 24

// Unreachable reports that no resolver has answered at all during this scan.
func (r *Resolver) Unreachable() bool {
	return r.okAnswers.Load() == 0 && r.failStreak.Load() >= resolverDeadStreak
}

// HostResult is everything DNS says about one host, plus which lookups failed (so absence is not mistaken for non-existence).
type HostResult struct {
	Host     string
	NX       bool // name does not exist at all (NXDOMAIN on CNAME probe)
	Records  map[string][]string
	Failed   map[string]bool // record types whose lookup failed (timeouts/SERVFAIL)
	Dangling string          // CNAME target that returns NXDOMAIN
}

// NewResolver creates a rate-limited resolver that round-robins across the configured servers.
func NewResolver(ctx context.Context, cfg DNSCfg) *Resolver {
	r := &Resolver{addrs: cfg.Resolvers, timeout: cfg.Timeout, retries: cfg.Retries, tokens: make(chan struct{}, 1)}
	interval := time.Second / time.Duration(cfg.QPS)
	if interval <= 0 {
		interval = time.Microsecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				select {
				case r.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return r
}

func (r *Resolver) wait(ctx context.Context) error {
	select {
	case <-r.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// exchange sends one DNS query to one server, retrying over TCP when the UDP answer is truncated.
func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.timeout}
	in, _, err := c.ExchangeContext(ctx, m, addr)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, addr)
	}
	return in, err
}

// query returns the response for SUCCESS and NXDOMAIN; anything else is retried
// (rotating resolvers) and finally returned as an error.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	var last error
	for attempt := 0; attempt <= r.retries; attempt++ {
		if r.Unreachable() {
			return nil, errors.New("no DNS resolver is reachable")
		}
		if err := r.wait(ctx); err != nil {
			return nil, err
		}
		addr := r.addrs[(r.next.Add(1)-1)%uint64(len(r.addrs))] // round-robin across resolvers
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true
		t0 := time.Now()
		in, err := r.exchange(ctx, m, addr)
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r.failStreak.Add(1)
			r.health.Record("dns:"+addr, r.viaOr(), false, time.Since(t0), err)
			continue
		}
		r.okAnswers.Add(1)
		r.failStreak.Store(0)
		r.health.Record("dns:"+addr, r.viaOr(), true, time.Since(t0), nil) // any answer (even SERVFAIL) proves reachability
		switch in.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return in, nil
		default:
			last = fmt.Errorf("%s %s via %s: %s", name, dns.TypeToString[qtype], addr, dns.RcodeToString[in.Rcode])
		}
	}
	return nil, last
}

func cleanName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// collectRRs extracts the values of the wanted record type from a reply.
func collectRRs(in *dns.Msg, owner string, qtype uint16) []string {
	var out []string
	for _, rr := range in.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				out = append(out, v.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				out = append(out, v.AAAA.String())
			}
		case *dns.CNAME:
			if qtype == dns.TypeCNAME && cleanName(v.Hdr.Name) == owner {
				out = append(out, cleanName(v.Target))
			}
		case *dns.NS:
			if qtype == dns.TypeNS && cleanName(v.Hdr.Name) == owner {
				out = append(out, cleanName(v.Ns))
			}
		case *dns.MX:
			if qtype == dns.TypeMX && cleanName(v.Hdr.Name) == owner {
				out = append(out, fmt.Sprintf("%d %s", v.Preference, cleanName(v.Mx)))
			}
		case *dns.TXT:
			if qtype == dns.TypeTXT && cleanName(v.Hdr.Name) == owner {
				out = append(out, truncate(strings.Join(v.Txt, ""), 1024))
			}
		}
	}
	return out
}

func (h *HostResult) add(rtype string, vals []string) {
	h.Records[rtype] = append(h.Records[rtype], vals...)
}

func (h *HostResult) finalize() {
	for k, v := range h.Records {
		v = dedupe(v)
		sort.Strings(v)
		h.Records[k] = v
	}
}

// ResolveHost queries CNAME, A, AAAA, NS, MX, TXT for one host.
func (r *Resolver) ResolveHost(ctx context.Context, host string) *HostResult {
	hr := &HostResult{Host: host, Records: map[string][]string{}, Failed: map[string]bool{}}

	// CNAME first: NXDOMAIN here means the name itself does not exist, so skip the rest.
	in, err := r.query(ctx, host, dns.TypeCNAME)
	switch {
	case err != nil:
		hr.Failed["CNAME"] = true
	case in.Rcode == dns.RcodeNameError:
		hr.NX = true
		return hr
	default:
		hr.add("CNAME", collectRRs(in, host, dns.TypeCNAME))
	}

	for _, q := range []struct {
		name string
		t    uint16
	}{{"A", dns.TypeA}, {"AAAA", dns.TypeAAAA}, {"NS", dns.TypeNS}, {"MX", dns.TypeMX}, {"TXT", dns.TypeTXT}} {
		if ctx.Err() != nil {
			break
		}
		in, err := r.query(ctx, host, q.t)
		if err != nil {
			hr.Failed[q.name] = true
			continue
		}
		hr.add(q.name, collectRRs(in, host, q.t))
	}

	// Dangling CNAME: the alias exists but its target is NXDOMAIN (takeover candidate).
	if cn := hr.Records["CNAME"]; len(cn) > 0 && ctx.Err() == nil {
		in, err := r.query(ctx, cn[0], dns.TypeA)
		switch {
		case err != nil:
			hr.Failed["CNAME-TARGET"] = true // unknown: must not auto-resolve findings
		case in.Rcode == dns.RcodeNameError:
			hr.Dangling = cn[0]
		}
	}
	hr.finalize()
	return hr
}

// TXT looks up TXT records for an arbitrary name. nx is true on NXDOMAIN.
func (r *Resolver) TXT(ctx context.Context, name string) (txts []string, nx bool, err error) {
	in, err := r.query(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, false, err
	}
	if in.Rcode == dns.RcodeNameError {
		return nil, true, nil
	}
	return collectRRs(in, cleanName(name), dns.TypeTXT), false, nil
}

// WildcardIPs probes random labels under root; any IPs returned reveal wildcard DNS.
func (r *Resolver) WildcardIPs(ctx context.Context, root string) map[string]struct{} {
	ips := map[string]struct{}{}
	for i := 0; i < 2; i++ {
		name := "wc-" + randHex(6) + "-easm." + root
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			in, err := r.query(ctx, name, t)
			if err != nil || in.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, ip := range collectRRs(in, name, t) {
				ips[ip] = struct{}{}
			}
		}
	}
	return ips
}

func (r *Resolver) viaOr() string {
	if r.via == "" {
		return "scan"
	}
	return r.via
}

// PTR returns the reverse-DNS names of an address (empty when none is published).
func (r *Resolver) PTR(ctx context.Context, ip string) ([]string, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}
	in, err := r.query(ctx, arpa, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range in.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			out = append(out, strings.TrimSuffix(p.Ptr, "."))
		}
	}
	return out, nil
}
