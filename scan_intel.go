package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// intelData is everything the optional enrichment step learned during one scan.
type intelData struct {
	active   []string // per-IP sources that are enabled
	ips      []string // public, non-wildcard addresses of this entity
	hostsBy  map[string][]string
	res      *IPResult
	skipped  int
	domain   *DomainInfo // fresh or cached registration data (nil = unknown)
	domainOK bool        // the registration data is current
	enabled  bool
}

// reliableFor says whether a finding of this kind can be auto-resolved: only when this
// scan actually observed the thing it is about (an outage must not "fix" a finding).
func (d *intelData) reliableFor(kind, key string, dnsClean bool) bool {
	if d == nil || !d.enabled {
		return false
	}
	if kind == "domain-expiry" {
		return d.domainOK
	}
	if len(d.active) == 0 {
		return false
	}
	ip := findingIP(key)
	known := false
	for _, a := range d.ips {
		if a == ip {
			known = true
		}
	}
	if !known {
		return dnsClean // no host points at this address any more
	}
	for _, src := range d.active {
		if !d.res.OK[ip+"|"+src] {
			return false
		}
	}
	return true
}

// findingIP extracts the address from keys like "svc:<ip>:<port>", "vuln:<ip>", "flag:<ip>", "eol:<ip>".
func findingIP(key string) string {
	i := strings.Index(key, ":")
	if i < 0 {
		return ""
	}
	prefix, rest := key[:i], key[i+1:]
	if prefix == "svc" {
		if j := strings.LastIndex(rest, ":"); j >= 0 {
			return rest[:j]
		}
	}
	return rest
}

// gatherIntel collects exposure intelligence and registration data for the scan's addresses and domain, using the cache and honouring per-source caps.
func (s *Scanner) gatherIntel(ctx context.Context, t *Target, hosts []string, results map[string]*HostResult, wildcard map[string]struct{}, ips []string) *intelData {
	in := s.cfg.Intel
	d := &intelData{hostsBy: map[string][]string{}}
	d.active = s.enr.IPSources()
	d.enabled = len(d.active) > 0 || in.RDAP
	if !d.enabled {
		return d
	}
	for _, h := range hosts {
		hr := results[h]
		if hr == nil {
			continue
		}
		for _, rt := range []string{"A", "AAAA"} {
			for _, ip := range hr.Records[rt] {
				if _, w := wildcard[ip]; !w && publicIP(ip) {
					d.hostsBy[ip] = append(d.hostsBy[ip], h)
				}
			}
		}
	}
	for _, ip := range ips {
		if publicIP(ip) {
			d.ips = append(d.ips, ip)
		}
	}
	sort.Strings(d.ips)

	if len(d.active) > 0 && len(d.ips) > 0 {
		cached, err := s.store.LoadIntel(d.ips)
		if s.force {
			cached = nil
		}
		if err != nil {
			s.log.Warn("could not read cached intelligence", "err", err)
		}
		d.res = s.enr.LookupIPs(ctx, d.ips, cached)
		d.skipped = d.res.Skipped
		if d.skipped > 0 {
			s.log.Warn("IP lookups capped for this scan; the rest will be covered on later scans", "skipped", d.skipped, "cap", in.MaxIPs)
		}
	} else {
		d.res = &IPResult{Intel: map[string]map[string]*IPIntel{}, OK: map[string]bool{}}
	}

	if in.RDAP {
		cached, _ := s.store.GetDomainInfo(t.Domain)
		if cached != nil && !s.force {
			if ft, err := time.Parse(time.RFC3339, cached.Fetched); err == nil && time.Since(ft) < in.CacheTTL {
				d.domain, d.domainOK = cached, true
			}
		}
		if !d.domainOK {
			if fresh, err := s.enr.RDAPDomain(ctx, t.Domain); err == nil {
				d.domain, d.domainOK = fresh, true
			} else {
				if errors.Is(err, errNoData) {
					s.log.Info("no RDAP registration data for this name", "domain", t.Domain)
				} else {
					s.log.Warn("RDAP lookup failed", "domain", t.Domain, "err", err)
				}
				if cached != nil {
					d.domain = cached // show stale data, but do not trust it to resolve findings
				}
			}
		}
	}
	return d
}

var highRiskPorts = map[int]bool{23: true, 445: true, 3389: true, 5900: true, 2375: true, 27017: true, 6379: true,
	9200: true, 11211: true, 1433: true, 3306: true, 5432: true, 1521: true, 5984: true, 2049: true}

// expiryRisk grades a domain's expiry date into a severity ("" when far enough away).
func expiryRisk(expires string, now time.Time) (sev string, days int, ok bool) {
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return "", 0, false
	}
	days = int(t.Sub(now).Hours() / 24)
	switch {
	case days <= 14:
		sev = "high"
	case days <= 30:
		sev = "medium"
	case days <= 60:
		sev = "low"
	default:
		return "", days, true
	}
	return sev, days, true
}

// emitFn records a change event; inventory events are silent during the baseline scan.
type emitFn func(kind, sev, host, detail string, inventory bool)

// raiseFn records or refreshes a finding.
type raiseFn func(key, kind, sev, host, detail, source string)

// applyIntel stores fresh intelligence, emits change events for new services and
// raises findings. It runs inside the scan transaction.
func (s *Scanner) applyIntel(tx *Tx, t *Target, d *intelData, asns map[string]*ASNInfo, now string,
	emit emitFn, raise raiseFn, seen map[string]bool) error {
	if d == nil || !d.enabled {
		return nil
	}
	for _, ip := range d.ips {
		bySrc := d.res.Intel[ip]
		var tags, vulns, cpes, oses []string
		ports := map[int][]string{} // port -> source labels
		prods := map[int]string{}   // port -> product
		vsrc := map[string]bool{}
		for _, src := range sortedKeys(bySrc) {
			in := bySrc[src]
			label := sourceLabel(src)
			if in.Fresh {
				if err := tx.PutIntel(in); err != nil {
					return err
				}
				for _, sv := range in.Services {
					isNew, err := tx.UpsertService(ip, sv, src, now)
					if err != nil {
						return err
					}
					if isNew {
						s.stats.Services++
						host := ip
						if hs := d.hostsBy[ip]; len(hs) > 0 {
							host = hs[0]
						}
						name := sv.Product
						if name == "" {
							if n, ok := isRiskyPort(sv.Port); ok {
								name = n
							}
						}
						emit("service", "info", host, fmt.Sprintf("%s/%d open on %s%s (%s)", sv.Transport, sv.Port, ip, paren(name), label), true)
					}
				}
				closed, err := tx.PruneServices(ip, src, in.Services)
				if err != nil {
					return err
				}
				for _, sv := range closed {
					host := ip
					if hs := d.hostsBy[ip]; len(hs) > 0 {
						host = hs[0]
					}
					emit("service-removed", "info", host, fmt.Sprintf("%s/%d is no longer reported open on %s (%s)", sv.Transport, sv.Port, ip, label), true)
				}
			}
			tags = append(tags, in.Tags...)
			for _, c := range in.CPEs {
				if n := cpeName(c); n != "" {
					cpes = append(cpes, n)
				}
			}
			if in.OS != "" {
				oses = append(oses, in.OS)
			}
			for _, sv := range in.Services {
				ports[sv.Port] = append(ports[sv.Port], label)
				if sv.Product != "" {
					prods[sv.Port] = sv.Product
				}
			}
			if len(in.Vulns) > 0 {
				vulns = append(vulns, in.Vulns...)
				vsrc[label] = true
			}
		}
		vulns = dedupe(vulns)
		sort.Strings(vulns)

		// Third-party or CDN edge addresses are not this entity's responsibility.
		if hasTag(tags, "cdn") {
			continue
		}
		// An address outside the expected ownership is still reported: a name under this
		// domain points there, which is exactly where forgotten or hijacked assets show up.
		// The text says so, so the reader can tell a vendor's server from shadow IT.
		foreign := ""
		if info := asns[ip]; info != nil && t.hasOwnershipRules() && !t.owns(info) {
			foreign = ", on a network outside the expected ownership"
		}
		host := ip
		if hs := d.hostsBy[ip]; len(hs) > 0 {
			sort.Strings(hs)
			host = hs[0]
		}
		where := fmt.Sprintf("%s (%s%s)", host, ip, foreign)
		if host == ip {
			where = ip + foreign
		}

		for _, p := range sortedIntKeys(ports) {
			name, risky := isRiskyPort(p)
			if !risky {
				continue
			}
			sev := "medium"
			if highRiskPorts[p] {
				sev = "high"
			}
			prod := ""
			if prods[p] != "" {
				prod = ", running " + prods[p]
			}
			raise("svc:"+ip+":"+strconv.Itoa(p), "exposed-service", sev, host,
				fmt.Sprintf("%s (port %d) is reachable from the internet on %s%s", name, p, where, prod), strings.Join(dedupe(ports[p]), ", "))
		}
		if len(vulns) > 0 {
			sev := "medium"
			if len(vulns) >= 10 {
				sev = "high"
			}
			shown := vulns
			if len(shown) > 12 {
				shown = shown[:12]
			}
			more := ""
			if len(vulns) > len(shown) {
				more = fmt.Sprintf(" and %d more", len(vulns)-len(shown))
			}
			raise("vuln:"+ip, "known-vuln", sev, host,
				fmt.Sprintf("%d possible vulnerabilities on %s: %s%s", len(vulns), where, strings.Join(shown, ", "), more), strings.Join(sortedKeys(vsrc), ", "))
		}
		if hasTag(tags, "compromised", "malware", "doublepulsar") {
			raise("flag:"+ip, "ip-flagged", "high", host,
				fmt.Sprintf("%s is tagged %s by exposure-intelligence data", where, strings.Join(dedupe(filterTags(tags, "compromised", "malware", "doublepulsar")), ", ")), "Shodan tags")
		}
		if eol := eolTags(tags); len(eol) > 0 {
			var parts []string
			for _, e := range eol {
				switch e {
				case "eol-os":
					parts = append(parts, "the operating system is end-of-life")
				case "eol-product":
					parts = append(parts, "a network service/product is end-of-life")
				default:
					parts = append(parts, e)
				}
			}
			msg := fmt.Sprintf("Shodan flags %s: %s (tag %s). Shodan does not say exactly which component, so check the versions detected on this host: ", where, strings.Join(parts, " and "), strings.Join(eol, ", "))
			var found []string
			if o := dedupe(oses); len(o) > 0 {
				found = append(found, "OS: "+strings.Join(o, ", "))
			}
			if c := dedupe(cpes); len(c) > 0 {
				found = append(found, "software: "+strings.Join(c, ", "))
			}
			var svc []string
			for _, p := range sortedIntKeys(prods) {
				svc = append(svc, fmt.Sprintf("%d/tcp %s", p, prods[p]))
			}
			if len(svc) > 0 {
				found = append(found, "services: "+strings.Join(svc, ", "))
			}
			if len(found) == 0 {
				found = append(found, "no version details were returned by the source")
			}
			msg += strings.Join(found, "; ") + ". Compare each against its vendor support dates (e.g. endoflife.date)."
			raise("eol:"+ip, "eol-software", "medium", host, msg, "Shodan tags")
		}
	}

	if d.domain != nil {
		if err := tx.PutDomainInfo(t.Domain, d.domain); err != nil {
			return err
		}
		if d.domainOK {
			if sev, days, ok := expiryRisk(d.domain.Expires, time.Now().UTC()); ok && sev != "" {
				msg := fmt.Sprintf("%s expires in %d days (%s)", d.domain.Domain, days, d.domain.Expires[:10])
				if days < 0 {
					msg = fmt.Sprintf("%s expired %d days ago (%s)", d.domain.Domain, -days, d.domain.Expires[:10])
				}
				if d.domain.Registrar != "" {
					msg += ", registrar " + d.domain.Registrar
				}
				raise("expiry:"+d.domain.Domain, "domain-expiry", sev, d.domain.Domain, msg, "RDAP")
			}
		}
	}
	_ = seen
	return nil
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func sortedIntKeys[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// filterTags returns the tags from the wanted set.
func filterTags(tags []string, want ...string) []string {
	var out []string
	for _, t := range tags {
		if hasTag([]string{t}, want...) {
			out = append(out, strings.ToLower(t))
		}
	}
	return out
}

// eolTags returns the end-of-life markers ("eol-...") among the tags.
func eolTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(strings.ToLower(t), "eol-") {
			out = append(out, strings.ToLower(t))
		}
	}
	return dedupe(out)
}

// cpeName turns "cpe:/a:apache:http_server:2.2.15" or "cpe:2.3:a:apache:http_server:2.2.15:*..." into "apache http_server 2.2.15".
func cpeName(c string) string {
	c = strings.TrimPrefix(c, "cpe:2.3:")
	c = strings.TrimPrefix(c, "cpe:/")
	f := strings.Split(c, ":")
	if len(f) < 3 {
		return ""
	}
	out := []string{f[1], f[2]}
	if len(f) > 3 && f[3] != "" && f[3] != "*" && f[3] != "-" {
		out = append(out, f[3])
	}
	return strings.Join(out, " ")
}
