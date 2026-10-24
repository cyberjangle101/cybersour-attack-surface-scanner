package main

import (
	"fmt"
	"sort"
	"strings"
)

// Asset is one row of the unified inventory: anything the agent has discovered
// about an entity, whatever its kind.
type Asset struct {
	Type      string // domain | ip | service | certificate | dns | vulnerability | registration
	Value     string
	Key       string // stable id used in the detail-page link (defaults to Value)
	Root      string
	Details   string
	Sources   string
	FirstSeen string
	LastSeen  string
}

var assetTypes = []struct{ ID, Label string }{
	{"domain", "Domains & subdomains"}, {"ip", "IP addresses"}, {"service", "Open services"}, {"web", "Web services"},
	{"certificate", "Certificates"}, {"dns", "DNS records"}, {"vulnerability", "Vulnerabilities"}, {"registration", "Registration"},
}

func validAssetType(t string) bool {
	for _, a := range assetTypes {
		if a.ID == t {
			return true
		}
	}
	return false
}

// ListAssets returns the inventory for one entity ("" = all) and type ("" = all types),
// optionally filtered by a case-insensitive text match, plus per-type counts.
func (s *Store) ListAssets(root, typ, q string) ([]Asset, map[string]int, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	counts := map[string]int{}
	var all []Asset
	add := func(list []Asset, err error) error {
		if err != nil {
			return err
		}
		for _, a := range list {
			if q != "" && !strings.Contains(strings.ToLower(a.Value+" "+a.Details+" "+a.Root+" "+a.Sources), q) {
				continue
			}
			counts[a.Type]++
			if typ == "" || typ == a.Type {
				all = append(all, a)
			}
		}
		return nil
	}
	// Shared lookups first; each query finishes before the next starts (single connection).
	asn, err := s.assetASNs()
	if err != nil {
		return nil, nil, err
	}
	ports, err := s.assetPorts()
	if err != nil {
		return nil, nil, err
	}
	intel, err := s.assetIntel()
	if err != nil {
		return nil, nil, err
	}
	for _, f := range []func() ([]Asset, error){
		func() ([]Asset, error) { return s.assetDomains(root) },
		func() ([]Asset, error) { return s.assetIPs(root, asn, ports, intel) },
		func() ([]Asset, error) { return s.assetServices(root) },
		func() ([]Asset, error) { return s.assetWeb(root) },
		func() ([]Asset, error) { return s.assetCerts(root) },
		func() ([]Asset, error) { return s.assetDNS(root) },
		func() ([]Asset, error) { return s.assetVulns(root, intel) },
		func() ([]Asset, error) { return s.assetRegistration(root) },
	} {
		if err := add(f()); err != nil {
			return nil, nil, err
		}
	}
	for i := range all {
		if all[i].Key == "" {
			all[i].Key = all[i].Value
		}
	}
	order := map[string]int{}
	for i, a := range assetTypes {
		order[a.ID] = i
	}
	sort.SliceStable(all, func(i, j int) bool {
		if order[all[i].Type] != order[all[j].Type] {
			return order[all[i].Type] < order[all[j].Type]
		}
		if all[i].Root != all[j].Root {
			return all[i].Root < all[j].Root
		}
		return all[i].Value < all[j].Value
	})
	return all, counts, nil
}

// assetASNs loads the cached owner of every address.
func (s *Store) assetASNs() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT ip, asn, org, country FROM asn_cache`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var ip, org, cc string
		var asn int
		if err := rows.Scan(&ip, &asn, &org, &cc); err != nil {
			return nil, err
		}
		out[ip] = fmt.Sprintf("AS%d %s, %s", asn, org, cc)
	}
	return out, rows.Err()
}

// assetPorts loads the open ports of every address.
func (s *Store) assetPorts() (map[string][]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT ip, port, transport FROM services ORDER BY ip, port`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var ip, tr string
		var port int
		if err := rows.Scan(&ip, &port, &tr); err != nil {
			return nil, err
		}
		out[ip] = append(out[ip], fmt.Sprintf("%d/%s", port, tr))
	}
	return out, rows.Err()
}

type ipIntelSummary struct {
	Tags  []string
	Vulns []string
	Hosts []string
	Srcs  []string
}

// assetIntel loads the per-source intelligence of every address.
func (s *Store) assetIntel() (map[string]*ipIntelSummary, error) {
	rows, err := s.db.Query(`SELECT ip, source, tags, vulns, hostnames FROM intel`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*ipIntelSummary{}
	for rows.Next() {
		var ip, src, tg, vu, hn string
		if err := rows.Scan(&ip, &src, &tg, &vu, &hn); err != nil {
			return nil, err
		}
		x := out[ip]
		if x == nil {
			x = &ipIntelSummary{}
			out[ip] = x
		}
		x.Tags = dedupe(append(x.Tags, csvSplit(tg)...))
		x.Vulns = dedupe(append(x.Vulns, csvSplit(vu)...))
		x.Hosts = dedupe(append(x.Hosts, csvSplit(hn)...))
		x.Srcs = append(x.Srcs, sourceLabel(src))
	}
	return out, rows.Err()
}

func rootClause(col, root string) (string, []any) {
	if root == "" {
		return "1=1", nil
	}
	return col + "=?", []any{root}
}

// assetDomains lists hosts as assets.
func (s *Store) assetDomains(root string) ([]Asset, error) {
	w, args := rootClause("s.root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT s.root, s.host, s.sources, s.first_seen, s.last_seen,
		COALESCE((SELECT group_concat(value, ', ') FROM records r WHERE r.host=s.host AND r.rtype IN ('A','AAAA')),''),
		COALESCE((SELECT group_concat(value, ', ') FROM records r WHERE r.host=s.host AND r.rtype='CNAME'),'')
		FROM subdomains s WHERE `+w, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var addrs, cname string
		if err := rows.Scan(&a.Root, &a.Value, &a.Sources, &a.FirstSeen, &a.LastSeen, &addrs, &cname); err != nil {
			return nil, err
		}
		a.Type = "domain"
		var d []string
		if cname != "" {
			d = append(d, "CNAME → "+cname)
		}
		if addrs != "" {
			d = append(d, "resolves to "+addrs)
		} else if cname == "" {
			d = append(d, "does not resolve")
		}
		a.Details = strings.Join(d, "; ")
		out = append(out, a)
	}
	return out, rows.Err()
}

// assetIPs lists addresses as assets, with owner, host names, ports and CVE counts.
func (s *Store) assetIPs(root string, asn map[string]string, ports map[string][]string, intel map[string]*ipIntelSummary) ([]Asset, error) {
	w, args := rootClause("root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT value, MIN(root), group_concat(DISTINCT host), MIN(first_seen), MAX(last_seen)
		FROM records WHERE rtype IN ('A','AAAA') AND `+w+` GROUP BY value`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var hosts string
		if err := rows.Scan(&a.Value, &a.Root, &hosts, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		a.Type = "ip"
		hs := strings.Split(hosts, ",")
		sort.Strings(hs)
		shown := hs
		if len(shown) > 4 {
			shown = shown[:4]
		}
		var d []string
		if n := asn[a.Value]; n != "" {
			d = append(d, n)
		}
		d = append(d, fmt.Sprintf("%d host(s): %s%s", len(hs), strings.Join(shown, ", "), map[bool]string{true: ", …", false: ""}[len(hs) > len(shown)]))
		if p := ports[a.Value]; len(p) > 0 {
			d = append(d, "open ports "+strings.Join(p, ", "))
		}
		if x := intel[a.Value]; x != nil {
			if len(x.Vulns) > 0 {
				d = append(d, fmt.Sprintf("%d possible CVEs", len(x.Vulns)))
			}
			if len(x.Tags) > 0 {
				d = append(d, "tags: "+strings.Join(x.Tags, ", "))
			}
			a.Sources = strings.Join(dedupe(x.Srcs), ", ")
		}
		a.Details = strings.Join(d, "; ")
		out = append(out, a)
	}
	return out, rows.Err()
}

// assetServices lists open ports as assets.
func (s *Store) assetServices(root string) ([]Asset, error) {
	// A service belongs to an entity when one of the entity's hosts resolves to its IP.
	q := `SELECT v.ip, v.port, v.transport, group_concat(DISTINCT v.source), COALESCE(group_concat(DISTINCT CASE WHEN v.product<>'' THEN v.product END),''), MIN(v.first_seen), MAX(v.last_seen),
		COALESCE((SELECT MIN(r.root) FROM records r WHERE r.value=v.ip AND r.rtype IN ('A','AAAA')),'')
		FROM services v GROUP BY v.ip, v.port, v.transport`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var ip, tr, prod, srcs string
		var port int
		if err := rows.Scan(&ip, &port, &tr, &srcs, &prod, &a.FirstSeen, &a.LastSeen, &a.Root); err != nil {
			return nil, err
		}
		if root != "" && a.Root != root {
			continue
		}
		a.Type, a.Value = "service", fmt.Sprintf("%s:%d/%s", ip, port, tr)
		var labels []string
		for _, x := range strings.Split(srcs, ",") {
			labels = append(labels, sourceLabel(x))
		}
		a.Sources = strings.Join(labels, ", ")
		name := strings.ReplaceAll(prod, ",", " / ")
		if n, ok := isRiskyPort(port); ok {
			if name == "" {
				name = n
			}
			name += " (sensitive service)"
		}
		a.Details = name
		out = append(out, a)
	}
	return out, rows.Err()
}

// assetCerts lists certificates as assets.
func (s *Store) assetCerts(root string) ([]Asset, error) {
	w, args := rootClause("root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT root, common_name, names, issuer, not_before, not_after, first_seen, key FROM certs WHERE `+w, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var cn, names, issuer, nb, na string
		if err := rows.Scan(&a.Root, &cn, &names, &issuer, &nb, &na, &a.FirstSeen, &a.Key); err != nil {
			return nil, err
		}
		a.Type, a.Sources, a.LastSeen = "certificate", "crt.sh", a.FirstSeen
		a.Value = cn
		if a.Value == "" {
			a.Value = strings.SplitN(names, ",", 2)[0]
		}
		a.Details = fmt.Sprintf("issuer %s; valid %s → %s; names: %s", truncate(issuer, 60), shortDate(nb), shortDate(na), truncate(names, 120))
		out = append(out, a)
	}
	return out, rows.Err()
}

func shortDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// assetDNS lists non-address DNS records as assets.
func (s *Store) assetDNS(root string) ([]Asset, error) {
	w, args := rootClause("root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT root, host, rtype, value, first_seen, last_seen FROM records WHERE rtype NOT IN ('A','AAAA') AND `+w, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var host, rt, val string
		if err := rows.Scan(&a.Root, &host, &rt, &val, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		a.Type, a.Sources = "dns", "DNS resolvers"
		a.Value = rt + " " + host
		a.Key = rt + "|" + host
		a.Details = truncate(val, 300)
		out = append(out, a)
	}
	return out, rows.Err()
}

// assetVulns lists possible CVEs per domain.
func (s *Store) assetVulns(root string, intel map[string]*ipIntelSummary) ([]Asset, error) {
	// Only IPs that belong to the selected entity.
	w, args := rootClause("root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT DISTINCT value, root FROM records WHERE rtype IN ('A','AAAA') AND `+w, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	byCVE := map[string]*Asset{}
	for rows.Next() {
		var ip, r string
		if err := rows.Scan(&ip, &r); err != nil {
			return nil, err
		}
		x := intel[ip]
		if x == nil {
			continue
		}
		for _, cve := range x.Vulns {
			a := byCVE[r+"|"+cve]
			if a == nil {
				a = &Asset{Type: "vulnerability", Value: cve, Root: r, Sources: strings.Join(dedupe(x.Srcs), ", ")}
				byCVE[r+"|"+cve] = a
			}
			a.Details += map[bool]string{true: ", ", false: ""}[a.Details != ""] + ip
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []Asset
	for _, a := range byCVE {
		a.Details = "possible on " + a.Details + " (inferred from service banners)"
		out = append(out, *a)
	}
	return out, nil
}

// assetRegistration lists domain registration records as assets.
func (s *Store) assetRegistration(root string) ([]Asset, error) {
	w, args := rootClause("root", root)
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT root, domain, registrar, created, expires, nameservers, fetched FROM domain_info WHERE `+w, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Asset
	for rows.Next() {
		var a Asset
		var reg, created, expires, ns string
		if err := rows.Scan(&a.Root, &a.Value, &reg, &created, &expires, &ns, &a.LastSeen); err != nil {
			return nil, err
		}
		a.Type, a.Sources, a.FirstSeen = "registration", "RDAP", created
		a.Details = fmt.Sprintf("registrar %s; registered %s; expires %s; nameservers %s", orDash(reg), shortDate(created), shortDate(expires), orDash(strings.ReplaceAll(ns, ",", ", ")))
		out = append(out, a)
	}
	return out, rows.Err()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// assetWeb lists web services found by the active checks.
func (s *Store) assetWeb(root string) ([]Asset, error) {
	list, err := s.ListWeb(root)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for _, w := range list {
		d := fmt.Sprintf("HTTP %d", w.Status)
		for _, x := range []string{w.Title, w.Server, w.DefaultPage} {
			if x != "" {
				d += "; " + x
			}
		}
		if w.TLSProblem != "" {
			d += "; certificate problem: " + w.TLSProblem
		}
		out = append(out, Asset{Type: "web", Value: w.URL(), Key: fmt.Sprintf("%s:%d", w.Host, w.Port), Root: w.Root, Details: d,
			Sources: "Active check", FirstSeen: w.FirstSeen, LastSeen: w.LastSeen})
	}
	return out, nil
}
