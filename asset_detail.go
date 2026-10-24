package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ReverseDNS returns the PTR names of an address, using a 24h cache.
func (e *Engine) ReverseDNS(ctx context.Context, ip string) (string, error) {
	if ptr, ok := e.store.GetRDNS(ip, 24*time.Hour); ok {
		return ptr, nil
	}
	cfg, _, err := e.config()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	r := NewResolver(cctx, cfg.DNS)
	r.health, r.via = e.health, "check"
	names, err := r.PTR(cctx, ip)
	if err != nil {
		return "", err
	}
	ptr := strings.Join(names, ", ")
	e.store.PutRDNS(ip, ptr)
	return ptr, nil
}

// ---------------------------------------------------------------- view model

type dCell struct {
	T    string
	Href string // a plain string, so html/template still checks the URL scheme
	Ext  bool   // external link
	Mono bool
	Cls  string // badge class
}

type dTable struct {
	Title string
	Note  string
	Cols  []string
	Rows  [][]dCell
}

type dFact struct {
	K string
	V dCell
}

// AssetDetail is the view model of one asset page: facts, tables of related data, and related findings.
type AssetDetail struct {
	Type, TypeLabel, Title, Intro string
	Facts                         []dFact
	Tables                        []dTable
	Findings                      []Finding
	Shot                          string // URL of a stored screenshot, if any
}

func assetLink(typ, id string) string {
	v := url.Values{"type": {typ}, "id": {id}}
	return "/assets/view?" + v.Encode()
}

// plain makes a table cell that is only text.
func plain(s string) dCell   { return dCell{T: s} }
func mono(s string) dCell    { return dCell{T: s, Mono: true} }
func link(s, h string) dCell { return dCell{T: s, Href: h} }
func orNA(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// dayCount returns the whole days from now until a YYYY-MM-DD date (negative if past).
func dayCount(date string) (int, bool) {
	if len(date) < 10 {
		return 0, false
	}
	t, err := time.Parse("2006-01-02", date[:10])
	if err != nil {
		return 0, false
	}
	return int(time.Until(t).Hours() / 24), true
}

// expiryText formats an expiry date together with how long remains or how long ago it passed.
func expiryText(date string) string {
	if date == "" {
		return "—"
	}
	d, ok := dayCount(date)
	if !ok {
		return date
	}
	switch {
	case d < 0:
		return fmt.Sprintf("%s (expired %d days ago)", date[:10], -d)
	case d == 0:
		return date[:10] + " (expires today)"
	default:
		return fmt.Sprintf("%s (in %d days)", date[:10], d)
	}
}

var errNotFound = errors.New("asset not found")

// findingsAbout returns findings that mention the term (host name, IP, CVE…).
func (s *Server) findingsAbout(terms ...string) []Finding {
	all, err := s.store.ListFindings("", "")
	if err != nil {
		return nil
	}
	var out []Finding
	for _, f := range all {
		for _, t := range terms {
			if t != "" && (f.Host == t || strings.Contains(f.Key, ":"+t) || strings.Contains(f.Detail, t)) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// buildAssetDetail dispatches to the builder for the asset type and returns errNotFound for unknown assets.
func (s *Server) buildAssetDetail(ctx context.Context, typ, id string) (*AssetDetail, error) {
	d := &AssetDetail{Type: typ, Title: id}
	for _, a := range assetTypes {
		if a.ID == typ {
			d.TypeLabel = a.Label
		}
	}
	switch typ {
	case "domain":
		return d, s.detailHost(ctx, d, id)
	case "ip":
		return d, s.detailIP(ctx, d, id)
	case "service":
		return d, s.detailService(ctx, d, id)
	case "web":
		return d, s.detailWeb(d, id)
	case "certificate":
		return d, s.detailCert(d, id)
	case "dns":
		return d, s.detailDNS(d, id)
	case "vulnerability":
		return d, s.detailVuln(d, id)
	case "registration":
		return d, s.detailReg(d, id)
	}
	return nil, errNotFound
}

// rdnsText returns the reverse-DNS result for display, turning errors and empty answers into readable text.
func (s *Server) rdnsText(ctx context.Context, ip string) string {
	ptr, err := s.eng.ReverseDNS(ctx, ip)
	switch {
	case err != nil:
		return "lookup failed: " + err.Error()
	case ptr == "":
		return "none published"
	}
	return ptr
}

// detailHost builds the page for a host name: its DNS records, addresses with owners and reverse DNS, covering certificates and findings.
func (s *Server) detailHost(ctx context.Context, d *AssetDetail, host string) error {
	rows, err := s.store.HostRows(host)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	d.Intro = "A host name discovered for a monitored domain, with what DNS currently says about it."
	for _, r := range rows {
		d.Facts = append(d.Facts,
			dFact{"Belongs to", plain(r.Root)},
			dFact{"Discovered via", plain(orNA(r.Sources))},
			dFact{"First seen", plain(fmtTS(r.First))}, dFact{"Last seen", plain(fmtTS(r.Last))})
	}
	// "Belongs to" link: resolved below once target ids are known
	if ts, err := s.store.ListTargets(); err == nil {
		for i := range d.Facts {
			if d.Facts[i].K == "Belongs to" {
				for _, t := range ts {
					if t.Domain == d.Facts[i].V.T {
						d.Facts[i].V.Href = fmt.Sprintf("/targets/%d", t.ID)
					}
				}
			}
		}
	}
	recs, err := s.store.RecordsOfHost(host)
	if err != nil {
		return err
	}
	t := dTable{Title: "DNS records", Cols: []string{"Type", "Value", "First seen", "Last seen"}}
	var ips []string
	for _, r := range recs {
		c := mono(r.Value)
		if r.Type == "A" || r.Type == "AAAA" {
			c = link(r.Value, assetLink("ip", r.Value))
			c.Mono = true
			ips = append(ips, r.Value)
		}
		t.Rows = append(t.Rows, []dCell{plain(r.Type), c, plain(fmtTS(r.First)), plain(fmtTS(r.Last))})
	}
	if len(recs) == 0 {
		t.Note = "No DNS records are stored: the name did not resolve at the last scan."
	}
	d.Tables = append(d.Tables, t)

	if len(ips) > 0 {
		at := dTable{Title: "Addresses, owners and reverse DNS", Note: "Reverse DNS (PTR) is looked up live and cached for 24 hours.", Cols: []string{"Address", "Owner (ASN)", "Reverse DNS"}}
		for i, ip := range dedupe(ips) {
			if i >= 8 {
				at.Note += " Only the first 8 addresses are shown."
				break
			}
			owner := "—"
			if a, _ := s.store.ASNOfIP(ip); a != nil {
				owner = (&ASNInfo{ASN: a.ASN, Org: a.Org, Country: a.Country}).String()
			}
			at.Rows = append(at.Rows, []dCell{link(ip, assetLink("ip", ip)), plain(owner), mono(s.rdnsText(ctx, ip))})
		}
		d.Tables = append(d.Tables, at)
	}

	certs, err := s.store.CertsCovering(host)
	if err != nil {
		return err
	}
	if len(certs) > 0 {
		ct := dTable{Title: "Certificates covering this name", Note: "From Certificate Transparency logs (crt.sh).", Cols: []string{"Subject", "Issuer", "Valid from", "Expires"}}
		for i, c := range certs {
			if i >= 25 {
				break
			}
			cn := c.CN
			if cn == "" {
				cn = host
			}
			ct.Rows = append(ct.Rows, []dCell{link(cn, assetLink("certificate", c.Key)), plain(truncate(c.Issuer, 60)), plain(shortDate(c.NotBefore)), plain(expiryText(c.NotAfter))})
		}
		d.Tables = append(d.Tables, ct)
	}
	if di, _, _ := s.store.DomainInfoByName(host); di != nil {
		d.Facts = append(d.Facts, dFact{"Registration", link("Expires "+expiryText(di.Expires), assetLink("registration", host))})
	}
	d.Findings = s.findingsAbout(host)
	return nil
}

// detailIP builds the page for an IP address: owner, reverse DNS, host names pointing at it, open services, intelligence by source and possible CVEs.
func (s *Server) detailIP(ctx context.Context, d *AssetDetail, ip string) error {
	p := net.ParseIP(ip)
	if p == nil {
		return errNotFound
	}
	d.Intro = "An IP address that monitored host names resolve to."
	ver := "IPv4"
	if p.To4() == nil {
		ver = "IPv6"
	}
	d.Facts = append(d.Facts, dFact{"Address", mono(ip)}, dFact{"Type", plain(ver + map[bool]string{true: ", public", false: ", non-public (private/reserved)"}[isPublicIP(p)])})
	if a, _ := s.store.ASNOfIP(ip); a != nil {
		d.Facts = append(d.Facts,
			dFact{"Owner", plain((&ASNInfo{ASN: a.ASN, Org: a.Org, Country: a.Country}).String())},
			dFact{"Announced prefix", mono(orNA(a.Prefix))})
	}
	d.Facts = append(d.Facts, dFact{"Reverse DNS (PTR)", mono(s.rdnsText(ctx, ip))})

	pointers, err := s.store.RecordsPointingTo(ip)
	if err != nil {
		return err
	}
	if len(pointers) == 0 {
		return errNotFound
	}
	first, last := pointers[0].First, pointers[0].Last
	ht := dTable{Title: "Host names that resolve here", Cols: []string{"Host", "Record", "Entity", "First seen", "Last seen"}}
	for _, r := range pointers {
		if r.First < first {
			first = r.First
		}
		if r.Last > last {
			last = r.Last
		}
		ht.Rows = append(ht.Rows, []dCell{link(r.Host, assetLink("domain", r.Host)), plain(r.Type), plain(r.Root), plain(fmtTS(r.First)), plain(fmtTS(r.Last))})
	}
	d.Facts = append(d.Facts, dFact{"First seen", plain(fmtTS(first))}, dFact{"Last seen", plain(fmtTS(last))})
	d.Tables = append(d.Tables, ht)

	svcs, err := s.store.ServicesOfIP(ip)
	if err != nil {
		return err
	}
	st := dTable{Title: "Open ports and services", Note: "Reported by exposure-intelligence sources, not by scanning from this agent.", Cols: []string{"Port", "Product", "Reported by", "First seen", "Last seen"}}
	for _, v := range svcs {
		port := fmt.Sprintf("%d/%s", v.Port, v.Transport)
		prod := v.Product
		if n, ok := isRiskyPort(v.Port); ok {
			prod = strings.TrimSpace(prod + " (" + n + ", sensitive)")
		}
		st.Rows = append(st.Rows, []dCell{link(port, assetLink("service", fmt.Sprintf("%s:%d/%s", ip, v.Port, v.Transport))), plain(orNA(prod)), plain(sourceLabel(v.Source)), plain(fmtTS(v.First)), plain(fmtTS(v.Last))})
	}
	if len(svcs) == 0 {
		st.Note = "No open services reported (enable Shodan InternetDB in Settings, or the address is not indexed)."
	}
	d.Tables = append(d.Tables, st)

	intel, err := s.store.IntelOfIP(ip)
	if err != nil {
		return err
	}
	if len(intel) > 0 {
		it := dTable{Title: "Intelligence by source", Cols: []string{"Source", "Operating system", "Software (CPE)", "Tags", "Known host names", "Checked"}}
		var cves []string
		for _, r := range intel {
			var sw []string
			for _, c := range csvSplit(r.CPEs) {
				if n := cpeName(c); n != "" {
					sw = append(sw, n)
				}
			}
			it.Rows = append(it.Rows, []dCell{plain(sourceLabel(r.Source)), plain(orNA(r.OS)), plain(orNA(strings.Join(sw, ", "))),
				plain(orNA(strings.ReplaceAll(r.Tags, ",", ", "))), plain(orNA(strings.ReplaceAll(r.Hostnames, ",", ", "))), plain(fmtTS(r.Fetched))})
			cves = append(cves, csvSplit(r.Vulns)...)
		}
		d.Tables = append(d.Tables, it)
		if cves = dedupe(cves); len(cves) > 0 {
			vt := dTable{Title: "Possible vulnerabilities", Note: "Inferred from service banners/versions, so they may be false positives (e.g. backported patches). Verify before acting.", Cols: []string{"CVE"}}
			for _, c := range cves {
				vt.Rows = append(vt.Rows, []dCell{link(c, assetLink("vulnerability", c))})
			}
			d.Tables = append(d.Tables, vt)
		}
	}
	d.Findings = s.findingsAbout(ip)
	return nil
}

// detailService builds the page for one open port (id format ip:port/transport).
func (s *Server) detailService(ctx context.Context, d *AssetDetail, id string) error {
	// id = ip:port/transport (the IP may be IPv6, so split from the right)
	slash := strings.LastIndex(id, "/")
	colon := strings.LastIndex(id, ":")
	if slash < 0 || colon < 0 || colon > slash {
		return errNotFound
	}
	ip, port, tr := id[:colon], id[colon+1:slash], id[slash+1:]
	svcs, err := s.store.ServicesOfIP(ip)
	if err != nil {
		return err
	}
	d.Intro = "A network service reported as reachable from the internet."
	d.Facts = append(d.Facts, dFact{"Address", link(ip, assetLink("ip", ip))}, dFact{"Port", plain(port + "/" + tr)})
	t := dTable{Title: "Reports", Cols: []string{"Reported by", "Product / banner", "First seen", "Last seen"}}
	found := false
	for _, v := range svcs {
		if fmt.Sprint(v.Port) != port || v.Transport != tr {
			continue
		}
		found = true
		t.Rows = append(t.Rows, []dCell{plain(sourceLabel(v.Source)), plain(orNA(v.Product)), plain(fmtTS(v.First)), plain(fmtTS(v.Last))})
		if n, ok := isRiskyPort(v.Port); ok && len(d.Facts) < 4 {
			d.Facts = append(d.Facts, dFact{"Service type", plain(n + " — commonly targeted when exposed to the internet")})
		}
	}
	if !found {
		return errNotFound
	}
	d.Facts = append(d.Facts, dFact{"Reverse DNS (PTR)", mono(s.rdnsText(ctx, ip))})
	d.Tables = append(d.Tables, t)
	if recs, _ := s.store.RecordsPointingTo(ip); len(recs) > 0 {
		ht := dTable{Title: "Host names on this address", Cols: []string{"Host"}}
		for _, r := range recs {
			ht.Rows = append(ht.Rows, []dCell{link(r.Host, assetLink("domain", r.Host))})
		}
		d.Tables = append(d.Tables, ht)
	}
	d.Findings = s.findingsAbout(ip + ":" + port)
	return nil
}

// detailCert builds the page for a certificate: issuer, validity, status and every name on it.
func (s *Server) detailCert(d *AssetDetail, key string) error {
	c, err := s.store.CertByKey(key)
	if err != nil {
		return err
	}
	if c == nil {
		return errNotFound
	}
	d.Title = orNA(c.CN)
	d.Intro = "A TLS certificate that was issued for a monitored domain (found in public Certificate Transparency logs)."
	status := "valid"
	if n, ok := dayCount(c.NotAfter); ok {
		switch {
		case n < 0:
			status = "expired"
		case n < 30:
			status = "expiring soon"
		}
	}
	d.Facts = append(d.Facts,
		dFact{"Common name", mono(orNA(c.CN))},
		dFact{"Issuer", plain(orNA(c.Issuer))},
		dFact{"Valid from", plain(shortDate(c.NotBefore))},
		dFact{"Expires", plain(expiryText(c.NotAfter))},
		dFact{"Status", dCell{T: status, Cls: map[string]string{"valid": "good", "expired": "bad", "expiring soon": "warn"}[status]}},
		dFact{"First seen by agent", plain(fmtTS(c.First))},
		dFact{"Belongs to", plain(c.Root)})
	if c.CrtShID != 0 {
		d.Facts = append(d.Facts, dFact{"Public record", dCell{T: fmt.Sprintf("crt.sh entry %d", c.CrtShID), Href: fmt.Sprintf("https://crt.sh/?id=%d", c.CrtShID), Ext: true}})
	}
	nt := dTable{Title: "Names on the certificate", Note: "Wildcard names (*.) cover every sub-name one level below.", Cols: []string{"Name"}}
	hosts := map[string]bool{}
	if hr, _ := s.store.scanHostNames(c.Root); hr != nil {
		hosts = hr
	}
	for _, n := range strings.Split(c.Names, ",") {
		if n == "" {
			continue
		}
		cell := mono(n)
		if hosts[n] {
			cell = link(n, assetLink("domain", n))
			cell.Mono = true
		}
		nt.Rows = append(nt.Rows, []dCell{cell})
	}
	d.Tables = append(d.Tables, nt)
	return nil
}

// scanHostNames returns the set of host names known for a monitored domain.
func (s *Store) scanHostNames(root string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT host FROM subdomains WHERE root=?`, root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out[h] = true
	}
	return out, rows.Err()
}

// detailDNS builds the page for all records of one type on one host (id format TYPE|host).
func (s *Server) detailDNS(d *AssetDetail, id string) error {
	i := strings.Index(id, "|")
	if i < 0 {
		return errNotFound
	}
	rt, host := id[:i], id[i+1:]
	recs, err := s.store.RecordsOfType(host, rt)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return errNotFound
	}
	d.Title = rt + " " + host
	d.Intro = "DNS records of this type published for the host, as seen by the resolvers."
	d.Facts = append(d.Facts, dFact{"Host", link(host, assetLink("domain", host))}, dFact{"Record type", plain(rt)}, dFact{"Entity", plain(recs[0].Root)})
	t := dTable{Title: "Values", Cols: []string{"Value", "First seen", "Last seen"}}
	for _, r := range recs {
		t.Rows = append(t.Rows, []dCell{mono(r.Value), plain(fmtTS(r.First)), plain(fmtTS(r.Last))})
	}
	d.Tables = append(d.Tables, t)
	return nil
}

// detailVuln builds the page for a CVE and the addresses it was reported on.
func (s *Server) detailVuln(d *AssetDetail, cve string) error {
	ips, err := s.store.VulnIPs(cve)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errNotFound
	}
	d.Intro = "A vulnerability that exposure-intelligence data associates with a monitored address. It is inferred from the software version shown in service banners, so confirm it is really exploitable."
	d.Facts = append(d.Facts, dFact{"Identifier", mono(cve)},
		dFact{"Details", dCell{T: "NIST National Vulnerability Database", Href: "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(cve), Ext: true}})
	t := dTable{Title: "Affected addresses", Cols: []string{"Address", "Host names"}}
	for _, ip := range ips {
		var hs []string
		recs, _ := s.store.RecordsPointingTo(ip)
		for _, r := range recs {
			hs = append(hs, r.Host)
		}
		t.Rows = append(t.Rows, []dCell{link(ip, assetLink("ip", ip)), plain(orNA(strings.Join(dedupe(hs), ", ")))})
	}
	d.Tables = append(d.Tables, t)
	return nil
}

// detailReg builds the page for a domain's registration (RDAP) data.
func (s *Server) detailReg(d *AssetDetail, domain string) error {
	di, root, err := s.store.DomainInfoByName(domain)
	if err != nil {
		return err
	}
	if di == nil {
		return errNotFound
	}
	d.Intro = "Domain registration data from RDAP, the registries' public lookup service."
	d.Facts = append(d.Facts,
		dFact{"Domain", mono(di.Domain)}, dFact{"Entity", plain(root)},
		dFact{"Registrar", plain(orNA(di.Registrar))},
		dFact{"Registered", plain(orNA(shortDate(di.Created)))},
		dFact{"Expires", plain(expiryText(di.Expires))},
		dFact{"Last changed", plain(orNA(shortDate(di.Updated)))},
		dFact{"Status flags", plain(orNA(strings.Join(di.Status, ", ")))},
		dFact{"Checked", plain(fmtTS(di.Fetched))})
	nt := dTable{Title: "Name servers", Cols: []string{"Name server"}}
	for _, n := range di.Nameservers {
		nt.Rows = append(nt.Rows, []dCell{mono(n)})
	}
	if len(nt.Rows) > 0 {
		d.Tables = append(d.Tables, nt)
	}
	d.Findings = s.findingsAbout(domain)
	return nil
}

// ---------------------------------------------------------------- handler

// assetDetail is the HTTP handler for /assets/view?type=&id=.
func (s *Server) assetDetail(w http.ResponseWriter, r *http.Request, sess *Session) {
	typ, id := r.URL.Query().Get("type"), r.URL.Query().Get("id")
	if !validAssetType(typ) || id == "" || len(id) > 600 {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "That asset is not (or no longer) in the inventory.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := s.buildAssetDetail(ctx, typ, id)
	if errors.Is(err, errNotFound) {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "That asset is not (or no longer) in the inventory.")
		return
	}
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.render(w, r, sess, "asset", http.StatusOK, map[string]any{"Title": d.Title, "Nav": "assets", "D": d})
}

// detailWeb builds the page for a web service found by the active checks.
func (s *Server) detailWeb(d *AssetDetail, id string) error {
	i := strings.LastIndex(id, ":")
	if i < 0 {
		return errNotFound
	}
	port, err := strconv.Atoi(id[i+1:])
	if err != nil {
		return errNotFound
	}
	w, err := s.store.GetWeb(id[:i], port)
	if err != nil {
		return err
	}
	if w == nil {
		return errNotFound
	}
	d.Intro = "A web server the active checks reached, with what it answered."
	d.Facts = append(d.Facts,
		dFact{"Address", dCell{T: w.URL(), Mono: true}}, dFact{"Host", link(w.Host, assetLink("domain", w.Host))},
		dFact{"Connected to", link(w.IP, assetLink("ip", w.IP))}, dFact{"HTTP status", plain(strconv.Itoa(w.Status))},
		dFact{"Page title", plain(orNA(w.Title))}, dFact{"Server software", plain(orNA(w.Server))})
	if w.Powered != "" {
		d.Facts = append(d.Facts, dFact{"Powered by", plain(w.Powered)})
	}
	if w.Location != "" {
		d.Facts = append(d.Facts, dFact{"Redirects to", mono(w.Location)})
	}
	if w.DefaultPage != "" {
		d.Facts = append(d.Facts, dFact{"Default page", plain(w.DefaultPage)})
	}
	if w.Scheme == "https" {
		hs := "not sent"
		if w.HSTS {
			hs = "sent"
		}
		cert := w.TLSSubject
		if w.TLSIssuer != "" {
			cert += " issued by " + w.TLSIssuer
		}
		d.Facts = append(d.Facts, dFact{"TLS", plain(orNA(w.TLSVersion))}, dFact{"Certificate", plain(orNA(cert))},
			dFact{"Certificate expires", plain(expiryText(w.TLSExpires))}, dFact{"Strict-Transport-Security", plain(hs)})
		if w.TLSProblem != "" {
			d.Facts = append(d.Facts, dFact{"Certificate problem", dCell{T: w.TLSProblem, Cls: "sev-medium"}})
		}
		if w.TLSLegacy != "" {
			d.Facts = append(d.Facts, dFact{"Old protocols accepted", dCell{T: w.TLSLegacy, Cls: "sev-medium"}})
		}
	}
	d.Facts = append(d.Facts, dFact{"First seen", plain(fmtTS(w.FirstSeen))}, dFact{"Last seen", plain(fmtTS(w.LastSeen))})
	if w.HasShot {
		d.Shot = "/shots?" + url.Values{"host": {w.Host}, "port": {strconv.Itoa(w.Port)}}.Encode()
	}
	d.Findings = s.findingsAbout(w.Host + ":" + strconv.Itoa(w.Port))
	return nil
}

// shotView serves a stored screenshot.
func (s *Server) shotView(w http.ResponseWriter, r *http.Request, sess *Session) {
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	png, taken, ok := s.store.GetShot(r.URL.Query().Get("host"), port)
	if err != nil || !ok {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("X-Screenshot-Taken", taken)
	_, _ = w.Write(png) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- stored PNG bytes served as image/png, never HTML
}
