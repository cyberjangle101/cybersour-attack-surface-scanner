package main

import (
	"database/sql"
	"strings"
	"time"
)

// Read-only lookups that feed the asset detail pages. Each query completes before the next
// begins (the database has a single connection).

// recRow is one DNS record row.
type recRow struct{ Root, Host, Type, Value, First, Last string }

// scanRecs runs a DNS-record query.
func (s *Store) scanRecs(q string, args ...any) ([]recRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []recRow
	for rows.Next() {
		var r recRow
		if err := rows.Scan(&r.Root, &r.Host, &r.Type, &r.Value, &r.First, &r.Last); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordsOfHost returns every record of a host.
func (s *Store) RecordsOfHost(host string) ([]recRow, error) {
	return s.scanRecs(`SELECT root,host,rtype,value,first_seen,last_seen FROM records WHERE host=? ORDER BY rtype, value`, host)
}

// RecordsPointingTo returns records whose value equals the given address or name.
func (s *Store) RecordsPointingTo(value string) ([]recRow, error) {
	return s.scanRecs(`SELECT root,host,rtype,value,first_seen,last_seen FROM records WHERE value=? ORDER BY host`, value)
}

// RecordsOfType returns a host's records of one type.
func (s *Store) RecordsOfType(host, rtype string) ([]recRow, error) {
	return s.scanRecs(`SELECT root,host,rtype,value,first_seen,last_seen FROM records WHERE host=? AND rtype=? ORDER BY value`, host, rtype)
}

// hostRow is one monitored-host row.
type hostRow struct{ Root, Sources, First, Last string }

// HostRows returns the entries for a host name.
func (s *Store) HostRows(host string) ([]hostRow, error) {
	rows, err := s.db.Query(`SELECT root,sources,first_seen,last_seen FROM subdomains WHERE host=?`, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []hostRow
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.Root, &h.Sources, &h.First, &h.Last); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

type svcRow struct {
	IP, Transport, Source, Product, First, Last string
	Port                                        int
}

// ServicesOfIP returns the open services reported for an address.
func (s *Store) ServicesOfIP(ip string) ([]svcRow, error) {
	rows, err := s.db.Query(`SELECT ip,port,transport,source,product,first_seen,last_seen FROM services WHERE ip=? ORDER BY port, source`, ip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []svcRow
	for rows.Next() {
		var v svcRow
		if err := rows.Scan(&v.IP, &v.Port, &v.Transport, &v.Source, &v.Product, &v.First, &v.Last); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// intelRow is one source's data about an address.
type intelRow struct{ Source, Hostnames, Tags, CPEs, Vulns, Org, OS, Fetched string }

// IntelOfIP returns the stored per-source intelligence for an address.
func (s *Store) IntelOfIP(ip string) ([]intelRow, error) {
	rows, err := s.db.Query(`SELECT source,hostnames,tags,cpes,vulns,org,os,fetched FROM intel WHERE ip=? ORDER BY source`, ip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []intelRow
	for rows.Next() {
		var r intelRow
		if err := rows.Scan(&r.Source, &r.Hostnames, &r.Tags, &r.CPEs, &r.Vulns, &r.Org, &r.OS, &r.Fetched); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type asnRow struct {
	ASN                       int
	Prefix, Country, Org, Got string
}

// ASNOfIP returns the cached owner of an address regardless of age.
func (s *Store) ASNOfIP(ip string) (*asnRow, error) {
	var a asnRow
	err := s.db.QueryRow(`SELECT asn,prefix,country,org,fetched FROM asn_cache WHERE ip=?`, ip).Scan(&a.ASN, &a.Prefix, &a.Country, &a.Org, &a.Got)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

type certRow struct {
	Key, Root, CN, Names, Issuer, NotBefore, NotAfter, First string
	CrtShID                                                  int64
}

// scanCerts runs a certificate query.
func (s *Store) scanCerts(q string, args ...any) ([]certRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []certRow
	for rows.Next() {
		var c certRow
		var cn, names, iss, nb, na sql.NullString
		var id sql.NullInt64
		if err := rows.Scan(&c.Key, &c.Root, &cn, &names, &iss, &nb, &na, &id, &c.First); err != nil {
			return nil, err
		}
		c.CN, c.Names, c.Issuer, c.NotBefore, c.NotAfter, c.CrtShID = cn.String, names.String, iss.String, nb.String, na.String, id.Int64
		out = append(out, c)
	}
	return out, rows.Err()
}

const certCols = `key,root,common_name,names,issuer,not_before,not_after,crtsh_id,first_seen`

// CertByKey returns one certificate.
func (s *Store) CertByKey(key string) (*certRow, error) {
	l, err := s.scanCerts(`SELECT `+certCols+` FROM certs WHERE key=?`, key)
	if err != nil || len(l) == 0 {
		return nil, err
	}
	return &l[0], nil
}

// CertsCovering returns certificates whose names include host (exact or wildcard match).
func (s *Store) CertsCovering(host string) ([]certRow, error) {
	all, err := s.scanCerts(`SELECT ` + certCols + ` FROM certs ORDER BY not_after DESC`)
	if err != nil {
		return nil, err
	}
	var out []certRow
	for _, c := range all {
		for _, n := range strings.Split(c.Names, ",") {
			if nameCovers(n, host) {
				out = append(out, c)
				break
			}
		}
	}
	return out, nil
}

// nameCovers reports whether a certificate name (possibly "*.example.com") covers host.
func nameCovers(cert, host string) bool {
	cert, host = strings.ToLower(strings.TrimSpace(cert)), strings.ToLower(host)
	if cert == host {
		return true
	}
	if strings.HasPrefix(cert, "*.") {
		i := strings.Index(host, ".")
		return i > 0 && host[i+1:] == cert[2:]
	}
	return false
}

// DomainInfoByName returns the registration data stored for a domain.
func (s *Store) DomainInfoByName(domain string) (*DomainInfo, string, error) {
	var d DomainInfo
	var st, ns, root string
	err := s.db.QueryRow(`SELECT domain,registrar,created,expires,updated,status,nameservers,fetched,root FROM domain_info WHERE domain=?`, domain).
		Scan(&d.Domain, &d.Registrar, &d.Created, &d.Expires, &d.Updated, &st, &ns, &d.Fetched, &root)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	d.Status, d.Nameservers = csvSplit(st), csvSplit(ns)
	return &d, root, nil
}

// ---- reverse DNS cache

// GetRDNS returns a cached reverse-DNS answer younger than ttl.
func (s *Store) GetRDNS(ip string, ttl time.Duration) (string, bool) {
	var ptr, fetched string
	if err := s.db.QueryRow(`SELECT ptr,fetched FROM rdns WHERE ip=?`, ip).Scan(&ptr, &fetched); err != nil {
		return "", false
	}
	t, err := time.Parse(time.RFC3339, fetched)
	if err != nil || time.Since(t) > ttl {
		return "", false
	}
	return ptr, true
}

// PutRDNS caches a reverse-DNS answer.
func (s *Store) PutRDNS(ip, ptr string) {
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO rdns(ip,ptr,fetched) VALUES(?,?,?)`, ip, ptr, nowUTC())
}

// VulnIPs lists, for one CVE, the monitored IPs whose intelligence mentions it.
func (s *Store) VulnIPs(cve string) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT ip, vulns FROM intel`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ip, v string
		if err := rows.Scan(&ip, &v); err != nil {
			return nil, err
		}
		for _, x := range csvSplit(v) {
			if strings.EqualFold(x, cve) {
				out = append(out, ip)
				break
			}
		}
	}
	return dedupe(out), rows.Err()
}
