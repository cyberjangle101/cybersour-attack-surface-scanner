package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

func csvJoin(v []string) string { return strings.Join(v, ",") }

func csvSplit(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// PutIntel stores (or refreshes) what one source knows about one IP. A refresh
// without a raw answer keeps the one already stored.
func (t *Tx) PutIntel(in *IPIntel) error {
	_, err := t.tx.Exec(`INSERT INTO intel(ip,source,hostnames,tags,cpes,vulns,org,os,fetched,raw) VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip,source) DO UPDATE SET hostnames=excluded.hostnames, tags=excluded.tags, cpes=excluded.cpes, vulns=excluded.vulns,
		org=excluded.org, os=excluded.os, fetched=excluded.fetched, raw=CASE WHEN excluded.raw<>'' THEN excluded.raw ELSE intel.raw END`,
		in.IP, in.Source, csvJoin(in.Hostnames), csvJoin(in.Tags), csvJoin(in.CPEs), csvJoin(in.Vulns), in.Org, in.OS, in.Fetched, in.Raw)
	return err
}

// RawIntel is one source's stored answer about an IP.
type RawIntel struct{ Source, Fetched, Raw string }

// IntelRaw returns every source's stored raw answer for an IP, by source name.
func (s *Store) IntelRaw(ip string) ([]RawIntel, error) {
	rows, err := s.db.Query(`SELECT source, fetched, raw FROM intel WHERE ip=? ORDER BY source`, ip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RawIntel
	for rows.Next() {
		var r RawIntel
		if err := rows.Scan(&r.Source, &r.Fetched, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ServiceRec is one stored observation of an open port.
type ServiceRec struct {
	Port                                           int
	Transport, Source, Product, FirstSeen, LastSeen string
}

// ServicesFor lists what every source reported for an IP (port 0 = all ports).
func (s *Store) ServicesFor(ip string, port int) ([]ServiceRec, error) {
	rows, err := s.db.Query(`SELECT port, transport, source, product, first_seen, last_seen FROM services WHERE ip=? AND (?=0 OR port=?) ORDER BY port, source`, ip, port, port)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ServiceRec
	for rows.Next() {
		var r ServiceRec
		if err := rows.Scan(&r.Port, &r.Transport, &r.Source, &r.Product, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ShotsForIP lists stored screenshots of web services on an IP (or on host).
func (s *Store) ShotsForIP(ip, host string) ([]WebShotRef, error) {
	rows, err := s.db.Query(`SELECT w.host, w.port, ws.taken, w.scheme FROM web_services w JOIN web_shots ws ON ws.host=w.host AND ws.port=w.port
		WHERE w.ip=? OR w.host=? ORDER BY w.host, w.port`, ip, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []WebShotRef
	for rows.Next() {
		var r WebShotRef
		if err := rows.Scan(&r.Host, &r.Port, &r.Taken, &r.Scheme); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// WebShotRef points at a stored screenshot.
type WebShotRef struct {
	Host, Taken, Scheme string
	Port                int
}

// UpsertService records an open port and reports whether (ip, port, transport) was
// previously unknown to every source, i.e. whether a change event is warranted.
func (t *Tx) UpsertService(ip string, sv Service, source, now string) (bool, error) {
	var n int
	if err := t.tx.QueryRow(`SELECT COUNT(*) FROM services WHERE ip=? AND port=? AND transport=?`, ip, sv.Port, sv.Transport).Scan(&n); err != nil {
		return false, err
	}
	_, err := t.tx.Exec(`INSERT INTO services(ip,port,transport,source,product,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(ip,port,transport,source) DO UPDATE SET last_seen=excluded.last_seen,
		product=CASE WHEN excluded.product<>'' THEN excluded.product ELSE services.product END`,
		ip, sv.Port, sv.Transport, source, sv.Product, now, now)
	return n == 0, err
}

// PruneServices removes ports a source no longer reports for an IP it just refreshed (keep is
// what it reported now). It returns the services that no source reports any more, so a
// "port closed" event can be raised.
func (t *Tx) PruneServices(ip, source string, keep []Service) ([]Service, error) {
	rows, err := t.tx.Query(`SELECT port, transport, product FROM services WHERE ip=? AND source=?`, ip, source)
	if err != nil {
		return nil, err
	}
	still := map[string]bool{}
	for _, k := range keep {
		still[fmt.Sprintf("%d/%s", k.Port, k.Transport)] = true
	}
	var dropped []Service
	for rows.Next() {
		var sv Service
		if err := rows.Scan(&sv.Port, &sv.Transport, &sv.Product); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !still[fmt.Sprintf("%d/%s", sv.Port, sv.Transport)] {
			dropped = append(dropped, sv)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	var gone []Service
	for _, sv := range dropped {
		if _, err := t.tx.Exec(`DELETE FROM services WHERE ip=? AND source=? AND port=? AND transport=?`, ip, source, sv.Port, sv.Transport); err != nil {
			return nil, err
		}
		var n int
		if err := t.tx.QueryRow(`SELECT COUNT(*) FROM services WHERE ip=? AND port=? AND transport=?`, ip, sv.Port, sv.Transport).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			gone = append(gone, sv)
		}
	}
	return gone, nil
}

// PutDomainInfo stores registration data.
func (t *Tx) PutDomainInfo(root string, d *DomainInfo) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO domain_info(domain,root,registrar,created,expires,updated,status,nameservers,fetched) VALUES(?,?,?,?,?,?,?,?,?)`,
		d.Domain, root, d.Registrar, d.Created, d.Expires, d.Updated, csvJoin(d.Status), csvJoin(d.Nameservers), d.Fetched)
	return err
}

// GetDomainInfo returns the registration data for a monitored domain.
func (s *Store) GetDomainInfo(root string) (*DomainInfo, error) {
	var d DomainInfo
	var st, ns string
	err := s.db.QueryRow(`SELECT domain,registrar,created,expires,updated,status,nameservers,fetched FROM domain_info WHERE root=? ORDER BY length(domain) DESC LIMIT 1`, root).
		Scan(&d.Domain, &d.Registrar, &d.Created, &d.Expires, &d.Updated, &st, &ns, &d.Fetched)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Status, d.Nameservers = csvSplit(st), csvSplit(ns)
	return &d, nil
}

// LoadIntel returns cached per-source intelligence (including open services) for the IPs.
func (s *Store) LoadIntel(ips []string) (map[string]map[string]*IPIntel, error) {
	out := map[string]map[string]*IPIntel{}
	for start := 0; start < len(ips); start += 400 {
		end := start + 400
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[start:end]
		ph := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, len(chunk))
		for i, ip := range chunk {
			args[i] = ip
		}
		//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
		rows, err := s.db.Query(`SELECT ip,source,hostnames,tags,cpes,vulns,org,os,fetched FROM intel WHERE ip IN (`+ph+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var in IPIntel
			var h, tg, cp, vu string
			if err := rows.Scan(&in.IP, &in.Source, &h, &tg, &cp, &vu, &in.Org, &in.OS, &in.Fetched); err != nil {
				_ = rows.Close()
				return nil, err
			}
			in.Hostnames, in.Tags, in.CPEs, in.Vulns = csvSplit(h), csvSplit(tg), csvSplit(cp), csvSplit(vu)
			if out[in.IP] == nil {
				out[in.IP] = map[string]*IPIntel{}
			}
			cp2 := in
			out[in.IP][in.Source] = &cp2
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close() // finish this cursor before the next query: one connection only
		//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
		rows, err = s.db.Query(`SELECT ip,port,transport,source,product FROM services WHERE ip IN (`+ph+`) ORDER BY port`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip, tr, src, prod string
			var port int
			if err := rows.Scan(&ip, &port, &tr, &src, &prod); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if in := out[ip][src]; in != nil {
				in.Services = append(in.Services, Service{Port: port, Transport: tr, Product: prod})
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close()
	}
	return out, nil
}

// sortedKeys is a small helper used by several callers.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NextScanTime returns the earliest scheduled scan among enabled targets ("" if none).
func (s *Store) NextScanTime() (string, error) {
	var v sql.NullString
	err := s.db.QueryRow(`SELECT MIN(next_scan) FROM targets WHERE enabled=1`).Scan(&v)
	return v.String, err
}

// Ping checks the database is readable and returns its size on disk in bytes.
func (s *Store) Ping() (int64, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&n); err != nil {
		return 0, err
	}
	return fileSize(s.path), nil
}
