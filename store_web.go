package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// WebService is a web server the active checks found.
type WebService struct {
	Host, Root, Scheme, IP            string
	Port, Status                      int
	Title, Server, Location, Powered  string
	HSTS                              bool
	TLSVersion, TLSSubject, TLSIssuer string
	TLSExpires, TLSProblem, TLSLegacy string
	DefaultPage, FirstSeen, LastSeen  string
	HasShot                           bool
}

// UpsertWeb stores or refreshes a web service and reports whether it is new.
func (t *Tx) UpsertWeb(root string, w *WebResult, now string) (bool, error) {
	var n int
	if err := t.tx.QueryRow(`SELECT COUNT(*) FROM web_services WHERE host=? AND port=?`, w.Host, w.Port).Scan(&n); err != nil {
		return false, err
	}
	var ver, subj, iss, exp, prob, legacy string
	if w.TLS != nil {
		ver, subj, iss, exp, prob = w.TLS.Version, w.TLS.Subject, w.TLS.Issuer, w.TLS.NotAfter.UTC().Format("2006-01-02"), w.TLS.Problem
		legacy = strings.Join(w.TLS.Legacy, ",")
	}
	hsts := 0
	if w.HSTS {
		hsts = 1
	}
	_, err := t.tx.Exec(`INSERT INTO web_services(host,port,root,scheme,ip,status,title,server,location,hsts,powered,tls_version,tls_subject,tls_issuer,tls_expires,tls_problem,tls_legacy,default_page,first_seen,last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host,port) DO UPDATE SET root=excluded.root, scheme=excluded.scheme, ip=excluded.ip, status=excluded.status, title=excluded.title,
		server=excluded.server, location=excluded.location, hsts=excluded.hsts, powered=excluded.powered, tls_version=excluded.tls_version,
		tls_subject=excluded.tls_subject, tls_issuer=excluded.tls_issuer, tls_expires=excluded.tls_expires, tls_problem=excluded.tls_problem,
		tls_legacy=excluded.tls_legacy, default_page=excluded.default_page, last_seen=excluded.last_seen`,
		w.Host, w.Port, root, w.Scheme, w.IP, w.Status, w.Title, w.Server, w.Location, hsts, w.Powered, ver, subj, iss, exp, prob, legacy, w.DefaultPg, now, now)
	return n == 0, err
}

// PutShot stores a screenshot.
func (t *Tx) PutShot(host string, port int, png []byte, now string) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO web_shots(host,port,taken,png) VALUES(?,?,?,?)`, host, port, now, png)
	return err
}

// GetShot returns a stored screenshot.
func (s *Store) GetShot(host string, port int) ([]byte, string, bool) {
	var png []byte
	var taken string
	err := s.db.QueryRow(`SELECT png, taken FROM web_shots WHERE host=? AND port=?`, host, port).Scan(&png, &taken)
	if err != nil {
		return nil, "", false
	}
	return png, taken, true
}

const webCols = `w.host,w.port,w.root,w.scheme,w.ip,w.status,w.title,w.server,w.location,w.hsts,w.powered,w.tls_version,w.tls_subject,w.tls_issuer,w.tls_expires,w.tls_problem,w.tls_legacy,w.default_page,w.first_seen,w.last_seen,(SELECT COUNT(*) FROM web_shots s WHERE s.host=w.host AND s.port=w.port)`

func scanWeb(rows *sql.Rows) ([]WebService, error) {
	var out []WebService
	for rows.Next() {
		var w WebService
		var hsts, shot int
		if err := rows.Scan(&w.Host, &w.Port, &w.Root, &w.Scheme, &w.IP, &w.Status, &w.Title, &w.Server, &w.Location, &hsts, &w.Powered,
			&w.TLSVersion, &w.TLSSubject, &w.TLSIssuer, &w.TLSExpires, &w.TLSProblem, &w.TLSLegacy, &w.DefaultPage, &w.FirstSeen, &w.LastSeen, &shot); err != nil {
			return nil, err
		}
		w.HSTS, w.HasShot = hsts != 0, shot != 0
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListWeb lists web services for an entity ("" = all).
func (s *Store) ListWeb(root string) ([]WebService, error) {
	q := `SELECT ` + webCols + ` FROM web_services w`
	var args []any
	if root != "" {
		q += ` WHERE w.root=?`
		args = append(args, root)
	}
	rows, err := s.db.Query(q+` ORDER BY w.host, w.port`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanWeb(rows)
}

// GetWeb returns one web service.
func (s *Store) GetWeb(host string, port int) (*WebService, error) {
	rows, err := s.db.Query(`SELECT `+webCols+` FROM web_services w WHERE w.host=? AND w.port=?`, host, port)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	l, err := scanWeb(rows)
	if err != nil || len(l) == 0 {
		return nil, err
	}
	return &l[0], nil
}

// webPortsFor lists extra web-looking ports other sources reported open on an address.
func (s *Store) webPortsFor(ip string) []int {
	rows, err := s.db.Query(`SELECT DISTINCT port FROM services WHERE ip=? AND transport='tcp' AND port IN (3000,5000,8000,8008,8080,8081,8181,8443,8888,9443)`, ip)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []int
	for rows.Next() {
		var p int
		if rows.Scan(&p) == nil {
			out = append(out, p)
		}
	}
	return out
}

func (w WebService) URL() string {
	r := WebResult{Host: w.Host, Port: w.Port, Scheme: w.Scheme}
	return r.URL()
}

func (w WebService) String() string { return fmt.Sprintf("%s:%d", w.Host, w.Port) }
