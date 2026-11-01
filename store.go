package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver" // pure-Go SQLite (WASM translated to Go, built in): no CGO, single static binary
)

var schemaStmts = []string{
	`CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS targets(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		expected_asns TEXT NOT NULL DEFAULT '',
		org_keywords TEXT NOT NULL DEFAULT '',
		ignore_patterns TEXT NOT NULL DEFAULT '',
		interval_minutes INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		notes TEXT NOT NULL DEFAULT '',
		created TEXT NOT NULL,
		next_scan TEXT NOT NULL,
		last_start TEXT NOT NULL DEFAULT '',
		last_end TEXT NOT NULL DEFAULT '',
		last_status TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE IF NOT EXISTS subdomains(
		root TEXT NOT NULL, host TEXT NOT NULL, sources TEXT NOT NULL DEFAULT '',
		first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(root, host))`,
	`CREATE TABLE IF NOT EXISTS records(
		root TEXT NOT NULL, host TEXT NOT NULL, rtype TEXT NOT NULL, value TEXT NOT NULL,
		first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(host, rtype, value))`,
	`CREATE INDEX IF NOT EXISTS idx_records_root ON records(root)`,
	`CREATE TABLE IF NOT EXISTS certs(
		key TEXT PRIMARY KEY, root TEXT NOT NULL, common_name TEXT, names TEXT, issuer TEXT,
		not_before TEXT, not_after TEXT, crtsh_id INTEGER, first_seen TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_certs_root ON certs(root)`,
	`CREATE TABLE IF NOT EXISTS asn_cache(
		ip TEXT PRIMARY KEY, asn INTEGER, prefix TEXT, country TEXT, org TEXT, fetched TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS findings(
		id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, root TEXT NOT NULL,
		kind TEXT NOT NULL, severity TEXT NOT NULL, host TEXT NOT NULL, detail TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'open', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
		source TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS idx_findings_root ON findings(root, status)`,
	`CREATE TABLE IF NOT EXISTS events(
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, root TEXT NOT NULL,
		kind TEXT NOT NULL, severity TEXT NOT NULL, host TEXT NOT NULL, detail TEXT NOT NULL,
		notified INTEGER NOT NULL DEFAULT 0, baseline INTEGER NOT NULL DEFAULT 0)`,
	`CREATE INDEX IF NOT EXISTS idx_events_pending ON events(notified, id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_root ON events(root, id)`,
	`CREATE TABLE IF NOT EXISTS scans(
		id INTEGER PRIMARY KEY AUTOINCREMENT, root TEXT NOT NULL, started TEXT NOT NULL, finished TEXT NOT NULL,
		status TEXT NOT NULL, hosts INTEGER NOT NULL DEFAULT 0, new_subdomains INTEGER NOT NULL DEFAULT 0,
		new_records INTEGER NOT NULL DEFAULT 0, new_certs INTEGER NOT NULL DEFAULT 0,
		new_findings INTEGER NOT NULL DEFAULT 0, new_events INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS idx_scans_root ON scans(root, id)`,
	`CREATE TABLE IF NOT EXISTS services(
		ip TEXT NOT NULL, port INTEGER NOT NULL, transport TEXT NOT NULL, source TEXT NOT NULL,
		product TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
		PRIMARY KEY(ip, port, transport, source))`,
	`CREATE TABLE IF NOT EXISTS intel(
		ip TEXT NOT NULL, source TEXT NOT NULL, hostnames TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '',
		cpes TEXT NOT NULL DEFAULT '', vulns TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '',
		fetched TEXT NOT NULL, PRIMARY KEY(ip, source))`,
	`CREATE TABLE IF NOT EXISTS domain_info(
		domain TEXT PRIMARY KEY, root TEXT NOT NULL, registrar TEXT NOT NULL DEFAULT '', created TEXT NOT NULL DEFAULT '',
		expires TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
		nameservers TEXT NOT NULL DEFAULT '', fetched TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS rdns(
		ip TEXT PRIMARY KEY, ptr TEXT NOT NULL DEFAULT '', fetched TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS web_services(
		host TEXT NOT NULL, port INTEGER NOT NULL, root TEXT NOT NULL, scheme TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 0, title TEXT NOT NULL DEFAULT '', server TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '',
		hsts INTEGER NOT NULL DEFAULT 0, powered TEXT NOT NULL DEFAULT '', tls_version TEXT NOT NULL DEFAULT '', tls_subject TEXT NOT NULL DEFAULT '',
		tls_issuer TEXT NOT NULL DEFAULT '', tls_expires TEXT NOT NULL DEFAULT '', tls_problem TEXT NOT NULL DEFAULT '', tls_legacy TEXT NOT NULL DEFAULT '',
		default_page TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(host, port))`,
	`CREATE TABLE IF NOT EXISTS web_shots(
		host TEXT NOT NULL, port INTEGER NOT NULL, taken TEXT NOT NULL, png BLOB NOT NULL, PRIMARY KEY(host, port))`,
	`CREATE TABLE IF NOT EXISTS suggestions(
		root TEXT NOT NULL, domain TEXT NOT NULL, via TEXT NOT NULL, detail TEXT NOT NULL, first_seen TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'new', PRIMARY KEY(root, domain))`,
	`CREATE TABLE IF NOT EXISTS channels(
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, kind TEXT NOT NULL, cfg TEXT NOT NULL,
		min_sev TEXT NOT NULL DEFAULT 'low', enabled INTEGER NOT NULL DEFAULT 1, cursor INTEGER NOT NULL DEFAULT 0,
		last_try TEXT NOT NULL DEFAULT '', last_ok TEXT NOT NULL DEFAULT '', last_err TEXT NOT NULL DEFAULT '', created TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS channel_tickets(
		channel_id INTEGER NOT NULL, dedupe TEXT NOT NULL, ticket TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY(channel_id, dedupe))`,
	`CREATE TABLE IF NOT EXISTS audit(
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)`,
	`CREATE TABLE IF NOT EXISTS api_tokens(
		id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL,
		hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL DEFAULT '',
		last_used TEXT NOT NULL DEFAULT '', revoked INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		hash TEXT NOT NULL, role TEXT NOT NULL, created TEXT NOT NULL)`,
}

var findingKinds = map[string]bool{"tls-expired": true, "tls-expiring": true, "tls-hostname": true, "tls-untrusted": true, "tls-legacy": true,
	"default-page": true, "exposed-path": true, "no-https-redirect": true, "bucket-public": true, "bucket-takeover": true, "dangling-cname": true, "asn-unexpected": true, "private-ip": true, "email-auth": true,
	"lookalike-domain": true, "leaked-credentials": true, "repo-exposure": true, "cloud-datastore": true,
	"exposed-service": true, "known-vuln": true, "ip-flagged": true, "eol-software": true, "domain-expiry": true}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// Store is the encrypted SQLite database. It uses a single connection: never start a query while another cursor is open.
type Store struct {
	db    *sql.DB
	path  string
	vault *Vault // seals user password hashes at rest (nil only in tests that do not need it)
}

const sealedPrefix = "enc1:"

// SetVault enables AES-256-GCM sealing of stored password hashes and upgrades any
// plain bcrypt hashes written by earlier versions.
func (s *Store) SetVault(v *Vault) error {
	s.vault = v
	if v == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, hash FROM users WHERE hash NOT LIKE ?`, sealedPrefix+"%")
	if err != nil {
		return err
	}
	type idh struct {
		id int64
		h  string
	}
	var todo []idh
	for rows.Next() {
		var x idh
		if err := rows.Scan(&x.id, &x.h); err != nil {
			_ = rows.Close()
			return err
		}
		todo = append(todo, x)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, x := range todo {
		if err := s.SetPassword(x.id, x.h); err != nil {
			return err
		}
	}
	return nil
}

// sealHash encrypts a password hash for storage.
func (s *Store) sealHash(h string) (string, error) {
	if s.vault == nil {
		return h, nil
	}
	enc, err := s.vault.Seal(h)
	if err != nil {
		return "", err
	}
	return sealedPrefix + enc, nil
}

// openHash decrypts a stored password hash (plain legacy hashes pass through).
func (s *Store) openHash(stored string) (string, error) {
	if !strings.HasPrefix(stored, sealedPrefix) {
		return stored, nil // legacy plain bcrypt hash, upgraded by SetVault
	}
	if s.vault == nil {
		return "", errors.New("password store is encrypted but no key is loaded")
	}
	return s.vault.Open(strings.TrimPrefix(stored, sealedPrefix))
}

// Event is one recorded change (new host, record, certificate, service or finding).
type Event struct {
	ID       int64  `json:"id"`
	TS       string `json:"time"`
	Root     string `json:"target"`
	Kind     string `json:"type"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Detail   string `json:"detail"`
	Notified bool   `json:"-"`
	NoAlert  bool   `json:"-"` // record the event but do not email it (not a baseline event either)
	Baseline bool   `json:"baseline"`
}

// OpenStore opens an UNENCRYPTED database. Production code uses OpenEncryptedStore; this
// exists for tests and for reading a legacy file during migration.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return initStore(db, path)
}

// initStore applies pragmas, creates/migrates the schema and wraps the handle.
func initStore(db *sql.DB, path string) (*Store, error) {
	// One connection serialises access, keeps PRAGMAs in effect and avoids SQLITE_BUSY.
	// IMPORTANT: never run a second query while a rows cursor is still open.
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=10000", "PRAGMA synchronous=NORMAL"} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	for _, s := range schemaStmts {
		if _, err := db.Exec(s); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	// Additive migrations for databases created by an earlier version.
	for _, m := range migrateStmts {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			_ = db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	if err := backfillTrust(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: finding trust levels: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

var migrateStmts = []string{
	`ALTER TABLE findings ADD COLUMN source TEXT NOT NULL DEFAULT ''`,
	// risk acceptance and analyst severity
	`ALTER TABLE findings ADD COLUMN ack_reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN ack_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN ack_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN ack_until TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN scan_sev TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN sev_override TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN sev_reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN sev_by TEXT NOT NULL DEFAULT ''`,
	// "Confirm via active scan" result (exposed-service findings)
	`ALTER TABLE findings ADD COLUMN verify_state TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN verify_banner TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN verify_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN verify_by TEXT NOT NULL DEFAULT ''`,
	// the exposure source's raw answer, shown as evidence on findings
	`ALTER TABLE intel ADD COLUMN raw TEXT NOT NULL DEFAULT ''`,
	`UPDATE findings SET scan_sev=severity WHERE scan_sev=''`,
	// accounts: sign-in kind (local|ad), two-factor, state
	`ALTER TABLE events ADD COLUMN muted INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE records ADD COLUMN misses INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE records ADD COLUMN gone TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE subdomains ADD COLUMN gone TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'local'`,
	`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN totp_on INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN recovery TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN last_login TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`,
	// corroboration of third-party findings (trust.go)
	`ALTER TABLE findings ADD COLUMN trust TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN trust_sources TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN trust_src TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN confirm_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN confirm_at TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN confirm_note TEXT NOT NULL DEFAULT ''`,
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ---------------------------------------------------------------- meta / settings

func (s *Store) getMeta(k string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) setMeta(k, v string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)`, k, v)
	return err
}

// LoadSettings returns the saved settings, defaults filling any missing fields.
func (s *Store) LoadSettings() (Settings, error) {
	st := DefaultSettings()
	v, ok, err := s.getMeta("settings")
	if err != nil || !ok {
		return st, err
	}
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return DefaultSettings(), fmt.Errorf("stored settings are corrupt: %w", err)
	}
	return st, nil
}

// SaveSettings stores the settings as JSON.
func (s *Store) SaveSettings(st Settings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.setMeta("settings", string(b))
}

// ---------------------------------------------------------------- targets

const targetCols = `id, domain, expected_asns, org_keywords, ignore_patterns, interval_minutes, enabled, notes, created, next_scan, last_start, last_end, last_status, last_error`

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

// scanTarget reads one target row.
func scanTarget(sc rowScanner) (*Target, error) {
	var t Target
	var asns, kws, ign string
	var en int
	if err := sc.Scan(&t.ID, &t.Domain, &asns, &kws, &ign, &t.IntervalMinutes, &en, &t.Notes, &t.Created,
		&t.NextScan, &t.LastStart, &t.LastEnd, &t.LastStatus, &t.LastError); err != nil {
		return nil, err
	}
	t.ExpectedASNs = splitInts(asns)
	t.ExpectedOrgKeywords = splitList(kws, false)
	t.IgnoreSubdomains = splitList(ign, false)
	t.Enabled = en == 1
	if err := t.Compile(); err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Domain, err)
	}
	return &t, nil
}

// baselineMap returns when each domain's baseline completed.
func (s *Store) baselineMap() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k, v FROM meta WHERE k LIKE 'baselined:%'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[strings.TrimPrefix(k, "baselined:")] = v
	}
	return m, rows.Err()
}

// ListTargets returns all monitored domains.
func (s *Store) ListTargets() ([]*Target, error) {
	rows, err := s.db.Query(`SELECT ` + targetCols + ` FROM targets ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	bm, err := s.baselineMap()
	if err != nil {
		return nil, err
	}
	for _, t := range out {
		t.BaselinedAt = bm[t.Domain]
	}
	return out, nil
}

// GetTarget returns one target by id.
func (s *Store) GetTarget(id int64) (*Target, error) {
	t, err := scanTarget(s.db.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if v, ok, err := s.getMeta("baselined:" + t.Domain); err == nil && ok {
		t.BaselinedAt = v
	}
	return t, nil
}

var ErrNotFound = sql.ErrNoRows

// AddTarget inserts a new target scheduled to scan immediately.
func (s *Store) AddTarget(t *Target) (int64, error) {
	existing, err := s.ListTargets()
	if err != nil {
		return 0, err
	}
	for _, e := range existing {
		switch {
		case e.Domain == t.Domain:
			return 0, fmt.Errorf("%s is already being monitored", t.Domain)
		case inScope(t.Domain, e.Domain):
			return 0, fmt.Errorf("%s is already covered by the existing target %s", t.Domain, e.Domain)
		case inScope(e.Domain, t.Domain):
			return 0, fmt.Errorf("%s would overlap the existing target %s; remove that one first", t.Domain, e.Domain)
		}
	}
	now := nowUTC()
	res, err := s.db.Exec(`INSERT INTO targets(domain, expected_asns, org_keywords, ignore_patterns, interval_minutes, enabled, notes, created, next_scan)
		VALUES(?,?,?,?,?,1,?,?,?)`, t.Domain, joinInts(t.ExpectedASNs), strings.Join(t.ExpectedOrgKeywords, "\n"),
		strings.Join(t.IgnoreSubdomains, "\n"), t.IntervalMinutes, t.Notes, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateTarget saves edited target options.
func (s *Store) UpdateTarget(t *Target) error {
	_, err := s.db.Exec(`UPDATE targets SET expected_asns=?, org_keywords=?, ignore_patterns=?, interval_minutes=?, notes=? WHERE id=?`,
		joinInts(t.ExpectedASNs), strings.Join(t.ExpectedOrgKeywords, "\n"), strings.Join(t.IgnoreSubdomains, "\n"),
		t.IntervalMinutes, t.Notes, t.ID)
	return err
}

// DeleteTarget removes a domain and everything stored about it.
func (s *Store) DeleteTarget(id int64) error {
	t, err := s.GetTarget(id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Everything keyed by the root domain. Screenshots and web services are keyed by host,
	// so they are removed before the rows that name those hosts.
	for _, q := range []string{
		`DELETE FROM web_shots WHERE host IN (SELECT host FROM web_services WHERE root=?)`,
		`DELETE FROM web_services WHERE root=?`,
		`DELETE FROM subdomains WHERE root=?`, `DELETE FROM records WHERE root=?`, `DELETE FROM certs WHERE root=?`,
		`DELETE FROM findings WHERE root=?`, `DELETE FROM events WHERE root=?`, `DELETE FROM scans WHERE root=?`,
		`DELETE FROM suggestions WHERE root=?`, `DELETE FROM domain_info WHERE root=?`,
	} {
		if _, err := tx.Exec(q, t.Domain); err != nil {
			return err
		}
	}
	// Intelligence is keyed by IP and may be shared; drop it only when no remaining record uses the address.
	for _, q := range []string{
		`DELETE FROM services WHERE ip NOT IN (SELECT value FROM records WHERE rtype IN ('A','AAAA'))`,
		`DELETE FROM intel WHERE ip NOT IN (SELECT value FROM records WHERE rtype IN ('A','AAAA'))`,
		`DELETE FROM rdns WHERE ip NOT IN (SELECT value FROM records WHERE rtype IN ('A','AAAA'))`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM meta WHERE k=? OR k LIKE ?`, "baselined:"+t.Domain, "%:"+t.Domain); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM targets WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// TargetDataCounts says how much stored data belongs to a domain, for the delete confirmation.
type TargetDataCounts struct{ Hosts, Records, Certs, Findings, Events, Scans, Screenshots int }

// CountTargetData counts what DeleteTarget would remove.
func (s *Store) CountTargetData(domain string) (TargetDataCounts, error) {
	var c TargetDataCounts
	for _, q := range []struct {
		dst *int
		sql string
	}{
		{&c.Hosts, `SELECT COUNT(*) FROM subdomains WHERE root=?`},
		{&c.Records, `SELECT COUNT(*) FROM records WHERE root=?`},
		{&c.Certs, `SELECT COUNT(*) FROM certs WHERE root=?`},
		{&c.Findings, `SELECT COUNT(*) FROM findings WHERE root=?`},
		{&c.Events, `SELECT COUNT(*) FROM events WHERE root=?`},
		{&c.Scans, `SELECT COUNT(*) FROM scans WHERE root=?`},
		{&c.Screenshots, `SELECT COUNT(*) FROM web_shots WHERE host IN (SELECT host FROM web_services WHERE root=?)`},
	} {
		if err := s.db.QueryRow(q.sql, domain).Scan(q.dst); err != nil {
			return c, err
		}
	}
	return c, nil
}

// SetTargetEnabled pauses or resumes a target.
func (s *Store) SetTargetEnabled(id int64, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := s.db.Exec(`UPDATE targets SET enabled=?, next_scan=CASE WHEN ?=1 THEN ? ELSE next_scan END WHERE id=?`, e, e, nowUTC(), id)
	return err
}

// RequestScan schedules an immediate scan unless one is already running.
func (s *Store) RequestScan(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE targets SET next_scan=? WHERE id=? AND enabled=1 AND last_status!='running'`, nowUTC(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DueTargets lists enabled, idle targets whose next scan time has passed.
func (s *Store) DueTargets(now string) ([]*Target, error) {
	rows, err := s.db.Query(`SELECT `+targetCols+` FROM targets WHERE enabled=1 AND last_status!='running' AND next_scan<=? ORDER BY next_scan`, now)
	if err != nil {
		return nil, err
	}
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	for _, t := range out {
		if v, ok, e := s.getMeta("baselined:" + t.Domain); e == nil && ok {
			t.BaselinedAt = v
		}
	}
	return out, nil
}

// MarkRunning flags a target as scanning.
func (s *Store) MarkRunning(id int64, now string) error {
	_, err := s.db.Exec(`UPDATE targets SET last_status='running', last_start=?, last_error='' WHERE id=?`, now, id)
	return err
}

// FinishScan stores a scan's result and next scheduled time.
func (s *Store) FinishScan(id int64, status, errMsg, end, next string) error {
	_, err := s.db.Exec(`UPDATE targets SET last_status=?, last_error=?, last_end=?, next_scan=? WHERE id=?`,
		status, truncate(errMsg, 500), end, next, id)
	return err
}

// ResetRunning recovers from a crash or kill that left targets marked running.
func (s *Store) ResetRunning() error {
	_, err := s.db.Exec(`UPDATE targets SET last_status='interrupted', next_scan=? WHERE last_status='running'`, nowUTC())
	return err
}

// ---------------------------------------------------------------- scan history

// ScanRec is one row of scan history.
type ScanRec struct {
	ID                                                                 int64
	Root, Started, Finished, Status, Error                             string
	Hosts, NewSubdomains, NewRecords, NewCerts, NewFindings, NewEvents int
}

// InsertScan appends a scan-history row.
func (s *Store) InsertScan(r ScanRec) error {
	_, err := s.db.Exec(`INSERT INTO scans(root,started,finished,status,hosts,new_subdomains,new_records,new_certs,new_findings,new_events,error)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, r.Root, r.Started, r.Finished, r.Status, r.Hosts, r.NewSubdomains, r.NewRecords,
		r.NewCerts, r.NewFindings, r.NewEvents, truncate(r.Error, 500))
	return err
}

// ListScans returns recent scan history for a domain (or all).
func (s *Store) ListScans(root string, limit int) ([]ScanRec, error) {
	q := `SELECT id,root,started,finished,status,hosts,new_subdomains,new_records,new_certs,new_findings,new_events,error FROM scans`
	var args []any
	if root != "" {
		q += ` WHERE root=?`
		args = append(args, root)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ScanRec
	for rows.Next() {
		var r ScanRec
		if err := rows.Scan(&r.ID, &r.Root, &r.Started, &r.Finished, &r.Status, &r.Hosts, &r.NewSubdomains, &r.NewRecords,
			&r.NewCerts, &r.NewFindings, &r.NewEvents, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- users

// User is a web-interface account.
type User struct {
	ID                            int64
	Username, Hash, Role, Created string
	Kind                          string // "local" (password in this database) or "ad" (signs in with Active Directory)
	TOTPSecret, Recovery          string // sealed; see twofactor.go
	TOTPOn, Disabled              bool
	LastLogin                     string
}

// CountUsers returns the number of accounts (zero means first-run setup).
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser adds an account; the password hash is sealed before storage.
func (s *Store) CreateUser(username, hash, role string) (int64, error) {
	return s.CreateUserKind(username, hash, role, "local")
}

// CreateUserKind adds an account of the given kind ("local" or "ad"). Directory accounts
// have no password hash here: the directory checks the password at every sign-in.
func (s *Store) CreateUserKind(username, hash, role, kind string) (int64, error) {
	if hash != "" {
		var err0 error
		if hash, err0 = s.sealHash(hash); err0 != nil {
			return 0, err0
		}
	}
	res, err := s.db.Exec(`INSERT INTO users(username,hash,role,created,kind) VALUES(?,?,?,?,?)`, username, hash, role, nowUTC(), kind)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return 0, fmt.Errorf("user %q already exists", username)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// finishUser opens the sealed fields of a freshly read account.
func (s *Store) finishUser(u *User, totp, dis int) (*User, error) {
	var err error
	u.TOTPOn, u.Disabled = totp != 0, dis != 0
	if u.Hash, err = s.openHash(u.Hash); err != nil {
		return nil, err
	}
	if u.TOTPSecret, err = s.openHash(u.TOTPSecret); err != nil {
		return nil, err
	}
	if u.Recovery, err = s.openHash(u.Recovery); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByName returns an account with its decrypted hash.
func (s *Store) GetUserByName(name string) (*User, error) {
	var u User
	var totp, dis int
	err := s.db.QueryRow(`SELECT id,username,hash,role,created,kind,totp_secret,totp_on,recovery,last_login,disabled FROM users WHERE username=?`, name).Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &u.Created, &u.Kind, &u.TOTPSecret, &totp, &u.Recovery, &u.LastLogin, &dis)
	if err != nil {
		return nil, err
	}
	return s.finishUser(&u, totp, dis)
}

// GetUser returns an account by id.
func (s *Store) GetUser(id int64) (*User, error) {
	var u User
	var totp, dis int
	err := s.db.QueryRow(`SELECT id,username,hash,role,created,kind,totp_secret,totp_on,recovery,last_login,disabled FROM users WHERE id=?`, id).Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &u.Created, &u.Kind, &u.TOTPSecret, &totp, &u.Recovery, &u.LastLogin, &dis)
	if err != nil {
		return nil, err
	}
	return s.finishUser(&u, totp, dis)
}

// ListUsers returns all accounts without their hashes.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id,username,hash,role,created,kind,totp_secret,totp_on,recovery,last_login,disabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		var totp, dis int
		if err := rows.Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &u.Created, &u.Kind, &u.TOTPSecret, &totp, &u.Recovery, &u.LastLogin, &dis); err != nil {
			return nil, err
		}
		u.TOTPOn, u.Disabled = totp != 0, dis != 0
		u.Hash, u.TOTPSecret, u.Recovery = "", "", "" // never hand secrets to list views
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountAdmins returns how many administrators exist.
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND kind<>'ad-group'`).Scan(&n)
	return n, err
}

// DeleteUser removes an account.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// SetPassword replaces an account's password hash (sealed).
func (s *Store) SetPassword(id int64, hash string) error {
	hash, err := s.sealHash(hash)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET hash=? WHERE id=?`, hash, id)
	return err
}

// ---------------------------------------------------------------- alert queue

// PendingEvents returns events not yet emailed.
func (s *Store) PendingEvents() ([]Event, error) {
	rows, err := s.db.Query(`SELECT id, ts, root, kind, severity, host, detail FROM events WHERE notified=0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Root, &e.Kind, &e.Severity, &e.Host, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkNotified marks events as emailed.
func (s *Store) MarkNotified(maxID int64) error {
	_, err := s.db.Exec(`UPDATE events SET notified=1 WHERE notified=0 AND id<=?`, maxID)
	return err
}

// Prune deletes events older than the retention period.
func (s *Store) Prune(days int) error {
	cut := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	if _, err := s.db.Exec(`DELETE FROM events WHERE notified=1 AND ts<?`, cut); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM scans WHERE finished<?`, cut); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM findings WHERE status='resolved' AND last_seen<?`, cut)
	return err
}

// ---------------------------------------------------------------- ASN cache

// GetASN returns a cached owner record if it is younger than ttl.
func (s *Store) GetASN(ip string, ttl time.Duration) (*ASNInfo, bool) {
	var a ASNInfo
	var fetched string
	err := s.db.QueryRow(`SELECT asn, prefix, country, org, fetched FROM asn_cache WHERE ip=?`, ip).
		Scan(&a.ASN, &a.Prefix, &a.Country, &a.Org, &fetched)
	if err != nil {
		return nil, false
	}
	t, err := time.Parse(time.RFC3339, fetched)
	if err != nil || time.Since(t) > ttl {
		return nil, false
	}
	a.IP = ip
	return &a, true
}

// PutASN caches an owner record.
func (s *Store) PutASN(a *ASNInfo) {
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO asn_cache(ip, asn, prefix, country, org, fetched) VALUES(?,?,?,?,?,?)`,
		a.IP, a.ASN, a.Prefix, a.Country, a.Org, nowUTC())
}

// ---------------------------------------------------------------- reporting queries

// AddrInfo is an address with its owner, for reports.
type AddrInfo struct {
	IP      string `json:"ip"`
	ASN     int    `json:"asn"`
	Org     string `json:"asn_org"`
	Country string `json:"country"`
}

// HostRow is one inventory row.
type HostRow struct {
	Root      string     `json:"target"`
	Host      string     `json:"host"`
	Sources   string     `json:"sources"`
	FirstSeen string     `json:"first_seen"`
	LastSeen  string     `json:"last_seen"`
	Addrs     []AddrInfo `json:"addresses"`
	CNAMEs    []string   `json:"cname"`
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Inventory returns known hosts with their current addresses. root=="" means all targets.
func (s *Store) Inventory(root, q string, limit int) ([]HostRow, int, error) {
	where := []string{"1=1"}
	var args []any
	if root != "" {
		where = append(where, "root=?")
		args = append(args, root)
	}
	if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
		where = append(where, `host LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(q)+"%")
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT root, host, sources, first_seen, last_seen FROM subdomains WHERE `+w+` ORDER BY root, host LIMIT ?`, append(args, limit)...) //nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	if err != nil {
		return nil, 0, err
	}
	var hosts []HostRow
	idx := map[string]int{}
	for rows.Next() {
		var h HostRow
		if err := rows.Scan(&h.Root, &h.Host, &h.Sources, &h.FirstSeen, &h.LastSeen); err != nil {
			_ = rows.Close()
			return nil, 0, err
		}
		idx[h.Host] = len(hosts)
		hosts = append(hosts, h)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, 0, err
	}

	asnMap := map[string]AddrInfo{}
	ar, err := s.db.Query(`SELECT ip, asn, country, org FROM asn_cache`)
	if err != nil {
		return nil, 0, err
	}
	for ar.Next() {
		var a AddrInfo
		if err := ar.Scan(&a.IP, &a.ASN, &a.Country, &a.Org); err != nil {
			_ = ar.Close()
			return nil, 0, err
		}
		asnMap[a.IP] = a
	}
	_ = ar.Close()

	rq := `SELECT host, rtype, value FROM records WHERE rtype IN ('A','AAAA','CNAME')`
	var rargs []any
	if root != "" {
		rq += ` AND root=?`
		rargs = append(rargs, root)
	}
	rr, err := s.db.Query(rq+` ORDER BY host, rtype, value`, rargs...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rr.Close() }()
	for rr.Next() {
		var host, rtype, val string
		if err := rr.Scan(&host, &rtype, &val); err != nil {
			return nil, 0, err
		}
		i, ok := idx[host]
		if !ok {
			continue
		}
		if rtype == "CNAME" {
			hosts[i].CNAMEs = append(hosts[i].CNAMEs, val)
			continue
		}
		a := AddrInfo{IP: val}
		if known, ok := asnMap[val]; ok {
			a = known
		}
		hosts[i].Addrs = append(hosts[i].Addrs, a)
	}
	return hosts, total, rr.Err()
}

// CertRow is one certificate row.
type CertRow struct {
	Root       string `json:"target"`
	CommonName string `json:"common_name"`
	Names      string `json:"names"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	FirstSeen  string `json:"first_seen"`
}

// ListCerts returns certificates for a domain (or all) newest first.
func (s *Store) ListCerts(root string, limit int) ([]CertRow, int, error) {
	where, args := "1=1", []any{}
	if root != "" {
		where, args = "root=?", []any{root}
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM certs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT root, COALESCE(common_name,''), COALESCE(names,''), COALESCE(issuer,''), COALESCE(not_before,''), COALESCE(not_after,''), first_seen
		FROM certs WHERE `+where+` ORDER BY first_seen DESC, crtsh_id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []CertRow
	for rows.Next() {
		var c CertRow
		if err := rows.Scan(&c.Root, &c.CommonName, &c.Names, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.FirstSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// Finding is a tracked issue with a stable key, severity and open/resolved/acknowledged status.
type Finding struct {
	ID                                                                           int64
	Key, Root, Kind, Severity, Host, Detail, Status, FirstSeen, LastSeen, Source string
	// Risk acceptance (status "ack") and analyst severity override.
	AckReason, AckBy, AckAt, AckUntil      string
	ScanSev, SevOverride, SevReason, SevBy string
	// Last "Confirm via active scan" result.
	VerifyState, VerifyBanner, VerifyAt, VerifyBy string
	// Corroboration (trust.go): level, the independent sources behind it, and an analyst's confirmation.
	Trust, TrustSources, ConfirmBy, ConfirmAt, ConfirmNote string
}

// ListFindings returns findings for a root ("" = all) filtered by status ("" = all), worst first.
func (s *Store) ListFindings(root, status string) ([]Finding, error) {
	where := []string{"1=1"}
	var args []any
	if root != "" {
		where = append(where, "root=?")
		args = append(args, root)
	}
	if status != "" {
		where = append(where, "status=?")
		args = append(args, status)
	}
	rows, err := s.db.Query(`SELECT id,key,root,kind,severity,host,detail,status,first_seen,last_seen,source,ack_reason,ack_by,ack_at,ack_until,scan_sev,sev_override,sev_reason,sev_by,verify_state,verify_banner,verify_at,verify_by,trust,trust_sources,confirm_by,confirm_at,confirm_note FROM findings WHERE `+strings.Join(where, " AND "), args...) //nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.Key, &f.Root, &f.Kind, &f.Severity, &f.Host, &f.Detail, &f.Status, &f.FirstSeen, &f.LastSeen, &f.Source,
			&f.AckReason, &f.AckBy, &f.AckAt, &f.AckUntil, &f.ScanSev, &f.SevOverride, &f.SevReason, &f.SevBy,
			&f.VerifyState, &f.VerifyBanner, &f.VerifyAt, &f.VerifyBy,
			&f.Trust, &f.TrustSources, &f.ConfirmBy, &f.ConfirmAt, &f.ConfirmNote); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := sevRank(out[i].Severity), sevRank(out[j].Severity); a != b {
			return a > b
		}
		if out[i].Root != out[j].Root {
			return out[i].Root < out[j].Root
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

// SetFindingVerification records the result of a "Confirm via active scan".
func (s *Store) SetFindingVerification(id int64, state, banner, by string) error {
	_, err := s.db.Exec(`UPDATE findings SET verify_state=?, verify_banner=?, verify_at=?, verify_by=? WHERE id=?`,
		state, truncate(banner, verifyBannerMax), nowUTC(), by, id)
	return err
}

// SetFindingStatus acknowledges, reopens or resolves a finding.
func (s *Store) SetFindingStatus(id int64, status string) error {
	if status != "open" && status != "ack" {
		return errors.New("invalid finding status")
	}
	if status == "open" {
		return s.ReopenFinding(id)
	}
	return s.AcceptRisk(id, "system", "acknowledged", "")
}

// EventFilter selects events for the Events page.
type EventFilter struct {
	Root, Kind, MinSeverity, Since string
	IncludeBaseline                bool
	Limit, Offset                  int
}

// ListEvents returns a filtered, paged slice of the change log.
func (s *Store) ListEvents(f EventFilter) ([]Event, int, error) {
	where := []string{"1=1"}
	var args []any
	if f.Root != "" {
		where = append(where, "root=?")
		args = append(args, f.Root)
	}
	if f.Kind != "" {
		where = append(where, "kind=?")
		args = append(args, f.Kind)
	}
	if f.Since != "" {
		where = append(where, "ts>=?")
		args = append(args, f.Since)
	}
	if !f.IncludeBaseline {
		where = append(where, "baseline=0")
	}
	if f.MinSeverity != "" {
		// Severity names are bound as parameters like every other value.
		var marks []string
		for sev, r := range severityRank {
			if r >= sevRank(f.MinSeverity) {
				marks = append(marks, "?")
				args = append(args, sev)
			}
		}
		where = append(where, "severity IN ("+strings.Join(marks, ",")+")")
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT id, ts, root, kind, severity, host, detail, notified, baseline FROM events WHERE `+w+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		var n, b int
		if err := rows.Scan(&e.ID, &e.TS, &e.Root, &e.Kind, &e.Severity, &e.Host, &e.Detail, &n, &b); err != nil {
			return nil, 0, err
		}
		e.Notified, e.Baseline = n == 1, b == 1
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Stats holds the dashboard counters.
type Stats struct {
	Targets, Enabled, Hosts, OpenFindings, HighFindings, Events24h, PendingEvents, Running int
	UnconfirmedFindings                                                                    int // open, from one third-party source only: not in OpenFindings
}

// Stats computes the dashboard counters.
func (s *Store) Stats() (Stats, error) {
	var st Stats
	day := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	qs := []struct {
		q    string
		dst  *int
		args []any
	}{
		{`SELECT COUNT(*) FROM targets`, &st.Targets, nil},
		{`SELECT COUNT(*) FROM targets WHERE enabled=1`, &st.Enabled, nil},
		{`SELECT COUNT(*) FROM targets WHERE last_status='running'`, &st.Running, nil},
		{`SELECT COUNT(*) FROM subdomains`, &st.Hosts, nil},
		{`SELECT COUNT(*) FROM findings WHERE status='open' AND ` + countedFinding, &st.OpenFindings, nil},
		{`SELECT COUNT(*) FROM findings WHERE status='open' AND severity='high' AND ` + countedFinding, &st.HighFindings, nil},
		{`SELECT COUNT(*) FROM findings WHERE status='open' AND NOT ` + countedFinding, &st.UnconfirmedFindings, nil},
		{`SELECT COUNT(*) FROM events WHERE baseline=0 AND ts>=?`, &st.Events24h, []any{day}},
		{`SELECT COUNT(*) FROM events WHERE notified=0`, &st.PendingEvents, nil},
	}
	for _, q := range qs {
		if err := s.db.QueryRow(q.q, q.args...).Scan(q.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

// TargetCounts returns per-root host counts and open-finding counts by severity.
func (s *Store) TargetCounts() (hosts map[string]int, findings map[string]map[string]int, err error) {
	hosts, findings = map[string]int{}, map[string]map[string]int{}
	rows, err := s.db.Query(`SELECT root, COUNT(*) FROM subdomains GROUP BY root`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r string
		var n int
		if err := rows.Scan(&r, &n); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		hosts[r] = n
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, nil, err
	}
	// The trust condition is countedFinding, written out so the query is one fixed string.
	fr, err := s.db.Query(`SELECT root, severity, COUNT(*) FROM findings WHERE status='open' AND trust NOT IN ('unconfirmed','disputed') GROUP BY root, severity`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = fr.Close() }()
	for fr.Next() {
		var r, sev string
		var n int
		if err := fr.Scan(&r, &sev, &n); err != nil {
			return nil, nil, err
		}
		if findings[r] == nil {
			findings[r] = map[string]int{}
		}
		findings[r][sev] = n
	}
	return hosts, findings, fr.Err()
}

// ---------------------------------------------------------------- transactional persistence (one tx per scan)

// Tx is a write transaction used by a scan so its results land atomically.
type Tx struct{ tx *sql.Tx }

// Begin starts a scan transaction.
func (s *Store) Begin() (*Tx, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx}, nil
}

// Commit makes the scan's changes permanent.
func (t *Tx) Commit() error { return t.tx.Commit() }

// Rollback discards the scan's changes (no-op after Commit).
func (t *Tx) Rollback() { _ = t.tx.Rollback() }

func (t *Tx) insertNew(q string, args ...any) (bool, error) {
	res, err := t.tx.Exec(q, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// AddSubdomain records a host and reports whether it is new.
func (t *Tx) AddSubdomain(root, host, sources, now string) (bool, error) {
	isNew, err := t.insertNew(`INSERT OR IGNORE INTO subdomains(root,host,sources,first_seen,last_seen) VALUES(?,?,?,?,?)`,
		root, host, sources, now, now)
	if err == nil && !isNew {
		_, err = t.tx.Exec(`UPDATE subdomains SET last_seen=?, sources=?, gone='' WHERE root=? AND host=?`, now, sources, root, host)
	}
	return isNew, err
}

// AddRecord records a DNS record and reports whether it is new.
func (t *Tx) AddRecord(root, host, rtype, value, now string) (bool, error) {
	st, err := t.SeeRecord(root, host, rtype, value, now)
	return st != recSame, err
}

// recState says what seeing a DNS record meant.
type recState int

const (
	recSame     recState = iota // already known and present
	recNew                      // never seen before
	recReturned                 // was reported removed, and is back
)

// SeeRecord notes that a record exists now: new records are added, a record that had been
// reported as removed is revived, and the missed-scan counter is reset.
func (t *Tx) SeeRecord(root, host, rtype, value, now string) (recState, error) {
	isNew, err := t.insertNew(`INSERT OR IGNORE INTO records(root,host,rtype,value,first_seen,last_seen) VALUES(?,?,?,?,?,?)`,
		root, host, rtype, value, now, now)
	if err != nil || isNew {
		if isNew {
			return recNew, nil
		}
		return recSame, err
	}
	var gone string
	if err := t.tx.QueryRow(`SELECT gone FROM records WHERE host=? AND rtype=? AND value=?`, host, rtype, value).Scan(&gone); err != nil {
		return recSame, err
	}
	if _, err := t.tx.Exec(`UPDATE records SET last_seen=?, misses=0, gone='' WHERE host=? AND rtype=? AND value=?`, now, host, rtype, value); err != nil {
		return recSame, err
	}
	if gone != "" {
		return recReturned, nil
	}
	return recSame, nil
}

// Missing is a record that was expected but not seen.
type Missing struct {
	Host, Type, Value string
	Gone              bool // reached the threshold in this call
}

// MissRecords counts a missed scan for every active record of the host and type whose value is
// not in present. Records that reach the threshold are marked removed and returned.
func (t *Tx) MissRecords(host, rtype string, present map[string]bool, threshold int, now string) ([]Missing, error) {
	rows, err := t.tx.Query(`SELECT value, misses FROM records WHERE host=? AND rtype=? AND gone=''`, host, rtype)
	if err != nil {
		return nil, err
	}
	type row struct {
		v string
		m int
	}
	var cand []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.v, &r.m); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if !present[r.v] {
			cand = append(cand, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	var gone []Missing
	for _, r := range cand {
		if r.m+1 >= threshold {
			if _, err := t.tx.Exec(`UPDATE records SET misses=?, gone=? WHERE host=? AND rtype=? AND value=?`, r.m+1, now, host, rtype, r.v); err != nil {
				return nil, err
			}
			gone = append(gone, Missing{Host: host, Type: rtype, Value: r.v, Gone: true})
		} else if _, err := t.tx.Exec(`UPDATE records SET misses=? WHERE host=? AND rtype=? AND value=?`, r.m+1, host, rtype, r.v); err != nil {
			return nil, err
		}
	}
	return gone, nil
}

// KnownHosts lists hosts that had a live DNS record at the last scan, so they can be checked
// again even when the passive sources no longer mention them.
func (s *Store) KnownHosts(root string, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT host FROM records WHERE root=? AND gone='' ORDER BY host LIMIT ?`, root, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostHasLiveRecords reports whether the host still has any active record.
func (t *Tx) HostHasLiveRecords(host string) (bool, error) {
	var n int
	err := t.tx.QueryRow(`SELECT COUNT(*) FROM records WHERE host=? AND gone=''`, host).Scan(&n)
	return n > 0, err
}

// MarkHostGone marks a subdomain as no longer existing (and reports whether this changed it).
func (t *Tx) MarkHostGone(root, host, now string) (bool, error) {
	res, err := t.tx.Exec(`UPDATE subdomains SET gone=? WHERE root=? AND host=? AND gone=''`, now, root, host)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AddCert records a certificate and reports whether it is new.
func (t *Tx) AddCert(root string, c CertInfo, now string) (bool, error) {
	return t.insertNew(`INSERT OR IGNORE INTO certs(key,root,common_name,names,issuer,not_before,not_after,crtsh_id,first_seen) VALUES(?,?,?,?,?,?,?,?,?)`,
		c.Key, root, c.CommonName, joinSorted(c.Names), c.Issuer, c.NotBefore, c.NotAfter, c.CrtShID, now)
}

// UpsertFinding records a finding. It returns true when the finding is new or has
// reappeared after being resolved, i.e. when an alert should be raised.
func (t *Tx) UpsertFinding(root, key, kind, severity, host, detail, source, now string) (bool, error) {
	isNew, err := t.insertNew(`INSERT OR IGNORE INTO findings(key,root,kind,severity,scan_sev,host,detail,status,first_seen,last_seen,source) VALUES(?,?,?,?,?,?,?,'open',?,?,?)`,
		key, root, kind, severity, severity, host, detail, now, now, source)
	if err != nil || isNew {
		return isNew, err
	}
	var status, have string
	if err := t.tx.QueryRow(`SELECT status, source FROM findings WHERE key=?`, key).Scan(&status, &have); err != nil {
		return false, err
	}
	src := mergeSources(have, source)
	if status == "resolved" {
		_, err = t.tx.Exec(`UPDATE findings SET status='open', scan_sev=?, severity=CASE WHEN sev_override<>'' THEN sev_override ELSE ? END, host=?, detail=?, last_seen=?, source=?,
			ack_reason='', ack_by='', ack_at='', ack_until='' WHERE key=?`, severity, severity, host, detail, now, source, key)
		return true, err
	}
	_, err = t.tx.Exec(`UPDATE findings SET scan_sev=?, severity=CASE WHEN sev_override<>'' THEN sev_override ELSE ? END, detail=?, last_seen=?, source=? WHERE key=?`, severity, severity, detail, now, src, key)
	return false, err
}

// mergeSources keeps a comma-separated, de-duplicated list of evidence sources.
func mergeSources(have, add string) string {
	if add == "" {
		return have
	}
	parts := splitCSV(have)
	for _, a := range splitCSV(add) {
		found := false
		for _, p := range parts {
			if p == a {
				found = true
			}
		}
		if !found {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, ", ")
}

// splitCSV splits a comma-separated column.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type openFinding struct {
	ID              int64
	Key, Kind, Host string
	Detail          string
}

// OpenFindings lists a domain's unresolved findings.
func (t *Tx) OpenFindings(root string) ([]openFinding, error) {
	rows, err := t.tx.Query(`SELECT id, key, kind, host, detail FROM findings WHERE root=? AND status IN ('open','ack')`, root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []openFinding
	for rows.Next() {
		var f openFinding
		if err := rows.Scan(&f.ID, &f.Key, &f.Kind, &f.Host, &f.Detail); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ResolveFinding marks a finding as no longer reproducing.
func (t *Tx) ResolveFinding(id int64, now string) error {
	_, err := t.tx.Exec(`UPDATE findings SET status='resolved', last_seen=? WHERE id=?`, now, id)
	return err
}

// AddEvent queues an event. silent events (baseline inventory) are stored as already notified.
func (t *Tx) AddEvent(e Event, silent bool) error {
	n, base, muted := 0, 0, 0
	if silent {
		n, base, muted = 1, 1, 1
	} else if e.NoAlert {
		n, muted = 1, 1
	}
	_, err := t.tx.Exec(`INSERT INTO events(ts,root,kind,severity,host,detail,notified,baseline,muted) VALUES(?,?,?,?,?,?,?,?,?)`,
		e.TS, e.Root, e.Kind, e.Severity, e.Host, e.Detail, n, base, muted)
	return err
}

// SetMeta stores a key/value pair inside the transaction.
func (t *Tx) SetMeta(k, v string) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)`, k, v)
	return err
}

// SetBaselined records that the domain's baseline scan completed.
func (t *Tx) SetBaselined(root, now string) error {
	_, err := t.tx.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)`, "baselined:"+root, now)
	return err
}
