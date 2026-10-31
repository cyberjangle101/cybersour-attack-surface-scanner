package main

import (
	"database/sql"
	"errors"
	"strings"
)

// Corroboration of findings built from third-party exposure data.
//
// Exposure intelligence (Shodan InternetDB in particular) is often stale or wrong:
// a port closed weeks ago, a CVE guessed from a version string. A finding raised
// only from such data is "unconfirmed" until a second, independent source reports
// the same thing; then it is "trusted". Only trusted findings are alerted and
// counted; unconfirmed ones stay visible, marked, so they can be checked.
//
// Independent sources are:
//   - Shodan: InternetDB and the Shodan API are views of one dataset, so together they count once;
//   - Censys, which scans the internet on its own;
//   - an active check by this agent (a TCP connection to the port, for exposed services);
//   - an analyst who confirmed the finding by hand, with a note saying how.
//
// Findings the agent observes itself (DNS, TLS, HTTP checks) are first-hand and
// need no corroboration; their trust level is empty.

const (
	trustTrusted     = "trusted"     // two or more independent sources agree
	trustUnconfirmed = "unconfirmed" // one source only
	trustDisputed    = "disputed"    // one source, and the agent's own check could not reach the port
)

// countedFinding is the SQL condition for a finding that counts in totals and
// risk figures: first-hand or trusted, not unconfirmed or disputed.
const countedFinding = `trust NOT IN ('unconfirmed','disputed')`

// thirdPartyKinds are the finding kinds raised only from exposure-intelligence data.
var thirdPartyKinds = map[string]bool{"exposed-service": true, "known-vuln": true, "ip-flagged": true, "eol-software": true}

// sourceFamily names the dataset behind an evidence source label.
func sourceFamily(label string) string {
	l := strings.ToLower(label)
	switch {
	case strings.Contains(l, "shodan"), l == "internetdb":
		return "Shodan"
	case strings.Contains(l, "censys"):
		return "Censys"
	}
	return strings.TrimSpace(label)
}

// corroborate works out a third-party finding's trust level and the independent
// sources behind it. sources is the evidence of the latest scan (comma-separated
// labels). Findings of other kinds get an empty level.
func corroborate(kind, sources, verifyState, confirmedBy string) (string, []string) {
	if !thirdPartyKinds[kind] {
		return "", nil
	}
	var fams []string
	add := func(f string) {
		for _, x := range fams {
			if x == f {
				return
			}
		}
		fams = append(fams, f)
	}
	for _, s := range splitCSV(sources) {
		add(sourceFamily(s))
	}
	if kind == "exposed-service" && verifyState == verifyOpen {
		add("Active check")
	}
	if confirmedBy != "" {
		add("Analyst (" + confirmedBy + ")")
	}
	switch {
	case len(fams) >= 2:
		return trustTrusted, fams
	case kind == "exposed-service" && (verifyState == verifyClosed || verifyState == verifyFiltered):
		return trustDisputed, fams
	}
	return trustUnconfirmed, fams
}

// sqlRunner is what updateTrust needs from a *sql.DB or a *sql.Tx.
type sqlRunner interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// updateTrust recomputes the trust level of the finding with this key. current,
// when set, is the evidence of the scan that just raised it; otherwise the
// evidence stored by the last scan is used. upgraded reports a finding that was
// unconfirmed or disputed and is now trusted, which is when it should be alerted.
func updateTrust(db sqlRunner, key, current string) (level string, upgraded bool, err error) {
	var kind, source, cur, verify, confirm, old string
	err = db.QueryRow(`SELECT kind, source, trust_src, verify_state, confirm_by, trust FROM findings WHERE key=?`, key).
		Scan(&kind, &source, &cur, &verify, &confirm, &old)
	if err != nil {
		return "", false, err
	}
	if current != "" {
		cur = current
	}
	if cur == "" {
		cur = source // a finding from before trust levels existed
	}
	level, fams := corroborate(kind, cur, verify, confirm)
	if _, err = db.Exec(`UPDATE findings SET trust=?, trust_sources=?, trust_src=? WHERE key=?`, level, strings.Join(fams, ", "), cur, key); err != nil {
		return "", false, err
	}
	return level, level == trustTrusted && (old == trustUnconfirmed || old == trustDisputed), nil
}

// UpdateTrust is updateTrust inside a scan's transaction.
func (t *Tx) UpdateTrust(key, current string) (string, bool, error) {
	return updateTrust(t.tx, key, current)
}

// backfillTrust gives findings stored by an earlier version their trust level.
func backfillTrust(db *sql.DB) error {
	rows, err := db.Query(`SELECT key FROM findings WHERE trust='' AND kind IN ('exposed-service','known-vuln','ip-flagged','eol-software')`)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			_ = rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	err = rows.Err()
	_ = rows.Close() // one connection: the cursor must be closed before the updates
	if err != nil {
		return err
	}
	for _, k := range keys {
		if _, _, err := updateTrust(db, k, ""); err != nil {
			return err
		}
	}
	return nil
}

// RecordVerification stores the result of an active check on a finding and
// re-evaluates its trust. When the check makes it trusted, an alerting event says so.
func (s *Store) RecordVerification(f *Finding, state, banner, by string) (string, error) {
	if err := s.SetFindingVerification(f.ID, state, banner, by); err != nil {
		return "", err
	}
	return s.retrust(f, "active check, "+by)
}

// SetFindingConfirmation records (or, with by empty, removes) an analyst's
// confirmation of a third-party finding, with a note saying how it was confirmed.
func (s *Store) SetFindingConfirmation(f *Finding, by, note string) (string, error) {
	if !thirdPartyKinds[f.Kind] {
		return "", errors.New("only findings from exposure data need confirming")
	}
	at := ""
	if by != "" {
		at = nowUTC()
	}
	if _, err := s.db.Exec(`UPDATE findings SET confirm_by=?, confirm_at=?, confirm_note=? WHERE id=?`, by, at, truncate(note, 500), f.ID); err != nil {
		return "", err
	}
	return s.retrust(f, "confirmation by "+by)
}

// retrust recomputes a finding's trust after a check or confirmation and queues an
// alert when it has just become trusted.
func (s *Store) retrust(f *Finding, how string) (string, error) {
	level, upgraded, err := updateTrust(s.db, f.Key, "")
	if err != nil || !upgraded || f.Status != "open" {
		return level, err
	}
	tx, err := s.Begin()
	if err != nil {
		return level, err
	}
	defer tx.Rollback()
	if err := tx.AddEvent(Event{TS: nowUTC(), Root: f.Root, Kind: f.Kind, Severity: f.Severity, Host: f.Host,
		Detail: "Now confirmed by a second source (" + how + "): " + f.Detail}, false); err != nil {
		return level, err
	}
	return level, tx.Commit()
}

// trustLabel is the wording of a trust level on the findings pages.
func trustLabel(level string) string {
	switch level {
	case trustTrusted:
		return "Trusted"
	case trustUnconfirmed:
		return "Unconfirmed"
	case trustDisputed:
		return "Disputed"
	}
	return ""
}
