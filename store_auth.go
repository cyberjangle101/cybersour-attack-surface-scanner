package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------- audit log

// AuditEntry is one line of the audit trail: who did what, to what, from where.
type AuditEntry struct {
	ID                                          int64
	TS, Actor, Kind, Action, Target, Detail, IP string
}

// Audit appends an entry. Failures are returned but callers normally only log them:
// an audit write must never block the action that is being recorded.
func (s *Store) Audit(actor, kind, action, target, detail, ip string) error {
	_, err := s.db.Exec(`INSERT INTO audit(ts,actor,kind,action,target,detail,ip) VALUES(?,?,?,?,?,?,?)`,
		nowUTC(), clip(actor, 80), kind, clip(action, 60), clip(target, 200), clip(detail, 1000), clip(ip, 64))
	return err
}

// clip shortens s to at most n bytes (on a rune boundary) so log fields stay bounded.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// AuditFilter selects audit entries.
type AuditFilter struct {
	Actor, Action, Since string // Action matches as a prefix ("user." matches "user.create")
	Limit, Offset        int
}

// ListAudit returns a filtered page of the audit trail, newest first, and the total match count.
func (s *Store) ListAudit(f AuditFilter) ([]AuditEntry, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.Actor != "" {
		where = append(where, "actor=? COLLATE NOCASE")
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where = append(where, `action LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(f.Action)+"%")
	}
	if f.Since != "" {
		where = append(where, "ts>=?")
		args = append(args, f.Since)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE `+w, args...).Scan(&total); err != nil { //nolint:gosec // G202: fixed fragments, bound values
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	//nolint:gosec // G202: SQL text is built only from fixed fragments; every value is a bound parameter
	rows, err := s.db.Query(`SELECT id,ts,actor,kind,action,target,detail,ip FROM audit WHERE `+w+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Kind, &a.Action, &a.Target, &a.Detail, &a.IP); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// PruneAudit deletes audit entries older than days (0 keeps everything).
func (s *Store) PruneAudit(days int) error {
	if days <= 0 {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM audit WHERE ts<?`, time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339))
	return err
}

// ---------------------------------------------------------------- finding triage

// AcceptRisk marks a finding as an accepted risk. A reason is mandatory; until (YYYY-MM-DD)
// optionally makes the acceptance expire, after which the finding reopens and alerts again.
func (s *Store) AcceptRisk(id int64, by, reason, until string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 {
		return errors.New("give a reason for accepting the risk")
	}
	if until != "" {
		d, err := time.Parse("2006-01-02", until)
		if err != nil {
			return errors.New("the review date must look like 2026-12-31")
		}
		if !d.After(time.Now().UTC().Truncate(24 * time.Hour)) {
			return errors.New("the review date must be in the future")
		}
		if d.After(time.Now().UTC().AddDate(2, 0, 0)) {
			return errors.New("risk can be accepted for at most two years")
		}
	}
	res, err := s.db.Exec(`UPDATE findings SET status='ack', ack_reason=?, ack_by=?, ack_at=?, ack_until=? WHERE id=? AND status<>'resolved'`,
		clip(reason, 500), by, nowUTC(), until, id)
	return affected(res, err)
}

// ReopenFinding returns an accepted finding to the open list and clears the acceptance.
func (s *Store) ReopenFinding(id int64) error {
	res, err := s.db.Exec(`UPDATE findings SET status='open', ack_reason='', ack_by='', ack_at='', ack_until='' WHERE id=? AND status='ack'`, id)
	return affected(res, err)
}

// OverrideSeverity sets an analyst's severity for a finding in place of the scanner's. An empty
// severity removes the override. The override survives later scans of the same finding.
func (s *Store) OverrideSeverity(id int64, sev, by, reason string) error {
	if sev == "" {
		res, err := s.db.Exec(`UPDATE findings SET severity=scan_sev, sev_override='', sev_reason='', sev_by='' WHERE id=?`, id)
		return affected(res, err)
	}
	if _, ok := severityRank[sev]; !ok {
		return errors.New("unknown severity")
	}
	if len(strings.TrimSpace(reason)) < 3 {
		return errors.New("give a reason for changing the severity")
	}
	res, err := s.db.Exec(`UPDATE findings SET severity=?, sev_override=?, sev_reason=?, sev_by=? WHERE id=?`, sev, sev, clip(strings.TrimSpace(reason), 500), by, id)
	return affected(res, err)
}

// affected turns "no row matched" into an error.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("finding not found, already resolved, or not in the expected state")
	}
	return nil
}

// ExpireAcceptances reopens findings whose accepted-risk review date has passed and records an
// alertable event for each. It returns how many were reopened.
func (s *Store) ExpireAcceptances(now time.Time) (int, error) {
	today := now.UTC().Format("2006-01-02")
	rows, err := s.db.Query(`SELECT id,root,host,kind,severity,detail,ack_by,ack_reason FROM findings WHERE status='ack' AND ack_until<>'' AND ack_until<=?`, today)
	if err != nil {
		return 0, err
	}
	type exp struct {
		id                                        int64
		root, host, kind, sev, detail, by, reason string
	}
	var list []exp
	for rows.Next() {
		var e exp
		if err := rows.Scan(&e.id, &e.root, &e.host, &e.kind, &e.sev, &e.detail, &e.by, &e.reason); err != nil {
			_ = rows.Close()
			return 0, err
		}
		list = append(list, e)
	}
	_ = rows.Close() // finish the cursor before the next statement (single connection)
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, e := range list {
		if _, err := s.db.Exec(`UPDATE findings SET status='open', ack_reason='', ack_by='', ack_at='', ack_until='' WHERE id=?`, e.id); err != nil {
			return 0, err
		}
		detail := fmt.Sprintf("Accepted risk expired (accepted by %s: %q), finding is open again: %s", e.by, e.reason, e.detail)
		if _, err := s.db.Exec(`INSERT INTO events(ts,root,kind,severity,host,detail,notified,baseline) VALUES(?,?,?,?,?,?,0,0)`,
			nowUTC(), e.root, "finding-reopened", e.sev, e.host, detail); err != nil {
			return 0, err
		}
		_ = s.Audit("system", "system", "finding.risk_expired", fmt.Sprintf("finding %d", e.id), e.detail, "")
	}
	return len(list), nil
}

// ---------------------------------------------------------------- API tokens

// APIToken is a long-lived credential for scripts and integrations. Only a hash is stored.
type APIToken struct {
	ID                                                    int64
	Name, Role, Prefix, Created, Expires, LastUsed, Owner string
	OwnerID                                               int64
	Revoked                                               bool
}

// hashToken returns the SHA-256 of a token. Tokens are 256-bit random values, so a fast
// hash is appropriate (there is nothing to brute-force, unlike a password).
func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// CreateToken stores a new token for a user. role may not exceed the owner's own role.
func (s *Store) CreateToken(ownerID int64, name, role, plain, expires string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO api_tokens(owner_id,name,role,hash,prefix,created,expires,last_used,revoked) VALUES(?,?,?,?,?,?,?,'',0)`,
		ownerID, clip(strings.TrimSpace(name), 80), role, hashToken(plain), plain[:8], nowUTC(), expires)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// TokenByPlain finds a live token and the owning account.
func (s *Store) TokenByPlain(plain string) (*APIToken, *User, error) {
	var t APIToken
	var revoked int
	err := s.db.QueryRow(`SELECT id,owner_id,name,role,prefix,created,expires,last_used,revoked FROM api_tokens WHERE hash=?`, hashToken(plain)).
		Scan(&t.ID, &t.OwnerID, &t.Name, &t.Role, &t.Prefix, &t.Created, &t.Expires, &t.LastUsed, &revoked)
	if err != nil {
		return nil, nil, err
	}
	t.Revoked = revoked != 0
	if t.Revoked {
		return nil, nil, errors.New("token revoked")
	}
	if t.Expires != "" {
		if e, perr := time.Parse("2006-01-02", t.Expires); perr == nil && !time.Now().UTC().Before(e.AddDate(0, 0, 1)) {
			return nil, nil, errors.New("token expired")
		}
	}
	u, err := s.GetUser(t.OwnerID)
	if err != nil {
		return nil, nil, err
	}
	if u.Disabled {
		return nil, nil, errors.New("account disabled")
	}
	return &t, u, nil
}

// TouchToken records that a token was just used (at most once per minute per token).
func (s *Store) TouchToken(id int64) {
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used=? WHERE id=? AND (last_used='' OR last_used<?)`,
		nowUTC(), id, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
}

// ListTokens returns tokens (without secrets). ownerID 0 lists everyone's.
func (s *Store) ListTokens(ownerID int64) ([]APIToken, error) {
	q := `SELECT t.id,t.owner_id,u.username,t.name,t.role,t.prefix,t.created,t.expires,t.last_used,t.revoked FROM api_tokens t JOIN users u ON u.id=t.owner_id`
	var args []any
	if ownerID != 0 {
		q += ` WHERE t.owner_id=?`
		args = append(args, ownerID)
	}
	rows, err := s.db.Query(q+` ORDER BY t.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var rev int
		if err := rows.Scan(&t.ID, &t.OwnerID, &t.Owner, &t.Name, &t.Role, &t.Prefix, &t.Created, &t.Expires, &t.LastUsed, &rev); err != nil {
			return nil, err
		}
		t.Revoked = rev != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken disables a token. ownerID restricts it to the owner's tokens (0 = any).
func (s *Store) RevokeToken(id, ownerID int64) error {
	q, args := `UPDATE api_tokens SET revoked=1 WHERE id=?`, []any{id}
	if ownerID != 0 {
		q += ` AND owner_id=?`
		args = append(args, ownerID)
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("token not found")
	}
	return nil
}

// ---------------------------------------------------------------- account state

// SetUserRole changes an account's role.
func (s *Store) SetUserRole(id int64, role string) error {
	if !validRole(role) {
		return errors.New("unknown role")
	}
	_, err := s.db.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

// SetUserDisabled blocks or re-allows sign-in for an account without deleting it.
func (s *Store) SetUserDisabled(id int64, disabled bool) error {
	n := 0
	if disabled {
		n = 1
	}
	_, err := s.db.Exec(`UPDATE users SET disabled=? WHERE id=?`, n, id)
	return err
}

// TouchLogin records the time of a successful sign-in.
func (s *Store) TouchLogin(id int64) {
	_, _ = s.db.Exec(`UPDATE users SET last_login=? WHERE id=?`, nowUTC(), id)
}

// ClaimTOTPStep records that a one-time code for this time step was used. It returns false if that
// step (or a later one) was already used, which makes every code single-use even across restarts.
func (s *Store) ClaimTOTPStep(id, step int64) bool {
	res, err := s.db.Exec(`UPDATE users SET totp_last=? WHERE id=? AND totp_last<?`, step, id, step)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// TOTPLast returns the newest time step already used by an account.
func (s *Store) TOTPLast(id int64) int64 {
	var n int64
	_ = s.db.QueryRow(`SELECT totp_last FROM users WHERE id=?`, id).Scan(&n)
	return n
}

// SetRecovery replaces the stored recovery-code hashes.
func (s *Store) SetRecovery(id int64, stored string) error {
	sealed := ""
	var err error
	if stored != "" {
		if sealed, err = s.sealHash(stored); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`UPDATE users SET recovery=? WHERE id=?`, sealed, id)
	return err
}

// SetTOTP stores (sealed) the two-factor secret and recovery-code hashes, or clears them.
func (s *Store) SetTOTP(id int64, secret, recovery string, on bool) error {
	var err error
	if secret != "" {
		if secret, err = s.sealHash(secret); err != nil {
			return err
		}
	}
	if recovery != "" {
		if recovery, err = s.sealHash(recovery); err != nil {
			return err
		}
	}
	n := 0
	if on {
		n = 1
	}
	_, err = s.db.Exec(`UPDATE users SET totp_secret=?, recovery=?, totp_on=? WHERE id=?`, secret, recovery, n, id)
	return err
}

// SetRefresh asks for the next scan of a domain to ignore cached exposure intelligence.
func (s *Store) SetRefresh(domain string, on bool) error {
	v := ""
	if on {
		v = "1"
	}
	return s.setMeta("refresh:"+domain, v)
}

// TakeRefresh reports (and clears) the one-shot "ignore the cache" request for a domain.
func (s *Store) TakeRefresh(domain string) bool {
	v, ok, err := s.getMeta("refresh:" + domain)
	if err != nil || !ok || v == "" {
		return false
	}
	_ = s.setMeta("refresh:"+domain, "")
	return true
}

// SetActiveOnce asks for the next scan of a domain to run the active checks even
// when they are switched off in Settings (the "Scan now with active checks" button).
func (s *Store) SetActiveOnce(domain string) error {
	return s.setMeta("active:"+domain, "1")
}

// TakeActiveOnce reports (and clears) the one-shot active-checks request for a domain.
func (s *Store) TakeActiveOnce(domain string) bool {
	v, ok, err := s.getMeta("active:" + domain)
	if err != nil || !ok || v == "" {
		return false
	}
	_ = s.setMeta("active:"+domain, "")
	return true
}

// FindUserFold finds an account by name ignoring case (directory names are case-insensitive).
func (s *Store) FindUserFold(name string) (*User, error) {
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE lower(username)=lower(?) ORDER BY id LIMIT 1`, name).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetUser(id)
}
