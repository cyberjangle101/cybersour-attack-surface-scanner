package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// audit records who did what. The actor is the signed-in session; a nil session means the
// action was not tied to a signed-in user (for example a failed sign-in).
func (s *Server) audit(sess *Session, r *http.Request, action, target, detail string) {
	actor, kind := "anonymous", ""
	if sess != nil {
		actor, kind = sess.Username, sess.Kind
	}
	ip := ""
	if r != nil {
		ip = clientIP(r)
	}
	if err := s.store.Audit(actor, kind, action, target, detail, ip); err != nil {
		s.log.Warn("audit write failed", "action", action, "err", err)
	}
}

// auditAs is audit for an explicit actor name (used before a session exists).
func (s *Server) auditAs(actor, kind string, r *http.Request, action, target, detail string) {
	ip := ""
	if r != nil {
		ip = clientIP(r)
	}
	if err := s.store.Audit(actor, kind, action, target, detail, ip); err != nil {
		s.log.Warn("audit write failed", "action", action, "err", err)
	}
}

// back sends the browser to the page it came from (a local path only) or the findings list.
func back(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, safeNext(r.PostFormValue("next"), "/findings"), http.StatusSeeOther)
}

// findingFromPath loads the finding named in the URL, or writes a 404.
func (s *Server) findingFromPath(w http.ResponseWriter, r *http.Request, sess *Session) (*Finding, bool) {
	id, ok := pathID(r)
	if ok {
		all, err := s.store.ListFindings("", "")
		if err != nil {
			s.serverError(w, r, sess, err)
			return nil, false
		}
		for i := range all {
			if all[i].ID == id {
				return &all[i], true
			}
		}
	}
	s.renderError(w, r, sess, http.StatusNotFound, "Not found", "")
	return nil, false
}

// findingAccept records an accepted risk with a mandatory reason and an optional review date.
func (s *Server) findingAccept(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, ok := s.findingFromPath(w, r, sess)
	if !ok {
		return
	}
	if err := s.store.AcceptRisk(f.ID, sess.Username, r.PostFormValue("reason"), strings.TrimSpace(r.PostFormValue("until"))); err != nil {
		s.flash(sess, "bad", "Not saved: "+err.Error()+".")
		back(w, r)
		return
	}
	s.audit(sess, r, "finding.accept", fmt.Sprintf("%s %s", f.Kind, f.Host), "reason: "+r.PostFormValue("reason")+"; review: "+r.PostFormValue("until"))
	s.flash(sess, "good", "Risk accepted. The finding stays on record and will not alert"+untilNote(r.PostFormValue("until"))+".")
	back(w, r)
}

// untilNote words the review date for the confirmation message.
func untilNote(until string) string {
	if until == "" {
		return ""
	}
	return " until " + until + ", when it reopens"
}

// findingReopen undoes an acceptance.
func (s *Server) findingReopen(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, ok := s.findingFromPath(w, r, sess)
	if !ok {
		return
	}
	if err := s.store.ReopenFinding(f.ID); err != nil {
		s.flash(sess, "bad", "Not reopened: "+err.Error()+".")
	} else {
		s.audit(sess, r, "finding.reopen", fmt.Sprintf("%s %s", f.Kind, f.Host), "was accepted by "+f.AckBy+": "+f.AckReason)
		s.flash(sess, "good", "Finding reopened.")
	}
	back(w, r)
}

// findingSeverity changes a finding's severity (or restores the scanner's) with a recorded reason.
func (s *Server) findingSeverity(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, ok := s.findingFromPath(w, r, sess)
	if !ok {
		return
	}
	sev := strings.ToLower(strings.TrimSpace(r.PostFormValue("severity")))
	if sev == "scanner" {
		sev = ""
	}
	if err := s.store.OverrideSeverity(f.ID, sev, sess.Username, r.PostFormValue("reason")); err != nil {
		s.flash(sess, "bad", "Not saved: "+err.Error()+".")
	} else {
		to := sev
		if to == "" {
			to = "scanner default (" + f.ScanSev + ")"
		}
		s.audit(sess, r, "finding.severity", fmt.Sprintf("%s %s", f.Kind, f.Host), fmt.Sprintf("%s -> %s; reason: %s", f.Severity, to, r.PostFormValue("reason")))
		s.flash(sess, "good", "Severity updated.")
	}
	back(w, r)
}

// ---------------------------------------------------------------- users: role and state

// userSetRole changes another account's role. The last administrator cannot be demoted.
func (s *Server) userSetRole(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, ok := pathID(r)
	role := r.PostFormValue("role")
	u, err := s.store.GetUser(id)
	if !ok || err != nil || !validRole(role) {
		s.renderError(w, r, sess, http.StatusBadRequest, "Cannot change role", "Unknown user or role.")
		return
	}
	if u.Kind == kindADGroup {
		s.flash(sess, "bad", u.Username+" gets their role from a directory group. Change the group mapping, or add them as an explicit directory user.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	if u.Role == RoleAdmin && role != RoleAdmin {
		if n, _ := s.store.CountAdmins(); n <= 1 {
			s.flash(sess, "bad", "There must always be at least one administrator.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
	}
	if err := s.store.SetUserRole(id, role); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.dropSessionsFor(id)
	s.audit(sess, r, "user.role", u.Username, u.Role+" -> "+role)
	s.flash(sess, "good", fmt.Sprintf("%s is now %s. Their active sessions were ended.", u.Username, roleLabel(role)))
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// userDisable blocks or re-allows an account. You cannot disable yourself or the last administrator.
func (s *Server) userDisable(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, ok := pathID(r)
	u, err := s.store.GetUser(id)
	if !ok || err != nil {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "")
		return
	}
	disable := r.PostFormValue("disable") == "1"
	if disable {
		if id == sess.UserID {
			s.flash(sess, "bad", "You cannot disable your own account.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
		if n, _ := s.store.CountAdmins(); u.Role == RoleAdmin && u.Kind != kindADGroup && n <= 1 {
			s.flash(sess, "bad", "There must always be at least one enabled administrator.")
			http.Redirect(w, r, "/users", http.StatusSeeOther)
			return
		}
	}
	if err := s.store.SetUserDisabled(id, disable); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	if disable {
		s.dropSessionsFor(id)
	}
	s.audit(sess, r, map[bool]string{true: "user.disable", false: "user.enable"}[disable], u.Username, "")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// ---------------------------------------------------------------- audit page

// auditFilter reads the audit page filters from the query string.
func auditFilterFrom(r *http.Request) AuditFilter {
	q := r.URL.Query()
	f := AuditFilter{Actor: strings.TrimSpace(q.Get("actor")), Action: strings.TrimSpace(q.Get("action"))}
	if d, err := strconv.Atoi(q.Get("days")); err == nil && d > 0 && d <= 3650 {
		f.Since = time.Now().UTC().AddDate(0, 0, -d).Format(time.RFC3339)
	}
	return f
}

const auditPageSize = 100

// auditView shows the audit trail.
func (s *Server) auditView(w http.ResponseWriter, r *http.Request, sess *Session) {
	f := auditFilterFrom(r)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	f.Limit, f.Offset = auditPageSize, (page-1)*auditPageSize
	list, total, err := s.store.ListAudit(f)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	pages := (total + auditPageSize - 1) / auditPageSize
	s.render(w, r, sess, "audit", http.StatusOK, map[string]any{"Title": "Audit log", "Nav": "audit", "Entries": list, "Total": total,
		"Page": page, "Pages": pages, "Actor": f.Actor, "Action": f.Action, "Days": r.URL.Query().Get("days"),
		"Query": "actor=" + urlQ(f.Actor) + "&action=" + urlQ(f.Action) + "&days=" + urlQ(r.URL.Query().Get("days"))})
}

// auditCSV exports the filtered audit trail.
func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request, sess *Session) {
	f := auditFilterFrom(r)
	f.Limit = 100000
	list, _, err := s.store.ListAudit(f)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.audit(sess, r, "audit.export", "csv", fmt.Sprintf("%d rows", len(list)))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-audit-`+time.Now().Format("20060102")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time_utc", "actor", "auth", "action", "target", "detail", "ip"})
	for _, a := range list {
		_ = cw.Write([]string{a.TS, csvSafe(a.Actor), a.Kind, a.Action, csvSafe(a.Target), csvSafe(a.Detail), a.IP})
	}
	cw.Flush()
}

// urlQ escapes a value for use in a query string.
func urlQ(v string) string { return url.QueryEscape(v) }
