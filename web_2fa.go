package main

import (
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// pendingLogin is a password-verified sign-in waiting for its second factor.
type pendingLogin struct {
	userID  int64
	expires time.Time
	tries   int
}

type pendingLogins struct {
	mu sync.Mutex
	m  map[string]*pendingLogin
}

const (
	pendingTTL   = 5 * time.Minute
	pendingTries = 5
)

func (p *pendingLogins) add(userID int64) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*pendingLogin{}
	}
	for k, v := range p.m {
		if time.Now().After(v.expires) {
			delete(p.m, k)
		}
	}
	tok := randToken(24)
	p.m[tok] = &pendingLogin{userID: userID, expires: time.Now().Add(pendingTTL)}
	return tok
}

// try returns the user for a ticket and counts the attempt; the ticket dies after too many.
func (p *pendingLogins) try(tok string) (int64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.m[tok]
	if v == nil || time.Now().After(v.expires) {
		delete(p.m, tok)
		return 0, false
	}
	if v.tries++; v.tries > pendingTries {
		delete(p.m, tok)
		return 0, false
	}
	return v.userID, true
}

func (p *pendingLogins) done(tok string) {
	p.mu.Lock()
	delete(p.m, tok)
	p.mu.Unlock()
}

func (s *Server) askSecondFactor(w http.ResponseWriter, r *http.Request, u *User, msg string) {
	status := http.StatusOK
	if msg != "" {
		status = http.StatusUnauthorized
	}
	s.render(w, r, nil, "login2fa", status, map[string]any{"Title": "Two-factor sign-in", "PreCSRF": s.preCSRF(w, r), "Error": msg,
		"Ticket": s.pending.add(u.ID)})
}

// login2FA checks the second factor of a pending sign-in.
func (s *Server) login2FA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if !s.checkPreCSRF(r) {
		http.Error(w, "invalid CSRF token; reload the page", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	restart := func(msg string) {
		s.render(w, r, nil, "login", http.StatusUnauthorized, map[string]any{"Title": "Sign in", "PreCSRF": s.preCSRF(w, r), "Error": msg})
	}
	ticket := r.PostFormValue("ticket")
	uid, ok := s.pending.try(ticket)
	if !ok {
		restart("That sign-in took too long or failed too many times. Please start again.")
		return
	}
	u, err := s.store.GetUser(uid)
	if err != nil || u.Disabled || !u.TOTPOn {
		s.pending.done(ticket)
		restart("Please sign in again.")
		return
	}
	keys := signInKeys(ip, u.Username)
	if s.throttled(keys) {
		s.pending.done(ticket)
		restart("Too many failed attempts. Try again in a few minutes.")
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	good, how := false, ""
	if step, okc := totpVerify(u.TOTPSecret, code, time.Now(), s.store.TOTPLast(u.ID)); okc && s.store.ClaimTOTPStep(u.ID, step) {
		good, how = true, "code"
	} else if rest, okr := useRecovery(u.Recovery, code); okr {
		if err := s.store.SetRecovery(u.ID, rest); err == nil {
			good, how = true, "recovery code"
		}
	}
	if !good {
		s.recordFail(keys)
		s.auditAs(u.Username, u.Kind, r, "login.fail", "", "wrong two-factor code")
		s.render(w, r, nil, "login2fa", http.StatusUnauthorized, map[string]any{"Title": "Two-factor sign-in", "PreCSRF": s.preCSRF(w, r),
			"Error": "That code was not accepted. Wait for the next code and try again.", "Ticket": ticket})
		return
	}
	s.pending.done(ticket)
	if how == "recovery code" {
		s.auditAs(u.Username, u.Kind, r, "2fa.recovery-used", "", "")
	}
	s.finishLogin(w, r, u)
}

// markNeed2FA makes every current session of an account without two-factor enrol first.
func (s *Server) markNeed2FA() {
	users, err := s.store.ListUsers()
	if err != nil {
		return
	}
	on := map[int64]bool{}
	for _, u := range users {
		on[u.ID] = u.TOTPOn || u.Kind != kindLocal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if !on[sess.UserID] {
			sess.Need2FA = true
		}
	}
}

// ---------------------------------------------------------------- account pages

func (s *Server) twoFactorView(w http.ResponseWriter, r *http.Request, sess *Session) {
	u, err := s.store.GetUser(sess.UserID)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	data := map[string]any{"Title": "Two-factor sign-in", "Nav": "account", "Directory": u.Kind != kindLocal, "On": u.TOTPOn,
		"Left": recoveryLeft(u.Recovery), "Enforced": sess.Need2FA}
	s.mu.Lock()
	codes := sess.Codes
	sess.Codes = nil
	s.mu.Unlock()
	data["Codes"] = codes
	if u.Kind == kindLocal && !u.TOTPOn {
		secret := ""
		s.mu.Lock()
		secret = sess.PendingTOTP
		s.mu.Unlock()
		if secret == "" {
			if secret, err = newTOTPSecret(); err != nil {
				s.serverError(w, r, sess, err)
				return
			}
			s.mu.Lock()
			sess.PendingTOTP = secret
			s.mu.Unlock()
		}
		qr, err := qrDataURI(totpURI(u.Username, secret))
		if err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		data["Secret"], data["QR"] = groupSecret(secret), template.URL(qr) //nolint:gosec // G203: a PNG data: URI we just generated // nosemgrep: go.lang.security.audit.xss.template-html-does-not-escape.unsafe-template-type -- html/template would block a data: URI given as a string
	}
	s.render(w, r, sess, "twofactor", http.StatusOK, data)
}

func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

func (s *Server) localUser(w http.ResponseWriter, r *http.Request, sess *Session) *User {
	u, err := s.store.GetUser(sess.UserID)
	if err != nil {
		s.serverError(w, r, sess, err)
		return nil
	}
	if u.Kind != kindLocal {
		s.flash(sess, "bad", "Two-factor for directory accounts is handled by your directory.")
		http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
		return nil
	}
	return u
}

// twoFactorEnable confirms the first code from the app and switches two-factor on.
func (s *Server) twoFactorEnable(w http.ResponseWriter, r *http.Request, sess *Session) {
	u := s.localUser(w, r, sess)
	if u == nil {
		return
	}
	s.mu.Lock()
	secret := sess.PendingTOTP
	s.mu.Unlock()
	back := func() { http.Redirect(w, r, "/account/2fa", http.StatusSeeOther) }
	if u.TOTPOn || secret == "" {
		back()
		return
	}
	step, ok := totpVerify(secret, r.PostFormValue("code"), time.Now(), 0)
	if !ok {
		s.flash(sess, "bad", "That code was not right. Check the code in your app (it changes every 30 seconds) and try again.")
		back()
		return
	}
	shown, stored, err := newRecoveryCodes()
	if err == nil {
		err = s.store.SetTOTP(u.ID, secret, stored, true)
	}
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.store.ClaimTOTPStep(u.ID, step)
	s.mu.Lock()
	sess.PendingTOTP, sess.Need2FA, sess.Codes = "", false, shown
	s.mu.Unlock()
	s.audit(sess, r, "2fa.enable", u.Username, "")
	s.flash(sess, "good", "Two-factor sign-in is on. Save your recovery codes now.")
	back()
}

// checkSecondProof asks for the current password and a current code before a sensitive change.
func (s *Server) checkSecondProof(u *User, r *http.Request) bool {
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(r.PostFormValue("current"))) != nil {
		return false
	}
	step, ok := totpVerify(u.TOTPSecret, r.PostFormValue("code"), time.Now(), s.store.TOTPLast(u.ID))
	return ok && s.store.ClaimTOTPStep(u.ID, step)
}

func (s *Server) twoFactorDisable(w http.ResponseWriter, r *http.Request, sess *Session) {
	u := s.localUser(w, r, sess)
	if u == nil {
		return
	}
	if !u.TOTPOn || !s.checkSecondProof(u, r) {
		s.flash(sess, "bad", "Enter your current password and a current code to turn two-factor off.")
	} else if st, _ := s.store.LoadSettings(); st.Require2FA {
		s.flash(sess, "bad", "Your administrator requires two-factor sign-in, so it cannot be turned off.")
	} else if err := s.store.SetTOTP(u.ID, "", "", false); err != nil {
		s.serverError(w, r, sess, err)
		return
	} else {
		s.audit(sess, r, "2fa.disable", u.Username, "")
		s.flash(sess, "good", "Two-factor sign-in is off.")
	}
	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

func (s *Server) twoFactorRecovery(w http.ResponseWriter, r *http.Request, sess *Session) {
	u := s.localUser(w, r, sess)
	if u == nil {
		return
	}
	if !u.TOTPOn || !s.checkSecondProof(u, r) {
		s.flash(sess, "bad", "Enter your current password and a current code to make new recovery codes.")
	} else {
		shown, stored, err := newRecoveryCodes()
		if err == nil {
			err = s.store.SetRecovery(u.ID, stored)
		}
		if err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		s.mu.Lock()
		sess.Codes = shown
		s.mu.Unlock()
		s.audit(sess, r, "2fa.recovery-new", u.Username, "")
		s.flash(sess, "good", "New recovery codes made. The old ones no longer work.")
	}
	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

// userReset2FA lets an administrator clear another account's two-factor (lost phone and recovery codes).
func (s *Server) userReset2FA(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, ok := pathID(r)
	u, err := s.store.GetUser(id)
	if !ok || err != nil || u.Kind != kindLocal {
		s.renderError(w, r, sess, http.StatusBadRequest, "Cannot reset", "Unknown user, or not a local account.")
		return
	}
	if err := s.store.SetTOTP(u.ID, "", "", false); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.dropSessionsFor(u.ID)
	s.audit(sess, r, "2fa.reset", u.Username, "by administrator")
	s.flash(sess, "good", "Two-factor reset for "+u.Username+". They are signed out and can set it up again.")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
