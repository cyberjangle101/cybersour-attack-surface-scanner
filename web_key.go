package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// System health → Encryption key: how easm.key is protected, a recovery copy, and
// switching to protection by the Windows account (DPAPI).
//
// A key tied to a Windows account can only be opened by that account on that computer,
// which is what makes it safe without a passphrase. It also means a rebuilt or moved
// server cannot open the data, so administrators download a recovery copy (the key locked
// with a passphrase they choose) and keep it offline. Both actions hand out or change the
// key, so they need the administrator's password again (and a two-factor code when on),
// and are audited.

// metaKeyRecovery records when, and by whom, the last recovery copy was downloaded.
const metaKeyRecovery = "key_recovery"

// keyInfo is the Encryption key panel.
type keyInfo struct {
	Mode       string // keyPassphrase, keyWindows or keyPlain
	Account    string // the Windows account the agent runs as
	CanWindows bool   // switching to Windows-account protection is possible here
	Recovery   string // "2026-10-25T14:00:00Z by alice", or "" when never made
	NeedsCopy  bool   // protected by the Windows account and no recovery copy yet
	TwoFactor  bool   // the signed-in administrator must also give a code
}

func (s *Server) keyPanel(sess *Session) keyInfo {
	v := s.eng.vault
	k := keyInfo{Mode: v.Protection(), Account: windowsAccount()}
	k.CanWindows = dpapiSupported && k.Mode != keyWindows
	k.Recovery, _, _ = s.store.getMeta(metaKeyRecovery)
	k.NeedsCopy = k.Mode == keyWindows && k.Recovery == ""
	if u, err := s.store.GetUser(sess.UserID); err == nil {
		k.TwoFactor = u.Kind == kindLocal && u.TOTPOn
	}
	return k
}

// confirmIdentity asks the signed-in administrator to prove it is still them: their
// password (local or directory) and, for local accounts with two-factor on, a code.
// Repeated failures lock the account out of these actions for a while, like sign-in.
func (s *Server) confirmIdentity(r *http.Request, sess *Session) bool {
	key := "confirm:" + strings.ToLower(sess.Username)
	if s.adg.blocked(key) {
		return false
	}
	ok := false
	if u, _ := s.authenticate(r, sess.Username, r.PostFormValue("current")); u != nil && (u.ID == sess.UserID || strings.EqualFold(u.Username, sess.Username)) {
		ok = true
		if u.Kind == kindLocal && u.TOTPOn {
			step, good := totpVerify(u.TOTPSecret, r.PostFormValue("code"), time.Now(), s.store.TOTPLast(u.ID))
			ok = good && s.store.ClaimTOTPStep(u.ID, step)
		}
	}
	if ok {
		s.adg.ok(key)
	} else {
		s.adg.fail(key)
	}
	return ok
}

// keyRecovery downloads the master key locked with a recovery passphrase.
func (s *Server) keyRecovery(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func(kind, msg string) {
		s.flash(sess, kind, msg)
		http.Redirect(w, r, "/health#key", http.StatusSeeOther)
	}
	if !s.confirmIdentity(r, sess) {
		s.audit(sess, r, "key.recovery-copy", "", "refused: identity not confirmed")
		back("bad", "Your password (and code) did not match, so no recovery copy was made.")
		return
	}
	pass := r.PostFormValue("passphrase")
	if pass != r.PostFormValue("confirm") {
		back("bad", "The two recovery passphrases do not match.")
		return
	}
	data, err := s.eng.vault.RecoveryCopy(pass)
	if err != nil {
		back("bad", strings.ToUpper(err.Error()[:1])+err.Error()[1:]+".")
		return
	}
	now := nowUTC()
	if err := s.store.setMeta(metaKeyRecovery, now+" by "+sess.Username); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.audit(sess, r, "key.recovery-copy", "", "recovery copy of the encryption key downloaded")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="easm-key-recovery-%s.key"`, now[:10]))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- a binary key file sent as an octet-stream attachment, never rendered as HTML
}

// keyWindows re-protects the key with the Windows account the agent runs as.
func (s *Server) keyWindows(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func(kind, msg string) {
		s.flash(sess, kind, msg)
		http.Redirect(w, r, "/health#key", http.StatusSeeOther)
	}
	if !dpapiSupported {
		back("bad", "Protecting the key with the Windows account is only possible on Windows.")
		return
	}
	if !s.confirmIdentity(r, sess) {
		s.audit(sess, r, "key.protect-windows", "", "refused: identity not confirmed")
		back("bad", "Your password (and code) did not match, so the key was not changed.")
		return
	}
	if err := s.eng.vault.ProtectWithWindows(s.boot.KeyPath()); err != nil {
		back("bad", "The key could not be re-protected: "+err.Error())
		return
	}
	acct := windowsAccount()
	s.audit(sess, r, "key.protect-windows", acct, "the encryption key is now protected with this Windows account")
	back("good", "The encryption key is now protected with the Windows account "+acct+". Nothing needs to be typed at start-up. "+
		"If EASM_KEY_PASSPHRASE is set for this agent, remove it now. Download a recovery copy below and keep it offline.")
}
