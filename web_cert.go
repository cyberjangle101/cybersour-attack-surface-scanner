package main

import (
	"net/http"
	"strings"
)

// certView describes the web server's certificate for the Settings page.
func (s *Server) certView() map[string]any {
	if s.certs == nil {
		// Either a certificate is configured by file, or HTTPS is off.
		switch {
		case s.boot != nil && s.boot.UsesTLS():
			return map[string]any{"ByFile": true, "File": s.boot.TLSCert}
		default:
			return map[string]any{"Off": true}
		}
	}
	return map[string]any{"Info": s.certs.Info()}
}

// certUpload installs a certificate chain and private key supplied as PEM text.
func (s *Server) certUpload(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func(kind, msg string) {
		s.flash(sess, kind, msg)
		http.Redirect(w, r, "/settings#certificate", http.StatusSeeOther)
	}
	if s.certs == nil {
		back("bad", "The certificate is set in the config file (tls_cert / tls_key), or HTTPS is off, so it cannot be changed here.")
		return
	}
	info, warns, err := s.certs.InstallCustom(r.PostFormValue("cert_pem"), r.PostFormValue("key_pem"))
	if err != nil {
		s.audit(sess, r, "tls.upload.rejected", "", err.Error())
		back("bad", "Certificate not installed: "+err.Error()+". The previous certificate is still in use.")
		return
	}
	s.audit(sess, r, "tls.upload", info.Subject, "sha256 "+info.Fingerprint+", valid until "+info.NotAfter.Format("2006-01-02"))
	s.log.Info("TLS certificate uploaded", "by", sess.Username, "subject", info.Subject)
	msg := "Certificate installed. New connections use it straight away; no restart is needed."
	kind := "good"
	if len(warns) > 0 {
		msg += " Please note: " + strings.Join(warns, " ")
		kind = "warn"
	}
	back(kind, msg)
}

// certRemove goes back to the automatic self-signed certificate.
func (s *Server) certRemove(w http.ResponseWriter, r *http.Request, sess *Session) {
	if s.certs == nil {
		s.flash(sess, "bad", "There is no uploaded certificate to remove.")
	} else if err := s.certs.RemoveCustom(); err != nil {
		s.serverError(w, r, sess, err)
		return
	} else {
		s.audit(sess, r, "tls.remove", "", "returned to the self-signed certificate")
		s.flash(sess, "good", "The uploaded certificate was removed. The agent now uses its own self-signed certificate, and browsers will warn again.")
	}
	http.Redirect(w, r, "/settings#certificate", http.StatusSeeOther)
}
