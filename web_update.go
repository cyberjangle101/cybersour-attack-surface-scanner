package main

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// updateCheck asks GitHub for the newest release now (System health → Updates).
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st := s.eng.CheckForUpdate(ctx)
	switch {
	case st.Err != "":
		s.flash(sess, "warn", "Could not check for updates: "+st.Err)
	case st.Available:
		s.flash(sess, "good", "Version "+st.Latest.Version+" is available.")
	default:
		s.flash(sess, "good", "You are running the latest version.")
	}
	http.Redirect(w, r, "/health#updates", http.StatusSeeOther)
}

// updateInstall downloads, verifies and installs the release the last check found,
// after taking a backup, then restarts into it where that can be done safely.
func (s *Server) updateInstall(w http.ResponseWriter, r *http.Request, sess *Session) {
	st := s.eng.UpdateState()
	want := r.PostFormValue("version")
	if !st.Available || st.Latest == nil || st.Latest.Version != want {
		s.flash(sess, "warn", "Check for updates again first; the version offered has changed.")
		http.Redirect(w, r, "/health#updates", http.StatusSeeOther)
		return
	}
	exeFn := s.exePath
	if exeFn == nil {
		exeFn = os.Executable
	}
	exe, err := exeFn()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		s.renderError(w, r, sess, http.StatusInternalServerError, "Update not installed", "Cannot find this program's file: "+err.Error())
		return
	}
	s.audit(sess, r, "update.start", st.Latest.Version, "from "+version)

	// A backup first: the new version may upgrade the database on its first start.
	if s.eng.vault != nil && s.eng.dataDir != "" {
		if _, err := s.eng.BackupNow(s.store.LoadBackupConfig(s.eng.dataDir), "before update to "+st.Latest.Version); err != nil {
			s.audit(sess, r, "update.failed", st.Latest.Version, "backup: "+err.Error())
			s.renderError(w, r, sess, http.StatusInternalServerError, "Update not installed",
				"The backup taken before updating failed, so nothing was changed: "+err.Error())
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	u := s.eng.updater()
	file, err := u.Fetch(ctx, st.Latest, filepath.Dir(exe))
	if err == nil {
		if err = ReplaceExecutable(exe, file); err != nil {
			_ = os.Remove(file)
		}
	}
	if err != nil {
		s.audit(sess, r, "update.failed", st.Latest.Version, err.Error())
		hint := ""
		if errors.Is(err, fs.ErrPermission) {
			// A service account is deliberately not allowed to change its own program file.
			hint = " This agent's account may not change the program file (as intended for a service). " +
				"Update it from an elevated prompt on this computer: easm-agent -update"
		}
		s.renderError(w, r, sess, http.StatusBadGateway, "Update not installed", err.Error()+" The running version is unchanged."+hint)
		return
	}
	s.audit(sess, r, "update.installed", st.Latest.Version, "previous version kept as "+filepath.Base(exe)+".old")
	s.log.Info("update installed", "from", version, "to", st.Latest.Version, "file", exe)
	if s.restart != nil {
		s.renderError(w, r, sess, http.StatusOK, "Updated to "+st.Latest.Version,
			"The agent is restarting into the new version in a new window. If the encryption key has a passphrase, enter it there; this page will then work again after a reload.")
		s.restart()
		return
	}
	s.renderError(w, r, sess, http.StatusOK, "Updated to "+st.Latest.Version,
		"The new version is installed and starts the next time the agent starts. Restart it now to finish: "+
			"for a service, easm-agent -service restart (or the Services panel); otherwise stop it and start it again. "+
			"To go back, run easm-agent -rollback while it is stopped.")
}
