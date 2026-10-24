package main

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// backupView feeds the Backup card on the Settings page.
func (s *Server) backupView() map[string]any {
	dir := s.eng.dataDir
	if dir == "" {
		return nil
	}
	cfg := s.store.LoadBackupConfig(dir)
	return map[string]any{
		"Cfg": cfg, "Files": ListBackups(cfg.Dir), "KeyProtected": keyFileProtected(dir + string(os.PathSeparator) + "easm.key"),
		"DataDir": dir,
	}
}

// backupSave stores the scheduled-backup settings.
func (s *Server) backupSave(w http.ResponseWriter, r *http.Request, sess *Session) {
	hours, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("every_hours")))
	keep, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("keep")))
	cfg := BackupConfig{
		Enabled: r.PostFormValue("enabled") != "", Dir: r.PostFormValue("dir"), EveryHours: hours, Keep: keep,
		IncludeKey: r.PostFormValue("include_key") != "",
	}
	if cfg.IncludeKey && !keyFileProtected(s.eng.dataDir+string(os.PathSeparator)+"easm.key") {
		s.flash(sess, "bad", "The key file has no passphrase, so it cannot be included in backups. Protect it first (easm-agent -protect-key), or leave this off and keep a separate copy of easm.key.")
		http.Redirect(w, r, "/settings#backup", http.StatusSeeOther)
		return
	}
	if err := s.store.SaveBackupConfig(cfg); err != nil {
		s.flash(sess, "bad", "Backup settings not saved: "+err.Error())
	} else {
		s.audit(sess, r, "backup.settings", cfg.Dir, "enabled="+strconv.FormatBool(cfg.Enabled)+" every "+strconv.Itoa(cfg.EveryHours)+"h keep "+strconv.Itoa(cfg.Keep))
		s.flash(sess, "good", "Backup settings saved.")
	}
	http.Redirect(w, r, "/settings#backup", http.StatusSeeOther)
}

// backupNow writes a backup to the configured folder right away.
func (s *Server) backupNow(w http.ResponseWriter, r *http.Request, sess *Session) {
	cfg := s.store.LoadBackupConfig(s.eng.dataDir)
	path, err := s.eng.BackupNow(cfg, "manual by "+sess.Username)
	if err != nil {
		s.flash(sess, "bad", "Backup failed: "+err.Error())
	} else {
		s.audit(sess, r, "backup.now", path, "")
		s.flash(sess, "good", "Backup written to "+path)
	}
	http.Redirect(w, r, "/settings#backup", http.StatusSeeOther)
}

// backupDownload builds a backup and sends it to the browser.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request, sess *Session) {
	include := r.PostFormValue("include_key") != ""
	tmp, err := os.CreateTemp(s.eng.dataDir, ".download-*.zip")
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	now := time.Now()
	if _, err := WriteBackup(s.store, s.eng.vault, s.eng.dataDir, include, tmp, now); err != nil {
		s.flash(sess, "bad", "Backup failed: "+err.Error())
		http.Redirect(w, r, "/settings#backup", http.StatusSeeOther)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.audit(sess, r, "backup.download", "", "key included: "+strconv.FormatBool(include))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+BackupFileName(now)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, BackupFileName(now), now, tmp)
}
