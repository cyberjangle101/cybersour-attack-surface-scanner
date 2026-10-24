package main

import (
	"fmt"
	"time"
)

// maybeBackup writes the scheduled backup when it is due. It runs in the background so a large
// database never holds up the scheduler, and a failure is retried after half an hour.
func (e *Engine) maybeBackup() {
	if e.vault == nil || e.dataDir == "" {
		return
	}
	cfg := e.store.LoadBackupConfig(e.dataDir)
	if !cfg.Enabled {
		return
	}
	now := time.Now()
	if last, err := time.Parse(time.RFC3339, cfg.LastRun); err == nil && now.Sub(last) < time.Duration(cfg.EveryHours)*time.Hour {
		return
	}
	if !e.lastBkTry.IsZero() && now.Sub(e.lastBkTry) < 30*time.Minute {
		return
	}
	if !e.backing.CompareAndSwap(false, true) {
		return
	}
	e.lastBkTry = now
	go func() {
		defer e.backing.Store(false)
		_, _ = e.BackupNow(cfg, "scheduled") // failures are logged and shown on the Settings page
	}()
}

// BackupNow writes one backup into the configured folder and records the outcome.
func (e *Engine) BackupNow(cfg BackupConfig, trigger string) (string, error) {
	path, m, err := WriteBackupFile(e.store, e.vault, e.dataDir, cfg.Dir, cfg.IncludeKey, cfg.Keep, time.Now())
	if err != nil {
		e.log.Error("backup failed", "folder", cfg.Dir, "err", err)
		_ = e.store.setMeta(backupResultKey, "failed "+time.Now().UTC().Format(time.RFC3339)+": "+err.Error())
		_ = e.store.Audit("system", "", "backup.failed", cfg.Dir, err.Error(), "")
		return "", err
	}
	e.log.Info("backup written", "file", path, "bytes", m.DBBytes, "trigger", trigger)
	_ = e.store.setMeta(backupLastKey, time.Now().UTC().Format(time.RFC3339))
	_ = e.store.setMeta(backupResultKey, fmt.Sprintf("ok %s: %s", time.Now().UTC().Format(time.RFC3339), path))
	_ = e.store.Audit("system", "", "backup.written", path, trigger, "")
	return path, nil
}
