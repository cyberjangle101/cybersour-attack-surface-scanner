package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine is the always-on scheduler. It wakes every few seconds, runs any target
// whose next_scan time has passed (one at a time, to stay polite to the free
// public data sources), sends alerts and periodic digest emails, and prunes old data.
type Engine struct {
	store   *Store
	vault   *Vault
	log     *slog.Logger
	wake    chan struct{}
	health  *HealthBoard
	started time.Time

	// intelURLs is a test seam that redirects the exposure-intelligence services.
	intelURLs func() *intelURLs
	// reachFn is a test seam replacing the TLS reachability probe used for quota-limited sources.
	reachFn func(host string) func(context.Context) error

	// newScanner is a seam for tests; production uses NewScanner.
	newScanner func(cfg *Config, res *Resolver) *Scanner

	mu        sync.Mutex
	lastPrune time.Time
	active    map[int64]string // target id -> domain, scans in flight
	wg        sync.WaitGroup
	alertMu   sync.Mutex // one alert flush at a time so batches never duplicate

	progress *ProgressBoard
	dataDir  string // shown on the Health page so it is obvious where the database and key live
}

// NewEngine creates the scheduler, restoring persisted connector health.
func NewEngine(store *Store, vault *Vault, log *slog.Logger) *Engine {
	e := &Engine{store: store, vault: vault, log: log, wake: make(chan struct{}, 1), health: NewHealthBoard(), started: time.Now(),
		active: map[int64]string{}, progress: NewProgressBoard()}
	if v, ok, _ := store.getMeta("health"); ok {
		e.health.Load(v)
	}
	e.newScanner = func(cfg *Config, res *Resolver) *Scanner { return NewScanner(cfg, log, store, res) }
	return e
}

// Wake asks the scheduler to re-check for due work now.
func (e *Engine) Wake() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Progress exposes the live per-scan progress board.
func (e *Engine) Progress() *ProgressBoard { return e.progress }

// Current returns the domain(s) being scanned right now, comma separated.
func (e *Engine) Current() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var d []string
	for _, v := range e.active {
		d = append(d, v)
	}
	sort.Strings(d)
	return strings.Join(d, ", ")
}

// claim reserves a scan slot for a target; false if it is already running or the pool is full.
func (e *Engine) claim(t *Target, limit int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.active[t.ID]; ok || len(e.active) >= limit {
		return false
	}
	e.active[t.ID] = t.Domain
	return true
}

func (e *Engine) release(t *Target) {
	e.mu.Lock()
	delete(e.active, t.ID)
	e.mu.Unlock()
}

// Secret returns a decrypted credential ("" if unset or undecryptable).
func (e *Engine) Secret(name string) string {
	enc, ok, err := e.store.getMeta(name)
	if err != nil || !ok || enc == "" {
		return ""
	}
	pw, err := e.vault.Open(enc)
	if err != nil {
		e.log.Error("cannot decrypt a stored credential (was easm.key replaced?); re-enter it in Settings", "name", name)
		return ""
	}
	return pw
}

// SetSecret encrypts value with the vault and stores it under name (empty value clears it).
func (e *Engine) SetSecret(name, value string) error {
	if value == "" {
		return e.store.setMeta(name, "")
	}
	enc, err := e.vault.Seal(value)
	if err != nil {
		return err
	}
	return e.store.setMeta(name, enc)
}

// HasSecret reports whether a secret is stored, without decrypting it.
func (e *Engine) HasSecret(name string) bool {
	v, ok, _ := e.store.getMeta(name)
	return ok && v != ""
}

// SMTPPassword returns the decrypted SMTP password.
func (e *Engine) SMTPPassword() string { return e.Secret(secretSMTP) }

// SetSMTPPassword stores the SMTP password encrypted.
func (e *Engine) SetSMTPPassword(pw string) error { return e.SetSecret(secretSMTP, pw) }

// HasSMTPPassword reports whether an SMTP password is stored.
func (e *Engine) HasSMTPPassword() bool { return e.HasSecret(secretSMTP) }

// Health returns the connector health board.
func (e *Engine) Health() *HealthBoard { return e.health }

func (e *Engine) saveHealth() {
	if err := e.store.setMeta("health", e.health.Marshal()); err != nil {
		e.log.Warn("could not persist connector health", "err", err)
	}
}

// config loads the saved settings and secrets and builds the runtime Config for a scan.
func (e *Engine) config() (*Config, Settings, error) {
	st, err := e.store.LoadSettings()
	if err != nil {
		return nil, st, err
	}
	return st.RuntimeWith(Secrets{
		SMTP: e.SMTPPassword(), Shodan: e.Secret(secretShodan), Censys: e.Secret(secretCensys), VirusTotal: e.Secret(secretVT),
		HIBP: e.Secret(secretHIBP), GitHub: e.Secret(secretGitHub),
	}), st, nil
}

// Run blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	if err := e.store.ResetRunning(); err != nil {
		e.log.Error("resetting interrupted scans failed", "err", err)
	}
	defer e.wg.Wait() // let in-flight scans record their "interrupted" state before returning
	e.log.Info("scheduler started")
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		e.runDue(ctx)
		e.housekeeping(ctx)
		select {
		case <-ctx.Done():
			e.log.Info("scheduler stopping")
			return
		case <-tick.C:
		case <-e.wake:
		}
	}
}

// runDue starts a scan for every due target, up to the configured concurrency. Scans run in their own goroutines so a slow domain never blocks the scheduler.
func (e *Engine) runDue(ctx context.Context) {
	due, err := e.store.DueTargets(nowUTC())
	if err != nil {
		e.log.Error("reading due targets failed", "err", err)
		return
	}
	limit := 2
	if st, err := e.store.LoadSettings(); err == nil && st.ConcurrentScans > 0 {
		limit = st.ConcurrentScans
	}
	// Scans run in their own goroutines: the scheduler loop never blocks on a slow
	// domain, so a newly added domain starts as soon as a slot is free.
	for _, t := range due {
		if ctx.Err() != nil {
			return
		}
		if !e.claim(t, limit) {
			continue
		}
		e.wg.Add(1)
		go func(t *Target) {
			defer e.wg.Done()
			defer e.release(t)
			e.scan(ctx, t)
			e.Wake() // a slot just freed: start the next queued domain without waiting for the tick
		}(t)
	}
}

// ScanNow scans one target synchronously (used by tests and the CLI).
func (e *Engine) ScanNow(ctx context.Context, t *Target) {
	if !e.claim(t, 1<<30) {
		return
	}
	defer e.release(t)
	e.scan(ctx, t)
}

// scan scans one target synchronously and records the outcome. It never panics.
func (e *Engine) scan(ctx context.Context, t *Target) {
	startedAt := nowUTC()
	if err := e.store.MarkRunning(t.ID, startedAt); err != nil {
		e.log.Error("cannot mark target running", "domain", t.Domain, "err", err)
		return
	}
	e.progress.Start(t.ID, t.Domain)
	defer e.progress.Done(t.ID)

	cfg, settings, err := e.config()
	if err != nil {
		e.finish(t, nil, startedAt, "error", "settings unreadable: "+err.Error(), 30*time.Minute)
		return
	}
	tctx, cancel := context.WithTimeout(ctx, cfg.Schedule.TargetTimeout)
	defer cancel()
	res := NewResolver(tctx, cfg.DNS)
	sc := e.newScanner(cfg, res)
	sc.SetHealth(e.health)
	sc.SetProgress(func(stage string, pct int, detail string) { e.progress.Update(t.ID, stage, pct, detail) })

	var scanErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				scanErr = fmt.Errorf("internal error: %v", r)
				e.log.Error("panic during scan (daemon continues)", "domain", t.Domain, "panic", fmt.Sprint(r))
			}
		}()
		scanErr = sc.scanTarget(tctx, t)
	}()

	status, msg := "ok", ""
	switch {
	case scanErr == nil:
	case ctx.Err() != nil:
		status, msg = "interrupted", "agent was stopping"
	case errors.Is(tctx.Err(), context.DeadlineExceeded):
		status, msg = "error", "scan exceeded the per-target timeout"
	default:
		status, msg = "error", scanErr.Error()
		e.log.Error("scan failed", "domain", t.Domain, "err", scanErr)
	}

	interval := time.Duration(t.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = time.Duration(settings.IntervalMinutes) * time.Minute
	}
	wait := interval
	if status == "error" && wait > 30*time.Minute {
		wait = 30 * time.Minute // retry sooner after a failure
	}
	if j := time.Duration(settings.JitterMinutes) * time.Minute; j > 0 && status != "interrupted" {
		wait += time.Duration(rand.Int63n(int64(j))) //nolint:gosec // G404: schedule jitter, not security-sensitive
	}
	if status == "interrupted" {
		wait = 0
	}
	e.finish(t, sc, startedAt, status, msg, wait)
	e.saveHealth()
	if status != "interrupted" {
		e.alertMu.Lock()
		sc.FlushAlerts(ctx)
		sc.DispatchChannels(ctx)
		e.alertMu.Unlock()
	}
}

// finish records a scan's outcome and schedules the next one.
func (e *Engine) finish(t *Target, sc *Scanner, started, status, msg string, wait time.Duration) {
	end := nowUTC()
	next := time.Now().UTC().Add(wait).Format(time.RFC3339)
	if err := e.store.FinishScan(t.ID, status, msg, end, next); err != nil {
		e.log.Error("recording scan result failed", "domain", t.Domain, "err", err)
	}
	rec := ScanRec{Root: t.Domain, Started: started, Finished: end, Status: status, Error: msg}
	if sc != nil && status == "ok" {
		rec.Hosts, rec.NewSubdomains, rec.NewRecords = sc.stats.Hosts, sc.stats.Subdomains, sc.stats.Records
		rec.NewCerts, rec.NewFindings, rec.NewEvents = sc.stats.Certs, sc.stats.Findings, sc.newEvents
	}
	if err := e.store.InsertScan(rec); err != nil {
		e.log.Error("recording scan history failed", "err", err)
	}
}

// housekeeping prunes old data hourly and sends the scheduled digest when due.
func (e *Engine) housekeeping(ctx context.Context) {
	if time.Since(e.lastPrune) > time.Hour {
		e.lastPrune = time.Now()
		if st, err := e.store.LoadSettings(); err == nil {
			if err := e.store.Prune(st.EventRetentionDays); err != nil {
				e.log.Warn("pruning old data failed", "err", err)
			}
			if err := e.store.PruneAudit(auditRetentionDays); err != nil {
				e.log.Warn("pruning audit log failed", "err", err)
			}
		}
	}
	e.expireAcceptances()
	e.maybeDigest(ctx)
}

// auditRetentionDays is how long audit entries are kept (two years).
const auditRetentionDays = 730

// expireAcceptances reopens accepted risks whose review date has passed and tells the log.
func (e *Engine) expireAcceptances() {
	n, err := e.store.ExpireAcceptances(time.Now().UTC())
	if err != nil {
		e.log.Warn("expiring accepted risks failed", "err", err)
		return
	}
	if n > 0 {
		e.log.Info("accepted risks reached their review date and were reopened", "count", n)
		_ = e.store.Audit("system", "", "finding.reopen", "", fmt.Sprintf("%d accepted risk(s) reached their review date", n), "")
	}
}

// ---------------------------------------------------------------- digest

// maybeDigest sends the periodic summary email when its schedule says it is due.
func (e *Engine) maybeDigest(ctx context.Context) {
	cfg, st, err := e.config()
	if err != nil || st.DigestFrequency == "off" || !cfg.SMTP.Enabled || ctx.Err() != nil {
		return
	}
	period := 24 * time.Hour
	if st.DigestFrequency == "weekly" {
		period = 7 * 24 * time.Hour
	}
	now := time.Now()
	v, ok, err := e.store.getMeta("digest_last")
	if err != nil {
		return
	}
	last, perr := time.Parse(time.RFC3339, v)
	if !ok || perr != nil {
		_ = e.store.setMeta("digest_last", now.UTC().Format(time.RFC3339)) // first run: start the clock
		return
	}
	if now.Sub(last) < period || now.Hour() < st.DigestHour {
		return
	}
	if err := e.SendDigest(ctx, period); err != nil {
		e.log.Error("digest email failed (will retry)", "err", err)
		return
	}
	anchor := time.Date(now.Year(), now.Month(), now.Day(), st.DigestHour, 0, 0, 0, now.Location())
	_ = e.store.setMeta("digest_last", anchor.UTC().Format(time.RFC3339))
}

// SendDigest emails a summary report covering [now-period, now].
func (e *Engine) SendDigest(ctx context.Context, period time.Duration) error {
	cfg, _, err := e.config()
	if err != nil {
		return err
	}
	if !cfg.SMTP.Enabled {
		return errors.New("SMTP is not enabled")
	}
	since := time.Now().Add(-period)
	rep, err := BuildReport(e.store, "", since, 0)
	if err != nil {
		return err
	}
	subject, plain, htmlBody := renderDigest(rep, cfg)
	sctx, cancel := context.WithTimeout(ctx, 3*cfg.SMTP.Timeout)
	defer cancel()
	if err := NewMailer(cfg.SMTP).WithHealth(e.health).Send(sctx, subject, plain, htmlBody); err != nil {
		return err
	}
	e.log.Info("digest email sent", "subject", subject)
	return nil
}

// SendTestEmail verifies the SMTP settings.
func (e *Engine) SendTestEmail(ctx context.Context) error {
	cfg, _, err := e.config()
	if err != nil {
		return err
	}
	if !cfg.SMTP.Enabled {
		return errors.New("SMTP is not enabled (tick 'Enable email' and save first)")
	}
	sctx, cancel := context.WithTimeout(ctx, 3*cfg.SMTP.Timeout)
	defer cancel()
	return NewMailer(cfg.SMTP).WithHealth(e.health).Send(sctx, cfg.SMTP.SubjectPrefix+" test message",
		"EASM agent SMTP test: delivery works.\n", "<p>EASM agent SMTP test: delivery works.</p>")
}
