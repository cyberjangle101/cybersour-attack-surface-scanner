package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// defaultUpdateEvery is how often the scheduler asks GitHub for a newer release.
const defaultUpdateEvery = 24 * time.Hour

// UpdateState is what the last update check found, for System health and the dashboard.
type UpdateState struct {
	Checked   time.Time
	Latest    *Release
	Available bool   // Latest is newer than the running version
	CanApply  bool   // this build can verify (and so install) it
	Err       string // last check failure, if any
}

// updateBoard holds the last check result between scheduler passes.
type updateBoard struct {
	mu    sync.Mutex
	state UpdateState
}

// UpdateState returns the result of the last check.
func (e *Engine) UpdateState() UpdateState {
	e.updates.mu.Lock()
	defer e.updates.mu.Unlock()
	return e.updates.state
}

// CheckForUpdate asks for the newest release now and records the answer.
func (e *Engine) CheckForUpdate(ctx context.Context) UpdateState {
	u := e.updater()
	st := UpdateState{Checked: time.Now(), CanApply: u.CanInstall()}
	if r, err := u.Latest(ctx); errors.Is(err, ErrNoRelease) {
		e.log.Info("update check: no release published yet")
	} else if err != nil {
		st.Err = err.Error()
		e.log.Warn("update check failed", "err", err)
	} else {
		st.Latest, st.Available = r, u.IsNewer(r)
		if st.Available {
			e.log.Info("a newer version is available", "running", u.Current, "latest", r.Version, "notes", r.URL)
		}
	}
	e.updates.mu.Lock()
	e.updates.state = st
	e.updates.mu.Unlock()
	return st
}

// maybeUpdateCheck runs the daily check in the background when Settings allow it.
func (e *Engine) maybeUpdateCheck(ctx context.Context) {
	if e.updateEvery <= 0 || time.Since(e.lastUpdate) < e.updateEvery {
		return
	}
	if st, err := e.store.LoadSettings(); err != nil || !st.UpdateCheck {
		return
	}
	if !e.updChecking.CompareAndSwap(false, true) {
		return
	}
	e.lastUpdate = time.Now()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.updChecking.Store(false)
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		e.CheckForUpdate(cctx)
	}()
}

// updater is the release source; tests replace it through newUpdater.
func (e *Engine) updater() *Updater {
	if e.newUpdater != nil {
		return e.newUpdater()
	}
	return NewUpdater()
}
