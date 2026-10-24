package main

import (
	"sort"
	"sync"
	"time"
)

// ScanProgress is the live state of one running scan, shown as a progress bar.
type ScanProgress struct {
	ID       int64
	Domain   string
	Stage    string // human-readable current stage
	Detail   string // what exactly is being waited on
	Percent  int    // 0-100, never decreases during a scan
	Started  time.Time
	Updated  time.Time
	Elapsed  int // seconds, filled in by Snapshot
	IdleSecs int // seconds since the last update, filled in by Snapshot
}

// ProgressBoard tracks every scan currently running. It is safe for concurrent use
// and a nil board is a no-op.
type ProgressBoard struct {
	mu sync.Mutex
	m  map[int64]*ScanProgress
}

// NewProgressBoard creates an empty progress board.
func NewProgressBoard() *ProgressBoard { return &ProgressBoard{m: map[int64]*ScanProgress{}} }

// Start registers a scan so its progress can be shown.
func (b *ProgressBoard) Start(id int64, domain string) {
	if b == nil {
		return
	}
	now := time.Now()
	b.mu.Lock()
	b.m[id] = &ScanProgress{ID: id, Domain: domain, Stage: "Starting", Started: now, Updated: now}
	b.mu.Unlock()
}

// Update records the current stage; the percentage never goes backwards.
func (b *ProgressBoard) Update(id int64, stage string, pct int, detail string) {
	if b == nil {
		return
	}
	if pct > 100 {
		pct = 100
	}
	b.mu.Lock()
	if p := b.m[id]; p != nil {
		if pct > p.Percent {
			p.Percent = pct
		}
		p.Stage, p.Detail, p.Updated = stage, detail, time.Now()
	}
	b.mu.Unlock()
}

// Done removes a finished scan from the board.
func (b *ProgressBoard) Done(id int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	delete(b.m, id)
	b.mu.Unlock()
}

// Get returns a copy of one scan's progress, or nil.
func (b *ProgressBoard) Get(id int64) *ScanProgress {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.m[id]
	if p == nil {
		return nil
	}
	c := *p
	c.fill()
	return &c
}

func (p *ScanProgress) fill() {
	p.Elapsed = int(time.Since(p.Started).Seconds())
	p.IdleSecs = int(time.Since(p.Updated).Seconds())
}

// Snapshot returns copies of all running scans, oldest first.
func (b *ProgressBoard) Snapshot() []ScanProgress {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]ScanProgress, 0, len(b.m))
	for _, p := range b.m {
		c := *p
		c.fill()
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}
