package main

import (
	"strings"
	"time"
)

// Sign-in throttling. Failures count against several buckets at once, so that one person's
// mistakes cannot lock everybody else out of a shared address (the default loopback binding,
// a reverse proxy, an office NAT), while guessing stays slow:
//   - per address and account name: the main limit, with progressive back-off;
//   - per account name from any address: a higher limit, so guesses spread over many addresses
//     are still slowed down (directory accounts also have adGuard);
//   - per address, any account: a much higher ceiling against spraying many names from one place.
//
// A blocked request is refused before the password is checked, whatever the name, so the
// answer does not tell an attacker whether an account exists.
const (
	maxFails     = 5   // per address and account (and per address for API tokens)
	acctMaxFails = 20  // per account, from any address
	ipMaxFails   = 100 // per address, any account, within failSpan
	failSpan     = 15 * time.Minute
	blockSpan    = 10 * time.Minute // block once the address ceiling is reached
	backoffBase  = time.Minute      // first back-off; it doubles with every further failure
	backoffMax   = 30 * time.Minute
	throttleMax  = 50000 // tracked buckets; stale ones are pruned first
	throttleName = 256   // longest account name kept in a key
)

// bucket is one throttling counter. A flat bucket counts failures in a fixed window and blocks
// for blockSpan; the others back off progressively and are forgotten after failSpan of quiet.
type bucket struct {
	key   string
	limit int
	flat  bool
}

// signInKeys are the buckets a password or two-factor attempt for name from ip counts against.
func signInKeys(ip, name string) []bucket {
	name = strings.ToLower(name)
	if len(name) > throttleName {
		name = name[:throttleName]
	}
	return []bucket{
		{key: "p\x00" + ip + "\x00" + name, limit: maxFails},
		{key: "a\x00" + name, limit: acctMaxFails},
		{key: "i\x00" + ip, limit: ipMaxFails, flat: true},
	}
}

// apiKeys are the buckets a bearer-token attempt counts against. They are kept apart from the
// sign-in form, so bad tokens from a script do not block people signing in from the same address.
func apiKeys(ip string) []bucket {
	return []bucket{
		{key: "t\x00" + ip, limit: maxFails},
		{key: "i\x00" + ip, limit: ipMaxFails, flat: true},
	}
}

func backoff(count, limit int) time.Duration {
	if count < limit {
		return 0
	}
	d := backoffBase << min(count-limit, 10)
	return min(d, backoffMax)
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// stale reports whether a counter can be forgotten.
func (f *failRec) stale(b bucket, now time.Time) bool {
	if now.Before(f.blocked) {
		return false
	}
	if b.flat {
		return now.Sub(f.first) > failSpan
	}
	return now.Sub(later(f.last, f.blocked)) > failSpan
}

// throttled reports whether any of the buckets is blocked.
func (s *Server) throttled(bs []bucket) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, b := range bs {
		if f := s.fails[b.key]; f != nil && now.Before(f.blocked) {
			return true
		}
	}
	return false
}

// recordFail counts a failed attempt against every bucket.
func (s *Server) recordFail(bs []bucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.fails) >= throttleMax {
		s.pruneFails(now)
	}
	for _, b := range bs {
		f := s.fails[b.key]
		if f != nil && f.stale(b, now) {
			f = nil
		}
		if f == nil {
			if len(s.fails) >= throttleMax {
				continue // full of live counters: existing blocks still hold
			}
			f = &failRec{first: now}
			s.fails[b.key] = f
		}
		f.count++
		f.last = now
		switch {
		case b.flat && f.count >= b.limit:
			f.blocked = now.Add(blockSpan)
		case !b.flat:
			if d := backoff(f.count, b.limit); d > 0 {
				f.blocked = now.Add(d)
			}
		}
	}
}

// clearFails forgets the per-account buckets after a successful sign-in. The address ceiling
// is left to expire on its own, so one valid account cannot be used to reset it.
func (s *Server) clearFails(bs []bucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range bs {
		if !b.flat {
			delete(s.fails, b.key)
		}
	}
}

// pruneFails drops counters that are neither blocked nor recent. The caller holds s.mu.
func (s *Server) pruneFails(now time.Time) {
	for k, f := range s.fails {
		if f.stale(bucket{}, now) {
			delete(s.fails, k)
		}
	}
}
