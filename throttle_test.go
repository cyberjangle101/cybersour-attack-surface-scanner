package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// loginFrom posts the sign-in form straight to the handler as if it came from addr.
func (e *webEnv) loginFrom(addr, user, pw string) int {
	e.t.Helper()
	tok := strings.Repeat("a", 32)
	v := url.Values{"csrf": {tok}, "username": {user}, "password": {pw}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(v.Encode()))
	req.Host = "127.0.0.1"
	req.RemoteAddr = addr + ":40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	rec := httptest.NewRecorder()
	e.web.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func (e *webEnv) addUser(name, pw, role string) {
	e.t.Helper()
	hash, err := hashPassword(pw)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.store.CreateUser(name, hash, role); err != nil {
		e.t.Fatal(err)
	}
}

// One person's failures from a shared address (loopback, a reverse proxy) must not lock
// everybody else at that address out.
func TestThrottleSharedAddress(t *testing.T) {
	e := newWebEnv(t)
	e.browser().setup("admin", "correct horse battery")
	e.addUser("bob", "bob password 1", RoleViewer)
	for i := 0; i < maxFails; i++ {
		if code := e.loginFrom("10.0.0.1", "bob", "wrong-wrong-wrong"); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := e.loginFrom("10.0.0.1", "bob", "bob password 1"); code != 429 {
		t.Errorf("bob not throttled at his own address: %d", code)
	}
	if code := e.loginFrom("10.0.0.1", "admin", "correct horse battery"); code != 303 {
		t.Errorf("admin locked out by bob's failures from the same address: %d", code)
	}
	if code := e.loginFrom("10.0.0.2", "bob", "bob password 1"); code != 303 {
		t.Errorf("bob blocked from another address before the account limit: %d", code)
	}
	// the name is matched without case, so changing case does not reset the count
	for i := 0; i < maxFails; i++ {
		e.loginFrom("10.0.0.3", "bob", "wrong-wrong-wrong")
	}
	if code := e.loginFrom("10.0.0.3", "BOB", "bob password 1"); code != 429 {
		t.Errorf("case change escaped the throttle: %d", code)
	}
}

// Guesses for one local account spread over many addresses are still limited.
func TestThrottlePerAccountAcrossAddresses(t *testing.T) {
	e := newWebEnv(t)
	e.browser().setup("admin", "correct horse battery")
	e.addUser("bob", "bob password 1", RoleViewer)
	for i := 0; i < acctMaxFails; i++ {
		if code := e.loginFrom(fmt.Sprintf("192.0.2.%d", i+1), "admin", "wrong-wrong-wrong"); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := e.loginFrom("198.51.100.7", "admin", "correct horse battery"); code != 429 {
		t.Errorf("account limit across addresses not applied: %d", code)
	}
	if code := e.loginFrom("198.51.100.7", "bob", "bob password 1"); code != 303 {
		t.Errorf("another account was blocked by the account limit: %d", code)
	}
	// every failure was audited
	_, n, err := e.store.ListAudit(AuditFilter{Actor: "admin", Action: "login.fail", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if n < acctMaxFails {
		t.Errorf("audit has %d login.fail entries, want at least %d", n, acctMaxFails)
	}
}

// Spraying many names from one address hits the address ceiling.
func TestThrottleAddressCeiling(t *testing.T) {
	e := newWebEnv(t)
	e.browser().setup("admin", "correct horse battery")
	for i := 0; i < ipMaxFails; i++ {
		e.loginFrom("203.0.113.9", fmt.Sprintf("user%03d", i), "wrong-wrong-wrong")
	}
	if code := e.loginFrom("203.0.113.9", "admin", "correct horse battery"); code != 429 {
		t.Errorf("address ceiling not applied: %d", code)
	}
	if code := e.loginFrom("203.0.113.10", "admin", "correct horse battery"); code != 303 {
		t.Errorf("other address blocked: %d", code)
	}
}

// Back-off grows with each failure past the limit, and success clears the account buckets
// but not the address ceiling.
func TestThrottleBackoff(t *testing.T) {
	s := &Server{fails: map[string]*failRec{}}
	keys := signInKeys("10.1.1.1", "alice")
	for i := 0; i < maxFails; i++ {
		s.recordFail(keys)
	}
	first := time.Until(s.fails[keys[0].key].blocked)
	s.recordFail(keys)
	second := time.Until(s.fails[keys[0].key].blocked)
	if first <= 0 || second < first+backoffBase/2 {
		t.Errorf("back-off did not grow: %v then %v", first, second)
	}
	for i := 0; i < 30; i++ {
		s.recordFail(keys)
	}
	if d := time.Until(s.fails[keys[0].key].blocked); d > backoffMax {
		t.Errorf("back-off above the cap: %v", d)
	}
	s.clearFails(keys)
	if s.fails[keys[0].key] != nil || s.fails[keys[1].key] != nil || s.fails[keys[2].key] == nil {
		t.Error("clearFails must drop the account buckets and keep the address ceiling")
	}
	// bad API tokens do not block the sign-in form from the same address
	api := apiKeys("10.2.2.2")
	for i := 0; i < maxFails; i++ {
		s.recordFail(api)
	}
	if !s.throttled(api) || s.throttled(signInKeys("10.2.2.2", "alice")) {
		t.Error("API and sign-in buckets are not kept apart")
	}
}

func TestThrottlePrune(t *testing.T) {
	s := &Server{fails: map[string]*failRec{}}
	old := time.Now().Add(-2 * failSpan)
	s.fails["p\x00x\x00old"] = &failRec{count: 1, first: old, last: old}
	s.fails["p\x00x\x00live"] = &failRec{count: 9, first: old, last: old, blocked: time.Now().Add(time.Minute)}
	s.pruneFails(time.Now())
	if s.fails["p\x00x\x00old"] != nil || s.fails["p\x00x\x00live"] == nil {
		t.Errorf("prune kept stale or dropped a live block: %v", s.fails)
	}
}
