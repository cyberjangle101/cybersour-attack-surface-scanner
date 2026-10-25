package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// sourceServer answers like a passive source and counts the requests it got.
func sourceServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestOTXSendsKey(t *testing.T) {
	srv, _ := sourceServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "OTXKEY1234" || r.URL.Path != "/otx/example.test/passive_dns" {
			http.Error(w, `{"detail": "Authentication required"}`, http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"passive_dns":[{"hostname":"api.example.test"}]}`))
	})
	st := DefaultSettings()
	st.OTXEnabled = true
	d := NewDiscoverer(st.RuntimeWith(Secrets{OTX: "OTXKEY1234"}), testLogger(t))
	d.urls.otx = srv.URL + "/otx/"
	hosts, err := d.fetchOTX(context.Background(), "example.test")
	if err != nil || len(hosts) != 1 || hosts[0] != "api.example.test" {
		t.Fatalf("hosts %v, err %v", hosts, err)
	}
}

// Anonymous OTX callers get a 429 on the first request. It must not be retried or
// reported as rate limiting: the fix is a key, not waiting.
func TestOTXAnonymousRefusalIsClearAndNotRetried(t *testing.T) {
	srv, n := sourceServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`))
	})
	d := NewDiscoverer(DefaultSettings().RuntimeWith(Secrets{}), testLogger(t))
	d.urls.otx = srv.URL + "/otx/"
	_, err := d.fetchOTX(context.Background(), "example.test")
	if err == nil || !strings.Contains(err.Error(), "OTX API key") {
		t.Fatalf("err %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("%d requests, want 1 (no retries)", n.Load())
	}
	if h := Hint(err.Error()); strings.Contains(h, "Rate limited") {
		t.Errorf("hint calls it rate limiting: %q", h)
	}
}

// A plain 429 (real rate limiting) is still retried.
func TestOTXPlainRateLimitStillRetried(t *testing.T) {
	var calls atomic.Int32
	srv, n := sourceServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, `{"detail": "slow down"}`, http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"passive_dns":[]}`))
	})
	d := NewDiscoverer(DefaultSettings().RuntimeWith(Secrets{OTX: "OTXKEY1234"}), testLogger(t))
	d.urls.otx = srv.URL + "/otx/"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := d.fetchOTX(ctx, "example.test"); err != nil || n.Load() != 2 {
		t.Fatalf("err %v after %d requests", err, n.Load())
	}
}

func TestAnubisBotChallengeIsClearAndNotRetried(t *testing.T) {
	srv, n := sourceServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<!DOCTYPE html><head><title>Attention Required! | Cloudflare</title></head>`))
	})
	d := NewDiscoverer(DefaultSettings().RuntimeWith(Secrets{}), testLogger(t))
	d.urls.anubis = srv.URL + "/anubis/"
	_, err := d.fetchAnubis(context.Background(), "example.test")
	if err == nil || !strings.Contains(err.Error(), "bot challenge") {
		t.Fatalf("err %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("%d requests, want 1 (no retries)", n.Load())
	}
	if h := Hint(err.Error()); strings.Contains(h, "credentials") {
		t.Errorf("hint blames credentials: %q", h)
	}
}

func TestOTXNeedsKeyToRun(t *testing.T) {
	st := DefaultSettings()
	if st.OTXEnabled || st.AnubisEnabled {
		t.Fatal("OTX and Anubis must be off by default")
	}
	st.OTXEnabled = true
	if st.RuntimeWith(Secrets{}).Sources.OTX.Enabled {
		t.Error("OTX enabled without a key")
	}
	if c := st.RuntimeWith(Secrets{OTX: "OTXKEY1234"}).Sources.OTX; !c.Enabled || c.Key != "OTXKEY1234" {
		t.Errorf("OTX with key: %+v", c)
	}
}
