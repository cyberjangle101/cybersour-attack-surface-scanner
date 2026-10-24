package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSelfSignedCertIsCreatedAndReused checks the certificate covers the loopback
// names, the key file is private, and a restart reuses the same certificate.
func TestSelfSignedCertIsCreatedAndReused(t *testing.T) {
	dir := t.TempDir()
	k, err := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := k.Get(nil)
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := c1.Leaf.VerifyHostname(h); err != nil {
			t.Errorf("certificate does not cover %s: %v", h, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, selfSignedKeyFile)); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("TLS key must be private to the owner: %v %v", fi, err)
	}
	k2, err := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := k2.Get(nil)
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Error("a restart must reuse the saved certificate, not make a new one")
	}
}

// TestSelfSignedCertIsReissuedWhenNamesChangeOrExpire covers the two renewal triggers.
func TestSelfSignedCertIsReissuedWhenNamesChangeOrExpire(t *testing.T) {
	dir := t.TempDir()
	k, _ := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	old, _ := k.Get(nil)

	k2, err := newCertKeeper(dir, "127.0.0.1:8080", []string{"easm.internal.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := k2.Get(nil)
	if c.Leaf.VerifyHostname("easm.internal.example") != nil || string(c.Certificate[0]) == string(old.Certificate[0]) {
		t.Error("a new allowed host name must produce a certificate that covers it")
	}

	// Force the cached certificate to look nearly expired: Get must renew it.
	k2.mu.Lock()
	k2.leaf.NotAfter = time.Now().Add(24 * time.Hour)
	k2.mu.Unlock()
	_ = os.Remove(filepath.Join(dir, selfSignedCertFile)) // and the saved copy is gone
	renewed, err := k2.Get(nil)
	if err != nil || time.Until(renewed.Leaf.NotAfter) < selfSignedRenewAt {
		t.Errorf("certificate was not renewed: %v", err)
	}
}

// TestServerTalksTLSWithSelfSignedCert does a real TLS handshake, trusting only the
// generated certificate, and checks old protocol versions are refused.
func TestServerTalksTLSWithSelfSignedCert(t *testing.T) {
	k, err := newCertKeeper(t.TempDir(), "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = k.tlsConfig()
	srv.StartTLS()
	defer srv.Close()

	c, _ := k.Get(nil)
	pool := x509.NewCertPool()
	pool.AddCert(c.Leaf)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	_ = resp.Body.Close()

	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: tls.VersionTLS11}}}
	if r, err := old.Get(srv.URL); err == nil {
		_ = r.Body.Close()
		t.Error("TLS 1.1 must be refused")
	}
}

// TestAutoTLSRules covers when the agent makes its own certificate.
func TestAutoTLSRules(t *testing.T) {
	for _, c := range []struct {
		b    Bootstrap
		auto bool
		tls  bool
	}{
		{Bootstrap{}, true, true},
		{Bootstrap{PlainHTTP: true}, false, false},
		{Bootstrap{SecureCookies: true}, false, false}, // a reverse proxy terminates TLS
		{Bootstrap{TLSCert: "a", TLSKey: "b"}, false, true},
	} {
		if c.b.AutoTLS() != c.auto || c.b.UsesTLS() != c.tls {
			t.Errorf("%+v: auto=%v tls=%v, want %v %v", c.b, c.b.AutoTLS(), c.b.UsesTLS(), c.auto, c.tls)
		}
	}
}
