package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pemOf(t *testing.T, c tls.Certificate) (chain, key string) {
	t.Helper()
	for _, der := range c.Certificate {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	kd, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return chain, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func newKeeperWithVault(t *testing.T, dir string) (*certKeeper, *Vault) {
	t.Helper()
	v, err := OpenVault(filepath.Join(t.TempDir(), "easm.key"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	k.attachVault(v)
	return k, v
}

func TestUploadedCertificateIsServedAndPersisted(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, -time.Hour, 90*24*time.Hour, "localhost", "easm.corp.example")
	chain, key := pemOf(t, leaf)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))

	dir := t.TempDir()
	k, v := newKeeperWithVault(t, dir)
	if k.Info().Source != "self-signed" {
		t.Fatal("should start self-signed")
	}
	// CA first, leaf second: the order of a sloppy download must still work
	info, warns, err := k.InstallCustom(caPEM+chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Source != "uploaded" || info.ChainLength != 2 || info.DaysLeft < 80 {
		t.Errorf("info = %+v", info)
	}
	// 127.0.0.1 and ::1 are not in the certificate: a warning, not an error
	if len(warns) == 0 || !strings.Contains(strings.Join(warns, " "), "does not cover") {
		t.Errorf("expected a coverage warning, got %v", warns)
	}

	// a real TLS handshake that trusts only the test CA proves the new certificate is the one served
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	srv.TLS = k.tlsConfig()
	srv.StartTLS()
	defer srv.Close()
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: ca.pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("handshake with the uploaded certificate failed: %v", err)
	}
	_ = conn.Close()

	// the private key is on disk only in sealed form
	sealed, err := os.ReadFile(filepath.Join(dir, customKeyFile))
	if err != nil || strings.Contains(string(sealed), "PRIVATE KEY") || len(sealed) < 40 {
		t.Errorf("sealed key file looks wrong: %v %q", err, sealed)
	}
	assertOwnerOnly(t, filepath.Join(dir, customKeyFile), "sealed key file")

	// a restart keeps serving it (same master key)
	k2, err := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	k2.attachVault(v)
	if k2.Info().Source != "uploaded" {
		t.Error("uploaded certificate was not reloaded after a restart")
	}
	// a different master key cannot read it and falls back to the self-signed certificate
	other, _ := OpenVault(filepath.Join(t.TempDir(), "other.key"))
	k3, _ := newCertKeeper(dir, "127.0.0.1:8080", nil, nil)
	k3.attachVault(other)
	if k3.Info().Source != "self-signed" {
		t.Error("with the wrong master key the uploaded key must stay unreadable")
	}

	// removing goes back to self-signed and deletes both files
	if err := k.RemoveCustom(); err != nil {
		t.Fatal(err)
	}
	if k.Info().Source != "self-signed" {
		t.Error("remove did not revert")
	}
	for _, f := range []string{customCertFile, customKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s still exists", f)
		}
	}
}

func TestCombinedPEMAndRejections(t *testing.T) {
	ca := newTestCA(t)
	good := ca.leaf(t, -time.Hour, 24*time.Hour*60, "localhost")
	chain, key := pemOf(t, good)
	k, _ := newKeeperWithVault(t, t.TempDir())

	if _, _, err := k.InstallCustom(chain+key, ""); err != nil {
		t.Errorf("a single combined PEM must work: %v", err)
	}

	other := ca.leaf(t, -time.Hour, 24*time.Hour*60, "localhost")
	_, otherKey := pemOf(t, other)
	expired := ca.leaf(t, -48*time.Hour, -time.Hour, "localhost")
	expChain, expKey := pemOf(t, expired)
	caCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	caKeyDER, _ := x509.MarshalPKCS8PrivateKey(ca.key)
	caKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}))
	encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}))

	cases := []struct{ name, cert, key, want string }{
		{"key from another certificate", chain, otherKey, "matches this private key"},
		{"expired", expChain, expKey, "expired"},
		{"CA certificate instead of a server certificate", caCert, caKey, "certificate authority"},
		{"password-protected key", chain, encrypted, "password-protected"},
		{"no key", chain, "", "no private key"},
		{"no certificate", "", key, "no certificate"},
		{"garbage", "hello", "world", "no certificate"},
	}
	for _, c := range cases {
		_, _, err := k.InstallCustom(c.cert, c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
	// a failed upload must not replace the working one
	if k.Info().Source != "uploaded" {
		t.Error("rejected uploads must leave the previous certificate in place")
	}
}

func TestExpiredUploadFallsBackToSelfSigned(t *testing.T) {
	k, _ := newKeeperWithVault(t, t.TempDir())
	ca := newTestCA(t)
	chain, key := pemOf(t, ca.leaf(t, -time.Hour, 24*time.Hour*30, "localhost"))
	if _, _, err := k.InstallCustom(chain, key); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	k.customLeaf.NotAfter = time.Now().Add(-time.Minute) // simulate the passage of time
	k.mu.Unlock()
	c, err := k.Get(nil)
	if err != nil || c.Leaf == nil && len(c.Certificate) == 0 {
		t.Fatal("must still serve something")
	}
	if got := k.Info(); got.Source != "self-signed" || len(got.Missing) == 0 {
		t.Errorf("expired upload should fall back and say so: %+v", got)
	}
}
