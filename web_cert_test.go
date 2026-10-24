package main

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSettingsCertificateUpload(t *testing.T) {
	e := newWebEnv(t)
	k, _ := newKeeperWithVault(t, t.TempDir())
	e.web.certs = k
	b := e.browser()
	b.setup("admin", "correct horse battery")

	_, body, _ := b.get("/settings")
	for _, want := range []string{"Web server certificate", "Self-signed (browsers warn)", `name="cert_pem"`, `data-fill="key_pem"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	// a bad upload is explained and changes nothing
	b.post("/settings/certificate", url.Values{"cert_pem": {"not a certificate"}, "key_pem": {""}})
	_, body, _ = b.get("/settings")
	if !strings.Contains(body, "Certificate not installed") || !strings.Contains(body, "previous certificate is still in use") {
		t.Error("rejection not shown to the administrator")
	}
	// a good one is installed and shown
	ca := newTestCA(t)
	chain, key := pemOf(t, ca.leaf(t, -time.Hour, 24*time.Hour*100, "localhost", "easm.example.test"))
	if code, _, _ := b.post("/settings/certificate", url.Values{"cert_pem": {chain}, "key_pem": {key}}); code != 303 {
		t.Fatalf("upload: %d", code)
	}
	_, body, _ = b.get("/settings")
	for _, want := range []string{"Uploaded certificate", "easm.example.test", "Certificate installed", "Remove uploaded certificate"} {
		if !strings.Contains(body, want) {
			t.Errorf("after upload the page is missing %q", want)
		}
	}
	if keyLines := strings.Split(strings.TrimSpace(key), "\n"); strings.Contains(body, keyLines[1]) {
		t.Error("the private key must never be shown again")
	}
	_, audit, _ := b.get("/audit")
	if !strings.Contains(audit, "tls.upload") {
		t.Error("upload not in the audit log")
	}
	b.post("/settings/certificate/remove", nil)
	if _, body, _ = b.get("/settings"); !strings.Contains(body, "Self-signed (browsers warn)") {
		t.Error("remove did not revert")
	}
}
