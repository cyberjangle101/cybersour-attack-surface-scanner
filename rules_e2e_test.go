package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// End-to-end tests for rules whose logic was only unit-tested before: each one feeds a full
// scan the DNS or TLS data the rule looks for and checks that the stored finding appears
// (rules_coverage_test.go fails the suite when any rule never fires like this).

// mailDomain publishes a domain that receives mail, with the given SPF records, DMARC record
// and DKIM key at the "default" selector. MTA-STS, TLS reporting, CAA and DNSSEC are in place so
// only the rules under test fire.
func mailDomain(t *testing.T, h *harness, domain string, spf []string, dmarc, dkim string) {
	t.Helper()
	d := h.dns
	d.add(t, domain+". 60 IN A 203.0.113.10")
	d.add(t, domain+". 60 IN MX 10 mail."+domain+".")
	d.add(t, "mail."+domain+". 60 IN A 203.0.113.12")
	for _, s := range spf {
		d.add(t, fmt.Sprintf(`%s. 60 IN TXT "%s"`, domain, s))
	}
	if dmarc != "" {
		d.add(t, fmt.Sprintf(`_dmarc.%s. 60 IN TXT "%s"`, domain, dmarc))
	}
	d.add(t, fmt.Sprintf(`default._domainkey.%s. 60 IN TXT "%s"`, domain, dkim))
	d.add(t, fmt.Sprintf(`_mta-sts.%s. 60 IN TXT "v=STSv1; id=1"`, domain))
	d.add(t, fmt.Sprintf(`_smtp._tls.%s. 60 IN TXT "v=TLSRPTv1; rua=mailto:tls@%s"`, domain, domain))
	d.add(t, fmt.Sprintf(`%s. 60 IN CAA 0 issue "ca.test"`, domain))
	d.add(t, fmt.Sprintf(`%s. 60 IN DS 12345 13 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC1234`, domain))
	h.src.addCert(domain, "mail."+domain)
}

// emailCodes returns the email-auth checks open for a domain (the last part of each key).
func emailCodes(t *testing.T, h *harness, domain string) map[string]Finding {
	t.Helper()
	out := map[string]Finding{}
	for _, f := range findingsOf(t, h, domain, "email-auth", "open") {
		out[f.Key[strings.LastIndex(f.Key, ":")+1:]] = f
	}
	return out
}

func TestEmailRulesFireOnScannedDNS(t *testing.T) {
	h := newHarness(t)
	const goodDMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@example.test"
	const okKey = "v=DKIM1; k=rsa; p=AAAA" // present but not parseable as a key: no strength finding
	cases := []struct {
		domain string
		spf    []string
		dmarc  string
		dkim   string
		want   map[string]string // check -> severity
		not    []string
	}{
		{"permissive.test", []string{"v=spf1 +all"}, "v=DMARC1; p=none; rua=mailto:d@permissive.test", dkimTXT(t, 1024),
			map[string]string{"spf-permissive": "high", "dmarc-p-none": "low", "dkim-short-key": "low"},
			[]string{"dmarc-sp-none", "dmarc-pct", "dmarc-no-reports", "no-spf", "no-dmarc"}},
		{"multiple.test", []string{"v=spf1 -all", "v=spf1 include:_spf.multiple.test -all"}, "v=DMARC1; p=reject; sp=none; pct=25", okKey,
			map[string]string{"spf-multiple": "high", "dmarc-sp-none": "medium", "dmarc-pct": "low", "dmarc-no-reports": "low"},
			[]string{"dmarc-p-none", "dkim-short-key", "dkim-weak-key"}},
		{"neutral.test", []string{"v=spf1 ?all"}, goodDMARC, okKey,
			map[string]string{"spf-neutral": "medium"},
			[]string{"spf-permissive", "spf-ptr", "dmarc-no-reports"}},
		{"ptr.test", []string{"v=spf1 ptr -all"}, goodDMARC, okKey,
			map[string]string{"spf-ptr": "low"},
			[]string{"spf-neutral", "spf-permissive"}},
	}
	for _, c := range cases {
		mailDomain(t, h, c.domain, c.spf, c.dmarc, c.dkim)
	}
	for _, c := range cases {
		tg := h.addTarget(c.domain, "")
		h.scan(tg.ID)
		got := emailCodes(t, h, c.domain)
		for code, sev := range c.want {
			if f, ok := got[code]; !ok {
				t.Errorf("%s: %s not raised; open checks %v", c.domain, code, keysOf(got))
			} else if f.Severity != sev {
				t.Errorf("%s: %s severity %s, want %s", c.domain, code, f.Severity, sev)
			}
		}
		for _, code := range c.not {
			if _, ok := got[code]; ok {
				t.Errorf("%s: %s raised but the record is fine in that respect", c.domain, code)
			}
		}
	}
}

// DKIM keys under 1024 bits cannot be generated with crypto/rsa any more, so EASM-MAIL-013
// (weak key) is fed a real 512-bit public key, encoded by hand.
func TestDKIMWeakKeyFiresOnScannedDNS(t *testing.T) {
	h := newHarness(t)
	mailDomain(t, h, "weakdkim.test", []string{"v=spf1 -all"}, "v=DMARC1; p=reject; rua=mailto:d@weakdkim.test", dkim512)
	tg := h.addTarget("weakdkim.test", "")
	h.scan(tg.ID)
	f, ok := emailCodes(t, h, "weakdkim.test")["dkim-weak-key"]
	if !ok || f.Severity != "medium" || !strings.Contains(f.Detail, "512 bits") {
		t.Fatalf("512-bit DKIM key not reported: %+v (open: %v)", f, keysOf(emailCodes(t, h, "weakdkim.test")))
	}
	// replaced with a strong key: the finding closes
	h.dns.remove("default._domainkey.weakdkim.test.", 16) // TXT
	h.dns.add(t, `default._domainkey.weakdkim.test. 60 IN TXT "v=DKIM1; k=rsa; p=AAAA"`)
	h.scan(tg.ID)
	if _, ok := emailCodes(t, h, "weakdkim.test")["dkim-weak-key"]; ok {
		t.Error("the weak-key finding should close once the key is replaced")
	}
}

// dkim512 is a DKIM record holding a 512-bit RSA public key (SubjectPublicKeyInfo, base64).
var dkim512 = func() string {
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	n.Add(n, big.NewInt(0x1d)) // any odd 512-bit modulus will do: only its length is checked
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		panic(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}()

func TestPrivateAddressInPublicDNS(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "intranet.example.test. 60 IN A 10.20.30.40")
	h.src.addCert("example.test", "intranet.example.test")
	tg := h.addTarget("example.test", "AS64500")
	h.scan(tg.ID)
	f := openFindingOf(t, h, "example.test", "private-ip", "intranet.example.test")
	if f == nil || f.Severity != "low" || !strings.Contains(f.Detail, "10.20.30.40") {
		t.Fatalf("private address not reported: %+v", f)
	}
	if openFindingOf(t, h, "example.test", "asn-unexpected", "intranet.example.test") != nil {
		t.Error("a private address has no ASN, so it must not also count as outside the expected networks")
	}
}

func TestCloudDatastoreNameInPublicDNS(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "db.example.test. 60 IN CNAME prod.abc123.eu-west-1.rds.amazonaws.com.")
	h.dns.add(t, "prod.abc123.eu-west-1.rds.amazonaws.com. 60 IN A 198.51.100.40")
	h.src.addCert("example.test", "db.example.test")
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	f := openFindingOf(t, h, "example.test", "cloud-datastore", "db.example.test")
	if f == nil || f.Severity != "medium" || !strings.Contains(f.Detail, "AWS RDS") {
		t.Fatalf("managed database name not reported: %+v", f)
	}
}

// weakLeaf issues a certificate with a 1024-bit RSA key, signed with ECDSA and SHA-1.
func (ca *testCA) weakLeaf(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour), SignatureAlgorithm: x509.ECDSAWithSHA1,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestWeakCertificateKeyAndSignature(t *testing.T) {
	l := newWebLab(t)
	good := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "www.example.test", "example.test")
	l.serve("203.0.113.10", 443, page("Home", "hello"), &good, tls.VersionTLS12)
	l.host("legacy.example.test", "203.0.113.33")
	weak := l.ca.weakLeaf(t, "legacy.example.test")
	l.serve("203.0.113.33", 443, page("Legacy", "x"), &weak, tls.VersionTLS12)
	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scan(tg.ID)

	if f := l.findingFor("tls-weak-key", "legacy.example.test"); f == nil || f.Severity != "medium" || !strings.Contains(f.Detail, "1024-bit RSA") {
		t.Errorf("weak key not reported: %+v (open: %v)", f, l.openKinds())
	}
	if f := l.findingFor("tls-weak-signature", "legacy.example.test"); f == nil || !strings.Contains(f.Detail, "SHA-1") {
		t.Errorf("SHA-1 signature not reported: %+v (open: %v)", f, l.openKinds())
	}
	for _, k := range []string{"tls-weak-key", "tls-weak-signature"} {
		if f := l.findingFor(k, "www.example.test"); f != nil {
			t.Errorf("%s raised for the healthy certificate: %+v", k, f)
		}
	}
}
