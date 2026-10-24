//go:debug rsa1024min=0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func codes(is []issue) string {
	var c []string
	for _, i := range is {
		c = append(c, i.Code)
	}
	return strings.Join(c, ",")
}

func TestSPFAndDMARCDetails(t *testing.T) {
	cases := []struct {
		got  []issue
		want string
	}{
		{spfIssues([]string{"v=spf1 -all", "v=spf1 +all"}), "spf-multiple"},
		{spfIssues([]string{"v=spf1 ptr -all"}), "spf-ptr"},
		{spfIssues([]string{"v=spf1 mx -all"}), ""},
		{spfIssues([]string{"v=spf1 include:a.example ?all"}), "spf-neutral"},
		{dmarcIssues([]string{"v=DMARC1; p=reject; sp=none; rua=mailto:a@b.test"}), "dmarc-sp-none"},
		{dmarcIssues([]string{"v=DMARC1; p=quarantine; pct=25; rua=mailto:a@b.test"}), "dmarc-pct"},
		{dmarcIssues([]string{"v=DMARC1; p=reject"}), "dmarc-no-reports"},
		{dmarcIssues([]string{"v=DMARC1; p=reject; rua=mailto:a@b.test"}), ""},
		{dmarcIssues([]string{"v=DMARC1; p=none; rua=mailto:a@b.test"}), "dmarc-p-none"},
		{dmarcIssues(nil), "no-dmarc"},
	}
	for i, c := range cases {
		if got := codes(c.got); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
	if hasMail(&HostResult{Records: map[string][]string{"MX": {"0 "}}}) || !hasMail(&HostResult{Records: map[string][]string{"MX": {"10 mx.example.test"}}}) {
		t.Error("null MX handling")
	}
}

func dkimTXT(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestDKIMKeyStrength(t *testing.T) {
	if is, ok := dkimKeyIssue("s", dkimTXT(t, 512)); !ok || is.Code != "dkim-weak-key" {
		t.Errorf("512-bit key: %v %v", is, ok)
	}
	if is, ok := dkimKeyIssue("s", dkimTXT(t, 1024)); !ok || is.Code != "dkim-short-key" {
		t.Errorf("1024-bit key: %v %v", is, ok)
	}
	if _, ok := dkimKeyIssue("s", dkimTXT(t, 2048)); ok {
		t.Error("2048-bit key flagged")
	}
	if _, ok := dkimKeyIssue("s", "v=DKIM1; p="); ok {
		t.Error("revoked key flagged")
	}
	if _, ok := dkimKeyIssue("s", "v=DKIM1; p=%%%"); ok {
		t.Error("garbage flagged")
	}
}

func emailFindings(t *testing.T, h *harness, status string) map[string]Finding {
	return findingKeys(t, h, "email-auth", status)
}

func TestEmailChecksEndToEnd(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	// 11 chained includes: over the limit of 10
	var inc []string
	for i := 1; i <= 11; i++ {
		inc = append(inc, fmt.Sprintf("include:s%d.example.net", i))
		h.dns.add(t, fmt.Sprintf(`s%d.example.net. 60 IN TXT "v=spf1 ip4:192.0.2.%d -all"`, i, i))
	}
	h.dns.remove("example.test", 16)
	h.dns.add(t, `example.test. 60 IN TXT "v=spf1 `+strings.Join(inc, " ")+` -all"`)
	// a subdomain with mail but no SPF, and a clean one
	h.dns.add(t, "mail.example.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "mail.example.test. 60 IN MX 10 mx.example.test.")
	h.dns.add(t, "mx.example.test. 60 IN A 203.0.113.10")
	h.src.addCert("mail.example.test", "mx.example.test")
	h.dns.remove("example.test", 1)
	h.dns.add(t, "example.test. 60 IN A 203.0.113.10")
	// strip CAA / DNSSEC / MTA-STS / TLS-RPT so those are reported
	h.dns.remove("example.test", 257)
	h.dns.remove("example.test", 43)
	h.dns.remove("_mta-sts.example.test", 16)
	h.dns.remove("_smtp._tls.example.test", 16)
	h.dns.remove("default._domainkey.example.test", 16)
	tg := h.addTarget("example.test", "AS64500")
	h.scan(tg.ID)

	open := emailFindings(t, h, "open")
	want := []string{"spf-too-many-lookups", "no-caa", "no-dnssec", "no-mta-sts", "no-tls-rpt", "dkim-not-found"}
	for _, c := range want {
		if _, ok := open["email:example.test:"+c]; !ok {
			t.Errorf("missing %s; have %v", c, fkeys(open))
		}
	}
	if f, ok := open["email:mail.example.test:no-spf"]; !ok || f.Host != "mail.example.test" || f.Severity != "medium" {
		t.Errorf("subdomain SPF finding: %+v", f)
	}
	if _, ok := open["email:example.test:no-spf"]; ok {
		t.Error("the apex has SPF")
	}
	if _, ok := open["email:www.example.test:no-spf"]; ok {
		t.Error("a host without mail should not need SPF")
	}

	// fix a few things; they resolve, the others stay
	h.dns.add(t, `mail.example.test. 60 IN TXT "v=spf1 mx -all"`)
	h.dns.remove("example.test", 16)
	h.dns.add(t, `example.test. 60 IN TXT "v=spf1 include:s1.example.net -all"`)
	h.dns.add(t, `example.test. 60 IN CAA 0 issue "ca.test"`)
	h.scan(tg.ID)
	res := emailFindings(t, h, "resolved")
	for _, k := range []string{"email:mail.example.test:no-spf", "email:example.test:spf-too-many-lookups", "email:example.test:no-caa"} {
		if _, ok := res[k]; !ok {
			t.Errorf("%s was not resolved; resolved=%v", k, fkeys(res))
		}
	}
	if _, ok := emailFindings(t, h, "open")["email:example.test:no-dnssec"]; !ok {
		t.Error("an unrelated finding was closed")
	}

	// an outage must not close anything
	h.dns.setServfail(true)
	h.scan(tg.ID)
	h.dns.setServfail(false)
	if _, ok := emailFindings(t, h, "open")["email:example.test:no-dnssec"]; !ok {
		t.Error("a DNS outage resolved a finding")
	}
}
