package main

import (
	"strings"
	"testing"
	"time"
)

func TestDNSOutageDoesNotResolveFindings(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")
	h.scan(tg.ID) // opens the api ASN finding
	if open, _ := h.store.ListFindings("example.test", "open"); len(open) != 1 {
		t.Fatalf("setup: expected 1 open finding, got %d", len(open))
	}
	h.dns.setServfail(true) // resolver trouble: we cannot observe anything
	tg = h.scan(tg.ID)
	if tg.LastStatus != "ok" {
		t.Fatalf("scan during DNS trouble: %q %q", tg.LastStatus, tg.LastError)
	}
	if open, _ := h.store.ListFindings("example.test", "open"); len(open) != 1 {
		t.Errorf("a DNS outage must not auto-resolve findings (open=%d)", len(open))
	}
	h.dns.setServfail(false)
	h.scan(tg.ID)
	if open, _ := h.store.ListFindings("example.test", "open"); len(open) != 1 {
		t.Errorf("finding vanished after DNS recovered (open=%d)", len(open))
	}
	// the ASN finding resolves only once the address genuinely moves to an expected network
	h.dns.remove("api.example.test", 1)
	h.dns.add(t, "api.example.test. 60 IN A 203.0.113.10")
	h.scan(tg.ID)
	if res, _ := h.store.ListFindings("example.test", "resolved"); len(res) != 1 {
		t.Errorf("finding should resolve when the address is fixed (resolved=%d)", len(res))
	}
}

func TestWildcardDNSDoesNotCreateRecords(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "wild.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "*.wild.test. 60 IN A 203.0.113.80")
	h.dns.addIP(t, "203.0.113.10", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.dns.addIP(t, "203.0.113.80", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.src.addCert("wild.test")
	h.src.addAnubis("junk1.wild.test", "junk2.wild.test")
	tg := h.addTarget("wild.test", "")
	h.scan(tg.ID)
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM records WHERE value='203.0.113.80'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("wildcard-synthesised addresses were stored (%d rows, %v)", n, err)
	}
	if _, total, _ := h.store.Inventory("wild.test", "", 10); total != 3 {
		t.Errorf("hosts still listed from passive sources, want 3 got %d", total)
	}
}

func TestSMTPSecurityModes(t *testing.T) {
	cfg := selfSignedTLS(t)
	cases := []struct {
		name, security string
		implicit       bool
	}{{"starttls", "starttls", false}, {"implicit-tls", "tls", true}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			srv := newFakeSMTPWith(t, cfg, c.implicit, "alerts", "s3cret-pass")
			st, _ := h.store.LoadSettings()
			st.SMTPPort, st.SMTPSecurity, st.SMTPInsecureSkipVerify, st.SMTPUsername = srv.port(), c.security, true, "alerts"
			h.saveSettings(st)
			if err := h.eng.SetSMTPPassword("s3cret-pass"); err != nil {
				t.Fatal(err)
			}
			if err := h.eng.SendTestEmail(testCtx(t)); err != nil {
				t.Fatalf("send: %v", err)
			}
			srv.mu.Lock()
			auth, tlsSeen := srv.authSeen, srv.tlsSeen
			srv.mu.Unlock()
			if !auth {
				t.Error("AUTH was not performed")
			}
			if c.security == "starttls" && !tlsSeen {
				t.Error("STARTTLS was not negotiated")
			}
			if msgs := srv.all(); len(msgs) != 1 || !strings.Contains(parseMail(t, msgs[0]).Subject, "test message") {
				t.Errorf("message not delivered: %v", msgs)
			}
			// wrong password must fail cleanly
			_ = h.eng.SetSMTPPassword("wrong")
			if err := h.eng.SendTestEmail(testCtx(t)); err == nil {
				t.Error("bad credentials should fail")
			}
		})
	}
}

func TestStartTLSRefusedWithoutServerSupport(t *testing.T) {
	h := newHarness(t) // fake server advertises no STARTTLS
	st, _ := h.store.LoadSettings()
	st.SMTPSecurity = "starttls"
	h.saveSettings(st)
	err := h.eng.SendTestEmail(testCtx(t))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("must refuse to fall back to cleartext, got %v", err)
	}
	if h.smtp.count() != 0 {
		t.Error("message was sent in cleartext")
	}
}

func TestDigestScheduleAndContent(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	tg := h.addTarget("example.test", "AS64500")
	h.scan(tg.ID)
	base := h.smtp.count()

	st, _ := h.store.LoadSettings()
	st.DigestFrequency, st.DigestHour = "daily", 0
	h.saveSettings(st)

	h.eng.maybeDigest(testCtx(t)) // first run only starts the clock
	if h.smtp.count() != base {
		t.Fatal("digest must not fire the first time it is enabled")
	}
	if _, ok, _ := h.store.getMeta("digest_last"); !ok {
		t.Fatal("digest clock not started")
	}
	_ = h.store.setMeta("digest_last", time.Now().Add(-49*time.Hour).UTC().Format(time.RFC3339))
	h.eng.maybeDigest(testCtx(t))
	mails := h.mails()
	if len(mails) != base+1 {
		t.Fatalf("expected one digest, got %d new mails", len(mails)-base)
	}
	d := mails[len(mails)-1]
	for _, want := range []string{"example.test", "asn-unexpected", "api.example.test"} {
		if !strings.Contains(d.Plain, want) || !strings.Contains(d.HTML, want) {
			t.Errorf("digest missing %q", want)
		}
	}
	if !strings.Contains(d.Subject, "report") {
		t.Errorf("subject %q", d.Subject)
	}
	h.eng.maybeDigest(testCtx(t)) // same day: nothing more
	if h.smtp.count() != base+1 {
		t.Error("digest sent twice")
	}
}

func TestReportExportsAreSafe(t *testing.T) {
	if csvSafe("=cmd|' /C calc'!A0") == "=cmd|' /C calc'!A0" || csvSafe("@SUM(1)") == "@SUM(1)" || csvSafe("+1") == "+1" {
		t.Error("formula prefixes must be neutralised")
	}
	if csvSafe("host.example.com") != "host.example.com" {
		t.Error("normal values must pass through")
	}
}

func TestInputValidation(t *testing.T) {
	bad := []struct{ domain, asns, ignore, interval string }{
		{"not a domain", "", "", ""}, {"user@example.com", "", "", ""}, {"10.0.0.1", "", "", ""}, {"localhost", "", "", ""},
		{"example.com", "ASxyz", "", ""}, {"example.com", "", "([unclosed", ""}, {"example.com", "", "", "5"}, {"example.com", "", "", "abc"},
		{"example.com", "0", "", ""}, {"http://example.com/path", "", "", ""},
	}
	for _, b := range bad {
		if _, err := TargetFromForm(b.domain, b.asns, "", b.ignore, b.interval, ""); err == nil {
			t.Errorf("accepted bad input %+v", b)
		}
	}
	tg, err := TargetFromForm(" WWW.Example.COM. ", "AS13335, 16509\n as8075", "Foo, Bar\nFoo", `^ci-\d+\.`, "60", "note")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Domain != "www.example.com" || len(tg.ExpectedASNs) != 3 || len(tg.ExpectedOrgKeywords) != 2 || tg.IntervalMinutes != 60 {
		t.Errorf("normalisation wrong: %+v", tg)
	}
}

func TestSettingsValidationAndSecretStorage(t *testing.T) {
	st := DefaultSettings()
	if err := st.Normalize(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	for name, mut := range map[string]func(*Settings){
		"interval too small": func(s *Settings) { s.IntervalMinutes = 1 },
		"bad resolver":       func(s *Settings) { s.DNSResolvers = []string{"dns.google"} },
		"bad severity":       func(s *Settings) { s.AlertImmediateSeverity = "urgent" },
		"smtp w/o host":      func(s *Settings) { s.SMTPEnabled = true },
		"bad url":            func(s *Settings) { s.PublicURL = "javascript:alert(1)" },
		"header injection":   func(s *Settings) { s.SMTPSubjectPrefix = "x\r\nBcc: a@b.c" },
		"bad recipient":      func(s *Settings) { s.SMTPTo = []string{"nope"} },
	} {
		s := DefaultSettings()
		mut(&s)
		if err := s.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	h := newHarness(t)
	if err := h.eng.SetSMTPPassword("hunter2-hunter2"); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := h.store.getMeta(secretSMTP)
	if raw == "" || strings.Contains(raw, "hunter2") {
		t.Errorf("password not encrypted at rest: %q", raw)
	}
	if h.eng.SMTPPassword() != "hunter2-hunter2" {
		t.Error("password round-trip failed")
	}
	var js string
	_ = h.store.db.QueryRow(`SELECT v FROM meta WHERE k='settings'`).Scan(&js)
	if strings.Contains(js, "hunter2") {
		t.Error("password leaked into settings JSON")
	}
	// a different key cannot read the secret
	other, _ := OpenVault(h.dir + "/other.key")
	if _, err := other.Open(raw); err == nil {
		t.Error("secret decrypted with the wrong key")
	}
}

func TestNormalizeHostAndParsers(t *testing.T) {
	for in, want := range map[string]string{"WWW.Example.com.": "www.example.com", "*.example.com": "example.com", "user@example.com": "",
		"bad host.com": "", "a_b.example.com": "a_b.example.com", "localhost": "", "x.example.com:443": ""} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q)=%q want %q", in, got, want)
		}
	}
	asn, prefix, cc, err := parseCymruOrigin("13335 15169 | 1.1.1.0/24 | AU | apnic | 2011-08-11")
	if err != nil || asn != 13335 || prefix != "1.1.1.0/24" || cc != "AU" {
		t.Errorf("cymru parse: %d %q %q %v", asn, prefix, cc, err)
	}
	// A negative, signed or out-of-range ASN is malformed (found by FuzzCymruAndEmailPolicy).
	for _, bad := range []string{"-1||", "-13335 | 1.1.1.0/24 | AU", "+13335 | 1.1.1.0/24 | AU", "4294967296 | 1.1.1.0/24 | AU"} {
		if asn, _, _, err := parseCymruOrigin(bad); err == nil {
			t.Errorf("parseCymruOrigin(%q) = %d, want error", bad, asn)
		}
	}
	if asn, _, _, err := parseCymruOrigin("4294967295 | 1.1.1.0/24 | AU"); err != nil || asn != 4294967295 {
		t.Errorf("max 32-bit ASN: %d %v", asn, err)
	}
	if got := cymruOriginName(netIP("8.8.4.4")); got != "4.4.8.8.origin.asn.cymru.com" {
		t.Errorf("cymru v4 name %s", got)
	}
	if got := cymruOriginName(netIP("2001:db8::1")); !strings.HasSuffix(got, ".origin6.asn.cymru.com") || strings.Count(got, ".") != 35 {
		t.Errorf("cymru v6 name %s", got)
	}
	if takeoverProvider("foo.github.io.") != "github.io" || takeoverProvider("mail.example.com") != "" {
		t.Error("takeover provider detection")
	}
	if got := spfIssues([]string{"v=spf1 +all"}); len(got) != 1 || got[0].Severity != "high" {
		t.Errorf("spf +all: %v", got)
	}
	if got := dmarcIssues([]string{"v=DMARC1; p=none; rua=mailto:a@example.test"}); len(got) != 1 || got[0].Code != "dmarc-p-none" {
		t.Errorf("dmarc none: %v", got)
	}
}
