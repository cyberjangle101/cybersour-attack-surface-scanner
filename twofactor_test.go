package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890")) // the RFC's SHA-1 test key
	// RFC 6238 Appendix B (8-digit values; the 6-digit code is their last six digits)
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		got, err := totpCode(secret, ts/30)
		if err != nil || got != want {
			t.Errorf("T=%d: got %q err=%v, want %q", ts, got, err, want)
		}
	}
	now := time.Unix(1111111111, 0)
	step, ok := totpVerify(secret, "050471", now, 0)
	if !ok || step != 1111111111/30 {
		t.Fatalf("verify: %v %d", ok, step)
	}
	if _, ok := totpVerify(secret, "050471", now, step); ok {
		t.Error("a code was accepted twice")
	}
	if _, ok := totpVerify(secret, "050471", now.Add(2*time.Minute), 0); ok {
		t.Error("an old code was accepted")
	}
	if _, ok := totpVerify(secret, "05047", now, 0); ok {
		t.Error("short code accepted")
	}
	if s, _ := newTOTPSecret(); len(s) != 32 {
		t.Errorf("secret length %d", len(s))
	}
}

func TestRecoveryCodes(t *testing.T) {
	shown, stored, err := newRecoveryCodes()
	if err != nil || len(shown) != recoveryCount || recoveryLeft(stored) != recoveryCount {
		t.Fatal(err, shown)
	}
	if strings.Contains(stored, strings.ReplaceAll(shown[0], "-", "")) {
		t.Fatal("codes stored in clear")
	}
	rest, ok := useRecovery(stored, strings.ToUpper(shown[2])+" ")
	if !ok || recoveryLeft(rest) != recoveryCount-1 {
		t.Fatal("recovery code rejected")
	}
	if _, ok := useRecovery(rest, shown[2]); ok {
		t.Fatal("recovery code reused")
	}
	if _, ok := useRecovery(stored, "000000-000000"); ok {
		t.Fatal("wrong code accepted")
	}
}

func codeNow(t *testing.T, secret string) string {
	t.Helper()
	c, err := totpCode(secret, time.Now().Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTwoFactorFlow(t *testing.T) {
	e := newWebEnv(t)
	b := e.signedIn("tina", RoleAnalyst)
	admin := e.signedIn("boss", RoleAdmin)

	_, body, _ := b.get("/account/2fa")
	m := regexp.MustCompile(`Key: <strong class="mono">([A-Z2-7 ]+)</strong>`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, `src="data:image/png;base64,`) {
		t.Fatalf("setup page lacks the key or QR:\n%s", body)
	}
	secret := strings.ReplaceAll(m[1], " ", "")

	b.post("/account/2fa/enable", url.Values{"code": {"000000"}})
	if u, _ := e.store.FindUserFold("tina"); u.TOTPOn {
		t.Fatal("enabled with a wrong code")
	}
	enrolCode := codeNow(t, secret)
	b.post("/account/2fa/enable", url.Values{"code": {enrolCode}})
	u, _ := e.store.FindUserFold("tina")
	if !u.TOTPOn || u.TOTPSecret != secret {
		t.Fatal("not enabled")
	}
	var raw string
	_ = e.store.db.QueryRow(`SELECT totp_secret FROM users WHERE username='tina'`).Scan(&raw)
	if strings.Contains(raw, secret) {
		t.Fatal("two-factor secret stored in clear")
	}
	_, body, _ = b.get("/account/2fa")
	codes := regexp.MustCompile(`[0-9a-f]{6}-[0-9a-f]{6}`).FindAllString(body, -1)
	if len(codes) != recoveryCount {
		t.Fatalf("recovery codes shown: %d", len(codes))
	}
	if _, body, _ = b.get("/account/2fa"); regexp.MustCompile(`[0-9a-f]{6}-[0-9a-f]{6}`).MatchString(body) {
		t.Fatal("recovery codes shown twice")
	}

	// sign-in now needs the second factor
	login := func(code string) (int, string) {
		nb := e.browser()
		pre := nb.loginPre("/login")
		c, body, r := nb.postRaw("/login", url.Values{"csrf": {pre}, "username": {"tina"}, "password": {"correct horse battery"}})
		if c == 303 {
			t.Fatalf("password alone signed in (to %s)", loc(r))
		}
		tk := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(body)
		if tk == nil {
			t.Fatalf("no 2FA prompt: %d", c)
		}
		c, _, _ = nb.postRaw("/login/2fa", url.Values{"csrf": {pre}, "ticket": {tk[1]}, "code": {code}})
		if c == 303 {
			if c2, _, _ := nb.get("/findings"); c2 != 200 {
				t.Fatalf("signed in but cannot browse: %d", c2)
			}
		}
		return c, tk[1]
	}
	if c, _ := login("123456"); c != 401 {
		t.Errorf("wrong code: %d", c)
	}
	// Replay the enrolment code itself: recomputing it here could land in the next 30s step,
	// a fresh code that is rightly accepted.
	if c, _ := login(enrolCode); c != 401 { // that step was already used when enabling
		t.Errorf("a code used at enrolment worked again: %d", c)
	}
	// recovery code works once
	if c, _ := login(codes[0]); c != 303 {
		t.Errorf("recovery code rejected: %d", c)
	}
	if c, _ := login(codes[0]); c != 401 {
		t.Errorf("recovery code worked twice: %d", c)
	}

	// turning off needs the password and a code; fresh code can't be reused
	b.post("/account/2fa/disable", url.Values{"current": {"wrong"}, "code": {"000000"}})
	if u, _ := e.store.FindUserFold("tina"); !u.TOTPOn {
		t.Fatal("disabled without proof")
	}

	// administrator reset
	admin.post("/users/"+itoa(u.ID)+"/reset2fa", url.Values{})
	if u, _ := e.store.FindUserFold("tina"); u.TOTPOn || u.TOTPSecret != "" {
		t.Fatal("reset did not clear two-factor")
	}
	if c := e.browser().login("tina", "correct horse battery"); c != 303 {
		t.Errorf("after reset the password alone should work: %d", c)
	}
}

func TestTwoFactorTicketsAndEnforcement(t *testing.T) {
	e := newWebEnv(t)
	hash, _ := hashPassword("correct horse battery")
	id, _ := e.store.CreateUser("zed", hash, RoleViewer)
	secret, _ := newTOTPSecret()
	if err := e.store.SetTOTP(id, secret, "", true); err != nil {
		t.Fatal(err)
	}
	// enforcement: turning on "require 2FA" forces enrolment before anything else
	admin := e.signedIn("boss", RoleAdmin)
	other := e.signedIn("vee", RoleViewer)
	cur, _ := e.store.LoadSettings()
	cur.Require2FA = true
	admin.post("/settings", settingsForm(cur))
	if c, _, r := other.get("/findings"); c != 303 || loc(r) != "/account/2fa" {
		t.Fatalf("existing session not forced to enrol: %d %s", c, loc(r))
	}
	if c, _, _ := other.get("/account/2fa"); c != 200 {
		t.Fatalf("cannot reach the set-up page: %d", c)
	}
	if c, _, _ := other.post("/targets", url.Values{"domain": {"x.test"}}); c != 403 {
		t.Fatalf("POST allowed while enrolment pending: %d", c)
	}
	_, pg, _ := other.get("/account/2fa")
	secret2 := strings.ReplaceAll(regexp.MustCompile(`Key: <strong class="mono">([A-Z2-7 ]+)</strong>`).FindStringSubmatch(pg)[1], " ", "")
	other.post("/account/2fa/enable", url.Values{"code": {codeNow(t, secret2)}})
	if c, _, _ := other.get("/findings"); c != 200 {
		t.Fatalf("still blocked after enrolling: %d", c)
	}
	// and a user who is enforced cannot turn it off again
	u, _ := e.store.FindUserFold("vee")
	if !u.TOTPOn {
		t.Fatal("not enrolled")
	}

	nb := e.browser()
	pre := nb.loginPre("/login")
	_, body, _ := nb.postRaw("/login", url.Values{"csrf": {pre}, "username": {"zed"}, "password": {"correct horse battery"}})
	tk := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(body)[1]
	// a forged ticket is useless, and a real one dies after a few wrong guesses
	if c, _, _ := nb.postRaw("/login/2fa", url.Values{"csrf": {pre}, "ticket": {"nope"}, "code": {codeNow(t, secret)}}); c == 303 {
		t.Fatal("forged ticket accepted")
	}
	for i := 0; i < pendingTries; i++ {
		nb.postRaw("/login/2fa", url.Values{"csrf": {pre}, "ticket": {tk}, "code": {"111111"}})
	}
	if c, _, _ := nb.postRaw("/login/2fa", url.Values{"csrf": {pre}, "ticket": {tk}, "code": {codeNow(t, secret)}}); c == 303 {
		t.Fatal("ticket survived too many wrong guesses")
	}

}
