package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 authenticator apps use HMAC-SHA1; not a collision-resistance use
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Two-factor sign-in for local accounts: time-based one-time codes (RFC 6238, as used by every common
// authenticator app) with single-use recovery codes. Directory (AD) accounts rely on the directory's own MFA.

const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept the previous and next 30-second step to allow for clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret makes a 160-bit secret in the base32 form authenticator apps expect.
func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpCode computes the code for a time step.
func totpCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(key) < 10 {
		return "", fmt.Errorf("the two-factor secret is not valid")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: step is a positive Unix time / 30
	m := hmac.New(sha1.New, key)                     //nolint:gosec // see import note
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%0*d", totpDigits, n), nil
}

// totpVerify checks a typed code and returns the matching step, which the caller must remember so a
// code cannot be used twice. lastUsed is the newest step already accepted for this account.
func totpVerify(secret, typed string, now time.Time, lastUsed int64) (step int64, ok bool) {
	typed = strings.ReplaceAll(strings.TrimSpace(typed), " ", "")
	if len(typed) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		c, err := totpCode(secret, cur+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(c), []byte(typed)) == 1 && cur+d > lastUsed {
			return cur + d, true
		}
	}
	return 0, false
}

// totpURI is what the QR code carries.
func totpURI(account, secret string) string {
	return "otpauth://totp/" + url.PathEscape("EASM Agent:"+account) + "?" + url.Values{
		"secret": {secret}, "issuer": {"EASM Agent"}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(totpDigits)}, "period": {fmt.Sprint(totpPeriod)}}.Encode()
}

// qrDataURI renders text as a QR code image that fits the page's img-src 'self' data: policy.
func qrDataURI(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 220)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// ---------------------------------------------------------------- recovery codes

const recoveryCount = 8

// newRecoveryCodes returns the codes to show the person once and the stored form (newline-separated hashes).
func newRecoveryCodes() (shown []string, stored string, err error) {
	var hashes []string
	for i := 0; i < recoveryCount; i++ {
		b := make([]byte, 6)
		if _, err = rand.Read(b); err != nil {
			return nil, "", err
		}
		h := strings.ToLower(hex.EncodeToString(b)) // 48 bits each, single use, throttled
		code := h[:6] + "-" + h[6:]
		shown = append(shown, code)
		hashes = append(hashes, hashRecovery(code))
	}
	return shown, strings.Join(hashes, "\n"), nil
}

func hashRecovery(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	h := sha256.Sum256([]byte("easm-recovery:" + code))
	return hex.EncodeToString(h[:])
}

// useRecovery checks a recovery code against the stored hashes and returns the remaining hashes.
func useRecovery(stored, typed string) (remaining string, ok bool) {
	want := hashRecovery(typed)
	var keep []string
	for _, h := range strings.Split(stored, "\n") {
		if h == "" {
			continue
		}
		if !ok && subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			ok = true
			continue
		}
		keep = append(keep, h)
	}
	return strings.Join(keep, "\n"), ok
}

func recoveryLeft(stored string) int {
	n := 0
	for _, h := range strings.Split(stored, "\n") {
		if h != "" {
			n++
		}
	}
	return n
}
