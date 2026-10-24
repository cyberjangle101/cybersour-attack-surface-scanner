package main

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/net/publicsuffix"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

var hostRe = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$`)

// normalizeHost lowercases, strips trailing dots and a leading wildcard label,
// and returns "" if the result is not a plausible DNS hostname.
func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	if isNonASCII(s) { // internationalised names (bücher.example) are stored and queried in their ASCII form (xn--bcher-kva.example)
		a, err := idna.Registration.ToASCII(s)
		if err != nil {
			return ""
		}
		s = a
	}
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "*@ /:\\") {
		return ""
	}
	if !hostRe.MatchString(s) {
		return ""
	}
	return s
}

func isNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

func inScope(host, root string) bool {
	return host == root || strings.HasSuffix(host, "."+root)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}

func sevRank(s string) int { return severityRank[strings.ToLower(s)] }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func joinSorted(in []string) string {
	c := append([]string(nil), in...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// registeredDomain returns the registrable domain of name ("www.example.co.uk" -> "example.co.uk"),
// using the public-suffix list (which also knows hosting suffixes such as github.io). It returns
// "" when name is itself a public suffix or cannot be classified.
func registeredDomain(name string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return d
}

// isSubdomainScope reports whether name sits below a registrable domain, so that monitoring it
// covers only part of the organisation's namespace.
func isSubdomainScope(name string) bool {
	d := registeredDomain(name)
	return d != "" && d != name
}
