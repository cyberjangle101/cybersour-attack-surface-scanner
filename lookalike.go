package main

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Look-alike domain generation: the variations attackers register to imitate a brand. The list is
// built locally; nothing is contacted until the names are looked up in DNS.

type lookalike struct{ Domain, Kind string }

var qwerty = map[rune]string{
	'q': "wa", 'w': "qes", 'e': "wrd", 'r': "etf", 't': "ryg", 'y': "tuh", 'u': "yij", 'i': "uok", 'o': "ipl", 'p': "ol",
	'a': "qsz", 's': "awdx", 'd': "sefc", 'f': "drgv", 'g': "fthb", 'h': "gyjn", 'j': "hukm", 'k': "jil", 'l': "ko",
	'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk",
}

var glyphs = [][2]string{{"o", "0"}, {"l", "1"}, {"l", "i"}, {"i", "1"}, {"i", "l"}, {"m", "rn"}, {"w", "vv"}, {"rn", "m"}, {"vv", "w"},
	{"cl", "d"}, {"s", "5"}, {"e", "3"}, {"a", "4"}, {"b", "d"}, {"g", "q"}, {"u", "v"}, {"n", "m"}}

// cyrillic letters that look like Latin ones.
var confusable = map[rune]rune{'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о', 'p': 'р', 'x': 'х', 'y': 'у', 'i': 'і', 's': 'ѕ', 'j': 'ј'}

// parkingNS are the name-server domains of parking and resale services. A variation served there is
// parked or for sale, not set up to imitate anyone, so it is not reported (it is once it moves away).
var parkingNS = map[string]bool{
	"sedoparking.com": true, "parkingcrew.net": true, "bodis.com": true, "abovedomains.com": true, "above.com": true,
	"afternic.com": true, "dan.com": true, "undeveloped.com": true, "hugedomains.com": true, "parklogic.com": true,
	"namebrightdns.com": true, "namepros-dns.com": true, "atom.com": true, "brandbucket.com": true, "cashparking.com": true,
}

// isParkingNS reports whether a name server belongs to a parking or resale service.
func isParkingNS(host string) bool {
	e, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(host, "."))
	return err == nil && parkingNS[e]
}

var affixes = []string{"login", "secure", "support", "portal", "online", "mail", "account", "verify", "pay", "my", "app", "help"}
var otherTLDs = []string{"com", "net", "org", "co", "io", "app", "info", "biz", "online", "shop", "xyz", "site", "support", "cloud", "dev"}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
		return false
	}
	if len(l) >= 4 && l[2:4] == "--" && !strings.HasPrefix(l, "xn--") {
		return false
	}
	for _, r := range l {
		if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

// splitRegistrable returns the name and public suffix of a registrable domain, or ok=false.
func splitRegistrable(root string) (label, suffix string, ok bool) {
	e, err := publicsuffix.EffectiveTLDPlusOne(root)
	if err != nil || e != root {
		return "", "", false
	}
	suffix, _ = publicsuffix.PublicSuffix(root)
	label = strings.TrimSuffix(root, "."+suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", "", false
	}
	return label, suffix, true
}

// genLookalikes returns up to max distinct variations, mixing every technique so a cap never drops a whole kind.
func genLookalikes(root string, limit int) []lookalike {
	label, suffix, ok := splitRegistrable(root)
	if !ok || !validLabel(label) {
		return nil
	}
	cats := map[string][]string{}
	add := func(kind, l string) {
		if l != label && validLabel(l) {
			cats[kind] = append(cats[kind], l+"."+suffix)
		}
	}
	rs := []rune(label)
	for i := range rs {
		add("missing letter", string(rs[:i])+string(rs[i+1:]))
		add("repeated letter", string(rs[:i+1])+string(rs[i:]))
		if i+1 < len(rs) && rs[i] != rs[i+1] {
			sw := append([]rune(nil), rs...)
			sw[i], sw[i+1] = sw[i+1], sw[i]
			add("swapped letters", string(sw))
		}
		for _, n := range qwerty[rs[i]] {
			add("neighbouring key", string(rs[:i])+string(n)+string(rs[i+1:]))
		}
		if i > 0 {
			add("hyphen added", string(rs[:i])+"-"+string(rs[i:]))
		}
		if strings.ContainsRune("aeiou", rs[i]) {
			for _, v := range "aeiou" {
				if v != rs[i] {
					add("changed vowel", string(rs[:i])+string(v)+string(rs[i+1:]))
				}
			}
		}
		// No bitsquatting (one bit different): those names model memory errors, not people being
		// misled, and on short names they are mostly unrelated words that someone owns legitimately.
		if cy, ok := confusable[rs[i]]; ok {
			u := string(rs[:i]) + string(cy) + string(rs[i+1:])
			if a, err := idna.Lookup.ToASCII(u); err == nil && a != u {
				cats["look-alike letter"] = append(cats["look-alike letter"], a+"."+suffix)
			}
		}
	}
	for _, g := range glyphs {
		for at := 0; ; {
			i := strings.Index(label[at:], g[0])
			if i < 0 {
				break
			}
			i += at
			add("similar-looking characters", label[:i]+g[1]+label[i+len(g[0]):])
			at = i + 1
		}
	}
	for _, a := range affixes {
		add("added word", label+"-"+a)
		add("added word", a+"-"+label)
		add("added word", label+a)
	}
	for _, t := range otherTLDs {
		if t != suffix {
			cats["other ending"] = append(cats["other ending"], label+"."+t)
		}
	}
	// round-robin across the kinds, most convincing first
	order := []string{"swapped letters", "missing letter", "repeated letter", "similar-looking characters", "look-alike letter", "other ending",
		"neighbouring key", "hyphen added", "added word", "changed vowel"}
	seen := map[string]bool{root: true}
	var out []lookalike
	for round := 0; len(out) < limit; round++ {
		progressed := false
		for _, k := range order {
			l := cats[k]
			sort.Strings(l)
			for round < len(l) && seen[l[round]] {
				l = append(l[:round], l[round+1:]...)
			}
			cats[k] = l
			if round < len(l) {
				progressed = true
				seen[l[round]] = true
				out = append(out, lookalike{l[round], k})
				if len(out) >= limit {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
