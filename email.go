package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Email and DNS hygiene checks beyond the basic SPF and DMARC presence tests: SPF correctness and
// the 10-lookup limit, DMARC details, DKIM keys, MTA-STS, TLS reporting, CAA and DNSSEC, and SPF on subdomains.
// Everything here is DNS only. A check whose lookups failed is left unchecked so it cannot close a finding.

// hostIssue is an issue found at a specific name.
type hostIssue struct {
	Host string
	issue
}

// mailPosture is the outcome of the checks for one target.
type mailPosture struct {
	issues  []hostIssue
	checked map[string]bool // "host|code": evaluated reliably this scan (whether or not it was a problem)
}

func (m *mailPosture) did(host string, codes ...string) {
	for _, c := range codes {
		m.checked[host+"|"+c] = true
	}
}

func (m *mailPosture) add(host, code, sev, detail string) {
	m.issues = append(m.issues, hostIssue{host, issue{code, sev, detail}})
	m.checked[host+"|"+code] = true
}

// reliable says whether a finding of this key may be closed.
func (m *mailPosture) reliable(host, code string) bool {
	return m != nil && m.checked[host+"|"+code]
}

func spfRecords(txt []string) []string {
	var out []string
	for _, t := range txt {
		if tl := strings.ToLower(strings.TrimSpace(t)); tl == "v=spf1" || strings.HasPrefix(tl, "v=spf1 ") {
			out = append(out, tl)
		}
	}
	return out
}

func hasMail(hr *HostResult) bool {
	if hr == nil {
		return false
	}
	for _, mx := range hr.Records["MX"] {
		if f := strings.Fields(mx); len(f) == 2 && f[1] != "." { // "0 ." is the null MX: this name explicitly accepts no mail
			return true
		}
	}
	return false
}

// spfLookups counts the DNS-querying terms of an SPF record, following include and redirect (RFC 7208 section 4.6.4).
func (s *Scanner) spfLookups(ctx context.Context, record string, depth int, seen map[string]bool) (n int, ok bool) {
	if depth > 6 {
		return 0, true
	}
	ok = true
	for _, tok := range strings.Fields(record) {
		tok = strings.TrimLeft(tok, "+-~?")
		name, val, _ := strings.Cut(tok, ":")
		switch {
		case name == "include" || strings.HasPrefix(tok, "redirect="):
			n++
			target := val
			if strings.HasPrefix(tok, "redirect=") {
				target = strings.TrimPrefix(tok, "redirect=")
			}
			target = cleanName(target)
			if target == "" || seen[target] {
				continue
			}
			seen[target] = true
			txts, nx, err := s.res.TXT(ctx, target)
			if err != nil {
				ok = false
				continue
			}
			if nx {
				continue
			}
			if recs := spfRecords(txts); len(recs) > 0 {
				sub, subOK := s.spfLookups(ctx, recs[0], depth+1, seen)
				n += sub
				ok = ok && subOK
			}
		case name == "a" || name == "mx" || name == "ptr" || name == "exists":
			n++
		case tok == "a" || tok == "mx" || tok == "ptr":
			n++
		}
	}
	return n, ok
}

// commonSelectors are DKIM selectors used by the large mail services. DKIM selectors cannot be listed, so this is a probe.
var commonSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1", "cm", "zendesk1", "mimecast20190104"}

// emailPosture runs the checks. hosts are the resolved hosts of the target.
func (s *Scanner) emailPosture(ctx context.Context, root string, hosts []string, results map[string]*HostResult) *mailPosture {
	m := &mailPosture{checked: map[string]bool{}}
	rr := results[root]
	if rr == nil || rr.NX {
		return m
	}
	mailDomain := hasMail(rr)

	// ---- SPF at the apex (the original checks plus the new ones)
	if !rr.Failed["TXT"] {
		txts := rr.Records["TXT"]
		for _, is := range spfIssues(txts) {
			m.add(root, is.Code, is.Severity, strings.ReplaceAll(is.Detail, "<domain>", root))
		}
		m.did(root, "no-spf", "spf-permissive", "spf-neutral", "spf-multiple", "spf-ptr", "spf-too-many-lookups")
		if recs := spfRecords(txts); len(recs) == 1 && ctx.Err() == nil {
			n, ok := s.spfLookups(ctx, recs[0], 0, map[string]bool{root: true})
			switch {
			case n > 10:
				m.add(root, "spf-too-many-lookups", "medium", fmt.Sprintf("the SPF record needs %d DNS lookups to evaluate; the limit is 10, and receivers treat anything over it as an error (SPF fails)", n))
			case !ok:
				delete(m.checked, root+"|spf-too-many-lookups") // some includes could not be read: unknown
			}
		}
	}

	// ---- DMARC at the apex
	if txts, _, err := s.res.TXT(ctx, "_dmarc."+root); err == nil {
		for _, is := range dmarcIssues(txts) {
			m.add(root, is.Code, is.Severity, strings.ReplaceAll(is.Detail, "<domain>", root))
		}
		m.did(root, "no-dmarc", "dmarc-p-none", "dmarc-sp-none", "dmarc-pct", "dmarc-no-reports")
	}

	// ---- SPF on subdomains that receive mail
	for _, h := range hosts {
		if h == root || ctx.Err() != nil {
			continue
		}
		hr := results[h]
		if hr == nil || hr.NX || hr.Failed["TXT"] || hr.Failed["MX"] || !hasMail(hr) {
			continue
		}
		recs := spfRecords(hr.Records["TXT"])
		switch {
		case len(recs) == 0:
			m.add(h, "no-spf", "medium", fmt.Sprintf("%s has mail servers (MX records) but publishes no SPF record, so anyone can send mail that claims to come from it", h))
		case len(recs) > 1:
			m.add(h, "spf-multiple", "high", fmt.Sprintf("%s publishes %d SPF records; receivers treat that as an error and SPF fails for every message", h, len(recs)))
		default:
			for _, is := range spfIssues(hr.Records["TXT"]) {
				m.add(h, is.Code, is.Severity, strings.ReplaceAll(is.Detail, "<domain>", h))
			}
		}
		m.did(h, "no-spf", "spf-multiple", "spf-permissive", "spf-neutral", "spf-ptr")
	}

	// ---- DKIM (only meaningful for a domain that handles mail)
	if mailDomain && ctx.Err() == nil {
		found, failed := 0, 0
		for _, sel := range commonSelectors {
			name := sel + "._domainkey." + root
			txts, nx, err := s.res.TXT(ctx, name)
			if err != nil {
				failed++
				continue
			}
			if nx || len(txts) == 0 {
				// A CNAME to the provider's key also counts; the resolver follows it when it exists.
				continue
			}
			found++
			for _, t := range txts {
				if is, ok := dkimKeyIssue(sel, t); ok {
					m.add(root, is.Code, is.Severity, strings.ReplaceAll(is.Detail, "<domain>", root))
				}
			}
		}
		if found == 0 && failed == 0 {
			m.add(root, "dkim-not-found", "low", fmt.Sprintf("none of the %d most common DKIM selectors has a key for %s. Your mail provider may use a different selector name; if mail from this domain is not signed, receivers have one less way to trust it", len(commonSelectors), root))
		}
		if failed == 0 {
			m.did(root, "dkim-not-found")
		}
		m.did(root, "dkim-weak-key", "dkim-short-key")
		if found > 0 && failed > 0 {
			delete(m.checked, root+"|dkim-weak-key")
			delete(m.checked, root+"|dkim-short-key")
		}

		// ---- MTA-STS and TLS reporting
		if txts, _, err := s.res.TXT(ctx, "_mta-sts."+root); err == nil {
			if !hasPrefixRecord(txts, "v=stsv1") {
				m.add(root, "no-mta-sts", "low", fmt.Sprintf("%s receives mail but publishes no MTA-STS policy, so a network attacker can downgrade the encryption of mail sent to it", root))
			}
			m.did(root, "no-mta-sts")
		}
		if txts, _, err := s.res.TXT(ctx, "_smtp._tls."+root); err == nil {
			if !hasPrefixRecord(txts, "v=tlsrptv1") {
				m.add(root, "no-tls-rpt", "low", fmt.Sprintf("%s publishes no TLS reporting address, so failures to deliver mail to it securely go unnoticed", root))
			}
			m.did(root, "no-tls-rpt")
		}
	}

	// ---- CAA and DNSSEC
	if ctx.Err() == nil {
		if in, err := s.res.query(ctx, root, dns.TypeCAA); err == nil && in.Rcode == dns.RcodeSuccess {
			has := false
			for _, rr := range in.Answer {
				if c, ok := rr.(*dns.CAA); ok && strings.EqualFold(c.Tag, "issue") || ok && strings.EqualFold(c.Tag, "issuewild") {
					has = true
				}
			}
			if !has {
				m.add(root, "no-caa", "low", fmt.Sprintf("%s has no CAA record, so any certificate authority may issue certificates for it", root))
			}
			m.did(root, "no-caa")
		}
		if in, err := s.res.query(ctx, root, dns.TypeDS); err == nil && in.Rcode == dns.RcodeSuccess {
			has := false
			for _, rr := range in.Answer {
				if _, ok := rr.(*dns.DS); ok {
					has = true
				}
			}
			if !has {
				m.add(root, "no-dnssec", "low", fmt.Sprintf("%s is not signed with DNSSEC (no DS record at the parent), so forged DNS answers for it cannot be detected by validating resolvers", root))
			}
			m.did(root, "no-dnssec")
		}
	}
	sort.SliceStable(m.issues, func(i, j int) bool { return m.issues[i].Host < m.issues[j].Host })
	return m
}

func hasPrefixRecord(txts []string, prefix string) bool {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), prefix) {
			return true
		}
	}
	return false
}

// dkimKeyIssue checks the public key in a DKIM record.
func dkimKeyIssue(sel, txt string) (issue, bool) {
	var p string
	for _, part := range strings.Split(txt, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(strings.TrimSpace(k), "p") {
			p = strings.ReplaceAll(strings.TrimSpace(v), " ", "")
		}
	}
	if p == "" {
		return issue{}, false // a revoked key (empty p=) is not a weakness
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return issue{}, false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return issue{}, false
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return issue{}, false
	}
	switch bits := k.N.BitLen(); {
	case bits < 1024:
		return issue{"dkim-weak-key", "medium", fmt.Sprintf("the DKIM key for selector %q is only %d bits; keys under 1024 bits can be broken and forged", sel, bits)}, true
	case bits == 1024:
		return issue{"dkim-short-key", "low", fmt.Sprintf("the DKIM key for selector %q is 1024 bits; 2048 is the recommended size", sel)}, true
	}
	return issue{}, false
}
