package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The evidence behind a finding: what the agent recorded, each source's raw answer,
// the active-check result, screenshots, and links to look the data up independently.

// EvidenceLink is a place to check a finding outside the agent.
type EvidenceLink struct{ Label, Href, Note string }

// FindingEvidence is everything shown on a finding's evidence page.
type FindingEvidence struct {
	F        Finding
	Title    string
	IP, Host string
	Port     int
	Links    []EvidenceLink
	Services []ServiceRec
	Raw      []RawIntelView
	Shots    []WebShotRef
	AssetURL string
	CVEs     []string
}

// RawIntelView is a source's raw answer, pretty-printed for reading.
type RawIntelView struct {
	Source, Label, Fetched, JSON string
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// findingAddress extracts the IP (and port) a finding is about, from its key.
func findingAddress(f *Finding) (ip string, port int) {
	if ip, port, ok := serviceTarget(f); ok {
		return ip, port
	}
	parts := strings.Split(f.Key, ":")
	switch parts[0] {
	case "vuln", "flag", "eol":
		ip = strings.Join(parts[1:], ":")
	case "priv", "asn":
		if len(parts) >= 3 {
			ip = strings.Join(parts[2:], ":")
		}
	}
	if net.ParseIP(ip) == nil {
		return "", 0
	}
	return ip, 0
}

// evidenceLinks lists independent places to confirm a finding. They open the third
// party's own page (the person's browser contacts it, not the agent).
func evidenceLinks(f *Finding, ip string, cves []string) []EvidenceLink {
	var l []EvidenceLink
	if ip != "" {
		e := url.PathEscape(ip)
		l = append(l,
			EvidenceLink{"Shodan host page", "https://www.shodan.io/host/" + e, "ports, banners and history Shodan holds for this address"},
			EvidenceLink{"Shodan InternetDB (raw JSON)", "https://internetdb.shodan.io/" + e, "the free data the agent uses: open ports, CVEs and tags"},
			EvidenceLink{"Censys host page", "https://search.censys.io/hosts/" + e, "a second, independent scan of the address"},
			EvidenceLink{"VirusTotal", "https://www.virustotal.com/gui/ip-address/" + e, "reputation and malware reports"},
		)
	}
	for _, c := range cves {
		l = append(l, EvidenceLink{c + " (NVD)", "https://nvd.nist.gov/vuln/detail/" + c, "the vulnerability record"})
	}
	// First, any web address the finding itself names (the public file, the exposed page, ...):
	// it is the most direct thing to check.
	l = append(l, detailLinks(f.Detail)...)
	d := f.Host
	if ip == "" && dnsNameRe.MatchString(d) && net.ParseIP(d) == nil {
		e, p := url.QueryEscape(d), url.PathEscape(d)
		crt := EvidenceLink{"crt.sh certificates", "https://crt.sh/?q=" + e, "certificate transparency entries for the name"}
		switch {
		case strings.HasPrefix(f.Kind, "tls-"):
			l = append(l, EvidenceLink{"SSL Labs test", "https://www.ssllabs.com/ssltest/analyze.html?hideResults=on&d=" + e, "an independent check of the certificate and TLS set-up"}, crt)
		case f.Kind == "lookalike-domain":
			l = append(l,
				EvidenceLink{"RDAP registration record", "https://rdap.org/domain/" + p, "registrar, dates and status"},
				EvidenceLink{"urlscan.io", "https://urlscan.io/search/#domain:" + e, "what the site has shown when others scanned it"},
				crt) // a certificate for a look-alike often means a phishing site is being set up
		case f.Kind == "domain-expiry":
			l = append(l, EvidenceLink{"RDAP registration record", "https://rdap.org/domain/" + p, "registrar, dates and status"})
		case f.Kind == "email-auth":
			l = append(l, EvidenceLink{"MXToolbox lookup", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + e, "mail and DNS records as seen from the internet"})
		case f.Kind == "dangling-cname", f.Kind == "subdomain-takeover":
			l = append(l, EvidenceLink{"Google public DNS (JSON)", "https://dns.google/resolve?type=CNAME&name=" + e, "the CNAME record as published"})
		case f.Kind == "hsts-missing", f.Kind == "no-https-redirect":
			l = append(l, EvidenceLink{"securityheaders.com", "https://securityheaders.com/?followRedirects=on&q=" + e, "the response headers as seen from the internet"})
		case f.Kind == "no-security-txt":
			l = append(l, EvidenceLink{"security.txt on the site", "https://" + d + "/.well-known/security.txt", "the file the finding says is missing"})
		case f.Kind == "default-page", f.Kind == "login-portal":
			l = append(l, EvidenceLink{"The site", "https://" + d + "/", "open the page the finding is about"})
		case f.Kind == "repo-exposure":
			l = append(l, EvidenceLink{"GitHub code search", "https://github.com/search?type=code&q=" + url.QueryEscape(`"`+d+`"`), "every public file that mentions the domain"})
		}
	}
	if f.Kind == "leaked-credentials" {
		l = append(l, EvidenceLink{"Have I Been Pwned", "https://haveibeenpwned.com/DomainSearch", "domain search (needs a verified domain)"})
	}
	return dedupeLinks(l)
}

// dnsNameRe accepts a plain host name, so links built from it cannot carry a path or query.
var dnsNameRe = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+\.?$`)

// urlInText finds web addresses written in a finding's description.
var urlInText = regexp.MustCompile(`https?://[^\s"'<>()]+`)

// detailLinks turns the web addresses a finding's description names into links (at most 5).
// Only http(s) with a host is kept, and trailing punctuation from the sentence is dropped.
func detailLinks(detail string) []EvidenceLink {
	var l []EvidenceLink
	for _, raw := range urlInText.FindAllString(detail, 5) {
		raw = strings.TrimRight(raw, ".,;:!?")
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		label, note := "Named in the finding", u.Host
		if u.Host == "github.com" {
			label, note = "The file on GitHub", "the public file the finding found"
		}
		l = append(l, EvidenceLink{label, u.String(), note})
	}
	return l
}

func dedupeLinks(in []EvidenceLink) []EvidenceLink {
	seen := map[string]bool{}
	out := in[:0]
	for _, x := range in {
		if !seen[x.Href] {
			seen[x.Href] = true
			out = append(out, x)
		}
	}
	return out
}

// buildEvidence gathers the evidence for one finding.
func (s *Server) buildEvidence(f *Finding) (*FindingEvidence, error) {
	ev := &FindingEvidence{F: *f, Title: describeFinding(*f).Title, Host: f.Host}
	ev.IP, ev.Port = findingAddress(f)
	ev.CVEs = cveRe.FindAllString(f.Detail, 20)
	if ev.IP != "" && f.Kind == "known-vuln" {
		if intel, err := s.store.LoadIntel([]string{ev.IP}); err == nil {
			for _, in := range intel[ev.IP] {
				ev.CVEs = append(ev.CVEs, in.Vulns...)
			}
		}
	}
	sort.Strings(ev.CVEs)
	ev.CVEs = dedupe(ev.CVEs)
	if len(ev.CVEs) > 20 {
		ev.CVEs = ev.CVEs[:20]
	}
	if ev.IP != "" {
		var err error
		if ev.Services, err = s.store.ServicesFor(ev.IP, ev.Port); err != nil {
			return nil, err
		}
		raws, err := s.store.IntelRaw(ev.IP)
		if err != nil {
			return nil, err
		}
		for _, r := range raws {
			v := RawIntelView{Source: r.Source, Label: sourceLabel(r.Source), Fetched: r.Fetched, JSON: r.Raw}
			var b bytes.Buffer
			if r.Raw != "" && json.Indent(&b, []byte(r.Raw), "", "  ") == nil {
				v.JSON = b.String()
			}
			ev.Raw = append(ev.Raw, v)
		}
		ev.AssetURL = "/assets/view?type=ip&id=" + url.QueryEscape(ev.IP)
	}
	shots, err := s.store.ShotsForIP(ev.IP, f.Host)
	if err != nil {
		return nil, err
	}
	for _, sh := range shots {
		if ev.Port == 0 || sh.Port == ev.Port || f.Kind != "exposed-service" {
			ev.Shots = append(ev.Shots, sh)
		}
	}
	ev.Links = evidenceLinks(f, ev.IP, ev.CVEs)
	return ev, nil
}

// findingEvidence renders a finding's evidence page.
func (s *Server) findingEvidence(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, ok := s.findingFromPath(w, r, sess)
	if !ok {
		return
	}
	ev, err := s.buildEvidence(f)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.render(w, r, sess, "evidence", http.StatusOK, map[string]any{"Title": "Evidence: " + ev.Title, "Nav": "findings", "E": ev})
}

// findingEvidenceJSON downloads the same evidence as one JSON file (for a ticket or an audit).
func (s *Server) findingEvidenceJSON(w http.ResponseWriter, r *http.Request, sess *Session) {
	f, ok := s.findingFromPath(w, r, sess)
	if !ok {
		return
	}
	ev, err := s.buildEvidence(f)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	type rawOut struct {
		Source, Fetched string
		Answer          json.RawMessage `json:",omitempty"`
		Text            string          `json:",omitempty"`
	}
	out := struct {
		Finding  Finding
		Address  string `json:",omitempty"`
		Services []ServiceRec
		Sources  []rawOut
		Links    []EvidenceLink
	}{Finding: ev.F, Services: ev.Services, Links: ev.Links}
	if ev.IP != "" {
		out.Address = ev.IP
		if ev.Port > 0 {
			out.Address = net.JoinHostPort(ev.IP, strconv.Itoa(ev.Port))
		}
	}
	for _, r := range ev.Raw {
		ro := rawOut{Source: r.Source, Fetched: r.Fetched}
		if json.Valid([]byte(r.JSON)) {
			ro.Answer = json.RawMessage(r.JSON)
		} else {
			ro.Text = r.JSON
		}
		out.Sources = append(out.Sources, ro)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-evidence-`+strconv.FormatInt(f.ID, 10)+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
