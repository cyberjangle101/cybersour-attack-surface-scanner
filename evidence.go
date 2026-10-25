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
	d := f.Host
	if ip == "" && d != "" && net.ParseIP(d) == nil {
		e := url.QueryEscape(d)
		switch f.Kind {
		case "domain-expiry", "lookalike-domain":
			l = append(l, EvidenceLink{"RDAP registration record", "https://rdap.org/domain/" + url.PathEscape(d), "registrar, dates and status"})
		case "email-auth":
			l = append(l, EvidenceLink{"MXToolbox lookup", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + e, "mail and DNS records as seen from the internet"})
		case "dangling-cname":
			l = append(l, EvidenceLink{"Google public DNS (JSON)", "https://dns.google/resolve?type=CNAME&name=" + e, "the CNAME record as published"})
		}
		l = append(l, EvidenceLink{"crt.sh certificates", "https://crt.sh/?q=" + e, "certificate transparency entries for the name"})
	}
	if f.Kind == "leaked-credentials" {
		l = append(l, EvidenceLink{"Have I Been Pwned", "https://haveibeenpwned.com/DomainSearch", "domain search (needs a verified domain)"})
	}
	return l
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
