package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// HealthBoard records the outcome of every call to an external connector (public
// data sources, DNS resolvers, ASN services, SMTP, optional paid APIs) so the GUI
// can show which ones are actually connected. A nil *HealthBoard is a valid no-op,
// which keeps unit tests that do not care about health simple.
type HealthBoard struct {
	mu    sync.Mutex
	items map[string]*HealthItem
	log   []LogEntry     // newest last, capped at maxLog
	last  map[string]int // index in log of the last entry per connector, used to collapse repeats
}

const maxLog = 600

// LogEntry is one line of the connection log.
type LogEntry struct {
	Time      time.Time
	Name      string // connector id
	Via       string // scan | check
	OK        bool
	LatencyMs int64
	Error     string
	Count     int // identical consecutive results collapsed into this line
}

// HealthItem is the running record of one connector: last success/failure, latency and counters.
type HealthItem struct {
	Name      string
	LastOK    time.Time
	LastFail  time.Time
	LastError string
	LatencyMs int64
	OKCount   int
	FailCount int
	Via       string // "scan" (a real query) or "check" (the Check now button)
	Note      string // extra detail, e.g. the plan behind an API key
}

// NewHealthBoard creates an empty board.
func NewHealthBoard() *HealthBoard {
	return &HealthBoard{items: map[string]*HealthItem{}, last: map[string]int{}}
}

// cancelled reports whether err only means the work was called off.
func cancelled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, errScanPaused) || errors.Is(err, errScanRestarted)
}

// Record notes the outcome of one call. Errors are stored truncated and with any
// secrets the caller registered already stripped (see redact).
func (h *HealthBoard) Record(name, via string, ok bool, d time.Duration, err error) {
	if h == nil || (!ok && cancelled(err)) {
		return // a scan stopped by the agent or a user says nothing about the connector
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	it := h.items[name]
	if it == nil {
		it = &HealthItem{Name: name}
		h.items[name] = it
	}
	it.Via = via
	it.LatencyMs = d.Milliseconds()
	h.appendLog(name, via, ok, d, err)
	if ok {
		it.LastOK = time.Now().UTC()
		it.OKCount++
		return
	}
	it.LastFail = time.Now().UTC()
	it.FailCount++
	if err != nil {
		it.LastError = truncate(err.Error(), 300)
	}
}

// appendLog adds a connection-log line. A scan makes thousands of DNS calls, so identical
// consecutive results for one connector are collapsed into a single line with a count
// (a success is logged at most once a minute unless the previous result was a failure).
// Caller holds h.mu.
func (h *HealthBoard) appendLog(name, via string, ok bool, d time.Duration, err error) {
	msg := ""
	if err != nil {
		msg = truncate(err.Error(), 400)
	}
	now := time.Now().UTC()
	if i, found := h.last[name]; found && i < len(h.log) {
		if l := &h.log[i]; l.OK == ok && l.Error == msg && l.Via == via && now.Sub(l.Time) < time.Minute {
			l.Count++
			return
		}
	}
	h.log = append(h.log, LogEntry{Time: now, Name: name, Via: via, OK: ok, LatencyMs: d.Milliseconds(), Error: msg, Count: 1})
	if len(h.log) > maxLog {
		h.log = append([]LogEntry(nil), h.log[len(h.log)-maxLog:]...)
		h.reindex()
		return
	}
	h.last[name] = len(h.log) - 1
}

func (h *HealthBoard) reindex() {
	h.last = map[string]int{}
	for i := range h.log {
		h.last[h.log[i].Name] = i
	}
}

// Log returns the connection log newest first, optionally filtered by connector id
// (prefix match, so "dns" covers every resolver) and by failures only.
func (h *HealthBoard) Log(name string, failedOnly bool, limit int) []LogEntry {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []LogEntry
	for i := len(h.log) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		e := h.log[i]
		if name != "" && e.Name != name && !strings.HasPrefix(e.Name, name+":") {
			continue
		}
		if failedOnly && e.OK {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Hint turns a raw connector error into plain-language troubleshooting advice.
func Hint(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case msg == "":
		return ""
	case strings.Contains(m, "no such host"):
		return "This machine could not resolve the service's hostname. Check its DNS settings, VPN or proxy; the service may also have been discontinued."
	case strings.Contains(m, "i/o timeout"), strings.Contains(m, "deadline exceeded"), strings.Contains(m, "timeout"):
		return "No answer in time. A firewall may be blocking outbound access to it, or the service is slow or overloaded. It is retried on the next scan."
	case strings.Contains(m, "connection refused"):
		return "The host actively refused the connection. Check the address and port, and that nothing local blocks it."
	case strings.Contains(m, "x509"), strings.Contains(m, "certificate"), strings.Contains(m, "tls"):
		return "TLS problem. A corporate proxy that inspects traffic is a common cause; for SMTP check the security mode (STARTTLS / TLS / none) matches the port."
	case strings.Contains(m, "http 401"), strings.Contains(m, "http 403"), strings.Contains(m, "unauthor"), strings.Contains(m, "invalid api"), strings.Contains(m, "forbidden"):
		return "The service rejected the credentials or blocked this address. Re-check the API key in Settings (and that the plan allows this call)."
	case strings.Contains(m, "http 429"), strings.Contains(m, "rate"), strings.Contains(m, "too many"):
		return "Rate limited by the service. Free tiers allow only a few calls per minute or day; scans back off and retry."
	case strings.Contains(m, "http 5"):
		return "The service itself is failing (server error). Usually temporary; it is retried on the next scan."
	case strings.Contains(m, "no dns resolver"), strings.Contains(m, "servfail"):
		return "None of the configured DNS resolvers answered. Check Settings → DNS resolvers and that UDP/TCP port 53 is allowed outbound."
	case strings.Contains(m, "auth"), strings.Contains(m, "535"), strings.Contains(m, "username"), strings.Contains(m, "password"):
		return "The mail server refused the login. Re-enter the SMTP username and password in Settings."
	}
	return ""
}

// SetNote attaches extra information (e.g. an API plan) to a connector.
func (h *HealthBoard) SetNote(name, note string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	it := h.items[name]
	if it == nil {
		it = &HealthItem{Name: name}
		h.items[name] = it
	}
	it.Note = note
}

// Get returns a copy of one connector's record.
func (h *HealthBoard) Get(name string) (HealthItem, bool) {
	if h == nil {
		return HealthItem{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if it := h.items[name]; it != nil {
		return *it, true
	}
	return HealthItem{}, false
}

// Snapshot returns copies of all records sorted by name.
func (h *HealthBoard) Snapshot() []HealthItem {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HealthItem, 0, len(h.items))
	for _, it := range h.items {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type healthDisk struct {
	Items []HealthItem
	Log   []LogEntry
}

// Marshal serialises the records and the connection log for persistence.
func (h *HealthBoard) Marshal() string {
	if h == nil {
		return ""
	}
	d := healthDisk{Items: h.Snapshot()}
	h.mu.Lock()
	d.Log = append([]LogEntry(nil), h.log...)
	h.mu.Unlock()
	b, _ := json.Marshal(d)
	return string(b)
}

// Load restores persisted health data (current and the older bare-array format).
func (h *HealthBoard) Load(s string) {
	if h == nil || s == "" {
		return
	}
	var d healthDisk
	if json.Unmarshal([]byte(s), &d) != nil { // v1.1/1.2 stored a bare array of items
		if json.Unmarshal([]byte(s), &d.Items) != nil {
			return
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range d.Items {
		it := d.Items[i]
		h.items[it.Name] = &it
	}
	if len(d.Log) > maxLog {
		d.Log = d.Log[len(d.Log)-maxLog:]
	}
	h.log = d.Log
	h.reindex()
}

// redact removes secrets from an error message before it is logged or stored.
func redact(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	if msg == err.Error() {
		return err
	}
	return redacted(msg)
}

// redacted is an error whose message has had secrets removed.
type redacted string

// Error returns the scrubbed message.
func (r redacted) Error() string { return string(r) }

// ---- connector catalogue (what the Health page lists) ----

// Connector describes one external dependency shown on the System health page.
type Connector struct {
	ID, Group, Label, What string
	Enabled                bool
	NeedsKey               bool
	HasKey                 bool
	// Probe says what the "Check now" button does for this connector.
	Probe string
}

// Connectors lists every connector given the current settings and which secrets exist.
func Connectors(s Settings, have map[string]bool) []Connector {
	c := []Connector{
		{ID: "crtsh", Group: "Subdomain discovery", Label: "crt.sh", What: "Certificate Transparency search", Enabled: s.CrtShEnabled, Probe: "Connectivity only (queries are heavy, so a real search is not used)"},
		{ID: "hackertarget", Group: "Subdomain discovery", Label: "HackerTarget", What: "Host search (free tier ≈50 queries/day)", Enabled: s.HackerTargetEnabled, Probe: "Connectivity only (preserves the free daily quota)"},
		{ID: "otx", Group: "Subdomain discovery", Label: "AlienVault OTX", What: "Passive DNS (free key)", Enabled: s.OTXEnabled, NeedsKey: true, HasKey: have[secretOTX], Probe: "Connectivity only"},
		{ID: "anubis", Group: "Subdomain discovery", Label: "Anubis (jonlu.ca)", What: "Subdomain dataset (blocks automated clients)", Enabled: s.AnubisEnabled, Probe: "Connectivity only"},
		{ID: "shodan-dns", Group: "Subdomain discovery", Label: "Shodan DNS", What: "Subdomains from Shodan (uses 1 query credit per scan)", Enabled: s.ShodanEnabled && s.ShodanDomainLookup, NeedsKey: true, HasKey: have[secretShodan], Probe: "Not probed (would use a query credit); status comes from real scans"},
		{ID: "virustotal", Group: "Subdomain discovery", Label: "VirusTotal", What: "Subdomains (free key: 4 requests/min)", Enabled: s.VirusTotalEnabled, NeedsKey: true, HasKey: have[secretVT], Probe: "One API request"},
		{ID: "hibp", Group: "Exposure of people and code", Label: "Have I Been Pwned", What: "Leaked accounts for your domain (paid key, verified domain)", Enabled: s.HIBPEnabled, NeedsKey: true, HasKey: have[secretHIBP], Probe: "Checks the key with a subscription-status call"},
		{ID: "github", Group: "Exposure of people and code", Label: "GitHub code search", What: "Public code that names your domain next to secrets", Enabled: s.GitHubEnabled, NeedsKey: true, HasKey: have[secretGitHub], Probe: "Checks the token with a rate-limit call (free)"},
		{ID: "dns", Group: "DNS and ownership", Label: "DNS resolvers", What: strings.Join(s.DNSResolvers, ", "), Enabled: true, Probe: "A query for example.com against each resolver"},
		{ID: "asn-cymru", Group: "DNS and ownership", Label: "Team Cymru", What: "IP → ASN via DNS WHOIS", Enabled: s.ASNEnabled, Probe: "One origin lookup"},
		{ID: "asn-ripestat", Group: "DNS and ownership", Label: "RIPEstat", What: "IP → ASN fallback (stat.ripe.net, free, no key)", Enabled: s.ASNEnabled && s.ASNBGPViewFallback, Probe: "One lookup"},
		{ID: "internetdb", Group: "Exposure intelligence", Label: "Shodan InternetDB", What: "Open ports, CVEs, tags per IP (free, no key)", Enabled: s.InternetDBEnabled, Probe: "One lookup"},
		{ID: "shodan", Group: "Exposure intelligence", Label: "Shodan API", What: "Host banners and vulnerabilities per IP", Enabled: s.ShodanEnabled, NeedsKey: true, HasKey: have[secretShodan], Probe: "api-info call (free, validates the key)"},
		{ID: "censys", Group: "Exposure intelligence", Label: "Censys", What: "Services per IP (Platform API)", Enabled: s.CensysEnabled, NeedsKey: true, HasKey: have[secretCensys], Probe: "One host lookup"},
		{ID: "rdap", Group: "Registration", Label: "RDAP", What: "Domain registrar and expiry date", Enabled: s.RDAPEnabled, Probe: "One domain lookup"},
		{ID: "smtp", Group: "Alert delivery", Label: "SMTP", What: s.SMTPHost, Enabled: s.SMTPEnabled, Probe: "Connects, negotiates TLS and authenticates; sends nothing"},
	}
	return c
}

// Status turns a connector plus its recorded history into a display state.
func (c Connector) Status(it HealthItem, seen bool) (state, label string) {
	switch {
	case c.NeedsKey && !c.HasKey:
		// Reported even while disabled: a keyed source can never work until a key is added.
		return "warn", "No API key"
	case !c.Enabled:
		return "off", "Disabled"
	case !seen || (it.LastOK.IsZero() && it.LastFail.IsZero()):
		return "unknown", "Not used yet"
	case it.LastOK.After(it.LastFail):
		return "good", "Connected"
	default:
		return "bad", "Failing"
	}
}
