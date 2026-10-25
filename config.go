package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Bootstrap configuration: the few things needed BEFORE the database can be
// opened. Everything else (targets, schedule, alerting, SMTP...) lives in the
// database and is edited from the web GUI. The file is optional.
// ---------------------------------------------------------------------------

// Bootstrap holds the few settings needed before the database can be opened (listen address, data folder, TLS, logging). Everything else is configured in the web interface.
type Bootstrap struct {
	Listen  string `yaml:"listen"`
	DataDir string `yaml:"data_dir"`

	// LegacyDataDir is set when the data folder is the program's own folder (older versions).
	LegacyDataDir  bool     `yaml:"-"`
	DataDirWarning string   `yaml:"-"`
	TLSCert        string   `yaml:"tls_cert"`
	TLSKey         string   `yaml:"tls_key"`
	AllowedHosts   []string `yaml:"allowed_hosts"`
	// SecureCookies marks cookies Secure when TLS is terminated by a reverse proxy in front of the agent.
	SecureCookies bool `yaml:"secure_cookies"`
	// PlainHTTP turns off the automatic self-signed certificate and serves unencrypted HTTP.
	PlainHTTP bool `yaml:"plain_http"`
	// ListenExplicit is true when the listen address came from the command line or config file (it then cannot be changed in the web interface).
	ListenExplicit bool `yaml:"-"`
	// NoPassphrase lets a first start create the encryption key without a passphrase (not recommended).
	NoPassphrase bool `yaml:"no_passphrase"`
	// NoBrowser stops an interactive start from opening the web interface in the default browser.
	NoBrowser bool `yaml:"no_browser"`
	// KeepConsole keeps the console window visible on Windows after an interactive start.
	KeepConsole bool `yaml:"keep_console"`
	// AfterUpdate is set when an update restarted the agent: wait for the old process to exit.
	AfterUpdate bool       `yaml:"-"`
	Logging     LoggingCfg `yaml:"logging"`
}

// LoggingCfg selects log level, format and optional log file.
type LoggingCfg struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // text|json
	File   string `yaml:"file"`
}

func defaultBootstrap() *Bootstrap {
	return &Bootstrap{
		Listen:  defaultListen,
		Logging: LoggingCfg{Level: "info", Format: "text"},
	}
}

// LoadBootstrap reads the optional bootstrap file. path may be empty.
func LoadBootstrap(path string) (*Bootstrap, error) {
	b := defaultBootstrap()
	if path != "" {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the administrator's -config flag
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true) // typos should fail loudly
		if err := dec.Decode(b); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if b.DataDir == "" {
			b.DataDir = filepath.Dir(path)
		}
		b.ListenExplicit = b.Listen != defaultListen
	}
	return b, nil
}

// Finalize resolves paths and validates. Called after command-line overrides.
func (b *Bootstrap) Finalize() error {
	if b.DataDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		dir, legacy, err := defaultDataDir(filepath.Dir(exe))
		if err != nil {
			return err
		}
		b.DataDir, b.LegacyDataDir = dir, legacy
	}
	abs, err := filepath.Abs(b.DataDir)
	if err != nil {
		return err
	}
	b.DataDir = abs
	if err := prepareDataDir(b.DataDir); err != nil {
		// A failure to tighten permissions is reported but must not stop an existing installation.
		if _, serr := os.Stat(b.DataDir); serr != nil {
			return fmt.Errorf("data_dir: %w", err)
		}
		b.DataDirWarning = err.Error()
	}
	if b.Logging.File != "" && !filepath.IsAbs(b.Logging.File) {
		b.Logging.File = filepath.Join(b.DataDir, b.Logging.File)
	}
	for _, p := range []*string{&b.TLSCert, &b.TLSKey} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(b.DataDir, *p)
		}
	}
	if (b.TLSCert == "") != (b.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}
	if b.Listen == "" {
		return errors.New("listen address is required")
	}
	switch strings.ToLower(b.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("logging.level must be debug|info|warn|error")
	}
	return nil
}

// AutoTLS reports whether the agent should create and use its own self-signed
// certificate: when no certificate is configured, plain HTTP was not requested,
// and no reverse proxy is terminating TLS in front of it.
func (b *Bootstrap) AutoTLS() bool { return b.TLSCert == "" && !b.PlainHTTP && !b.SecureCookies }

// UsesTLS reports whether the web interface is served over HTTPS.
func (b *Bootstrap) UsesTLS() bool { return b.TLSCert != "" || b.AutoTLS() }

// DBPath is the location of the encrypted SQLite database.
func (b *Bootstrap) DBPath() string { return filepath.Join(b.DataDir, "easm.db") }

// KeyPath is the location of the master key file (easm.key).
func (b *Bootstrap) KeyPath() string { return filepath.Join(b.DataDir, "easm.key") }

// ---------------------------------------------------------------------------
// Runtime configuration: built from the database Settings for each scan, so
// changes made in the GUI apply without a restart.
// ---------------------------------------------------------------------------

// Config is the runtime configuration for one scan, built from the saved Settings by Settings.RuntimeWith.
type Config struct {
	Schedule      ScheduleCfg
	Sources       SourcesCfg
	DNS           DNSCfg
	ASN           ASNCfg
	Alerts        AlertsCfg
	SMTP          SMTPCfg
	Intel         IntelCfg
	Active        ActiveCfg
	Discover      DiscoverCfg
	RetentionDays int
	PublicURL     string
}

// ScheduleCfg holds scan timing options.
type ScheduleCfg struct {
	Interval      time.Duration
	Jitter        time.Duration
	TargetTimeout time.Duration
}

// Toggle is an on/off switch for an optional data source.
type Toggle struct{ Enabled bool }

// IntelCfg configures exposure intelligence. InternetDB and RDAP need no key; the
// others are opt-in and only run when a key was saved in Settings.
type IntelCfg struct {
	InternetDB bool
	RDAP       bool

	Shodan struct {
		Enabled      bool
		Key          string
		DomainLookup bool // /dns/domain: subdomains, costs a query credit per page
	}
	Censys struct {
		Enabled bool
		Token   string
		OrgID   string
	}
	VirusTotal struct {
		Enabled bool
		Key     string
	}
	HIBP struct { // Have I Been Pwned domain search (needs a paid key and a verified domain)
		Enabled bool
		Key     string
	}
	GitHub struct { // GitHub code search for the domain next to secrets (needs a token)
		Enabled bool
		Key     string
	}
	MaxIPs   int           // per scan, per source
	CacheTTL time.Duration // reuse a fetched answer this long
}

// DiscoverCfg switches the extra discovery checks.
type DiscoverCfg struct {
	Lookalikes   bool // look for registered domains that resemble the target
	LookalikeMax int  // how many variations to look up per scan
	Related      bool // suggest other domains that share certificates with the target
	ReverseIP    bool // suggest other domains hosted on the same addresses (HackerTarget)
}

// Secrets holds decrypted credentials for one scan.
type Secrets struct{ SMTP, Shodan, Censys, VirusTotal, HIBP, GitHub, OTX string }

const (
	secretSMTP   = "secret:smtp_password"
	secretShodan = "secret:shodan_key"
	secretCensys = "secret:censys_token" //nolint:gosec // G101: the NAME of a stored secret, not a credential
	secretVT     = "secret:virustotal_key"
	secretHIBP   = "secret:hibp_key"     //nolint:gosec // G101: the NAME of a stored secret, not a credential
	secretGitHub = "secret:github_token" //nolint:gosec // G101: the NAME of a stored secret, not a credential
	secretOTX    = "secret:otx_key"
)

// CrtShCfg configures the crt.sh certificate-transparency source, including its retry/backoff behaviour.
type CrtShCfg struct {
	Enabled     bool
	Timeout     time.Duration
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// SourcesCfg groups the passive subdomain-discovery sources.
type SourcesCfg struct {
	CrtSh        CrtShCfg
	HackerTarget Toggle
	OTX          struct { // passive DNS now refuses anonymous callers, so it needs a (free) key
		Enabled bool
		Key     string
	}
	Anubis    Toggle
	UserAgent    string
}

// DNSCfg configures the DNS resolver pool: servers, concurrency, rate limit, timeout and retries.
type DNSCfg struct {
	Resolvers []string
	Workers   int
	QPS       int
	Timeout   time.Duration
	Retries   int
}

// ASNCfg configures IP-to-network ownership lookups.
type ASNCfg struct {
	Enabled         bool
	BGPViewFallback bool
	CacheTTL        time.Duration
}

// AlertsCfg controls which changes trigger email alerts.
type AlertsCfg struct {
	MinEvents           int
	ImmediateSeverity   string
	MaxRows             int
	SendBaselineSummary bool
	Certs               bool
	TXT                 bool
	Removals            bool
	RemovalMisses       int
}

// SMTPCfg holds the mail-server settings used for alerts and digests.
type SMTPCfg struct {
	Enabled            bool
	Host               string
	Port               int
	Security           string // starttls | tls | none
	Username           string
	Password           string
	From               string
	To                 []string
	SubjectPrefix      string
	Timeout            time.Duration
	InsecureSkipVerify bool
	EHLOName           string
}

// ---------------------------------------------------------------------------
// Targets (entities to scan). Stored in the database, managed in the GUI.
// ---------------------------------------------------------------------------

// Target is one monitored domain together with its ownership expectations (ASNs, organisation keywords), ignore patterns and scan state.
type Target struct {
	ID                  int64
	Domain              string
	ExpectedASNs        []int
	ExpectedOrgKeywords []string
	IgnoreSubdomains    []string // regular expressions (RE2)
	IntervalMinutes     int      // 0 = use the global default
	Enabled             bool
	Notes               string
	Created             string
	NextScan            string
	LastStart           string
	LastEnd             string
	LastStatus          string // "", running, ok, error, interrupted
	LastError           string
	BaselinedAt         string // "" until the first complete scan

	ignore []*regexp.Regexp
}

// Baselined reports whether the first (silent) baseline scan has completed.
func (t *Target) Baselined() bool { return t.BaselinedAt != "" }

// Compile validates the target's ignore patterns and caches the compiled regular expressions.
func (t *Target) Compile() error {
	t.ignore = nil
	for _, p := range t.IgnoreSubdomains {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("ignore pattern %q: %w", p, err)
		}
		t.ignore = append(t.ignore, re)
	}
	return nil
}

func (t *Target) ignored(host string) bool {
	for _, re := range t.ignore {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func (t *Target) hasOwnershipRules() bool {
	return len(t.ExpectedASNs) > 0 || len(t.ExpectedOrgKeywords) > 0
}

// owns reports whether the network info matches this target's expected ASNs or organisation keywords.
func (t *Target) owns(info *ASNInfo) bool {
	for _, a := range t.ExpectedASNs {
		if a == info.ASN {
			return true
		}
	}
	org := strings.ToUpper(info.Org)
	for _, k := range t.ExpectedOrgKeywords {
		if k != "" && strings.Contains(org, strings.ToUpper(k)) {
			return true
		}
	}
	return false
}

const maxListItems = 100

// splitList splits on newlines and commas, trims, drops blanks, de-duplicates.
func splitList(s string, commas bool) []string {
	f := func(r rune) bool { return r == '\n' || r == '\r' || (commas && r == ',') }
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.FieldsFunc(s, f) {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// parseASNList parses "AS13335, 16509" style input into AS numbers, rejecting anything else.
func parseASNList(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' }) {
		typed := strings.TrimSpace(p)
		p = strings.TrimPrefix(strings.ToUpper(typed), "AS")
		if p == "" { // "AS 13335": the number is the next field
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 4294967295 {
			return nil, fmt.Errorf("%q is not a valid AS number (use e.g. AS13335 or 13335)", typed) // quote what was typed
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > maxListItems {
		return nil, fmt.Errorf("too many ASNs (max %d)", maxListItems)
	}
	return out, nil
}

func joinInts(in []int) string {
	s := make([]string, len(in))
	for i, n := range in {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}

// splitInts splits a comma/space separated list of integers.
func splitInts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// TargetFromForm validates user input for a target. It never trusts the caller.
func TargetFromForm(domain, asns, keywords, ignore, interval, notes string) (*Target, error) {
	d := normalizeHost(domain)
	if d == "" || strings.Count(d, ".") < 1 {
		return nil, fmt.Errorf("%q is not a valid domain name", strings.TrimSpace(domain))
	}
	if looksLikeIP(d) {
		return nil, errors.New("enter a domain name, not an IP address")
	}
	t := &Target{Domain: d, Enabled: true}
	var err error
	if t.ExpectedASNs, err = parseASNList(asns); err != nil {
		return nil, err
	}
	t.ExpectedOrgKeywords = splitList(keywords, true)
	t.IgnoreSubdomains = splitList(ignore, false)
	if len(t.ExpectedOrgKeywords) > maxListItems || len(t.IgnoreSubdomains) > maxListItems {
		return nil, fmt.Errorf("too many list entries (max %d)", maxListItems)
	}
	for _, s := range append(append([]string{}, t.ExpectedOrgKeywords...), t.IgnoreSubdomains...) {
		if len(s) > 200 {
			return nil, errors.New("list entries are limited to 200 characters")
		}
	}
	if interval = strings.TrimSpace(interval); interval != "" {
		n, err := strconv.Atoi(interval)
		if err != nil || n < 0 || (n > 0 && n < 15) || n > 60*24*30 {
			return nil, errors.New("scan interval must be blank (use default) or between 15 and 43200 minutes")
		}
		t.IntervalMinutes = n
	}
	if len(notes) > 500 {
		return nil, errors.New("notes are limited to 500 characters")
	}
	t.Notes = strings.TrimSpace(notes)
	if err := t.Compile(); err != nil {
		return nil, err
	}
	return t, nil
}

func looksLikeIP(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
