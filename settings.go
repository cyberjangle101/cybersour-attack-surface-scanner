package main

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// maxOrgName is the longest organisation name accepted for the report header.
const maxOrgName = 120

// Settings are the global, GUI-editable options. They are stored as JSON in the
// database; missing fields fall back to DefaultSettings so upgrades are safe.
// The SMTP password is stored separately, encrypted (see Vault).
type Settings struct {
	// Scheduling
	IntervalMinutes      int
	JitterMinutes        int
	TargetTimeoutMinutes int
	EventRetentionDays   int
	ConcurrentScans      int // domains scanned at the same time

	// Alerting
	AlertMinEvents         int
	AlertImmediateSeverity string
	AlertMaxRows           int
	AlertBaselineSummary   bool
	AlertCerts             bool
	AlertRemovals          bool // tell me when records, hosts, ports or findings disappear
	Require2FA             bool // local accounts must use two-factor sign-in (directory accounts use the directory's own MFA)
	RemovalMisses          int  // consecutive scans a record must be missing before it counts as removed
	AlertTXT               bool
	PublicURL              string

	// OrgName is the organisation the reports are prepared for, shown at the top of every report.
	OrgName string

	// UpdateCheck asks GitHub once a day whether a newer release exists (it only tells
	// administrators; installing is always their decision).
	UpdateCheck bool

	// Reporting digest email
	DigestFrequency string // off | daily | weekly
	DigestHour      int    // 0-23, server local time

	// Passive sources
	CrtShEnabled        bool
	CrtShTimeoutSeconds int
	CrtShMaxAttempts    int
	HackerTargetEnabled bool
	OTXEnabled          bool
	AnubisEnabled       bool

	// DNS
	DNSResolvers      []string
	DNSWorkers        int
	DNSQPS            int
	DNSTimeoutSeconds int
	DNSRetries        int

	// ASN mapping
	ASNEnabled         bool
	ASNBGPViewFallback bool

	// Exposure intelligence (third-party services that receive your IPs / domain names)
	InternetDBEnabled  bool
	RDAPEnabled        bool
	ShodanEnabled      bool
	ShodanDomainLookup bool
	CensysEnabled      bool
	CensysOrgID        string
	VirusTotalEnabled  bool
	HIBPEnabled        bool // leaked-credential check (Have I Been Pwned)
	GitHubEnabled      bool // code-repository exposure check
	EnrichMaxIPs       int

	// Active checks (connect to your own servers; off by default)
	ActiveChecks         bool
	ActiveForeign        bool // also probe addresses outside the expected ownership
	LookalikeEnabled     bool // look for registered look-alike domains
	LookalikeMax         int
	RelatedEnabled       bool // suggest related domains from shared certificates
	ReverseIPEnabled     bool // suggest domains on the same addresses
	ActivePaths          bool // look for exposed files such as .git and .env
	ActiveBuckets        bool // check cloud storage that names point to
	ActiveMaxHosts       int
	ActiveTimeoutSeconds int
	ActiveConcurrency    int
	Screenshots          bool
	ScreenshotMax        int
	ChromePath           string

	// SMTP
	SMTPEnabled            bool
	SMTPHost               string
	SMTPPort               int
	SMTPSecurity           string // starttls | tls | none
	SMTPUsername           string
	SMTPFrom               string
	SMTPTo                 []string
	SMTPSubjectPrefix      string
	SMTPInsecureSkipVerify bool
}

// DefaultSettings returns the factory defaults used on first run and for fields missing from older saved settings.
func DefaultSettings() Settings {
	return Settings{
		IntervalMinutes:      360,
		JitterMinutes:        5,
		TargetTimeoutMinutes: 45,
		EventRetentionDays:   90,
		ConcurrentScans:      2,

		UpdateCheck: true,

		AlertMinEvents:         1,
		AlertImmediateSeverity: "high",
		AlertMaxRows:           500,
		AlertBaselineSummary:   true,
		AlertCerts:             true,
		AlertRemovals:          true,
		RemovalMisses:          3,
		LookalikeMax:           300,
		RelatedEnabled:         true,

		DigestFrequency: "weekly",
		DigestHour:      8,

		CrtShEnabled:        true,
		CrtShTimeoutSeconds: 120,
		CrtShMaxAttempts:    5,
		HackerTargetEnabled: true,
		OTXEnabled:          false, // needs a free API key since OTX closed anonymous passive DNS
		AnubisEnabled:       false, // jonlu.ca sits behind a Cloudflare bot challenge that refuses non-browser clients

		DNSResolvers:      []string{"1.1.1.1:53", "8.8.8.8:53"},
		DNSWorkers:        20,
		DNSQPS:            50,
		DNSTimeoutSeconds: 4,
		DNSRetries:        2,

		ASNEnabled:         true,
		ASNBGPViewFallback: true,

		InternetDBEnabled: true,
		RDAPEnabled:       true,
		EnrichMaxIPs:      250,

		ActivePaths:          true,
		ActiveBuckets:        true,
		ActiveMaxHosts:       300,
		ActiveTimeoutSeconds: 8,
		ActiveConcurrency:    6,
		ScreenshotMax:        30,

		SMTPSecurity:      "starttls",
		SMTPSubjectPrefix: "[EASM]",
	}
}

func between(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
	}
	return nil
}

// Normalize validates and canonicalises the settings in place.
func (s *Settings) Normalize() error {
	checks := []error{
		between("Default scan interval (minutes)", s.IntervalMinutes, 15, 60*24*30),
		between("Jitter (minutes)", s.JitterMinutes, 0, 240),
		between("Per-target timeout (minutes)", s.TargetTimeoutMinutes, 1, 24*60),
		between("Concurrent domain scans", s.ConcurrentScans, 1, 8),
		between("Event retention (days)", s.EventRetentionDays, 1, 3650),
		between("Alert threshold (events)", s.AlertMinEvents, 1, 10000),
		between("Max rows per email", s.AlertMaxRows, 10, 5000),
		between("Scans before something counts as removed", s.RemovalMisses, 1, 10),
		between("Active checks: hosts per scan", s.ActiveMaxHosts, 1, 5000),
		between("Active checks: timeout", s.ActiveTimeoutSeconds, 2, 60),
		between("Active checks: parallel probes", s.ActiveConcurrency, 1, 32),
		between("Look-alike variations per scan", s.LookalikeMax, 10, 2000),
		between("Screenshots per scan", s.ScreenshotMax, 1, 200),
		between("Digest hour", s.DigestHour, 0, 23),
		between("crt.sh timeout (seconds)", s.CrtShTimeoutSeconds, 10, 600),
		between("crt.sh attempts", s.CrtShMaxAttempts, 1, 10),
		between("DNS workers", s.DNSWorkers, 1, 200),
		between("DNS queries per second", s.DNSQPS, 1, 5000),
		between("DNS timeout (seconds)", s.DNSTimeoutSeconds, 1, 30),
		between("DNS retries", s.DNSRetries, 0, 5),
		between("Max IPs looked up per scan", s.EnrichMaxIPs, 1, 5000),
	}
	s.ChromePath = strings.TrimSpace(s.ChromePath)
	if len(s.ChromePath) > 500 || strings.ContainsFunc(s.ChromePath, func(r rune) bool { return r < 32 }) {
		return errors.New("the browser path is not valid")
	}
	for _, e := range checks {
		if e != nil {
			return e
		}
	}
	s.AlertImmediateSeverity = strings.ToLower(s.AlertImmediateSeverity)
	if _, ok := severityRank[s.AlertImmediateSeverity]; !ok {
		return errors.New("Immediate-alert severity must be info, low, medium or high") //nolint:staticcheck // shown verbatim in the settings form
	}
	s.DigestFrequency = strings.ToLower(s.DigestFrequency)
	switch s.DigestFrequency {
	case "off", "daily", "weekly":
	default:
		return errors.New("Digest frequency must be off, daily or weekly") //nolint:staticcheck // shown verbatim in the settings form
	}

	s.OrgName = strings.Join(strings.Fields(s.OrgName), " ")
	if utf8.RuneCountInString(s.OrgName) > maxOrgName {
		return fmt.Errorf("Organisation name: at most %d characters", maxOrgName) //nolint:staticcheck // shown verbatim in the settings form
	}
	for _, c := range s.OrgName {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) { // Cf: bidi overrides could disguise the name in a report
			return errors.New("Organisation name contains a control or formatting character") //nolint:staticcheck // shown verbatim in the settings form
		}
	}
	if s.PublicURL = strings.TrimSpace(s.PublicURL); s.PublicURL != "" {
		u, err := url.Parse(s.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("Dashboard URL must be a full http(s) URL") //nolint:staticcheck // shown verbatim in the settings form
		}
		s.PublicURL = strings.TrimRight(s.PublicURL, "/")
	}

	if len(s.DNSResolvers) == 0 {
		return errors.New("At least one DNS resolver is required") //nolint:staticcheck // shown verbatim in the settings form
	}
	res := make([]string, 0, len(s.DNSResolvers))
	for _, r := range s.DNSResolvers {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(strings.Trim(r, "[]"), "53")
		}
		host, _, err := net.SplitHostPort(r)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("DNS resolver %q must be an IP address (optionally with :port)", r)
		}
		res = append(res, r)
	}
	if len(res) == 0 {
		return errors.New("At least one DNS resolver is required") //nolint:staticcheck // shown verbatim in the settings form
	}
	s.DNSResolvers = res

	s.CensysOrgID = strings.TrimSpace(s.CensysOrgID)
	if len(s.CensysOrgID) > 64 || strings.ContainsAny(s.CensysOrgID, " \r\n\t&?#/") {
		return errors.New("Censys organisation ID must be a single token (letters, digits and dashes)") //nolint:staticcheck // shown verbatim in the settings form
	}

	s.SMTPSecurity = strings.ToLower(s.SMTPSecurity)
	switch s.SMTPSecurity {
	case "starttls", "tls", "none":
	default:
		return errors.New("SMTP security must be starttls, tls or none")
	}
	s.SMTPHost = strings.TrimSpace(s.SMTPHost)
	s.SMTPFrom = strings.TrimSpace(s.SMTPFrom)
	s.SMTPUsername = strings.TrimSpace(s.SMTPUsername)
	if s.SMTPPort == 0 {
		s.SMTPPort = map[string]int{"starttls": 587, "tls": 465, "none": 25}[s.SMTPSecurity]
	}
	if err := between("SMTP port", s.SMTPPort, 1, 65535); err != nil {
		return err
	}
	if strings.ContainsAny(s.SMTPSubjectPrefix, "\r\n") || len(s.SMTPSubjectPrefix) > 40 {
		return errors.New("Subject prefix must be one short line") //nolint:staticcheck // shown verbatim in the settings form
	}
	if s.SMTPEnabled {
		if s.SMTPHost == "" {
			return errors.New("SMTP host is required")
		}
		if _, err := mail.ParseAddress(s.SMTPFrom); err != nil {
			return fmt.Errorf("SMTP From address: %w", err)
		}
		if len(s.SMTPTo) == 0 {
			return errors.New("At least one alert recipient is required") //nolint:staticcheck // shown verbatim in the settings form
		}
	}
	for _, r := range s.SMTPTo {
		if _, err := mail.ParseAddress(r); err != nil {
			return fmt.Errorf("Recipient %q: %w", r, err) //nolint:staticcheck // shown verbatim in the settings form
		}
	}
	return nil
}

// Runtime converts the settings into the Config used by one scan.
func (s Settings) Runtime(smtpPassword string) *Config {
	return s.RuntimeWith(Secrets{SMTP: smtpPassword})
}

// RuntimeWith converts the saved settings plus decrypted secrets into the Config used by a scan.
func (s Settings) RuntimeWith(sec Secrets) *Config {
	smtpPassword := sec.SMTP
	c := &Config{
		Schedule: ScheduleCfg{
			Interval:      time.Duration(s.IntervalMinutes) * time.Minute,
			Jitter:        time.Duration(s.JitterMinutes) * time.Minute,
			TargetTimeout: time.Duration(s.TargetTimeoutMinutes) * time.Minute,
		},
		Sources: SourcesCfg{
			CrtSh: CrtShCfg{
				Enabled: s.CrtShEnabled, Timeout: time.Duration(s.CrtShTimeoutSeconds) * time.Second,
				MaxAttempts: s.CrtShMaxAttempts, BaseBackoff: 5 * time.Second, MaxBackoff: 2 * time.Minute,
			},
			HackerTarget: Toggle{s.HackerTargetEnabled},
			Anubis:       Toggle{s.AnubisEnabled},
			UserAgent:    "easm-agent/" + version + " (+defensive attack-surface monitoring)",
		},
		DNS: DNSCfg{
			Resolvers: s.DNSResolvers, Workers: s.DNSWorkers, QPS: s.DNSQPS,
			Timeout: time.Duration(s.DNSTimeoutSeconds) * time.Second, Retries: s.DNSRetries,
		},
		ASN: ASNCfg{Enabled: s.ASNEnabled, BGPViewFallback: s.ASNBGPViewFallback, CacheTTL: 7 * 24 * time.Hour},
		Alerts: AlertsCfg{
			MinEvents: s.AlertMinEvents, ImmediateSeverity: s.AlertImmediateSeverity, MaxRows: s.AlertMaxRows,
			SendBaselineSummary: s.AlertBaselineSummary, Certs: s.AlertCerts, TXT: s.AlertTXT, Removals: s.AlertRemovals, RemovalMisses: s.RemovalMisses,
		},
		SMTP: SMTPCfg{
			Enabled: s.SMTPEnabled, Host: s.SMTPHost, Port: s.SMTPPort, Security: s.SMTPSecurity,
			Username: s.SMTPUsername, Password: smtpPassword, From: s.SMTPFrom, To: s.SMTPTo,
			SubjectPrefix: s.SMTPSubjectPrefix, Timeout: 30 * time.Second, InsecureSkipVerify: s.SMTPInsecureSkipVerify,
		},
		Active: ActiveCfg{Enabled: s.ActiveChecks, Foreign: s.ActiveForeign, Paths: s.ActivePaths, Buckets: s.ActiveBuckets,
			Shots: s.Screenshots, MaxShots: s.ScreenshotMax, ChromePath: s.ChromePath, MaxHosts: s.ActiveMaxHosts,
			Concurrency: s.ActiveConcurrency, Timeout: time.Duration(s.ActiveTimeoutSeconds) * time.Second},
		Discover:      DiscoverCfg{Lookalikes: s.LookalikeEnabled, LookalikeMax: s.LookalikeMax, Related: s.RelatedEnabled, ReverseIP: s.ReverseIPEnabled},
		RetentionDays: s.EventRetentionDays,
		PublicURL:     s.PublicURL,
	}
	c.Sources.OTX.Enabled, c.Sources.OTX.Key = s.OTXEnabled && sec.OTX != "", sec.OTX
	in := &c.Intel
	in.InternetDB, in.RDAP = s.InternetDBEnabled, s.RDAPEnabled
	in.Shodan.Enabled, in.Shodan.Key, in.Shodan.DomainLookup = s.ShodanEnabled && sec.Shodan != "", sec.Shodan, s.ShodanDomainLookup
	in.Censys.Enabled, in.Censys.Token, in.Censys.OrgID = s.CensysEnabled && sec.Censys != "", sec.Censys, s.CensysOrgID
	in.VirusTotal.Enabled, in.VirusTotal.Key = s.VirusTotalEnabled && sec.VirusTotal != "", sec.VirusTotal
	in.HIBP.Enabled, in.HIBP.Key = s.HIBPEnabled && sec.HIBP != "", sec.HIBP
	in.GitHub.Enabled, in.GitHub.Key = s.GitHubEnabled && sec.GitHub != "", sec.GitHub
	in.MaxIPs, in.CacheTTL = s.EnrichMaxIPs, 24*time.Hour
	return c
}
