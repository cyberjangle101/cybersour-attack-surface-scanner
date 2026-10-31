package main

// The rule index: every finding the agent can raise, with a stable rule ID, how its
// evidence is gathered, its severity and exactly what triggers it. It is the source of
// docs/RULES.md (rules_doc_test.go regenerates and checks that file), together with
// the detection tables the rules use: sensitivePaths, portalSigs, defaultPages,
// riskyPorts, takeoverSuffixes, datastoreSigs and the rest. Every kind in
// findingCatalog must have an entry here, and the test fails if one is missing.

// How a rule gathers its evidence.
const (
	modePassiveDNS = "Passive: DNS"
	modeActive     = "Active: connects to the organisation's own servers (opt-in)"
	modeIntel      = "Third-party intelligence (needs a second source to be trusted)"
	modeRegistry   = "Passive: registration data (RDAP)"
	modeOSINT      = "Passive: public sources (OSINT)"
)

// Rule categories, in the order the reference lists them.
var ruleCategories = []string{
	"DNS and domain", "Email authentication", "TLS and HTTPS", "Web exposure", "Cloud and storage",
	"Exposure intelligence", "Brand and leak monitoring",
}

type ruleMeta struct {
	ID, Category, Mode, Severity, Trigger string
}

var ruleIndex = map[string]ruleMeta{
	// DNS and domain
	"dangling-cname": {"EASM-DNS-001", "DNS and domain", modePassiveDNS, "High on a claim-able platform (see takeover platforms, plus the can-i-take-over-xyz services that report NXDOMAIN), otherwise Low",
		"A CNAME record whose target does not exist (NXDOMAIN)."},
	"private-ip": {"EASM-DNS-002", "DNS and domain", modePassiveDNS, "Low",
		"An A/AAAA record in public DNS points at a private, loopback or other non-public address."},
	"asn-unexpected": {"EASM-DNS-003", "DNS and domain", modePassiveDNS, "High",
		"An address the domain's names resolve to is announced by a network (ASN) or organisation outside the expected ownership configured for the domain."},
	"email-auth/no-caa":    {"EASM-DNS-004", "DNS and domain", modePassiveDNS, "Low", "No CAA record at the domain."},
	"email-auth/no-dnssec": {"EASM-DNS-005", "DNS and domain", modePassiveDNS, "Low", "No DS record for the domain at its parent zone."},
	"subdomain-takeover": {"EASM-DNS-007", "DNS and domain", modeActive, "High",
		"A name's CNAME points at a service listed as claimable by can-i-take-over-xyz, and its home page shows that service's 'nothing here' text."},
	"domain-expiry": {"EASM-DNS-006", "DNS and domain", modeRegistry, "High within 14 days (or expired), Medium within 30, Low within 60",
		"The registration expiry date in RDAP is close."},

	// Email authentication
	"email-auth/no-spf":               {"EASM-MAIL-001", "Email authentication", modePassiveDNS, "Medium", "No TXT record starting v=spf1 at the domain apex."},
	"email-auth/spf-multiple":         {"EASM-MAIL-002", "Email authentication", modePassiveDNS, "High", "More than one SPF record at the apex."},
	"email-auth/spf-permissive":       {"EASM-MAIL-003", "Email authentication", modePassiveDNS, "High", "The SPF record ends in +all or all."},
	"email-auth/spf-neutral":          {"EASM-MAIL-004", "Email authentication", modePassiveDNS, "Medium", "The SPF record ends in ?all."},
	"email-auth/spf-ptr":              {"EASM-MAIL-005", "Email authentication", modePassiveDNS, "Low", "The SPF record uses the ptr mechanism."},
	"email-auth/spf-too-many-lookups": {"EASM-MAIL-006", "Email authentication", modePassiveDNS, "Medium", "Evaluating SPF, including every include:, needs more than 10 DNS lookups."},
	"email-auth/no-dmarc":             {"EASM-MAIL-007", "Email authentication", modePassiveDNS, "Medium", "No TXT record starting v=DMARC1 at _dmarc.<domain>."},
	"email-auth/dmarc-p-none":         {"EASM-MAIL-008", "Email authentication", modePassiveDNS, "Low", "The DMARC policy is p=none."},
	"email-auth/dmarc-sp-none":        {"EASM-MAIL-009", "Email authentication", modePassiveDNS, "Medium", "The DMARC record sets sp=none for subdomains."},
	"email-auth/dmarc-pct":            {"EASM-MAIL-010", "Email authentication", modePassiveDNS, "Low", "The DMARC record has pct below 100."},
	"email-auth/dmarc-no-reports":     {"EASM-MAIL-011", "Email authentication", modePassiveDNS, "Low", "The DMARC record has no rua= reporting address."},
	"email-auth/dkim-not-found":       {"EASM-MAIL-012", "Email authentication", modePassiveDNS, "Low", "No DKIM key at any of the common selector names (see DKIM selectors)."},
	"email-auth/dkim-weak-key":        {"EASM-MAIL-013", "Email authentication", modePassiveDNS, "Medium", "A DKIM key is shorter than 1024 bits."},
	"email-auth/dkim-short-key":       {"EASM-MAIL-014", "Email authentication", modePassiveDNS, "Low", "A DKIM key is exactly 1024 bits."},
	"email-auth/no-mta-sts":           {"EASM-MAIL-015", "Email authentication", modePassiveDNS, "Low", "No TXT record at _mta-sts.<domain>."},
	"email-auth/no-tls-rpt":           {"EASM-MAIL-016", "Email authentication", modePassiveDNS, "Low", "No TXT record at _smtp._tls.<domain>."},

	// TLS and HTTPS
	"tls-expired": {"EASM-TLS-001", "TLS and HTTPS", modeActive, "High", "The certificate presented on an HTTPS port has expired."},
	"tls-expiring": {"EASM-TLS-002", "TLS and HTTPS", modeActive, "High within 7 days, Medium within 30",
		"The certificate expires within 30 days."},
	"tls-hostname":       {"EASM-TLS-003", "TLS and HTTPS", modeActive, "Medium", "The certificate does not cover the host name it was served for."},
	"tls-untrusted":      {"EASM-TLS-004", "TLS and HTTPS", modeActive, "Medium", "The certificate is self-signed, from an untrusted authority, has an incomplete chain, or is not yet valid."},
	"tls-legacy":         {"EASM-TLS-005", "TLS and HTTPS", modeActive, "Medium", "A handshake offering only TLS 1.0 or only TLS 1.1 succeeds."},
	"tls-weak-key":       {"EASM-TLS-006", "TLS and HTTPS", modeActive, "Medium", "The certificate key is RSA under 2048 bits or ECDSA under 256 bits."},
	"tls-weak-signature": {"EASM-TLS-007", "TLS and HTTPS", modeActive, "Medium", "The certificate is signed with SHA-1, MD5 or MD2."},
	"hsts-missing":       {"EASM-TLS-008", "TLS and HTTPS", modeActive, "Low", "An HTTPS site with a valid certificate answers 2xx without a Strict-Transport-Security header."},
	"no-https-redirect": {"EASM-TLS-009", "TLS and HTTPS", modeActive, "Low",
		"Port 80 answers with content instead of redirecting to https://, while the same host serves HTTPS."},

	// Web exposure
	"login-portal": {"EASM-WEB-001", "Web exposure", modeActive, "Per product (see login portals): High for infrastructure consoles, Medium for remote-access gateways, webmail/SSO and monitoring or collaboration tools, Low for website sign-ins",
		"The home page, or a product's well-known sign-in page, is recognised as one of the login portals listed below."},
	"exposed-path": {"EASM-WEB-002", "Web exposure", modeActive, "Per file: High, Medium or Low (see sensitive files)",
		"A well-known sensitive file or page answers 200 and its content passes the file's own test (and is not the site's catch-all page); or / shows a directory listing (Medium)."},
	"default-page": {"EASM-WEB-003", "Web exposure", modeActive, "Low",
		"The home page answers 200 with a web server's default page (see default pages)."},
	"no-security-txt": {"EASM-WEB-004", "Web exposure", modeActive, "Low",
		"The domain or www over HTTPS has no /.well-known/security.txt with a Contact: line."},

	// Cloud and storage
	"bucket-public":   {"EASM-CLOUD-001", "Cloud and storage", modeActive, "High", "A name points at an S3 or Google Cloud Storage bucket that lists its contents to anyone."},
	"bucket-takeover": {"EASM-CLOUD-002", "Cloud and storage", modeActive, "High", "A name points at an S3 or Google Cloud Storage bucket that does not exist (NoSuchBucket)."},
	"cloud-datastore": {"EASM-CLOUD-003", "Cloud and storage", modePassiveDNS, "Medium",
		"A name in public DNS is an alias for a managed database, cache or search service (see managed datastores)."},

	// Exposure intelligence
	"exposed-service": {"EASM-EXP-001", "Exposure intelligence", modeIntel, "High for the high-risk ports, Medium for the other risky ports (see risky ports)",
		"An intelligence source reports one of the risky ports open on an address of the domain. Addresses on a CDN edge are skipped: tagged cdn by Shodan, or inside the published Cloudflare, Fastly, CloudFront or GitHub Pages ranges."},
	"known-vuln": {"EASM-EXP-002", "Exposure intelligence", modeIntel, "High with any CVE in CISA KEV, an EPSS of 50% or more, or 10 or more CVEs; otherwise Medium",
		"Shodan lists CVEs for the software versions seen on an address. CVEs in CISA KEV come first, then the highest FIRST EPSS scores."},
	"ip-flagged": {"EASM-EXP-003", "Exposure intelligence", modeIntel, "High",
		"Shodan tags an address compromised, malware or doublepulsar, or SANS ISC has reports of it attacking DShield sensors or lists it on a compromised-host feed (Emerging Threats compromised, CINS Army). The two are independent, so together they make the finding trusted."},
	"tor-exit": {"EASM-EXP-005", "Exposure intelligence", "Passive: Tor Project exit list (download)", "Medium",
		"An address the domain's names resolve to is on the Tor Project's current exit-node list."},
	"eol-software": {"EASM-EXP-004", "Exposure intelligence", modeIntel, "Medium",
		"Shodan tags an address eol-os or eol-product."},

	// Brand and leak monitoring
	"lookalike-domain": {"EASM-BRAND-001", "Brand and leak monitoring", modeOSINT, "Medium when it accepts email (MX), otherwise Low",
		"A registered variation of the domain resolves (see look-alike techniques)."},
	"leaked-credentials": {"EASM-BRAND-002", "Brand and leak monitoring", modeOSINT, "High for 5 or more accounts in one breach, otherwise Medium",
		"Have I Been Pwned lists accounts at the domain in a breach (API key required)."},
	"repo-exposure": {"EASM-BRAND-003", "Brand and leak monitoring", modeOSINT, "Medium",
		"GitHub code search finds the domain near words such as password, secret or token (token required)."},
}

// dataSource is one external source, for the rules reference.
type dataSource struct {
	Name, Kind, Key, Sends, Default, Feeds string
}

// dataSources lists every external source the agent can use, what it is sent and
// which rules it feeds.
var dataSources = []dataSource{
	{"crt.sh", "Subdomain discovery (Certificate Transparency)", "None", "The domain name", "On", "Inventory; DNS-001...007 and every host-based rule"},
	{"CertSpotter", "Subdomain discovery (Certificate Transparency)", "None (100 requests/hour)", "The domain name", "On", "Inventory; a scan counts as complete when crt.sh or CertSpotter answered"},
	{"HackerTarget", "Subdomain discovery", "None (about 50 requests/day)", "The domain name", "On", "Inventory"},
	{"urlscan.io", "Subdomain discovery (public scans)", "None", "The domain name", "On", "Inventory"},
	{"Wayback Machine", "Subdomain discovery (archived URLs)", "None", "The domain name", "Off (slow)", "Inventory"},
	{"AlienVault OTX", "Subdomain discovery (passive DNS)", "Free key", "The domain name", "Off until a key is saved", "Inventory"},
	{"Anubis (jonlu.ca)", "Subdomain discovery", "None", "The domain name", "Off (blocks automated clients)", "Inventory"},
	{"Shodan DNS", "Subdomain discovery", "Shodan key (1 query credit per scan)", "The domain name", "Off", "Inventory"},
	{"VirusTotal", "Subdomain discovery", "Free key", "The domain name", "Off until a key is saved", "Inventory"},
	{"Public DNS resolvers (1.1.1.1, 8.8.8.8)", "DNS", "None", "Host names", "On", "All DNS and email rules"},
	{"DNS-over-HTTPS (Google, Cloudflare)", "DNS fallback when port 53 is blocked", "None", "Host names", "On", "All DNS and email rules"},
	{"Team Cymru", "IP to network owner (DNS)", "None", "IP addresses", "On", "DNS-003"},
	{"RIPEstat", "IP to network owner (fallback)", "None", "IP addresses", "On", "DNS-003"},
	{"Cloud and CDN IP ranges (AWS, Google Cloud, Cloudflare, Fastly, Oracle Cloud, GitHub)", "Reference download", "None", "Nothing (plain downloads)", "On", "EXP-001 skips CDN edges; findings name the hosting provider"},
	{"RDAP (rdap.org)", "Registration data", "None", "The domain name", "On", "DNS-006"},
	{"Shodan InternetDB", "Exposure intelligence", "None", "IP addresses", "On", "EXP-001...004"},
	{"Shodan API", "Exposure intelligence", "Shodan key", "IP addresses", "Off until a key is saved", "EXP-001...004"},
	{"Censys", "Exposure intelligence", "Personal access token", "IP addresses", "Off until a token is saved", "EXP-001 (an independent second source)"},
	{"SANS Internet Storm Center", "Threat intelligence (attack reports)", "None", "IP addresses", "On", "EXP-003 (an independent second source to Shodan's tags)"},
	{"Tor Project exit list", "Threat intelligence (download)", "None", "Nothing (plain download)", "On", "EXP-005"},
	{"CISA Known Exploited Vulnerabilities", "Vulnerability intelligence (download)", "None", "Nothing (plain download)", "On", "EXP-002 severity and ordering"},
	{"FIRST EPSS", "Vulnerability intelligence", "None", "CVE identifiers", "On", "EXP-002 severity and ordering"},
	{"can-i-take-over-xyz fingerprints", "Takeover intelligence (download)", "None", "Nothing (plain download)", "On", "DNS-001, DNS-007"},
	{"Have I Been Pwned", "Leak monitoring", "Paid key, verified domain", "The domain name", "Off until a key is saved", "BRAND-002"},
	{"GitHub code search", "Leak monitoring", "Token", "The domain name", "Off until a token is saved", "BRAND-003"},
}
