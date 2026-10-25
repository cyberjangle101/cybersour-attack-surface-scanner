# Cybersour Attack Surface Scanner

A lightweight, single-binary agent for continuous **External Attack Surface Management (EASM)**. It runs as a persistent background service on Windows or Linux, watches the internet-facing footprint of the organisations you tell it about, and emails you only when something **changes**.

> **Status:** v1.9.0. See "What's new in 1.9" below.

## Why

Attack surfaces drift. A forgotten subdomain, a new certificate or an unexpected IP resolution can be the first sign of shadow IT or a takeover risk. Commercial EASM platforms are expensive, so this project uses only free, no-API-key sources and ships as one small Go binary with no external services to run.

## Features

- **Passive discovery, zero cost, no API keys**
  - Certificate transparency via crt.sh
  - HackerTarget and AlienVault OTX passive DNS
- **DNS resolution** of A, AAAA, CNAME, NS, MX and TXT records via 1.1.1.1 and 8.8.8.8
- **ASN mapping** (BGPView or Team Cymru DNS WHOIS) to spot assets outside your expected network ranges
- **Delta-only alerting**: new subdomains, new IP resolutions and new TLS certificates trigger notifications, so routine scans stay quiet
- **Email reports** over SMTP with TLS/STARTTLS, in HTML and plain-text with a summary table
- **Local state** in embedded SQLite, so there is nothing else to install
- **Runs as a daemon or service** on Windows and Linux, scanning every 6 hours by default
- **Target management in the app**: add a domain, expected ASNs, organisation keywords and ignore patterns in one place; scanning, alerting and reporting follow automatically (GUI planned)

## Reliability and safety

- Capped DNS worker pool, so scans stay polite
- Retry with backoff and graceful timeout handling for crt.sh
- Structured, timestamped `INFO` / `WARN` / `ERROR` logging

## Quick start

1. Build (or use the provided binary): `go mod tidy && go build -o easm-agent .`
   Windows: `go build -o easm-agent.exe .`
2. Run it: `easm-agent` (Windows: double-click or run `easm-agent.exe` in a terminal) and enter the key passphrase.
3. The web interface opens in your browser (**https://127.0.0.1:8080**); create the first administrator account.
4. **Settings** → configure email (SMTP) and press *Send test email*.
5. **Dashboard** → *Add an entity to monitor*: enter `example.com`. Optionally add expected ASNs,
   organisation keywords and ignore patterns. Scanning starts immediately.

The first scan of a domain is a silent baseline (it records what exists today). After that you
are emailed only about new subdomains, new IP/DNS records, new certificates and new findings.

## What it does

* **Discovery (free, no keys):** crt.sh (retry/backoff), HackerTarget, AlienVault OTX, Anubis.
* **Resolution:** A/AAAA/CNAME/NS/MX/TXT via 1.1.1.1 and 8.8.8.8, bounded workers and a global QPS cap, wildcard-DNS detection.
* **Ownership:** Team Cymru DNS WHOIS (RIPEstat fallback) maps IPs to ASN/organisation; addresses outside your expected ASNs/keywords raise a HIGH finding.
* **Exposure intelligence:** open ports, CVEs and risk tags per IP, and domain expiry (see below).
* **Findings:** every finding lists its *source of evidence*, the *risk* and the *recommended fix*. Findings can be acknowledged and auto-resolve when fixed.
* **Alerts:** HTML + plaintext email (STARTTLS / implicit TLS), plus an optional daily/weekly digest that includes the same source/risk/fix text.
* **Reports:** per-domain or all-domain report page, CSV exports (inventory, findings, assets) and JSON.
* **Users:** admin, analyst and read-only viewer roles; local accounts with optional two-factor sign-in, or Active Directory sign-in (see *What's new in 1.6*).

## What's new in 1.9

**Updates itself, safely.** The agent checks GitHub once a day for a newer release (switch it off in *Settings → Organisation*) and tells administrators with a banner and on *System health → Updates*, with the release notes. *Back up and install* takes a backup, downloads the new version, and installs it only if it matches the release's `SHA256SUMS`, whose Ed25519 signature is checked against the key built into the program and which must name that exact version (so an old release cannot be passed off as new). The previous version is kept for `easm-agent -rollback`. On Windows, an agent started from its `.exe` restarts into the new version in a new window (enter the key passphrase there if it has one); services are updated with `easm-agent -update`, which stops and restarts the service around the swap. Releases are built and signed by CI from a version tag; see [RELEASING.md](RELEASING.md). Builds without a release key (such as your own) report new versions but never install them.

**Fixes from QA.** Two agents could run on the same data folder at once, scanning and alerting twice and risking the database: the data folder is now locked, and a second start says which process holds it. Passphrases piped to `-protect-key` or `-reset-password` were rejected (one buffered reader per prompt, and the UTF-8 byte-order mark Windows PowerShell 5.1 puts in front of piped input): both are fixed.

## Updating

* **From the web interface:** *System health → Updates → Back up and install X.Y.Z* (administrators).
* **From the command line** (servers, services): `easm-agent -update-check`, then `easm-agent -update` (add `-yes` to skip the question). Run it from an elevated prompt / as root when the agent is a service.
* **Going back:** stop the agent, then `easm-agent -rollback`.

## What's new in 1.8

**Opens itself, then gets out of the way.** After you enter the key passphrase, the web interface opens in your default browser. On Windows, when the program was double-clicked, its console window then hides and the agent keeps running in the background; an administrator stops it from *System health → Stop agent* (recorded in the audit trail). Started from an existing terminal, the console stays as it was and Ctrl-C works. Use `-no-browser` and `-keep-console` (or `no_browser` / `keep_console` in the config file) to turn either off. To run unattended across sign-outs and reboots, install it as a service instead (see *Running as a service*).

**System health is current at start-up.** The connectors are now checked automatically right after start and every 6 hours, so the Health page no longer shows failures left over from the previous session until someone presses *Check connections now*.

**Scan now with active checks.** Administrators get a third button on a domain's page that runs the active checks (TLS certificates, home pages, exposed files, cloud storage) for that one scan, even while *Settings → Active checks* stays off. It follows the same rules as the setting: only addresses inside the networks you declared unless *probe outside my networks* is on, never private addresses, read-only requests. Passive scans that follow do not resolve what it found, since they cannot check it. Each request is in the audit trail.

**Reports say whose they are and who made them.** Set *Settings → Organisation name* and every report (page, PDF, JSON, digest email) opens with that name, the domains it covers and *Prepared by* (the signed-in user and role, the API token's owner, or "EASM Agent (scheduled digest)"). Without an organisation name, a single-domain report is headed by its domain.

**Gate fixes.** All lint findings fixed, the test suite passes on Windows, a data race in a test fixed, a CodeQL redirect-check alert resolved, Semgrep added to the Security Scan workflow, and known false positives recorded in `.gitleaksignore`.

## What's new in 1.7

**Cloud and SaaS sprawl.** Every scan now builds an inventory of the cloud platforms, APIs, SaaS products and mail services your domain uses, read from DNS it already has (no extra traffic): CNAME targets (AWS, Azure, Google Cloud, Cloudflare, Heroku, Netlify, Shopify, Zendesk and more), SPF `include:` entries, MX hosts and domain-verification TXT tokens left behind by SaaS onboarding (Atlassian, Stripe, Slack, DocuSign and others). A service seen for the first time raises a *cloud-service* event (quiet during the baseline scan). A name that points at a managed database, cache or search cluster (RDS, Azure SQL, MongoDB Atlas, Redis, Elastic and similar) raises a medium *cloud-datastore* finding. SPF, DKIM, DMARC, MTA-STS and CAA were already checked. Limits: this finds what DNS reveals; a SaaS tool that never touches your DNS, or a database with no public name, is invisible to it.

**Ownership checks.** On a domain, *Expected ASNs* takes ASN numbers (`AS16509`, `16509`, mixed separators) and *Expected organisation keywords* takes words such as `AMAZON, MICROSOFT` (case-insensitive substring of the network's registered name). An address matching either is fine; one matching neither raises a high *asn-unexpected* finding. Leave both empty to skip the check. Use it to spot forgotten servers, shadow IT in an unapproved cloud, and hijacked records.

**Data folder.** The database, key, certificates and backups now live in a per-user data folder (`%LocalAppData%\EASM Agent` on Windows, `~/.local/share/easm-agent` on Linux, or `-data-dir`), created with restricted permissions. Move an old install with `easm-agent -migrate-data`.

**Backup and restore.** Settings → Backup writes encrypted snapshots (the database is never copied in clear) on a schedule or on demand, keeps the newest N, and offers a download. The encryption key is included only if you tick it; otherwise keep your key file safe separately. Restore offline with `easm-agent -restore <file>`.

**Server certificate upload.** Settings → Web server certificate accepts a CA-signed certificate chain and key (paste or upload PEM); it is validated, applied without a restart, and can be removed to fall back to the self-signed certificate.

**Delete a domain.** The red icon on the Dashboard's domain list removes the domain and all its data after a confirmation page that shows what will go.

**Dashboard tiles are links** to the domains, assets and findings behind each number. A **Quick guide** (menu, and a welcome card on first use) explains what the tool does and how to start.

**Reports.** The report has an executive summary with charts, then new findings, resolved findings, severity filters, findings grouped by asset and by finding name, and full detail for the security team. The PDF mirrors it.

**Sub-domain scope.** You can add `www.example.com`, but the tool warns: only that name and what is below it is covered, and parent-level email records, look-alikes and sibling hosts are missed. Add the registered domain where you can. A sub-domain of an already monitored domain is rejected as an overlap.

## What's new in 1.6

**Roles.** *Viewer* reads everything. *Analyst* can also triage: acknowledge, reopen, accept a risk (with a written reason and optional expiry), override a finding's severity, accept or dismiss discovery suggestions, and start scans. *Admin* additionally manages settings, users, alert channels and Active Directory. Every change is written to an **audit trail** (who, what, when, why).

**Active Directory sign-in** (Settings → Active Directory, admin only). LDAPS or StartTLS to one or more domain controllers; a read-only service account is used to look people up (its password is stored encrypted). Map **AD groups** to roles, or add individual **AD users**; the highest matching role wins, and removing someone from the group removes their access at the next sign-in. Local accounts keep working, so you cannot lock yourself out. Nested groups are matched through `memberOf`; a user whose only membership is their *primary* group (usually "Domain Users") is not matched, so map a normal security group instead.

**Removals are visible.** A host, address or record that stops appearing is confirmed missing over several scans and then logged as *removed* (Events, alerts and the report). **Refresh intelligence now** on a domain re-queries ports/CVE/ownership without waiting for the schedule.

**Optional live checks** (Settings → Active checks, off by default; SSRF-safe, only your own discovered hosts): TLS protocol/cipher/expiry, HTTP security headers, default/admin pages, open storage buckets, and screenshots when a Chrome/Chromium is installed.

**Alert channels** (Settings → Alert channels): generic webhook (optionally HMAC-signed), Slack, Microsoft Teams, syslog/SIEM (UDP/TCP/TLS, CEF or JSON) and Jira tickets (de-duplicated). Each has its own minimum severity, a *Send test* button, and secrets are stored encrypted. Email alerts are grouped per host and link to each finding.

**API and exports.** Create bearer tokens under *Account* (viewer/analyst/admin; a token never exceeds its owner's current role). Endpoints live under `/api/v1/` (findings, assets, events, report); findings use the same key names as the CSV. SARIF 2.1.0 and STIX 2.1 exports are available there and on the Report page. Cookies never authenticate API calls.

**Two-factor sign-in** for local accounts: TOTP (authenticator app) with 8 single-use recovery codes. Admins can require it for all local accounts and reset a user's 2FA. API tokens are not subject to 2FA.

**Wider discovery** (each switchable in Settings): look-alike domains (typos, homoglyphs, TLD swaps) that are actually registered; leaked credentials via Have I Been Pwned (needs a key); exposed repositories via GitHub (needs a token); related domains from certificates; reverse-IP neighbours. Results arrive as **suggestions** you add or dismiss; they never become scan targets on their own.

**More email/DNS checks:** MTA-STS, TLS-RPT, DKIM (probes common selectors only, so "not found" is not proof of absence), SPF lookup limit and subdomain coverage, DMARC subdomain policy and reporting, CAA, DNSSEC.

**Small items:** internationalised domain names are stored as punycode (shown with a Unicode hint); the dashboard has a proper page heading; findings can be grouped by host.

## Pages

| Page | Purpose |
|---|---|
| Dashboard | Add entities, see status and open findings. Running scans show a live percentage bar with the current stage (e.g. "Resolving DNS · 120 of 400 hosts") and flag a source that has gone quiet |
| Findings | Severity, finding, source of evidence, risk, recommended fix; acknowledge / reopen |
| Assets | One searchable inventory (click any row for its detail page: registration and certificate dates, owner/ASN, live reverse DNS, open ports, related findings): domains, IP addresses (with ASN, ports, CVEs), open services, certificates, DNS records, vulnerabilities, registration. CSV export |
| Events | The change log that drives email alerts |
| Report | Summary for any period, CSV/JSON export |
| System health | Whether each connector is connected (last success, last failure and reason, latency), a filterable **connection log** with plain-language troubleshooting hints, the data folder in use, plus database and scheduler status. *Check connections now* probes everything on demand |
| Settings | Schedule, alerting, SMTP, data sources, optional API keys |

## Scanning several domains

Domains are scanned in parallel (default 2 at a time, **Settings → Domains scanned at the same time**, 1-8), so a big or slow domain never holds up the others; a domain waiting for a free slot shows *Queued*. Scans fail fast instead of hanging: if no DNS resolver answers at all the scan stops with a clear error, the RIPEstat fallback is skipped after repeated failures, and every scan has the per-domain timeout. Alert emails are sent one batch at a time, so parallel scans never produce duplicates.

## Exposure intelligence and optional API keys

| Source | Key? | What it adds |
|---|---|---|
| Shodan InternetDB | none | open ports, CVEs, tags (cdn, compromised, eol-os…) per IP |
| RDAP | none | registrar and expiry date; finding when a domain is close to expiring |
| Shodan API | your key | banners/products and vulnerabilities per IP (host lookups use no query credits); optional subdomain search via Shodan DNS (uses a query credit) |
| Censys Platform | your personal access token | services seen on each IP (free accounts can do host lookups) |
| VirusTotal | your key | subdomains (free key: 4 requests/min, 500/day; the agent paces itself and reads at most 120 names per scan) |

Notes:

* Keys are entered in **Settings**, stored AES-256-GCM encrypted, never displayed again, and scrubbed from logs and error messages. A rejected key stops further requests to that service for the rest of the scan.
* **These services receive the IP addresses (and, for Shodan DNS and VirusTotal, the domain names) you monitor.** The agent never scans or connects to your hosts itself. Each source is opt-in or can be switched off.
* Findings from these sources come from third-party scan data that may be days old, and CVEs are inferred from service banners (back-ported fixes can make some false positives). Treat them as leads to verify.
* Addresses tagged `cdn`, and addresses outside an entity's expected ASNs, are inventoried but do **not** raise exposure findings, because they are not yours to fix.
* Answers are cached for 24 hours and capped per scan (default 250 IPs per source) so large estates are covered over several scans. A finding is auto-resolved only when a fresh answer was obtained; an outage or stale cache never closes one.
* Free-tier terms apply to InternetDB and the other services; check them if you use the agent commercially.

## Running as a service

```
easm-agent -service install     # Windows: run from an elevated prompt; Linux: as root
easm-agent -service start
easm-agent -service status
```
Also available: `stop`, `restart`, `uninstall`. Logs go to the console/service manager, or to a file via the bootstrap config.

## Options

| Flag | Meaning |
|---|---|
| `-listen addr` | Web UI address (default `127.0.0.1:8080`) |
| `-data-dir path` | Where `easm.db` and `easm.key` live (default: next to the program) |
| `-config file` | Optional bootstrap YAML, see `config.example.yaml` |
| `-reset-password user` | Offline password recovery, then exit |
| `-update-check` | Say whether a newer release exists, then exit |
| `-update` | Download, verify and install the newest release (stops/starts the service around it); `-yes` skips the question |
| `-rollback` | Go back to the version the last update replaced (stop the agent first) |
| `-no-browser` | Do not open the web interface in the browser at start-up |
| `-keep-console` | Windows: keep the console window visible after start-up |
| `-service action` | install / uninstall / start / stop / restart / status |
| `-version` | Print version |

## Encryption at rest

Everything the agent stores is encrypted on disk, in two layers:

* **Whole-database encryption (transparent).** `easm.db` is encrypted block by block with **AES-256-XTS** (the mode used for disk encryption), including the write-ahead log. Nothing readable, not even the SQLite header, table names, hostnames or user names, appears in the file. It is on by default and needs no setup. A database from an older version is encrypted automatically at the first start (a one-time migration that is verified, then overwrites and removes the plaintext copy).
* **Field encryption.** API keys (Shodan, Censys, VirusTotal), the SMTP password and the password hashes are additionally sealed with **AES-256-GCM** inside the database. Both the API keys and the SMTP settings live in the database, so they are covered by both layers; there is no separate plaintext file for them.
* **Passwords** are never stored. Only a salted **bcrypt** hash is kept (and sealed as above). Hashing is the correct protection for passwords because even the agent cannot recover them.
* **The key.** A random 256-bit master key is created on first start in `easm.key` (permissions 0600). The database key and the field key are derived from it with separate labels. Back up `easm.key` together with `easm.db`; without it the data cannot be read.
* **Passphrase for the key file (asked on first start).** The very first time the agent starts it asks you to choose a passphrase (at least 12 characters, entered twice) and creates `easm.key` locked with it (scrypt + AES-256-GCM). Every later start asks for it again. A copied data folder is then useless without the passphrase. If the passphrase is lost the data cannot be recovered.
  * Services and other unattended starts have no terminal: set the `EASM_KEY_PASSPHRASE` environment variable (on the very first start too). A first start with neither a terminal nor the variable stops with an explanation instead of silently creating an unprotected key.
  * `-no-passphrase` (first start only, or `no_passphrase: true`) stores the key unprotected. Then the key sits next to the database, so encryption only protects a copied database or backup, not someone who can read the whole data folder.
  * `easm-agent -protect-key` / `-unprotect-key` add, change or remove the passphrase later.
* **Limits to know about.** XTS gives confidentiality but no tamper detection: someone who can modify the file can corrupt it, though not read it. Data in memory while the agent runs is not encrypted. Everything lives in the data folder shown on **System health**; a different `-data-dir` means a different, empty database.

## Listen address and port

By default the web interface listens on `127.0.0.1:8080` (this computer only). Change it in **Settings → Web interface address**: pick an IP address (or type an interface name such as `eth0`, or `*` for every interface) and a port. The new address is tested before anything changes, so a busy port or an address this computer does not have leaves the old one working. The choice is remembered and the certificate is re-issued to cover the new address. An address given with `-listen` or `listen:` in the config file takes priority and is shown read-only. When you listen beyond this computer, use strong passwords and keep HTTPS on.

## Security notes

* Binds to **loopback only by default** and always serves **HTTPS**. On first start it creates a self-signed
  certificate (ECDSA P-256, TLS 1.2 or newer) as `server.crt` / `server.key` in the data folder, valid for `localhost`,
  the loopback addresses, this machine's name, the listen address and any `allowed_hosts`. It is reused on restart and
  renewed automatically before it expires or when those names change. Your browser will show a one-time warning
  because no authority vouches for the certificate; check that the SHA-256 fingerprint shown in the log (and in the
  browser's certificate details) matches, then accept it. To avoid the warning, use your own certificate
  (`tls_cert` / `tls_key`) or put the agent behind a TLS reverse proxy and set `secure_cookies: true`.
  Plain HTTP is only used if you ask for it (`-plain-http` or `plain_http: true`).
* Passwords are bcrypt-hashed; login attempts are throttled; CSRF tokens on all changes.
* **Content Security Policy** on every response: everything is blocked by default (`default-src 'none'`); scripts and styles only from this site (no inline code, no `eval`); no frames, plug-ins, workers, fonts or media; forms post only to this site; pages cannot be framed or re-based; `require-trusted-types-for 'script'` blocks DOM script-injection; `upgrade-insecure-requests` over HTTPS. Violations the browser reports are logged. `Permissions-Policy`, cross-origin isolation headers and HSTS are set as well.
* The database is encrypted at rest (see *Encryption at rest*). The data folder is created with owner-only permissions.
* Sessions are held in memory, so everyone is signed out when the agent restarts.
* Only scan domains you own or are authorised to assess. Passive sources are queried for the domain name; the agent
  sends DNS queries for discovered hostnames to the public resolvers.

## Development

```
make test        # go vet + go test
go test -race .  # race detector
go test -run '^$' -fuzz FuzzParseCrtSh -fuzztime 30s .   # one of 10 fuzz targets (see fuzz_test.go)
make all         # linux amd64/arm64 and windows amd64 into dist/
```
The suite uses fake DNS, passive-source and SMTP servers, so it needs no network. Pure-Go SQLite
(ncruces/go-sqlite3) means `CGO_ENABLED=0` static builds.

## Responsible use

By default this tool performs **passive** reconnaissance using public data sources; the optional active checks (off by default) connect to hosts it discovered. Only monitor domains and organisations you own or have explicit permission to assess. You are responsible for complying with the terms of the data sources and with applicable law.

## Contributing

Issues and pull requests are welcome.

## License

MIT (pending confirmation).
