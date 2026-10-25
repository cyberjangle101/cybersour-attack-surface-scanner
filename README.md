# Cybersour Attack Surface Scanner

A lightweight, single-binary agent for continuous **External Attack Surface Management (EASM)**. It runs as a persistent background service on Windows or Linux, watches the internet-facing footprint of the organisations you tell it about, and emails you only when something **changes**.

> **Status:** v1.9.7. See "What's new in 1.9" below. Every check the agent runs is listed in [docs/RULES.md](docs/RULES.md).

## Why

Attack surfaces drift. A forgotten subdomain, a new certificate or an unexpected IP resolution can be the first sign of shadow IT or a takeover risk. Commercial EASM platforms are expensive, so this project uses only free, no-API-key sources and ships as one small Go binary with no external services to run.

## Features

- **Passive discovery, zero cost, no API keys**
  - Certificate transparency via crt.sh
  - HackerTarget host search, plus AlienVault OTX passive DNS with a free OTX key
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

* **Discovery (free):** crt.sh (retry/backoff) and HackerTarget need no key; AlienVault OTX needs a free API key. Anubis is still listed but off, because its service now blocks automated clients.
* **Resolution:** A/AAAA/CNAME/NS/MX/TXT via 1.1.1.1 and 8.8.8.8, bounded workers and a global QPS cap, wildcard-DNS detection.
* **Ownership:** Team Cymru DNS WHOIS (RIPEstat fallback) maps IPs to ASN/organisation; addresses outside your expected ASNs/keywords raise a HIGH finding.
* **Exposure intelligence:** open ports, CVEs and risk tags per IP, and domain expiry (see below).
* **Findings:** every finding lists its *source of evidence*, the *risk* and the *recommended fix*. Findings can be acknowledged and auto-resolve when fixed. The full rule list (rule IDs, triggers, severities, and every path, product, port and platform checked) is in **[docs/RULES.md](docs/RULES.md)**, which is generated from the code.
* **Alerts:** HTML + plaintext email (STARTTLS / implicit TLS), plus an optional daily/weekly digest that includes the same source/risk/fix text.
* **Reports:** per-domain or all-domain report page, CSV exports (inventory, findings, assets) and JSON.
* **Users:** admin, analyst and read-only viewer roles; local accounts with optional two-factor sign-in, or Active Directory sign-in (see *What's new in 1.6*).

## What's new in 1.9

**v1.9.7 (rules reference and new checks):**
* **[docs/RULES.md](docs/RULES.md) lists every rule** with a stable ID (`EASM-WEB-001` and so on), its trigger, severity, how the evidence is collected, why it matters and what to do, plus every path, product, port, platform and signature the rules use. It is generated from the code, and a test fails if the two disagree.
* **Login portals and admin consoles (EASM-WEB-001):**
  * **Remote-access gateways (Medium):** Fortinet, Palo Alto GlobalProtect, Ivanti/Pulse, Citrix, Cisco ASA, SonicWall, Check Point and RD Web Access, the devices behind most recent mass-exploitation campaigns.
  * **Webmail and SSO (Medium):** Outlook on the web, AD FS.
  * **Administration consoles (High, or Medium for monitoring tools):** Tomcat Manager, Jenkins, phpMyAdmin, Webmin, cPanel/WHM, Plesk, vCenter/ESXi, Kubernetes Dashboard, Portainer, Rancher, Argo CD, MinIO, RabbitMQ, pfSense, OPNsense, MikroTik, Jupyter, Grafana, Kibana, Prometheus, Zabbix, SonarQube, GitLab, Jira/Confluence, Synology, QNAP.
  * **Website sign-ins (Low):** WordPress, Joomla, Drupal.
  * **How they are recognised:** by the product's own page title, header or 401 realm, so a page that only mentions a product, or a site that answers every path, does not count.
* **20 more sensitive files (EASM-WEB-002):** Subversion and Mercurial metadata, `.htpasswd`, AWS credentials, `.npmrc` tokens, SFTP deployment settings, `web.config`, Docker Compose files, SQL dumps, `info.php`, Apache `server-info`, ASP.NET `elmah.axd`/`trace.axd`, Go `pprof`, public API descriptions and an open `crossdomain.xml`. Each needs a content match.
* **TLS:** certificates with weak keys (RSA under 2048 bits) or SHA-1/MD5 signatures (EASM-TLS-006/007), and HTTPS sites without HSTS (EASM-TLS-008, Low).
* **No `security.txt`** on the domain or www (EASM-WEB-004, Low).
* **More risky ports (EASM-EXP-001):**
  * **Industrial control (High):** Modbus, Siemens S7, DNP3, EtherNet/IP.
  * **High:** Kubernetes kubelet and etcd, Cisco Smart Install, Java RMI, Android Debug Bridge.
  * **Medium:** WinRM over HTTPS, the Docker TLS API, the Kubernetes API, MikroTik Winbox, PPTP, rsync, AJP, WebLogic, GlassFish, Cassandra, InfluxDB, MQTT, printers.
* **More subdomain-takeover platforms (EASM-DNS-001):** Azure API Management, Container Instances, HDInsight and Service Bus, ngrok, LaunchRock, UptimeRobot and Pingdom status pages, Agile CRM, JetBrains YouTrack, Gemfury, SmartJobBoard.
**v1.9.6 (deploying on a shared server):**
* **The first administrator needs a one-time setup code.** Before, whoever submitted the setup page first became administrator, which on a server reachable from the network could be anyone. The code is written to `setup-code.txt` in the data folder, which only administrators can read. On a workstation it is filled in automatically on the page the agent opens. It changes at every start, is never logged, and stops working once the administrator exists.
* **Services run as their own low-privilege account** (`NT SERVICE\easm-agent`), from `%ProgramFiles%\EASM Agent`, with data in `%ProgramData%\EASM Agent`. They start automatically and restart if they fail. See *Workstation or server*.
* **The key can be protected with the Windows account (DPAPI)** instead of a passphrase. This is the default for a new service, and optional at a workstation's first start (press Enter). Only that account on that computer can open the key, so a copied data folder or backup is useless. System health → Encryption key shows how the key is protected. With your password (and two-factor code) you can download a **recovery copy** locked with a passphrase you choose, or switch an existing key to Windows-account protection. Both actions are audited.
* **Fixed: the data folder's permissions under a service account.** They were given to the `USERNAME` variable, which under a service names the computer, not the service; they now go to the account the agent actually runs as.
* **Double-clicking the program where it already runs as a service** opens that service's web page instead of starting a second, empty agent.
* **AlienVault OTX needs a free API key.** OTX now refuses passive-DNS lookups without one, which System health showed as "Rate limited by the service" on every scan. Create a free account at otx.alienvault.com, copy the key from its API Integration page and paste it in Settings → Data sources. The key is stored encrypted like the other API keys. OTX only runs once a key is saved, and new installs start with it off.
* **Anubis is off by default.** `jldc.me` moved to `jonlu.ca`, which answers every automated client with a Cloudflare bot challenge, so it failed on every scan with "rejected the credentials". System health now says so plainly. **After updating:** in Settings, paste an OTX key or untick OTX, and untick Anubis. Until OTX gets a key or is unticked, saving Settings asks you to choose.
* **Every pull request is now compiled, linted and tested on Linux and Windows** before it can merge, so a change that breaks the build can no longer reach a release.

**v1.9.5:**
* **Findings from exposure data need two sources.** A finding raised only from Shodan data (open port, CVE list, tags) is marked **Unconfirmed**. It is still listed, but it is not emailed, not sent to channels and not counted in totals or reports. It becomes **Trusted** when a second, independent source agrees: Censys, the agent's own active check, or an analyst. InternetDB and the Shodan API are one dataset, so together they count once. When a scan runs with active checks on, the agent connects to each unconfirmed open port itself. A port that answers becomes trusted and alerts ("Now confirmed by a second source"); one that doesn't is marked **Disputed**. What no connection can prove, such as a CVE or an end-of-life tag, an analyst confirms with *Mark as confirmed*, saying how (audited, and can be removed). The Findings page has a *Corroboration* filter, each finding shows the sources that agree, and the dashboard shows the unconfirmed count separately. Findings from earlier versions are graded when the agent starts.
* **The console window really closes.** On Windows 11 console programs open in Windows Terminal, which ignored the old "hide window" call, so the window stayed open. After start-up the agent now detaches from its window, which closes it, and keeps running. The log continues in `easm.log` in the data folder, unless a log file is configured.
* **Notification-area icon and logo.** While the agent runs, its icon sits next to the clock. Click it to open EASM Agent; right-click it to open the log file or stop the agent (with a confirmation). The program, the icon and the browser tab now carry the EASM Agent logo, drawn by `tools/icon` (`go run ./tools/icon` rebuilds the icon resource and favicon).

**v1.9.4:**
* **Updates restart cleanly.** After *Back up and install* the new version now opens in its own window and asks for the key passphrase there, then carries on in the background. Before, the restarted program could not use its window, so it closed at once and had to be started by hand.
* **Evidence for every finding.** *View evidence* (Findings page and each domain's page) opens a page with: what the agent recorded (ports per source, first and last reported), the **raw answer** each exposure source returned (Shodan InternetDB, Shodan, Censys, API keys removed), the active-scan result and banner, any **screenshots** of web services on the address, and links to check the data yourself (Shodan host page, InternetDB JSON, Censys, VirusTotal, NVD for CVEs, RDAP and crt.sh for domains). *Download evidence (JSON)* saves it all for a ticket. Raw answers are kept from the next scan that asks the source (*Scan now and refresh exposure data* fetches them at once).
* **First-scan options when adding a domain:** *Active scanning enabled*, *Screenshots enabled* and *Confirm open ports* (connect to each open port the exposure data reports, as *Confirm via active scan* does, and record the result). They apply to the first scan; Settings → Active checks turns them on for every scan.

**v1.9.3:**
* **Pause stops the scan.** Pausing a domain while it is being scanned now stops that scan straight away (nothing from the stopped scan is saved) instead of letting it run to the end. Scan history records it as "stopped: monitoring was paused".
* **Active checks mid-scan.** *Scan now with active checks* while a passive scan is running stops it and starts again with active checks, instead of only warning that a scan was already running. The progress bar now shows **Active checks** when a scan runs them.
* **Confirm via active scan.** Open-port (exposed-service) findings come from Shodan, InternetDB or Censys data that can be days old. Administrators can now press *Confirm via active scan* on such a finding: the agent connects to that one address and port (like `Test-NetConnection -Port` or `nc -v`) and reads the service's banner if it sends one. The result (*Verified open*, *port closed* or *no response*), the banner, when and by whom are shown on the finding and written to the audit log. Addresses outside the domain's expected ownership are only contacted if *Settings → Active checks* allows it.
* Stopped scans are no longer counted as connector failures on *System health*.

**v1.9.2:** the start-up window shows where the data folder, database and key file are. A wrong key-file passphrase now says "Incorrect Password, try again." and allows three attempts before aborting, and the window stays open for a few seconds so the reason can be read. Passphrases from `EASM_KEY_PASSPHRASE` still get one attempt.

**v1.9.1:** no functional changes. It is the first release that a v1.9.0 agent (the first build carrying the release key) can install itself from *System health → Updates*.

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
| AlienVault OTX | your free key | subdomains from passive DNS (entered under Settings → Data sources) |

Notes:

* Keys are entered in **Settings**, stored AES-256-GCM encrypted, never displayed again, and scrubbed from logs and error messages. A rejected key stops further requests to that service for the rest of the scan.
* **These services receive the IP addresses (and, for Shodan DNS, VirusTotal and OTX, the domain names) you monitor.** The agent never scans or connects to your hosts itself. Each source is opt-in or can be switched off.
* Findings from these sources come from third-party scan data that may be days old, and CVEs are inferred from service banners (back-ported fixes can make some false positives). Treat them as leads to verify.
* Addresses tagged `cdn`, and addresses outside an entity's expected ASNs, are inventoried but do **not** raise exposure findings, because they are not yours to fix.
* Answers are cached for 24 hours and capped per scan (default 250 IPs per source) so large estates are covered over several scans. A finding is auto-resolved only when a fresh answer was obtained; an outage or stale cache never closes one.
* Free-tier terms apply to InternetDB and the other services; check them if you use the agent commercially.

## Workstation or server

The same program runs in either role.

**On a workstation (one person):** double-click `easm-agent.exe`.
* **First start:** a console window asks for a key passphrase, or you press Enter to protect the key with your Windows account instead (nothing to type at later starts).
* **Setting up:** the agent opens the setup page with the one-time setup code already filled in, and you create the administrator account.
* **After that:** the window closes and the agent's icon stays next to the clock.
* **Data and access:** the data lives in `%LocalAppData%\EASM Agent`, and the web interface only listens on `127.0.0.1`.

**On a server (several people, through the browser):** install it once as a service, from an elevated prompt.
```
easm-agent -service install -listen 0.0.0.0:8443
easm-agent -service start
```
* **Program:** copied to `%ProgramFiles%\EASM Agent`, and runs from there.
* **Account:** it runs as `NT SERVICE\easm-agent`, a low-privilege account that Windows manages and that has no password. It does not run as LocalSystem, because the agent fetches internet data and drives a browser, so a flaw in it must not hand over the server. `-service-account DOMAIN\name$` uses a group managed service account instead.
* **Data:** kept in `%ProgramData%\EASM Agent`, which only that account, SYSTEM and Administrators can open. Not in the installing administrator's profile.
* **Encryption key:** created on the first start and protected with the service's own Windows account (DPAPI). There is no passphrase to store in an environment variable, which every user of the server could read. Then download a **recovery copy** (System health → Encryption key) and keep it offline; without it, a rebuilt server cannot open the data.
* **First administrator:** open the address and enter the setup code from `%ProgramData%\EASM Agent\setup-code.txt`. Only administrators can read that file, so nobody else on the network can claim the agent first.
* **Access for others:** add the name people will type to `allowed_hosts` in the config file and upload your organisation's certificate in System health. Everyone else signs in with their own account (local or Active Directory) as viewer, analyst or administrator; nobody needs to log on to the server.
* **Restarts:** the service starts automatically (delayed start) and restarts if it fails.
* **Updates:** run `easm-agent -update` from an elevated prompt, because the service account deliberately cannot change its own program file.
* **Already-running service:** if someone double-clicks the program on that server, it opens the service's web page instead of starting a second, empty agent.

Also available: `-service stop`, `restart`, `status`, `uninstall`. On Linux, `-service install` (as root) keeps data in `/var/lib/easm-agent`, and the passphrase comes from `EASM_KEY_PASSPHRASE`. Logs go to the service manager, or to a file via the bootstrap config.

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
| `-keep-console` | Windows: keep the console window open after start-up |
| `-service-account name` | With `-service install` on Windows: the account the service runs as (default `NT SERVICE\easm-agent`; or `DOMAIN\name$` for a group managed service account, or `LocalSystem`) |
| `-service action` | install / uninstall / start / stop / restart / status |
| `-version` | Print version |

## Encryption at rest

Everything the agent stores is encrypted on disk, in two layers:

* **Whole-database encryption (transparent).** `easm.db` is encrypted block by block with **AES-256-XTS** (the mode used for disk encryption), including the write-ahead log. Nothing readable, not even the SQLite header, table names, hostnames or user names, appears in the file. It is on by default and needs no setup. A database from an older version is encrypted automatically at the first start (a one-time migration that is verified, then overwrites and removes the plaintext copy).
* **Field encryption.** API keys (Shodan, Censys, VirusTotal), the SMTP password and the password hashes are additionally sealed with **AES-256-GCM** inside the database. Both the API keys and the SMTP settings live in the database, so they are covered by both layers; there is no separate plaintext file for them.
* **Passwords** are never stored. Only a salted **bcrypt** hash is kept (and sealed as above). Hashing is the correct protection for passwords because even the agent cannot recover them.
* **The key.** A random 256-bit master key is created on first start in `easm.key` (permissions 0600). The database key and the field key are derived from it with separate labels. Back up `easm.key` together with `easm.db`; without it the data cannot be read.
* **Passphrase for the key file (asked on first start).** The very first time the agent starts it asks you to choose a passphrase (at least 12 characters, entered twice) and creates `easm.key` locked with it (scrypt + AES-256-GCM). Every later start asks for it again. A copied data folder is then useless without the passphrase. If the passphrase is lost the data cannot be recovered.
  * Services and other unattended starts have no terminal. On Windows the key is then protected with the service's account (DPAPI, see *Workstation or server*); elsewhere set the `EASM_KEY_PASSPHRASE` environment variable (on the very first start too). A first start that can do neither stops with an explanation instead of silently creating an unprotected key.
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
* Passwords are bcrypt-hashed; login attempts are throttled per account and address, with back-off; CSRF tokens on all changes.
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
