<p align="center"><img src="docs/brand/wordmark.png" width="332" height="110" alt="CyberSoar EASM logo: a wing in orange, crimson and green beside the name"></p>

# Cybersour Attack Surface Scanner

A lightweight, single-binary agent for continuous **External Attack Surface Management (EASM)**. It runs as a persistent background service on Windows or Linux, watches the internet-facing footprint of the organisations you tell it about, and emails you only when something **changes**.

> **Status:** v1.9.18. What changed in each release is in [CHANGELOG.md](CHANGELOG.md). Every check the agent runs is listed in [docs/RULES.md](docs/RULES.md).

![A one-minute tour of EASM Agent: the dashboard, findings with their risk and fix, the evidence behind a finding, a domain's page and the report, using a made-up company](docs/images/demo.gif)

*The tour uses a made-up company (acme-corp.test) from the test lab: nothing real was scanned. How it is made: [docs/DEMO.md](docs/DEMO.md).*

## Why

Attack surfaces drift. A forgotten subdomain, a new certificate or an unexpected IP resolution can be the first sign of shadow IT or a takeover risk. Commercial EASM platforms are expensive, so this project uses only free, no-API-key sources and ships as one small Go binary with no external services to run.

## Features

- **Passive discovery at no cost:** certificate transparency (crt.sh, CertSpotter), HackerTarget and urlscan.io with no key; more sources with free or paid keys
- **DNS, ownership and exposure:** resolves every name, maps addresses to their network owner (Team Cymru, RIPEstat) to spot assets outside your expected networks, and adds open ports and CVEs from Shodan InternetDB and optional keyed sources
- **Findings with evidence:** each finding gives its source of evidence, the risk and the fix, with links to check it yourself; every rule is listed in [docs/RULES.md](docs/RULES.md)
- **Delta-only alerting:** email, Slack, Teams, webhooks, Jira, and syslog/SIEM over TLS to a collector on your own network, only when something changes, so routine scans stay quiet
- **Web interface:** dashboard, findings, asset inventory, reports (page, PDF, CSV, JSON, SARIF, STIX), an API, and an MCP endpoint for AI assistants ([docs/MCP.md](docs/MCP.md))
- **Users and access:** viewer, analyst and admin roles, two-factor sign-in, Active Directory sign-in and an audit trail
- **Optional checks, off by default:** active checks of your own hosts (TLS, headers, exposed files, screenshots) and threat intelligence (look-alike domains, leaked accounts, public code)
- **Encrypted local state:** an embedded SQLite database, encrypted at rest, so there is nothing else to install
- **Runs anywhere:** a workstation program, a Windows or Linux service, or a container on Docker and Kubernetes ([docs/KUBERNETES.md](docs/KUBERNETES.md))
- **Signed self-updates:** the agent installs a new release only after checking its signature

## Screenshots

| | |
|---|---|
| [![Dashboard: monitored domains, hosts, open findings and recent changes](docs/images/dashboard.png)](docs/images/dashboard.png) **Dashboard.** Domains, hosts, open findings and the changes of the last day at a glance. | [![Findings: each with its severity, source of evidence, risk and recommended fix](docs/images/findings.png)](docs/images/findings.png) **Findings.** Every finding says where the evidence came from, why it matters and how to fix it. |
| [![A domain's page: scan controls, settings, findings, hosts, certificates and history](docs/images/domain.png)](docs/images/domain.png) **One page per domain.** Scan controls and settings at the top, then its findings, hosts, certificates, changes and scan history. | [![The evidence behind a finding, with links to check it yourself](docs/images/evidence.png)](docs/images/evidence.png) **Evidence.** What was found, by which check, when, and links to confirm it yourself. |
| [![Assets: one searchable inventory of domains, addresses, services and certificates](docs/images/assets.png)](docs/images/assets.png) **Assets.** One searchable inventory of everything found. | [![Report: posture score, charts and exports](docs/images/report.png)](docs/images/report.png) **Reports.** A posture score and charts, exported as PDF, CSV, JSON, SARIF or STIX. |

[![Dark mode](docs/images/dashboard-dark.png)](docs/images/dashboard-dark.png)
*Light and dark mode: the interface follows your system until you choose with the moon/sun button.*

## Reliability and safety

- Capped DNS worker pool and a global query rate, so scans stay polite
- Retry with backoff and graceful timeout handling for slow sources, with a second source for certificate transparency and DNS over HTTPS when port 53 is blocked
- Structured, timestamped `INFO` / `WARN` / `ERROR` logging, and a System health page for every connector

## Quick start

1. Download the program for your system from the [Releases page](https://github.com/cyberjangle101/cybersour-attack-surface-scanner/releases) (`easm-agent-windows-amd64.exe`, `easm-agent-linux-amd64` or `easm-agent-linux-arm64`). To check that a download was built by this repository's release workflow:
   `gh attestation verify easm-agent-windows-amd64.exe --repo cyberjangle101/cybersour-attack-surface-scanner`
   To build it yourself instead: `go build -o easm-agent .` (Windows: `go build -o easm-agent.exe .`).
2. Run it (Windows: double-click `easm-agent.exe`) and choose a key passphrase, or on Windows press Enter to protect the key with your Windows account.
3. The web interface opens in your browser (**https://127.0.0.1:8080**) with the one-time setup code filled in; create the first administrator account.
4. **Settings** → configure email (SMTP) and press *Send test email*.
5. **Dashboard** → *Add an entity to monitor*: enter `example.com`. Optionally add expected ASNs,
   organisation keywords and ignore patterns. Scanning starts immediately.

The first scan of a domain is a baseline: it records what exists today without alerting on it,
and sends a "baseline established" email. Security findings are the exception: anything risky it
finds, such as an exposed service or a weak email policy, is emailed from that first scan on.
After that you are emailed only about new subdomains, new IP/DNS records, new certificates and
new findings.

To run it on a server for several people, see *Workstation or server* below. For Docker and Kubernetes (GKE, AKS, EKS), see [docs/KUBERNETES.md](docs/KUBERNETES.md).

## What it does

* **Discovery (free):** crt.sh (retry/backoff), CertSpotter, HackerTarget and urlscan.io need no key; the Wayback Machine is available but off (slow). AlienVault OTX needs a free API key. Anubis is still listed but off, because its service now blocks automated clients. Every source is listed in [docs/RULES.md](docs/RULES.md#data-sources).
* **Resolution:** A/AAAA/CNAME/NS/MX/TXT via 1.1.1.1 and 8.8.8.8, bounded workers and a global QPS cap, wildcard-DNS detection.
* **Ownership:** Team Cymru DNS WHOIS (RIPEstat fallback) maps IPs to ASN/organisation; addresses outside your expected ASNs/keywords raise a HIGH finding.
* **Exposure intelligence:** open ports, CVEs and risk tags per IP, and domain expiry (see below).
* **Findings:** every finding lists its *source of evidence*, the *risk* and the *recommended fix*. Findings can be acknowledged and auto-resolve when fixed. The full rule list (rule IDs, triggers, severities, and every path, product, port and platform checked) is in **[docs/RULES.md](docs/RULES.md)**, which is generated from the code.
* **Alerts:** HTML + plaintext email (STARTTLS / implicit TLS), plus an optional daily/weekly digest that includes the same source/risk/fix text.
* **Reports:** per-domain or all-domain report page, CSV exports (inventory, findings, assets) and JSON.
* **Users:** admin, analyst and read-only viewer roles; local accounts with optional two-factor sign-in, or Active Directory sign-in (Settings → Active Directory).

## Updating

* **From the web interface:** *System health → Updates → Back up and install X.Y.Z* (administrators).
* **From the command line** (servers, services): `easm-agent -update-check`, then `easm-agent -update` (add `-yes` to skip the question). Run it from an elevated prompt / as root when the agent is a service.
* **Going back:** stop the agent, then `easm-agent -rollback`.
* **Containers:** deploy the new image tag instead; the agent in a container never installs over itself.

## Pages

| Page | Purpose |
|---|---|
| Dashboard | Add entities, see status and open findings. Running scans show a live percentage bar with the current stage (e.g. "Resolving DNS · 120 of 400 hosts") and flag a source that has gone quiet |
| Findings | Severity, finding, source of evidence, risk, recommended fix; acknowledge / reopen. Choose one domain (or click it on the Dashboard) for **its page**: scan buttons, its settings at the top, then its hosts, certificates, changes and scan history |
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
| `-data-dir path` | Where `easm.db` and `easm.key` live (default: the per-user data folder, or the service's, shown on System health) |
| `-config file` | Optional bootstrap YAML, see [docs/config.example.yaml](docs/config.example.yaml) |
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

Issues and pull requests are welcome. Before a change can merge into `main`:

* every commit in it must be signed (GitHub shows it as *Verified*);
* the required checks must pass: build and tests on Linux and Windows, CodeQL, Semgrep, Gitleaks, dependency review and workflow security (zizmor);
* the code owner must approve it.

Report security problems privately, as described in [SECURITY.md](SECURITY.md). How releases are built, tested and signed is in [docs/RELEASING.md](docs/RELEASING.md).

## License

[MIT](LICENSE).
