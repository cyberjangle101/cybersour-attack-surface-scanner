# Changelog

What changed in each release of EASM Agent, newest first. Releases and their signed downloads are on the [Releases page](https://github.com/cyberjangle101/cybersour-attack-surface-scanner/releases).

## 1.9

**Unreleased (CyberSoar EASM logo pack, MCP settings, every rule tested end to end):**

* **New logo.** The CyberSoar EASM logo pack replaces the radar icon: the wing and name in the sidebar, the stacked "CS EASM" mark on the sign-in and set-up pages, and the app icon for the program (Explorer, the taskbar and the notification area) and the browser tab. The logos have transparent backgrounds, so they suit the light and the dark theme. They are cut from the pack in `docs/brand` by `go run ./tools/icon`.
* **AI assistants (MCP) in Settings.** A new Settings section explains the `/mcp` endpoint: this agent's own address, ready-to-paste set-up for Claude Code and Claude Desktop, the tools an assistant gets and which token role each needs, what to know before connecting one, and the latest connections. A switch turns MCP off (every request to `/mcp` is then refused, whatever the token; the REST API is not affected). It is on by default, as before; an assistant still needs an API token.
* **Every rule is tested end to end.** The test suite now fails if any of the 77 rules is never raised by a scan of test data. New tests feed scans the SPF, DMARC and DKIM records, private address, managed-database name and weak TLS certificate (1024-bit RSA key, SHA-1 signature) behind the 14 rules that were only unit-tested before.

**v1.9.18 (one page per domain, accessible light mode, public storage and API checks, update banner):**

* **One page per domain.** Clicking a domain now opens its Findings page, filtered to that domain, with its scan buttons, its settings (in a card at the top: click to open), and its hosts, certificates, changes and scan history below. The separate `/targets/…` page is gone; old links and bookmarks go to the new page.
* **Light mode is white and light grey**, with a white sidebar, and every colour pair meets WCAG 2.2 AA contrast (4.5:1 for text, 3:1 for the borders of inputs and buttons). The search box no longer overlaps its icon.
* **New version available banner.** When a newer release is out, a banner at the top of every page says so, for everyone signed in. Administrators get a button to review and install it; others are told an administrator can; container installs are told to deploy the new image.
* **Public storage.** Bucket checks (EASM-CLOUD-001 and -002) now cover DigitalOcean Spaces, Alibaba Cloud OSS, Azure Blob Storage containers and Firebase Storage as well as Amazon S3 and Google Cloud Storage, and check buckets your site's pages and scripts link to, not only those named in DNS. A missing bucket your site loads files from is reported as a takeover: anyone could create it and serve scripts to your visitors.
* **EASM-CLOUD-008 Firebase database can be read by anyone (new).** A Firebase Realtime Database your site names is asked for its top-level keys without signing in.
* **Public APIs.** EASM-EXP-006 now also checks the Kubernetes API server, Docker registries, Consul, CouchDB, Apache Solr, ClickHouse, Kibana and Prometheus for answering without credentials, on ports that exposure data reports open.
* **EASM-WEB-012 API key or secret in a public web page (new).** The home page and the site's own scripts are checked for keys in formats that are secret by themselves (private keys; AWS, Stripe, GitHub, Slack, SendGrid, OpenAI and Anthropic keys). The key itself is never stored: only its type, a masked form and a hash.
* **Possible vulnerabilities (CVEs) can now be confirmed automatically.** CVEs come from Shodan data, which guesses them from the software version it last saw, so on their own they are *unconfirmed*: listed, but not counted or alerted. With active checks on, a CVE finding is now trusted when the agent's own web check sees the server announce the same product at the same version (for example `Apache/2.4.49`), and it goes back to unconfirmed when the server is upgraded. The dashboard now says how many findings are unconfirmed and why, with a link to review them.
* **Fixed: the window of an agent restarted by an update did not close.** After *Back up and install* the new version opened a console window that stayed on screen. The restart now opens no window at all unless the key passphrase has to be typed, and when it does, the window closes as intended.
* **The logo** (the radar sweep from the program icon) now appears in the sidebar and on the sign-in pages instead of the letter "E".
* **README tour and screenshots**, made from the test lab's made-up company. The tools that make them, and a full-length video for YouTube, are described in [docs/DEMO.md](docs/DEMO.md).* **Fixed: the Events page said "sent" for every alert, even with email not set up.** It now says what really happened: "sent" by email, "queued", "not sent" (email not set up, so the alert went to the log), or "not alerted" (a kind of change that is only recorded). Events recorded before this version say "not recorded", because that was not kept.
* **Fixed:** network checks sent a query string as part of the path, so the Elasticsearch index count was always 0.
* **Kubernetes manifests** pin the 1.9.17 image, and move to 1.9.18 once it is published.
* **Scheduling checked:** a new test runs the real scheduler loop and confirms that each domain is scanned on its own when its interval passes, that one not yet due is left alone, and that a paused one is never scanned.

**v1.9.17 (new look, light and dark mode, search, AI assistants over MCP):**

* **New look.** The menu is now down the left-hand side, grouped into Monitor, Reporting, System and Administration, with your account in the top bar. Colours are coded by meaning across the interface: severities, finding status (open red, accepted amber, resolved green) and asset types each have their own colour. On a phone, the menu slides in from the left.
* **Light and dark mode.** The interface follows your computer's setting until you choose with the moon/sun button in the top bar. The choice is remembered by your browser.
* **Search everything.** The search box at the top of every page looks through monitored domains, findings (any status) and the asset inventory at once. Press `/` to jump to it.
* **Connect an AI assistant (MCP).** Claude, or any other assistant that speaks the Model Context Protocol, can read findings, assets and recent changes through `/mcp` using an API token. A Viewer token is read-only; an Analyst token can also queue a rescan of a domain that is already monitored. Nothing an assistant does can add a domain or change a finding. Every connection is audited. Read [docs/MCP.md](docs/MCP.md) before you turn it on: it covers where your data goes and the prompt-injection risk.
* **More security checks on every change.** The container image is now built, run and scanned for vulnerabilities (Trivy) on every pull request, on Intel and ARM; the Dockerfile and Kubernetes manifests are checked for risky settings; the PowerShell test scripts are analysed (PSScriptAnalyzer); and CodeQL runs its extended security queries. Each release image now carries a signed software bill of materials (SBOM): `gh attestation verify oci://ghcr.io/cyberjangle101/easm-agent:1.9.17 --repo cyberjangle101/cybersour-attack-surface-scanner --predicate-type https://cyclonedx.org/bom`.
* **Container image on Debian 13.** The image is now built on distroless Debian 13 (it was Debian 12), whose time zone data and CA certificates are current. Same non-root user (65532), same volume, nothing to change.
* **Kubernetes manifests** pin the 1.9.16 image (they were still on 1.9.13) and move to 1.9.17 once it is published.

**v1.9.16 (twenty-eight new rules: DNS, certificates, web applications, network services, threat intelligence):**

Every rule is listed in [docs/RULES.md](docs/RULES.md).

*Threat intelligence and reputation.* These are all **off by default**.

* **EASM-BRAND-005 New certificate for a look-alike domain, High.** Certificate Transparency shows a certificate from the last 30 days for a look-alike already reported under EASM-BRAND-001. It runs whenever look-alike checks are on.
* **EASM-BRAND-004 Look-alike site copies yours.** High when it serves your exact site icon (with its Shodan favicon hash, to search for more copies) or a password form under your name or title; Medium when only the title matches. Its own switch, *Also visit the look-alike web sites*, is needed, because it connects to servers someone else, possibly an attacker, runs.
* **EASM-BRAND-006 Internal package name anyone could publish (dependency confusion):** package names your own sites reveal in source maps, package.json or requirements.txt are checked against npm and PyPI. High when the name is free; Medium for a scoped npm name. Needs active checks, and the registries see the names.
* **EASM-MAIL-018 Address on a spam blocklist:** your mail servers, SPF addresses, domain and www are looked up on SpamCop and PSBL. High for a mail address, Medium for a web-only one. Spamhaus is not used: it refuses lookups through public resolvers without a paid DQS key.

*Not built, by design:* writing to buckets to test them, guessing other people's bucket names, open-relay tests that ask your mail server to relay, exploit checks, and scanning public container images. The reasons are in the pull requests.

*Network-service checks.* These are part of the active checks, under a new *Check network services* switch that is on by default once active checks are on. They send one read-only request each, and only to ports that exposure data reports open on your own addresses.

* **EASM-EXP-006 Database, cache or control API answers without a password, High:** Redis INFO, Memcached stats, Elasticsearch, MongoDB listDatabases, the Docker API, the Kubernetes kubelet, and anonymous FTP.
* **EASM-DNS-010 Zone transfer allowed, High:** one of your own nameservers hands out the whole zone (AXFR).
* **EASM-DNS-011 Open DNS resolver, Medium.**
* **EASM-TLS-010 Weak TLS cipher suites, Medium:** NULL, export, RC4, DES, 3DES or anonymous suites, found with a handshake that offers nothing else.
* **EASM-EXP-010 NTLM sign-in reveals internal Windows details, Low:** the Active Directory domain, computer name and Windows build.
* **EASM-CLOUD-006 Cloud load balancer with no healthy backend, Medium:** AWS ELB, Azure Traffic Manager or Front Door answering 502, 503 or 504.
* **EASM-CLOUD-007 Serverless function or API endpoint without authentication:** a Lambda URL, API Gateway, Cloud Run or Cloud Functions endpoint returns JSON data. High with real data, otherwise Medium.
* **EASM-EXP-008 Origin reachable around the CDN, High:** a site behind a CDN is also served directly by one of your own addresses, which bypasses the WAF.
* **EASM-EXP-009 Default SNMP password, High.** This one has its own switch, **off by default**, because it tries the communities public and private, which is a password attempt.

*Web and mail checks.* These are part of the opt-in active checks: they stay within your own networks, never touch private addresses, and only read. The one non-GET request is a GraphQL introspection query, which only asks for the schema.

* **EASM-WEB-005 Directory listing** now has its own rule: High when the listing offers archives, dumps or backups, otherwise Medium. It was part of EASM-WEB-002, so an open listing finding there closes and reappears under this rule.
* **EASM-WEB-006 API documentation or GraphQL schema is public:** Swagger UI and GraphQL introspection are Medium, and a bare API description is Low. Everything is Low on hosts named like dev, test or staging systems. The /swagger.json, /openapi.json and /v3/api-docs checks move here from EASM-WEB-002.
* **EASM-WEB-007 CORS trusts any site with credentials, High:** a made-up Origin is echoed back with Access-Control-Allow-Credentials: true.
* **EASM-WEB-008 Debug mode:** interactive debuggers and environment dumps (Werkzeug, Laravel Ignition, Symfony profiler, Django and Whoops debug pages) are High, ASP.NET detailed errors are Medium, and exact version headers are Low.
* **EASM-WEB-009 Script from a domain anyone can register, High:** the home page loads JavaScript from a lapsed domain.
* **EASM-WEB-010 Session cookie without Secure or HttpOnly:** Medium on login pages, Low elsewhere.
* **EASM-WEB-011 Missing security headers** (CSP, X-Frame-Options, nosniff): Low, or Medium when a login page can be framed.
* **EASM-MAIL-017 MTA-STS policy is unusable, Medium:** the TXT record exists, but the policy file is missing, has an invalid certificate, or is malformed.
* **EASM-TLS-011 Default certificate reveals internal host names, Low:** asked without SNI, a server shows a certificate naming corp, local or internal hosts, or names under your domain the scan has not seen.
* **Fixed:** login-portal, subdomain-takeover, security.txt, HSTS and weak-certificate findings were closed by any scan that ran without active checks. Now only a web check that ran can close them.

*DNS and certificate checks.* These are passive: they use DNS, registration data and Certificate Transparency, which the scan already reads, plus one direct question to a delegated zone's nameservers, as any resolver asks.

* **EASM-DNS-008 Delegated zone can be taken over (dangling NS), High.** A part of your domain is delegated to nameservers that either no longer serve it, which matters most on providers such as Route 53 or Azure DNS where anyone can create the zone, or that sit on a domain that is not registered. When resolvers only answer SERVFAIL, the delegation is read from your own nameservers. A nameserver domain that is registered but withdrawn from DNS (on hold) is Medium.
* **EASM-DNS-009 Mail server on a lapsed or missing name (dangling MX).** High when the mail server's domain is not registered, so anyone could register it and receive your mail; Medium when it is on hold; Low when the mail server name simply does not exist.
* **EASM-DNS-012 No registrar transfer lock, Medium.** RDAP shows neither clientTransferProhibited nor serverTransferProhibited. Two-letter country domains are skipped, because many of their registries do not use these statuses.
* **EASM-DNS-013 Wildcard DNS, Low.** The scan already detected wildcards to avoid false results; it now reports them, because they hide dangling names.
* **EASM-TLS-012 Certificate from an authority your CAA record does not allow, High.** Certificates issued in the last 30 days are compared with the CAA records that govern each name, including a subdomain's own CAA and issuewild for wildcard names. Only issuers the agent recognises are compared, so an unknown authority never causes a false alarm. These findings stay open until you review them.
* **EASM-TLS-013 New host appeared in Certificate Transparency and is live.** After the baseline, a name first seen in CT that resolves is Low, or Medium when the active web check reaches a service on it. It stays open until reviewed, or until the host goes away.

**v1.9.15 (syslog over TLS, on your own network only):**

* **Syslog / SIEM channels can use TLS** (RFC 5425, usually port 6514), and new channels offer it first. The collector's certificate is checked against the system's trusted authorities plus an internal CA you can paste in. Switching the check off is possible but marked as not recommended. The 1.6 notes said TLS was already supported; it was not, and that entry is corrected.
* **Syslog only goes to private or local addresses:** 10.x, 172.16–31.x, 192.168.x, IPv6 fc00::/7 and loopback. Syslog has no sign-in of its own, so it is for a collector on your own network; alerts that must cross the internet go through a webhook over HTTPS. The rule is checked when a channel is saved, by resolving its name, and again on every connection, so a name that later points at a public address is refused too.
* **After updating:** a syslog channel that points at a public address stops sending. The channels page shows why. Move it to a collector on your network, or use a webhook.

**v1.9.14 (safer releases; Kubernetes pinned to a published image):**

* **The Kubernetes manifests point at an image that exists.** They named 1.9.12, which was never published, so a deploy from `main` could not pull it. They now pin 1.9.13 by digest, so the image cannot change under you, and re-pinning is part of every release.
* **Signed commits and tags.** Changes to `main` must now be signed, and release tags are signed too.
* **The release signing key is held by the release environments only.** Only the job that signs a release candidate (UAT) or a production release (which also needs the owner's approval) can read it, instead of any workflow in the repository.
* **Sign-in blocks say so, with how long.** After too many wrong passwords or two-factor codes, the page now says sign-in is blocked and for how many minutes. Before, the wrong code that set off a block still said "wait for the next code and try again", so the next, right code was refused and two-factor looked broken. Once a block ends, one more wrong attempt blocks it again for longer (up to 30 minutes), and the message now says that too. The limits themselves are unchanged.

**v1.9.13 (threat intelligence kept apart; evidence links that fit):**

* **Threat intelligence is separate and off by default.** Look-alike domains, public code (GitHub) and leaked accounts (Have I Been Pwned) look outside your own attack surface. They now have their own *Settings → Threat intelligence* section, marked off by default, and their rules are in a "Threat intelligence (off by default)" category. **Switching one off closes its open findings**, with an audit entry; risks you accepted are kept. Before, the findings stayed open for ever once nothing re-checked them. SANS ISC and the Tor exit list stay on: they are about your own addresses.
* **"Check it yourself" links fit the finding.** Every finding about a name used to get a certificate-search (crt.sh) link, whatever it was about. Now each kind gets its own checks:
  * public code: the file on GitHub and a code search for the domain;
  * TLS: SSL Labs and crt.sh;
  * look-alikes: RDAP, urlscan and crt.sh;
  * takeovers: the published CNAME;
  * HSTS and redirects: the response headers;
  * missing `security.txt`: the file;
  * any web address named in the finding.

**v1.9.12 (runs on Kubernetes: GKE, AKS, EKS):**

* **Container image:** `ghcr.io/cyberjangle101/easm-agent:<version>` for amd64 and arm64.
  * Built from the signed release binaries on distroless.
  * Runs as non-root with a read-only file system, and carries SLSA provenance.
  * Every release candidate's image is tested in Docker and on a real Kubernetes cluster before it can be released.
* **Manifests** in [`deploy/kubernetes`](deploy/kubernetes): a single-replica StatefulSet on block storage, the restricted Pod Security Standard, a NetworkPolicy, and health probes. The guide is [docs/KUBERNETES.md](docs/KUBERNETES.md).
* **For containers and services:**
  * `EASM_KEY_PASSPHRASE_FILE` reads the key passphrase from a mounted secret (Kubernetes Secret, Secret Manager, Key Vault) instead of an environment variable.
  * `EASM_MANAGED=1` (set in the image) keeps the "new version available" notice but never installs over the program: you update by deploying the new image.
  * `-show-setup-code` prints the first-administrator code, for images with no shell.

**v1.9.11 (fewer false positives in two rules):**

* **Look-alike domains (EASM-BRAND-001)** now report only variations that someone else registered *and* that can be used: they accept email or have a web address. These are left out:
  * names parked or for sale (Afternic, Sedo, Bodis, Dan.com and similar);
  * names with neither mail nor web;
  * names whose name servers or mail servers are under your domain, or that point at your own web server (your defensive registrations);
  * bitsquatting variations, which on short names are mostly unrelated words.
  
  Tried on three well-known domains, this cut the findings by 48 to 81%.
* **Address flagged as malicious (EASM-EXP-003):** SANS ISC now counts only *recent and substantial* activity: reports in the last 30 days from at least 100 sensors, or a compromised-host listing seen in the last 30 days. Older or sparser reports, such as a CDN's few stray reports over the years or a listing from 2017, stay as evidence on the asset page. A flag from SANS ISC alone is now Medium; Shodan's compromised tag stays High.

**v1.9.10 (dependency updates):**

* **Database engine:** the SQLite driver goes from 0.30.5 to 0.35.6. SQLite now runs as WebAssembly translated into Go, instead of through a WebAssembly runtime. This needs no change to your data: encrypted databases from earlier versions open as before, which the release tests check by upgrading real v1.9.9 data. The binary is about 1 MB bigger, and speed is unchanged.
* **Other libraries:** DNS (`miekg/dns` 1.1.73), Windows service (`kardianos/service` 1.3.0), LDAP (`go-ldap` 3.4.15, `asn1-ber` 1.5.8), and `golang.org/x/net` 0.62.0, which clears two advisories in its HTML parser (the agent never called the affected code).

**v1.9.9 (every release is tested before it reaches you):**

* Each release is first published as a release candidate (a GitHub pre-release, which agents never update to) and tested automatically. That testing covers the full test suite with the race detector, fuzzing, static and dependency scans, a ZAP scan of the running agent, the end-to-end UAT suite, an upgrade from the previous release, and a Windows service install.
* A release only reaches the Releases page, and so the agent's update check, once that candidate has passed on the same code and the maintainer has approved it.
* No change to how the agent behaves.

**v1.9.8 (more free sources, for redundancy and accuracy):**

Each source below was checked against the live service before being added. All need no key, all can be switched off in Settings, and all show on System health.

* **Redundancy:**
  * **CertSpotter** is a second Certificate Transparency source. A scan now counts as complete when crt.sh *or* CertSpotter answered, so a crt.sh outage no longer leaves a domain's baseline unfinished.
  * **urlscan.io** adds names seen in public scans, including hosts that never had a certificate. The **Wayback Machine** (archived URLs) is available too, but off by default because it is slow.
  * **DNS-over-HTTPS fallback** (Google, Cloudflare): when a resolver cannot be reached, for example on a server whose network blocks outbound port 53, the same question is asked over HTTPS. The real DNS answer and error codes are kept, so takeover detection still works.
* **Accuracy:**
  * **Cloud and CDN IP ranges** (AWS, Google Cloud, Cloudflare, Fastly, Oracle Cloud, GitHub): open ports on a CDN edge that Shodan did not tag are no longer reported, and findings name the hosting provider ("hosted on AWS (EC2, eu-west-2)").
  * **SANS Internet Storm Center** gives an independent second opinion on malicious addresses: reports of the address attacking DShield sensors, or listings on compromised-host feeds. When it agrees with Shodan's tags, the "address flagged" finding becomes *Trusted* without a manual check.
  * **CISA KEV and FIRST EPSS** rank vulnerability findings. CVEs exploited in the wild (and those used by ransomware) come first, then the most likely to be exploited. Any KEV CVE, or an EPSS of 50% or more, makes the finding High.
  * **Subdomain takeover fingerprints** (can-i-take-over-xyz): a dangling CNAME to a service the community lists as claimable is High. A new rule, **EASM-DNS-007**, catches names that still resolve but show the service's "nothing here" page; this needs active checks.
* **New finding: Tor exit node** (EASM-EXP-005), when one of your addresses is on the Tor Project's exit list.
* **How downloads are handled:** bulk lists are downloaded at most daily (Tor every 6 hours, slow-changing ones weekly). Each is checked before use, kept in the encrypted database, and the last good copy stays in use when a download fails.
* **Not added, and why:**
  * URLhaus and ThreatFox now require an Auth-Key (HTTP 401).
  * BGPView has shut down.
  * ThreatMiner was unreachable (HTTP 522).
  * AnubisDB still blocks automated clients.
  * RapidDNS only offers an HTML page to scrape.
  * Quad9's DNS-over-HTTPS endpoint timed out.
  * ip-api.com's and ipwho.is's free tiers do not allow this use.
  * SSL Labs duplicates the agent's own TLS checks at 25 assessments a day.
  * Common Crawl overlaps the Wayback Machine at a much higher cost.
  * NVD, CIRCL and OSV add nothing to the NVD link already on every CVE.

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

**Updates itself, safely.** The agent checks GitHub once a day for a newer release (switch it off in *Settings → Organisation*) and tells administrators with a banner and on *System health → Updates*, with the release notes. *Back up and install* takes a backup, downloads the new version, and installs it only if it matches the release's `SHA256SUMS`, whose Ed25519 signature is checked against the key built into the program and which must name that exact version (so an old release cannot be passed off as new). The previous version is kept for `easm-agent -rollback`. On Windows, an agent started from its `.exe` restarts into the new version in a new window (enter the key passphrase there if it has one); services are updated with `easm-agent -update`, which stops and restarts the service around the swap. Releases are built and signed by CI from a version tag; see [RELEASING.md](docs/RELEASING.md). Builds without a release key (such as your own) report new versions but never install them.

**Fixes from QA.** Two agents could run on the same data folder at once, scanning and alerting twice and risking the database: the data folder is now locked, and a second start says which process holds it. Passphrases piped to `-protect-key` or `-reset-password` were rejected (one buffered reader per prompt, and the UTF-8 byte-order mark Windows PowerShell 5.1 puts in front of piped input): both are fixed.

## 1.8

**Opens itself, then gets out of the way.** After you enter the key passphrase, the web interface opens in your default browser. On Windows, when the program was double-clicked, its console window then hides and the agent keeps running in the background; an administrator stops it from *System health → Stop agent* (recorded in the audit trail). Started from an existing terminal, the console stays as it was and Ctrl-C works. Use `-no-browser` and `-keep-console` (or `no_browser` / `keep_console` in the config file) to turn either off. To run unattended across sign-outs and reboots, install it as a service instead (see *Running as a service*).

**System health is current at start-up.** The connectors are now checked automatically right after start and every 6 hours, so the Health page no longer shows failures left over from the previous session until someone presses *Check connections now*.

**Scan now with active checks.** Administrators get a third button on a domain's page that runs the active checks (TLS certificates, home pages, exposed files, cloud storage) for that one scan, even while *Settings → Active checks* stays off. It follows the same rules as the setting: only addresses inside the networks you declared unless *probe outside my networks* is on, never private addresses, read-only requests. Passive scans that follow do not resolve what it found, since they cannot check it. Each request is in the audit trail.

**Reports say whose they are and who made them.** Set *Settings → Organisation name* and every report (page, PDF, JSON, digest email) opens with that name, the domains it covers and *Prepared by* (the signed-in user and role, the API token's owner, or "EASM Agent (scheduled digest)"). Without an organisation name, a single-domain report is headed by its domain.

**Gate fixes.** All lint findings fixed, the test suite passes on Windows, a data race in a test fixed, a CodeQL redirect-check alert resolved, Semgrep added to the Security Scan workflow, and known false positives recorded in `.gitleaksignore`.

## 1.7

**Cloud and SaaS sprawl.** Every scan now builds an inventory of the cloud platforms, APIs, SaaS products and mail services your domain uses, read from DNS it already has (no extra traffic): CNAME targets (AWS, Azure, Google Cloud, Cloudflare, Heroku, Netlify, Shopify, Zendesk and more), SPF `include:` entries, MX hosts and domain-verification TXT tokens left behind by SaaS onboarding (Atlassian, Stripe, Slack, DocuSign and others). A service seen for the first time raises a *cloud-service* event (quiet during the baseline scan). A name that points at a managed database, cache or search cluster (RDS, Azure SQL, MongoDB Atlas, Redis, Elastic and similar) raises a medium *cloud-datastore* finding. SPF, DKIM, DMARC, MTA-STS and CAA were already checked. Limits: this finds what DNS reveals; a SaaS tool that never touches your DNS, or a database with no public name, is invisible to it.

**Ownership checks.** On a domain, *Expected ASNs* takes ASN numbers (`AS16509`, `16509`, mixed separators) and *Expected organisation keywords* takes words such as `AMAZON, MICROSOFT` (case-insensitive substring of the network's registered name). An address matching either is fine; one matching neither raises a high *asn-unexpected* finding. Leave both empty to skip the check. Use it to spot forgotten servers, shadow IT in an unapproved cloud, and hijacked records.

**Data folder.** The database, key, certificates and backups now live in a per-user data folder (`%LocalAppData%\EASM Agent` on Windows, `~/.local/share/easm-agent` on Linux, or `-data-dir`), created with restricted permissions. Move an old install with `easm-agent -migrate-data`.

**Backup and restore.** Settings → Backup writes encrypted snapshots (the database is never copied in clear) on a schedule or on demand, keeps the newest N, and offers a download. The encryption key is included only if you tick it; otherwise keep your key file safe separately. Restore offline with `easm-agent -restore <file>`.

**Server certificate upload.** Settings → Web server certificate accepts a CA-signed certificate chain and key (paste or upload PEM); it is validated, applied without a restart, and can be removed to fall back to the self-signed certificate.

**Delete a domain.** The red icon on the Dashboard's domain list removes the domain and all its data after a confirmation page that shows what will go.

**Dashboard tiles are links** to the domains, assets and findings behind each number. A **Quick guide** (menu, and a welcome card on first use) explains what the tool does and how to start.

**Reports.** The report has an executive summary with charts, then new findings, resolved findings, severity filters, findings grouped by asset and by finding name, and full detail for the security team. The PDF mirrors it.

**Sub-domain scope.** You can add `www.example.com`, but the tool warns: only that name and what is below it is covered, and parent-level email records, look-alikes and sibling hosts are missed. Add the registered domain where you can. A sub-domain of an already monitored domain is rejected as an overlap.

## 1.6

**Roles.** *Viewer* reads everything. *Analyst* can also triage: acknowledge, reopen, accept a risk (with a written reason and optional expiry), override a finding's severity, accept or dismiss discovery suggestions, and start scans. *Admin* additionally manages settings, users, alert channels and Active Directory. Every change is written to an **audit trail** (who, what, when, why).

**Active Directory sign-in** (Settings → Active Directory, admin only). LDAPS or StartTLS to one or more domain controllers; a read-only service account is used to look people up (its password is stored encrypted). Map **AD groups** to roles, or add individual **AD users**; the highest matching role wins, and removing someone from the group removes their access at the next sign-in. Local accounts keep working, so you cannot lock yourself out. Nested groups are matched through `memberOf`; a user whose only membership is their *primary* group (usually "Domain Users") is not matched, so map a normal security group instead.

**Removals are visible.** A host, address or record that stops appearing is confirmed missing over several scans and then logged as *removed* (Events, alerts and the report). **Refresh intelligence now** on a domain re-queries ports/CVE/ownership without waiting for the schedule.

**Optional live checks** (Settings → Active checks, off by default; SSRF-safe, only your own discovered hosts): TLS protocol/cipher/expiry, HTTP security headers, default/admin pages, open storage buckets, and screenshots when a Chrome/Chromium is installed.

**Alert channels** (Settings → Alert channels): generic webhook (optionally HMAC-signed), Slack, Microsoft Teams, syslog/SIEM (UDP or TCP, CEF or JSON; TLS came in 1.9.15) and Jira tickets (de-duplicated). Each has its own minimum severity, a *Send test* button, and secrets are stored encrypted. Email alerts are grouped per host and link to each finding.

**API and exports.** Create bearer tokens under *Account* (viewer/analyst/admin; a token never exceeds its owner's current role). Endpoints live under `/api/v1/` (findings, assets, events, report); findings use the same key names as the CSV. SARIF 2.1.0 and STIX 2.1 exports are available there and on the Report page. Cookies never authenticate API calls.

**Two-factor sign-in** for local accounts: TOTP (authenticator app) with 8 single-use recovery codes. Admins can require it for all local accounts and reset a user's 2FA. API tokens are not subject to 2FA.

**Wider discovery** (each switchable in Settings): related domains from certificates; reverse-IP neighbours. Results arrive as **suggestions** you add or dismiss; they never become scan targets on their own.

**Threat intelligence (off by default, Settings → Threat intelligence):**
* **What it covers:** look-alike domains that someone else registered and that can be used; leaked accounts via Have I Been Pwned (needs a key); public code that names your domain next to secret-like words, via GitHub (needs a token).
* **Why it's separate:** these look outside your own attack surface. They are leads for a threat-intelligence team rather than exposures to fix, and they are noisier.
* **Switching one off** closes its open findings. Risks you accepted are kept.

**More email/DNS checks:** MTA-STS, TLS-RPT, DKIM (probes common selectors only, so "not found" is not proof of absence), SPF lookup limit and subdomain coverage, DMARC subdomain policy and reporting, CAA, DNSSEC.

**Small items:** internationalised domain names are stored as punycode (shown with a Unicode hint); the dashboard has a proper page heading; findings can be grouped by host.
