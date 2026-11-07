package main

import "strings"

// FindingInfo is the plain-language explanation shown next to every finding.
type FindingInfo struct {
	Title    string
	Source   string // where the evidence came from
	Risk     string // why it matters
	Solution string // what to do about it
}

var findingCatalog = map[string]FindingInfo{
	"dangling-ns": {
		Title:    "Delegated zone can be taken over (dangling NS)",
		Source:   "DNS: the zone's delegation read from your own nameservers, a direct question to each delegated nameserver, and whether the nameservers' domain is registered (with RDAP where enabled)",
		Risk:     "Part of your domain is handed to nameservers that either no longer serve it or sit on a domain anyone can register. Whoever registers that domain, or creates the zone at the DNS provider, controls every record under the name: web sites, mail and certificates.",
		Solution: "If the zone is still used, set it up again at the DNS provider (or renew the nameservers' domain). If it is not, remove the NS records for it from your zone. Then check that nothing was published there in the meantime.",
	},
	"dangling-mx": {
		Title:    "Mail server record points at a lapsed or missing name (dangling MX)",
		Source:   "DNS: the MX records, whether each mail server name exists, and whether its domain is registered (with RDAP where enabled)",
		Risk:     "When the mail server's domain is not registered, anyone can register it and receive the mail sent to this name, including password resets. When the name merely does not exist, mail cannot be delivered and the record is a leftover from a service that was given up.",
		Solution: "Point the MX record at your current mail service, or remove it. If the name should not receive mail at all, publish a null MX (0 .).",
	},
	"domain-unlocked": {
		Title:    "Domain has no registrar transfer lock",
		Source:   "Registration data (RDAP status)",
		Risk:     "Without clientTransferProhibited (or a registry lock), a domain can be moved to another registrar by anyone who gets into the registrar account or talks support into it. Losing the domain loses its web sites and mail.",
		Solution: "Turn on the transfer lock in your registrar account (often called domain lock or transfer protection). For critical domains, ask the registrar about registry lock (serverTransferProhibited), which needs an out-of-band confirmation to change.",
	},
	"dns-wildcard": {
		Title:    "Wildcard DNS answers for any name",
		Source:   "DNS: randomly generated names under the domain were looked up",
		Risk:     "Every name under the domain resolves, even ones that were never created. Forgotten names never stop resolving, so dangling records are hidden, mistyped or invented links reach your server, and asset counts are inflated.",
		Solution: "Remove the wildcard record unless a service needs it. If it is needed, make sure the server it points at answers unknown names with an error rather than content.",
	},
	"ct-unauthorized-ca": {
		Title:    "Certificate issued by an authority your CAA record does not allow",
		Source:   "Certificate Transparency logs compared with the CAA records that govern each name",
		Risk:     "A publicly trusted certificate exists for your name from an authority you did not authorise. It may have been obtained by an attacker who controls part of your DNS or web traffic, by a team using an unapproved provider, or the CAA record may have changed after issuance.",
		Solution: "Find out who requested it (the crt.sh entry shows the details). If nobody in your organisation did, ask the authority to revoke it and look for how it was obtained. If it was legitimate, add that authority to the CAA record or move the service to an approved one, then accept the risk.",
	},
	"shadow-it-ct-subdomain": {
		Title:    "New host appeared in Certificate Transparency and is live",
		Source:   "Certificate Transparency logs (crt.sh, CertSpotter), DNS, and the active web check where enabled",
		Risk:     "A certificate was issued for a name nobody had seen before, and the name is live. That is someone publishing a new service under your domain, which may not have been reviewed for security or may not be yours at all.",
		Solution: "Find the owner of the new service and confirm it is approved and maintained. If it is not wanted, remove its DNS records. Once reviewed, acknowledge the finding.",
	},
	"lookalike-domain": {
		Title:    "A look-alike of your domain is registered",
		Source:   "DNS: a variation of your domain name (a typo, a similar-looking character, another ending) is registered by someone else and accepts email or has a web address. Parked or for-sale names and your own registrations are left out.",
		Risk:     "Someone has registered a name that people could mistake for yours. These are used for phishing emails, fake login pages and intercepting mail sent to a mistyped address. A domain that accepts email is the more serious case.",
		Solution: "Find out who owns it (registration lookup). If it is yours, accept the risk so it stops being reported. If it is not, consider a takedown request through the registrar, block it in your mail and web filters, and brief staff about it. Consider registering the likeliest typos yourself.",
	},
	"leaked-credentials": {
		Title:    "Accounts at your domain appear in a data breach",
		Source:   "Have I Been Pwned domain search",
		Risk:     "Email addresses at your domain were exposed in a breach of another service. If people reused that password for work accounts, attackers can sign in as them.",
		Solution: "Open your Have I Been Pwned domain dashboard to see which accounts are affected. Force a password reset for them, make sure two-factor sign-in is on, and remind staff not to reuse work passwords. Accept the risk once this has been done.",
	},
	"repo-exposure": {
		Title:    "Public code mentions your domain next to secret-like words",
		Source:   "GitHub code search",
		Risk:     "A public repository contains your domain name close to words such as password, secret or token. It may hold real credentials, internal addresses or configuration that helps an attacker. It is also often harmless, such as documentation or an example.",
		Solution: "Open the listed files. If they hold real secrets, change those secrets immediately (removing the file is not enough, because history is kept), then ask the owner or GitHub to take the repository down. If it is harmless, accept the risk with a note.",
	},
	"tls-expired": {
		Title:    "TLS certificate has expired",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "Browsers show a full-page warning and many clients refuse to connect, so the service is effectively down for ordinary users, and people learn to click through warnings.",
		Solution: "Renew the certificate now and install it on every server that answers for this name. Set up automatic renewal (for example ACME) and an expiry reminder.",
	},
	"tls-expiring": {
		Title:    "TLS certificate expires soon",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "When the certificate expires, browsers will block the site. Expiry is the most common cause of avoidable outages.",
		Solution: "Renew and install the certificate before the date shown. Automate renewal so this stops being a manual task.",
	},
	"tls-hostname": {
		Title:    "TLS certificate does not match the host name",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "The certificate presented was issued for other names, so browsers warn visitors. It often means a server is serving the wrong site or a certificate was never installed for this name.",
		Solution: "Install a certificate that lists this exact name (or a matching wildcard), or point the DNS name at the right server.",
	},
	"tls-untrusted": {
		Title:    "TLS certificate is not trusted",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "Self-signed certificates and certificates from unknown authorities cause browser warnings and cannot protect users from impersonation.",
		Solution: "Replace it with a certificate from a public authority, and make sure the server sends the full chain including intermediates.",
	},
	"tls-legacy": {
		Title:    "Server still accepts TLS 1.0 / 1.1",
		Source:   "Active check: a TLS handshake with the server offering old protocol versions",
		Risk:     "TLS 1.0 and 1.1 are deprecated and have known weaknesses; compliance standards such as PCI DSS forbid them.",
		Solution: "Disable TLS 1.0 and 1.1 and allow only TLS 1.2 and 1.3 on the server, load balancer or CDN setting.",
	},
	"default-page": {
		Title:    "Default web server page is public",
		Source:   "Active check: the page served at the root of the site",
		Risk:     "A default page shows that software was installed and never configured or maintained. Such servers are often unpatched and missing from inventories.",
		Solution: "Find out who owns the server. Either put the intended site there and harden it, or take the server offline and remove the DNS record.",
	},
	"exposed-path": {
		Title:    "Sensitive file or page is publicly readable",
		Source:   "Active check: a request for a well-known path, confirmed by its content",
		Risk:     "Files such as .git folders, .env files, backups and status pages leak source code, passwords, API keys and internal details that let attackers go much further.",
		Solution: "Block public access to the path in the web server configuration and remove the file from the web root. Treat any secrets in it as compromised and rotate them.",
	},
	"subdomain-takeover": {
		Title:  "Name shows an unclaimed service page (subdomain takeover)",
		Source: "Active check: the home page matched a can-i-take-over-xyz fingerprint for the service the CNAME points at",
		Risk: "The name still points at a hosting or SaaS service, but nothing is set up there any more and the service says so. " +
			"Anyone can create a resource with that name and publish their own content (phishing, malware, cookie theft) on your domain.",
		Solution: "Delete the DNS record if the service is retired, or claim the name again at the provider in your own account. Check other records that point at the same provider.",
	},
	"tor-exit": {
		Title:    "Address is a Tor exit node",
		Source:   "Tor Project bulk exit list (check.torproject.org)",
		Risk:     "Traffic from anyone using Tor leaves the internet from this address. Abuse reports, blocklists and investigators will point at it, and on a server you did not mean to run as an exit it can mean the host was taken over.",
		Solution: "If the exit is intended, document it and keep it on a separate address from your services. If not, find and stop the Tor process and investigate how it got there.",
	},
	"login-portal": {
		Title:  "Login portal or admin console is public",
		Source: "Active check: the site's home page, and well-known sign-in pages, recognised by the product's own wording",
		Risk: "VPN and remote-access gateways (Fortinet, Ivanti, Citrix, Palo Alto, Cisco, SonicWall) are the devices attackers exploit first after a vulnerability is published, often within days. " +
			"Webmail and single sign-on pages attract password spraying. Administration consoles (Tomcat Manager, Jenkins, phpMyAdmin, hypervisors, firewalls, Kubernetes tools) give full control when a password is guessed or a flaw is found.",
		Solution: "Administration consoles: make them reachable only from an internal network or VPN. Gateways and sign-in pages that must be public: patch within days of vendor advisories, " +
			"require MFA, rate-limit and monitor failed sign-ins. Accept the risk with a note for portals that are meant to be public.",
	},
	"tls-weak-key": {
		Title:    "TLS certificate uses a weak key",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "RSA keys under 2048 bits (or small elliptic-curve keys) are below what browsers and standards require and are within reach of well-funded attackers.",
		Solution: "Issue a new certificate with a 2048-bit (or larger) RSA key or a P-256 ECDSA key, and revoke the old one.",
	},
	"tls-weak-signature": {
		Title:    "TLS certificate is signed with SHA-1 or MD5",
		Source:   "Active check: a TLS handshake with the server",
		Risk:     "SHA-1 and MD5 signatures can be forged; browsers reject such certificates, so the site shows warnings or fails.",
		Solution: "Re-issue the certificate with a SHA-256 signature from a current certificate authority.",
	},
	"hsts-missing": {
		Title:    "HTTPS site does not send HSTS",
		Source:   "Active check: the response headers of the HTTPS site",
		Risk:     "Without Strict-Transport-Security, a browser may still make its first request over plain HTTP, where an attacker on the network can intercept or redirect it (SSL stripping).",
		Solution: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once every name under the domain works over HTTPS.",
	},
	"directory-listing": {
		Title:    "Web server directory listing is enabled",
		Source:   "Active check: the home page is an automatic folder index (\"Index of /\")",
		Risk:     "Anyone can browse and download every file in the folder, including ones never linked from the site. Archives, database dumps and backups found this way often hold source code, data and passwords.",
		Solution: "Turn off directory indexes on the web server (Apache: Options -Indexes; nginx: autoindex off; IIS: Directory Browsing off), remove files that should not be public, and put an index page in the folder.",
	},
	"exposed-api-schema": {
		Title:    "API documentation or GraphQL schema is public",
		Source:   "Active check: well-known API description and Swagger UI paths, and a read-only GraphQL introspection query",
		Risk:     "A full map of the API, every endpoint, parameter, query and mutation, tells an attacker exactly what to try, including internal or admin operations that were never meant to be found. Swagger UI also lets anyone call the API from a browser.",
		Solution: "If the API is not deliberately public, put its documentation behind sign-in or remove it from production, and turn off GraphQL introspection in production. If it is public on purpose, accept the risk.",
	},
	"cors-credential-leak": {
		Title:    "CORS trusts any web site, with the visitor's cookies",
		Source:   "Active check: a request with a made-up Origin header, looking at the Access-Control-Allow-* response headers",
		Risk:     "The server tells browsers that any site may read its responses on behalf of the visitor, cookies included. A malicious page a signed-in user visits can then read their data from this service.",
		Solution: "Compare the Origin header against an allow-list of your own sites instead of echoing it back, and only send Access-Control-Allow-Credentials: true for those origins.",
	},
	"debug-mode-enabled": {
		Title:    "Application runs in debug mode or announces exact versions",
		Source:   "Active check: response headers, the error page for a made-up path, and well-known debug endpoints (Laravel Ignition, Symfony profiler)",
		Risk:     "Interactive debuggers (Werkzeug, Laravel Ignition with commands enabled) let anyone run code on the server. Debug error pages and profilers show configuration, paths, and sometimes passwords. Exact version headers tell an attacker which known vulnerabilities to try.",
		Solution: "Switch debug mode off in production (DEBUG = False, APP_DEBUG=false, the framework's production environment), remove profilers and debug endpoints, and stop sending X-Powered-By and version headers.",
	},
	"second-order-script-takeover": {
		Title:    "Page loads a script from a domain anyone can register",
		Source:   "Active check: the <script src> addresses on the home page, then DNS (and RDAP where enabled) for each outside domain",
		Risk:     "The site runs JavaScript from a domain that has lapsed. Whoever registers it serves their own script to every visitor: stealing sessions and passwords, or changing what the page shows.",
		Solution: "Remove the script tag, or host the script yourself. Re-register the domain if it was yours, and review the site's other third-party scripts (Subresource Integrity helps for fixed files).",
	},
	"insecure-auth-cookie": {
		Title:    "Session cookie without Secure or HttpOnly",
		Source:   "Active check: the Set-Cookie headers on the home page",
		Risk:     "Without HttpOnly, any script injected into the page can read the session cookie and take over the account. Without Secure, the cookie is also sent over plain HTTP, where anyone on the network can read it.",
		Solution: "Set HttpOnly and Secure (and SameSite=Lax or Strict) on session and sign-in cookies, usually a single setting in the framework or web server.",
	},
	"secret-in-page": {
		Title:    "API key or secret in a public web page",
		Source:   "Active check: the home page and the first five of the site's own scripts, matched against secret key formats (the value is not stored)",
		Risk:     "Everything a web page or script contains is public. A live key in it lets anyone use the service it belongs to as you: read data, run up charges, send email or messages in your name, or reach your code and cloud. Automated scanners collect such keys within hours.",
		Solution: "Revoke the key at the service now and issue a new one (removing it from the page is not enough: it has been public). Keep keys on the server side, behind your own API, and check the service's logs for use you do not recognise.",
	},
	"missing-security-headers": {
		Title:    "Baseline security headers are missing",
		Source:   "Active check: the response headers of the home page",
		Risk:     "Without Content-Security-Policy, an injected script runs unhindered. Without X-Frame-Options (or CSP frame-ancestors), other sites can frame the page to trick users into clicking (clickjacking), which matters most on sign-in pages. Without X-Content-Type-Options: nosniff, browsers may run files as a different type than intended.",
		Solution: "Send Content-Security-Policy (start in report-only mode), X-Frame-Options: DENY or CSP frame-ancestors 'none', and X-Content-Type-Options: nosniff, from the web server or framework.",
	},
	"lookalike-tls-issued": {
		Title:    "New certificate issued for a look-alike domain",
		Source:   "Certificate Transparency logs (crt.sh) for the look-alike domains already reported",
		Risk:     "Someone obtained a publicly trusted certificate for a domain that resembles yours and accepts email or has a web address. Phishing sites need HTTPS to look genuine, so a fresh certificate usually means one is being set up.",
		Solution: "Look at the site and the certificate. If it impersonates you, report it to the registrar and hosting provider for takedown, block it in your mail and web filters, and warn staff and customers.",
	},
	"phishing-clone": {
		Title:    "Look-alike site copies yours",
		Source:   "A visit to the look-alike's home page and icon, compared with your own site (optional, off by default)",
		Risk:     "A domain that resembles yours serves your site icon, your page title, or a sign-in form under your name. That is the shape of a phishing site aimed at your staff or customers.",
		Solution: "Collect evidence (screenshots, the crt.sh entry), report the site to the registrar, the hosting provider and services such as Google Safe Browsing, block it in your filters, and warn the people it targets.",
	},
	"dependency-confusion": {
		Title:    "Internal package name could be published by anyone",
		Source:   "Package names revealed by your own web services (source maps, package.json, requirements.txt), checked against npm and PyPI",
		Risk:     "Your code uses a package name that does not exist on the public registry. An attacker who publishes a package with that name can get their code run on build servers and developers' machines that also look in the public registry (dependency confusion).",
		Solution: "Publish a placeholder under that name or reserve your npm scope, configure package managers to fetch internal packages only from your private registry, and stop serving source maps and package files from production sites.",
	},
	"email-auth/dnsbl-listed": {
		Title:    "Mail or web address is on a spam blocklist",
		Source:   "DNS blocklist lookups (SpamCop, PSBL) for the addresses of your mail servers, SPF entries, domain and www",
		Risk:     "Mail from a listed address is rejected or filed as spam by many receivers. A listing usually means the address sent spam, often because the server or an account on it was compromised.",
		Solution: "Find out why it was listed (the list's lookup page explains), fix the cause, such as a compromised account, an open relay or a hacked web form, then request removal from each list.",
	},
	"unauthenticated-datastore": {
		Title:    "Database, cache or control API answers without a password",
		Source:   "Active check: one read-only request to a port exposure data reports open (Redis INFO, Memcached stats, Elasticsearch /, MongoDB listDatabases, Docker /version, kubelet /pods, anonymous FTP sign-in)",
		Risk:     "Anyone on the internet can read, change or delete the data, and a Docker API or kubelet gives full control of the machine. Exposed databases like these are found by automated scanners within hours and are a common cause of breaches and ransom notes.",
		Solution: "Take the service off the internet (firewall or bind it to a private address), and turn on authentication. Then check its data and logs for signs that someone else already got in.",
	},
	"dns-zone-transfer": {
		Title:    "Nameserver allows a full zone transfer (AXFR)",
		Source:   "Active check: a zone-transfer request to the domain's own nameservers",
		Risk:     "Anyone can download every record in the zone: internal host names, test systems and services that are not linked anywhere. It is a ready-made target list.",
		Solution: "Allow zone transfers only to your secondary nameservers (by address or TSIG key) in the nameserver's configuration.",
	},
	"dns-open-resolver": {
		Title:    "DNS server resolves names for anyone",
		Source:   "Active check: one recursive question for example.com to an address with port 53 open",
		Risk:     "Open resolvers are abused to amplify denial-of-service attacks against others, which gets your addresses blocklisted, and they reveal what your network looks up.",
		Solution: "Allow recursion only from your own networks, or stop running a resolver on the public address.",
	},
	"snmp-default-creds": {
		Title:    "Device accepts the default SNMP password",
		Source:   "Active check (separate switch, off by default): one SNMP read of the device description with the community public, then private",
		Risk:     "SNMP with a default community lets anyone read the device's configuration, interfaces and routing, and with private often change them. Network devices exposed like this are a favourite first step for attackers.",
		Solution: "Turn SNMP off on internet-facing interfaces, or use SNMPv3 with authentication and encryption, and change the communities on every device.",
	},
	"ntlm-info-leak": {
		Title:    "NTLM sign-in reveals internal Windows details",
		Source:   "Active check: an NTLM sign-in offer (NEGOTIATE) to the web service, reading the server's challenge",
		Risk:     "The challenge names the internal Active Directory domain, the server's computer name and its Windows build. That helps an attacker aim password spraying and pick exploits, and confirms an internal Windows server is reachable.",
		Solution: "Prefer modern sign-in (Kerberos behind a gateway, or SAML/OIDC) on internet-facing services, and keep Windows servers patched. Where NTLM must stay, accept the risk with a note.",
	},
	"tls-weak-cipher": {
		Title:    "Server agrees to weak TLS cipher suites",
		Source:   "Active check: a TLS handshake offering only weak suites (NULL, export, RC4, DES, 3DES, anonymous)",
		Risk:     "These suites give no or breakable encryption, or no authentication of the server, so traffic can be read or tampered with. Compliance standards (PCI DSS and others) forbid them.",
		Solution: "Allow only AEAD suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy on the server, load balancer or CDN, and remove the legacy ones.",
	},
	"orphaned-load-balancer": {
		Title:    "Cloud load balancer has no healthy backend",
		Source:   "Active check: the web service behind a name pointing at a cloud load balancer or traffic manager",
		Risk:     "A load balancer answering 502/503 serves nothing, which usually means the service behind it was removed but the name and balancer were left. Forgotten resources cost money, and on some platforms the name can be claimed by someone else.",
		Solution: "Restore the backend if the service is still needed; otherwise delete the load balancer and the DNS record that points at it.",
	},
	"exposed-function-url": {
		Title:    "Serverless function or API endpoint answers without authentication",
		Source:   "Active check: the home page of a name that is a Lambda function URL, API Gateway, Cloud Run or Cloud Functions endpoint",
		Risk:     "The function returns data to anyone on the internet without credentials. Function URLs are often created for testing with authentication set to none and then forgotten.",
		Solution: "Require authentication on the endpoint (IAM auth, an authoriser, or Cloud Run's require-authentication setting), or remove it if it is not used.",
	},
	"waf-origin-bypass": {
		Title:    "Site behind a CDN can be reached directly at its origin",
		Source:   "Active check: the site's home page through the CDN, compared with the same request sent straight to the organisation's own addresses",
		Risk:     "An attacker who finds the origin address skips the CDN's web application firewall, rate limits and DDoS protection, and attacks the server directly.",
		Solution: "Let the origin accept traffic only from the CDN (its published address ranges, an authenticated origin pull, or a secret header), and change the origin address if it has been exposed for a long time.",
	},
	"tls-sni-hostname-leak": {
		Title:    "Default certificate reveals internal host names",
		Source:   "Active check: a TLS handshake with the address without a host name (no SNI)",
		Risk:     "The certificate a server shows to anyone who connects by IP address names internal systems or hosts you have not published. That maps your addresses to internal and cloud host names for an attacker, and points at forgotten services.",
		Solution: "Configure the server or load balancer's default certificate to one that names nothing internal (or to refuse connections without SNI), and review the hosts named.",
	},
	"no-security-txt": {
		Title:    "No security.txt on the main site",
		Source:   "Active check: a request for /.well-known/security.txt on the domain and www (HTTPS)",
		Risk:     "Researchers who find a vulnerability have no published way to report it (RFC 9116), so reports get lost or end up public instead.",
		Solution: "Publish /.well-known/security.txt with at least a Contact: line (an email or form) and an Expires: date.",
	},
	"no-https-redirect": {
		Title:    "HTTP does not redirect to HTTPS",
		Source:   "Active check: a request to port 80 compared with port 443",
		Risk:     "Visitors who type the address or follow an old link stay on unencrypted HTTP, where anyone on the network can read or change what they see.",
		Solution: "Redirect all HTTP requests to HTTPS (a 301) and enable HSTS once HTTPS works everywhere.",
	},
	"firebase-public": {
		Title:    "Firebase database can be read by anyone",
		Source:   "Active check: an unauthenticated, read-only request for the top-level keys of a Firebase Realtime Database the site names",
		Risk:     "The database's security rules let anyone on the internet read it, and often write to it. App databases like this hold user records, messages and tokens; open ones are found and copied by automated scanners.",
		Solution: "Change the database's security rules so reads and writes need a signed-in user (\".read\": \"auth != null\" at the least, better per-user rules), then check what was exposed and whether anything was changed.",
	},
	"bucket-public": {
		Title:    "Cloud storage bucket can be listed by anyone",
		Source:   "Active check: an unauthenticated request to the storage provider",
		Risk:     "Anyone can list and probably download the files in the bucket. Data leaks from public buckets are among the most common cloud breaches.",
		Solution: "Turn on the provider's block-public-access setting, review the bucket policy and ACLs, and check what was exposed.",
	},
	"bucket-takeover": {
		Title:    "Name points to a storage bucket that does not exist",
		Source:   "Active check: an unauthenticated request to the storage provider",
		Risk:     "The DNS name still points at a bucket that was deleted. Anyone can create a bucket with that name and serve their own content from your domain.",
		Solution: "Delete the DNS record, or re-create the bucket in your own account so that no one else can claim it.",
	},
	"cloud-datastore": {
		Title:  "Managed database or cache named in public DNS",
		Source: "DNS resolvers (a CNAME points at a managed database, cache or search service)",
		Risk: "A name in public DNS is an alias for a managed database, cache or search cluster (RDS, Azure SQL, MongoDB Atlas, Redis, Elasticsearch and similar). " +
			"The record does not prove the service is reachable, but it tells attackers exactly where it is, and these services are frequently exposed to the internet by mistake.",
		Solution: "Confirm the service accepts connections only from your private network (security group, firewall rule or private endpoint) and requires authentication. " +
			"Prefer internal DNS names for databases; remove the public record if it is not needed.",
	},
	"dangling-cname": {
		Title:  "Dangling CNAME (possible subdomain takeover)",
		Source: "DNS resolvers (the name has a CNAME record whose target returns NXDOMAIN)",
		Risk: "The name is an alias (CNAME) for a target that no longer exists. It becomes exploitable only if someone else can claim " +
			"that target: an unused name on a shared platform (GitHub Pages, Azure, S3, Heroku and similar), or a lapsed domain anyone can " +
			"register. They could then serve content from your domain (phishing, malware, cookie theft). If the target cannot be claimed it is " +
			"just a broken record: harmless to attackers but worth cleaning up. Severity is High only when the target is on a known claim-able platform.",
		Solution: "Delete the DNS record if the service is retired. If it is still needed, re-create the resource at the provider " +
			"so you own the target again. Review other records that point at the same provider.",
	},
	"asn-unexpected": {
		Title:  "Address outside expected ownership",
		Source: "DNS resolvers + ASN mapping (Team Cymru DNS WHOIS, RIPEstat fallback)",
		Risk: "The hostname resolves to a network that is not on this entity's list of expected ASNs or organisation keywords. " +
			"That can be shadow IT, a forgotten vendor, a hijacked or poisoned DNS record, or an asset that was never meant to be public.",
		Solution: "Confirm who owns the address. If it is legitimate, add its ASN or organisation keyword to the entity so it stops alerting. " +
			"If not, correct or remove the DNS record and investigate how it was created.",
	},
	"private-ip": {
		Title:  "Private address in public DNS",
		Source: "DNS resolvers (A/AAAA record in a non-public range)",
		Risk: "Internal addressing published in public DNS reveals network layout and can help attackers target internal systems " +
			"(for example through DNS rebinding or SSRF).",
		Solution: "Remove the record from public DNS, or serve it only from an internal (split-horizon) zone.",
	},
	"email-auth/spf-multiple": {
		Title:    "More than one SPF record",
		Source:   "DNS resolvers (several TXT records starting v=spf1)",
		Risk:     "The SPF standard allows exactly one record. With two, receivers report an error and SPF fails for all mail from the name, including your own legitimate mail.",
		Solution: "Merge the records into one (combine the include: parts) and delete the others.",
	},
	"email-auth/spf-ptr": {
		Title:    "SPF uses the ptr mechanism",
		Source:   "DNS resolvers (SPF record contains ptr)",
		Risk:     "The ptr mechanism is slow, puts load on other people's DNS and is discouraged by the SPF standard. Some receivers ignore it.",
		Solution: "Replace ptr with explicit ip4:, ip6: or include: entries for your senders.",
	},
	"email-auth/spf-too-many-lookups": {
		Title:    "SPF needs more than 10 DNS lookups",
		Source:   "DNS resolvers (the SPF record and everything it includes, counted)",
		Risk:     "SPF allows at most 10 DNS lookups. Over that, receivers give a permanent error and treat SPF as failed, so even your own mail may be rejected or marked as spam. The usual cause is stacking many include: services.",
		Solution: "Remove services you no longer use, replace includes with ip4:/ip6: ranges where the provider's addresses are stable, or use an SPF flattening service. Re-check after each change.",
	},
	"email-auth/dmarc-sp-none": {
		Title:    "DMARC leaves subdomains unprotected",
		Source:   "DNS resolvers (DMARC record has sp=none)",
		Risk:     "The policy protects the main domain but sp=none switches it off for every subdomain, so attackers can send convincing mail from names like billing.yourdomain.",
		Solution: "Remove sp=none (subdomains then follow p=), or set sp=reject once legitimate subdomain senders are authorised.",
	},
	"email-auth/dmarc-pct": {
		Title:    "DMARC applies to only part of the mail",
		Source:   "DNS resolvers (DMARC record has pct below 100)",
		Risk:     "Only the stated percentage of failing mail is subject to the policy; the rest is delivered normally, so spoofing still gets through.",
		Solution: "Raise pct to 100 (or remove it) once the reports show legitimate mail passes.",
	},
	"email-auth/dmarc-no-reports": {
		Title:    "DMARC sends you no reports",
		Source:   "DNS resolvers (DMARC record has no rua=)",
		Risk:     "Without reports you cannot see who is sending mail as your domain, or whether your own services fail authentication, so tightening the policy is guesswork.",
		Solution: "Add rua=mailto:<address> to the DMARC record, ideally to a DMARC reporting service that summarises the data.",
	},
	"email-auth/dkim-not-found": {
		Title:    "No DKIM key found at common selector names",
		Source:   "DNS resolvers (the common DKIM selector names, such as google, selector1, k1, s1)",
		Risk:     "DKIM signs outgoing mail so receivers can trust it, and DMARC relies on it. DKIM selectors cannot be listed, so this check only tries common names: it may simply have missed a custom one.",
		Solution: "Confirm in your mail provider's settings that DKIM signing is on and which selector it uses. If it is on, accept the risk with a note; if not, turn it on and publish the key it gives you.",
	},
	"email-auth/dkim-weak-key": {
		Title:    "DKIM key is too short",
		Source:   "DNS resolvers (the DKIM public key)",
		Risk:     "Keys under 1024 bits can be broken with modest computing power, letting an attacker sign mail as your domain.",
		Solution: "Generate a 2048-bit key with your mail provider, publish it under a new selector, then retire the old one.",
	},
	"email-auth/dkim-short-key": {
		Title:    "DKIM key is 1024 bits",
		Source:   "DNS resolvers (the DKIM public key)",
		Risk:     "1024-bit keys are still accepted but are no longer considered comfortable; 2048 bits is the recommended size.",
		Solution: "Rotate to a 2048-bit key at your next convenient maintenance window.",
	},
	"email-auth/mta-sts-broken": {
		Title:    "MTA-STS policy is published but unusable",
		Source:   "Active check: the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt, fetched the way a sending mail server does (valid certificate required)",
		Risk:     "The TXT record says a policy exists, but senders cannot get a valid one, so they treat the domain as having none. Mail to you loses the protection MTA-STS was meant to give, and you may believe it is on.",
		Solution: "Make https://mta-sts.<domain>/.well-known/mta-sts.txt answer 200 over HTTPS with a certificate valid for that name, containing version: STSv1, mode, mx: lines for your mail servers and max_age. Change the id= in the TXT record whenever the file changes.",
	},
	"email-auth/no-mta-sts": {
		Title:    "No MTA-STS policy",
		Source:   "DNS resolvers (TXT at _mta-sts.<domain>)",
		Risk:     "Mail between servers is encrypted only if both sides agree, and an attacker on the network path can strip that. MTA-STS tells senders to require TLS when delivering to you.",
		Solution: "Publish a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt and a TXT record at _mta-sts.<domain>; start in testing mode, then switch to enforce.",
	},
	"email-auth/no-tls-rpt": {
		Title:    "No TLS reporting address",
		Source:   "DNS resolvers (TXT at _smtp._tls.<domain>)",
		Risk:     "Without TLS-RPT you get no reports when other mail servers fail to deliver to you securely, so downgrade attacks and certificate problems go unnoticed.",
		Solution: "Publish a TXT record at _smtp._tls.<domain> such as \"v=TLSRPTv1; rua=mailto:tls-reports@<domain>\".",
	},
	"email-auth/no-caa": {
		Title:    "No CAA record",
		Source:   "DNS resolvers (CAA records at the domain)",
		Risk:     "Without CAA, any certificate authority may issue a certificate for your domain, which widens the chance of a mistaken or fraudulent certificate.",
		Solution: "Publish CAA records naming only the authorities you use, for example: 0 issue \"letsencrypt.org\".",
	},
	"email-auth/no-dnssec": {
		Title:    "DNSSEC is not enabled",
		Source:   "DNS resolvers (no DS record at the parent zone)",
		Risk:     "Without DNSSEC, resolvers cannot detect forged DNS answers for your domain. It protects mainly against DNS spoofing and cache poisoning.",
		Solution: "Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar. Skip this if your provider does not support it, and accept the risk.",
	},
	"email-auth/no-spf": {
		Title:    "No SPF record",
		Source:   "DNS resolvers (TXT at the domain apex)",
		Risk:     "Without SPF, receivers cannot tell which servers may send mail for the domain, so spoofed mail is more likely to be delivered.",
		Solution: "Publish a TXT record such as \"v=spf1 include:<your mail provider> -all\" listing only the services that send your mail.",
	},
	"email-auth/spf-permissive": {
		Title:    "SPF allows any sender",
		Source:   "DNS resolvers (SPF TXT record ends in +all or all)",
		Risk:     "The SPF record authorises every server on the internet to send as this domain, which defeats the control entirely.",
		Solution: "End the record with -all (or ~all while testing) after listing your legitimate senders.",
	},
	"email-auth/spf-neutral": {
		Title:    "SPF is neutral (?all)",
		Source:   "DNS resolvers (SPF TXT record ends in ?all)",
		Risk:     "A neutral policy tells receivers not to judge unlisted senders, so spoofed mail is not penalised.",
		Solution: "Change ?all to -all (reject) or ~all (soft fail) once your sender list is complete.",
	},
	"email-auth/no-dmarc": {
		Title:    "No DMARC record",
		Source:   "DNS resolvers (TXT at _dmarc.<domain>)",
		Risk:     "Without DMARC there is no policy for mail that fails SPF/DKIM and no reporting, which makes phishing from your domain easier and harder to notice.",
		Solution: "Publish _dmarc TXT \"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\", review the reports, then move to p=quarantine and p=reject.",
	},
	"email-auth/dmarc-p-none": {
		Title:    "DMARC policy is monitor-only",
		Source:   "DNS resolvers (DMARC record has p=none)",
		Risk:     "Spoofed mail that fails authentication is still delivered; the record only collects reports.",
		Solution: "After confirming legitimate mail passes, raise the policy to p=quarantine and then p=reject.",
	},
	"exposed-service": {
		Title:  "Sensitive service reachable from the internet",
		Source: "Exposure intelligence (Shodan InternetDB / Shodan / Censys scan data)",
		Risk: "Remote-administration, file-sharing and database ports are frequent targets for brute force, ransomware and exploitation " +
			"of unpatched flaws. Scan data may be days old, so confirm the port is still open.",
		Solution: "Close the port on the firewall or security group, or restrict it to a VPN or allow-listed addresses. " +
			"Where remote access is required, use a VPN or zero-trust gateway with MFA.",
	},
	"known-vuln": {
		Title:  "Host associated with known vulnerabilities (CVEs)",
		Source: "Exposure intelligence (CVE list from Shodan InternetDB / Shodan), ranked by CISA KEV and FIRST EPSS",
		Risk: "The service banners on this address match software versions with published vulnerabilities. Matches are inferred from banners, " +
			"so some may not apply (for example if fixes were back-ported), but each is worth verifying.",
		Solution: "Check each CVE against the software actually running, apply vendor patches or upgrade, and re-scan. " +
			"If the service does not need to be public, remove it from the internet.",
	},
	"ip-flagged": {
		Title:  "Address flagged as compromised or malicious",
		Source: "Exposure intelligence (tags on Shodan InternetDB / Shodan) and SANS Internet Storm Center: attack reports from many sensors, or a compromised-host feed listing, in the last 30 days",
		Risk: "Shodan tags this IP as compromised, running malware or carrying a known backdoor, or SANS ISC has recently seen it attacking " +
			"other systems. It may be hosting attacker tooling or be part of a botnet. SANS ISC alone shows attacking traffic, not how it started, so it is rated Medium.",
		Solution: "Check what this address sends out and whether it is still yours (cloud addresses change hands). Treat the host as potentially compromised: isolate it, investigate, and rebuild from a known-good image if confirmed.",
	},
	"eol-software": {
		Title:    "End-of-life operating system or software",
		Source:   "Exposure intelligence (eol tags on Shodan InternetDB / Shodan)",
		Risk:     "Software that no longer receives security updates accumulates unpatched vulnerabilities that attackers can rely on. The evidence column lists the OS, software versions and services detected on the host so you can see what is out of support.",
		Solution: "Upgrade or replace the affected component, or isolate it behind a firewall until it can be retired.",
	},
	"domain-expiry": {
		Title:  "Domain registration expiring",
		Source: "RDAP (registry registration data)",
		Risk: "If the registration lapses, the domain and everything on it (website, email, certificates) goes offline, and an attacker " +
			"could re-register it and receive your mail.",
		Solution: "Renew the domain now and enable auto-renew with a current payment method. Make sure renewal notices go to a monitored mailbox.",
	},
}

// describeFinding returns the explanation for a stored finding. Email-auth findings
// encode their specific check in the key ("email:<root>:<code>").
func describeFinding(f Finding) FindingInfo {
	info, ok := findingCatalog[ruleKind(f.Kind, f.Key)]
	if !ok {
		info = FindingInfo{Title: f.Kind, Source: "EASM agent", Risk: "See the detail column.", Solution: "Investigate the detail and correct the underlying configuration."}
	}
	if f.Source != "" {
		info.Source = f.Source
	}
	return info
}

// ruleKind is the catalogue entry for a finding's kind and key: email-auth findings name
// their check in the last part of the key.
func ruleKind(kind, key string) string {
	if kind == "email-auth" {
		if i := strings.LastIndex(key, ":"); i >= 0 {
			return "email-auth/" + key[i+1:]
		}
	}
	return kind
}

// sourceLabel is the display name of an intelligence source id.
func sourceLabel(id string) string {
	switch id {
	case "internetdb":
		return "Shodan InternetDB"
	case "shodan":
		return "Shodan"
	case "censys":
		return "Censys"
	case "virustotal":
		return "VirusTotal"
	case "rdap":
		return "RDAP"
	case "isc":
		return "SANS ISC"
	}
	return id
}
