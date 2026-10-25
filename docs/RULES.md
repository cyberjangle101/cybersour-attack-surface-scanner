# EASM Agent detection rules

This is every check the EASM Agent runs against a monitored domain: the finding it raises, its rule ID, how the evidence is collected, how severe it is and exactly what triggers it, followed by the detection tables (paths, products, ports, platforms and signatures) the rules use.

> Generated from the source code (`rules.go`, `catalog.go` and the detection tables) by `rules_doc_test.go`. Do not edit by hand: after changing a rule, run `EASM_UPDATE_RULES=1 go test -run TestRulesReference .`. The test fails when this file and the code disagree.

## How findings are produced

* **Passive checks** read public DNS, registration data (RDAP) and public sources. They send nothing to the organisation's own servers.
* **Active checks** connect to the organisation's own web servers and are off unless switched on (Settings → Active checks, or the first-scan option when a domain is added). They use read-only `GET` requests and TLS handshakes, follow no redirects, connect only to public routable addresses, and by default only to addresses inside the domain's expected ownership. Exposed-file and login-portal path checks need the separate *exposed files* option.
* **Third-party intelligence** (Shodan InternetDB, Shodan, Censys) is often stale. Its findings are *Unconfirmed* until a second, independent source agrees: Censys, the agent's own active check, or an analyst. InternetDB and the Shodan API count as one source. Unconfirmed findings are listed but not alerted, counted or reported.
* **Resolution.** A finding resolves automatically only when a later scan actually re-checked the thing it is about and found it fixed; an outage or unreachable server never closes a finding.
* **Severity** is High, Medium, Low or Info; analysts can override it per finding with a reason.

## Rule summary

| ID | Rule | Finding type | Collection | Severity |
|---|---|---|---|---|
| EASM-BRAND-001 | A look-alike of your domain is registered | `lookalike-domain` | Passive: public sources (OSINT) | Medium when it accepts email (MX), otherwise Low |
| EASM-BRAND-002 | Accounts at your domain appear in a data breach | `leaked-credentials` | Passive: public sources (OSINT) | High for 5 or more accounts in one breach, otherwise Medium |
| EASM-BRAND-003 | Public code mentions your domain next to secret-like words | `repo-exposure` | Passive: public sources (OSINT) | Medium |
| EASM-CLOUD-001 | Cloud storage bucket can be listed by anyone | `bucket-public` | Active: connects to the organisation's own servers (opt-in) | High |
| EASM-CLOUD-002 | Name points to a storage bucket that does not exist | `bucket-takeover` | Active: connects to the organisation's own servers (opt-in) | High |
| EASM-CLOUD-003 | Managed database or cache named in public DNS | `cloud-datastore` | Passive: DNS | Medium |
| EASM-DNS-001 | Dangling CNAME (possible subdomain takeover) | `dangling-cname` | Passive: DNS | High on a claim-able platform (see takeover platforms), otherwise Low |
| EASM-DNS-002 | Private address in public DNS | `private-ip` | Passive: DNS | Low |
| EASM-DNS-003 | Address outside expected ownership | `asn-unexpected` | Passive: DNS | High |
| EASM-DNS-004 | No CAA record | `email-auth/no-caa` | Passive: DNS | Low |
| EASM-DNS-005 | DNSSEC is not enabled | `email-auth/no-dnssec` | Passive: DNS | Low |
| EASM-DNS-006 | Domain registration expiring | `domain-expiry` | Passive: registration data (RDAP) | High within 14 days (or expired), Medium within 30, Low within 60 |
| EASM-EXP-001 | Sensitive service reachable from the internet | `exposed-service` | Third-party intelligence (needs a second source to be trusted) | High for the high-risk ports, Medium for the other risky ports (see risky ports) |
| EASM-EXP-002 | Host associated with known vulnerabilities (CVEs) | `known-vuln` | Third-party intelligence (needs a second source to be trusted) | High with 10 or more CVEs, otherwise Medium |
| EASM-EXP-003 | Address flagged as compromised or malicious | `ip-flagged` | Third-party intelligence (needs a second source to be trusted) | High |
| EASM-EXP-004 | End-of-life operating system or software | `eol-software` | Third-party intelligence (needs a second source to be trusted) | Medium |
| EASM-MAIL-001 | No SPF record | `email-auth/no-spf` | Passive: DNS | Medium |
| EASM-MAIL-002 | More than one SPF record | `email-auth/spf-multiple` | Passive: DNS | High |
| EASM-MAIL-003 | SPF allows any sender | `email-auth/spf-permissive` | Passive: DNS | High |
| EASM-MAIL-004 | SPF is neutral (?all) | `email-auth/spf-neutral` | Passive: DNS | Medium |
| EASM-MAIL-005 | SPF uses the ptr mechanism | `email-auth/spf-ptr` | Passive: DNS | Low |
| EASM-MAIL-006 | SPF needs more than 10 DNS lookups | `email-auth/spf-too-many-lookups` | Passive: DNS | Medium |
| EASM-MAIL-007 | No DMARC record | `email-auth/no-dmarc` | Passive: DNS | Medium |
| EASM-MAIL-008 | DMARC policy is monitor-only | `email-auth/dmarc-p-none` | Passive: DNS | Low |
| EASM-MAIL-009 | DMARC leaves subdomains unprotected | `email-auth/dmarc-sp-none` | Passive: DNS | Medium |
| EASM-MAIL-010 | DMARC applies to only part of the mail | `email-auth/dmarc-pct` | Passive: DNS | Low |
| EASM-MAIL-011 | DMARC sends you no reports | `email-auth/dmarc-no-reports` | Passive: DNS | Low |
| EASM-MAIL-012 | No DKIM key found at common selector names | `email-auth/dkim-not-found` | Passive: DNS | Low |
| EASM-MAIL-013 | DKIM key is too short | `email-auth/dkim-weak-key` | Passive: DNS | Medium |
| EASM-MAIL-014 | DKIM key is 1024 bits | `email-auth/dkim-short-key` | Passive: DNS | Low |
| EASM-MAIL-015 | No MTA-STS policy | `email-auth/no-mta-sts` | Passive: DNS | Low |
| EASM-MAIL-016 | No TLS reporting address | `email-auth/no-tls-rpt` | Passive: DNS | Low |
| EASM-TLS-001 | TLS certificate has expired | `tls-expired` | Active: connects to the organisation's own servers (opt-in) | High |
| EASM-TLS-002 | TLS certificate expires soon | `tls-expiring` | Active: connects to the organisation's own servers (opt-in) | High within 7 days, Medium within 30 |
| EASM-TLS-003 | TLS certificate does not match the host name | `tls-hostname` | Active: connects to the organisation's own servers (opt-in) | Medium |
| EASM-TLS-004 | TLS certificate is not trusted | `tls-untrusted` | Active: connects to the organisation's own servers (opt-in) | Medium |
| EASM-TLS-005 | Server still accepts TLS 1.0 / 1.1 | `tls-legacy` | Active: connects to the organisation's own servers (opt-in) | Medium |
| EASM-TLS-006 | TLS certificate uses a weak key | `tls-weak-key` | Active: connects to the organisation's own servers (opt-in) | Medium |
| EASM-TLS-007 | TLS certificate is signed with SHA-1 or MD5 | `tls-weak-signature` | Active: connects to the organisation's own servers (opt-in) | Medium |
| EASM-TLS-008 | HTTPS site does not send HSTS | `hsts-missing` | Active: connects to the organisation's own servers (opt-in) | Low |
| EASM-TLS-009 | HTTP does not redirect to HTTPS | `no-https-redirect` | Active: connects to the organisation's own servers (opt-in) | Low |
| EASM-WEB-001 | Login portal or admin console is public | `login-portal` | Active: connects to the organisation's own servers (opt-in) | Per product (see login portals): High for infrastructure consoles, Medium for remote-access gateways, webmail/SSO and monitoring or collaboration tools, Low for website sign-ins |
| EASM-WEB-002 | Sensitive file or page is publicly readable | `exposed-path` | Active: connects to the organisation's own servers (opt-in) | Per file: High, Medium or Low (see sensitive files) |
| EASM-WEB-003 | Default web server page is public | `default-page` | Active: connects to the organisation's own servers (opt-in) | Low |
| EASM-WEB-004 | No security.txt on the main site | `no-security-txt` | Active: connects to the organisation's own servers (opt-in) | Low |

45 rules.

## DNS and domain

### EASM-DNS-001: Dangling CNAME (possible subdomain takeover)

* **Finding type:** `dangling-cname`
* **Collection:** Passive: DNS
* **Triggered when:** A CNAME record whose target does not exist (NXDOMAIN).
* **Severity:** High on a claim-able platform (see takeover platforms), otherwise Low
* **Evidence:** DNS resolvers (the name has a CNAME record whose target returns NXDOMAIN)
* **Why it matters:** The name is an alias (CNAME) for a target that no longer exists. It becomes exploitable only if someone else can claim that target: an unused name on a shared platform (GitHub Pages, Azure, S3, Heroku and similar), or a lapsed domain anyone can register. They could then serve content from your domain (phishing, malware, cookie theft). If the target cannot be claimed it is just a broken record: harmless to attackers but worth cleaning up. Severity is High only when the target is on a known claim-able platform.
* **What to do:** Delete the DNS record if the service is retired. If it is still needed, re-create the resource at the provider so you own the target again. Review other records that point at the same provider.

### EASM-DNS-002: Private address in public DNS

* **Finding type:** `private-ip`
* **Collection:** Passive: DNS
* **Triggered when:** An A/AAAA record in public DNS points at a private, loopback or other non-public address.
* **Severity:** Low
* **Evidence:** DNS resolvers (A/AAAA record in a non-public range)
* **Why it matters:** Internal addressing published in public DNS reveals network layout and can help attackers target internal systems (for example through DNS rebinding or SSRF).
* **What to do:** Remove the record from public DNS, or serve it only from an internal (split-horizon) zone.

### EASM-DNS-003: Address outside expected ownership

* **Finding type:** `asn-unexpected`
* **Collection:** Passive: DNS
* **Triggered when:** An address the domain's names resolve to is announced by a network (ASN) or organisation outside the expected ownership configured for the domain.
* **Severity:** High
* **Evidence:** DNS resolvers + ASN mapping (Team Cymru DNS WHOIS, RIPEstat fallback)
* **Why it matters:** The hostname resolves to a network that is not on this entity's list of expected ASNs or organisation keywords. That can be shadow IT, a forgotten vendor, a hijacked or poisoned DNS record, or an asset that was never meant to be public.
* **What to do:** Confirm who owns the address. If it is legitimate, add its ASN or organisation keyword to the entity so it stops alerting. If not, correct or remove the DNS record and investigate how it was created.

### EASM-DNS-004: No CAA record

* **Finding type:** `email-auth/no-caa`
* **Collection:** Passive: DNS
* **Triggered when:** No CAA record at the domain.
* **Severity:** Low
* **Evidence:** DNS resolvers (CAA records at the domain)
* **Why it matters:** Without CAA, any certificate authority may issue a certificate for your domain, which widens the chance of a mistaken or fraudulent certificate.
* **What to do:** Publish CAA records naming only the authorities you use, for example: 0 issue "letsencrypt.org".

### EASM-DNS-005: DNSSEC is not enabled

* **Finding type:** `email-auth/no-dnssec`
* **Collection:** Passive: DNS
* **Triggered when:** No DS record for the domain at its parent zone.
* **Severity:** Low
* **Evidence:** DNS resolvers (no DS record at the parent zone)
* **Why it matters:** Without DNSSEC, resolvers cannot detect forged DNS answers for your domain. It protects mainly against DNS spoofing and cache poisoning.
* **What to do:** Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar. Skip this if your provider does not support it, and accept the risk.

### EASM-DNS-006: Domain registration expiring

* **Finding type:** `domain-expiry`
* **Collection:** Passive: registration data (RDAP)
* **Triggered when:** The registration expiry date in RDAP is close.
* **Severity:** High within 14 days (or expired), Medium within 30, Low within 60
* **Evidence:** RDAP (registry registration data)
* **Why it matters:** If the registration lapses, the domain and everything on it (website, email, certificates) goes offline, and an attacker could re-register it and receive your mail.
* **What to do:** Renew the domain now and enable auto-renew with a current payment method. Make sure renewal notices go to a monitored mailbox.

## Email authentication

### EASM-MAIL-001: No SPF record

* **Finding type:** `email-auth/no-spf`
* **Collection:** Passive: DNS
* **Triggered when:** No TXT record starting v=spf1 at the domain apex.
* **Severity:** Medium
* **Evidence:** DNS resolvers (TXT at the domain apex)
* **Why it matters:** Without SPF, receivers cannot tell which servers may send mail for the domain, so spoofed mail is more likely to be delivered.
* **What to do:** Publish a TXT record such as "v=spf1 include:<your mail provider> -all" listing only the services that send your mail.

### EASM-MAIL-002: More than one SPF record

* **Finding type:** `email-auth/spf-multiple`
* **Collection:** Passive: DNS
* **Triggered when:** More than one SPF record at the apex.
* **Severity:** High
* **Evidence:** DNS resolvers (several TXT records starting v=spf1)
* **Why it matters:** The SPF standard allows exactly one record. With two, receivers report an error and SPF fails for all mail from the name, including your own legitimate mail.
* **What to do:** Merge the records into one (combine the include: parts) and delete the others.

### EASM-MAIL-003: SPF allows any sender

* **Finding type:** `email-auth/spf-permissive`
* **Collection:** Passive: DNS
* **Triggered when:** The SPF record ends in +all or all.
* **Severity:** High
* **Evidence:** DNS resolvers (SPF TXT record ends in +all or all)
* **Why it matters:** The SPF record authorises every server on the internet to send as this domain, which defeats the control entirely.
* **What to do:** End the record with -all (or ~all while testing) after listing your legitimate senders.

### EASM-MAIL-004: SPF is neutral (?all)

* **Finding type:** `email-auth/spf-neutral`
* **Collection:** Passive: DNS
* **Triggered when:** The SPF record ends in ?all.
* **Severity:** Medium
* **Evidence:** DNS resolvers (SPF TXT record ends in ?all)
* **Why it matters:** A neutral policy tells receivers not to judge unlisted senders, so spoofed mail is not penalised.
* **What to do:** Change ?all to -all (reject) or ~all (soft fail) once your sender list is complete.

### EASM-MAIL-005: SPF uses the ptr mechanism

* **Finding type:** `email-auth/spf-ptr`
* **Collection:** Passive: DNS
* **Triggered when:** The SPF record uses the ptr mechanism.
* **Severity:** Low
* **Evidence:** DNS resolvers (SPF record contains ptr)
* **Why it matters:** The ptr mechanism is slow, puts load on other people's DNS and is discouraged by the SPF standard. Some receivers ignore it.
* **What to do:** Replace ptr with explicit ip4:, ip6: or include: entries for your senders.

### EASM-MAIL-006: SPF needs more than 10 DNS lookups

* **Finding type:** `email-auth/spf-too-many-lookups`
* **Collection:** Passive: DNS
* **Triggered when:** Evaluating SPF, including every include:, needs more than 10 DNS lookups.
* **Severity:** Medium
* **Evidence:** DNS resolvers (the SPF record and everything it includes, counted)
* **Why it matters:** SPF allows at most 10 DNS lookups. Over that, receivers give a permanent error and treat SPF as failed, so even your own mail may be rejected or marked as spam. The usual cause is stacking many include: services.
* **What to do:** Remove services you no longer use, replace includes with ip4:/ip6: ranges where the provider's addresses are stable, or use an SPF flattening service. Re-check after each change.

### EASM-MAIL-007: No DMARC record

* **Finding type:** `email-auth/no-dmarc`
* **Collection:** Passive: DNS
* **Triggered when:** No TXT record starting v=DMARC1 at _dmarc.<domain>.
* **Severity:** Medium
* **Evidence:** DNS resolvers (TXT at _dmarc.<domain>)
* **Why it matters:** Without DMARC there is no policy for mail that fails SPF/DKIM and no reporting, which makes phishing from your domain easier and harder to notice.
* **What to do:** Publish _dmarc TXT "v=DMARC1; p=none; rua=mailto:dmarc@<domain>", review the reports, then move to p=quarantine and p=reject.

### EASM-MAIL-008: DMARC policy is monitor-only

* **Finding type:** `email-auth/dmarc-p-none`
* **Collection:** Passive: DNS
* **Triggered when:** The DMARC policy is p=none.
* **Severity:** Low
* **Evidence:** DNS resolvers (DMARC record has p=none)
* **Why it matters:** Spoofed mail that fails authentication is still delivered; the record only collects reports.
* **What to do:** After confirming legitimate mail passes, raise the policy to p=quarantine and then p=reject.

### EASM-MAIL-009: DMARC leaves subdomains unprotected

* **Finding type:** `email-auth/dmarc-sp-none`
* **Collection:** Passive: DNS
* **Triggered when:** The DMARC record sets sp=none for subdomains.
* **Severity:** Medium
* **Evidence:** DNS resolvers (DMARC record has sp=none)
* **Why it matters:** The policy protects the main domain but sp=none switches it off for every subdomain, so attackers can send convincing mail from names like billing.yourdomain.
* **What to do:** Remove sp=none (subdomains then follow p=), or set sp=reject once legitimate subdomain senders are authorised.

### EASM-MAIL-010: DMARC applies to only part of the mail

* **Finding type:** `email-auth/dmarc-pct`
* **Collection:** Passive: DNS
* **Triggered when:** The DMARC record has pct below 100.
* **Severity:** Low
* **Evidence:** DNS resolvers (DMARC record has pct below 100)
* **Why it matters:** Only the stated percentage of failing mail is subject to the policy; the rest is delivered normally, so spoofing still gets through.
* **What to do:** Raise pct to 100 (or remove it) once the reports show legitimate mail passes.

### EASM-MAIL-011: DMARC sends you no reports

* **Finding type:** `email-auth/dmarc-no-reports`
* **Collection:** Passive: DNS
* **Triggered when:** The DMARC record has no rua= reporting address.
* **Severity:** Low
* **Evidence:** DNS resolvers (DMARC record has no rua=)
* **Why it matters:** Without reports you cannot see who is sending mail as your domain, or whether your own services fail authentication, so tightening the policy is guesswork.
* **What to do:** Add rua=mailto:<address> to the DMARC record, ideally to a DMARC reporting service that summarises the data.

### EASM-MAIL-012: No DKIM key found at common selector names

* **Finding type:** `email-auth/dkim-not-found`
* **Collection:** Passive: DNS
* **Triggered when:** No DKIM key at any of the common selector names (see DKIM selectors).
* **Severity:** Low
* **Evidence:** DNS resolvers (the common DKIM selector names, such as google, selector1, k1, s1)
* **Why it matters:** DKIM signs outgoing mail so receivers can trust it, and DMARC relies on it. DKIM selectors cannot be listed, so this check only tries common names: it may simply have missed a custom one.
* **What to do:** Confirm in your mail provider's settings that DKIM signing is on and which selector it uses. If it is on, accept the risk with a note; if not, turn it on and publish the key it gives you.

### EASM-MAIL-013: DKIM key is too short

* **Finding type:** `email-auth/dkim-weak-key`
* **Collection:** Passive: DNS
* **Triggered when:** A DKIM key is shorter than 1024 bits.
* **Severity:** Medium
* **Evidence:** DNS resolvers (the DKIM public key)
* **Why it matters:** Keys under 1024 bits can be broken with modest computing power, letting an attacker sign mail as your domain.
* **What to do:** Generate a 2048-bit key with your mail provider, publish it under a new selector, then retire the old one.

### EASM-MAIL-014: DKIM key is 1024 bits

* **Finding type:** `email-auth/dkim-short-key`
* **Collection:** Passive: DNS
* **Triggered when:** A DKIM key is exactly 1024 bits.
* **Severity:** Low
* **Evidence:** DNS resolvers (the DKIM public key)
* **Why it matters:** 1024-bit keys are still accepted but are no longer considered comfortable; 2048 bits is the recommended size.
* **What to do:** Rotate to a 2048-bit key at your next convenient maintenance window.

### EASM-MAIL-015: No MTA-STS policy

* **Finding type:** `email-auth/no-mta-sts`
* **Collection:** Passive: DNS
* **Triggered when:** No TXT record at _mta-sts.<domain>.
* **Severity:** Low
* **Evidence:** DNS resolvers (TXT at _mta-sts.<domain>)
* **Why it matters:** Mail between servers is encrypted only if both sides agree, and an attacker on the network path can strip that. MTA-STS tells senders to require TLS when delivering to you.
* **What to do:** Publish a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt and a TXT record at _mta-sts.<domain>; start in testing mode, then switch to enforce.

### EASM-MAIL-016: No TLS reporting address

* **Finding type:** `email-auth/no-tls-rpt`
* **Collection:** Passive: DNS
* **Triggered when:** No TXT record at _smtp._tls.<domain>.
* **Severity:** Low
* **Evidence:** DNS resolvers (TXT at _smtp._tls.<domain>)
* **Why it matters:** Without TLS-RPT you get no reports when other mail servers fail to deliver to you securely, so downgrade attacks and certificate problems go unnoticed.
* **What to do:** Publish a TXT record at _smtp._tls.<domain> such as "v=TLSRPTv1; rua=mailto:tls-reports@<domain>".

## TLS and HTTPS

### EASM-TLS-001: TLS certificate has expired

* **Finding type:** `tls-expired`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate presented on an HTTPS port has expired.
* **Severity:** High
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** Browsers show a full-page warning and many clients refuse to connect, so the service is effectively down for ordinary users, and people learn to click through warnings.
* **What to do:** Renew the certificate now and install it on every server that answers for this name. Set up automatic renewal (for example ACME) and an expiry reminder.

### EASM-TLS-002: TLS certificate expires soon

* **Finding type:** `tls-expiring`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate expires within 30 days.
* **Severity:** High within 7 days, Medium within 30
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** When the certificate expires, browsers will block the site. Expiry is the most common cause of avoidable outages.
* **What to do:** Renew and install the certificate before the date shown. Automate renewal so this stops being a manual task.

### EASM-TLS-003: TLS certificate does not match the host name

* **Finding type:** `tls-hostname`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate does not cover the host name it was served for.
* **Severity:** Medium
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** The certificate presented was issued for other names, so browsers warn visitors. It often means a server is serving the wrong site or a certificate was never installed for this name.
* **What to do:** Install a certificate that lists this exact name (or a matching wildcard), or point the DNS name at the right server.

### EASM-TLS-004: TLS certificate is not trusted

* **Finding type:** `tls-untrusted`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate is self-signed, from an untrusted authority, has an incomplete chain, or is not yet valid.
* **Severity:** Medium
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** Self-signed certificates and certificates from unknown authorities cause browser warnings and cannot protect users from impersonation.
* **What to do:** Replace it with a certificate from a public authority, and make sure the server sends the full chain including intermediates.

### EASM-TLS-005: Server still accepts TLS 1.0 / 1.1

* **Finding type:** `tls-legacy`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** A handshake offering only TLS 1.0 or only TLS 1.1 succeeds.
* **Severity:** Medium
* **Evidence:** Active check: a TLS handshake with the server offering old protocol versions
* **Why it matters:** TLS 1.0 and 1.1 are deprecated and have known weaknesses; compliance standards such as PCI DSS forbid them.
* **What to do:** Disable TLS 1.0 and 1.1 and allow only TLS 1.2 and 1.3 on the server, load balancer or CDN setting.

### EASM-TLS-006: TLS certificate uses a weak key

* **Finding type:** `tls-weak-key`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate key is RSA under 2048 bits or ECDSA under 256 bits.
* **Severity:** Medium
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** RSA keys under 2048 bits (or small elliptic-curve keys) are below what browsers and standards require and are within reach of well-funded attackers.
* **What to do:** Issue a new certificate with a 2048-bit (or larger) RSA key or a P-256 ECDSA key, and revoke the old one.

### EASM-TLS-007: TLS certificate is signed with SHA-1 or MD5

* **Finding type:** `tls-weak-signature`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The certificate is signed with SHA-1, MD5 or MD2.
* **Severity:** Medium
* **Evidence:** Active check: a TLS handshake with the server
* **Why it matters:** SHA-1 and MD5 signatures can be forged; browsers reject such certificates, so the site shows warnings or fails.
* **What to do:** Re-issue the certificate with a SHA-256 signature from a current certificate authority.

### EASM-TLS-008: HTTPS site does not send HSTS

* **Finding type:** `hsts-missing`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** An HTTPS site with a valid certificate answers 2xx without a Strict-Transport-Security header.
* **Severity:** Low
* **Evidence:** Active check: the response headers of the HTTPS site
* **Why it matters:** Without Strict-Transport-Security, a browser may still make its first request over plain HTTP, where an attacker on the network can intercept or redirect it (SSL stripping).
* **What to do:** Send Strict-Transport-Security: max-age=31536000; includeSubDomains once every name under the domain works over HTTPS.

### EASM-TLS-009: HTTP does not redirect to HTTPS

* **Finding type:** `no-https-redirect`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** Port 80 answers with content instead of redirecting to https://, while the same host serves HTTPS.
* **Severity:** Low
* **Evidence:** Active check: a request to port 80 compared with port 443
* **Why it matters:** Visitors who type the address or follow an old link stay on unencrypted HTTP, where anyone on the network can read or change what they see.
* **What to do:** Redirect all HTTP requests to HTTPS (a 301) and enable HSTS once HTTPS works everywhere.

## Web exposure

### EASM-WEB-001: Login portal or admin console is public

* **Finding type:** `login-portal`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The home page, or a product's well-known sign-in page, is recognised as one of the login portals listed below.
* **Severity:** Per product (see login portals): High for infrastructure consoles, Medium for remote-access gateways, webmail/SSO and monitoring or collaboration tools, Low for website sign-ins
* **Evidence:** Active check: the site's home page, and well-known sign-in pages, recognised by the product's own wording
* **Why it matters:** VPN and remote-access gateways (Fortinet, Ivanti, Citrix, Palo Alto, Cisco, SonicWall) are the devices attackers exploit first after a vulnerability is published, often within days. Webmail and single sign-on pages attract password spraying. Administration consoles (Tomcat Manager, Jenkins, phpMyAdmin, hypervisors, firewalls, Kubernetes tools) give full control when a password is guessed or a flaw is found.
* **What to do:** Administration consoles: make them reachable only from an internal network or VPN. Gateways and sign-in pages that must be public: patch within days of vendor advisories, require MFA, rate-limit and monitor failed sign-ins. Accept the risk with a note for portals that are meant to be public.

### EASM-WEB-002: Sensitive file or page is publicly readable

* **Finding type:** `exposed-path`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** A well-known sensitive file or page answers 200 and its content passes the file's own test (and is not the site's catch-all page); or / shows a directory listing (Medium).
* **Severity:** Per file: High, Medium or Low (see sensitive files)
* **Evidence:** Active check: a request for a well-known path, confirmed by its content
* **Why it matters:** Files such as .git folders, .env files, backups and status pages leak source code, passwords, API keys and internal details that let attackers go much further.
* **What to do:** Block public access to the path in the web server configuration and remove the file from the web root. Treat any secrets in it as compromised and rotate them.

### EASM-WEB-003: Default web server page is public

* **Finding type:** `default-page`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The home page answers 200 with a web server's default page (see default pages).
* **Severity:** Low
* **Evidence:** Active check: the page served at the root of the site
* **Why it matters:** A default page shows that software was installed and never configured or maintained. Such servers are often unpatched and missing from inventories.
* **What to do:** Find out who owns the server. Either put the intended site there and harden it, or take the server offline and remove the DNS record.

### EASM-WEB-004: No security.txt on the main site

* **Finding type:** `no-security-txt`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** The domain or www over HTTPS has no /.well-known/security.txt with a Contact: line.
* **Severity:** Low
* **Evidence:** Active check: a request for /.well-known/security.txt on the domain and www (HTTPS)
* **Why it matters:** Researchers who find a vulnerability have no published way to report it (RFC 9116), so reports get lost or end up public instead.
* **What to do:** Publish /.well-known/security.txt with at least a Contact: line (an email or form) and an Expires: date.

## Cloud and storage

### EASM-CLOUD-001: Cloud storage bucket can be listed by anyone

* **Finding type:** `bucket-public`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** A name points at an S3 or Google Cloud Storage bucket that lists its contents to anyone.
* **Severity:** High
* **Evidence:** Active check: an unauthenticated request to the storage provider
* **Why it matters:** Anyone can list and probably download the files in the bucket. Data leaks from public buckets are among the most common cloud breaches.
* **What to do:** Turn on the provider's block-public-access setting, review the bucket policy and ACLs, and check what was exposed.

### EASM-CLOUD-002: Name points to a storage bucket that does not exist

* **Finding type:** `bucket-takeover`
* **Collection:** Active: connects to the organisation's own servers (opt-in)
* **Triggered when:** A name points at an S3 or Google Cloud Storage bucket that does not exist (NoSuchBucket).
* **Severity:** High
* **Evidence:** Active check: an unauthenticated request to the storage provider
* **Why it matters:** The DNS name still points at a bucket that was deleted. Anyone can create a bucket with that name and serve their own content from your domain.
* **What to do:** Delete the DNS record, or re-create the bucket in your own account so that no one else can claim it.

### EASM-CLOUD-003: Managed database or cache named in public DNS

* **Finding type:** `cloud-datastore`
* **Collection:** Passive: DNS
* **Triggered when:** A name in public DNS is an alias for a managed database, cache or search service (see managed datastores).
* **Severity:** Medium
* **Evidence:** DNS resolvers (a CNAME points at a managed database, cache or search service)
* **Why it matters:** A name in public DNS is an alias for a managed database, cache or search cluster (RDS, Azure SQL, MongoDB Atlas, Redis, Elasticsearch and similar). The record does not prove the service is reachable, but it tells attackers exactly where it is, and these services are frequently exposed to the internet by mistake.
* **What to do:** Confirm the service accepts connections only from your private network (security group, firewall rule or private endpoint) and requires authentication. Prefer internal DNS names for databases; remove the public record if it is not needed.

## Exposure intelligence

### EASM-EXP-001: Sensitive service reachable from the internet

* **Finding type:** `exposed-service`
* **Collection:** Third-party intelligence (needs a second source to be trusted)
* **Triggered when:** An intelligence source reports one of the risky ports open on an address of the domain (CDN addresses are skipped).
* **Severity:** High for the high-risk ports, Medium for the other risky ports (see risky ports)
* **Evidence:** Exposure intelligence (Shodan InternetDB / Shodan / Censys scan data)
* **Why it matters:** Remote-administration, file-sharing and database ports are frequent targets for brute force, ransomware and exploitation of unpatched flaws. Scan data may be days old, so confirm the port is still open.
* **What to do:** Close the port on the firewall or security group, or restrict it to a VPN or allow-listed addresses. Where remote access is required, use a VPN or zero-trust gateway with MFA.

### EASM-EXP-002: Host associated with known vulnerabilities (CVEs)

* **Finding type:** `known-vuln`
* **Collection:** Third-party intelligence (needs a second source to be trusted)
* **Triggered when:** Shodan lists CVEs for the software versions seen on an address.
* **Severity:** High with 10 or more CVEs, otherwise Medium
* **Evidence:** Exposure intelligence (CVE list from Shodan InternetDB / Shodan)
* **Why it matters:** The service banners on this address match software versions with published vulnerabilities. Matches are inferred from banners, so some may not apply (for example if fixes were back-ported), but each is worth verifying.
* **What to do:** Check each CVE against the software actually running, apply vendor patches or upgrade, and re-scan. If the service does not need to be public, remove it from the internet.

### EASM-EXP-003: Address flagged as compromised or malicious

* **Finding type:** `ip-flagged`
* **Collection:** Third-party intelligence (needs a second source to be trusted)
* **Triggered when:** Shodan tags an address compromised, malware or doublepulsar.
* **Severity:** High
* **Evidence:** Exposure intelligence (tags on Shodan InternetDB / Shodan)
* **Why it matters:** The intelligence source tags this IP as compromised, running malware or carrying a known backdoor. It may be hosting attacker tooling or be part of a botnet.
* **What to do:** Treat the host as potentially compromised: isolate it, investigate, and rebuild from a known-good image if confirmed.

### EASM-EXP-004: End-of-life operating system or software

* **Finding type:** `eol-software`
* **Collection:** Third-party intelligence (needs a second source to be trusted)
* **Triggered when:** Shodan tags an address eol-os or eol-product.
* **Severity:** Medium
* **Evidence:** Exposure intelligence (eol tags on Shodan InternetDB / Shodan)
* **Why it matters:** Software that no longer receives security updates accumulates unpatched vulnerabilities that attackers can rely on. The evidence column lists the OS, software versions and services detected on the host so you can see what is out of support.
* **What to do:** Upgrade or replace the affected component, or isolate it behind a firewall until it can be retired.

## Brand and leak monitoring

### EASM-BRAND-001: A look-alike of your domain is registered

* **Finding type:** `lookalike-domain`
* **Collection:** Passive: public sources (OSINT)
* **Triggered when:** A registered variation of the domain resolves (see look-alike techniques).
* **Severity:** Medium when it accepts email (MX), otherwise Low
* **Evidence:** DNS: a variation of your domain name (a typo, a similar-looking character, another ending) exists
* **Why it matters:** Someone has registered a name that people could mistake for yours. These are used for phishing emails, fake login pages and intercepting mail sent to a mistyped address. A domain that accepts email is the more serious case.
* **What to do:** Find out who owns it (registration lookup). If it is yours, accept the risk so it stops being reported. If it is not, consider a takedown request through the registrar, block it in your mail and web filters, and brief staff about it. Consider registering the likeliest typos yourself.

### EASM-BRAND-002: Accounts at your domain appear in a data breach

* **Finding type:** `leaked-credentials`
* **Collection:** Passive: public sources (OSINT)
* **Triggered when:** Have I Been Pwned lists accounts at the domain in a breach (API key required).
* **Severity:** High for 5 or more accounts in one breach, otherwise Medium
* **Evidence:** Have I Been Pwned domain search
* **Why it matters:** Email addresses at your domain were exposed in a breach of another service. If people reused that password for work accounts, attackers can sign in as them.
* **What to do:** Open your Have I Been Pwned domain dashboard to see which accounts are affected. Force a password reset for them, make sure two-factor sign-in is on, and remind staff not to reuse work passwords. Accept the risk once this has been done.

### EASM-BRAND-003: Public code mentions your domain next to secret-like words

* **Finding type:** `repo-exposure`
* **Collection:** Passive: public sources (OSINT)
* **Triggered when:** GitHub code search finds the domain near words such as password, secret or token (token required).
* **Severity:** Medium
* **Evidence:** GitHub code search
* **Why it matters:** A public repository contains your domain name close to words such as password, secret or token. It may hold real credentials, internal addresses or configuration that helps an attacker. It is also often harmless, such as documentation or an example.
* **What to do:** Open the listed files. If they hold real secrets, change those secrets immediately (removing the file is not enough, because history is kept), then ask the owner or GitHub to take the repository down. If it is harmless, accept the risk with a note.

## Detection tables

### Login portals and admin consoles (EASM-WEB-001)

Recognised on the home page by the product's page title or header, and at the product's own sign-in page when exposed-file checks are on. A match needs the product's wording, so a page that answers every path does not count.

| Product | Category | Severity | Where it is checked |
|---|---|---|---|
| Fortinet FortiGate SSL-VPN | Remote-access gateway | Medium | `/remote/login` |
| Palo Alto GlobalProtect | Remote-access gateway | Medium | `/global-protect/login.esp` |
| Ivanti / Pulse Connect Secure | Remote-access gateway | Medium | `/dana-na/auth/url_default/welcome.cgi` |
| Citrix Gateway (NetScaler) | Remote-access gateway | Medium | `/vpn/index.html` |
| Citrix Gateway (NetScaler) | Remote-access gateway | Medium | `/logon/LogonPoint/index.html` |
| Cisco ASA / AnyConnect | Remote-access gateway | Medium | `/+CSCOE+/logon.html` |
| SonicWall SSL-VPN | Remote-access gateway | Medium | `/cgi-bin/welcome` |
| Check Point Mobile Access | Remote-access gateway | Medium | `/sslvpn/Login/Login` |
| Microsoft RD Web Access | Remote-access gateway | Medium | `/RDWeb/Pages/en-US/login.aspx` |
| Outlook on the web (Exchange) | Webmail or single sign-on | Medium | `/owa/auth/logon.aspx` |
| AD FS sign-in | Webmail or single sign-on | Medium | `/adfs/ls/idpinitiatedsignon.aspx` |
| phpMyAdmin | Administration console | High | `/phpmyadmin/` |
| Apache Tomcat Manager | Administration console | High | `/manager/html` |
| Jenkins | Administration console | High | `/login` (or the `X-Jenkins` header on any page) |
| Webmin | Administration console | High | Home page |
| cPanel / WHM | Administration console | High | Home page |
| Plesk | Administration console | High | Home page |
| VMware vCenter / vSphere | Administration console | High | Home page |
| VMware ESXi Host Client | Administration console | High | Home page |
| Kubernetes Dashboard | Administration console | High | Home page |
| Portainer | Administration console | High | Home page |
| Rancher | Administration console | High | Home page |
| Argo CD | Administration console | High | Home page |
| MinIO Console | Administration console | High | Home page |
| RabbitMQ Management | Administration console | High | Home page |
| pfSense | Administration console | High | Home page |
| OPNsense | Administration console | High | Home page |
| MikroTik RouterOS | Administration console | High | Home page |
| Jupyter Notebook / Lab | Administration console | High | Home page |
| Grafana | Administration console | Medium | Home page |
| Kibana | Administration console | Medium | Home page |
| Prometheus | Administration console | Medium | Home page |
| Zabbix | Administration console | Medium | Home page |
| SonarQube | Administration console | Medium | Home page |
| GitLab (self-hosted) | Administration console | Medium | Home page |
| Jira / Confluence (self-hosted) | Administration console | Medium | Home page |
| Synology DiskStation | Administration console | Medium | Home page |
| QNAP QTS | Administration console | Medium | Home page |
| WordPress login | Website sign-in | Low | `/wp-login.php` |
| Joomla administrator | Website sign-in | Low | `/administrator/` |
| Drupal login | Website sign-in | Low | `/user/login` |

### Sensitive files and pages (EASM-WEB-002)

Each path is reported only when it answers 200 and its content passes the file's own test, so a site that answers every path with its home page produces nothing. Secret values are never copied into findings.

| Path | Severity | What it exposes |
|---|---|---|
| `/` (directory listing) | Medium | directory listing is switched on, so anyone can browse and download the files in this folder |
| `/.git/HEAD` | High | a Git repository's HEAD file is readable, so source code and secrets can be downloaded |
| `/.git/config` | High | a Git repository's configuration is readable, so source code and secrets can be downloaded |
| `/.env` | High | an environment file with settings and likely passwords or keys is readable |
| `/wp-config.php.bak` | High | a backup of the WordPress configuration, with database credentials, is readable |
| `/actuator/env` | High | a Spring Boot management endpoint shows the application's environment and configuration |
| `/server-status` | Medium | the Apache status page is public and shows requests and clients |
| `/phpinfo.php` | Medium | a PHP information page is public and shows the server's configuration |
| `/.DS_Store` | Low | a macOS folder index file is public and lists file names on the server |
| `/.svn/wc.db` | High | a Subversion working-copy database is readable, so file names and often source code can be recovered |
| `/.hg/requires` | High | a Mercurial repository is readable, so source code and history can be downloaded |
| `/.htpasswd` | High | a web server password file is readable; its hashes can be cracked offline |
| `/.aws/credentials` | High | an AWS credentials file is readable |
| `/.npmrc` | High | an npm configuration file with a registry access token is readable |
| `/sftp-config.json` | High | an editor's SFTP deployment settings, with the server password, are readable |
| `/.vscode/sftp.json` | High | an editor's SFTP deployment settings, with the server password, are readable |
| `/web.config` | High | the IIS/ASP.NET configuration file is readable and may hold connection strings and keys |
| `/docker-compose.yml` | Medium | a Docker Compose file is readable; it maps the services and often holds passwords |
| `/backup.sql` | High | a database dump is downloadable |
| `/dump.sql` | High | a database dump is downloadable |
| `/info.php` | Medium | a PHP information page is public and shows the server's configuration |
| `/server-info` | Medium | the Apache server-information page is public and shows modules and configuration |
| `/elmah.axd` | Medium | the ASP.NET error log is public and shows stack traces, and sometimes cookies and request data |
| `/trace.axd` | Medium | ASP.NET request tracing is public and shows request details, headers and session data |
| `/debug/pprof/` | Medium | the Go profiling endpoint is public: it reveals internals and can be used to load the server |
| `/swagger.json` | Low | an API description is public and maps every endpoint for an attacker (fine only for a deliberately public API) |
| `/openapi.json` | Low | an API description is public and maps every endpoint for an attacker (fine only for a deliberately public API) |
| `/v3/api-docs` | Low | an API description is public and maps every endpoint for an attacker (fine only for a deliberately public API) |
| `/crossdomain.xml` | Low | the Flash/Silverlight cross-domain policy allows any site to read responses as the visitor |

### Default pages (EASM-WEB-003)

| Page | Recognised by |
|---|---|
| nginx welcome page | `Welcome to nginx!` |
| Apache default page | `Apache2 Ubuntu Default Page` |
| Apache default page | `Apache2 Debian Default Page` |
| Apache test page | `Test Page for the Apache HTTP Server` |
| Apache test page | `Test Page for the HTTP Server on` |
| IIS default page | `IIS Windows Server` |
| IIS default page | `Welcome to Internet Information Services` |
| Tomcat default page | `If you're seeing this, you've successfully installed Tomcat` |
| Apache "It works!" page | `<html><body><h1>It works!</h1>` |
| Plesk default page | `Web Server's Default Page` |
| cPanel default page | `Default Web Site Page` |
| LiteSpeed default page | `Congratulations! Your website is up and running` |

### Risky ports (EASM-EXP-001)

Other open ports are recorded in the inventory but are not findings.

| Port | Service | Severity |
|---|---|---|
| 21 | FTP | Medium |
| 23 | Telnet | High |
| 69 | TFTP | Medium |
| 102 | Siemens S7 (industrial control) | High |
| 111 | RPC portmapper | Medium |
| 135 | MS-RPC | Medium |
| 137 | NetBIOS | Medium |
| 139 | NetBIOS | Medium |
| 161 | SNMP | Medium |
| 389 | LDAP | Medium |
| 445 | SMB | High |
| 502 | Modbus (industrial control) | High |
| 631 | Printer (IPP) | Medium |
| 873 | rsync | Medium |
| 1099 | Java RMI registry | High |
| 1433 | Microsoft SQL Server | High |
| 1521 | Oracle DB | High |
| 1723 | PPTP VPN | Medium |
| 1883 | MQTT broker | Medium |
| 2049 | NFS | High |
| 2375 | Docker API (unencrypted) | High |
| 2376 | Docker API (TLS) | Medium |
| 2379 | etcd | High |
| 3306 | MySQL | High |
| 3389 | RDP | High |
| 4786 | Cisco Smart Install | High |
| 4848 | GlassFish admin | Medium |
| 5432 | PostgreSQL | High |
| 5555 | Android Debug Bridge | High |
| 5601 | Kibana | Medium |
| 5900 | VNC | High |
| 5984 | CouchDB | High |
| 5985 | WinRM (HTTP) | Medium |
| 5986 | WinRM (HTTPS) | Medium |
| 6379 | Redis | High |
| 6443 | Kubernetes API server | Medium |
| 7001 | Oracle WebLogic | Medium |
| 8009 | Apache JServ (AJP) | Medium |
| 8086 | InfluxDB | Medium |
| 8291 | MikroTik Winbox | Medium |
| 9042 | Cassandra | Medium |
| 9100 | Printer (JetDirect) | Medium |
| 9200 | Elasticsearch | High |
| 9300 | Elasticsearch transport | Medium |
| 10250 | Kubernetes kubelet API | High |
| 11211 | Memcached | High |
| 20000 | DNP3 (industrial control) | High |
| 27017 | MongoDB | High |
| 44818 | EtherNet/IP (industrial control) | High |

### Subdomain-takeover platforms (EASM-DNS-001)

A dangling CNAME to one of these is High, because anyone can claim the unused name there:

`agilecrm.com`, `azure-api.net`, `azurecontainer.io`, `azureedge.net`, `azurehdinsight.net`, `azurewebsites.net`, `bitbucket.io`, `blob.core.windows.net`, `cargocollective.com`, `cloudapp.azure.com`, `cloudapp.net`, `cloudfront.net`, `elasticbeanstalk.com`, `fastly.net`, `furyns.com`, `ghost.io`, `github.io`, `helpjuice.com`, `helpscoutdocs.com`, `herokuapp.com`, `herokudns.com`, `launchrock.com`, `myjetbrains.com`, `netlify.app`, `ngrok.io`, `pantheonsite.io`, `readme.io`, `s3-website`, `s3.amazonaws.com`, `servicebus.windows.net`, `smartjobboard.com`, `stats.pingdom.com`, `stats.uptimerobot.com`, `statuspage.io`, `surge.sh`, `trafficmanager.net`, `unbouncepages.com`, `vercel.app`, `wordpress.com`, `zendesk.com`

### Managed datastores (EASM-CLOUD-003)

| DNS suffix | Service |
|---|---|
| `rds.amazonaws.com` | AWS RDS |
| `redshift.amazonaws.com` | AWS Redshift |
| `cache.amazonaws.com` | AWS ElastiCache |
| `docdb.amazonaws.com` | AWS DocumentDB |
| `es.amazonaws.com` | AWS OpenSearch |
| `database.windows.net` | Azure SQL |
| `postgres.database.azure.com` | Azure PostgreSQL |
| `mysql.database.azure.com` | Azure MySQL |
| `redis.cache.windows.net` | Azure Cache for Redis |
| `documents.azure.com` | Azure Cosmos DB |
| `mongodb.net` | MongoDB Atlas |
| `redislabs.com` | Redis Cloud |
| `redns.redis-cloud.com` | Redis Cloud |
| `found.io` | Elastic Cloud |
| `elastic-cloud.com` | Elastic Cloud |
| `es.io` | Elastic Cloud |
| `firebaseio.com` | Firebase Realtime Database |
| `supabase.co` | Supabase |
| `db.ondigitalocean.com` | DigitalOcean Managed DB |
| `neon.tech` | Neon Postgres |
| `cockroachlabs.cloud` | CockroachDB Cloud |
| `planetscale.com` | PlanetScale |

### DKIM selectors tried (EASM-MAIL-012)

`default`, `google`, `selector1`, `selector2`, `k1`, `k2`, `k3`, `s1`, `s2`, `mail`, `dkim`, `smtp`, `mandrill`, `mxvault`, `everlytickey1`, `cm`, `zendesk1`, `mimecast20190104`

### Look-alike techniques (EASM-BRAND-001)

Variations are generated locally and only looked up in DNS:

* typos: a missing, repeated or swapped letter, a neighbouring key (QWERTY), a changed vowel, an added hyphen
* bitsquatting: one bit different in a letter
* look-alike characters: o→0, l→1, l→i, i→1, i→l, m→rn, w→vv, rn→m, vv→w, cl→d, s→5, e→3, a→4, b→d, g→q, u→v, n→m
* Cyrillic homoglyphs (internationalised domain names): a→а, c→с, e→е, i→і, j→ј, o→о, p→р, s→ѕ, x→х, y→у
* added words (`name-word`, `word-name`, `nameword`): `login`, `secure`, `support`, `portal`, `online`, `mail`, `account`, `verify`, `pay`, `my`, `app`, `help`
* other endings: `.com`, `.net`, `.org`, `.co`, `.io`, `.app`, `.info`, `.biz`, `.online`, `.shop`, `.xyz`, `.site`, `.support`, `.cloud`, `.dev`

## Inventory signatures (not findings)

These identify the cloud and SaaS services the organisation uses, from DNS answers the scan already holds. New services raise an inventory event, not a finding.

### CNAME targets

| Match | Service | Category |
|---|---|---|
| `execute-api.` | AWS API Gateway | API & serverless |
| `lambda-url.` | AWS Lambda | API & serverless |
| `cloudfront.net` | AWS CloudFront | CDN & edge |
| `elb.amazonaws.com` | AWS Load Balancer | Cloud hosting |
| `elasticbeanstalk.com` | AWS Elastic Beanstalk | Cloud hosting |
| `s3.amazonaws.com` | AWS S3 | Database & storage |
| `amazonaws.com` | AWS | Cloud hosting |
| `azure-api.net` | Azure API Management | API & serverless |
| `azurewebsites.net` | Azure App Service | Cloud hosting |
| `azurefd.net` | Azure Front Door | CDN & edge |
| `azureedge.net` | Azure CDN | CDN & edge |
| `trafficmanager.net` | Azure Traffic Manager | Cloud hosting |
| `blob.core.windows.net` | Azure Blob Storage | Database & storage |
| `cloudapp.azure.com` | Azure VM | Cloud hosting |
| `azurecontainerapps.io` | Azure Container Apps | Cloud hosting |
| `cloudfunctions.net` | Google Cloud Functions | API & serverless |
| `run.app` | Google Cloud Run | API & serverless |
| `appspot.com` | Google App Engine | Cloud hosting |
| `storage.googleapis.com` | Google Cloud Storage | Database & storage |
| `web.app` | Firebase Hosting | Cloud hosting |
| `firebaseapp.com` | Firebase Hosting | Cloud hosting |
| `herokuapp.com` | Heroku | Cloud hosting |
| `netlify.app` | Netlify | Cloud hosting |
| `vercel.app` | Vercel | Cloud hosting |
| `github.io` | GitHub Pages | Developer platform |
| `pages.dev` | Cloudflare Pages | Cloud hosting |
| `workers.dev` | Cloudflare Workers | API & serverless |
| `fastly.net` | Fastly | CDN & edge |
| `akamaiedge.net` | Akamai | CDN & edge |
| `edgekey.net` | Akamai | CDN & edge |
| `digitaloceanspaces.com` | DigitalOcean Spaces | Database & storage |
| `ondigitalocean.app` | DigitalOcean App Platform | Cloud hosting |
| `zendesk.com` | Zendesk | Support & marketing |
| `freshdesk.com` | Freshdesk | Support & marketing |
| `statuspage.io` | Atlassian Statuspage | SaaS application |
| `atlassian.net` | Atlassian Cloud | SaaS application |
| `hubspot.net` | HubSpot | Support & marketing |
| `hs-sites.com` | HubSpot | Support & marketing |
| `mktoweb.com` | Marketo | Support & marketing |
| `salesforce.com` | Salesforce | SaaS application |
| `force.com` | Salesforce | SaaS application |
| `my.salesforce-sites.com` | Salesforce Sites | SaaS application |
| `shopify.com` | Shopify | SaaS application |
| `myshopify.com` | Shopify | SaaS application |
| `wpengine.com` | WP Engine | Cloud hosting |
| `readme.io` | ReadMe | SaaS application |
| `intercom.io` | Intercom | Support & marketing |
| `okta.com` | Okta | Identity & verification |
| `auth0.com` | Auth0 | Identity & verification |
| `sendgrid.net` | SendGrid | Email service |
| `mailgun.org` | Mailgun | Email service |
| `mcsv.net` | Mailchimp | Email service |
| `sharepoint.com` | Microsoft 365 SharePoint | SaaS application |
| `ghost.io` | Ghost | SaaS application |
| `pantheonsite.io` | Pantheon | Cloud hosting |
| `surge.sh` | Surge | Cloud hosting |
| `bitbucket.io` | Bitbucket Pages | Developer platform |
| `gitlab.io` | GitLab Pages | Developer platform |

### SPF include: domains

| Match | Service | Category |
|---|---|---|
| `_spf.google.com` | Google Workspace | Email service |
| `spf.protection.outlook.com` | Microsoft 365 Exchange | Email service |
| `sendgrid.net` | SendGrid | Email service |
| `mailgun.org` | Mailgun | Email service |
| `amazonses.com` | Amazon SES | Email service |
| `servers.mcsv.net` | Mailchimp | Email service |
| `mandrillapp.com` | Mandrill | Email service |
| `spf.mtasv.net` | Postmark | Email service |
| `mailjet.com` | Mailjet | Email service |
| `salesforce.com` | Salesforce | SaaS application |
| `zendesk.com` | Zendesk | Support & marketing |
| `hubspot.com` | HubSpot | Support & marketing |
| `freshdesk.com` | Freshdesk | Support & marketing |
| `_spf.atlassian.net` | Atlassian | SaaS application |
| `pphosted.com` | Proofpoint | Email service |
| `mimecast.com` | Mimecast | Email service |
| `zoho.com` | Zoho | SaaS application |
| `spf.sendinblue.com` | Brevo (Sendinblue) | Email service |
| `helpscoutemail.com` | Help Scout | Support & marketing |
| `intercom.io` | Intercom | Support & marketing |
| `servers.outlook.com` | Microsoft 365 | Email service |

### MX hosts

| Match | Service | Category |
|---|---|---|
| `google.com` | Google Workspace | Email service |
| `googlemail.com` | Google Workspace | Email service |
| `mail.protection.outlook.com` | Microsoft 365 Exchange | Email service |
| `pphosted.com` | Proofpoint | Email service |
| `mimecast.com` | Mimecast | Email service |
| `zoho.com` | Zoho Mail | Email service |
| `messagingengine.com` | Fastmail | Email service |
| `protonmail.ch` | Proton Mail | Email service |
| `barracudanetworks.com` | Barracuda | Email service |
| `mailgun.org` | Mailgun | Email service |

### Domain-verification TXT records

| Prefix | Service | Category |
|---|---|---|
| `google-site-verification=` | Google (Search Console / Workspace) | Identity & verification |
| `ms=ms` | Microsoft 365 | Identity & verification |
| `atlassian-domain-verification=` | Atlassian Cloud | SaaS application |
| `docusign=` | DocuSign | SaaS application |
| `facebook-domain-verification=` | Meta (Facebook) | Support & marketing |
| `apple-domain-verification=` | Apple Business | Identity & verification |
| `stripe-verification=` | Stripe | SaaS application |
| `slack-domain-verification=` | Slack | SaaS application |
| `zoom-domain-verification=` | Zoom | SaaS application |
| `adobe-idp-site-verification=` | Adobe | SaaS application |
| `onetrust-domain-verification=` | OneTrust | SaaS application |
| `dropbox-domain-verification=` | Dropbox | SaaS application |
| `shopify-verification-code=` | Shopify | SaaS application |
| `hubspot-developer-verification=` | HubSpot | Support & marketing |
| `miro-verification=` | Miro | SaaS application |
| `asana-verification=` | Asana | SaaS application |
| `canva-site-verification=` | Canva | SaaS application |
| `box-domain-verification=` | Box | SaaS application |
| `github-challenge-` | GitHub | Developer platform |
| `gitlab-pages-verification-code=` | GitLab | Developer platform |
| `figma-domain-verification=` | Figma | SaaS application |
| `notion-domain-verification=` | Notion | SaaS application |
| `smartsheet-site-validation=` | Smartsheet | SaaS application |
| `mongodb-site-verification=` | MongoDB Atlas | Database & storage |
| `cloudflare-verify` | Cloudflare | CDN & edge |
| `amazonses:` | Amazon SES | Email service |
| `openai-domain-verification=` | OpenAI | SaaS application |
| `anthropic-domain-verification-` | Anthropic | SaaS application |
| `postman-domain-verification=` | Postman | Developer platform |
| `airtable-verification=` | Airtable | SaaS application |
| `webexdomainverification.` | Cisco Webex | SaaS application |
