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
	"lookalike-domain": {
		Title:    "A look-alike of your domain is registered",
		Source:   "DNS: a variation of your domain name (a typo, a similar-looking character, another ending) exists",
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
	"no-https-redirect": {
		Title:    "HTTP does not redirect to HTTPS",
		Source:   "Active check: a request to port 80 compared with port 443",
		Risk:     "Visitors who type the address or follow an old link stay on unencrypted HTTP, where anyone on the network can read or change what they see.",
		Solution: "Redirect all HTTP requests to HTTPS (a 301) and enable HSTS once HTTPS works everywhere.",
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
		Source: "Exposure intelligence (CVE list from Shodan InternetDB / Shodan)",
		Risk: "The service banners on this address match software versions with published vulnerabilities. Matches are inferred from banners, " +
			"so some may not apply (for example if fixes were back-ported), but each is worth verifying.",
		Solution: "Check each CVE against the software actually running, apply vendor patches or upgrade, and re-scan. " +
			"If the service does not need to be public, remove it from the internet.",
	},
	"ip-flagged": {
		Title:  "Address flagged as compromised or malicious",
		Source: "Exposure intelligence (tags on Shodan InternetDB / Shodan)",
		Risk: "The intelligence source tags this IP as compromised, running malware or carrying a known backdoor. " +
			"It may be hosting attacker tooling or be part of a botnet.",
		Solution: "Treat the host as potentially compromised: isolate it, investigate, and rebuild from a known-good image if confirmed.",
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
	k := f.Kind
	if f.Kind == "email-auth" {
		if i := strings.LastIndex(f.Key, ":"); i >= 0 {
			k = "email-auth/" + f.Key[i+1:]
		}
	}
	info, ok := findingCatalog[k]
	if !ok {
		info = FindingInfo{Title: f.Kind, Source: "EASM agent", Risk: "See the detail column.", Solution: "Investigate the detail and correct the underlying configuration."}
	}
	if f.Source != "" {
		info.Source = f.Source
	}
	return info
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
	}
	return id
}
