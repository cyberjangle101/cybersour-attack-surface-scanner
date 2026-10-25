package main

import (
	"net/http"
	"strings"
)

// Login portals and administration consoles.
//
// Edge appliances and remote-access gateways (Fortinet, Ivanti/Pulse, Citrix, Palo Alto,
// Cisco, SonicWall) are behind most mass-exploitation campaigns of recent years, and their
// web logins are what attackers scan for first. Webmail and single sign-on pages attract
// password spraying. Infrastructure consoles (Tomcat Manager, Jenkins, phpMyAdmin,
// hypervisors, firewalls, Kubernetes tools) should not face the internet at all.
//
// Each signature is matched against the page the site serves at "/" (no extra request)
// and, for those with a Path, against that well-known page when exposed-file checks are
// on. A match needs the product's own wording, so a page that answers 200 for every path
// does not produce a finding.

// Portal categories, worst first.
const (
	portalAdmin  = "Administration console"
	portalRemote = "Remote-access gateway"
	portalSignIn = "Webmail or single sign-on"
	portalCMS    = "Website sign-in"
)

// portalSig recognises one product's sign-in page.
type portalSig struct {
	Name, Category, Severity string
	Path                     string   // well-known page to request ("" = recognised only on the root page)
	Any                      []string // the page (title, body or headers, case-insensitive) contains one of these
	Header                   string   // or this response header is present
	Auth401                  string   // or the page answers 401 with a WWW-Authenticate realm containing this
}

var portalSigs = []portalSig{
	// Remote-access gateways and edge appliances: exposed by design, but prime exploitation targets.
	{Name: "Fortinet FortiGate SSL-VPN", Category: portalRemote, Severity: "medium", Path: "/remote/login", Any: []string{"fgt_lang", "fortigate", "ftnt-fortinet"}},
	{Name: "Palo Alto GlobalProtect", Category: portalRemote, Severity: "medium", Path: "/global-protect/login.esp", Any: []string{"globalprotect portal", "global-protect/portal"}},
	{Name: "Ivanti / Pulse Connect Secure", Category: portalRemote, Severity: "medium", Path: "/dana-na/auth/url_default/welcome.cgi", Any: []string{"ivanti connect secure", "pulse connect secure", "/dana-na/"}},
	{Name: "Citrix Gateway (NetScaler)", Category: portalRemote, Severity: "medium", Path: "/vpn/index.html", Any: []string{"citrix gateway", "netscaler gateway", "/vpn/resources/", "citrix adc"}},
	{Name: "Citrix Gateway (NetScaler)", Category: portalRemote, Severity: "medium", Path: "/logon/LogonPoint/index.html", Any: []string{"citrix gateway", "logonpoint", "netscaler"}},
	{Name: "Cisco ASA / AnyConnect", Category: portalRemote, Severity: "medium", Path: "/+CSCOE+/logon.html", Any: []string{"webvpn", "+cscoe+", "anyconnect"}},
	{Name: "SonicWall SSL-VPN", Category: portalRemote, Severity: "medium", Path: "/cgi-bin/welcome", Any: []string{"sonicwall", "sonicos"}},
	{Name: "Check Point Mobile Access", Category: portalRemote, Severity: "medium", Path: "/sslvpn/Login/Login", Any: []string{"check point mobile", "checkpoint ssl vpn", "check point ssl"}},
	{Name: "Microsoft RD Web Access", Category: portalRemote, Severity: "medium", Path: "/RDWeb/Pages/en-US/login.aspx", Any: []string{"rd web access", "remote desktop web access", "tswaformsauthentication"}},

	// Webmail and single sign-on: password-spraying and phishing targets.
	{Name: "Outlook on the web (Exchange)", Category: portalSignIn, Severity: "medium", Path: "/owa/auth/logon.aspx", Any: []string{"/owa/auth/", "outlook web app", "microsoft exchange"}},
	{Name: "AD FS sign-in", Category: portalSignIn, Severity: "medium", Path: "/adfs/ls/idpinitiatedsignon.aspx", Any: []string{"idpinitiatedsignon", "/adfs/ls/"}},

	// Administration consoles that should never face the internet.
	{Name: "phpMyAdmin", Category: portalAdmin, Severity: "high", Path: "/phpmyadmin/", Any: []string{"<title>phpmyadmin", "phpmyadmin.css", "pma_password"}},
	{Name: "Apache Tomcat Manager", Category: portalAdmin, Severity: "high", Path: "/manager/html", Auth401: "Tomcat Manager Application", Any: []string{"tomcat web application manager"}},
	{Name: "Jenkins", Category: portalAdmin, Severity: "high", Path: "/login", Header: "X-Jenkins", Any: []string{"sign in [jenkins]"}},
	{Name: "Webmin", Category: portalAdmin, Severity: "high", Any: []string{"<title>login to webmin"}},
	{Name: "cPanel / WHM", Category: portalAdmin, Severity: "high", Any: []string{"<title>cpanel login", "<title>whm login"}},
	{Name: "Plesk", Category: portalAdmin, Severity: "high", Any: []string{"login_up.php"}},
	{Name: "VMware vCenter / vSphere", Category: portalAdmin, Severity: "high", Any: []string{"id_vc_welcome", "<title>vmware vsphere", "<title>vsphere client"}},
	{Name: "VMware ESXi Host Client", Category: portalAdmin, Severity: "high", Any: []string{"<title>vmware esxi", "<title>esxi host client"}},
	{Name: "Kubernetes Dashboard", Category: portalAdmin, Severity: "high", Any: []string{"<title>kubernetes dashboard"}},
	{Name: "Portainer", Category: portalAdmin, Severity: "high", Any: []string{"<title>portainer"}},
	{Name: "Rancher", Category: portalAdmin, Severity: "high", Any: []string{"<title>rancher"}},
	{Name: "Argo CD", Category: portalAdmin, Severity: "high", Any: []string{"<title>argo cd"}},
	{Name: "MinIO Console", Category: portalAdmin, Severity: "high", Any: []string{"<title>minio console"}},
	{Name: "RabbitMQ Management", Category: portalAdmin, Severity: "high", Any: []string{"<title>rabbitmq management"}},
	{Name: "pfSense", Category: portalAdmin, Severity: "high", Any: []string{"<title>pfsense"}},
	{Name: "OPNsense", Category: portalAdmin, Severity: "high", Any: []string{"<title>opnsense"}},
	{Name: "MikroTik RouterOS", Category: portalAdmin, Severity: "high", Any: []string{"<title>routeros router configuration page"}},
	{Name: "Jupyter Notebook / Lab", Category: portalAdmin, Severity: "high", Any: []string{"<title>jupyter", "<title>home page - select or create a notebook"}},
	{Name: "Grafana", Category: portalAdmin, Severity: "medium", Any: []string{"<title>grafana", "grafana-app"}},
	{Name: "Kibana", Category: portalAdmin, Severity: "medium", Header: "Kbn-Name", Any: []string{"<title>kibana"}},
	{Name: "Prometheus", Category: portalAdmin, Severity: "medium", Any: []string{"<title>prometheus time series"}},
	{Name: "Zabbix", Category: portalAdmin, Severity: "medium", Any: []string{"<title>zabbix"}},
	{Name: "SonarQube", Category: portalAdmin, Severity: "medium", Any: []string{"<title>sonarqube"}},
	{Name: "GitLab (self-hosted)", Category: portalAdmin, Severity: "medium", Any: []string{"<title>sign in · gitlab", "<title>gitlab"}},
	{Name: "Jira / Confluence (self-hosted)", Category: portalAdmin, Severity: "medium", Any: []string{"<title>log in - jira", "<title>log in - confluence"}},
	{Name: "Synology DiskStation", Category: portalAdmin, Severity: "medium", Any: []string{"<title>synology"}},
	{Name: "QNAP QTS", Category: portalAdmin, Severity: "medium", Any: []string{"<title>qts"}},

	// Website content-management sign-ins: expected on many sites, but brute-forced constantly.
	{Name: "WordPress login", Category: portalCMS, Severity: "low", Path: "/wp-login.php", Any: []string{"wp-submit", "user_login"}},
	{Name: "Joomla administrator", Category: portalCMS, Severity: "low", Path: "/administrator/", Any: []string{"joomla"}},
	{Name: "Drupal login", Category: portalCMS, Severity: "low", Path: "/user/login", Any: []string{"drupal"}},
}

// PortalHit is a sign-in page or console that answered.
type PortalHit struct {
	Name, Category, Severity, Path string
}

// matchPortal reports whether a response is the signature's page. It never matches an
// empty or error answer.
func matchPortal(sig portalSig, status int, h http.Header, body []byte) bool {
	if sig.Auth401 != "" && status == http.StatusUnauthorized && strings.Contains(h.Get("WWW-Authenticate"), sig.Auth401) {
		return true
	}
	if status != http.StatusOK && status != http.StatusUnauthorized {
		return false
	}
	if sig.Header != "" && h.Get(sig.Header) != "" {
		return true
	}
	b := strings.ToLower(string(body))
	for _, n := range sig.Any {
		if strings.Contains(b, n) {
			return true
		}
	}
	return false
}

// portalsOnPage returns the signatures the root page itself matches.
func portalsOnPage(status int, h http.Header, body []byte) []PortalHit {
	var out []PortalHit
	seen := map[string]bool{}
	for _, sig := range portalSigs {
		// A signature with its own page is recognised at "/" only by its product header:
		// a homepage that merely mentions the product (a Drupal site, a VPN how-to) is not its sign-in page.
		if sig.Path != "" && (sig.Header == "" || h.Get(sig.Header) == "") {
			continue
		}
		if !seen[sig.Name] && matchPortal(sig, status, h, body) {
			seen[sig.Name] = true
			out = append(out, PortalHit{Name: sig.Name, Category: sig.Category, Severity: sig.Severity, Path: "/"})
		}
	}
	return out
}

// portalSlug turns a product name into the stable part of a finding key ("Apache Tomcat Manager" -> "apache-tomcat-manager").
func portalSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// portalWhy words a portal finding's risk for its category.
func portalWhy(category string) string {
	switch category {
	case portalRemote:
		return "remote-access gateways like this are among the most exploited devices on the internet; keep it patched within days of vendor advisories and require MFA"
	case portalSignIn:
		return "public sign-in pages are targets for password spraying and phishing; require MFA and watch for failed sign-ins"
	case portalAdmin:
		return "an administration console should be reachable only from an internal network or VPN, not from the internet"
	}
	return "a public sign-in page is brute-forced constantly; use strong passwords, MFA and login rate limits"
}
