package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Providers where an unclaimed/dangling CNAME target is commonly takeover-able.
var takeoverSuffixes = []string{
	"github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com", "s3-website", "elasticbeanstalk.com",
	"azurewebsites.net", "cloudapp.azure.com", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
	"azureedge.net", "cloudfront.net", "fastly.net", "pantheonsite.io", "ghost.io", "surge.sh",
	"bitbucket.io", "wordpress.com", "zendesk.com", "statuspage.io", "unbouncepages.com",
	"helpjuice.com", "helpscoutdocs.com", "cargocollective.com", "readme.io", "netlify.app", "vercel.app",
	"azure-api.net", "azurecontainer.io", "azurehdinsight.net", "servicebus.windows.net", "ngrok.io", "launchrock.com",
	"stats.uptimerobot.com", "stats.pingdom.com", "agilecrm.com", "myjetbrains.com", "furyns.com", "smartjobboard.com",
}

// takeoverProvider names the claim-able hosting platform a CNAME target belongs to, or "" if it is not a known takeover-prone provider.
func takeoverProvider(target string) string {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, s := range takeoverSuffixes {
		if strings.HasSuffix(t, "."+s) || t == s || strings.Contains(t, "."+s+".") {
			return s
		}
	}
	return ""
}

type issue struct {
	Code     string
	Severity string
	Detail   string
}

// emailAuthIssues inspects SPF (root TXT) and DMARC (_dmarc TXT) records.
// Callers must only invoke the relevant half when the underlying lookup succeeded.
func spfIssues(rootTXT []string) []issue {
	var spf string
	for _, t := range rootTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = strings.ToLower(strings.TrimSpace(t))
			break
		}
	}
	if spf == "" {
		return []issue{{"no-spf", "medium", "no SPF record published at the domain apex"}}
	}
	if n := len(spfRecords(rootTXT)); n > 1 {
		return []issue{{"spf-multiple", "high", fmt.Sprintf("%d SPF records are published; receivers treat that as an error and SPF fails for every message", n)}}
	}
	var out []issue
	for _, tok := range strings.Fields(spf) {
		switch tok {
		case "+all", "all":
			return []issue{{"spf-permissive", "high", "SPF ends in +all/all: any host may send as this domain"}}
		case "?all":
			return []issue{{"spf-neutral", "medium", "SPF ends in ?all (neutral): provides no enforcement"}}
		}
		if t := strings.TrimLeft(tok, "+-~?"); t == "ptr" || strings.HasPrefix(t, "ptr:") {
			out = append(out, issue{"spf-ptr", "low", "SPF uses the ptr mechanism, which is slow, unreliable and discouraged by the SPF standard"})
		}
	}
	return out
}

// dmarcIssues inspects the _dmarc TXT records and reports a missing or weak policy.
func dmarcIssues(dmarcTXT []string) []issue {
	var rec string
	for _, t := range dmarcTXT {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			rec = strings.ToLower(strings.TrimSpace(t))
			break
		}
	}
	if rec == "" {
		return []issue{{"no-dmarc", "medium", "no DMARC record at _dmarc." + "<domain>"}}
	}
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	var out []issue
	if tags["p"] == "none" {
		out = append(out, issue{"dmarc-p-none", "low", "DMARC policy is p=none (monitor only, spoofed mail is still delivered)"})
	}
	if tags["sp"] == "none" && tags["p"] != "none" {
		out = append(out, issue{"dmarc-sp-none", "medium", "DMARC protects the domain (p=" + tags["p"] + ") but sp=none leaves every subdomain unprotected, so mail can be spoofed from any of them"})
	}
	if pct, err := strconv.Atoi(tags["pct"]); err == nil && pct < 100 && tags["p"] != "none" {
		out = append(out, issue{"dmarc-pct", "low", fmt.Sprintf("DMARC applies its policy to only %d%% of failing mail (pct=%d)", pct, pct)})
	}
	if tags["rua"] == "" {
		out = append(out, issue{"dmarc-no-reports", "low", "DMARC has no rua= address, so you receive no reports about who sends mail as this domain"})
	}
	return out
}
