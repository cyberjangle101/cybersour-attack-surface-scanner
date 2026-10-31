package main

import (
	"fmt"
	"sort"
	"strings"
)

// describeVulns words a known-vuln finding and grades it. A CVE list inferred from
// banners is noisy, so the CVEs that matter are put first: those in CISA's Known
// Exploited Vulnerabilities catalogue (exploited in the wild), then the highest
// FIRST EPSS scores (likely to be exploited in the next 30 days). Any KEV CVE, an EPSS
// of 50% or more, or ten or more CVEs makes the finding High.
func (s *Scanner) describeVulns(vulns []string, where string, epss map[string]float64) (sev, msg string) {
	kev := map[string]KEVEntry{}
	if s.cfg.Intel.KEV {
		for _, v := range vulns {
			if e, ok := s.feeds.KEV(v); ok {
				kev[v] = e
			}
		}
	}
	ordered := append([]string(nil), vulns...)
	sort.SliceStable(ordered, func(i, j int) bool {
		_, ki := kev[ordered[i]]
		_, kj := kev[ordered[j]]
		if ki != kj {
			return ki
		}
		if epss[ordered[i]] != epss[ordered[j]] {
			return epss[ordered[i]] > epss[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	topCVE, top := "", 0.0
	for _, v := range ordered {
		if p := epss[v]; p > top {
			topCVE, top = v, p
		}
	}
	sev = "medium"
	if len(vulns) >= 10 || len(kev) > 0 || top >= 0.5 {
		sev = "high"
	}
	shown := ordered
	if len(shown) > 12 {
		shown = shown[:12]
	}
	more := ""
	if len(vulns) > len(shown) {
		more = fmt.Sprintf(" and %d more", len(vulns)-len(shown))
	}
	msg = fmt.Sprintf("%d possible vulnerabilities on %s: %s%s", len(vulns), where, strings.Join(shown, ", "), more)
	if len(kev) > 0 {
		var names []string
		for _, v := range ordered {
			if e, ok := kev[v]; ok && len(names) < 5 {
				n := v + " (" + e.Name
				if e.Ransomware {
					n += ", used by ransomware"
				}
				names = append(names, n+")")
			}
		}
		msg += fmt.Sprintf(". %d of them are in CISA's Known Exploited Vulnerabilities catalogue, so attackers use them in the wild: %s", len(kev), strings.Join(names, "; "))
	}
	if topCVE != "" {
		msg += fmt.Sprintf(". Highest EPSS: %s, a %.0f%% chance of exploitation in the next 30 days", topCVE, top*100)
	}
	return sev, msg
}

// cloudLabel names a provider range for finding text: "AWS (EC2, eu-west-1)".
func cloudLabel(c CloudRange) string {
	var parts []string
	if c.Service != "" && !strings.EqualFold(c.Service, c.Provider) && c.Service != "AMAZON" {
		parts = append(parts, c.Service)
	}
	if c.Region != "" && c.Region != "GLOBAL" {
		parts = append(parts, c.Region)
	}
	if len(parts) == 0 {
		return c.Provider
	}
	return c.Provider + " (" + strings.Join(parts, ", ") + ")"
}
