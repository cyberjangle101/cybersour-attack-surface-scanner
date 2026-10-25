package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// docs/RULES.md is generated from the rule index and the detection tables, so it can
// never drift from what the agent actually does. After changing a rule, regenerate it:
//
//	EASM_UPDATE_RULES=1 go test -run TestRulesReference .
const rulesDoc = "docs/RULES.md"

func TestRulesReference(t *testing.T) {
	// Every finding kind has rule metadata, and the other way round; IDs are unique.
	ids := map[string]string{}
	for kind := range findingCatalog {
		m, ok := ruleIndex[kind]
		if !ok {
			t.Errorf("finding kind %q has no entry in ruleIndex (rules.go)", kind)
			continue
		}
		if other, dup := ids[m.ID]; dup {
			t.Errorf("rule ID %s used by both %q and %q", m.ID, kind, other)
		}
		ids[m.ID] = kind
	}
	for kind := range ruleIndex {
		if _, ok := findingCatalog[kind]; !ok {
			t.Errorf("ruleIndex has %q but findingCatalog (catalog.go) does not explain it", kind)
		}
	}
	want := renderRules()
	if os.Getenv("EASM_UPDATE_RULES") == "1" {
		if err := os.MkdirAll(filepath.Dir(rulesDoc), 0o755); err != nil { //nolint:gosec // G301: a documentation folder in the repository
			t.Fatal(err)
		}
		if err := os.WriteFile(rulesDoc, []byte(want), 0o644); err != nil { //nolint:gosec // G306: a documentation file in the repository
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(rulesDoc)
	if err != nil {
		t.Fatalf("%s is missing; create it with EASM_UPDATE_RULES=1 go test -run TestRulesReference .", rulesDoc)
	}
	if strings.ReplaceAll(string(have), "\r\n", "\n") != want {
		t.Errorf("%s is out of date with the rules in the code; regenerate it with EASM_UPDATE_RULES=1 go test -run TestRulesReference .", rulesDoc)
	}
}

func cell(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ") }

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// renderRules builds the Markdown reference.
func renderRules() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	type rule struct {
		Kind string
		Meta ruleMeta
		Info FindingInfo
	}
	var rules []rule
	for kind, m := range ruleIndex {
		rules = append(rules, rule{kind, m, findingCatalog[kind]})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Meta.ID < rules[j].Meta.ID })

	w("# EASM Agent detection rules\n\n")
	w("This is every check the EASM Agent runs against a monitored domain: the finding it raises, its rule ID, how the evidence is collected, how severe it is and exactly what triggers it, followed by the detection tables (paths, products, ports, platforms and signatures) the rules use.\n\n")
	w("> Generated from the source code (`rules.go`, `catalog.go` and the detection tables) by `rules_doc_test.go`. Do not edit by hand: after changing a rule, run `EASM_UPDATE_RULES=1 go test -run TestRulesReference .`. The test fails when this file and the code disagree.\n\n")

	w("## How findings are produced\n\n")
	w("* **Passive checks** read public DNS, registration data (RDAP) and public sources. They send nothing to the organisation's own servers.\n")
	w("* **Active checks** connect to the organisation's own web servers and are off unless switched on (Settings → Active checks, or the first-scan option when a domain is added). They use read-only `GET` requests and TLS handshakes, follow no redirects, connect only to public routable addresses, and by default only to addresses inside the domain's expected ownership. Exposed-file and login-portal path checks need the separate *exposed files* option.\n")
	w("* **Third-party intelligence** (Shodan InternetDB, Shodan, Censys) is often stale. Its findings are *Unconfirmed* until a second, independent source agrees: Censys, the agent's own active check, or an analyst. InternetDB and the Shodan API count as one source. Unconfirmed findings are listed but not alerted, counted or reported.\n")
	w("* **Resolution.** A finding resolves automatically only when a later scan actually re-checked the thing it is about and found it fixed; an outage or unreachable server never closes a finding.\n")
	w("* **Severity** is High, Medium, Low or Info; analysts can override it per finding with a reason.\n\n")

	w("## Rule summary\n\n")
	w("| ID | Rule | Finding type | Collection | Severity |\n|---|---|---|---|---|\n")
	for _, r := range rules {
		w("| %s | %s | `%s` | %s | %s |\n", r.Meta.ID, cell(r.Info.Title), r.Kind, cell(r.Meta.Mode), cell(r.Meta.Severity))
	}
	w("\n%d rules.\n\n", len(rules))

	for _, cat := range ruleCategories {
		w("## %s\n\n", cat)
		for _, r := range rules {
			if r.Meta.Category != cat {
				continue
			}
			w("### %s: %s\n\n", r.Meta.ID, r.Info.Title)
			w("* **Finding type:** `%s`\n", r.Kind)
			w("* **Collection:** %s\n", r.Meta.Mode)
			w("* **Triggered when:** %s\n", r.Meta.Trigger)
			w("* **Severity:** %s\n", r.Meta.Severity)
			w("* **Evidence:** %s\n", r.Info.Source)
			w("* **Why it matters:** %s\n", r.Info.Risk)
			w("* **What to do:** %s\n\n", r.Info.Solution)
		}
	}

	w("## Detection tables\n\n")

	w("### Login portals and admin consoles (EASM-WEB-001)\n\n")
	w("Recognised on the home page by the product's page title or header, and at the product's own sign-in page when exposed-file checks are on. A match needs the product's wording, so a page that answers every path does not count.\n\n")
	w("| Product | Category | Severity | Where it is checked |\n|---|---|---|---|\n")
	for _, s := range portalSigs {
		where := "Home page"
		if s.Path != "" {
			where = "`" + s.Path + "`"
			if s.Header != "" {
				where += " (or the `" + s.Header + "` header on any page)"
			}
		}
		w("| %s | %s | %s | %s |\n", cell(s.Name), s.Category, titleCase(s.Severity), where)
	}
	w("\n")

	w("### Sensitive files and pages (EASM-WEB-002)\n\n")
	w("Each path is reported only when it answers 200 and its content passes the file's own test, so a site that answers every path with its home page produces nothing. Secret values are never copied into findings.\n\n")
	w("| Path | Severity | What it exposes |\n|---|---|---|\n")
	w("| `/` (directory listing) | Medium | directory listing is switched on, so anyone can browse and download the files in this folder |\n")
	for _, p := range sensitivePaths {
		w("| `%s` | %s | %s |\n", p.Path, titleCase(p.Severity), cell(p.Why))
	}
	w("\n")

	w("### Default pages (EASM-WEB-003)\n\n| Page | Recognised by |\n|---|---|\n")
	for _, d := range defaultPages {
		w("| %s | `%s` |\n", cell(d.Name), cell(d.Needle))
	}
	w("\n")

	w("### Risky ports (EASM-EXP-001)\n\nOther open ports are recorded in the inventory but are not findings.\n\n| Port | Service | Severity |\n|---|---|---|\n")
	var ports []int
	for p := range riskyPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		sev := "Medium"
		if highRiskPorts[p] {
			sev = "High"
		}
		w("| %d | %s | %s |\n", p, cell(riskyPorts[p]), sev)
	}
	w("\n")

	w("### Subdomain-takeover platforms (EASM-DNS-001)\n\nA dangling CNAME to one of these is High, because anyone can claim the unused name there:\n\n")
	sufs := append([]string(nil), takeoverSuffixes...)
	sort.Strings(sufs)
	w("`%s`\n\n", strings.Join(sufs, "`, `"))

	w("### Managed datastores (EASM-CLOUD-003)\n\n| DNS suffix | Service |\n|---|---|\n")
	for _, s := range datastoreSigs {
		w("| `%s` | %s |\n", s.Suffix, cell(s.Provider))
	}
	w("\n")

	w("### DKIM selectors tried (EASM-MAIL-012)\n\n`%s`\n\n", strings.Join(commonSelectors, "`, `"))

	w("### Look-alike techniques (EASM-BRAND-001)\n\n")
	w("Variations are generated locally and only looked up in DNS:\n\n")
	w("* typos: a missing, repeated or swapped letter, a neighbouring key (QWERTY), a changed vowel, an added hyphen\n")
	w("* bitsquatting: one bit different in a letter\n")
	var gl []string
	for _, g := range glyphs {
		gl = append(gl, g[0]+"→"+g[1])
	}
	w("* look-alike characters: %s\n", strings.Join(gl, ", "))
	var cy []string
	for _, k := range sortedRunes(confusable) {
		cy = append(cy, fmt.Sprintf("%c→%c", k, confusable[k]))
	}
	w("* Cyrillic homoglyphs (internationalised domain names): %s\n", strings.Join(cy, ", "))
	w("* added words (`name-word`, `word-name`, `nameword`): `%s`\n", strings.Join(affixes, "`, `"))
	w("* other endings: `.%s`\n\n", strings.Join(otherTLDs, "`, `."))

	w("## Inventory signatures (not findings)\n\nThese identify the cloud and SaaS services the organisation uses, from DNS answers the scan already holds. New services raise an inventory event, not a finding.\n\n")
	sigTable := func(title string, sigs []cloudSig) {
		w("### %s\n\n| Match | Service | Category |\n|---|---|---|\n", title)
		for _, s := range sigs {
			w("| `%s` | %s | %s |\n", s.Suffix, cell(s.Provider), s.Category)
		}
		w("\n")
	}
	sigTable("CNAME targets", cnameSigs)
	sigTable("SPF include: domains", spfSigs)
	sigTable("MX hosts", mxSigs)
	w("### Domain-verification TXT records\n\n| Prefix | Service | Category |\n|---|---|---|\n")
	for _, s := range txtSigs {
		w("| `%s` | %s | %s |\n", s.Prefix, cell(s.Provider), s.Category)
	}
	return b.String()
}

func sortedRunes(m map[rune]rune) []rune {
	var out []rune
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
