package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file adds the "management view" to a Report: an executive summary, new and resolved findings,
// and the findings grouped by asset and by finding name. The numbers behind the summary always cover
// every finding; the severity filter narrows only the detail sections.

// ReportOpts narrows the detail sections of a report.
type ReportOpts struct {
	Sev map[string]bool // severities to show; nil means all
}

func (o ReportOpts) allows(sev string) bool { return o.Sev == nil || o.Sev[strings.ToLower(sev)] }

// Label describes the filter for headings ("All severities" or "High, medium").
func (o ReportOpts) Label() string {
	if o.Sev == nil {
		return "All severities"
	}
	var out []string
	for _, s := range []string{"high", "medium", "low", "info"} {
		if o.Sev[s] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "All severities"
	}
	l := strings.Join(out, ", ")
	return strings.ToUpper(l[:1]) + l[1:] + " only"
}

// ParseSeverityFilter builds options from request values; unknown values are ignored and an empty or
// complete selection means "all".
func ParseSeverityFilter(vals []string) ReportOpts {
	set := map[string]bool{}
	for _, v := range vals {
		v = strings.ToLower(strings.TrimSpace(v))
		if _, ok := severityRank[v]; ok {
			set[v] = true
		}
	}
	if len(set) == 0 || len(set) == len(severityRank) {
		return ReportOpts{}
	}
	return ReportOpts{Sev: set}
}

// Query returns the filter as URL query pairs ("sev=high&sev=medium"), or "" for all.
func (o ReportOpts) Query() string {
	if o.Sev == nil {
		return ""
	}
	var q []string
	for _, s := range []string{"high", "medium", "low", "info"} {
		if o.Sev[s] {
			q = append(q, "sev="+s)
		}
	}
	return strings.Join(q, "&")
}

// Has reports whether severity s is selected (used by the filter checkboxes).
func (o ReportOpts) Has(s string) bool { return o.Sev == nil || o.Sev[s] }

// ExecSummary is the one-page view for a non-technical reader.
type ExecSummary struct {
	Score       int    // 0-100, higher is better
	Rating      string // Good | Fair | Poor
	RatingClass string // good | warn | bad (CSS)
	Headline    string
	Domains     int
	Hosts       int
	Open        int
	OpenBySev   map[string]int
	Accepted    int
	Unconfirmed int // open findings from one third-party source only: left out of the counts and lists
	NewCount    int
	NewHigh     int
	Resolved    int
	TopRisks    []TopRisk
	Actions     []string
	Trend       []TrendBucket
	Categories  []CatCount
	TopAssets   []AssetCount
}

// TopRisk is one line of the "biggest risks" table.
type TopRisk struct {
	Title    string
	Severity string
	Assets   int
	Risk     string // first sentence of the plain-language risk
	Fix      string // first sentence of the recommended fix
}

// TrendBucket is a day or week of the trend chart.
type TrendBucket struct {
	Label         string
	New, Resolved int
}

// CatCount is the number of open findings in one category.
type CatCount struct {
	Name  string
	Count int
	High  int
}

// AssetCount is the number of open findings on one asset.
type AssetCount struct {
	Host  string
	Count int
	Max   string
}

// AssetGroup lists the findings of one host.
type AssetGroup struct {
	Host     string
	Root     string
	Max      string
	Findings []Finding
}

// FindingGroup lists every asset affected by one kind of finding.
type FindingGroup struct {
	Title    string
	Severity string // the worst severity in the group
	Info     FindingInfo
	Items    []Finding
	Assets   int
}

// findingCategory groups finding kinds the way a manager thinks about them.
func findingCategory(kind string) string {
	switch {
	case kind == "email-auth":
		return "Email security"
	case strings.HasPrefix(kind, "tls-"), kind == "domain-expiry":
		return "Certificates & TLS"
	case kind == "dangling-cname", kind == "bucket-takeover", kind == "bucket-public", kind == "cloud-datastore":
		return "Take-over & cloud storage"
	case kind == "exposed-service", kind == "known-vuln", kind == "eol-software", kind == "ip-flagged":
		return "Exposed services & software"
	case kind == "asn-unexpected", kind == "private-ip":
		return "Ownership & network"
	case kind == "lookalike-domain", kind == "leaked-credentials", kind == "repo-exposure":
		return "Brand & data leakage"
	case kind == "default-page", kind == "exposed-path", kind == "no-https-redirect":
		return "Web applications"
	}
	return "Other"
}

// firstSentence shortens a paragraph to its first sentence for tables.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}

// enrichReport fills the management view. all holds every finding of the scope in any state.
func enrichReport(rep *Report, all []Finding, since time.Time, opts ReportOpts) {
	sinceStr := since.UTC().Format(time.RFC3339)
	var open, newF, resolved []Finding
	ex := &rep.Exec
	ex.OpenBySev = map[string]int{}
	for _, f := range all {
		if f.Status == "open" && (f.Trust == trustUnconfirmed || f.Trust == trustDisputed) {
			ex.Unconfirmed++ // not reported until a second source agrees (trust.go)
			continue
		}
		switch f.Status {
		case "open":
			open = append(open, f)
			ex.OpenBySev[strings.ToLower(f.Severity)]++
		case "ack":
			ex.Accepted++
		case "resolved":
			if f.LastSeen >= sinceStr {
				resolved = append(resolved, f)
			}
		}
		if f.FirstSeen >= sinceStr {
			newF = append(newF, f)
		}
	}
	ex.Open, ex.NewCount, ex.Resolved = len(open), len(newF), len(resolved)
	for _, f := range newF {
		if strings.EqualFold(f.Severity, "high") {
			ex.NewHigh++
		}
	}
	for _, t := range rep.Targets {
		ex.Domains++
		ex.Hosts += t.Hosts
	}

	// score and rating: transparent, so a reader can see why
	h, m, l := ex.OpenBySev["high"], ex.OpenBySev["medium"], ex.OpenBySev["low"]
	ex.Score = 100 - 12*minInt(h, 6) - 4*minInt(m, 10) - minInt(l, 10)
	if ex.Score < 0 {
		ex.Score = 0
	}
	switch {
	case h >= 2:
		ex.Rating, ex.RatingClass = "Poor", "bad"
	case h == 1 || m > 0:
		ex.Rating, ex.RatingClass = "Fair", "warn"
	default:
		ex.Rating, ex.RatingClass = "Good", "good"
	}

	// groups over the open findings, honouring the filter
	var shown []Finding
	for _, f := range open {
		if opts.allows(f.Severity) {
			shown = append(shown, f)
		}
	}
	rep.ByFinding = groupByFinding(shown)
	rep.ByAsset = groupByAsset(shown)
	// the headline groups always use every open finding
	allGroups := groupByFinding(open)
	for i, g := range allGroups {
		if i == 5 {
			break
		}
		ex.TopRisks = append(ex.TopRisks, TopRisk{Title: g.Title, Severity: g.Severity, Assets: g.Assets,
			Risk: firstSentence(g.Info.Risk), Fix: firstSentence(g.Info.Solution)})
	}
	for i, g := range allGroups {
		if i == 3 {
			break
		}
		ex.Actions = append(ex.Actions, fmt.Sprintf("%s (%d asset%s): %s", g.Title, g.Assets, plural(g.Assets), firstSentence(g.Info.Solution)))
	}
	cat := map[string]*CatCount{}
	assets := map[string]*AssetCount{}
	for _, f := range open {
		c := findingCategory(f.Kind)
		if cat[c] == nil {
			cat[c] = &CatCount{Name: c}
		}
		cat[c].Count++
		if strings.EqualFold(f.Severity, "high") {
			cat[c].High++
		}
		a := hostOrRoot(f)
		if assets[a] == nil {
			assets[a] = &AssetCount{Host: a, Max: f.Severity}
		}
		assets[a].Count++
		if sevRank(f.Severity) > sevRank(assets[a].Max) {
			assets[a].Max = f.Severity
		}
	}
	for _, c := range cat {
		ex.Categories = append(ex.Categories, *c)
	}
	sort.Slice(ex.Categories, func(i, j int) bool {
		if ex.Categories[i].Count != ex.Categories[j].Count {
			return ex.Categories[i].Count > ex.Categories[j].Count
		}
		return ex.Categories[i].Name < ex.Categories[j].Name
	})
	for _, a := range assets {
		ex.TopAssets = append(ex.TopAssets, *a)
	}
	sort.Slice(ex.TopAssets, func(i, j int) bool {
		a, b := ex.TopAssets[i], ex.TopAssets[j]
		if sevRank(a.Max) != sevRank(b.Max) {
			return sevRank(a.Max) > sevRank(b.Max)
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Host < b.Host
	})
	if len(ex.TopAssets) > 8 {
		ex.TopAssets = ex.TopAssets[:8]
	}
	ex.Trend = trendBuckets(all, since, rep.Generated)

	ex.Headline = headline(ex, rep.Days)

	// detail lists honour the filter
	rep.Findings = rep.Findings[:0]
	for _, f := range open {
		if opts.allows(f.Severity) {
			rep.Findings = append(rep.Findings, f)
		}
	}
	rep.NewFindings = filterFindings(newF, opts)
	rep.ResolvedFindings = filterFindings(resolved, opts)
	sort.SliceStable(rep.NewFindings, func(i, j int) bool {
		return sevRank(rep.NewFindings[i].Severity) > sevRank(rep.NewFindings[j].Severity)
	})
	sort.SliceStable(rep.ResolvedFindings, func(i, j int) bool { return rep.ResolvedFindings[i].LastSeen > rep.ResolvedFindings[j].LastSeen })
	rep.Filter = opts
}

func filterFindings(in []Finding, opts ReportOpts) []Finding {
	var out []Finding
	for _, f := range in {
		if opts.allows(f.Severity) {
			out = append(out, f)
		}
	}
	return out
}

func hostOrRoot(f Finding) string {
	if f.Host != "" {
		return f.Host
	}
	return f.Root
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func headline(ex *ExecSummary, days int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d domain%s and %d host%s are being monitored. ", ex.Domains, plural(ex.Domains), ex.Hosts, plural(ex.Hosts))
	switch {
	case ex.Open == 0:
		b.WriteString("There is nothing that needs attention right now. ")
	case ex.OpenBySev["high"] > 0:
		fmt.Fprintf(&b, "%d open finding%s need%s attention, %d of them high severity and worth fixing first. ", ex.Open, plural(ex.Open), map[bool]string{true: "s", false: ""}[ex.Open == 1], ex.OpenBySev["high"])
	default:
		fmt.Fprintf(&b, "%d open finding%s, none of them high severity. ", ex.Open, plural(ex.Open))
	}
	period := fmt.Sprintf("the last %d days", days)
	if days == 1 {
		period = "the last 24 hours"
	}
	fmt.Fprintf(&b, "In %s, %d new finding%s appeared (%d high) and %d %s fixed.", period, ex.NewCount, plural(ex.NewCount), ex.NewHigh, ex.Resolved,
		map[bool]string{true: "was", false: "were"}[ex.Resolved == 1])
	if ex.Unconfirmed > 0 {
		fmt.Fprintf(&b, " %d more finding%s from a single exposure-data source %s left out until a second source confirms %s.", ex.Unconfirmed, map[bool]string{true: "", false: "s"}[ex.Unconfirmed == 1], map[bool]string{true: "is", false: "are"}[ex.Unconfirmed == 1], map[bool]string{true: "it", false: "them"}[ex.Unconfirmed == 1])
	}
	if ex.Accepted > 0 {
		fmt.Fprintf(&b, " %d risk%s knowingly accepted.", ex.Accepted, map[bool]string{true: " is", false: "s are"}[ex.Accepted == 1])
	}
	return b.String()
}

func groupByFinding(in []Finding) []FindingGroup {
	idx := map[string]*FindingGroup{}
	var order []string
	for _, f := range in {
		info := describeFinding(f)
		g := idx[info.Title]
		if g == nil {
			g = &FindingGroup{Title: info.Title, Severity: f.Severity, Info: info}
			idx[info.Title] = g
			order = append(order, info.Title)
		}
		g.Items = append(g.Items, f)
		if sevRank(f.Severity) > sevRank(g.Severity) {
			g.Severity = f.Severity
		}
	}
	out := make([]FindingGroup, 0, len(order))
	for _, k := range order {
		g := idx[k]
		set := map[string]bool{}
		for _, f := range g.Items {
			set[hostOrRoot(f)] = true
		}
		g.Assets = len(set)
		sort.SliceStable(g.Items, func(i, j int) bool {
			if sevRank(g.Items[i].Severity) != sevRank(g.Items[j].Severity) {
				return sevRank(g.Items[i].Severity) > sevRank(g.Items[j].Severity)
			}
			return hostOrRoot(g.Items[i]) < hostOrRoot(g.Items[j])
		})
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		if out[i].Assets != out[j].Assets {
			return out[i].Assets > out[j].Assets
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func groupByAsset(in []Finding) []AssetGroup {
	idx := map[string]*AssetGroup{}
	for _, f := range in {
		h := hostOrRoot(f)
		g := idx[h]
		if g == nil {
			g = &AssetGroup{Host: h, Root: f.Root, Max: f.Severity}
			idx[h] = g
		}
		g.Findings = append(g.Findings, f)
		if sevRank(f.Severity) > sevRank(g.Max) {
			g.Max = f.Severity
		}
	}
	out := make([]AssetGroup, 0, len(idx))
	for _, g := range idx {
		sort.SliceStable(g.Findings, func(i, j int) bool { return sevRank(g.Findings[i].Severity) > sevRank(g.Findings[j].Severity) })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if sevRank(out[i].Max) != sevRank(out[j].Max) {
			return sevRank(out[i].Max) > sevRank(out[j].Max)
		}
		if len(out[i].Findings) != len(out[j].Findings) {
			return len(out[i].Findings) > len(out[j].Findings)
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// trendBuckets counts new and resolved findings per day (short periods) or per week.
func trendBuckets(all []Finding, since, end time.Time) []TrendBucket {
	span := end.Sub(since)
	step := 24 * time.Hour
	if span > 14*24*time.Hour {
		step = 7 * 24 * time.Hour
	}
	if span < time.Hour {
		span = time.Hour
	}
	n := int((span + step/2) / step) // the last bucket absorbs any remainder
	if n < 1 {
		n = 1
	}
	if n > 60 {
		n = 60
	}
	out := make([]TrendBucket, n)
	for i := range out {
		out[i].Label = since.Add(time.Duration(i) * step).Local().Format("02 Jan")
	}
	at := func(ts string) int {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || t.Before(since) || t.After(end.Add(time.Minute)) {
			return -1
		}
		i := int(t.Sub(since) / step)
		if i >= n {
			i = n - 1
		}
		return i
	}
	for _, f := range all {
		if i := at(f.FirstSeen); i >= 0 {
			out[i].New++
		}
		if f.Status == "resolved" {
			if i := at(f.LastSeen); i >= 0 {
				out[i].Resolved++
			}
		}
	}
	return out
}
