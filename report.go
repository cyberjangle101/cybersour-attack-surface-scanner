package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// TargetSummary is the per-domain row of a report.
type TargetSummary struct {
	ID           int64          `json:"id"`
	Domain       string         `json:"target"`
	Hosts        int            `json:"hosts"`
	NewHosts     int            `json:"new_hosts"`
	OpenFindings map[string]int `json:"open_findings"`
	Status       string         `json:"status"`
	LastScan     string         `json:"last_scan"`
	Baselined    bool           `json:"baselined"`
	Enabled      bool           `json:"enabled"`
}

// FindingTotal sums the open findings of a target.
func (t TargetSummary) FindingTotal() int {
	n := 0
	for _, c := range t.OpenFindings {
		n += c
	}
	return n
}

// Report is a point-in-time summary of one or all targets for a period.
type Report struct {
	Generated      time.Time       `json:"generated"`
	Since          time.Time       `json:"since"`
	Days           int             `json:"days"`
	Scope          string          `json:"scope"`
	Targets        []TargetSummary `json:"targets"`
	Findings       []Finding       `json:"-"` // exported through MarshalJSON as apiFinding
	AckedFindings  int             `json:"accepted_findings"`
	Changes        []Event         `json:"changes"`
	ChangeCounts   []kindCount     `json:"change_counts"`
	Inventory      []HostRow       `json:"inventory"`
	InventoryTotal int             `json:"inventory_total"`
	Certs          []CertRow       `json:"certificates"`
	CertTotal      int             `json:"certificates_total"`

	// Management view (see report_model.go); not part of the JSON export.
	Exec             ExecSummary    `json:"-"`
	NewFindings      []Finding      `json:"-"`
	ResolvedFindings []Finding      `json:"-"`
	ByAsset          []AssetGroup   `json:"-"`
	ByFinding        []FindingGroup `json:"-"`
	Filter           ReportOpts     `json:"-"`
}

// MarshalJSON writes the report with the same field names the CSV exports use.
func (r Report) MarshalJSON() ([]byte, error) {
	type plain Report
	out := struct {
		plain
		Findings []apiFinding `json:"findings"`
	}{plain: plain(r), Findings: apiFindings(r.Findings)}
	return json.Marshal(out)
}

// BuildReport assembles everything the report page, exports and digest email need.
// root=="" covers all targets. invLimit<=0 skips the host inventory (digest emails).
func BuildReport(st *Store, root string, since time.Time, invLimit int) (*Report, error) {
	return BuildReportOpts(st, root, since, invLimit, ReportOpts{})
}

// BuildReportOpts is BuildReport with a severity filter for the detail sections.
func BuildReportOpts(st *Store, root string, since time.Time, invLimit int, opts ReportOpts) (*Report, error) {
	rep := &Report{Generated: time.Now(), Since: since, Scope: "All targets", Days: int(time.Since(since).Hours()/24 + 0.5)}
	if root != "" {
		rep.Scope = root
	}
	targets, err := st.ListTargets()
	if err != nil {
		return nil, err
	}
	hostCounts, findCounts, err := st.TargetCounts()
	if err != nil {
		return nil, err
	}
	sinceStr := since.UTC().Format(time.RFC3339)
	changes, _, err := st.ListEvents(EventFilter{Root: root, Since: sinceStr, Limit: 5000})
	if err != nil {
		return nil, err
	}
	rep.Changes = changes
	newHosts := map[string]int{}
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Kind]++
		if c.Kind == "subdomain" {
			newHosts[c.Root]++
		}
	}
	for k, c := range counts {
		rep.ChangeCounts = append(rep.ChangeCounts, kindCount{k, c})
	}
	sort.Slice(rep.ChangeCounts, func(i, j int) bool {
		if rep.ChangeCounts[i].Count != rep.ChangeCounts[j].Count {
			return rep.ChangeCounts[i].Count > rep.ChangeCounts[j].Count
		}
		return rep.ChangeCounts[i].Kind < rep.ChangeCounts[j].Kind
	})
	for _, t := range targets {
		if root != "" && t.Domain != root {
			continue
		}
		rep.Targets = append(rep.Targets, TargetSummary{
			ID: t.ID, Domain: t.Domain, Hosts: hostCounts[t.Domain], NewHosts: newHosts[t.Domain],
			OpenFindings: findCounts[t.Domain], Status: t.LastStatus, LastScan: t.LastEnd, Baselined: t.Baselined(), Enabled: t.Enabled,
		})
	}
	all, err := st.ListFindings(root, "")
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if f.Status == "ack" {
			rep.AckedFindings++
		}
	}
	enrichReport(rep, all, since, opts) // also fills rep.Findings with the open findings that pass the filter
	if invLimit > 0 {
		if rep.Inventory, rep.InventoryTotal, err = st.Inventory(root, "", invLimit); err != nil {
			return nil, err
		}
		if rep.Certs, rep.CertTotal, err = st.ListCerts(root, 200); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s // neutralise spreadsheet formula injection
	}
	return s
}

// WriteInventoryCSV exports the host inventory.
func WriteInventoryCSV(w io.Writer, rep *Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"target", "host", "addresses", "asn_org", "cname", "sources", "first_seen", "last_seen"})
	for _, h := range rep.Inventory {
		var ips, orgs []string
		for _, a := range h.Addrs {
			ips = append(ips, a.IP)
			if a.ASN != 0 {
				orgs = append(orgs, fmt.Sprintf("AS%d %s", a.ASN, a.Org))
			}
		}
		_ = cw.Write([]string{csvSafe(h.Root), csvSafe(h.Host), csvSafe(strings.Join(ips, " ")), csvSafe(strings.Join(dedupe(orgs), " | ")),
			csvSafe(strings.Join(h.CNAMEs, " ")), csvSafe(h.Sources), h.FirstSeen, h.LastSeen})
	}
	cw.Flush()
	return cw.Error()
}

// WriteFindingsCSV exports open findings.
func WriteFindingsCSV(w io.Writer, rep *Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"severity", "type", "title", "target", "host", "detail", "source", "risk", "solution", "first_seen", "last_seen"})
	for _, f := range rep.Findings {
		i := describeFinding(f)
		_ = cw.Write([]string{f.Severity, f.Kind, csvSafe(i.Title), csvSafe(f.Root), csvSafe(f.Host), csvSafe(f.Detail),
			csvSafe(i.Source), csvSafe(i.Risk), csvSafe(i.Solution), f.FirstSeen, f.LastSeen})
	}
	cw.Flush()
	return cw.Error()
}

// ---------------------------------------------------------------- digest email

// digestData is the template data of the digest email.
type digestData struct {
	Agent, Generated, Scope, Period string
	Report                          *Report
	Findings                        []Finding
	Changes                         []Event
	OmittedChanges                  int
	TotalHosts, TotalFindings       int
	PublicURL                       string
	SevColor                        map[string]template.CSS
}

const digestHTML = `<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2933">
<h2 style="margin:0 0 4px 0">EASM report: {{.Scope}}</h2>
<p style="margin:0 0 16px 0;color:#52606d">{{.Period}} &middot; generated {{.Generated}} &middot; agent {{.Agent}}</p>
<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;margin-bottom:18px">
<tr style="background:#f0f4f8"><th align="left" style="border:1px solid #d9e2ec">Target</th><th align="right" style="border:1px solid #d9e2ec">Hosts</th><th align="right" style="border:1px solid #d9e2ec">New hosts</th><th align="right" style="border:1px solid #d9e2ec">Open findings</th><th align="left" style="border:1px solid #d9e2ec">Last scan</th></tr>
{{range .Report.Targets}}<tr><td style="border:1px solid #d9e2ec">{{.Domain}}</td><td align="right" style="border:1px solid #d9e2ec">{{.Hosts}}</td><td align="right" style="border:1px solid #d9e2ec">{{.NewHosts}}</td><td align="right" style="border:1px solid #d9e2ec">{{.FindingTotal}}</td><td style="border:1px solid #d9e2ec">{{.LastScan}}</td></tr>
{{end}}</table>
<h3 style="margin:18px 0 6px 0">Open findings ({{len .Findings}})</h3>
{{if .Findings}}<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">
<tr style="background:#f0f4f8"><th align="left" style="border:1px solid #d9e2ec">Severity</th><th align="left" style="border:1px solid #d9e2ec">Finding</th><th align="left" style="border:1px solid #d9e2ec">Source</th><th align="left" style="border:1px solid #d9e2ec">Risk</th><th align="left" style="border:1px solid #d9e2ec">Fix</th></tr>
{{range .Findings}}<tr><td style="border:1px solid #d9e2ec;font-weight:bold;color:{{index $.SevColor .Severity}}">{{.Severity}}</td><td style="border:1px solid #d9e2ec"><strong>{{(finfo .).Title}}</strong><br><span style="font-family:Consolas,monospace">{{.Host}}</span><br><span style="font-size:12px">{{.Detail}}</span></td><td style="border:1px solid #d9e2ec;font-size:12px">{{(finfo .).Source}}</td><td style="border:1px solid #d9e2ec;font-size:12px">{{(finfo .).Risk}}</td><td style="border:1px solid #d9e2ec;font-size:12px">{{(finfo .).Solution}}</td></tr>
{{end}}</table>{{else}}<p>None. Nothing needs attention.</p>{{end}}
<h3 style="margin:18px 0 6px 0">Changes in this period ({{len .Report.Changes}})</h3>
{{if .Report.ChangeCounts}}<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;margin-bottom:10px">
{{range .Report.ChangeCounts}}<tr><td style="border:1px solid #d9e2ec">{{.Kind}}</td><td align="right" style="border:1px solid #d9e2ec">{{.Count}}</td></tr>
{{end}}</table>{{else}}<p>No changes were detected.</p>{{end}}
{{if .Changes}}<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">
<tr style="background:#f0f4f8"><th align="left" style="border:1px solid #d9e2ec">When (UTC)</th><th align="left" style="border:1px solid #d9e2ec">Type</th><th align="left" style="border:1px solid #d9e2ec">Host</th><th align="left" style="border:1px solid #d9e2ec">Detail</th></tr>
{{range .Changes}}<tr><td style="border:1px solid #d9e2ec">{{.TS}}</td><td style="border:1px solid #d9e2ec">{{.Kind}}</td><td style="border:1px solid #d9e2ec;font-family:Consolas,monospace">{{.Host}}</td><td style="border:1px solid #d9e2ec;font-family:Consolas,monospace;font-size:12px">{{.Detail}}</td></tr>
{{end}}</table>{{end}}
{{if .OmittedChanges}}<p style="color:#52606d">…and {{.OmittedChanges}} more change(s) not shown. Open the dashboard for the full list.</p>{{end}}
{{if .PublicURL}}<p><a href="{{.PublicURL}}/report">Open the full report</a></p>{{end}}
</body></html>`

var digestTpl = template.Must(template.New("digest").Funcs(template.FuncMap{"finfo": describeFinding}).Parse(digestHTML))

// renderDigest builds the subject, plain-text and HTML bodies of the digest email.
func renderDigest(rep *Report, cfg *Config) (subject, plain, htmlBody string) {
	agent, _ := os.Hostname()
	maxChanges := cfg.Alerts.MaxRows
	d := digestData{
		Agent: agent, Generated: rep.Generated.UTC().Format("2006-01-02 15:04 UTC"), Scope: rep.Scope, Report: rep,
		Period:   fmt.Sprintf("last %d day(s)", rep.Days),
		Findings: rep.Findings, Changes: rep.Changes, PublicURL: cfg.PublicURL, SevColor: sevColor,
	}
	if len(d.Changes) > maxChanges {
		d.OmittedChanges = len(d.Changes) - maxChanges
		d.Changes = d.Changes[:maxChanges]
	}
	for _, t := range rep.Targets {
		d.TotalHosts += t.Hosts
		d.TotalFindings += t.FindingTotal()
	}
	var hb bytes.Buffer
	if err := digestTpl.Execute(&hb, d); err != nil {
		hb.Reset()
		hb.WriteString("<p>HTML rendering failed; see the plain-text part.</p>")
	}
	subject = fmt.Sprintf("%s report: %d host(s), %d open finding(s), %d change(s) in the last %d day(s)",
		cfg.SMTP.SubjectPrefix, d.TotalHosts, d.TotalFindings, len(rep.Changes), rep.Days)

	var pb bytes.Buffer
	_, _ = fmt.Fprintf(&pb, "EASM report: %s\n%s | generated %s | agent %s\n\n", rep.Scope, d.Period, d.Generated, agent)
	w := tabwriter.NewWriter(&pb, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TARGET\tHOSTS\tNEW\tOPEN FINDINGS\tLAST SCAN")
	for _, t := range rep.Targets {
		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n", t.Domain, t.Hosts, t.NewHosts, t.FindingTotal(), t.LastScan)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintf(&pb, "\nOpen findings (%d):\n", len(rep.Findings))
	for _, f := range rep.Findings {
		i := describeFinding(f)
		_, _ = fmt.Fprintf(&pb, "  [%s] %s - %s: %s\n      Source: %s\n      Risk:   %s\n      Fix:    %s\n", strings.ToUpper(f.Severity), i.Title, f.Host, f.Detail, i.Source, i.Risk, i.Solution)
	}
	_, _ = fmt.Fprintf(&pb, "\nChanges (%d):\n", len(rep.Changes))
	for _, c := range d.Changes {
		_, _ = fmt.Fprintf(&pb, "  %s  %-14s %s  %s\n", c.TS, c.Kind, c.Host, c.Detail)
	}
	if d.OmittedChanges > 0 {
		_, _ = fmt.Fprintf(&pb, "  ...and %d more not shown.\n", d.OmittedChanges)
	}
	return subject, pb.String(), hb.String()
}
