// Command easm-agent is a single-binary External Attack Surface Management daemon: it discovers
// the public footprint of the domains you enter (subdomains, certificates, DNS, IP ownership,
// exposed services), stores it in an encrypted local database, shows it in a web interface and
// emails you only what changed.
package main

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// FlushAlerts sends all queued (un-notified) events. Events are only marked notified
// after the SMTP transaction succeeds, so a failed send is retried next cycle.
func (s *Scanner) FlushAlerts(ctx context.Context) {
	events, err := s.store.PendingEvents()
	if err != nil {
		s.log.Error("reading pending events failed", "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	maxSev := 0
	for _, e := range events {
		if r := sevRank(e.Severity); r > maxSev {
			maxSev = r
		}
	}
	if len(events) < s.cfg.Alerts.MinEvents && maxSev < sevRank(s.cfg.Alerts.ImmediateSeverity) {
		s.log.Info("pending events below alert threshold; holding", "pending", len(events), "min_events", s.cfg.Alerts.MinEvents)
		return
	}
	maxID := events[len(events)-1].ID

	if !s.cfg.SMTP.Enabled {
		for _, e := range events {
			s.log.Warn("ALERT (smtp disabled)", "severity", e.Severity, "type", e.Kind, "domain", e.Root, "host", e.Host, "detail", e.Detail)
		}
		if err := s.store.MarkNotified(maxID); err != nil {
			s.log.Error("marking events notified failed", "err", err)
		}
		return
	}

	subject, plain, htmlBody := renderAlert(events, s.cfg)
	sctx, cancel := context.WithTimeout(ctx, 3*s.cfg.SMTP.Timeout)
	defer cancel()
	if err := s.mailer.Send(sctx, subject, plain, htmlBody); err != nil {
		s.log.Error("alert delivery failed; events stay queued and will be retried", "events", len(events), "err", err)
		return
	}
	if err := s.store.MarkNotified(maxID); err != nil {
		s.log.Error("marking events notified failed (duplicates possible next cycle)", "err", err)
		return
	}
	s.log.Info("alert email sent", "events", len(events), "subject", subject)
}

// sendBaselineSummary emails a one-off inventory summary when a domain's first (silent) scan completes, so the operator knows monitoring is live.
func (s *Scanner) sendBaselineSummary(ctx context.Context, root string) {
	st := s.stats
	if !s.cfg.SMTP.Enabled || !s.cfg.Alerts.SendBaselineSummary {
		return
	}
	plain := fmt.Sprintf("EASM baseline established for %s.\n\nHosts tracked: %d\nSubdomains: %d\nDNS records: %d\nCertificates: %d\n\nFrom now on you will only be emailed about changes.\n",
		root, st.Hosts, st.Subdomains, st.Records, st.Certs)
	htmlBody := "<p>" + strings.ReplaceAll(html.EscapeString(plain), "\n", "<br>") + "</p>"
	sctx, cancel := context.WithTimeout(ctx, 3*s.cfg.SMTP.Timeout)
	defer cancel()
	if err := s.mailer.Send(sctx, fmt.Sprintf("%s baseline established for %s", s.cfg.SMTP.SubjectPrefix, root), plain, htmlBody); err != nil {
		s.log.Warn("baseline summary email failed", "domain", root, "err", err)
	}
}

type mailRow struct {
	Severity, Kind, Root, Host, Detail string
	Color                              template.CSS
}

// mailGroup is the changes of one host, shown together under a heading that links to the host in the web interface.
type mailGroup struct {
	Host, Link, Severity string
	Color                template.CSS
	Rows                 []mailRow
}
type kindCount struct {
	Kind  string `json:"type"`
	Count int    `json:"count"`
}
type mailData struct {
	Agent, Generated, MaxSeverity string
	Total, Roots, Omitted         int
	Summary                       []kindCount
	Groups                        []mailGroup
	EventsURL, FindingsURL        string
}

var sevColor = map[string]template.CSS{"high": "#b42318", "medium": "#b54708", "low": "#1d4ed8", "info": "#52606d"}

const htmlTemplate = `<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2933">
<h2 style="margin:0 0 4px 0">EASM: {{.Total}} new external asset change{{if ne .Total 1}}s{{end}}</h2>
<p style="margin:0 0 16px 0;color:#52606d">{{.Roots}} domain(s) &middot; highest severity <b>{{.MaxSeverity}}</b> &middot; {{.Generated}} &middot; agent {{.Agent}}</p>
{{if .EventsURL}}<p style="margin:0 0 16px 0"><a href="{{.EventsURL}}">Open the changes in EASM</a>{{if .FindingsURL}} &middot; <a href="{{.FindingsURL}}">Open findings</a>{{end}}</p>{{end}}
<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;margin-bottom:18px">
<tr style="background:#f0f4f8"><th align="left" style="border:1px solid #d9e2ec">Type</th><th align="right" style="border:1px solid #d9e2ec">Count</th></tr>
{{range .Summary}}<tr><td style="border:1px solid #d9e2ec">{{.Kind}}</td><td align="right" style="border:1px solid #d9e2ec">{{.Count}}</td></tr>
{{end}}</table>
{{range .Groups}}<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;margin-bottom:14px">
<tr style="background:#f0f4f8"><th colspan="3" align="left" style="border:1px solid #d9e2ec;font-family:Consolas,monospace"><span style="color:{{.Color}}">&#9632;</span> {{if .Link}}<a href="{{.Link}}">{{.Host}}</a>{{else}}{{.Host}}{{end}}</th></tr>
{{range .Rows}}<tr><td style="border:1px solid #d9e2ec;font-weight:bold;color:{{.Color}};white-space:nowrap">{{.Severity}}</td><td style="border:1px solid #d9e2ec;white-space:nowrap">{{.Kind}}</td><td style="border:1px solid #d9e2ec;font-family:Consolas,monospace;font-size:12px">{{.Detail}}</td></tr>
{{end}}</table>
{{end}}{{if .Omitted}}<p style="color:#52606d">…and {{.Omitted}} more event(s) omitted from this email{{if .EventsURL}} (see <a href="{{.EventsURL}}">the Events page</a>){{else}} (see agent logs / database){{end}}.</p>{{end}}
</body></html>`

var htmlTpl = template.Must(template.New("mail").Parse(htmlTemplate))

// renderAlert builds the plain-text and HTML alert email for a batch of events, with a severity summary and one row per change (capped by AlertMaxRows).
func renderAlert(events []Event, cfg *Config) (subject, plain, htmlBody string) {
	sorted := append([]Event(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if ra, rb := sevRank(a.Severity), sevRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Kind < b.Kind
	})

	roots := map[string]bool{}
	counts := map[string]int{}
	maxSev := "info"
	for _, e := range sorted {
		roots[e.Root] = true
		counts[e.Kind]++
		if sevRank(e.Severity) > sevRank(maxSev) {
			maxSev = e.Severity
		}
	}
	var summary []kindCount
	for k, c := range counts {
		summary = append(summary, kindCount{k, c})
	}
	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count != summary[j].Count {
			return summary[i].Count > summary[j].Count
		}
		return summary[i].Kind < summary[j].Kind
	})

	shown := sorted
	omitted := 0
	if len(shown) > cfg.Alerts.MaxRows {
		omitted = len(shown) - cfg.Alerts.MaxRows
		shown = shown[:cfg.Alerts.MaxRows]
	}
	base := strings.TrimRight(cfg.PublicURL, "/")
	agent, _ := os.Hostname()
	data := mailData{Agent: agent, Generated: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		MaxSeverity: strings.ToUpper(maxSev), Total: len(sorted), Roots: len(roots), Omitted: omitted, Summary: summary}
	if base != "" {
		data.EventsURL, data.FindingsURL = base+"/events", base+"/findings"
	}
	// One group per host, worst first: the reader sees which machines need attention, not a flat list of lines.
	idx := map[string]int{}
	for _, e := range shown {
		key := e.Host
		if key == "" {
			key = e.Root
		}
		gi, ok := idx[key]
		if !ok {
			g := mailGroup{Host: key, Severity: strings.ToUpper(e.Severity), Color: sevColor[strings.ToLower(e.Severity)]}
			if base != "" && inScope(key, e.Root) {
				g.Link = base + "/assets/view?" + url.Values{"type": {"domain"}, "id": {key}}.Encode()
			}
			data.Groups = append(data.Groups, g)
			gi = len(data.Groups) - 1
			idx[key] = gi
		}
		data.Groups[gi].Rows = append(data.Groups[gi].Rows, mailRow{Severity: strings.ToUpper(e.Severity), Kind: e.Kind, Root: e.Root, Host: key,
			Detail: e.Detail, Color: sevColor[strings.ToLower(e.Severity)]})
	}

	subject = fmt.Sprintf("%s %d new asset change(s) across %d domain(s) - highest severity %s",
		cfg.SMTP.SubjectPrefix, data.Total, data.Roots, data.MaxSeverity)

	var hb bytes.Buffer
	if err := htmlTpl.Execute(&hb, data); err != nil {
		hb.Reset()
		hb.WriteString("<p>HTML rendering failed; see plain-text part.</p>")
	}

	var pb bytes.Buffer
	_, _ = fmt.Fprintf(&pb, "EASM: %d new external asset change(s) across %d domain(s)\nHighest severity: %s | %s | agent %s\n",
		data.Total, data.Roots, data.MaxSeverity, data.Generated, data.Agent)
	if data.EventsURL != "" {
		_, _ = fmt.Fprintf(&pb, "Changes: %s\nFindings: %s\n", data.EventsURL, data.FindingsURL)
	}
	pb.WriteString("\nSummary:\n")
	for _, k := range summary {
		_, _ = fmt.Fprintf(&pb, "  %-18s %d\n", k.Kind, k.Count)
	}
	for _, g := range data.Groups {
		_, _ = fmt.Fprintf(&pb, "\n%s\n", g.Host)
		if g.Link != "" {
			_, _ = fmt.Fprintf(&pb, "  %s\n", g.Link)
		}
		w := tabwriter.NewWriter(&pb, 0, 4, 2, ' ', 0)
		for _, r := range g.Rows {
			_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\n", r.Severity, r.Kind, r.Detail)
		}
		_ = w.Flush()
	}
	if omitted > 0 {
		_, _ = fmt.Fprintf(&pb, "\n...and %d more event(s) omitted.\n", omitted)
	}
	return subject, pb.String(), hb.String()
}
