package main

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- system health

// healthRow is one connector row on the System health page.
type healthRow struct {
	ID, Group, Label, What, Probe string
	State, StateLabel             string
	LastOK, LastFail              string
	LastError, Note, Via          string
	LatencyMs                     int64
	OK, Fail                      int
	Seen                          bool
}

type healthGroup struct {
	Name string
	Rows []healthRow
}

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// healthRowsLabels builds the connector table plus a map of connector id -> display name
// (used to label connection-log lines).
func (s *Server) healthRowsLabels() ([]healthGroup, map[string]int, map[string]string, error) {
	labels := map[string]string{}
	groups, counts, err := s.healthRows2(labels)
	return groups, counts, labels, err
}

// healthRows2 evaluates every connector and groups the rows for display.
func (s *Server) healthRows2(labels map[string]string) ([]healthGroup, map[string]int, error) {
	st, err := s.store.LoadSettings()
	if err != nil {
		return nil, nil, err
	}
	have := map[string]bool{
		secretShodan: s.eng.HasSecret(secretShodan), secretCensys: s.eng.HasSecret(secretCensys), secretVT: s.eng.HasSecret(secretVT),
		secretHIBP: s.eng.HasSecret(secretHIBP), secretGitHub: s.eng.HasSecret(secretGitHub),
	}
	var conns []Connector
	for _, c := range Connectors(st, have) {
		if c.ID == "dns" { // one row per resolver
			for _, r := range st.DNSResolvers {
				conns = append(conns, Connector{ID: "dns:" + r, Group: c.Group, Label: "DNS resolver", What: r, Enabled: true, Probe: c.Probe})
			}
			continue
		}
		conns = append(conns, c)
	}
	counts := map[string]int{}
	var groups []healthGroup
	idx := map[string]int{}
	for _, c := range conns {
		labels[c.ID] = c.Label
		if strings.HasPrefix(c.ID, "dns:") {
			labels[c.ID] = "DNS resolver " + c.What
		}
		it, seen := s.eng.Health().Get(c.ID)
		state, label := c.Status(it, seen)
		counts[state]++
		row := healthRow{ID: c.ID, Group: c.Group, Label: c.Label, What: c.What, Probe: c.Probe, State: state, StateLabel: label,
			LastOK: rfc(it.LastOK), LastFail: rfc(it.LastFail), LastError: it.LastError, Note: it.Note, Via: it.Via,
			LatencyMs: it.LatencyMs, OK: it.OKCount, Fail: it.FailCount, Seen: seen}
		if state == "good" {
			row.LastError = "" // an old error is noise once the connector works again
		}
		i, ok := idx[c.Group]
		if !ok {
			i = len(groups)
			idx[c.Group] = i
			groups = append(groups, healthGroup{Name: c.Group})
		}
		groups[i].Rows = append(groups[i].Rows, row)
	}
	return groups, counts, nil
}

// healthView renders System health, including the connection log.
func (s *Server) healthView(w http.ResponseWriter, r *http.Request, sess *Session) {
	groups, counts, labels, err := s.healthRowsLabels()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	conn := r.URL.Query().Get("connector")
	if _, ok := labels[conn]; !ok {
		conn = ""
	}
	failed := r.URL.Query().Get("failed") == "1"
	type logRow struct {
		LogEntry
		Label, Hint string
	}
	var log []logRow
	for _, e := range s.eng.Health().Log(conn, failed, 150) {
		l := labels[e.Name]
		if l == "" {
			l = e.Name
		}
		log = append(log, logRow{e, l, Hint(e.Error)})
	}
	type opt struct{ ID, Label string }
	var opts []opt
	for _, g := range groups {
		for _, row := range g.Rows {
			opts = append(opts, opt{row.ID, row.Label + ifStr(strings.HasPrefix(row.ID, "dns:"), " "+row.What)})
		}
	}
	s.render(w, r, sess, "health", http.StatusOK, map[string]any{
		"Title": "System health", "Nav": "health", "Groups": groups, "Counts": counts, "Sys": s.eng.SystemInfo(),
		"Log": log, "LogConn": conn, "LogFailed": failed, "LogOpts": opts,
	})
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	s.eng.RunHealthChecks(ctx)
	s.flash(sess, "good", "Connection checks finished.")
	http.Redirect(w, r, "/health", http.StatusSeeOther)
}

// ---------------------------------------------------------------- assets

// assetFilter reads and validates the Assets page filters.
func (s *Server) assetFilter(r *http.Request) (root, typ, q string, names []string, err error) {
	names, err = s.targetNames()
	if err != nil {
		return
	}
	v := r.URL.Query()
	root = validRoot(names, v.Get("target"))
	if t := v.Get("type"); validAssetType(t) {
		typ = t
	}
	q = strings.TrimSpace(v.Get("q"))
	if len(q) > 100 {
		q = q[:100]
	}
	return
}

// assets renders the Assets page.
func (s *Server) assets(w http.ResponseWriter, r *http.Request, sess *Session) {
	root, typ, q, names, err := s.assetFilter(r)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	list, counts, err := s.store.ListAssets(root, typ, q)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	total := len(list)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pages := (total + pageSize - 1) / pageSize
	if page < 1 {
		page = 1
	}
	if page > pages && pages > 0 {
		page = pages
	}
	lo, hi := (page-1)*pageSize, page*pageSize
	if lo > total {
		lo = total
	}
	if hi > total {
		hi = total
	}
	type tab struct {
		ID, Label string
		Count     int
		On        bool
		Query     string
	}
	grand := 0
	var tabs []tab
	base := url.Values{}
	if root != "" {
		base.Set("target", root)
	}
	if q != "" {
		base.Set("q", q)
	}
	for _, a := range assetTypes {
		grand += counts[a.ID]
		v := url.Values{}
		for k, vv := range base {
			v[k] = vv
		}
		v.Set("type", a.ID)
		tabs = append(tabs, tab{a.ID, a.Label, counts[a.ID], typ == a.ID, v.Encode()})
	}
	keep := url.Values{}
	for k, vv := range base {
		keep[k] = vv
	}
	if typ != "" {
		keep.Set("type", typ)
	}
	s.render(w, r, sess, "assets", http.StatusOK, map[string]any{
		"Title": "Assets", "Nav": "assets", "Assets": list[lo:hi], "Total": total, "Grand": grand, "Tabs": tabs,
		"Targets": names, "Target": root, "Type": typ, "Q": q, "Page": page, "Pages": pages,
		"BaseQuery": keep.Encode(), "AllQuery": base.Encode(),
	})
}

// assetsCSV exports the filtered assets as CSV.
func (s *Server) assetsCSV(w http.ResponseWriter, r *http.Request, sess *Session) {
	root, typ, q, _, err := s.assetFilter(r)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	list, _, err := s.store.ListAssets(root, typ, q)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-assets-`+time.Now().Format("20060102")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "asset", "entity", "details", "sources", "first_seen", "last_seen"})
	for _, a := range list {
		_ = cw.Write([]string{a.Type, csvSafe(a.Value), csvSafe(a.Root), csvSafe(a.Details), csvSafe(a.Sources), a.FirstSeen, a.LastSeen})
	}
	cw.Flush()
}

func ifStr(c bool, s string) string {
	if c {
		return s
	}
	return ""
}
