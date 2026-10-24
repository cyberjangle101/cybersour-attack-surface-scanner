package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Alert channels send changes to systems other than email: a generic webhook, Slack, Microsoft
// Teams, a syslog/SIEM collector, or a ticket in Jira. Each channel keeps its own position in the
// event log, so a channel that is down is retried without holding back or repeating the others.

const (
	chWebhook = "webhook"
	chSlack   = "slack"
	chTeams   = "teams"
	chSyslog  = "syslog"
	chJira    = "jira"
)

var channelKinds = []struct{ ID, Label string }{
	{chWebhook, "Generic webhook (JSON)"}, {chSlack, "Slack"}, {chTeams, "Microsoft Teams"},
	{chSyslog, "Syslog / SIEM (CEF)"}, {chJira, "Jira ticket"},
}

// ChannelCfg holds every kind's settings; only the fields of the channel's kind are used.
type ChannelCfg struct {
	URL         string `json:"url,omitempty"`    // webhook, Slack, Teams: the address; Jira: the site address
	Secret      string `json:"secret,omitempty"` // webhook: key for the X-EASM-Signature header
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	Addr        string `json:"addr,omitempty"`   // syslog: host:port
	Proto       string `json:"proto,omitempty"`  // syslog: udp | tcp
	Format      string `json:"format,omitempty"` // syslog: cef | json
	Project     string `json:"project,omitempty"`
	IssueType   string `json:"issue_type,omitempty"`
	User        string `json:"user,omitempty"`  // Jira: account email (Cloud); empty = bearer token
	Token       string `json:"token,omitempty"` // Jira: API token or personal access token
}

// Channel is one configured destination.
type Channel struct {
	ID                       int64
	Name, Kind, MinSev       string
	Enabled                  bool
	Cursor                   int64
	Cfg                      ChannelCfg
	LastTry, LastOK, LastErr string
	Created                  string
}

// Validate checks a channel before it is stored.
func (c *Channel) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 60 || strings.ContainsFunc(c.Name, func(r rune) bool { return r < 32 }) {
		return errors.New("give the channel a short name")
	}
	if !validSeverity(c.MinSev) {
		return errors.New("choose a minimum severity")
	}
	g := &c.Cfg
	g.URL = strings.TrimSpace(g.URL)
	switch c.Kind {
	case chWebhook, chSlack, chTeams:
		if err := checkHTTPURL(g.URL); err != nil {
			return err
		}
		if c.Kind == chWebhook && (g.HeaderName != "") != (g.HeaderValue != "") {
			return errors.New("give both the header name and its value, or neither")
		}
		if g.HeaderName != "" && !validHeaderName(g.HeaderName) {
			return errors.New("that header name is not valid")
		}
	case chSyslog:
		g.Addr = strings.TrimSpace(g.Addr)
		if h, p, err := net.SplitHostPort(g.Addr); err != nil || h == "" || p == "" {
			return errors.New("the syslog server must look like host:514")
		}
		if g.Proto != "udp" && g.Proto != "tcp" {
			return errors.New("choose UDP or TCP")
		}
		if g.Format != "cef" && g.Format != "json" {
			return errors.New("choose CEF or JSON")
		}
	case chJira:
		if err := checkHTTPURL(g.URL); err != nil {
			return err
		}
		if g.Project == "" || len(g.Project) > 20 || strings.ContainsAny(g.Project, " \"'") {
			return errors.New("enter the Jira project key, for example SEC")
		}
		if g.IssueType == "" {
			g.IssueType = "Task"
		}
		if g.Token == "" {
			return errors.New("enter the Jira API token")
		}
	default:
		return errors.New("unknown channel type")
	}
	return nil
}

func validSeverity(s string) bool { return s == "high" || s == "medium" || s == "low" || s == "info" }

func validHeaderName(n string) bool {
	if n == "" || len(n) > 60 {
		return false
	}
	for _, r := range n {
		if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("enter a full web address starting with https://")
	}
	return nil
}

// redactURL shows where a request went without the path or query, which often carry a secret token.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "the configured address"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// ---------------------------------------------------------------- store

func (s *Store) chanScan(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	var enabled int
	var cfg string
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &cfg, &c.MinSev, &enabled, &c.Cursor, &c.LastTry, &c.LastOK, &c.LastErr, &c.Created); err != nil {
		return nil, err
	}
	c.Enabled = enabled != 0
	plain, err := s.openHash(cfg)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(plain), &c.Cfg); err != nil {
		return nil, fmt.Errorf("channel %q: stored settings unreadable: %w", c.Name, err)
	}
	return &c, nil
}

const chanCols = `id,name,kind,cfg,min_sev,enabled,cursor,last_try,last_ok,last_err,created`

// ListChannels returns all channels.
func (s *Store) ListChannels() ([]*Channel, error) {
	rows, err := s.db.Query(`SELECT ` + chanCols + ` FROM channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []*Channel
	var firstErr error
	for rows.Next() {
		c, err := s.chanScan(rows)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, c)
	}
	_ = rows.Close()
	return out, firstErr
}

// GetChannel returns one channel.
func (s *Store) GetChannel(id int64) (*Channel, error) {
	return s.chanScan(s.db.QueryRow(`SELECT `+chanCols+` FROM channels WHERE id=?`, id))
}

// AddChannel stores a new channel. Its position starts at the newest event, so it sends only what happens from now on.
func (s *Store) AddChannel(c *Channel) (int64, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	b, err := json.Marshal(c.Cfg)
	if err != nil {
		return 0, err
	}
	sealed, err := s.sealHash(string(b))
	if err != nil {
		return 0, err
	}
	var cur int64
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM events`).Scan(&cur)
	res, err := s.db.Exec(`INSERT INTO channels(name,kind,cfg,min_sev,enabled,cursor,created) VALUES(?,?,?,?,?,?,?)`,
		c.Name, c.Kind, sealed, c.MinSev, 1, cur, nowUTC())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, errors.New("a channel with that name already exists")
		}
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteChannel removes a channel.
func (s *Store) DeleteChannel(id int64) error {
	_, err := s.db.Exec(`DELETE FROM channels WHERE id=?`, id)
	if err == nil {
		_, err = s.db.Exec(`DELETE FROM channel_tickets WHERE channel_id=?`, id)
	}
	return err
}

// SetChannelEnabled turns a channel on or off. Turning it on skips what happened while it was off.
func (s *Store) SetChannelEnabled(id int64, on bool) error {
	if on {
		_, err := s.db.Exec(`UPDATE channels SET enabled=1, cursor=(SELECT COALESCE(MAX(id),0) FROM events) WHERE id=?`, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE channels SET enabled=0 WHERE id=?`, id)
	return err
}

// ChannelResult records the outcome of a delivery attempt (cursor < 0 = unchanged).
func (s *Store) ChannelResult(id int64, cursor int64, errText string) {
	now := nowUTC()
	if errText == "" {
		if cursor >= 0 {
			_, _ = s.db.Exec(`UPDATE channels SET cursor=?, last_try=?, last_ok=?, last_err='' WHERE id=?`, cursor, now, now, id)
		} else {
			_, _ = s.db.Exec(`UPDATE channels SET last_try=?, last_ok=?, last_err='' WHERE id=?`, now, now, id)
		}
		return
	}
	_, _ = s.db.Exec(`UPDATE channels SET last_try=?, last_err=? WHERE id=?`, now, clip(errText, 300), id)
}

// EventsAfter returns alertable events newer than the cursor.
func (s *Store) EventsAfter(cursor int64, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT id, ts, root, kind, severity, host, detail FROM events WHERE id>? AND baseline=0 AND muted=0 ORDER BY id LIMIT ?`, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Root, &e.Kind, &e.Severity, &e.Host, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MaxEventID is the newest event id.
func (s *Store) MaxEventID() int64 {
	var n int64
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM events`).Scan(&n)
	return n
}

func (s *Store) ticketFor(ch int64, key string) (string, bool) {
	var t string
	if err := s.db.QueryRow(`SELECT ticket FROM channel_tickets WHERE channel_id=? AND dedupe=?`, ch, key).Scan(&t); err != nil {
		return "", false
	}
	return t, true
}

func (s *Store) saveTicket(ch int64, key, ticket string) {
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO channel_tickets(channel_id,dedupe,ticket,created) VALUES(?,?,?,?)`, ch, key, ticket, nowUTC())
}

// ---------------------------------------------------------------- delivery

// ChannelSender delivers batches to channels.
type ChannelSender struct {
	store     *Store
	log       interface{ Warn(string, ...any) }
	publicURL func() string
	client    *http.Client
	dialTO    time.Duration
}

func newChannelSender(store *Store, log interface{ Warn(string, ...any) }, publicURL func() string) *ChannelSender {
	return &ChannelSender{store: store, log: log, publicURL: publicURL, client: &http.Client{Timeout: 20 * time.Second}, dialTO: 10 * time.Second}
}

// DispatchAll sends new events to every enabled channel.
func (cs *ChannelSender) DispatchAll(ctx context.Context) {
	chans, err := cs.store.ListChannels()
	if err != nil {
		cs.log.Warn("reading alert channels failed", "err", err)
	}
	for _, c := range chans {
		if !c.Enabled || ctx.Err() != nil {
			continue
		}
		cs.dispatch(ctx, c)
	}
}

func (cs *ChannelSender) dispatch(ctx context.Context, c *Channel) {
	events, err := cs.store.EventsAfter(c.Cursor, 500)
	if err != nil {
		cs.log.Warn("reading events for a channel failed", "channel", c.Name, "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	last := events[len(events)-1].ID
	var send []Event
	for _, e := range events {
		if sevRank(e.Severity) >= sevRank(c.MinSev) {
			send = append(send, e)
		}
	}
	if len(send) == 0 {
		cs.store.ChannelResult(c.ID, last, "")
		return
	}
	if err := cs.Send(ctx, c, send); err != nil {
		cs.log.Warn("alert channel delivery failed; will retry", "channel", c.Name, "err", err)
		cs.store.ChannelResult(c.ID, -1, err.Error())
		return
	}
	cs.store.ChannelResult(c.ID, last, "")
}

// Send delivers one batch.
func (cs *ChannelSender) Send(ctx context.Context, c *Channel, events []Event) error {
	switch c.Kind {
	case chWebhook:
		return cs.sendWebhook(ctx, c, events)
	case chSlack:
		return cs.postJSON(ctx, c.Cfg.URL, nil, slackBody(events, cs.base()))
	case chTeams:
		return cs.postJSON(ctx, c.Cfg.URL, nil, teamsBody(events, cs.base()))
	case chSyslog:
		return cs.sendSyslog(ctx, c, events)
	case chJira:
		return cs.sendJira(ctx, c, events)
	}
	return errors.New("unknown channel type")
}

// SendTest delivers a clearly marked sample event.
func (cs *ChannelSender) SendTest(ctx context.Context, c *Channel) error {
	e := Event{ID: 0, TS: nowUTC(), Root: "example.com", Kind: "test", Severity: "info", Host: "test.example.com",
		Detail: "This is a test message from the EASM agent. Nothing is wrong."}
	if c.Kind == chJira {
		return cs.jiraCreate(ctx, c, e, "easm-test-"+nowUTC())
	}
	return cs.Send(ctx, c, []Event{e})
}

func (cs *ChannelSender) base() string {
	if cs.publicURL == nil {
		return ""
	}
	return strings.TrimRight(cs.publicURL(), "/")
}

func hostLink(base, host string) string {
	if base == "" || host == "" {
		return ""
	}
	return base + "/assets/view?" + url.Values{"type": {"domain"}, "id": {host}}.Encode()
}

func (cs *ChannelSender) postJSON(ctx context.Context, target string, hdr map[string]string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return cs.post(ctx, target, hdr, b)
}

func (cs *ChannelSender) post(ctx context.Context, target string, hdr map[string]string, b []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return errors.New("the web address is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "easm-agent/"+version)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cs.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL, which may carry a token
		}
		return fmt.Errorf("could not reach %s: %v", redactURL(target), err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered HTTP %d %s", redactURL(target), resp.StatusCode, strings.TrimSpace(clip(string(body), 120)))
	}
	return nil
}

// ---- webhook

type hookEvent struct {
	ID       int64  `json:"id"`
	Time     string `json:"time"`
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Detail   string `json:"detail"`
	Link     string `json:"link,omitempty"`
}

func hookEvents(events []Event, base string) []hookEvent {
	out := make([]hookEvent, 0, len(events))
	for _, e := range events {
		out = append(out, hookEvent{e.ID, e.TS, e.Root, e.Kind, e.Severity, e.Host, e.Detail, hostLink(base, e.Host)})
	}
	return out
}

func (cs *ChannelSender) sendWebhook(ctx context.Context, c *Channel, events []Event) error {
	agent, _ := os.Hostname()
	body, err := json.Marshal(map[string]any{"agent": agent, "version": version, "generated": nowUTC(), "count": len(events), "events": hookEvents(events, cs.base())})
	if err != nil {
		return err
	}
	hdr := map[string]string{}
	if c.Cfg.Secret != "" {
		m := hmac.New(sha256.New, []byte(c.Cfg.Secret))
		m.Write(body)
		hdr["X-EASM-Signature"] = "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	if c.Cfg.HeaderName != "" {
		hdr[c.Cfg.HeaderName] = c.Cfg.HeaderValue
	}
	return cs.post(ctx, c.Cfg.URL, hdr, body)
}

// ---- Slack and Teams

func groupByHost(events []Event) (hosts []string, by map[string][]Event) {
	by = map[string][]Event{}
	for _, e := range events {
		k := e.Host
		if k == "" {
			k = e.Root
		}
		if _, ok := by[k]; !ok {
			hosts = append(hosts, k)
		}
		by[k] = append(by[k], e)
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := maxSev(by[hosts[i]]), maxSev(by[hosts[j]])
		if a != b {
			return a > b
		}
		return hosts[i] < hosts[j]
	})
	return
}

func maxSev(es []Event) int {
	m := 0
	for _, e := range es {
		if r := sevRank(e.Severity); r > m {
			m = r
		}
	}
	return m
}

var sevEmoji = map[string]string{"high": ":red_circle:", "medium": ":large_orange_circle:", "low": ":large_blue_circle:", "info": ":white_circle:"}

// slackEscape neutralises the three characters Slack treats as markup.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slackBody(events []Event, base string) map[string]any {
	hosts, by := groupByHost(events)
	var sb strings.Builder
	fmt.Fprintf(&sb, "*EASM: %d new change(s)*\n", len(events))
	n := 0
	for _, h := range hosts {
		label := "`" + slackEscape(h) + "`"
		if l := hostLink(base, h); l != "" {
			label = "<" + slackEscape(l) + "|" + slackEscape(h) + ">"
		}
		fmt.Fprintf(&sb, "\n%s\n", label)
		for _, e := range by[h] {
			if n++; n > 40 {
				break
			}
			fmt.Fprintf(&sb, "%s *%s* %s: %s\n", sevEmoji[e.Severity], strings.ToUpper(e.Severity), slackEscape(e.Kind), slackEscape(clip(e.Detail, 300)))
		}
		if n > 40 {
			break
		}
	}
	if len(events) > 40 {
		fmt.Fprintf(&sb, "\n…and %d more.", len(events)-40)
	}
	return map[string]any{"text": sb.String()}
}

func teamsBody(events []Event, base string) map[string]any {
	hosts, by := groupByHost(events)
	body := []map[string]any{{"type": "TextBlock", "text": fmt.Sprintf("EASM: %d new change(s)", len(events)), "weight": "Bolder", "size": "Medium", "wrap": true}}
	n := 0
	for _, h := range hosts {
		t := "**" + h + "**"
		if l := hostLink(base, h); l != "" {
			t = "[" + h + "](" + l + ")"
		}
		body = append(body, map[string]any{"type": "TextBlock", "text": t, "wrap": true, "spacing": "Medium"})
		for _, e := range by[h] {
			if n++; n > 30 {
				break
			}
			body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "spacing": "Small",
				"text": fmt.Sprintf("%s **%s**: %s", strings.ToUpper(e.Severity), e.Kind, clip(e.Detail, 300))})
		}
		if n > 30 {
			break
		}
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
	return map[string]any{"type": "message", "attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}
}

// ---- syslog

var syslogSev = map[string]int{"high": 3, "medium": 4, "low": 5, "info": 6}
var cefSev = map[string]int{"high": 9, "medium": 6, "low": 3, "info": 1}

func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "\n", " ", "\r", " ").Replace(s)
}
func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`, "\n", `\n`, "\r", `\n`).Replace(s)
}

// syslogLine formats one event as an RFC 5424 message with a CEF or JSON body.
func syslogLine(e Event, format, hostname string) string {
	pri := 20*8 + syslogSev[e.Severity] // facility local4
	var msg string
	if format == "json" {
		b, _ := json.Marshal(hookEvent{e.ID, e.TS, e.Root, e.Kind, e.Severity, e.Host, e.Detail, ""})
		msg = string(b)
	} else {
		ts, _ := time.Parse(time.RFC3339, e.TS)
		msg = fmt.Sprintf("CEF:0|EASM Agent|easm-agent|%s|%s|%s|%d|rt=%d dvchost=%s cs1Label=domain cs1=%s cs2Label=host cs2=%s msg=%s",
			cefHeader(version), cefHeader(e.Kind), cefHeader(clip(e.Kind+": "+e.Detail, 120)), cefSev[e.Severity],
			ts.UnixMilli(), cefExt(hostname), cefExt(e.Root), cefExt(e.Host), cefExt(clip(e.Detail, 900)))
	}
	if hostname == "" {
		hostname = "-"
	}
	ts := e.TS
	if ts == "" {
		ts = nowUTC()
	}
	return fmt.Sprintf("<%d>1 %s %s easm-agent - %d - %s", pri, ts, strings.ReplaceAll(hostname, " ", "_"), e.ID, msg)
}

func (cs *ChannelSender) sendSyslog(ctx context.Context, c *Channel, events []Event) error {
	host, _ := os.Hostname()
	d := net.Dialer{Timeout: cs.dialTO}
	conn, err := d.DialContext(ctx, c.Cfg.Proto, c.Cfg.Addr)
	if err != nil {
		return fmt.Errorf("could not connect to the syslog server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(cs.dialTO))
	for _, e := range events {
		line := syslogLine(e, c.Cfg.Format, host)
		if c.Cfg.Proto == "tcp" {
			line += "\n"
		}
		if _, err := conn.Write([]byte(line)); err != nil {
			return fmt.Errorf("sending to the syslog server failed: %v", err)
		}
	}
	return nil
}

// ---- Jira

func jiraKey(e Event) string {
	h := sha256.Sum256([]byte(e.Root + "|" + e.Kind + "|" + e.Host + "|" + clip(e.Detail, 60)))
	return hex.EncodeToString(h[:10])
}

func (cs *ChannelSender) sendJira(ctx context.Context, c *Channel, events []Event) error {
	var firstErr error
	for _, e := range events {
		if !findingKinds[e.Kind] { // tickets are for findings, not for every inventory change
			continue
		}
		key := jiraKey(e)
		if _, done := cs.store.ticketFor(c.ID, key); done {
			continue
		}
		if err := cs.jiraCreate(ctx, c, e, key); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break // stop at the first failure so the rest are retried in order
		}
	}
	return firstErr
}

func (cs *ChannelSender) jiraCreate(ctx context.Context, c *Channel, e Event, key string) error {
	desc := fmt.Sprintf("%s\n\nDomain: %s\nHost: %s\nSeverity: %s\nType: %s\nFound by the EASM agent at %s.", e.Detail, e.Root, e.Host, e.Severity, e.Kind, e.TS)
	if l := hostLink(cs.base(), e.Host); l != "" {
		desc += "\n" + l
	}
	fields := map[string]any{
		"project":     map[string]string{"key": c.Cfg.Project},
		"issuetype":   map[string]string{"name": c.Cfg.IssueType},
		"summary":     clip(fmt.Sprintf("[EASM] %s on %s", e.Kind, e.Host), 250),
		"description": desc,
		"labels":      []string{"easm", "easm-" + e.Severity},
	}
	b, _ := json.Marshal(map[string]any{"fields": fields})
	endpoint := strings.TrimRight(c.Cfg.URL, "/") + "/rest/api/2/issue"
	hdr := map[string]string{}
	if c.Cfg.User != "" {
		hdr["Authorization"] = "Basic " + base64Std(c.Cfg.User+":"+c.Cfg.Token)
	} else {
		hdr["Authorization"] = "Bearer " + c.Cfg.Token
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return errors.New("the Jira address is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cs.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("could not reach Jira: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("the Jira server answered HTTP %d %s", resp.StatusCode, strings.TrimSpace(clip(string(body), 160)))
	}
	var out struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(body, &out)
	if out.Key == "" {
		out.Key = "created"
	}
	cs.store.saveTicket(c.ID, key, out.Key)
	return nil
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
