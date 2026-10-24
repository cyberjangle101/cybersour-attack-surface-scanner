package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func addEvents(t *testing.T, s *Store, evs ...Event) {
	t.Helper()
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.TS == "" {
			e.TS = nowUTC()
		}
		if err := tx.AddEvent(e, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func testSender(h *harness) *ChannelSender {
	return newChannelSender(h.store, h.log, func() string { return "https://easm.example" })
}

func TestWebhookChannelSignsAndTracksPosition(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var bodies [][]byte
	var sigs []string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if fail {
			http.Error(w, "nope", 500)
			return
		}
		bodies = append(bodies, b)
		sigs = append(sigs, r.Header.Get("X-EASM-Signature")+"|"+r.Header.Get("X-Key"))
	}))
	defer srv.Close()
	addEvents(t, h.store, Event{Root: "a.test", Kind: "tls-expired", Severity: "high", Host: "old.a.test", Detail: "before"})
	id, err := h.store.AddChannel(&Channel{Name: "hook", Kind: chWebhook, MinSev: "medium", Cfg: ChannelCfg{URL: srv.URL + "/tok", Secret: "s3", HeaderName: "X-Key", HeaderValue: "k1"}})
	if err != nil {
		t.Fatal(err)
	}
	cs := testSender(h)
	cs.DispatchAll(context.Background())
	if len(bodies) != 0 {
		t.Fatal("events from before the channel existed were sent")
	}
	addEvents(t, h.store,
		Event{Root: "a.test", Kind: "tls-expired", Severity: "high", Host: "www.a.test", Detail: "cert expired"},
		Event{Root: "a.test", Kind: "subdomain", Severity: "info", Host: "x.a.test", Detail: "new"},
		Event{Root: "a.test", Kind: "dns-removed", Severity: "medium", Host: "gone.a.test", Detail: "removed", NoAlert: true})
	mu.Lock()
	fail = true
	mu.Unlock()
	cs.DispatchAll(context.Background())
	c, _ := h.store.GetChannel(id)
	if c.LastErr == "" || strings.Contains(c.LastErr, "/tok") {
		t.Fatalf("failure should be recorded without the address: %q", c.LastErr)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	cs.DispatchAll(context.Background())
	cs.DispatchAll(context.Background()) // nothing new: must not repeat
	if len(bodies) != 1 {
		t.Fatalf("want exactly one delivery, got %d", len(bodies))
	}
	var got struct {
		Count  int         `json:"count"`
		Events []hookEvent `json:"events"`
	}
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Events[0].Host != "www.a.test" || !strings.HasPrefix(got.Events[0].Link, "https://easm.example/assets/view?") {
		t.Fatalf("filtering by severity / muted events / link wrong: %+v", got)
	}
	m := hmac.New(sha256.New, []byte("s3"))
	m.Write(bodies[0])
	if sigs[0] != "sha256="+hex.EncodeToString(m.Sum(nil))+"|k1" {
		t.Fatalf("signature/header wrong: %s", sigs[0])
	}
}

func TestSlackTeamsBodies(t *testing.T) {
	ev := []Event{{Kind: "exposed-path", Severity: "high", Host: "a.test", Detail: "<script> & stuff"}, {Kind: "tls-expiring", Severity: "low", Host: "b.test", Detail: "soon"}}
	b, _ := json.Marshal(slackBody(ev, "https://e.example"))
	var m map[string]string
	_ = json.Unmarshal(b, &m)
	s := m["text"]
	if strings.Contains(s, "<script>") || !strings.Contains(s, "&lt;script&gt;") || !strings.Contains(s, "e.example/assets/view?id=a.test&amp;type=domain") {
		t.Fatalf("slack body not escaped/linked: %s", s)
	}
	b, _ = json.Marshal(teamsBody(ev, ""))
	if !strings.Contains(string(b), "AdaptiveCard") {
		t.Fatal("teams body not an adaptive card")
	}
}

func TestSyslogChannelCEF(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	c := &Channel{ID: 1, Name: "siem", Kind: chSyslog, MinSev: "low", Cfg: ChannelCfg{Addr: ln.Addr().String(), Proto: "tcp", Format: "cef"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e := Event{ID: 7, TS: "2026-01-02T03:04:05Z", Root: "a.test", Kind: "exposed|path", Severity: "high", Host: "h.a.test", Detail: "x=y\nline2"}
	if err := testSender(h).Send(context.Background(), c, []Event{e}); err != nil {
		t.Fatal(err)
	}
	line := <-got
	if !strings.HasPrefix(line, "<163>1 2026-01-02T03:04:05Z ") || !strings.Contains(line, `CEF:0|EASM Agent|easm-agent|`) ||
		!strings.Contains(line, `|exposed\|path|`) || !strings.Contains(line, `msg=x\=y\nline2`) || strings.Count(line, "\n") != 1 {
		t.Fatalf("bad syslog line: %q", line)
	}
}

func TestJiraCreatesOneTicketPerFinding(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var reqs []map[string]any
	auth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		reqs = append(reqs, m)
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"key":"SEC-12"}`))
	}))
	defer srv.Close()
	id, err := h.store.AddChannel(&Channel{Name: "jira", Kind: chJira, MinSev: "medium", Cfg: ChannelCfg{URL: srv.URL, Project: "SEC", User: "a@b.c", Token: "tok"}})
	if err != nil {
		t.Fatal(err)
	}
	addEvents(t, h.store,
		Event{Root: "a.test", Kind: "exposed-path", Severity: "high", Host: "www.a.test", Detail: "/.git exposed"},
		Event{Root: "a.test", Kind: "subdomain", Severity: "medium", Host: "n.a.test", Detail: "inventory only"})
	cs := testSender(h)
	cs.DispatchAll(context.Background())
	// the same finding reappearing later must not create a second ticket
	addEvents(t, h.store, Event{Root: "a.test", Kind: "exposed-path", Severity: "high", Host: "www.a.test", Detail: "/.git exposed"})
	cs.DispatchAll(context.Background())
	if len(reqs) != 1 {
		t.Fatalf("want 1 ticket, got %d", len(reqs))
	}
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("auth header %q", auth)
	}
	if k, ok := h.store.ticketFor(id, jiraKey(Event{Root: "a.test", Kind: "exposed-path", Host: "www.a.test", Detail: "/.git exposed"})); !ok || k != "SEC-12" {
		t.Fatal("ticket not remembered")
	}
}

func TestChannelValidationAndSealing(t *testing.T) {
	h := newHarness(t)
	bad := []Channel{
		{Name: "", Kind: chSlack, MinSev: "low", Cfg: ChannelCfg{URL: "https://x"}},
		{Name: "a", Kind: chSlack, MinSev: "low", Cfg: ChannelCfg{URL: "javascript:alert(1)"}},
		{Name: "a", Kind: chSlack, MinSev: "low", Cfg: ChannelCfg{URL: "https://u:p@x"}},
		{Name: "a", Kind: chSyslog, MinSev: "low", Cfg: ChannelCfg{Addr: "nohost", Proto: "udp", Format: "cef"}},
		{Name: "a", Kind: chWebhook, MinSev: "bogus", Cfg: ChannelCfg{URL: "https://x"}},
		{Name: "a", Kind: chWebhook, MinSev: "low", Cfg: ChannelCfg{URL: "https://x", HeaderName: "Bad Name", HeaderValue: "v"}},
		{Name: "a", Kind: "nope", MinSev: "low"},
	}
	for i := range bad {
		if _, err := h.store.AddChannel(&bad[i]); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := h.store.AddChannel(&Channel{Name: "ok", Kind: chSlack, MinSev: "low", Cfg: ChannelCfg{URL: "https://hooks.example/secret-token"}}); err != nil {
		t.Fatal(err)
	}
	var raw string
	_ = h.store.db.QueryRow(`SELECT cfg FROM channels`).Scan(&raw)
	if strings.Contains(raw, "secret-token") {
		t.Fatal("channel settings stored in clear")
	}
	if redactURL("https://hooks.example/secret-token?x=1") != "https://hooks.example/…" {
		t.Fatal("redact")
	}
}

func TestChannelsPageAdminOnlyAndFlow(t *testing.T) {
	e := newWebEnv(t)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	for _, role := range []string{RoleViewer, RoleAnalyst} {
		b := e.signedIn("u-"+role, role)
		if code, _, _ := b.get("/settings/channels"); code != 403 {
			t.Errorf("%s reached channels: %d", role, code)
		}
		if code, _, _ := b.post("/settings/channels", url.Values{"name": {"x"}}); code != 403 {
			t.Errorf("%s added a channel: %d", role, code)
		}
	}
	adm := e.signedIn("boss", RoleAdmin)
	if code, body, _ := adm.get("/settings/channels"); code != 200 || !strings.Contains(body, "Add a channel") {
		t.Fatalf("admin page: %d", code)
	}
	adm.post("/settings/channels", url.Values{"name": {"hook"}, "kind": {"webhook"}, "min_sev": {"low"}, "url": {hook.URL + "/secret-token"}})
	_, body, _ := adm.get("/settings/channels")
	if !strings.Contains(body, "hook") || strings.Contains(body, "secret-token") {
		t.Fatal("channel not listed, or its secret address shown")
	}
	list, _ := e.store.ListChannels()
	if len(list) != 1 {
		t.Fatal("not stored")
	}
	id := strconv.FormatInt(list[0].ID, 10)
	adm.post("/settings/channels/"+id+"/test", url.Values{})
	if _, body, _ := adm.get("/settings/channels"); !strings.Contains(body, "Test message sent") {
		t.Fatalf("test not reported: %s", body)
	}
	adm.post("/settings/channels/"+id+"/toggle", url.Values{})
	if c, _ := e.store.GetChannel(list[0].ID); c.Enabled {
		t.Fatal("toggle did not turn it off")
	}
	adm.post("/settings/channels/"+id+"/delete", url.Values{})
	if l, _ := e.store.ListChannels(); len(l) != 0 {
		t.Fatal("not deleted")
	}
}
