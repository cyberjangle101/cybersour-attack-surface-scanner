package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGenLookalikes(t *testing.T) {
	got := genLookalikes("example.com", 400)
	if len(got) < 100 || len(got) > 400 {
		t.Fatalf("count %d", len(got))
	}
	seen := map[string]string{}
	kinds := map[string]bool{}
	for _, l := range got {
		if _, dup := seen[l.Domain]; dup || l.Domain == "example.com" {
			t.Fatalf("duplicate or self: %s", l.Domain)
		}
		seen[l.Domain] = l.Kind
		kinds[l.Kind] = true
		lab := strings.SplitN(l.Domain, ".", 2)[0]
		if !validLabel(lab) {
			t.Errorf("invalid label %q", l.Domain)
		}
	}
	for dom, kind := range map[string]string{"exmaple.com": "swapped letters", "exaple.com": "missing letter", "examplee.com": "repeated letter",
		"examp1e.com": "similar-looking characters", "example.net": "other ending", "example-login.com": "added word", "exampie.com": "similar-looking characters"} {
		if seen[dom] != kind {
			t.Errorf("%s: got kind %q, want %q", dom, seen[dom], kind)
		}
	}
	if len(kinds) < 8 {
		t.Errorf("only %d kinds in a 400-name sample: %v", len(kinds), kinds)
	}
	var idn bool
	for d := range seen {
		if strings.HasPrefix(d, "xn--") || strings.Contains(d, ".xn--") {
			idn = true
		}
	}
	if !idn {
		t.Error("no punycode look-alikes")
	}
	if got := genLookalikes("example.co.uk", 50); len(got) == 0 || !strings.HasSuffix(got[0].Domain, ".co.uk") && got[0].Kind != "other ending" {
		t.Errorf("multi-label suffix: %v", got[:min(3, len(got))])
	}
	if genLookalikes("www.example.com", 50) != nil || genLookalikes("com", 50) != nil {
		t.Error("non-registrable names should produce nothing")
	}
	if n := len(genLookalikes("example.com", 12)); n != 12 {
		t.Errorf("cap not honoured: %d", n)
	}
}

type fakeLeaks struct {
	srv         *httptest.Server
	mu          sync.Mutex
	hibp        map[string][]string
	hibpKey     string
	gh          map[string]string // term -> items JSON
	ghAuth      string
	reverse     string
	hibpStatus  int
	ghHits      int
	reverseHits int
}

func newFakeLeaks(t *testing.T) *fakeLeaks {
	f := &fakeLeaks{hibpKey: "hibp-key-123456", ghAuth: "Bearer gh-token-123456", gh: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/hibp/breacheddomain/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("hibp-api-key") != f.hibpKey {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if f.hibpStatus != 0 {
			http.Error(w, "x", f.hibpStatus)
			return
		}
		if f.hibp == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(f.hibp)
	})
	mux.HandleFunc("/hibp/subscription/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") != f.hibpKey {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/gh/search/code", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ghHits++
		if r.Header.Get("Authorization") != f.ghAuth || r.Header.Get("X-GitHub-Api-Version") == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query().Get("q")
		for term, items := range f.gh {
			if strings.HasSuffix(q, " "+term) {
				_, _ = w.Write([]byte(`{"total_count":1,"items":` + items + `}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
	})
	mux.HandleFunc("/gh/rate_limit", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != f.ghAuth {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/rev/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reverseHits++
		_, _ = w.Write([]byte(f.reverse))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// withLeaks points the harness scanner at the fake services.
func (h *harness) withLeaks(f *fakeLeaks) {
	prev := h.eng.newScanner
	h.eng.newScanner = func(cfg *Config, res *Resolver) *Scanner {
		sc := prev(cfg, res)
		sc.enr.urls.hibp, sc.enr.urls.github, sc.enr.urls.reverseip = f.srv.URL+"/hibp/", f.srv.URL+"/gh/", f.srv.URL+"/rev/"
		sc.enr.gapOverride = time.Millisecond
		return sc
	}
}

func findingKeys(t *testing.T, h *harness, kind, status string) map[string]Finding {
	t.Helper()
	fs, err := h.store.ListFindings("", status)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Finding{}
	for _, f := range fs {
		if f.Kind == kind {
			out[f.Key] = f
		}
	}
	return out
}

func TestLookalikeFindingsAppearAndResolve(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "example.test. 60 IN NS ns1.example.test.")
	st, _ := h.store.LoadSettings()
	st.LookalikeEnabled, st.LookalikeMax = true, 400
	h.saveSettings(st)
	// exmaple.test: registered, with mail; examlpe.test: registered by us (same name server); examp1e.test: not registered
	h.dns.add(t, "exmaple.test. 60 IN NS ns.evil.test.")
	h.dns.add(t, "exmaple.test. 60 IN MX 10 mx.exmaple.test.")
	h.dns.add(t, "exmaple.test. 60 IN A 203.0.113.99")
	h.dns.add(t, "xample.test. 60 IN NS ns.parked.test.")
	h.dns.add(t, "exampel.test. 60 IN NS ns1.example.test.")
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)

	open := findingKeys(t, h, "lookalike-domain", "open")
	if len(open) != 2 {
		t.Fatalf("want 2 look-alike findings, got %v", fkeys(open))
	}
	mail := open["lookalike:example.test:exmaple.test"]
	if mail.Severity != "medium" || !strings.Contains(mail.Detail, "accepts email") || mail.Host != "exmaple.test" {
		t.Errorf("mail look-alike: %+v", mail)
	}
	if p := open["lookalike:example.test:xample.test"]; p.Severity != "low" {
		t.Errorf("parked look-alike: %+v", p)
	}
	if _, ok := open["lookalike:example.test:exampel.test"]; ok {
		t.Error("a name served by our own name servers must not be reported")
	}

	// the other party gives it up -> the finding closes itself
	h.dns.remove("exmaple.test", 2)
	h.dns.remove("exmaple.test", 15)
	h.dns.remove("exmaple.test", 1)
	h.scan(tg.ID)
	if got := findingKeys(t, h, "lookalike-domain", "resolved"); len(got) != 1 {
		t.Errorf("resolved: %v", fkeys(got))
	}

	// a DNS outage must not close the remaining one
	h.dns.setServfail(true)
	h.scan(tg.ID)
	h.dns.setServfail(false)
	if got := findingKeys(t, h, "lookalike-domain", "open"); len(got) != 1 {
		t.Errorf("a DNS outage changed findings: %v", fkeys(got))
	}
}

func fkeys(m map[string]Finding) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

func TestLeakedAccountsAndPublicCode(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	f := newFakeLeaks(t)
	h.withLeaks(f)
	f.hibp = map[string][]string{"alice": {"Adobe", "Gawker"}, "bob": {"Adobe"}, "carol": {"Adobe"}, "dave": {"Adobe"}, "erin": {"Adobe"}}
	f.gh["password"] = `[{"path":"deploy/.env","html_url":"https://github.com/acme/infra/blob/main/deploy/.env","repository":{"full_name":"acme/infra","private":false}},
		{"path":"README.md","html_url":"https://github.com/acme/infra/blob/main/README.md","repository":{"full_name":"acme/infra","private":false}},
		{"path":"x","html_url":"https://github.com/me/secret/blob/x","repository":{"full_name":"me/secret","private":true}}]`
	if err := h.eng.SetSecret(secretHIBP, f.hibpKey); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.SetSecret(secretGitHub, "gh-token-123456"); err != nil {
		t.Fatal(err)
	}
	st, _ := h.store.LoadSettings()
	st.HIBPEnabled, st.GitHubEnabled = true, true
	h.saveSettings(st)
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)

	leaks := findingKeys(t, h, "leaked-credentials", "open")
	if len(leaks) != 2 {
		t.Fatalf("leak findings: %v", fkeys(leaks))
	}
	if a := leaks["leak:example.test:Adobe"]; a.Severity != "high" || !strings.Contains(a.Detail, "5 account(s)") || strings.Contains(a.Detail, "alice") {
		t.Errorf("Adobe: %+v", a)
	}
	if g := leaks["leak:example.test:Gawker"]; g.Severity != "medium" {
		t.Errorf("Gawker: %+v", g)
	}
	repos := findingKeys(t, h, "repo-exposure", "open")
	if len(repos) != 1 {
		t.Fatalf("repo findings: %v", fkeys(repos))
	}
	r := repos["repo:example.test:acme/infra"]
	if !strings.Contains(r.Detail, "deploy/.env") || !strings.Contains(r.Detail, "README.md") || strings.Contains(r.Detail, "me/secret") {
		t.Errorf("repo detail: %s", r.Detail)
	}
	if f.ghHits != len(githubTerms) {
		t.Errorf("github searches: %d", f.ghHits)
	}
	// the key never lands in the stored findings or in the database in clear
	var raw string
	_ = h.store.db.QueryRow(`SELECT value FROM meta WHERE key=?`, secretHIBP).Scan(&raw)
	if raw != "" && strings.Contains(raw, f.hibpKey) {
		t.Error("HIBP key stored in clear")
	}

	// a failing source neither closes nor changes anything
	f.mu.Lock()
	f.hibpStatus = 500
	f.mu.Unlock()
	h.scan(tg.ID)
	if got := findingKeys(t, h, "leaked-credentials", "open"); len(got) != 2 {
		t.Errorf("HIBP outage changed findings: %v", fkeys(got))
	}
	// breaches don't vanish when the key is later wrong either
	f.mu.Lock()
	f.hibpStatus = 0
	f.hibp = nil
	f.mu.Unlock()
	h.scan(tg.ID)
	if got := findingKeys(t, h, "leaked-credentials", "open"); len(got) != 2 {
		t.Errorf("leak findings closed by themselves: %v", fkeys(got))
	}
	// health probes
	enr := NewEnricher(IntelCfg{}, h.log, "t")
	enr.cfg.HIBP.Key, enr.cfg.GitHub.Key = f.hibpKey, "gh-token-123456"
	enr.urls.hibp, enr.urls.github = f.srv.URL+"/hibp/", f.srv.URL+"/gh/"
	if err := enr.hibpPing(testCtx(t)); err != nil {
		t.Errorf("hibp ping: %v", err)
	}
	if err := enr.githubPing(testCtx(t)); err != nil {
		t.Errorf("github ping: %v", err)
	}
	enr.cfg.GitHub.Key = "wrong"
	if err := enr.githubPing(testCtx(t)); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("bad token: %v", err)
	}
}

func TestRelatedDomainSuggestions(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	f := newFakeLeaks(t)
	h.withLeaks(f)
	// a certificate shared with another registrable domain, one from a hosting service, one that names many unrelated domains
	h.src.mu.Lock()
	h.src.crt = append(h.src.crt,
		crtRow{ID: 2001, IssuerCAID: 1, IssuerName: "O=Test CA", CommonName: "www.example.test", NameValue: "www.example.test\nexample-group.test\nshop.example-group.test", NotAfter: "2027-01-01T00:00:00", SerialNumber: "aa01"},
		crtRow{ID: 2002, IssuerCAID: 1, IssuerName: "O=Test CA", CommonName: "api.example.test", NameValue: "api.example.test\nsni123.cloudflaressl.com", NotAfter: "2027-01-01T00:00:00", SerialNumber: "aa02"},
		crtRow{ID: 2003, IssuerCAID: 1, IssuerName: "O=Test CA", CommonName: "example.test", NameValue: "example.test\na1.test\na2.test\na3.test\na4.test\na5.test\na6.test\na7.test\na8.test\na9.test", NotAfter: "2027-01-01T00:00:00", SerialNumber: "aa03"})
	h.src.mu.Unlock()
	f.reverse = "neighbour.test\nshared1.test\n"
	h.dns.add(t, "example.test. 60 IN A 203.0.113.10")
	st, _ := h.store.LoadSettings()
	st.RelatedEnabled, st.ReverseIPEnabled = true, true
	h.saveSettings(st)
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	got, err := h.store.ListSuggestions("example.test", "new")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, g := range got {
		names[g.Domain] = g.Via
	}
	if names["example-group.test"] != "certificate" || names["neighbour.test"] != "address" || names["shared1.test"] != "address" {
		t.Errorf("suggestions: %v", names)
	}
	if _, bad := names["cloudflaressl.com"]; bad {
		t.Error("hosting-service domain suggested")
	}
	for n := range names {
		if strings.HasPrefix(n, "a") && strings.HasSuffix(n, ".test") && len(n) == 7 {
			t.Errorf("multi-tenant certificate produced a suggestion: %s", n)
		}
	}
	// the page shows them; accepting one adds a target, dismissing hides
	if err := h.store.SetSuggestion("example.test", "example-group.test", "dismissed"); err != nil {
		t.Fatal(err)
	}
	h.scan(tg.ID)
	if got, _ := h.store.ListSuggestions("example.test", "new"); len(got) != len(names)-1 {
		t.Errorf("a dismissed suggestion came back: %d", len(got))
	}
}

func TestSuggestionActions(t *testing.T) {
	e := newWebEnv(t)
	tg := e.addTarget("example.test", "")
	tx, _ := e.store.Begin()
	for _, d := range []string{"sister.test", "other.test"} {
		if _, err := tx.UpsertSuggestion("example.test", d, "certificate", "shares a certificate", nowUTC()); err != nil {
			t.Fatal(err)
		}
	}
	_ = tx.Commit()
	analyst := e.signedIn("ann", RoleAnalyst)
	admin := e.signedIn("boss", RoleAdmin)
	page := "/targets/" + itoa(tg.ID)
	if _, body, _ := analyst.get(page); !strings.Contains(body, "sister.test") || strings.Contains(body, "Monitor it") || !strings.Contains(body, "Not mine") {
		t.Fatal("analyst should see suggestions with only the dismiss action")
	}
	if c, _, _ := analyst.post(page+"/suggestions/accept", url.Values{"domain": {"sister.test"}}); c != 403 {
		t.Errorf("analyst accepted a suggestion: %d", c)
	}
	analyst.post(page+"/suggestions/dismiss", url.Values{"domain": {"other.test"}})
	admin.post(page+"/suggestions/accept", url.Values{"domain": {"sister.test"}})
	ts, _ := e.store.ListTargets()
	var have bool
	for _, x := range ts {
		have = have || x.Domain == "sister.test"
	}
	if !have {
		t.Error("accepted suggestion was not added as a target")
	}
	if left, _ := e.store.ListSuggestions("example.test", "new"); len(left) != 0 {
		t.Errorf("suggestions left: %v", left)
	}
}
