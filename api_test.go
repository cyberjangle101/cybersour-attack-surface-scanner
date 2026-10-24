package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func apiDo(t *testing.T, e *webEnv, method, path, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// makeToken signs a user in, creates a token through the account page and returns it.
func makeToken(t *testing.T, e *webEnv, b *browser, name, role, days string) string {
	t.Helper()
	b.post("/account/tokens", url.Values{"name": {name}, "role": {role}, "days": {days}})
	_, body, _ := b.get("/account")
	m := regexp.MustCompile(`easm_[A-Za-z0-9_-]{43}`).FindString(body)
	if m == "" {
		t.Fatalf("no token shown for %s/%s", name, role)
	}
	if _, body, _ = b.get("/account"); strings.Contains(body, m) {
		t.Fatal("token shown a second time")
	}
	return m
}

func TestAPITokensAndEndpoints(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)

	viewer := e.signedIn("vee", RoleViewer)
	analyst := e.signedIn("ann", RoleAnalyst)
	admin := e.signedIn("boss", RoleAdmin)

	// a token cannot exceed its owner's role
	viewer.post("/account/tokens", url.Values{"name": {"x"}, "role": {RoleAdmin}})
	if l, _ := e.store.ListTokens(0); len(l) != 0 {
		t.Fatal("viewer created an admin token")
	}
	vt := makeToken(t, e, viewer, "ro", RoleViewer, "")
	at := makeToken(t, e, analyst, "scanner", RoleAnalyst, "30")

	// no credentials, junk, and cookies alone do not work
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", "", ""); c != 401 {
		t.Errorf("no token: %d", c)
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", "easm_"+strings.Repeat("a", 43), ""); c != 401 {
		t.Errorf("bad token: %d", c)
	}
	if c, _, _ := admin.get("/api/v1/findings"); c != 401 {
		t.Errorf("a signed-in browser session must not authenticate the API: %d", c)
	}

	c, body := apiDo(t, e, "GET", "/api/v1/findings?target=example.test", vt, "")
	if c != 200 {
		t.Fatalf("findings: %d %s", c, body)
	}
	var fr struct {
		Count    int
		Findings []map[string]any
	}
	_ = json.Unmarshal([]byte(body), &fr)
	if fr.Count != 1 || fr.Findings[0]["host"] != "api.example.test" || fr.Findings[0]["type"] != "asn-unexpected" {
		t.Fatalf("findings body: %s", body)
	}

	// CSV headers and JSON keys use the same names
	_, csvBody, _ := admin.get("/report/findings.csv")
	hdr, _ := csv.NewReader(strings.NewReader(csvBody)).Read()
	for _, h := range hdr {
		if _, ok := fr.Findings[0][h]; !ok {
			t.Errorf("CSV column %q missing from JSON finding", h)
		}
	}
	_, rj, _ := admin.get("/report.json")
	var rep map[string]any
	_ = json.Unmarshal([]byte(rj), &rep)
	for _, k := range rep["findings"].([]any) {
		for _, h := range hdr {
			if _, ok := k.(map[string]any)[h]; !ok {
				t.Errorf("report.json finding lacks %q", h)
			}
		}
	}
	for key := range rep {
		if key != strings.ToLower(key) {
			t.Errorf("report.json key %q is not snake_case", key)
		}
	}

	for _, p := range []string{"/api/v1/targets", "/api/v1/events?days=30", "/api/v1/assets", "/api/v1/report"} {
		if c, b := apiDo(t, e, "GET", p, vt, ""); c != 200 || !json.Valid([]byte(b)) {
			t.Errorf("%s: %d", p, c)
		}
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings?status=bogus", vt, ""); c != 400 {
		t.Errorf("bad status accepted: %d", c)
	}

	// scanning needs an analyst token
	if c, _ := apiDo(t, e, "POST", "/api/v1/scan", vt, `{"target":"example.test"}`); c != 403 {
		t.Errorf("viewer token scanned: %d", c)
	}
	if c, b := apiDo(t, e, "POST", "/api/v1/scan", at, `{"target":"example.test"}`); c != 202 {
		t.Errorf("analyst token scan: %d %s", c, b)
	}
	if c, _ := apiDo(t, e, "POST", "/api/v1/scan", at, `{"target":"nope.test"}`); c != 404 {
		t.Errorf("unknown target: %d", c)
	}

	// SARIF
	c, body = apiDo(t, e, "GET", "/api/v1/export/sarif", vt, "")
	var sarif struct {
		Version string
		Runs    []struct {
			Tool    struct{ Driver struct{ Name string } }
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string
				Locations []struct {
					LogicalLocations []struct{ Name string }
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &sarif); err != nil || c != 200 || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 ||
		len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].Level != "error" || sarif.Runs[0].Results[0].Locations[0].LogicalLocations[0].Name != "api.example.test" {
		t.Fatalf("sarif: %v %s", err, body)
	}

	// STIX: every reference resolves, ids are well-formed
	c, body = apiDo(t, e, "GET", "/api/v1/export/stix", vt, "")
	var bundle struct {
		Type    string
		Objects []map[string]any
	}
	if err := json.Unmarshal([]byte(body), &bundle); err != nil || c != 200 || bundle.Type != "bundle" {
		t.Fatalf("stix: %v %s", err, body)
	}
	ids := map[string]bool{}
	idRe := regexp.MustCompile(`^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	for _, o := range bundle.Objects {
		id, _ := o["id"].(string)
		if !idRe.MatchString(id) || !strings.HasPrefix(id, o["type"].(string)+"--") {
			t.Errorf("bad STIX id %q", id)
		}
		ids[id] = true
	}
	var haveVuln bool
	for _, o := range bundle.Objects {
		if o["type"] == "vulnerability" {
			haveVuln = true
		}
		if o["type"] == "relationship" && (!ids[o["source_ref"].(string)] || !ids[o["target_ref"].(string)]) {
			t.Errorf("dangling relationship %v", o)
		}
		if cr, ok := o["created"].(string); ok {
			if m, _ := o["modified"].(string); m < cr {
				t.Errorf("modified before created: %v", o)
			}
		}
	}
	if !haveVuln {
		t.Error("no vulnerability object")
	}
	// same finding => same ids on a second export
	_, again := apiDo(t, e, "GET", "/api/v1/export/stix", vt, "")
	if !strings.Contains(again, ids2first(bundle.Objects, "vulnerability")) {
		t.Error("STIX ids are not stable between exports")
	}

	// browser exports work with a session
	if c, b, _ := admin.get("/report/findings.sarif"); c != 200 || !strings.Contains(b, `"2.1.0"`) {
		t.Errorf("sarif download: %d", c)
	}
	if c, _, _ := admin.get("/report/findings.stix.json"); c != 200 {
		t.Errorf("stix download: %d", c)
	}

	// revocation, expiry, disabled owner, demotion
	toks, _ := e.store.ListTokens(0)
	var vid string
	for _, tk := range toks {
		if tk.Name == "ro" {
			vid = itoa(tk.ID)
		}
	}
	viewer.post("/account/tokens/"+vid+"/revoke", url.Values{})
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", vt, ""); c != 401 {
		t.Errorf("revoked token works: %d", c)
	}
	u, _ := e.store.FindUserFold("ann")
	if _, err := e.store.db.Exec(`UPDATE api_tokens SET expires=? WHERE owner_id=?`, time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02"), u.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", at, ""); c != 401 {
		t.Errorf("expired token works: %d", c)
	}
	if err := e.store.SetUserRole(u.ID, RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.db.Exec(`UPDATE api_tokens SET expires='' WHERE owner_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := apiDo(t, e, "POST", "/api/v1/scan", at, `{"target":"example.test"}`); c != 403 {
		t.Errorf("token outlived its owner's demotion: %d", c)
	}
	if err := e.store.SetUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", at, ""); c != 401 {
		t.Errorf("disabled owner's token works: %d", c)
	}
	// the token itself is stored only as a hash
	var n int
	_ = e.store.db.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE hash=?`, at).Scan(&n)
	if n != 0 {
		t.Error("token stored in clear")
	}
}

func ids2first(objs []map[string]any, typ string) string {
	for _, o := range objs {
		if o["type"] == typ {
			return o["id"].(string)
		}
	}
	return "none"
}
