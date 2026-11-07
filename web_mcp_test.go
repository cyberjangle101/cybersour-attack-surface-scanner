package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Settings explains how to connect an assistant, with this agent's own address, and switching
// MCP off refuses every request to /mcp (whatever the token) while the REST API keeps working.
func TestSettingsMCPSection(t *testing.T) {
	e := newWebEnv(t)
	admin := e.signedIn("boss", RoleAdmin)
	tok := makeToken(t, e, admin, "claude", RoleViewer, "")

	code, body, _ := admin.get("/settings")
	host := strings.TrimPrefix(strings.TrimPrefix(e.srv.URL, "https://"), "http://")
	for _, want := range []string{`id="mcp"`, `name="mcp_enabled" checked`, host + `/mcp`, "claude mcp add --transport http easm", "mcp-remote", "request_scan", "No assistant has connected yet"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}

	// the connection appears under Recent connections
	if c, _ := mcpDo(t, e, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"9"}}}`); c != 200 {
		t.Fatalf("initialize: %d", c)
	}
	if _, body, _ = admin.get("/settings"); !strings.Contains(body, "claude-code 9") {
		t.Error("the MCP connection is not listed on the Settings page")
	}

	st, _ := e.store.LoadSettings()
	st.MCPEnabled = false
	if c, _, _ := admin.post("/settings", settingsForm(st)); c != 303 {
		t.Fatalf("save: %d", c)
	}
	if got, _ := e.store.LoadSettings(); got.MCPEnabled {
		t.Fatal("unticking the box did not switch MCP off")
	}
	if c, body := mcpDo(t, e, tok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 403 || !strings.Contains(body, "switched off") {
		t.Errorf("MCP off: %d %s", c, body)
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", tok, ""); c != 200 {
		t.Errorf("the REST API should not be affected by the MCP switch: %d", c)
	}
	if _, body, _ = admin.get("/settings"); strings.Contains(body, `name="mcp_enabled" checked`) {
		t.Error("the box should show MCP as off")
	}
}

func TestMCPEndpointAddress(t *testing.T) {
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host = "example.internal:8443"
	if got := mcpEndpoint(r, Settings{}, true); got != "https://example.internal:8443/mcp" {
		t.Errorf("from the request: %s", got)
	}
	if got := mcpEndpoint(r, Settings{PublicURL: "https://easm.example.com/ "}, true); got != "https://easm.example.com/mcp" {
		t.Errorf("from the public URL: %s", got)
	}
	if got := mcpEndpoint(r, Settings{PublicURL: "javascript:alert(1)"}, false); got != "http://example.internal:8443/mcp" {
		t.Errorf("a public URL that is not http(s) is ignored: %s", got)
	}
}
