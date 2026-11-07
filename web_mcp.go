package main

import (
	"net/http"
	"strings"
)

// mcpToolView is one row of the tool table on the Settings page.
type mcpToolView struct {
	Name, Title, Role string
	Writes            bool
}

// mcpView describes the MCP endpoint for the Settings page: whether it is on, the address an
// assistant connects to, ready-to-paste client configuration, the tools, and recent connections.
func (s *Server) mcpView(r *http.Request, st Settings) map[string]any {
	endpoint := mcpEndpoint(r, st, s.boot != nil && s.boot.UsesTLS())
	tools := make([]mcpToolView, 0, len(mcpTools))
	for _, t := range mcpTools {
		role := "Viewer"
		if t.Need >= permTriage {
			role = "Analyst"
		}
		tools = append(tools, mcpToolView{Name: t.Name, Title: t.Title, Role: role, Writes: t.Writes})
	}
	recent, _, _ := s.store.ListAudit(AuditFilter{Action: "mcp.connect", Limit: 10})
	selfSigned := false
	if s.certs != nil {
		selfSigned = s.certs.Info().Source != "uploaded"
	}
	return map[string]any{
		"On":         st.MCPEnabled,
		"Endpoint":   endpoint,
		"ClaudeCode": `claude mcp add --transport http easm ` + endpoint + ` --header "Authorization: Bearer <your token>"`,
		"Desktop": `{
  "mcpServers": {
    "easm": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "` + endpoint + `", "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "Bearer <your token>" }
    }
  }
}`,
		"Tools":      tools,
		"Recent":     recent,
		"SelfSigned": selfSigned,
		"Versions":   strings.Join(mcpVersions, ", "),
	}
}

// mcpEndpoint is the address assistants use: the dashboard address from Settings when one is
// set, otherwise the address this page was opened with.
func mcpEndpoint(r *http.Request, st Settings, tls bool) string {
	if u := strings.TrimRight(strings.TrimSpace(st.PublicURL), "/"); strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return u + "/mcp"
	}
	scheme := "http"
	if tls || r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/mcp"
}
