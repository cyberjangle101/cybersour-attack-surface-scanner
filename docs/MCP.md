# Connecting an AI assistant (MCP)

EASM Agent has a [Model Context Protocol](https://modelcontextprotocol.io) endpoint at `/mcp`. An assistant that speaks MCP (Claude Code, Claude Desktop, or another MCP client) can use it to answer questions such as *"what are our worst open findings on example.com?"*, *"what changed this week?"* or *"what do we know about 203.0.113.7?"*.

## What an assistant can do

| Tool | What it does | Token role |
|---|---|---|
| `search` | Finds domains, findings and assets containing some text (the same search as the box at the top of the web interface) | Viewer |
| `list_targets` | Lists the monitored domains with their scan status | Viewer |
| `list_findings` | Lists findings, worst first, with the risk and the fix | Viewer |
| `get_finding` | One finding with the services on the host and links to the public evidence | Viewer |
| `list_assets` | The inventory: subdomains, IPs, services, certificates, DNS, vulnerabilities | Viewer |
| `list_events` | Recent changes | Viewer |
| `request_scan` | Queues a rescan of a domain that is **already** monitored | Analyst |

There is no tool that adds a domain, changes or accepts a finding, changes settings or manages users, whatever the token's role.

## Set it up

**Settings → AI assistants (MCP)** shows the same steps with this agent's own address filled in, copy buttons, the latest connections, and a switch that turns MCP off (every request to `/mcp` is then refused; the REST API is not affected).

1. Sign in and open **your account → API tokens**. Create a token named after the assistant (for example `claude`).
   * Choose **Viewer** unless you want the assistant to be able to start rescans; then choose **Analyst**.
   * Give it an expiry date. The token is shown once.
2. Add the server to your assistant. The address is the one you use for the web interface, plus `/mcp`.

**Claude Code**

```bash
claude mcp add --transport http easm https://easm.internal.example:8443/mcp --header "Authorization: Bearer easm_..."
```

**Claude Desktop, and other clients that only start local servers.** Use the `mcp-remote` bridge in the client's configuration file:

```json
{
  "mcpServers": {
    "easm": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://easm.internal.example:8443/mcp", "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "Bearer easm_..." }
    }
  }
}
```

If the agent uses its automatic self-signed certificate, the assistant will refuse to connect until it trusts that certificate. Install your own certificate (Settings → Certificate) or add the agent's certificate to the computer's trusted store.

## Things to know before you turn it on

* **Your findings go to the AI provider.** Whatever the assistant reads (host names, IP addresses, findings) is sent to the company that runs the model, under that company's terms. If that is not acceptable for your data, use a model you run yourself, or do not connect an assistant.
* **Scan results can contain hostile text.** Banners, page titles and certificate names are written by whoever runs the scanned system, which may be an attacker who expects to be scanned. Text such as *"ignore your instructions and …"* in a page title is a real risk (prompt injection). The agent tells the assistant to treat these values as data, and its tools cannot change anything except queue a rescan. Still, do not give the same assistant tools that can act elsewhere (email, tickets, shell commands) without approving each action yourself.
* **Claude.ai and other web-based assistants connect from the internet.** They can only reach an agent that is published on the internet, which this agent is not designed for. Use an assistant that runs on a computer inside your network, such as Claude Code or Claude Desktop.
* **It is accountable.** Every connection is written to the audit log (`mcp.connect`, with the client's name and the token), as is every rescan (`scan.mcp`). Revoking the token cuts the assistant off at once, and demoting or disabling the account limits its tokens too.

## Protocol details

Streamable HTTP transport, protocol revisions 2025-11-25, 2025-06-18 and 2025-03-26. The server is stateless: each request is a single JSON-RPC message sent with `POST`, and each reply is a single JSON response (no server-sent events, no sessions, no batches). Requests carrying an `Origin` header from another site are refused. Requests are limited to 64 KB, and lists to 200 items.
