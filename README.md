# Cybersour Attack Surface Scanner

A lightweight, single-binary agent for continuous **External Attack Surface Management (EASM)**. It runs as a persistent background service on Windows or Linux, watches the internet-facing footprint of the organisations you tell it about, and emails you only when something **changes**.

> **Status:** early development. The feature list below describes the design goals; not everything is implemented yet.

## Why

Attack surfaces drift. A forgotten subdomain, a new certificate or an unexpected IP resolution can be the first sign of shadow IT or a takeover risk. Commercial EASM platforms are expensive, so this project uses only free, no-API-key sources and ships as one small Go binary with no external services to run.

## Features

- **Passive discovery, zero cost, no API keys**
  - Certificate transparency via crt.sh
  - HackerTarget and AlienVault OTX passive DNS
- **DNS resolution** of A, AAAA, CNAME, NS, MX and TXT records via 1.1.1.1 and 8.8.8.8
- **ASN mapping** (BGPView or Team Cymru DNS WHOIS) to spot assets outside your expected network ranges
- **Delta-only alerting**: new subdomains, new IP resolutions and new TLS certificates trigger notifications, so routine scans stay quiet
- **Email reports** over SMTP with TLS/STARTTLS, in HTML and plain-text with a summary table
- **Local state** in embedded SQLite, so there is nothing else to install
- **Runs as a daemon or service** on Windows and Linux, scanning every 6 hours by default
- **Target management in the app**: add a domain, expected ASNs, organisation keywords and ignore patterns in one place; scanning, alerting and reporting follow automatically (GUI planned)

## Reliability and safety

- Capped DNS worker pool, so scans stay polite
- Retry with backoff and graceful timeout handling for crt.sh
- Structured, timestamped `INFO` / `WARN` / `ERROR` logging

## Build

Requires Go (recent stable release).

```bash
git clone https://github.com/cyberjangle101/cybersour-attack-surface-scanner.git
cd cybersour-attack-surface-scanner
go build -o cybersour ./...
```

On Windows, build locally to produce `cybersour.exe`.

## Usage

Usage and configuration documentation will be added as the first release takes shape.

## Responsible use

This tool performs **passive** reconnaissance using public data sources. Only monitor domains and organisations you own or have explicit permission to assess. You are responsible for complying with the terms of the data sources and with applicable law.

## Contributing

Issues and pull requests are welcome.

## License

MIT (pending confirmation).
