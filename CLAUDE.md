# EASM Agent: working rules for Claude Code

Go 1.26 module `easm-agent`: an External Attack Surface Management daemon for Windows and Linux.
It has an embedded web UI and an AES-256-XTS encrypted SQLite database.
Repo: cyberjangle101/cybersour-attack-surface-scanner. `main` is protected.

## Working efficiently (save credits)

- Read narrowly. Use `grep -n` or Grep to find the code, then Read only that line range.
  Do not read whole large files (`web.go`, `scanner.go`, `store.go`, `report_pdf.go`).
- Do not re-read a file you just edited, and do not re-run a command whose output you already have.
- Batch independent tool calls in one turn. Prefer one Bash call with `&&` over several small ones.
- Trim output: pipe long results through `tail -n 20` or `grep`. Never paste logs back into chat.
- Run long jobs (full tests, race, fuzz, scans) in the background and keep working. Do not poll.
- Do not spawn subagents unless I ask. Do not write plans or summaries I did not ask for.
- Keep replies short: what changed, what was verified, what is left. No recap of the steps.
- If a request is clear, start. Ask at most one question, and only when a wrong guess would be costly.
- Edit with small, targeted changes. Do not rewrite a file to change a few lines.

## Architecture facts that prevent bugs

- SQLite uses a single connection (`MaxOpenConns(1)`).
  Never query while a `rows` cursor is open, and never call `s.store.*` while a `Tx` is open. Both deadlock.
- The CSP is strict: no inline script or style in templates. Use classes and `web/static/app.js`.
- Forms are CSRF-protected in `s.auth(min, h)` via `ParseForm` only, so there is no multipart. Pass file contents through textareas.
- Roles are viewer < analyst < admin. Every state change goes through `s.audit`.
- Per-domain data lives in tables plus `meta` keys. Meta keys for a domain must END in `:<domain>` so `DeleteTarget` removes them.
  A new per-domain table needs a matching line in `DeleteTarget` (`store.go`) and a test.
- New finding kinds need all of:
  - an entry in `catalog.go`
  - `findingKinds` in `store.go`
  - a category in `report_model.go` (`findingCategory`)
  - the event kind in `eventKinds` in `web.go`, if it is also an event
- Never hardcode or store passphrases. Passphrases must be at least 12 characters.
  Secrets are sealed with `Vault.Seal/Open`.
  Never write secrets to logs, findings or the audit trail.
- The TLS 1.0/1.1 probing in `probe.go` is intentional. CodeQL flags it as a false positive.

## The loop for every code change

Run the cheap checks while iterating and the full gate once, before committing.
Do not run the full gate after every small edit.

### 1. While developing (seconds)

- `gofmt -l .` must print nothing.
- `go vet ./...`
- `go test -run '<TestNameOrPattern>' .` for only the area you touched.
- Add or update a test for every change. A bug fix starts with a test that fails.

### 2. Before every commit: the full gate (all must pass)

Run these on the whole modified code base, not just the changed files.

| # | Check | Command | Pass condition |
|---|-------|---------|----------------|
| 1 | Unit and integration tests | `go test -count=1 ./...` | all ok |
| 2 | Race detector | `CGO_ENABLED=1 go test -race -count=1 ./...` (needs a C compiler; on Windows, WinLibs gcc on PATH) | no races |
| 3 | Lint | `golangci-lint run ./...` | 0 issues |
| 4 | Static scan (SAST) | `semgrep scan --error --metrics=off --config p/default --config p/golang --config p/secrets --config p/owasp-top-ten --exclude web/static .` (`--config auto` needs metrics on). On Windows first set `TEMP` and `TMP` to a folder without an 8.3 short name (e.g. `C:\Users\<you>\code\semgrep-tmp`): semgrep-core's AF_UNIX socketpair fails ("Unix_error: Invalid argument socketpair") under `C:\Users\BIGBUN~1\...`. The CI job only gates lines a PR changes; a full local scan also lists older findings (backlog). | 0 new findings. Fix them; do not suppress without a reason on that line. |
| 5 | Dependency scan (SCA) | `osv-scanner --lockfile=go.mod` (or OWASP Dependency-Check), plus `govulncheck ./...` | no known vulnerabilities |
| 6 | Secrets scan | `trufflehog git file://. --only-verified --fail` (also `trufflehog filesystem .`) | 0 findings |
| 7 | Fuzzing | `go test -run xxx -fuzz <FuzzTarget> -fuzztime 30s .` for every Fuzz target in packages you touched | no crashes |
| 8 | Dynamic scan (DAST) | start the agent on a throwaway data dir, then `zap-baseline.py -t https://127.0.0.1:8080 -I` (or ZAP Docker) | no new medium/high alerts |
| 9 | User acceptance (UAT) | see below | every step works |
| 10 | Stress | see below | no errors, no leaks, no deadlock |

If a tool is not installed or cannot run, say so plainly in the summary. Never claim a scan passed when it did not run.

Fuzz targets are in `fuzz_test.go`. Any new parser or input handler (DNS, HTTP, JSON, PEM, forms, files) needs its own `Fuzz...` target.

### UAT (user acceptance): do this for every change that touches behaviour

Use a throwaway data dir (`-data-dir $(mktemp -d)`) and a test domain. Do not point it at real targets without my say-so.
Walk the flow as a user would, with a headless browser (Playwright) or the existing `uat_lab_test.go` lab:

1. First start: create the key and the admin account, sign in, and see the welcome guide.
2. Add a domain with ownership rules. Confirm bad ASN input is rejected.
3. Run a scan against the lab. Check the Dashboard tiles link through to Domains, Assets and Findings.
4. Open a finding. Acknowledge it, reopen it, and check the audit trail.
5. Generate the HTML and PDF report, then open the PDF (`pdftotext`, `pdftoppm`) and check the sections and charts.
6. Settings: take a backup and restore it, upload a test certificate, and check the page still loads.
7. Delete a domain and confirm all its data is gone.
8. Sign in as a viewer and as an analyst. Confirm forbidden actions return 403.

Always test the feature that changed, plus anything it could break. Add a Go test for each UAT step that can be automated.

### Stress

- `go test -race -count=3 .` for flakiness.
- 100+ hosts through the scan path with the lab resolver, and 50 concurrent web requests against the UI and API. Watch for "database is locked", goroutine leaks and slow pages (more than 2s).

## Releasing

- Branch from an updated `main`: `feat/vX.Y.Z` or `fix/<name>`. Never commit to `main`.
- Force-pushes are blocked on every branch (never amend or rebase pushed commits). Fixes go in a new commit, pushed only after
  code scanning for the previous push has finished: the repo rejects a push while it is still running.
- Open the PR with the REST API: `gh api repos/cyberjangle101/cybersour-attack-surface-scanner/pulls -f title=... -f head=... -f base=main -F body=@file.md`
  (`gh pr create` fails here because GraphQL is blocked).
- `main` needs the Security Scan workflow to pass and owner approval. Do not try to bypass it.
- Pushes to a branch with no PR are refused by the code-scanning rule (except the push that creates it): push once, then open the PR.
- Publishing is tag-driven: after the PR merges, tag `vX.Y.Z` on `main` and push the tag. `.github/workflows/release.yml` builds,
  scans, signs `SHA256SUMS` with the `EASM_RELEASE_SIGNING_KEY` secret and publishes. See RELEASING.md. Never handle the private key.
- Installed agents self-update from those releases (`update.go`): never weaken the signature, version-header or GitHub-host checks.
  Plain HTTP and other hosts are only for `-X main.updateAPIBase=http://127.0.0.1:...` test builds.
- Local release build (for testing): `CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=X.Y.Z"` with the newest Go toolchain,
  then `govulncheck -mode=binary` on an unstripped build. Do not commit binaries or stray build output (`easm-agent`).
- Update the README ("What's new" and "Status") for every release: the release workflow refuses a tag the README does not mention.
- One agent per data folder (`easm.lock`). Tests or tools that open a data folder while an agent runs must expect the lock.
- Commit messages are imperative and say why. PR descriptions list what was verified and what could not be run.

## Reporting back

Finish with: what changed, a one-line result per gate item (pass, fail or not run), and any real limitation.
Do not pad it.
