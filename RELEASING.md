# Releasing EASM Agent

Releases are built, signed and published by `.github/workflows/release.yml` when a
version tag is pushed. Installed agents find the release with their daily update
check and install it only after verifying its signature (see `update.go`).

## One-time setup: the release signing key

Do this once, on a trusted machine. Only the maintainer holds the private key.

1. Create the key pair:

   ```
   go run ./tools/release keygen -out release-signing.key
   ```

   It prints the **public** key and writes the **private** key to `release-signing.key`.

2. Store the private key as a repository secret named `EASM_RELEASE_SIGNING_KEY`:

   ```
   gh secret set EASM_RELEASE_SIGNING_KEY < release-signing.key
   ```

   Keep an offline copy (for example in a password manager), then delete the file.
   Never commit it.

3. Put the public key in `release_key.go`:

   ```go
   var releasePublicKey = "<the printed public key>"
   ```

   Commit this through a normal PR. Builds made from then on can verify updates;
   older builds report new versions but never install them (download those by hand once).

If the private key is ever exposed, make a new pair, replace the secret and the public
key, and publish a release. Agents still on the old key need that release installed by hand.

## Every release

1. On a `feat/vX.Y.Z` or `fix/...` branch: update the version in README ("Status" and
   "What's new in X.Y"), pass the full gate in `CLAUDE.md`, and merge the PR.
2. UAT first: tag the merge commit on `main` as a release candidate and push it:

   ```
   git tag -a vX.Y.Z-rc.1 -m "EASM Agent X.Y.Z-rc.1"
   git push origin vX.Y.Z-rc.1
   ```

   The workflow runs in the `UAT` environment and publishes a pre-release, which installed
   agents never update to. Its `UAT:` jobs then test that published build: the full test
   gate, Semgrep, a ZAP scan, and on Windows `uat\run.ps1` (lab UAT, upgrade from the current
   release, service install). If any job fails, fix it in a new PR and tag `-rc.2`.
3. Production: once the RC passes UAT, tag the same commit as the release and push it:

   ```
   git tag -a vX.Y.Z -m "EASM Agent X.Y.Z"
   git push origin vX.Y.Z
   ```

   The run first checks that a release candidate of this version passed UAT on this commit
   and stops if none did. It then uses the `Production` environment, so it waits until the
   owner approves it under Actions ("Review deployments").
4. For either tag, the Release workflow:
   - checks that README mentions the version, and runs the tests;
   - builds `easm-agent-windows-amd64.exe`, `easm-agent-linux-amd64` and `easm-agent-linux-arm64`
     with the newest Go toolchain and `-X main.version=X.Y.Z`;
   - scans them with `govulncheck`;
   - writes `SHA256SUMS` (headed `# easm-agent X.Y.Z`), signs it into `SHA256SUMS.sig`,
     verifies the signature against the committed `release_key.go`, and only then publishes
     the GitHub release with generated notes.

   If the secret and `release_key.go` do not match, the workflow stops before publishing.

## What agents do with it

- Once a day (Settings → Organisation → "Check for new versions once a day"), or on
  *System health → Check for updates now*, the agent reads the releases list. It ignores
  drafts, pre-releases and tags that are not `vX.Y.Z`, and never offers an older version.
- *Back up and install* (administrators only, audited): takes a backup, downloads
  `SHA256SUMS` and its signature, checks the signature and that it names this version,
  downloads the binary for the platform and checks its hash, then swaps the program
  (previous version kept as `<program>.old`). On Windows an agent started from its
  `.exe` restarts itself in a new window; a service is restarted by the administrator.
- Command line: `easm-agent -update-check`, `easm-agent -update [-yes]` (stops and
  restarts the service around the swap), `easm-agent -rollback`.
