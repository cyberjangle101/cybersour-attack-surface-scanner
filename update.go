package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Self-update, the way most signed desktop and server tools do it:
//
//  1. CI builds a tagged release (vX.Y.Z) and uploads the binaries plus SHA256SUMS,
//     a list of their hashes headed by the version, and SHA256SUMS.sig, an Ed25519
//     signature of that file made with a key that lives only in a CI secret.
//  2. The agent asks GitHub for the newest release, refuses anything not newer than
//     itself, downloads SHA256SUMS and its signature, checks the signature with the
//     public key built into the program and that the signed version is the one
//     offered, then downloads its own binary and checks the hash.
//  3. Only then is the running program swapped: the old file is kept as .old for
//     -rollback, and the new one takes its place (a rename, so it is atomic).
//
// Nothing is installed without an administrator asking for it.

const (
	updateRepo      = "cyberjangle101/cybersour-attack-surface-scanner"
	updateAPI       = "https://api.github.com/repos/" + updateRepo
	sumsAsset       = "SHA256SUMS"
	sigAsset        = "SHA256SUMS.sig"
	sumsHeader      = "# easm-agent "
	maxBinarySize   = 200 << 20 // a release binary is ~20 MiB
	maxSmallAsset   = 64 << 10
	maxReleaseList  = 1 << 20
	updateUserAgent = "easm-agent-updater"
)

// Release is one published version.
type Release struct {
	Version   string    `json:"version"` // "1.9.0"
	Tag       string    `json:"tag"`
	URL       string    `json:"url"`   // release page
	Notes     string    `json:"notes"` // release notes (markdown, shown as text)
	Published time.Time `json:"published"`
	assets    map[string]string
}

// Updater finds, verifies and installs releases.
type Updater struct {
	API       string            // GitHub releases API base
	Current   string            // running version
	PublicKey ed25519.PublicKey // nil: this build cannot verify, so it never installs
	GOOS      string
	GOARCH    string
	Client    *http.Client
	// AllowHTTP permits plain-http hosts (tests with a local release server only).
	AllowHTTP bool
}

// updateAPIBase can be pointed at a local release server for end-to-end tests with
// -ldflags "-X main.updateAPIBase=http://127.0.0.1:PORT/repo". Only a loopback
// address may use plain HTTP; signatures are checked either way.
var updateAPIBase = updateAPI

// NewUpdater is the production updater for this build.
func NewUpdater() *Updater {
	u := &Updater{API: updateAPIBase, Current: version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if l, err := url.Parse(updateAPIBase); err == nil && l.Scheme == "http" && l.Hostname() == "127.0.0.1" {
		u.AllowHTTP = true
	}
	if k, err := parsePublicKey(releasePublicKey); err == nil {
		u.PublicKey = k
	}
	u.Client = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: u.checkRedirect}
	return u
}

// ErrNoVerificationKey means this build has no release key, so it cannot install updates.
var ErrNoVerificationKey = errors.New("this build has no release signing key, so it cannot verify updates; install new versions by hand")

func parsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("release public key must be 32 bytes, base64")
	}
	return ed25519.PublicKey(b), nil
}

// CanInstall reports whether this build is able to verify (and so install) updates.
func (u *Updater) CanInstall() bool { return len(u.PublicKey) == ed25519.PublicKeySize }

// AssetName is the release file for a platform.
func AssetName(goos, goarch string) string {
	n := "easm-agent-" + goos + "-" + goarch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

// checkRedirect keeps downloads on GitHub (release files are served from its CDN).
func (u *Updater) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	return u.allowedURL(req.URL)
}

func (u *Updater) allowedURL(l *url.URL) error {
	if u.AllowHTTP {
		return nil
	}
	if l.Scheme != "https" || !isGitHubHost(l.Hostname()) {
		return fmt.Errorf("refusing to download from %s", l.Redacted())
	}
	return nil
}

// isGitHubHost is true for GitHub's API, site and release-download CDN.
func isGitHubHost(host string) bool {
	h := strings.ToLower(host)
	return h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

func (u *Updater) get(ctx context.Context, rawURL string, limit int64, accept string) ([]byte, error) {
	l, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := u.allowedURL(l); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updateUserAgent+"/"+u.Current)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", l.Path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than expected", l.Path)
	}
	return b, nil
}

// Latest returns the newest stable release (drafts, pre-releases and tags that are
// not versions, such as an old "Windows" tag, are ignored).
func (u *Updater) Latest(ctx context.Context) (*Release, error) {
	b, err := u.get(ctx, u.API+"/releases?per_page=30", maxReleaseList, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	var list []struct {
		Tag        string    `json:"tag_name"`
		Draft      bool      `json:"draft"`
		Prerelease bool      `json:"prerelease"`
		URL        string    `json:"html_url"`
		Body       string    `json:"body"`
		Published  time.Time `json:"published_at"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("checking for updates: unexpected answer from GitHub: %w", err)
	}
	var best *Release
	for _, r := range list {
		v, ok := parseVersion(r.Tag)
		if !ok || r.Draft || r.Prerelease || v.pre != "" {
			continue
		}
		if best != nil && !newerThan(v, mustVersion(best.Version)) {
			continue
		}
		rel := &Release{Version: v.String(), Tag: r.Tag, URL: r.URL, Notes: clip(r.Body, 8000), Published: r.Published, assets: map[string]string{}}
		for _, a := range r.Assets {
			rel.assets[a.Name] = a.URL
		}
		best = rel
	}
	if best == nil {
		return nil, ErrNoRelease
	}
	return best, nil
}

// ErrNoRelease means no versioned release has been published yet.
var ErrNoRelease = errors.New("no versioned release has been published yet")

// IsNewer reports whether r is newer than the running version. A development build
// ("dev") is older than every release.
func (u *Updater) IsNewer(r *Release) bool {
	cur, ok := parseVersion(u.Current)
	if !ok {
		cur = semver{}
	}
	return newerThan(mustVersion(r.Version), cur)
}

// Fetch downloads this platform's binary of r into dir and verifies it. It returns
// the path of the verified file, which the caller installs with ReplaceExecutable.
func (u *Updater) Fetch(ctx context.Context, r *Release, dir string) (string, error) {
	if !u.CanInstall() {
		return "", ErrNoVerificationKey
	}
	if !u.IsNewer(r) {
		return "", fmt.Errorf("version %s is not newer than the running %s", r.Version, u.Current)
	}
	name := AssetName(u.GOOS, u.GOARCH)
	sumsURL, sigURL, binURL := r.assets[sumsAsset], r.assets[sigAsset], r.assets[name]
	if sumsURL == "" || sigURL == "" {
		return "", fmt.Errorf("release %s is not signed (no %s / %s); not installing it", r.Tag, sumsAsset, sigAsset)
	}
	if binURL == "" {
		return "", fmt.Errorf("release %s has no build for %s/%s", r.Tag, u.GOOS, u.GOARCH)
	}
	sums, err := u.get(ctx, sumsURL, maxSmallAsset, "")
	if err != nil {
		return "", err
	}
	sig, err := u.get(ctx, sigURL, maxSmallAsset, "")
	if err != nil {
		return "", err
	}
	want, err := verifySums(u.PublicKey, sums, sig, r.Version, name)
	if err != nil {
		return "", err
	}
	bin, err := u.get(ctx, binURL, maxBinarySize, "application/octet-stream")
	if err != nil {
		return "", err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("downloaded %s does not match its signed checksum; not installing it", name)
	}
	path := filepath.Join(dir, name+".download")
	if err := os.WriteFile(path, bin, 0o700); err != nil { //nolint:gosec // G306: an executable must be executable by its owner
		return "", err
	}
	return path, nil
}

// verifySums checks the signature on SHA256SUMS, that it is for version and returns
// the hash it lists for asset.
func verifySums(pub ed25519.PublicKey, sums, sig []byte, version, asset string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, raw) {
		return "", errors.New("the release signature is not valid for this program's release key; not installing it")
	}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	header := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, sumsHeader); ok {
			if strings.TrimPrefix(strings.TrimSpace(v), "v") != version {
				return "", fmt.Errorf("signed checksums are for version %s, not %s; not installing it", strings.TrimSpace(v), version)
			}
			header = true
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset && len(f[0]) == 64 {
			if !header {
				return "", errors.New("signed checksums do not name their version; not installing it")
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("signed checksums do not list %s", asset)
}

// ReplaceExecutable puts the verified file newFile in place of exe, keeping the
// previous program as exe+".old" for -rollback. On Windows a running program can
// be renamed but not overwritten, which is why this renames rather than copies.
func ReplaceExecutable(exe, newFile string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("moving the current program aside: %w", err)
	}
	if err := os.Rename(newFile, exe); err != nil {
		if rerr := os.Rename(old, exe); rerr != nil {
			return fmt.Errorf("installing the update failed (%v) and putting the old program back failed too (%v): copy %s to %s by hand", err, rerr, old, exe)
		}
		return fmt.Errorf("installing the update: %w (the old program is unchanged)", err)
	}
	return nil
}

// Rollback swaps the program back to the version kept by the last update.
func Rollback(exe string) error {
	old := exe + ".old"
	if _, err := os.Stat(old); err != nil {
		return fmt.Errorf("no previous version to go back to (%s not found)", old)
	}
	newer := exe + ".rolledback"
	_ = os.Remove(newer)
	if err := os.Rename(exe, newer); err != nil {
		return err
	}
	if err := os.Rename(old, exe); err != nil {
		_ = os.Rename(newer, exe)
		return err
	}
	return nil
}

// ---- versions

type semver struct {
	maj, min, pat int
	pre           string
}

func (v semver) String() string {
	s := strconv.Itoa(v.maj) + "." + strconv.Itoa(v.min) + "." + strconv.Itoa(v.pat)
	if v.pre != "" {
		s += "-" + v.pre
	}
	return s
}

// parseVersion reads "1.9.0", "v1.9.0" or "1.9.0-rc.1".
func parseVersion(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, pre, _ := strings.Cut(s, "-")
	p := strings.Split(core, ".")
	if len(p) != 3 {
		return semver{}, false
	}
	var n [3]int
	for i, x := range p {
		v, err := strconv.Atoi(x)
		if err != nil || v < 0 || v > 1e6 || (len(x) > 1 && x[0] == '0') {
			return semver{}, false
		}
		n[i] = v
	}
	return semver{n[0], n[1], n[2], pre}, true
}

func mustVersion(s string) semver { v, _ := parseVersion(s); return v }

// newerThan compares release versions; a pre-release is older than its release.
func newerThan(a, b semver) bool {
	if a.maj != b.maj {
		return a.maj > b.maj
	}
	if a.min != b.min {
		return a.min > b.min
	}
	if a.pat != b.pat {
		return a.pat > b.pat
	}
	return a.pre == "" && b.pre != ""
}
