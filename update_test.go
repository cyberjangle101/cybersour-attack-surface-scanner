package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeReleases is a stand-in for the GitHub releases API and its download CDN.
type fakeReleases struct {
	srv   *httptest.Server
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	mu    sync.Mutex
	files map[string][]byte // path -> body
	list  []map[string]any
	hits  map[string]int
}

func newFakeReleases(t *testing.T) *fakeReleases {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeReleases{priv: priv, pub: pub, files: map[string][]byte{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if r.URL.Path == "/repo/releases" {
			_ = json.NewEncoder(w).Encode(f.list)
			return
		}
		b, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// publish adds a release; bins maps asset name -> content. sign=false leaves it unsigned.
func (f *fakeReleases) publish(tag string, bins map[string][]byte, sign bool, extra ...func(sums []byte) []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ver := strings.TrimPrefix(tag, "v")
	var assets []map[string]any
	sums := "# easm-agent " + ver + "\n"
	for name, b := range bins {
		p := "/dl/" + tag + "/" + name
		f.files[p] = b
		assets = append(assets, map[string]any{"name": name, "browser_download_url": f.srv.URL + p})
		h := sha256.Sum256(b)
		sums += hex.EncodeToString(h[:]) + "  " + name + "\n"
	}
	if sign {
		sb := []byte(sums)
		sig := ed25519.Sign(f.priv, sb)
		for _, x := range extra {
			sb = x(sb) // tamper after signing
		}
		f.files["/dl/"+tag+"/SHA256SUMS"] = sb
		f.files["/dl/"+tag+"/SHA256SUMS.sig"] = []byte(base64.StdEncoding.EncodeToString(sig))
		assets = append(assets,
			map[string]any{"name": "SHA256SUMS", "browser_download_url": f.srv.URL + "/dl/" + tag + "/SHA256SUMS"},
			map[string]any{"name": "SHA256SUMS.sig", "browser_download_url": f.srv.URL + "/dl/" + tag + "/SHA256SUMS.sig"})
	}
	f.list = append(f.list, map[string]any{"tag_name": tag, "html_url": "https://example.test/" + tag, "body": "notes for " + tag,
		"published_at": time.Now().UTC().Format(time.RFC3339), "assets": assets})
}

func (f *fakeReleases) updater(current string) *Updater {
	return &Updater{API: f.srv.URL + "/repo", Current: current, PublicKey: f.pub, GOOS: "windows", GOARCH: "amd64",
		Client: &http.Client{Timeout: 10 * time.Second}, AllowHTTP: true}
}

const winAsset = "easm-agent-windows-amd64.exe"

func TestUpdaterPicksNewestStableRelease(t *testing.T) {
	f := newFakeReleases(t)
	f.publish("Windows", map[string][]byte{"cybersour.exe": []byte("old manual upload")}, false)
	f.publish("v1.8.0", map[string][]byte{winAsset: []byte("v180")}, true)
	f.publish("v1.10.0", map[string][]byte{winAsset: []byte("v1100")}, true) // numeric, not string, order
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("v190")}, true)
	f.publish("v2.0.0-rc.1", map[string][]byte{winAsset: []byte("rc")}, true)
	f.mu.Lock()
	f.list = append(f.list, map[string]any{"tag_name": "v3.0.0", "draft": true})
	f.list = append(f.list, map[string]any{"tag_name": "v2.5.0", "prerelease": true})
	f.mu.Unlock()

	u := f.updater("1.8.0")
	r, err := u.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "1.10.0" || !u.IsNewer(r) || r.Notes != "notes for v1.10.0" {
		t.Fatalf("latest = %+v", r)
	}
	if u.Current = "1.10.0"; u.IsNewer(r) {
		t.Error("the running version must not count as an update")
	}
	if u.Current = "dev"; !u.IsNewer(r) {
		t.Error("a development build should be offered releases")
	}
}

func TestUpdaterFetchVerifiesEverything(t *testing.T) {
	good := []byte("the real v1.9.0 binary")
	cases := []struct {
		name    string
		setup   func(f *fakeReleases)
		current string
		wantErr string
	}{
		{"valid release installs", func(f *fakeReleases) { f.publish("v1.9.0", map[string][]byte{winAsset: good}, true) }, "1.8.0", ""},
		{"binary swapped after signing", func(f *fakeReleases) {
			f.publish("v1.9.0", map[string][]byte{winAsset: good}, true)
			f.files["/dl/v1.9.0/"+winAsset] = []byte("malware")
		}, "1.8.0", "does not match its signed checksum"},
		{"checksums edited after signing", func(f *fakeReleases) {
			f.publish("v1.9.0", map[string][]byte{winAsset: good}, true, func(b []byte) []byte { return append(b, []byte("0000  extra\n")...) })
		}, "1.8.0", "signature is not valid"},
		{"signed by another key", func(f *fakeReleases) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.priv = other
			f.publish("v1.9.0", map[string][]byte{winAsset: good}, true)
		}, "1.8.0", "signature is not valid"},
		{"old signed release replayed under a new tag", func(f *fakeReleases) {
			f.publish("v1.9.0", map[string][]byte{winAsset: good}, true, func(b []byte) []byte { return b })
			// re-sign the checksums of 1.7.0 and serve them as 1.9.0's
			sums := []byte("# easm-agent 1.7.0\n" + hex.EncodeToString(sha256Sum(good)) + "  " + winAsset + "\n")
			f.files["/dl/v1.9.0/SHA256SUMS"] = sums
			f.files["/dl/v1.9.0/SHA256SUMS.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, sums)))
		}, "1.8.0", "for version 1.7.0, not 1.9.0"},
		{"not newer than the running version", func(f *fakeReleases) { f.publish("v1.9.0", map[string][]byte{winAsset: good}, true) }, "1.9.0", "not newer"},
		{"unsigned release", func(f *fakeReleases) { f.publish("v1.9.0", map[string][]byte{winAsset: good}, false) }, "1.8.0", "not signed"},
		{"no build for this platform", func(f *fakeReleases) {
			f.publish("v1.9.0", map[string][]byte{"easm-agent-linux-amd64": good}, true)
		}, "1.8.0", "no build for windows/amd64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeReleases(t)
			c.setup(f)
			u := f.updater(c.current)
			r, err := u.Latest(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path, err := u.Fetch(context.Background(), r, dir)
			if c.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if b, _ := os.ReadFile(path); string(b) != string(good) {
					t.Fatalf("downloaded %q", b)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("a refused download left files behind: %v", entries)
			}
		})
	}
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func TestUpdaterWithoutKeyNeverInstalls(t *testing.T) {
	f := newFakeReleases(t)
	f.publish("v1.9.0", map[string][]byte{winAsset: []byte("x")}, true)
	u := f.updater("1.8.0")
	u.PublicKey = nil
	r, err := u.Latest(context.Background())
	if err != nil || !u.IsNewer(r) {
		t.Fatalf("a keyless build should still report updates: %v", err)
	}
	if _, err := u.Fetch(context.Background(), r, t.TempDir()); !errors.Is(err, ErrNoVerificationKey) {
		t.Fatalf("err = %v", err)
	}
	if u.CanInstall() {
		t.Error("CanInstall without a key")
	}
	if _, err := parsePublicKey(""); err == nil {
		t.Error("empty key accepted")
	}
}

func TestUpdaterStaysOnGitHub(t *testing.T) {
	u := NewUpdater()
	for _, bad := range []string{"http://github.com/x", "https://evil.example/easm.exe", "https://github.com.evil.example/x", "https://githubusercontent.com.evil/x", "file:///c:/windows/x"} {
		l, _ := url.Parse(bad)
		if u.allowedURL(l) == nil {
			t.Errorf("%s allowed", bad)
		}
	}
	for _, ok := range []string{"https://api.github.com/repos/x/y/releases", "https://github.com/x/y/releases/download/v1/a", "https://objects.githubusercontent.com/a", "https://release-assets.githubusercontent.com/a"} {
		l, _ := url.Parse(ok)
		if err := u.allowedURL(l); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	// A redirect from GitHub to elsewhere is refused too.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer evil.Close()
	redir := httptest.NewServer(http.RedirectHandler(evil.URL, http.StatusFound))
	defer redir.Close()
	u.AllowHTTP = false
	l, _ := url.Parse(redir.URL)
	req := &http.Request{URL: l}
	if u.checkRedirect(req, nil) == nil {
		t.Error("redirect off GitHub accepted")
	}
}

func TestReplaceAndRollback(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "easm-agent.exe")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if err := Rollback(exe); err == nil {
		t.Error("rollback with nothing to roll back to")
	}
	write(exe, "v1.8.0")
	write(exe+".download", "v1.9.0")
	if err := ReplaceExecutable(exe, exe+".download"); err != nil {
		t.Fatal(err)
	}
	if read(exe) != "v1.9.0" || read(exe+".old") != "v1.8.0" {
		t.Fatalf("after update: exe=%q old=%q", read(exe), read(exe+".old"))
	}
	if err := Rollback(exe); err != nil {
		t.Fatal(err)
	}
	if read(exe) != "v1.8.0" {
		t.Fatalf("after rollback: %q", read(exe))
	}
	// A failed install leaves the old program in place.
	if err := ReplaceExecutable(exe, filepath.Join(dir, "missing")); err == nil || read(exe) != "v1.8.0" {
		t.Fatalf("failed install: err=%v exe=%q", err, read(exe))
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{"1.9.0": "1.9.0", "v1.10.2": "1.10.2", "v2.0.0-rc.1": "2.0.0-rc.1"} {
		if v, ok := parseVersion(in); !ok || v.String() != want {
			t.Errorf("%q -> %v %v", in, v, ok)
		}
	}
	for _, bad := range []string{"", "Windows", "1.9", "1.9.0.1", "v01.2.3", "1.-2.3", "dev", "1.2.x"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if !newerThan(mustVersion("1.10.0"), mustVersion("1.9.9")) || newerThan(mustVersion("2.0.0-rc.1"), mustVersion("2.0.0")) ||
		!newerThan(mustVersion("2.0.0"), mustVersion("2.0.0-rc.1")) || newerThan(mustVersion("1.0.0"), mustVersion("1.0.0")) {
		t.Error("version ordering")
	}
}
