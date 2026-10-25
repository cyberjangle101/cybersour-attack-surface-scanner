// Command release makes the signed checksum files that easm-agent's updater trusts.
//
//	go run ./tools/release keygen -out release-signing.key   # once; prints the public key
//	go run ./tools/release sums -version 1.9.0 -dir dist      # writes dist/SHA256SUMS
//	go run ./tools/release sign -dir dist                     # writes dist/SHA256SUMS.sig
//	go run ./tools/release verify -dir dist                   # checks it against release_key.go
//
// sign reads the private key from EASM_RELEASE_SIGNING_KEY (base64), never from a
// command-line argument, so it does not end up in shell history or CI logs.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sums":
		err = sums(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: release keygen -out FILE | sums -version X.Y.Z -dir DIR | sign -dir DIR | verify -dir DIR")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the private key to (must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("Private key written to %s. Store it as the EASM_RELEASE_SIGNING_KEY repository secret, keep an offline copy, then delete this file.\n", *out)
	fmt.Printf("Public key (put it in release_key.go):\n%s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sums(args []string) error {
	fs := flag.NewFlagSet("sums", flag.ExitOnError)
	ver := fs.String("version", "", "release version, e.g. 1.9.0")
	dir := fs.String("dir", "dist", "folder with the release binaries")
	_ = fs.Parse(args)
	v := strings.TrimPrefix(*ver, "v")
	if v == "" {
		return errors.New("-version is required")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "easm-agent-") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no easm-agent-* binaries in %s", *dir)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# easm-agent " + v + "\n")
	for _, n := range names {
		h, err := fileSHA256(filepath.Join(*dir, n))
		if err != nil {
			return err
		}
		b.WriteString(h + "  " + n + "\n")
	}
	return os.WriteFile(filepath.Join(*dir, "SHA256SUMS"), []byte(b.String()), 0o644) //nolint:gosec // G306: public release file
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("dir", "dist", "folder with SHA256SUMS")
	_ = fs.Parse(args)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("EASM_RELEASE_SIGNING_KEY")))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return errors.New("EASM_RELEASE_SIGNING_KEY must hold the base64 private key from keygen")
	}
	data, err := os.ReadFile(filepath.Join(*dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(raw), data)
	return os.WriteFile(filepath.Join(*dir, "SHA256SUMS.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644) //nolint:gosec // G306: public release file
}

// verify checks dist against the public key committed in release_key.go, exactly as
// the agent will, so a release signed with the wrong key is never published.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "dist", "folder with SHA256SUMS, SHA256SUMS.sig and the binaries")
	keyFile := fs.String("keyfile", "release_key.go", "Go file declaring releasePublicKey")
	_ = fs.Parse(args)
	src, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`releasePublicKey\s*=\s*"([A-Za-z0-9+/=]*)"`).FindSubmatch(src)
	if m == nil || len(m[1]) == 0 {
		return fmt.Errorf("%s has no releasePublicKey; run keygen and commit the public key first", *keyFile)
	}
	pub, err := base64.StdEncoding.DecodeString(string(m[1]))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("releasePublicKey is not a 32-byte base64 key")
	}
	sums, err := os.ReadFile(filepath.Join(*dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sigText, err := os.ReadFile(filepath.Join(*dir, "SHA256SUMS.sig"))
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || !ed25519.Verify(pub, sums, sig) {
		return errors.New("SHA256SUMS.sig does not verify with the committed public key: the signing secret and release_key.go do not match")
	}
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		h, err := fileSHA256(filepath.Join(*dir, f[1]))
		if err != nil {
			return err
		}
		if h != f[0] {
			return fmt.Errorf("%s does not match SHA256SUMS", f[1])
		}
	}
	fmt.Println("SHA256SUMS signature and every listed file verified.")
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a release binary named by the build
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
