package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// Vault holds the master key. It seals individual secrets (API keys, the SMTP
// password, password hashes) with AES-256-GCM and derives the whole-database key.
// The key lives in easm.key; with a passphrase it is stored locked (scrypt +
// AES-GCM) and only usable once the passphrase is supplied at start-up.
type Vault struct {
	aead   cipher.AEAD
	master []byte // 256-bit master key; the database key is derived from it (see tde.go)

	pmu  sync.Mutex
	mode string // how easm.key is stored: keyPassphrase, keyWindows or keyPlain
}

// wrappedMagic starts a passphrase-protected key file.
const wrappedMagic = "easm-key-v2-scrypt\n"

// dpapiMagic starts a key file protected with the Windows account (DPAPI, keyprotect_windows.go).
const dpapiMagic = "easm-key-v3-dpapi\n"

// How the key file is protected.
const (
	keyPassphrase = "passphrase" // scrypt + AES-GCM: asked for (or EASM_KEY_PASSPHRASE) at every start
	keyWindows    = "windows"    // DPAPI: only the Windows account that wrote it, on this computer, can open it
	keyPlain      = "none"       // 64 hex characters: anyone who can read the file can use it
)

// errDPAPIKey explains a Windows-protected key file that this account cannot open.
var errDPAPIKey = errors.New("easm.key is protected with the Windows account that created it, and only that account on this computer can open it. " +
	"Run the agent as that account (for a service: the service's account), or restore the key from the recovery copy made in System health → Encryption key")

// PassphraseSource supplies the key-file passphrase when the key file is protected.
// The default reads EASM_KEY_PASSPHRASE and falls back to a terminal prompt.
var PassphraseSource = func() (string, error) {
	if p := os.Getenv("EASM_KEY_PASSPHRASE"); p != "" {
		return p, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readPassword("Key file passphrase: ")
	}
	return "", errors.New("easm.key is passphrase-protected: set the EASM_KEY_PASSPHRASE environment variable (or start the program from a terminal to be prompted)")
}

// passphraseAttempts is how many passphrases someone at the terminal may try.
const passphraseAttempts = 3

// passphraseInteractive reports whether PassphraseSource will ask someone at the
// terminal, who can try again after a typo. A passphrase from the environment
// (services, tests) gets one attempt.
var passphraseInteractive = func() bool {
	return os.Getenv("EASM_KEY_PASSPHRASE") == "" && term.IsTerminal(int(os.Stdin.Fd()))
}

// promptOut receives the messages shown around the passphrase prompt.
var promptOut io.Writer = os.Stderr

// unlockKey asks for the passphrase and decrypts the key file, allowing
// passphraseAttempts tries at a terminal.
func unlockKey(raw []byte) ([]byte, error) {
	tries := 1
	if passphraseInteractive() {
		tries = passphraseAttempts
	}
	for i := 1; ; i++ {
		pass, err := PassphraseSource()
		if err != nil {
			return nil, err
		}
		key, err := unwrapKey(raw, pass)
		if err == nil || !errors.Is(err, errWrongPassphrase) || tries == 1 {
			return key, err
		}
		if i == tries {
			_, _ = fmt.Fprintln(promptOut, "Incorrect Password. Aborting.")
			return nil, fmt.Errorf("%w (%d attempts)", err, tries)
		}
		_, _ = fmt.Fprintln(promptOut, "Incorrect Password, try again.")
	}
}

// OpenVault loads the master key from path, creating a new random key on first run.
// A passphrase-protected key file is unlocked with PassphraseSource.
func OpenVault(path string) (*Vault, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own key file
	var key []byte
	mode := keyPlain
	switch {
	case err == nil && strings.HasPrefix(string(raw), wrappedMagic):
		if key, err = unlockKey(raw); err != nil {
			return nil, err
		}
		mode = keyPassphrase
	case err == nil && strings.HasPrefix(string(raw), dpapiMagic):
		if key, err = unwrapWindows(raw); err != nil {
			return nil, err
		}
		mode = keyWindows
	case err == nil:
		k, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(k) != 32 {
			return nil, errors.New("key file is corrupt (expected 64 hex characters)")
		}
		key = k
	case os.IsNotExist(err):
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: g, master: key, mode: mode}, nil
}

// wrapWindows writes the master key as a key file only this Windows account can open.
func wrapWindows(key []byte) ([]byte, error) {
	blob, err := dpapiProtect(key)
	if err != nil {
		return nil, err
	}
	return []byte(dpapiMagic + base64.StdEncoding.EncodeToString(blob) + "\n"), nil
}

// unwrapWindows opens a key file written by wrapWindows.
func unwrapWindows(file []byte) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(string(file), dpapiMagic)))
	if err != nil {
		return nil, errors.New("the Windows-protected key file is corrupt")
	}
	key, err := dpapiUnprotect(blob)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%w (%v)", errDPAPIKey, err)
	}
	return key, nil
}

// Protection says how the key file is stored (keyPassphrase, keyWindows or keyPlain).
func (v *Vault) Protection() string {
	v.pmu.Lock()
	defer v.pmu.Unlock()
	return v.mode
}

// ProtectWithWindows rewrites the key file at path so that only the Windows account
// this agent runs as can open it, with nothing to type at start-up.
func (v *Vault) ProtectWithWindows(path string) error {
	out, err := wrapWindows(v.master)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, out); err != nil {
		return err
	}
	v.pmu.Lock()
	v.mode = keyWindows
	v.pmu.Unlock()
	return nil
}

// RecoveryCopy returns the master key locked with pass, in the passphrase key-file
// format: saved as easm.key it opens with that passphrase on any computer. It is the
// way to move or rebuild an installation whose key is tied to a Windows account.
func (v *Vault) RecoveryCopy(pass string) ([]byte, error) {
	if len(pass) < minPassphrase {
		return nil, fmt.Errorf("the recovery passphrase must be at least %d characters", minPassphrase)
	}
	return wrapKey(v.master, pass)
}

// wrapKey encrypts the master key under a passphrase (scrypt N=2^15, AES-256-GCM).
func wrapKey(key []byte, pass string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kek, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(kek)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	blob := append(append(salt, nonce...), g.Seal(nil, nonce, key, []byte(wrappedMagic))...)
	return []byte(wrappedMagic + base64.StdEncoding.EncodeToString(blob) + "\n"), nil
}

var errWrongPassphrase = errors.New("wrong key-file passphrase")

// unwrapKey decrypts a passphrase-protected key file.
func unwrapKey(file []byte, pass string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(string(file), wrappedMagic)))
	if err != nil || len(blob) < 16+12+32 {
		return nil, errors.New("protected key file is corrupt")
	}
	kek, err := scrypt.Key([]byte(pass), blob[:16], 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(kek)
	g, _ := cipher.NewGCM(blk)
	ns := g.NonceSize()
	key, err := g.Open(nil, blob[16:16+ns], blob[16+ns:], []byte(wrappedMagic))
	if err != nil {
		return nil, errWrongPassphrase
	}
	return key, nil
}

// ProtectKeyFile re-writes easm.key so it can only be used with the passphrase.
func ProtectKeyFile(path, pass string) error {
	v, err := OpenVault(path)
	if err != nil {
		return err
	}
	if pass == "" {
		return errors.New("passphrase must not be empty")
	}
	out, err := wrapKey(v.master, pass)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out)
}

// UnprotectKeyFile removes the passphrase protection (key stored as plain hex again).
func UnprotectKeyFile(path string) error {
	v, err := OpenVault(path)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(hex.EncodeToString(v.master)+"\n"))
}

// writeFileAtomic replaces path via a temp file so a crash can never leave a half-written key.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Seal encrypts a secret with AES-256-GCM and a random nonce, returning base64.
func (v *Vault) Seal(plain string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// Open decrypts a value produced by Seal.
func (v *Vault) Open(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	ns := v.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	out, err := v.aead.Open(nil, raw[:ns], raw[ns:], nil)
	return string(out), err
}
