package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"

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
}

// wrappedMagic starts a passphrase-protected key file.
const wrappedMagic = "easm-key-v2-scrypt\n"

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

// OpenVault loads the master key from path, creating a new random key on first run.
// A passphrase-protected key file is unlocked with PassphraseSource.
func OpenVault(path string) (*Vault, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own key file
	var key []byte
	switch {
	case err == nil && strings.HasPrefix(string(raw), wrappedMagic):
		pass, perr := PassphraseSource()
		if perr != nil {
			return nil, perr
		}
		if key, err = unwrapKey(raw, pass); err != nil {
			return nil, err
		}
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
	return &Vault{aead: g, master: key}, nil
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
		return nil, errors.New("wrong key-file passphrase")
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
