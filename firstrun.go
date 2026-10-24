package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// minPassphrase is the shortest key-file passphrase accepted.
const minPassphrase = 12

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ensureKeyFile makes sure the encryption key exists before the database is
// opened. On the very first start it asks for a passphrase (twice, at a
// terminal), or takes it from EASM_KEY_PASSPHRASE for unattended installs, and
// creates the key file locked with it. When the key file already exists it
// does nothing; the passphrase is then asked for when the key is opened.
func ensureKeyFile(boot *Bootstrap, log *slog.Logger) error {
	if fileExists(boot.KeyPath()) {
		return nil
	}
	if fileExists(boot.DBPath()) {
		return fmt.Errorf("the database %s exists but its key file %s is missing; restore the key file from a backup (a new key could not open the old data)", boot.DBPath(), boot.KeyPath())
	}
	pass, err := firstRunPassphrase(boot)
	if err != nil {
		return err
	}
	if err := createKeyFile(boot.KeyPath(), pass); err != nil {
		return err
	}
	if pass == "" {
		log.Warn("encryption key created WITHOUT a passphrase: anyone who can copy the data folder can read the database")
		return nil
	}
	// The key was just locked with this passphrase; do not ask for it a second time.
	PassphraseSource = func() (string, error) { return pass, nil }
	log.Info("encryption key created and locked with your passphrase", "file", boot.KeyPath())
	return nil
}

// firstRunPassphrase obtains the passphrase for a brand-new installation.
func firstRunPassphrase(boot *Bootstrap) (string, error) {
	if boot.NoPassphrase {
		return "", nil
	}
	if p := os.Getenv("EASM_KEY_PASSPHRASE"); p != "" {
		if len(p) < minPassphrase {
			return "", fmt.Errorf("EASM_KEY_PASSPHRASE must be at least %d characters", minPassphrase)
		}
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("first start needs a passphrase to protect the database encryption key. " +
			"Run the program once from a terminal to be asked for it, set EASM_KEY_PASSPHRASE, " +
			"or start with -no-passphrase to store the key unprotected (not recommended)")
	}
	_, _ = fmt.Fprintf(os.Stderr, "\nFirst start: choose a passphrase to protect the database encryption key.\n"+
		"At least %d characters. You will be asked for it every time the program starts\n"+
		"(for a service, set EASM_KEY_PASSPHRASE instead). If it is lost, the data cannot be recovered.\n\n", minPassphrase)
	for attempt := 0; attempt < 3; attempt++ {
		p, err := readPassword("Choose a passphrase: ")
		if err != nil {
			return "", err
		}
		if len(p) < minPassphrase {
			_, _ = fmt.Fprintf(os.Stderr, "Too short: use at least %d characters (a few words is easy to remember and hard to guess).\n", minPassphrase)
			continue
		}
		again, err := readPassword("Repeat the passphrase: ")
		if err != nil {
			return "", err
		}
		if again != p {
			_, _ = fmt.Fprintln(os.Stderr, "The two entries do not match; try again.")
			continue
		}
		return p, nil
	}
	return "", errors.New("no valid passphrase entered")
}

// createKeyFile writes a new random 256-bit master key to path (owner-only),
// locked with pass, or as plain hex when pass is empty.
func createKeyFile(path, pass string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if pass == "" {
		return writeFileAtomic(path, []byte(hex.EncodeToString(key)+"\n"))
	}
	wrapped, err := wrapKey(key, pass)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, wrapped)
}
