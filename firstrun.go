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
	if errors.Is(err, errUseWindows) {
		if err := createWindowsKeyFile(boot.KeyPath()); err != nil {
			return fmt.Errorf("protecting the new key with the Windows account: %w", err)
		}
		log.Info("encryption key created and protected with this Windows account: nothing to type at start-up, and only this account on this computer can open it. "+
			"Make a recovery copy in System health → Encryption key", "file", boot.KeyPath(), "account", windowsAccount())
		return nil
	}
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

// errUseWindows asks for the new key to be protected with the Windows account (DPAPI) instead of a passphrase.
var errUseWindows = errors.New("protect the key with the Windows account")

// firstRunPassphrase obtains the passphrase for a brand-new installation, or
// errUseWindows when the key should be tied to the Windows account instead: always
// for a Windows service (nobody can type a passphrase, and an environment variable
// would be readable by every user of the server), and at the console when the
// person presses Enter without typing one.
func firstRunPassphrase(boot *Bootstrap) (string, error) {
	if boot.NoPassphrase {
		return "", nil
	}
	if p, ok, err := envPassphrase(); ok {
		if err != nil {
			return "", err
		}
		if len(p) < minPassphrase {
			return "", fmt.Errorf("the passphrase from EASM_KEY_PASSPHRASE(_FILE) must be at least %d characters", minPassphrase)
		}
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if dpapiSupported {
			return "", errUseWindows
		}
		return "", errors.New("first start needs a passphrase to protect the database encryption key. " +
			"Run the program once from a terminal to be asked for it, set EASM_KEY_PASSPHRASE or EASM_KEY_PASSPHRASE_FILE, " +
			"or start with -no-passphrase to store the key unprotected (not recommended)")
	}
	_, _ = fmt.Fprintf(os.Stderr, "\nFirst start: choose a passphrase to protect the database encryption key.\n"+
		"At least %d characters. You will be asked for it every time the program starts.\n"+
		"If it is lost, the data cannot be recovered.\n", minPassphrase)
	if dpapiSupported {
		_, _ = fmt.Fprintf(os.Stderr, "Or press Enter without typing to protect it with your Windows account (%s) instead:\n"+
			"nothing to type at start-up, and only that account on this computer can open it.\n", windowsAccount())
	}
	_, _ = fmt.Fprintln(os.Stderr)
	for attempt := 0; attempt < 3; attempt++ {
		p, err := readPassword("Choose a passphrase: ")
		if err != nil {
			return "", err
		}
		if p == "" && dpapiSupported {
			return "", errUseWindows
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

// createWindowsKeyFile writes a new random master key that only the current Windows account can open.
func createWindowsKeyFile(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	out, err := wrapWindows(key)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out)
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
