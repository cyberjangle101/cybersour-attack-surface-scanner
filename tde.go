package main

// Transparent database encryption (TDE).
//
// The whole SQLite file (tables, indexes, free pages, journals and temporary files) is encrypted
// with AES-256-XTS by the "xts" virtual file system. Encryption happens below SQLite, so no
// application code changes and nothing readable (host names, findings, API keys, SMTP settings,
// password hashes) ever reaches the disk in clear. The 512-bit XTS key is derived from the
// master key held in easm.key (see vault.go), never stored in the database itself.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/xts" // registers the "xts" VFS
)

// sqliteMagic is the header of an unencrypted SQLite 3 database file.
var sqliteMagic = []byte("SQLite format 3\x00")

// DBKey derives the AES-256-XTS key (64 bytes: data key + tweak key) from the master key.
// A distinct label keeps it independent from the key used to seal individual secrets.
func (v *Vault) DBKey() []byte {
	m := hmac.New(sha512.New, v.master)
	m.Write([]byte("easm-agent/database/aes-256-xts/v1"))
	return m.Sum(nil)
}

// fileURI turns a filesystem path into a SQLite "file:" URI that selects the xts VFS.
// "file:C:/x/y.db" (no "//") is taken as a plain path by SQLite and works on Windows and Unix.
func fileURI(path string) string {
	p := filepath.ToSlash(path)
	r := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")
	return "file:" + r.Replace(p) + "?vfs=xts"
}

// isPlainSQLite reports whether the file exists and is an unencrypted SQLite database.
func isPlainSQLite(path string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the agent's own data file
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, len(sqliteMagic))
	n, err := io.ReadFull(f, head)
	if err != nil && n == 0 {
		return false, nil // empty file: treat as new
	}
	return bytes.Equal(head[:n], sqliteMagic), nil
}

// openEncryptedDB opens (creating if needed) an xts-encrypted database with the given key.
func openEncryptedDB(path string, key []byte) (*sql.DB, error) {
	if len(key) != 64 {
		return nil, errors.New("database key must be 64 bytes")
	}
	hexKey := hex.EncodeToString(key)
	db, err := driver.Open(fileURI(path), func(c *sqlite3.Conn) error {
		// The key goes in through a PRAGMA (not the URI) so it never appears in a file name.
		return c.Exec("PRAGMA hexkey='" + hexKey + "'")
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}

// OpenEncryptedStore opens the transparently encrypted database. A plaintext database left by an
// earlier version is migrated automatically (and its plaintext copy securely overwritten).
func OpenEncryptedStore(path string, key []byte, log *slog.Logger) (*Store, error) {
	tmp := path + ".encrypting"
	// Finish an interrupted migration: the encrypted copy was verified but not yet moved into place.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(tmp); err == nil {
			if err := os.Rename(tmp, path); err != nil {
				return nil, fmt.Errorf("completing interrupted encryption: %w", err)
			}
		}
	}
	plain, err := isPlainSQLite(path)
	if err != nil {
		return nil, err
	}
	if plain {
		if err := migratePlainToEncrypted(path, tmp, key, log); err != nil {
			return nil, fmt.Errorf("encrypting existing database: %w", err)
		}
	}
	db, err := openEncryptedDB(path, key)
	if err != nil {
		return nil, err
	}
	st, err := initStore(db, path)
	if err != nil {
		return nil, wrapKeyError(err)
	}
	return st, nil
}

// wrapKeyError turns SQLite's "file is not a database" into advice a person can act on.
func wrapKeyError(err error) error {
	m := strings.ToLower(err.Error())
	if strings.Contains(m, "not a database") || strings.Contains(m, "malformed") || strings.Contains(m, "encrypted") {
		return fmt.Errorf("the database cannot be decrypted with the key in easm.key (wrong or replaced key file, or a damaged database): %w", err)
	}
	return err
}

// migratePlainToEncrypted copies every table into a new encrypted file, verifies it, then
// overwrites and removes the plaintext original.
func migratePlainToEncrypted(path, tmp string, key []byte, log *slog.Logger) error {
	if log != nil {
		log.Info("encrypting the existing database (one-time migration)", "file", path)
	}
	removeDB(tmp)
	old, err := OpenStore(path)
	if err != nil {
		return err
	}
	if _, err := old.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = old.Close()
		return err
	}
	// VACUUM INTO writes a consistent, compact copy through the encrypting VFS.
	dest := fileURI(tmp) + "&hexkey=" + hex.EncodeToString(key)
	if _, err := old.db.Exec("VACUUM INTO ?", dest); err != nil {
		_ = old.Close()
		removeDB(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	want, err := rowCounts(old.db)
	_ = old.Close()
	if err != nil {
		removeDB(tmp)
		return err
	}
	ndb, err := openEncryptedDB(tmp, key)
	if err != nil {
		removeDB(tmp)
		return err
	}
	got, err := rowCounts(ndb)
	if err == nil {
		var res string
		if e := ndb.QueryRow(`PRAGMA integrity_check`).Scan(&res); e != nil || res != "ok" {
			err = fmt.Errorf("integrity check of the encrypted copy failed: %v %s", e, res)
		}
	}
	_ = ndb.Close()
	if err == nil {
		for t, n := range want {
			if got[t] != n {
				err = fmt.Errorf("table %s: %d rows copied of %d", t, got[t], n)
			}
		}
	}
	if err != nil {
		removeDB(tmp)
		return err
	}
	// Verified. Destroy the plaintext, then move the encrypted copy into place.
	shred(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	_ = os.Remove(tmp + "-wal")
	_ = os.Remove(tmp + "-shm")
	if log != nil {
		log.Info("database is now encrypted at rest (AES-256-XTS); the plaintext copy was overwritten")
	}
	return nil
}

// rowCounts returns the number of rows in every user table.
func rowCounts(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, n := range names {
		var c int
		if err := db.QueryRow( // nosemgrep: string-formatted-query, go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- table names come from sqlite_master and are identifier-quoted
			`SELECT COUNT(*) FROM "` + strings.ReplaceAll(n, `"`, `""`) + `"`).Scan(&c); err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, nil
}

// shred overwrites a file with zeros before deleting it, so the plaintext does not linger.
// (On SSDs and journalling file systems this is best effort; full-disk encryption is the backstop.)
func shred(path string) {
	if fi, err := os.Stat(path); err == nil {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil { //nolint:gosec // G304: the agent's own data file
			buf := make([]byte, 1<<20)
			for off := int64(0); off < fi.Size(); off += int64(len(buf)) {
				n := int64(len(buf))
				if rest := fi.Size() - off; rest < n {
					n = rest
				}
				if _, err := f.WriteAt(buf[:n], off); err != nil {
					break
				}
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

func removeDB(path string) {
	for _, s := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(path + s)
	}
}
