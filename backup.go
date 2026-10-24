package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backups
//
// A backup is one .zip file holding:
//
//	easm.db        a consistent snapshot of the database, still encrypted (AES-256-XTS)
//	manifest.json  version, time, size and SHA-256 of the snapshot
//	custom.*       the uploaded web certificate and its sealed key, when there is one
//	easm.key       the master key file, ONLY when the administrator asks for it AND it is
//	               protected by a passphrase (an unprotected key would make the backup readable)
//
// The database is the whole configuration: targets, settings, users, channels, findings and history.
// Without easm.key the snapshot cannot be opened, so the key must be kept somewhere else.
// Restoring is an offline operation:  easm-agent -restore backup.zip

const (
	backupFormat     = 1
	backupPrefix     = "easm-backup-"
	backupSuffix     = ".zip"
	backupMetaKey    = "backup_cfg"
	backupLastKey    = "backup_last"
	backupResultKey  = "backup_result"
	manifestName     = "manifest.json"
	maxBackupKeep    = 365
	defaultBackupKep = 7
)

// BackupManifest describes the snapshot inside a backup file.
type BackupManifest struct {
	Format      int       `json:"format"`
	Version     string    `json:"agent_version"`
	Created     time.Time `json:"created"`
	DBSHA256    string    `json:"db_sha256"`
	DBBytes     int64     `json:"db_bytes"`
	KeyIncluded bool      `json:"key_included"`
	Files       []string  `json:"files"`
}

// BackupConfig is the scheduled-backup setting, kept in the database (not in Settings).
type BackupConfig struct {
	Enabled      bool   `json:"enabled"`
	Dir          string `json:"dir"`
	EveryHours   int    `json:"every_hours"`
	Keep         int    `json:"keep"`
	IncludeKey   bool   `json:"include_key"`
	LastResult   string `json:"-"`
	LastRun      string `json:"-"`
	DefaultedDir string `json:"-"`
}

// LoadBackupConfig reads the saved setting, with defaults.
func (s *Store) LoadBackupConfig(dataDir string) BackupConfig {
	c := BackupConfig{EveryHours: 24, Keep: defaultBackupKep}
	if v, ok, _ := s.getMeta(backupMetaKey); ok {
		_ = json.Unmarshal([]byte(v), &c)
	}
	if c.EveryHours < 1 {
		c.EveryHours = 24
	}
	if c.Keep < 1 || c.Keep > maxBackupKeep {
		c.Keep = defaultBackupKep
	}
	c.DefaultedDir = filepath.Join(dataDir, "backups")
	if c.Dir == "" {
		c.Dir = c.DefaultedDir
	}
	c.LastRun, _, _ = s.getMeta(backupLastKey)
	c.LastResult, _, _ = s.getMeta(backupResultKey)
	return c
}

// SaveBackupConfig validates and stores the setting.
func (s *Store) SaveBackupConfig(c BackupConfig) error {
	if c.EveryHours < 1 || c.EveryHours > 24*30 {
		return errors.New("the backup interval must be between 1 hour and 30 days")
	}
	if c.Keep < 1 || c.Keep > maxBackupKeep {
		return fmt.Errorf("keep between 1 and %d backups", maxBackupKeep)
	}
	c.Dir = strings.TrimSpace(c.Dir)
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return errors.New("the backup folder must be a full path such as D:\\Backups\\easm or /var/backups/easm")
	}
	b, _ := json.Marshal(c)
	return s.setMeta(backupMetaKey, string(b))
}

// snapshotDB writes a consistent, still-encrypted copy of the live database to dest.
func (s *Store) snapshotDB(dest string, key []byte) error {
	removeDB(dest)
	if _, err := s.db.Exec("VACUUM INTO ?", fileURI(dest)+"&hexkey="+hex.EncodeToString(key)); err != nil {
		removeDB(dest)
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

// keyFileProtected reports whether easm.key is locked with a passphrase.
func keyFileProtected(path string) bool {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own key file
	return err == nil && strings.HasPrefix(string(b), wrappedMagic)
}

// WriteBackup writes a backup archive to w. tmpDir receives the temporary snapshot.
func WriteBackup(st *Store, v *Vault, dataDir string, includeKey bool, w io.Writer, now time.Time) (*BackupManifest, error) {
	keyPath := filepath.Join(dataDir, "easm.key")
	if includeKey && !keyFileProtected(keyPath) {
		return nil, errors.New("the key file is not protected by a passphrase, so it cannot be put into a backup. Protect it first (easm-agent -protect-key) or back it up separately")
	}
	tmp := filepath.Join(dataDir, fmt.Sprintf(".backup-%d.db", now.UnixNano()))
	if err := st.snapshotDB(tmp, v.DBKey()); err != nil {
		return nil, err
	}
	defer removeDB(tmp)

	sum := sha256.New()
	f, err := os.Open(tmp) //nolint:gosec // G304: temporary snapshot created above
	if err != nil {
		return nil, err
	}
	size, err := io.Copy(sum, f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	m := &BackupManifest{Format: backupFormat, Version: version, Created: now.UTC(), DBSHA256: hex.EncodeToString(sum.Sum(nil)), DBBytes: size, KeyIncluded: includeKey, Files: []string{"easm.db"}}

	extras := []string{customCertFile, customKeyFile}
	if includeKey {
		extras = append(extras, "easm.key")
	}
	var present []string
	for _, n := range extras {
		if _, err := os.Stat(filepath.Join(dataDir, n)); err == nil {
			present = append(present, n)
			if n != "easm.key" {
				m.Files = append(m.Files, n)
			}
		}
	}
	if includeKey {
		m.Files = append(m.Files, "easm.key")
	}

	zw := zip.NewWriter(w)
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := zipBytes(zw, manifestName, mj, now); err != nil {
		return nil, err
	}
	if err := zipFile(zw, "easm.db", tmp, now); err != nil {
		return nil, err
	}
	for _, n := range present {
		if err := zipFile(zw, n, filepath.Join(dataDir, n), now); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return m, nil
}

func zipBytes(zw *zip.Writer, name string, b []byte, mod time.Time) error {
	h := &zip.FileHeader{Name: name, Method: zip.Store, Modified: mod}
	h.SetMode(0o600)
	fw, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = fw.Write(b)
	return err
}

func zipFile(zw *zip.Writer, name, path string, mod time.Time) error {
	f, err := os.Open(path) //nolint:gosec // G304: a file inside the data folder
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := &zip.FileHeader{Name: name, Method: zip.Store, Modified: mod} // the data is encrypted; compressing it gains nothing
	h.SetMode(0o600)
	fw, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, f)
	return err
}

// BackupFileName is the name used for a backup made at t.
func BackupFileName(t time.Time) string {
	return backupPrefix + t.UTC().Format("20060102-150405") + backupSuffix
}

// WriteBackupFile writes a backup into dir (created if needed) and applies the retention limit.
func WriteBackupFile(st *Store, v *Vault, dataDir, dir string, includeKey bool, keep int, now time.Time) (string, *BackupManifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("backup folder %s: %w", dir, err)
	}
	final := filepath.Join(dir, BackupFileName(now))
	tmp := final + ".partial"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: administrator-chosen backup folder
	if err != nil {
		return "", nil, err
	}
	m, err := WriteBackup(st, v, dataDir, includeKey, out, now)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", nil, err
	}
	pruneBackups(dir, keep)
	return final, m, nil
}

// BackupFile is one existing backup, for the list on the Settings page.
type BackupFile struct {
	Name    string
	Size    int64
	Created time.Time
}

// ListBackups returns the backups in dir, newest first. Only files that match the backup name are listed.
func ListBackups(dir string) []BackupFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []BackupFile
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, backupPrefix) || !strings.HasSuffix(n, backupSuffix) {
			continue
		}
		if info, err := e.Info(); err == nil {
			out = append(out, BackupFile{Name: n, Size: info.Size(), Created: info.ModTime()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// pruneBackups deletes the oldest backups beyond keep. It only ever touches files with the backup name pattern.
func pruneBackups(dir string, keep int) {
	files := ListBackups(dir)
	for i := keep; i < len(files); i++ {
		_ = os.Remove(filepath.Join(dir, files[i].Name))
	}
}

// ---------------------------------------------------------------- restore

// RestoreBackup unpacks a backup into dataDir. It never overwrites silently: an existing database
// (and key, when the backup carries one) is moved aside first, and that needs force.
func RestoreBackup(zipPath, dataDir string, force bool, now time.Time) ([]string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("%s is not a readable backup: %w", zipPath, err)
	}
	defer func() { _ = zr.Close() }()
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	mf, ok := files[manifestName]
	if !ok || files["easm.db"] == nil {
		return nil, errors.New("this is not an EASM Agent backup (manifest.json or easm.db is missing)")
	}
	var m BackupManifest
	if err := readZipJSON(mf, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format != backupFormat {
		return nil, fmt.Errorf("backup format %d is not supported by this version", m.Format)
	}
	// Verify the snapshot before touching anything.
	if err := verifyZipFile(files["easm.db"], m.DBSHA256); err != nil {
		return nil, fmt.Errorf("the backup is damaged: %w", err)
	}
	if err := prepareDataDir(dataDir); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "easm.db")
	keyPath := filepath.Join(dataDir, "easm.key")
	dbExists := fileExists(dbPath)
	keyExists := fileExists(keyPath)
	if dbExists && !force {
		return nil, fmt.Errorf("%s already contains a database. Stop the agent and run again with -force to replace it (the current one is kept as easm.db.before-restore-*)", dataDir)
	}
	stamp := now.UTC().Format("20060102-150405")
	var done []string
	if dbExists {
		if err := os.Rename(dbPath, dbPath+".before-restore-"+stamp); err != nil {
			return nil, err
		}
		_ = os.Remove(dbPath + "-wal")
		_ = os.Remove(dbPath + "-shm")
		_ = os.Remove(dbPath + "-journal")
		done = append(done, "kept the previous database as easm.db.before-restore-"+stamp)
	}
	if err := extractZipFile(files["easm.db"], dbPath); err != nil {
		return nil, err
	}
	done = append(done, "restored easm.db")
	for _, n := range []string{customCertFile, customKeyFile} {
		if f := files[n]; f != nil {
			if err := extractZipFile(f, filepath.Join(dataDir, n)); err != nil {
				return done, err
			}
			done = append(done, "restored "+n)
		}
	}
	if f := files["easm.key"]; f != nil {
		switch {
		case !keyExists:
			if err := extractZipFile(f, keyPath); err != nil {
				return done, err
			}
			done = append(done, "restored easm.key (passphrase-protected)")
		case force:
			if err := os.Rename(keyPath, keyPath+".before-restore-"+stamp); err != nil {
				return done, err
			}
			if err := extractZipFile(f, keyPath); err != nil {
				return done, err
			}
			done = append(done, "replaced easm.key with the one from the backup (the old one is easm.key.before-restore-"+stamp+")")
		default:
			done = append(done, "kept the existing easm.key; the backup also holds one (use -force to replace it)")
		}
	} else if !keyExists {
		done = append(done, "NOTE: this backup does not contain easm.key and none exists in "+dataDir+". Put the key file you saved earlier into that folder before starting the agent.")
	}
	return done, nil
}

func readZipJSON(f *zip.File, v any) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	return json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(v)
}

func verifyZipFile(f *zip.File, wantSHA string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(rc, int64(f.UncompressedSize64)+1)); err != nil { //nolint:gosec // G110: bounded by the size the archive declares
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != wantSHA {
		return errors.New("the checksum of easm.db does not match the manifest")
	}
	return nil
}

// extractZipFile writes one archive member to dst (a fixed, trusted path, never taken from the archive).
func extractZipFile(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: dst is built from a fixed file name
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil { //nolint:gosec // G110: the archive is the administrator's own backup, size is bounded by the disk
		_ = out.Close()
		return err
	}
	return out.Close()
}

// VerifyRestored opens the restored database with the key in dataDir and runs an integrity check.
func VerifyRestored(dataDir string, passphraseSource func() (string, error)) error {
	old := PassphraseSource
	if passphraseSource != nil {
		PassphraseSource = passphraseSource
		defer func() { PassphraseSource = old }()
	}
	v, err := OpenVault(filepath.Join(dataDir, "easm.key"))
	if err != nil {
		return err
	}
	st, err := OpenEncryptedStore(filepath.Join(dataDir, "easm.db"), v.DBKey(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	var res string
	if err := st.db.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil || res != "ok" {
		return fmt.Errorf("integrity check: %v %s", err, res)
	}
	return nil
}
