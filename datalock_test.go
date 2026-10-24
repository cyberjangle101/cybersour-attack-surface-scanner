package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// QA defect D1: two agents could run on one data folder at the same time.
func TestDataLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, lockFileName)); strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("lock file should name the holder, has %q", b)
	}
	// A second holder in another process is the real case; the helper below runs one.
	cmd := exec.Command(os.Args[0], "-test.run=TestDataLockHelper")
	cmd.Env = append(os.Environ(), "EASM_LOCK_HELPER_DIR="+dir)
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "LOCKED:") || !strings.Contains(string(out), "process "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("second process was not refused with the holder's PID:\n%s", out)
	}
	first.Release()
	first.Release() // twice is harmless
	again, err := LockDataDir(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again.Release()
	var nilLock *DataLock
	nilLock.Release()
}

// After an update the new process waits for the old one to let go of the folder.
func TestDataLockWaitsForRelease(t *testing.T) {
	dir := t.TempDir()
	held, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDataDirWait(dir, 0); !errors.Is(err, errDataLocked) {
		t.Fatalf("no wait: err = %v", err)
	}
	go func() { time.Sleep(700 * time.Millisecond); held.Release() }()
	t0 := time.Now()
	l, err := LockDataDirWait(dir, 10*time.Second)
	if err != nil {
		t.Fatalf("waiting for the lock: %v", err)
	}
	defer l.Release()
	if d := time.Since(t0); d < 500*time.Millisecond || d > 5*time.Second {
		t.Errorf("acquired after %v", d)
	}
}

// TestDataLockHelper runs only as the child of TestDataLockIsExclusive.
func TestDataLockHelper(t *testing.T) {
	dir := os.Getenv("EASM_LOCK_HELPER_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	l, err := LockDataDir(dir)
	if errors.Is(err, errDataLocked) {
		println("LOCKED: " + err.Error())
		return
	}
	if l != nil {
		l.Release()
	}
	println("NOT LOCKED", err)
}

// QA observation O1: the ASN error quoted the input with "AS" cut off ("-ACME" for "AS-ACME").
func TestASNErrorQuotesWhatWasTyped(t *testing.T) {
	if _, err := parseASNList("AS13335, AS-ACME"); err == nil || !strings.Contains(err.Error(), `"AS-ACME"`) {
		t.Errorf("error should quote the typed value: %v", err)
	}
	if got, err := parseASNList("AS 13335, as16509;64500"); err != nil || len(got) != 3 {
		t.Errorf("valid forms rejected: %v %v", got, err)
	}
}

// QA defect D2: piped passphrases — every prompt must get its own line.
func TestReadLineSharesOneReader(t *testing.T) {
	// Exactly what Windows PowerShell 5.1 pipes: a UTF-8 BOM, LF lines, then CRLF.
	r := bufio.NewReader(strings.NewReader("\ufefffirst passphrase\nsecond passphrase\r\n"))
	a, err1 := readLine(r)
	b, err2 := readLine(r)
	_, err3 := readLine(r)
	if a != "first passphrase" || b != "second passphrase" || err1 != nil || err2 != nil || err3 == nil {
		t.Fatalf("got %q %v, %q %v, then %v", a, err1, b, err2, err3)
	}
}
