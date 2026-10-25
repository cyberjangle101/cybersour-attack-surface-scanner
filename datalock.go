package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lockFileName is the file in the data folder that only one running agent may hold.
const lockFileName = "easm.lock"

// errDataLocked means another agent (or maintenance command) is using the data folder.
var errDataLocked = errors.New("data folder in use")

// DataLock is an exclusive, OS-level lock on a data folder. Two agents writing one
// database would double every scan and alert and risk corrupting it, so the agent
// and the offline commands that change the data hold this for as long as they run.
// The OS drops the lock when the process ends, so a crash never leaves it stuck.
type DataLock struct{ f *os.File }

// LockDataDir takes the lock or explains who holds it.
func LockDataDir(dir string) (*DataLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock file %s: %w", path, err)
	}
	if err := lockFile(f); err != nil {
		owner := "another process"
		if b, rerr := os.ReadFile(path); rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 0 {
				owner = "process " + strconv.Itoa(pid)
			}
		}
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s is already using %s. Stop it first (System health → Stop agent, or easm-agent -service stop): %v",
			errDataLocked, owner, dir, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &DataLock{f: f}, nil
}

// LockDataDirWait is LockDataDir, retrying while another agent holds the lock for up
// to wait (used when an update restarts the agent and the old one is still stopping).
func LockDataDirWait(dir string, wait time.Duration) (*DataLock, error) {
	deadline := time.Now().Add(wait)
	for {
		l, err := LockDataDir(dir)
		if err == nil || !errors.Is(err, errDataLocked) || time.Now().After(deadline) {
			return l, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Release gives the lock up. Safe to call on nil and more than once.
func (l *DataLock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unlockFile(l.f)
	_ = l.f.Close()
	l.f = nil
}
