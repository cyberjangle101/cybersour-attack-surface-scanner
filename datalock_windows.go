//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockOffset is where the locked byte sits: past the PID written at the start of
// the file, because Windows locks are mandatory and would hide it from readers.
const lockOffset = 0x7fffffff

// lockFile takes an exclusive lock on one byte without waiting.
func lockFile(f *os.File) error {
	ol := &windows.Overlapped{Offset: lockOffset}
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
}

func unlockFile(f *os.File) error {
	ol := &windows.Overlapped{Offset: lockOffset}
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
