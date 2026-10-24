//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// restrictDir removes inherited permissions on the data folder and grants full control
// only to the current user, SYSTEM and Administrators. File modes mean nothing on
// Windows, so without this the folder would be readable by every local account.
func restrictDir(dir string) error {
	user := os.Getenv("USERNAME")
	args := []string{dir, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"}
	if user != "" {
		args = append(args, "/grant:r", user+":(OI)(CI)F")
	}
	out, err := exec.Command("icacls", args...).CombinedOutput() //nolint:gosec // G204: fixed program, arguments are the data folder and account names
	if err != nil {
		return fmt.Errorf("restricting access to %s: %v: %s", dir, err, out)
	}
	return nil
}
