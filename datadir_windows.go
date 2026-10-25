//go:build windows

package main

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

// restrictDir removes inherited permissions on the data folder and grants full control
// only to the account this process runs as, SYSTEM and Administrators. File modes mean
// nothing on Windows, so without this the folder would be readable by every local account.
//
// The account is taken from the process token, not the USERNAME variable: under a service
// account (NT SERVICE\easm-agent, a gMSA) USERNAME names the computer, so the service
// would have locked itself out of its own data.
func restrictDir(dir string) error {
	return restrictDirFor(dir, currentUserSID())
}

// restrictDirFor is restrictDir granting access to the account given as a SID string
// ("S-1-5-...") or a name ("NT SERVICE\easm-agent"); "" grants SYSTEM and Administrators only.
func restrictDirFor(dir, account string) error {
	out, err := exec.Command("icacls", restrictArgs(dir, account)...).CombinedOutput() //nolint:gosec // G204: fixed program, arguments are the data folder and an account
	if err != nil {
		return fmt.Errorf("restricting access to %s: %v: %s", dir, err, out)
	}
	return nil
}

// restrictArgs builds the icacls arguments for restrictDirFor.
func restrictArgs(dir, account string) []string {
	args := []string{dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"} // SYSTEM, Administrators
	switch {
	case account == "" || account == "S-1-5-18":
	case len(account) > 4 && account[:4] == "S-1-":
		args = append(args, "/grant:r", "*"+account+":(OI)(CI)F")
	default:
		args = append(args, "/grant:r", account+":(OI)(CI)F")
	}
	return args
}

// currentUserSID is the SID of the account this process runs as ("" if it cannot be read).
func currentUserSID() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}
