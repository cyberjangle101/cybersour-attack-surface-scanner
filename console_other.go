//go:build !windows

package main

import "os/exec"

// ownsConsole is false outside Windows: a terminal there belongs to the shell.
func ownsConsole() bool { return false }

// leaveConsole does nothing outside Windows.
func leaveConsole() bool { return false }

// inNewConsole leaves cmd as it is outside Windows.
func inNewConsole(*exec.Cmd) {}

// useOwnConsole does nothing outside Windows.
func useOwnConsole() {}
