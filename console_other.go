//go:build !windows

package main

// ownsConsole is false outside Windows: a terminal there belongs to the shell.
func ownsConsole() bool { return false }

// hideConsole does nothing outside Windows.
func hideConsole() bool { return false }
