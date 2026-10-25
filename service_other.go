//go:build !windows

package main

import "os"

// serviceDataDir is "" outside Windows: a root service already uses /var/lib/easm-agent.
func serviceDataDir() string { return "" }

// serviceAccountFor is "" outside Windows: the service manager decides the account.
func serviceAccountFor(string) string { return "" }

// installProgram leaves the program where it is outside Windows.
func installProgram() (string, error) { return os.Executable() }

// grantServiceData is not needed outside Windows (the root service owns its folder).
func grantServiceData(string, string) error { return nil }

// installedServiceAddress is "" outside Windows.
func installedServiceAddress() string { return "" }

// defaultServiceAccount is only used on Windows.
const defaultServiceAccount = ""
