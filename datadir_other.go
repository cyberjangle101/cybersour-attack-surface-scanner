//go:build !windows

package main

import "os"

// restrictDir limits the data folder to its owner (MkdirAll does not change an existing folder).
func restrictDir(dir string) error { return os.Chmod(dir, 0o700) } //nolint:gosec // G302: a directory needs the execute bit
