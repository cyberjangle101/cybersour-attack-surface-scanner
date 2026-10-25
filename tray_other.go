//go:build !windows

package main

import "log/slog"

// trayOptions configures the notification-area icon (Windows only).
type trayOptions struct {
	Tip, Notice string
	Open, Stop  func()
	LogFile     func() string
}

// startTray does nothing outside Windows; it returns nil (no icon to remove).
func startTray(trayOptions, *slog.Logger) func() { return nil }
