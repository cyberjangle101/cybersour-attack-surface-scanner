package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// SetupLogger creates the structured logger (text or JSON, stdout or file) and a function that closes the log file.
func SetupLogger(c LoggingCfg) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stdout
	closer := func() {}
	if c.File != "" {
		f, err := os.OpenFile(c.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		w = io.MultiWriter(os.Stdout, f)
		closer = func() { _ = f.Close() }
	}
	lvl := slog.LevelInfo
	switch strings.ToLower(c.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	opts := &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339))
			}
			return a
		},
	}
	var h slog.Handler
	if strings.ToLower(c.Format) == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h), closer, nil
}
