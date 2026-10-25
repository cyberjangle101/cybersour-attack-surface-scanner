package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// logSink is where log lines go: the console, and a file when one is configured.
// The console part is dropped when the agent leaves its console window (see
// program.desktopStart); lines then go to the file only.
type logSink struct {
	mu      sync.Mutex
	console io.Writer
	file    *os.File
}

// logOut is the sink of the logger made by SetupLogger.
var logOut *logSink

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.console != nil {
		_, _ = s.console.Write(p) // a console that has gone away must not stop the file copy
	}
	if s.file != nil {
		return s.file.Write(p)
	}
	return len(p), nil
}

// maxLogBytes is the size at which a log file is moved to <name>.1 when it is opened.
const maxLogBytes = 10 << 20

// openLogFile opens path for appending, first moving it to path.1 when it has grown past maxLogBytes.
func openLogFile(path string) (*os.File, error) {
	if st, err := os.Stat(path); err == nil && st.Size() > maxLogBytes {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the configured log file, or easm.log in the data folder
}

// leaveConsole stops writing to the console. When no log file was configured it
// starts one at fallback so the log is still kept; it returns the file in use.
func (s *logSink) leaveConsole(fallback string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.console = nil
	if s.file != nil {
		return s.file.Name(), nil
	}
	f, err := openLogFile(fallback)
	if err != nil {
		return "", err
	}
	s.file = f
	return f.Name(), nil
}

func (s *logSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

// SetupLogger creates the structured logger (text or JSON, stdout or file) and a function that closes the log file.
func SetupLogger(c LoggingCfg) (*slog.Logger, func(), error) {
	sink := &logSink{console: os.Stdout}
	if c.File != "" {
		f, err := openLogFile(c.File)
		if err != nil {
			return nil, nil, err
		}
		sink.file = f
	}
	logOut = sink
	var w io.Writer = sink
	closer := sink.close
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
