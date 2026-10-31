package main

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The one-time setup code.
//
// Until the first administrator exists, whoever submits the setup page first owns the
// agent. On a workstation listening on 127.0.0.1 that is the person at the keyboard, but
// on a shared server (or a workstation other people can log on to) it could be anyone who
// reaches the page first. So the page also asks for a setup code that only the person who
// installed the agent can read: it is written to setup-code.txt in the data folder (which
// only the agent's account and administrators can open) and, on an interactive start,
// shown in the console and filled in automatically on the page the agent opens. The code
// changes at every start, is never logged, and stops working once the administrator exists.

// setupCodeFile is the file in the data folder that holds the current setup code.
const setupCodeFile = "setup-code.txt"

type setupGate struct {
	mu   sync.Mutex
	code string // normalised: upper case, no separators; "" once an administrator exists
	file string
}

// setupAlphabet leaves out letters and digits that are easy to confuse (0/O, 1/I/L, 8/B).
const setupAlphabet = "ACDEFGHJKMNPQRSTUVWXYZ2345679"

// newSetupCode returns 20 random characters (about 97 bits) from setupAlphabet.
// Bytes past the largest multiple of the alphabet size are skipped so every
// character is equally likely.
func newSetupCode() (string, error) {
	limit := 256 - 256%len(setupAlphabet)
	out := make([]byte, 0, 20)
	b := make([]byte, 32)
	for len(out) < cap(out) {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		for _, c := range b {
			if int(c) < limit && len(out) < cap(out) {
				out = append(out, setupAlphabet[int(c)%len(setupAlphabet)])
			}
		}
	}
	return string(out), nil
}

// groupCode writes a code as XXXXX-XXXXX-XXXXX-XXXXX so it is easy to read out and type.
func groupCode(c string) string {
	var parts []string
	for len(c) > 5 {
		parts = append(parts, c[:5])
		c = c[5:]
	}
	return strings.Join(append(parts, c), "-")
}

// normaliseCode accepts a code typed with spaces, dashes or in lower case.
func normaliseCode(c string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, c)
}

// prepareSetupCode makes a new setup code when no user exists yet and writes it to
// the data folder. It returns the code as shown to people ("" when setup is done).
func (s *Server) prepareSetupCode() (string, error) {
	g := &s.setup
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, err := s.store.CountUsers(); err != nil || n > 0 {
		g.code = ""
		s.removeSetupFile()
		return "", err
	}
	c, err := newSetupCode()
	if err != nil {
		return "", err
	}
	g.code = c
	if s.boot.DataDir != "" {
		g.file = filepath.Join(s.boot.DataDir, setupCodeFile)
		text := fmt.Sprintf("EASM Agent first-administrator setup code:\r\n\r\n    %s\r\n\r\n"+
			"Enter it on the setup page with the first administrator's name and password.\r\n"+
			"It changes every time the agent starts and stops working once that account exists;\r\n"+
			"this file is then deleted.\r\n", groupCode(c))
		if err := writeFileAtomic(g.file, []byte(text)); err != nil {
			return "", fmt.Errorf("writing the setup code: %w", err)
		}
	}
	return groupCode(c), nil
}

// setupCodeOK checks a submitted setup code in constant time.
func (s *Server) setupCodeOK(given string) bool {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	want := s.setup.code
	return want != "" && subtle.ConstantTimeCompare([]byte(normaliseCode(given)), []byte(want)) == 1
}

// finishSetup retires the setup code once the first administrator exists.
func (s *Server) finishSetup() {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	s.setup.code = ""
	s.removeSetupFile()
}

// SetupCodeFile is where the current setup code is written ("" when there is none).
func (s *Server) SetupCodeFile() string {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	if s.setup.code == "" {
		return ""
	}
	return s.setup.file
}

func (s *Server) removeSetupFile() {
	f := s.setup.file
	if f == "" && s.boot.DataDir != "" {
		f = filepath.Join(s.boot.DataDir, setupCodeFile)
	}
	if f != "" {
		_ = os.Remove(f)
	}
}

// SetupCode is the current setup code as shown to people ("" once an administrator exists).
func (s *Server) SetupCode() string {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	if s.setup.code == "" {
		return ""
	}
	return groupCode(s.setup.code)
}
