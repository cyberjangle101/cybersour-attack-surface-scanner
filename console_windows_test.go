//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/term"
)

// TestHelperConsoleChild is not a real test: TestRestartedAgentReachesItsConsole runs
// the test binary as the "restarted agent" and this reports what that child sees.
func TestHelperConsoleChild(t *testing.T) {
	out := os.Getenv("EASM_CONSOLE_PROBE")
	if out == "" {
		t.Skip("helper process")
	}
	before := term.IsTerminal(int(os.Stdin.Fd()))
	useOwnConsole()
	after := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
	_ = os.WriteFile(out, []byte(fmt.Sprintf("before=%v after=%v", before, after)), 0o600)
}

// Defect: after an in-app update the agent restarted in a new console window got NUL
// for stdin/stdout/stderr (os/exec does that for nil handles), could not ask for the
// key passphrase, and exited. The restarted process must reach its own console.
func TestRestartedAgentReachesItsConsole(t *testing.T) {
	out := filepath.Join(t.TempDir(), "probe.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperConsoleChild$") //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- G204: the test binary re-running itself with a fixed argument
	cmd.Env = append(os.Environ(), "EASM_CONSOLE_PROBE="+out)
	inNewConsole(cmd)
	cmd.SysProcAttr.HideWindow = true
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "before=false") {
		t.Logf("the child already had a console on stdin (%s); the defect would not show here", got)
	}
	if !strings.Contains(got, "after=true") {
		t.Fatalf("restarted agent cannot reach its console window: %s", got)
	}
}
