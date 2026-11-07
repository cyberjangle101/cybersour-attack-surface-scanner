package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Every rule in the catalogue must be raised, from test data, by at least one test: a rule
// that no test can make fire is either dead or untested. TestMain records the kind of every
// finding the scans in the suite raise and, after a full run (no -run filter), fails if any
// catalogued kind never appeared. Each rule's own test checks the details; this check makes
// sure none is left out.

var raised = struct {
	sync.Mutex
	kinds map[string]int
}{kinds: map[string]int{}}

func TestMain(m *testing.M) {
	findingRaised = func(kind string) {
		raised.Lock()
		raised.kinds[kind]++
		raised.Unlock()
	}
	code := m.Run()
	if code == 0 && fullRun() {
		if missing := rulesNeverRaised(); len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "FAIL: %d rules were never raised by any test, so nothing shows they work:\n  %s\n"+
				"Add a test that feeds each one the data it looks for (see rules_coverage_test.go).\n",
				len(missing), strings.Join(missing, "\n  "))
			code = 1
		}
	}
	os.Exit(code)
}

// fullRun reports whether every test ran: not a -run, -skip or -short subset.
func fullRun() bool {
	for _, name := range []string{"test.run", "test.skip"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" {
			return false
		}
	}
	return !testing.Short()
}

func rulesNeverRaised() []string {
	raised.Lock()
	defer raised.Unlock()
	var missing []string
	for kind := range findingCatalog {
		if raised.kinds[kind] == 0 {
			missing = append(missing, fmt.Sprintf("%s (%s)", kind, ruleIndex[kind].ID))
		}
	}
	sort.Strings(missing)
	return missing
}

// TestRuleCoverageRecorder makes sure the recorder sees findings at all, so the check in
// TestMain cannot pass by accident.
func TestRuleCoverageRecorder(t *testing.T) {
	if findingRaised == nil {
		t.Fatal("findingRaised is not set")
	}
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)
	raised.Lock()
	n := len(raised.kinds)
	raised.Unlock()
	if n == 0 {
		t.Fatal("a scan of the example data raised no findings, or the recorder is not wired to UpsertFinding")
	}
}
