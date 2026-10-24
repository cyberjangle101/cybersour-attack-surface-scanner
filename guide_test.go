package main

import (
	"strings"
	"testing"
)

func TestFirstRunGuide(t *testing.T) {
	e := newWebEnv(t)
	b := e.browser()
	b.setup("admin", "correct horse battery")
	_, body, _ := b.get("/")
	if !strings.Contains(body, "Welcome: how this works") || !strings.Contains(body, `href="/guide"`) {
		t.Fatal("a new user should see the welcome guide on the dashboard")
	}
	code, body, _ := b.get("/guide")
	for _, want := range []string{"Quick guide", "Get started in five steps", "What it is good for", "AS13335"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("guide page is missing %q (%d)", want, code)
		}
	}
	if c, _, _ := b.post("/guide/dismiss", nil); c != 303 {
		t.Fatalf("dismiss: %d", c)
	}
	if _, body, _ = b.get("/"); strings.Contains(body, "Welcome: how this works") {
		t.Error("the welcome card should stay hidden once dismissed")
	}
	if code, _, _ = b.get("/guide"); code != 200 {
		t.Error("the guide page must stay reachable from the menu")
	}
}
