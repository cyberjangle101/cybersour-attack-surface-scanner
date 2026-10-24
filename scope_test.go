package main

import "testing"

func TestSubdomainScope(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com": false, "www.example.com": true, "a.b.example.com": true,
		"example.co.uk": false, "www.example.co.uk": true,
		"acme.github.io":     false, // a hosting suffix: the tenant name is the registrable part
		"www.acme.github.io": true,
	} {
		if got := isSubdomainScope(name); got != want {
			t.Errorf("isSubdomainScope(%q) = %v, want %v", name, got, want)
		}
	}
	if registeredDomain("www.example.co.uk") != "example.co.uk" {
		t.Error("registeredDomain wrong for co.uk")
	}
}
