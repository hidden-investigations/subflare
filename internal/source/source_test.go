package source

import (
	"strings"
	"testing"
	"time"
)

func TestAvailableSourceNames(t *testing.T) {
	names := AvailableSourceNames()
	want := []string{
		"alienvault",
		"hackertarget",
		"rapiddns",
		"leakix",
		"certspotter",
		"crtsh",
		"anubis",
		"shodan",
		"commoncrawl",
		"waybackarchive",
		"digitorus",
		"riddler",
		"threatcrowd",
		"threatminer",
		"sitedossier",
		"securitytrails",
		"virustotal",
		"censys",
		"whoisxmlapi",
		"chaos",
		"github",
		"gitlab",
		"netlas",
		"fofa",
		"zoomeyeapi",
	}
	if len(names) != len(want) {
		t.Fatalf("unexpected source count: got %d want %d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("unexpected source at %d: got %s want %s", i, names[i], want[i])
		}
	}
}

func TestNewSourcesByNameAliasAndDedupe(t *testing.T) {
	sources, err := NewSourcesByName(5*time.Second, []string{"crt.sh", "crtsh", "anubis"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("unexpected source count: got %d want 2", len(sources))
	}
	found := map[string]bool{}
	for _, src := range sources {
		found[src.Name()] = true
	}
	if !found["crtsh"] || !found["anubis"] {
		t.Fatalf("unexpected source names: %#v", found)
	}
}

func TestNewSourcesByNameUnknown(t *testing.T) {
	_, err := NewSourcesByName(5*time.Second, []string{"unknown-source"})
	if err == nil {
		t.Fatal("expected unknown-source error")
	}
	if !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("unexpected error: %v", err)
	}
}
