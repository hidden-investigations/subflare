package source

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseCertSpotterBodyFixture(t *testing.T) {
	hosts, err := parseCertSpotterBody(fixture(t, "certspotter.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"api.example.com", "dev.example.com", "*.wild.example.com", "staging.example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("unexpected hosts: got %v want %v", hosts, want)
	}
}

func TestParseCRTShBodyFixture(t *testing.T) {
	hosts, err := parseCRTShBody(fixture(t, "crtsh.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"api.example.com", "www.example.com", "dev.example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("unexpected hosts: got %v want %v", hosts, want)
	}
}

func TestParseAnubisBodyFixture(t *testing.T) {
	hosts, err := parseAnubisBody(fixture(t, "anubis.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("unexpected count: %d", len(hosts))
	}
}

func TestParseHackertargetBodyFixture(t *testing.T) {
	hosts, err := parseHackerTargetBody(fixture(t, "hackertarget.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"api.example.com", "www.example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("unexpected hosts: got %v want %v", hosts, want)
	}
}

func TestParseLeakIXBodyFixture(t *testing.T) {
	hosts := parseLeakIXBody(fixture(t, "leakix_object.json"))
	want := []string{"api.example.com", "dev.example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("unexpected hosts: got %v want %v", hosts, want)
	}
}

func TestParseShodanBodyFixture(t *testing.T) {
	subs, err := parseShodanBody(fixture(t, "shodan.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"api", "www", "dev"}
	if !reflect.DeepEqual(subs, want) {
		t.Fatalf("unexpected subs: got %v want %v", subs, want)
	}
}

func TestParseAlienVaultPassiveDNSFixture(t *testing.T) {
	hosts, err := parseAlienVaultPassiveDNSBody(fixture(t, "alienvault_passive_dns.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("unexpected hosts: got %v want %v", hosts, want)
	}
}

func TestParseRapidDNSMaxPageFixture(t *testing.T) {
	maxPage := parseRapidDNSMaxPage(string(fixture(t, "rapiddns_page.html")))
	if maxPage != 11 {
		t.Fatalf("unexpected max page: got %d want 11", maxPage)
	}
}
