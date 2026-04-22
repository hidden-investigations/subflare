package options

import (
	"flag"
	"io"
	"reflect"
	"testing"
	"time"
)

func parseForTest(args ...string) (Options, error) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return Parse(fs, args)
}

func TestParseListSourcesWithoutDomain(t *testing.T) {
	opts, err := parseForTest("--list-sources")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.ListSources {
		t.Fatal("expected list-sources=true")
	}
}

func TestParseRequiresDomain(t *testing.T) {
	_, err := parseForTest("--passive")
	if err == nil {
		t.Fatal("expected error when domain is missing")
	}
}

func TestParseAllowsStdinWithoutDomain(t *testing.T) {
	opts, err := parseForTest("--stdin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Stdin {
		t.Fatal("expected stdin=true")
	}
}

func TestParseWordlistEnablesBruteforce(t *testing.T) {
	opts, err := parseForTest("-d", "example.com", "-w", "subdomains-1000.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Bruteforce {
		t.Fatal("expected bruteforce to auto-enable with wordlist")
	}
}

func TestParseSourcesNormalizedAndDeduped(t *testing.T) {
	opts, err := parseForTest("-d", "example.com", "-s", "crt.sh,CRTSH,anubis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"crt.sh", "crtsh", "anubis"}
	if !reflect.DeepEqual(opts.Sources, want) {
		t.Fatalf("unexpected sources: got %v want %v", opts.Sources, want)
	}
}

func TestRawNoBanner(t *testing.T) {
	if !RawNoBanner([]string{"--no-banner"}) {
		t.Fatal("expected no-banner to be detected")
	}
	if RawNoBanner([]string{"--no-banner=false"}) {
		t.Fatal("expected no-banner=false to disable suppression")
	}
}

func TestParseExcludeSources(t *testing.T) {
	opts, err := parseForTest("-d", "example.com", "--exclude-sources", "shodan,crtsh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"shodan", "crtsh"}
	if !reflect.DeepEqual(opts.ExcludeSources, want) {
		t.Fatalf("unexpected exclude-sources: got %v want %v", opts.ExcludeSources, want)
	}
}

func TestParseSourceRateAndTimeoutMaps(t *testing.T) {
	opts, err := parseForTest(
		"-d", "example.com",
		"--rls", "crtsh=5/s,shodan=120/m",
		"--source-timeout-source", "anubis=10s,rapiddns=25s",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.SourceRateLimits["crtsh"] != 5 {
		t.Fatalf("unexpected crtsh rate: %f", opts.SourceRateLimits["crtsh"])
	}
	if opts.SourceRateLimits["shodan"] != 2 {
		t.Fatalf("unexpected shodan rate: %f", opts.SourceRateLimits["shodan"])
	}
	if opts.SourceTimeouts["anubis"] != 10*time.Second {
		t.Fatalf("unexpected anubis timeout: %s", opts.SourceTimeouts["anubis"])
	}
	if opts.SourceTimeouts["rapiddns"] != 25*time.Second {
		t.Fatalf("unexpected rapiddns timeout: %s", opts.SourceTimeouts["rapiddns"])
	}
}

func TestParseCacheFlags(t *testing.T) {
	opts, err := parseForTest("-d", "example.com", "--cache-dir", "/tmp/subflare-cache", "--cache-ttl", "12h", "--no-cache")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.CacheDir != "/tmp/subflare-cache" {
		t.Fatalf("unexpected cache-dir: %s", opts.CacheDir)
	}
	if opts.CacheTTL != 12*time.Hour {
		t.Fatalf("unexpected cache-ttl: %s", opts.CacheTTL)
	}
	if !opts.NoCache {
		t.Fatal("expected no-cache to be true")
	}
}
