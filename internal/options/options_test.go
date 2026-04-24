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

func TestParseAllowsListWithoutDomain(t *testing.T) {
	opts, err := parseForTest("-l", "targets.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.InputList != "targets.txt" {
		t.Fatalf("unexpected input list: %q", opts.InputList)
	}
}

func TestParseAllowsTakeoverWithoutDomain(t *testing.T) {
	opts, err := parseForTest("--takeover")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Takeover {
		t.Fatal("expected takeover=true")
	}
}

func TestParseAllowsUpdateFingerprintsWithoutDomain(t *testing.T) {
	opts, err := parseForTest("--update-fingerprints")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.UpdateFingerprints {
		t.Fatal("expected update-fingerprints=true")
	}
}

func TestParseAllowsUpdateOnlyWithPassiveDisabled(t *testing.T) {
	opts, err := parseForTest("--update-fingerprints", "--passive=false")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.UpdateFingerprints {
		t.Fatal("expected update-fingerprints=true")
	}
}

func TestParseStillValidatesModesWhenScanTargetsPresent(t *testing.T) {
	_, err := parseForTest("--update-fingerprints", "-d", "example.com", "--passive=false")
	if err == nil {
		t.Fatal("expected mode validation error when scan target is present")
	}
}

func TestParseTakeoverWithListAndPassiveDisabled(t *testing.T) {
	opts, err := parseForTest("--takeover", "--passive=false", "-l", "subs.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Takeover {
		t.Fatal("expected takeover=true")
	}
	if opts.InputList != "subs.txt" {
		t.Fatalf("unexpected input list: %q", opts.InputList)
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

func TestParsePhase3Flags(t *testing.T) {
	opts, err := parseForTest(
		"-d", "example.com",
		"--bruteforce-depth", "2",
		"--bruteforce-max", "15000",
		"--permutation",
		"--permutation-depth", "2",
		"--permutation-max", "4000",
		"--dns-backend", "massdns",
		"--massdns-path", "/usr/bin/massdns",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.BruteforceDepth != 2 || opts.BruteforceMax != 15000 {
		t.Fatalf("unexpected bruteforce controls: depth=%d max=%d", opts.BruteforceDepth, opts.BruteforceMax)
	}
	if !opts.Permutation || opts.PermutationDepth != 2 || opts.PermutationMax != 4000 {
		t.Fatalf("unexpected permutation controls: enabled=%v depth=%d max=%d", opts.Permutation, opts.PermutationDepth, opts.PermutationMax)
	}
	if opts.DNSBackend != "massdns" {
		t.Fatalf("unexpected dns-backend: %s", opts.DNSBackend)
	}
	if opts.MassDNSPath != "/usr/bin/massdns" {
		t.Fatalf("unexpected massdns-path: %s", opts.MassDNSPath)
	}
}

func TestParseInvalidDNSBackend(t *testing.T) {
	_, err := parseForTest("-d", "example.com", "--dns-backend", "invalid")
	if err == nil {
		t.Fatal("expected invalid dns-backend error")
	}
}

func TestParsePhase5Flags(t *testing.T) {
	opts, err := parseForTest(
		"-d", "example.com",
		"--rdns-expand",
		"--rdns-limit", "300",
		"--enrich-infra",
		"--auto-tune",
		"--http-probe",
		"--http-probe-timeout", "7s",
		"--http-probe-threads", "25",
		"--takeover-check",
		"--takeover-threads", "12",
		"--takeover-timeout", "4s",
		"--only-new",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.RDNSExpand || opts.RDNSLimit != 300 {
		t.Fatalf("unexpected rdns flags: enabled=%v limit=%d", opts.RDNSExpand, opts.RDNSLimit)
	}
	if !opts.EnrichInfra {
		t.Fatal("expected enrich-infra=true")
	}
	if !opts.AutoTune {
		t.Fatal("expected auto-tune=true")
	}
	if !opts.OnlyNew {
		t.Fatal("expected only-new=true")
	}
	if !opts.HTTPProbe || opts.HTTPProbeThreads != 25 || opts.HTTPProbeTimeout != 7*time.Second {
		t.Fatalf("unexpected http probe flags: enabled=%v threads=%d timeout=%s", opts.HTTPProbe, opts.HTTPProbeThreads, opts.HTTPProbeTimeout)
	}
	if !opts.TakeoverCheck || opts.TakeoverThreads != 12 || opts.TakeoverTimeout != 4*time.Second {
		t.Fatalf("unexpected takeover flags: enabled=%v threads=%d timeout=%s", opts.TakeoverCheck, opts.TakeoverThreads, opts.TakeoverTimeout)
	}
}
