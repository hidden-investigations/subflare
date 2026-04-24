package takeover

import (
	"errors"
	"testing"
)

func TestMatchFingerprint(t *testing.T) {
	fp, ok := matchFingerprint("demo.github.io")
	if !ok {
		t.Fatal("expected fingerprint match")
	}
	if fp.Provider != "github-pages" {
		t.Fatalf("unexpected provider: %s", fp.Provider)
	}

	_, ok = matchFingerprint("api.example.com")
	if ok {
		t.Fatal("did not expect fingerprint match")
	}
}

func TestBuildMatchesDedupesAndNormalizes(t *testing.T) {
	matches := buildMatches([]string{
		" Demo.GitHub.io ",
		"demo.github.io",
		"app.herokudns.com",
		"api.example.com",
	})
	if len(matches) != 2 {
		t.Fatalf("unexpected match count: got %d want 2", len(matches))
	}
	if matches[0].Target != "demo.github.io" {
		t.Fatalf("unexpected first target: %s", matches[0].Target)
	}
	if matches[1].Target != "app.herokudns.com" {
		t.Fatalf("unexpected second target: %s", matches[1].Target)
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("there isn't a github pages site here", []string{"no such app", "github pages site"}) {
		t.Fatal("expected indicator hit")
	}
	if containsAny("all good", []string{"unknown domain"}) {
		t.Fatal("did not expect indicator hit")
	}
}

func TestClassifyDNSError(t *testing.T) {
	cases := []struct {
		err     error
		want    bool
		reason  string
		message string
	}{
		{err: errors.New("dns rcode=NXDOMAIN"), want: true, reason: "nxdomain", message: "nxdomain"},
		{err: errors.New("lookup app.example.com: no such host"), want: true, reason: "no such host", message: "no such host"},
		{err: errors.New("dns rcode=SERVFAIL"), want: false, reason: "", message: "servfail"},
		{err: errors.New("context deadline exceeded"), want: false, reason: "", message: "timeout"},
		{err: nil, want: false, reason: "", message: "nil"},
	}
	for _, tc := range cases {
		got, reason := classifyDNSError(tc.err)
		if got != tc.want || reason != tc.reason {
			t.Fatalf("classifyDNSError(%s) got=(%v,%q) want=(%v,%q)", tc.message, got, reason, tc.want, tc.reason)
		}
	}
}

func TestMatchesHTTPFingerprint(t *testing.T) {
	match := takeoverMatch{
		Provider:   "github-pages",
		Indicators: []string{"there isn't a github pages site here"},
		Statuses:   []int{404},
	}

	if !matchesHTTPFingerprint(match, 404, "there isn't a github pages site here") {
		t.Fatal("expected fingerprint match on valid status+indicator")
	}
	if matchesHTTPFingerprint(match, 200, "there isn't a github pages site here") {
		t.Fatal("did not expect match for non-matching status")
	}
	if matchesHTTPFingerprint(match, 404, "welcome page") {
		t.Fatal("did not expect match without indicator")
	}
}

func TestConfidenceFromHTTP(t *testing.T) {
	matchWithStatus := takeoverMatch{Statuses: []int{404}}
	if got := confidenceFromHTTP(404, matchWithStatus); got != "medium" {
		t.Fatalf("unexpected confidence: %s", got)
	}
	if got := confidenceFromHTTP(0, matchWithStatus); got != "low" {
		t.Fatalf("unexpected confidence for unknown status: %s", got)
	}

	matchNoStatus := takeoverMatch{}
	if got := confidenceFromHTTP(0, matchNoStatus); got != "medium" {
		t.Fatalf("unexpected confidence for no-status rule: %s", got)
	}
}
