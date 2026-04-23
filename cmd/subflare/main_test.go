package main

import (
	"reflect"
	"testing"

	"github.com/hidden-investigations/subflare/internal/model"
)

func TestNormalizeDiffShowMode(t *testing.T) {
	cases := map[string]string{
		"summary": "summary",
		"new":     "new",
		"added":   "new",
		"removed": "removed",
		"deleted": "removed",
		"stable":  "stable",
		"all":     "all",
		" NEW ":   "new",
	}

	for in, want := range cases {
		got := normalizeDiffShowMode(in)
		if got != want {
			t.Fatalf("normalizeDiffShowMode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollectTakeoverFindings(t *testing.T) {
	results := []model.Result{
		{Host: "b.example.com", TakeoverPotential: true, TakeoverProvider: "vercel", TakeoverReason: "fingerprint"},
		{Host: "a.example.com", TakeoverPotential: true, TakeoverProvider: "github-pages", TakeoverReason: "dangling"},
		{Host: "a.example.com", TakeoverPotential: true, TakeoverProvider: "github-pages", TakeoverReason: "duplicate"},
		{Host: "c.example.com", TakeoverPotential: false},
	}

	got := collectTakeoverFindings(results)
	want := []takeoverFinding{
		{Host: "a.example.com", Provider: "github-pages", Reason: "dangling"},
		{Host: "b.example.com", Provider: "vercel", Reason: "fingerprint"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected findings\n got: %#v\nwant: %#v", got, want)
	}
}

func TestFilterTakeoverResults(t *testing.T) {
	results := []model.Result{
		{Host: "b.example.com", TakeoverPotential: true},
		{Host: "a.example.com", TakeoverPotential: false},
		{Host: "c.example.com", TakeoverPotential: true},
	}
	got := filterTakeoverResults(results)
	want := []model.Result{
		{Host: "b.example.com", TakeoverPotential: true},
		{Host: "c.example.com", TakeoverPotential: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected filtered results\n got: %#v\nwant: %#v", got, want)
	}
}

func TestNormalizeTargetInputs(t *testing.T) {
	if got := normalizeDomainInput(" https://Example.com/path "); got != "example.com" {
		t.Fatalf("unexpected normalized domain: %q", got)
	}
	if got := normalizeHostInput("https://Sub.EXAMPLE.com/login"); got != "sub.example.com" {
		t.Fatalf("unexpected normalized host: %q", got)
	}
	if got := normalizeHostInput("localhost"); got != "" {
		t.Fatalf("expected localhost to be dropped, got %q", got)
	}
}
