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
