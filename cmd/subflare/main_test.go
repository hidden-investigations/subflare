package main

import "testing"

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
