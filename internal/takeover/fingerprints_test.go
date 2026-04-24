package takeover

import (
	"strings"
	"testing"
)

func TestNormalizeFingerprint(t *testing.T) {
	fp, ok := normalizeFingerprint(fingerprint{
		Provider:   " GitHub-Pages ",
		Suffixes:   []string{"github.io", ".github.io"},
		Indicators: []string{" There Isn't A GitHub Pages Site Here "},
	})
	if !ok {
		t.Fatal("expected fingerprint to normalize")
	}
	if fp.Provider != "github-pages" {
		t.Fatalf("unexpected provider: %s", fp.Provider)
	}
	if len(fp.Suffixes) != 1 || fp.Suffixes[0] != ".github.io" {
		t.Fatalf("unexpected suffixes: %#v", fp.Suffixes)
	}
	if len(fp.Indicators) != 1 || !strings.Contains(fp.Indicators[0], "github pages") {
		t.Fatalf("unexpected indicators: %#v", fp.Indicators)
	}
}

func TestMergeFingerprintsOverride(t *testing.T) {
	base := []fingerprint{{Provider: "provider-a", Suffixes: []string{".example.com"}, Indicators: []string{"old"}}}
	extra := []fingerprint{{Provider: "provider-a", Suffixes: []string{".example.com"}, Indicators: []string{"new"}}}
	merged := mergeFingerprints(base, extra)
	if len(merged) != 1 {
		t.Fatalf("unexpected merged length: %d", len(merged))
	}
	if len(merged[0].Indicators) != 1 || merged[0].Indicators[0] != "new" {
		t.Fatalf("expected override indicators, got %#v", merged[0].Indicators)
	}
}

func TestDecodeFingerprints(t *testing.T) {
	payload := []byte(`[
		{"Provider":"demo","Suffixes":[".demo.tld"],"Indicators":["missing"]}
	]`)
	rows, err := decodeFingerprints(payload)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(rows) != 1 || rows[0].Provider != "demo" {
		t.Fatalf("unexpected decoded rows: %#v", rows)
	}
}
