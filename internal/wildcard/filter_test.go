package wildcard

import "testing"

func TestParentSuffixes(t *testing.T) {
	suffixes := parentSuffixes("a.b.example.com", "example.com")
	if len(suffixes) != 2 {
		t.Fatalf("unexpected suffix count: %d", len(suffixes))
	}
	if suffixes[0] != "b.example.com" {
		t.Fatalf("unexpected first suffix: %s", suffixes[0])
	}
	if suffixes[1] != "example.com" {
		t.Fatalf("unexpected second suffix: %s", suffixes[1])
	}
}

func TestIsSubset(t *testing.T) {
	candidate := map[string]struct{}{"1.1.1.1": {}}
	wildcardSet := map[string]struct{}{"1.1.1.1": {}, "2.2.2.2": {}}
	if !isSubset(candidate, wildcardSet) {
		t.Fatal("candidate should be subset")
	}

	candidate = map[string]struct{}{"3.3.3.3": {}}
	if isSubset(candidate, wildcardSet) {
		t.Fatal("candidate should not be subset")
	}
}
