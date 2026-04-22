package enum

import "testing"

func TestGeneratePermutations(t *testing.T) {
	hosts := []string{
		"api.example.com",
		"dev.example.com",
		"assets.cdn.example.com",
	}
	out := GeneratePermutations("example.com", hosts, 2, 200)
	if len(out) == 0 {
		t.Fatal("expected non-empty permutations")
	}

	found := false
	for _, host := range out {
		if host == "api-dev.example.com" || host == "dev-api.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected combined permutation in output, got %d hosts", len(out))
	}
}
