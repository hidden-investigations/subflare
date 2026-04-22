package util

import "testing"

func TestNormalizeHost(t *testing.T) {
	host := NormalizeHost("https://*.API.Example.com/path")
	if host != "api.example.com" {
		t.Fatalf("unexpected host: %s", host)
	}
}

func TestIsSubdomainOf(t *testing.T) {
	if !IsSubdomainOf("api.example.com", "example.com") {
		t.Fatal("expected api.example.com to be a subdomain")
	}
	if IsSubdomainOf("example.com", "example.com") {
		t.Fatal("root domain should not be treated as subdomain")
	}
	if IsSubdomainOf("api.other.com", "example.com") {
		t.Fatal("cross-domain host should not match")
	}
}
