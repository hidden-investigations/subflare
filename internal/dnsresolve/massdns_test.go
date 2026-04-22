package dnsresolve

import "testing"

func TestParseMassDNSLine(t *testing.T) {
	host, typ, value, ok := parseMassDNSLine("api.example.com. A 1.2.3.4")
	if !ok {
		t.Fatal("expected parse success")
	}
	if host != "api.example.com" || typ != "A" || value != "1.2.3.4" {
		t.Fatalf("unexpected parse values: %s %s %s", host, typ, value)
	}

	host, typ, value, ok = parseMassDNSLine("cdn.example.com. CNAME edge.example.net.")
	if !ok {
		t.Fatal("expected cname parse success")
	}
	if host != "cdn.example.com" || typ != "CNAME" || value != "edge.example.net" {
		t.Fatalf("unexpected cname parse values: %s %s %s", host, typ, value)
	}
}
