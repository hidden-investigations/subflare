package infra

import (
	"testing"

	"github.com/hidden-investigations/subflare/internal/model"
)

func TestParseCymruTXT(t *testing.T) {
	info := parseCymruTXT("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11 | CLOUDFLARENET - Cloudflare, Inc., US")
	if info.ASN != "AS13335" {
		t.Fatalf("unexpected ASN: %s", info.ASN)
	}
	if info.Org == "" {
		t.Fatal("expected org")
	}
}

func TestDetectCDN(t *testing.T) {
	item := model.Result{CNAMEs: []string{"d111111abcdef8.cloudfront.net"}}
	if got := detectCDN(item); got != "cloudfront" {
		t.Fatalf("unexpected cdn: %s", got)
	}
}

func TestToCymruQueryName(t *testing.T) {
	q, err := toCymruQueryName("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if q != "4.3.2.1" {
		t.Fatalf("unexpected query name: %s", q)
	}
}
