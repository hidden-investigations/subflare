package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type CertSpotter struct {
	authRT   *runtimeClient
	unauthRT *runtimeClient
}

func NewCertSpotter(client *http.Client) *CertSpotter {
	return &CertSpotter{
		authRT:   newRuntimeClient("certspotter_auth", client),
		unauthRT: newRuntimeClient("certspotter_unauth", client),
	}
}

func (s *CertSpotter) Name() string {
	return "certspotter"
}

func (s *CertSpotter) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("domain", domain)
	query.Set("include_subdomains", "true")
	query.Set("expand", "dns_names")

	headers := map[string]string{"Accept": "application/json"}
	rt := s.unauthRT
	if token := s.authRT.ProviderValue("CERTSPOTTER_TOKEN", "CERTSPOTTER_API_TOKEN", "CERTSPOTTER_API_KEY"); token != "" {
		headers["Authorization"] = "Bearer " + token
		rt = s.authRT
	}

	endpoint := "https://api.certspotter.com/v1/issuances?" + query.Encode()
	body, _, err := rt.Get(ctx, endpoint, headers)
	if err != nil {
		if rt == s.authRT {
			// Fall back to unauthenticated mode if token request fails.
			delete(headers, "Authorization")
			body, _, err = s.unauthRT.Get(ctx, endpoint, headers)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	hosts, err := parseCertSpotterBody(body)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseCertSpotterBody(body []byte) ([]string, error) {
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	hosts := []string{}
	for _, row := range rows {
		hosts = append(hosts, row.DNSNames...)
	}
	return hosts, nil
}
