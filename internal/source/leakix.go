package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type LeakIX struct {
	rt *runtimeClient
}

func NewLeakIX(client *http.Client) *LeakIX {
	return &LeakIX{rt: newRuntimeClient("leakix", client)}
}

func (s *LeakIX) Name() string {
	return "leakix"
}

func (s *LeakIX) Enumerate(ctx context.Context, domain string) ([]string, error) {
	headers := map[string]string{"Accept": "application/json"}
	if key := s.rt.ProviderValue("LEAKIX_API_KEY", "leakix_api_key"); key != "" {
		headers["api-key"] = key
	}

	apiEndpoint := "https://leakix.net/api/subdomains/" + url.PathEscape(domain)
	body, _, err := s.rt.Get(ctx, apiEndpoint, headers)
	if err == nil {
		hosts := parseLeakIXBody(body)
		hosts = normalizeAndFilterHosts(hosts, domain)
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	htmlEndpoint := "https://leakix.net/domain/" + url.PathEscape(domain)
	htmlBody, _, htmlErr := s.rt.Get(ctx, htmlEndpoint, nil)
	if htmlErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, htmlErr
	}

	hosts := extractHostsFromText(string(htmlBody), domain)
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseLeakIXBody(body []byte) []string {
	hosts := []string{}

	var objectRows []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(body, &objectRows); err == nil && len(objectRows) > 0 {
		for _, row := range objectRows {
			hosts = append(hosts, row.Subdomain)
		}
		return hosts
	}

	var plainRows []string
	if err := json.Unmarshal(body, &plainRows); err == nil && len(plainRows) > 0 {
		return plainRows
	}

	var wrapped struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && len(wrapped.Subdomains) > 0 {
		return wrapped.Subdomains
	}

	return hosts
}
