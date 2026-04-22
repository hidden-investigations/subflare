package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type SecurityTrails struct {
	rt *runtimeClient
}

func NewSecurityTrails(client *http.Client) *SecurityTrails {
	return &SecurityTrails{rt: newRuntimeClient("securitytrails", client)}
}

func (s *SecurityTrails) Name() string {
	return "securitytrails"
}

func (s *SecurityTrails) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("SECURITYTRAILS_API_KEY", "securitytrails_api_key")
	if key == "" {
		return nil, fmt.Errorf("missing SECURITYTRAILS_API_KEY")
	}

	query := url.Values{}
	query.Set("children_only", "false")
	endpoint := "https://api.securitytrails.com/v1/domain/" + url.PathEscape(domain) + "/subdomains?" + query.Encode()
	headers := map[string]string{
		"Accept": "application/json",
		"APIKEY": key,
	}

	body, _, err := s.rt.Get(ctx, endpoint, headers)
	if err != nil {
		return nil, err
	}

	subs, err := parseSecurityTrailsBody(body)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(subs))
	for _, sub := range subs {
		hosts = append(hosts, sub+"."+domain)
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseSecurityTrailsBody(body []byte) ([]string, error) {
	var payload struct {
		Error      string   `json:"error"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Error != "" {
		return nil, fmt.Errorf(payload.Error)
	}
	return payload.Subdomains, nil
}
