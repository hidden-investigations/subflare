package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type Chaos struct {
	rt *runtimeClient
}

func NewChaos(client *http.Client) *Chaos {
	return &Chaos{rt: newRuntimeClient("chaos", client)}
}

func (s *Chaos) Name() string {
	return "chaos"
}

func (s *Chaos) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("CHAOS_API_KEY", "PDCP_API_KEY", "chaos_api_key")
	if key == "" {
		return nil, fmt.Errorf("missing CHAOS_API_KEY")
	}

	endpoint := "https://dns.projectdiscovery.io/dns/" + url.PathEscape(domain) + "/subdomains"
	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": key,
		"X-API-Key":     key,
	}

	body, _, err := s.rt.Get(ctx, endpoint, headers)
	if err != nil {
		return nil, err
	}

	subs, err := parseChaosBody(body)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(subs))
	for _, sub := range subs {
		hosts = append(hosts, sub+"."+domain)
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseChaosBody(body []byte) ([]string, error) {
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
