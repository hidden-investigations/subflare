package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type Shodan struct {
	rt *runtimeClient
}

func NewShodan(client *http.Client) *Shodan {
	return &Shodan{rt: newRuntimeClient("shodan", client)}
}

func (s *Shodan) Name() string {
	return "shodan"
}

func (s *Shodan) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("SHODAN_API_KEY", "shodan_api_key")
	if key == "" {
		return nil, fmt.Errorf("missing SHODAN_API_KEY")
	}

	query := url.Values{}
	query.Set("key", key)
	endpoint := "https://api.shodan.io/dns/domain/" + url.PathEscape(domain) + "?" + query.Encode()
	body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	subs, err := parseShodanBody(body)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(subs))
	for _, sub := range subs {
		hosts = append(hosts, sub+"."+domain)
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseShodanBody(body []byte) ([]string, error) {
	var response struct {
		Error      string   `json:"error"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, fmt.Errorf(response.Error)
	}
	return response.Subdomains, nil
}
