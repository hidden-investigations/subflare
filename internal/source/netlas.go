package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type Netlas struct {
	rt *runtimeClient
}

func NewNetlas(client *http.Client) *Netlas {
	return &Netlas{rt: newRuntimeClient("netlas", client)}
}

func (s *Netlas) Name() string {
	return "netlas"
}

func (s *Netlas) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("q", "domain:*."+domain)
	query.Set("size", "100")
	endpoint := "https://app.netlas.io/api/domains/?" + query.Encode()

	headers := map[string]string{"Accept": "application/json"}
	if key := s.rt.ProviderValue("NETLAS_API_KEY", "netlas_api_key"); key != "" {
		headers["X-API-Key"] = key
		headers["Authorization"] = "Bearer " + key
	}

	body, _, err := s.rt.Get(ctx, endpoint, headers)
	if err == nil {
		hosts, parseErr := parseNetlasBody(body, domain)
		if parseErr == nil && len(hosts) > 0 {
			return normalizeAndFilterHosts(hosts, domain), nil
		}
	}

	fallback := "https://app.netlas.io/responses/?q=" + url.QueryEscape("domain:*."+domain)
	html, _, htmlErr := s.rt.Get(ctx, fallback, nil)
	if htmlErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, htmlErr
	}
	return normalizeAndFilterHosts(extractHostsFromText(string(html), domain), domain), nil
}

func parseNetlasBody(body []byte, domain string) ([]string, error) {
	var payload struct {
		Items []struct {
			Domain string `json:"domain"`
			Name   string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	out := []string{}
	for _, item := range payload.Items {
		out = append(out, item.Domain)
		out = append(out, item.Name)
	}
	if len(out) == 0 {
		out = extractHostsFromText(string(body), domain)
	}
	return out, nil
}
