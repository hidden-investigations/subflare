package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type ThreatCrowd struct {
	rt *runtimeClient
}

func NewThreatCrowd(client *http.Client) *ThreatCrowd {
	return &ThreatCrowd{rt: newRuntimeClient("threatcrowd", client)}
}

func (s *ThreatCrowd) Name() string {
	return "threatcrowd"
}

func (s *ThreatCrowd) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("domain", domain)
	endpoint := "https://www.threatcrowd.org/searchApi/v2/domain/report/?" + query.Encode()
	body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	hosts, err := parseThreatCrowdBody(body)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseThreatCrowdBody(body []byte) ([]string, error) {
	var payload struct {
		ResponseCode string   `json:"response_code"`
		Subdomains   []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload.Subdomains, nil
}
