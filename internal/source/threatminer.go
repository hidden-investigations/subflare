package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type ThreatMiner struct {
	rt *runtimeClient
}

func NewThreatMiner(client *http.Client) *ThreatMiner {
	return &ThreatMiner{rt: newRuntimeClient("threatminer", client)}
}

func (s *ThreatMiner) Name() string {
	return "threatminer"
}

func (s *ThreatMiner) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("q", domain)
	query.Set("rt", "5")
	endpoint := "https://api.threatminer.org/v2/domain.php?" + query.Encode()

	body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	hosts, err := parseThreatMinerBody(body)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseThreatMinerBody(body []byte) ([]string, error) {
	var payload struct {
		StatusCode string   `json:"status_code"`
		Results    []string `json:"results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload.Results, nil
}
