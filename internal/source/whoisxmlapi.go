package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type WhoisXMLAPI struct {
	rt *runtimeClient
}

func NewWhoisXMLAPI(client *http.Client) *WhoisXMLAPI {
	return &WhoisXMLAPI{rt: newRuntimeClient("whoisxmlapi", client)}
}

func (s *WhoisXMLAPI) Name() string {
	return "whoisxmlapi"
}

func (s *WhoisXMLAPI) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("WHOISXMLAPI_API_KEY", "WHOISXML_API_KEY", "whoisxmlapi_api_key")
	if key == "" {
		return nil, fmt.Errorf("missing WHOISXMLAPI_API_KEY")
	}

	query := url.Values{}
	query.Set("apiKey", key)
	query.Set("domainName", domain)
	query.Set("outputFormat", "JSON")
	endpoint := "https://subdomains.whoisxmlapi.com/api/v1?" + query.Encode()

	body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	hosts, err := parseWhoisXMLAPIBody(body, domain)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseWhoisXMLAPIBody(body []byte, domain string) ([]string, error) {
	var payload struct {
		Error  string `json:"error"`
		Code   int    `json:"code"`
		Result struct {
			Records []struct {
				Domain string `json:"domain"`
			} `json:"records"`
			Subdomains []struct {
				Subdomain string `json:"subdomain"`
			} `json:"subdomains"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Error != "" {
		return nil, fmt.Errorf(payload.Error)
	}
	if payload.Code >= 400 {
		return nil, fmt.Errorf("whoisxmlapi error code %d", payload.Code)
	}

	out := []string{}
	for _, row := range payload.Result.Records {
		out = append(out, row.Domain)
	}
	for _, row := range payload.Result.Subdomains {
		if row.Subdomain != "" {
			out = append(out, row.Subdomain+"."+domain)
		}
	}
	if len(out) == 0 {
		out = extractHostsFromText(string(body), domain)
	}
	return out, nil
}
