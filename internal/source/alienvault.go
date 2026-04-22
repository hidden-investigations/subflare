package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type AlienVault struct {
	rt *runtimeClient
}

type alienVaultPassiveDNSResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

type alienVaultURLListResponse struct {
	HasNext bool `json:"has_next"`
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
}

func NewAlienVault(client *http.Client) *AlienVault {
	return &AlienVault{rt: newRuntimeClient("alienvault", client)}
}

func (s *AlienVault) Name() string {
	return "alienvault"
}

func (s *AlienVault) Enumerate(ctx context.Context, domain string) ([]string, error) {
	headers := map[string]string{"Accept": "application/json"}
	if key := s.rt.ProviderValue("ALIENVAULT_API_KEY", "alienvault_api_key", "otx_api_key"); key != "" {
		headers["Authorization"] = "Bearer " + key
	}

	passiveEndpoint := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(domain) + "/passive_dns"
	if body, _, err := s.rt.Get(ctx, passiveEndpoint, headers); err == nil {
		if hosts, decodeErr := parseAlienVaultPassiveDNSBody(body); decodeErr == nil {
			hosts = normalizeAndFilterHosts(hosts, domain)
			if len(hosts) > 0 {
				return hosts, nil
			}
		}
	}

	return s.enumerateFromURLList(ctx, domain, headers)
}

func (s *AlienVault) enumerateFromURLList(ctx context.Context, domain string, headers map[string]string) ([]string, error) {
	hosts := []string{}
	seen := map[string]struct{}{}

	page := 1
	for {
		endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=100&page=%d", url.PathEscape(domain), page)
		body, _, err := s.rt.Get(ctx, endpoint, headers)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		var payload alienVaultURLListResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		hostsFromPage := parseAlienVaultURLListBody(payload)
		for _, host := range hostsFromPage {
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}

		if !payload.HasNext {
			break
		}
		page++
		if page > 30 {
			break
		}
	}

	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseAlienVaultPassiveDNSBody(body []byte) ([]string, error) {
	var data alienVaultPassiveDNSResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(data.PassiveDNS))
	for _, row := range data.PassiveDNS {
		hosts = append(hosts, row.Hostname)
	}
	return hosts, nil
}

func parseAlienVaultURLListBody(payload alienVaultURLListResponse) []string {
	hosts := []string{}
	for _, row := range payload.URLList {
		parsed, parseErr := url.Parse(row.URL)
		if parseErr != nil {
			continue
		}
		host := strings.TrimSpace(strings.ToLower(parsed.Hostname()))
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
