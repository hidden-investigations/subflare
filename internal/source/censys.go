package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Censys struct {
	rt *runtimeClient
}

func NewCensys(client *http.Client) *Censys {
	return &Censys{rt: newRuntimeClient("censys", client)}
}

func (s *Censys) Name() string {
	return "censys"
}

func (s *Censys) Enumerate(ctx context.Context, domain string) ([]string, error) {
	id := s.rt.ProviderValue("CENSYS_API_ID", "censys_api_id")
	secret := s.rt.ProviderValue("CENSYS_API_SECRET", "censys_api_secret")
	token := s.rt.ProviderValue("CENSYS_API_KEY", "censys_api_key")
	if (id == "" || secret == "") && token == "" {
		return nil, fmt.Errorf("missing CENSYS_API_ID/CENSYS_API_SECRET or CENSYS_API_KEY")
	}

	headers := map[string]string{"Accept": "application/json"}
	if id != "" && secret != "" {
		raw := id + ":" + secret
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
	} else {
		headers["Authorization"] = "Bearer " + token
	}

	collected := []string{}
	seen := map[string]struct{}{}
	cursor := ""

	for page := 0; page < 5; page++ {
		query := url.Values{}
		query.Set("q", "parsed.names: *."+domain)
		query.Set("per_page", "100")
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		endpoint := "https://search.censys.io/api/v2/certificates/search?" + query.Encode()
		body, _, err := s.rt.Get(ctx, endpoint, headers)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			break
		}

		hosts, nextCursor, parseErr := parseCensysBody(body, domain)
		if parseErr != nil {
			if page == 0 {
				return nil, parseErr
			}
			break
		}
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}
		if strings.TrimSpace(nextCursor) == "" {
			break
		}
		cursor = nextCursor
	}

	return normalizeAndFilterHosts(collected, domain), nil
}

func parseCensysBody(body []byte, domain string) ([]string, string, error) {
	var payload struct {
		Error  string `json:"error"`
		Code   int    `json:"code"`
		Result struct {
			Hits []struct {
				Names  []string `json:"names"`
				Parsed struct {
					Names []string `json:"names"`
				} `json:"parsed"`
			} `json:"hits"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	if payload.Error != "" {
		return nil, "", fmt.Errorf(payload.Error)
	}
	if payload.Code >= 400 {
		return nil, "", fmt.Errorf("censys API error code %d", payload.Code)
	}

	hosts := []string{}
	for _, hit := range payload.Result.Hits {
		hosts = append(hosts, hit.Names...)
		hosts = append(hosts, hit.Parsed.Names...)
	}
	if len(hosts) == 0 {
		hosts = extractHostsFromText(string(body), domain)
	}
	return hosts, strings.TrimSpace(payload.Result.Links.Next), nil
}
