package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type ZoomEyeAPI struct {
	rt *runtimeClient
}

func NewZoomEyeAPI(client *http.Client) *ZoomEyeAPI {
	return &ZoomEyeAPI{rt: newRuntimeClient("zoomeyeapi", client)}
}

func (s *ZoomEyeAPI) Name() string {
	return "zoomeyeapi"
}

func (s *ZoomEyeAPI) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("ZOOMEYE_API_KEY", "zoomeye_api_key", "ZOOMEYEAPI_KEY")
	if key == "" {
		return nil, fmt.Errorf("missing ZOOMEYE_API_KEY")
	}

	collected := []string{}
	seen := map[string]struct{}{}
	for page := 1; page <= 3; page++ {
		query := url.Values{}
		query.Set("q", domain)
		query.Set("type", "1")
		query.Set("page", fmt.Sprintf("%d", page))
		endpoint := "https://api.zoomeye.hk/domain/search?" + query.Encode()
		headers := map[string]string{
			"Accept":        "application/json",
			"API-KEY":       key,
			"Authorization": "JWT " + key,
		}
		body, _, err := s.rt.Get(ctx, endpoint, headers)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		hosts, parseErr := parseZoomEyeBody(body, domain)
		if parseErr != nil {
			if page == 1 {
				return nil, parseErr
			}
			break
		}
		if len(hosts) == 0 {
			break
		}
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}
	}

	return normalizeAndFilterHosts(collected, domain), nil
}

func parseZoomEyeBody(body []byte, domain string) ([]string, error) {
	var payload struct {
		Message string `json:"message"`
		List    []struct {
			Name   string `json:"name"`
			Domain string `json:"domain"`
		} `json:"list"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Message != "" && len(payload.List) == 0 {
		return nil, fmt.Errorf(payload.Message)
	}

	out := []string{}
	for _, item := range payload.List {
		out = append(out, item.Name)
		out = append(out, item.Domain)
	}
	if len(out) == 0 {
		out = extractHostsFromText(string(body), domain)
	}
	return out, nil
}
