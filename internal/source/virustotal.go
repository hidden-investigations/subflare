package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type VirusTotal struct {
	rt *runtimeClient
}

func NewVirusTotal(client *http.Client) *VirusTotal {
	return &VirusTotal{rt: newRuntimeClient("virustotal", client)}
}

func (s *VirusTotal) Name() string {
	return "virustotal"
}

func (s *VirusTotal) Enumerate(ctx context.Context, domain string) ([]string, error) {
	key := s.rt.ProviderValue("VIRUSTOTAL_API_KEY", "VT_API_KEY", "virustotal_api_key")
	if key == "" {
		return nil, fmt.Errorf("missing VIRUSTOTAL_API_KEY")
	}

	headers := map[string]string{
		"Accept":   "application/json",
		"x-apikey": key,
	}

	collected := []string{}
	seen := map[string]struct{}{}
	cursor := ""

	for page := 0; page < 6; page++ {
		endpoint := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(domain) + "/subdomains?limit=40"
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		body, _, err := s.rt.Get(ctx, endpoint, headers)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			break
		}

		hosts, nextCursor, parseErr := parseVirusTotalBody(body)
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

func parseVirusTotalBody(body []byte) ([]string, string, error) {
	var payload struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				HostName string `json:"host_name"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			Cursor string `json:"cursor"`
		} `json:"meta"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	if payload.Error.Message != "" {
		return nil, "", fmt.Errorf(payload.Error.Message)
	}

	hosts := []string{}
	for _, item := range payload.Data {
		value := strings.TrimSpace(item.ID)
		if value == "" {
			value = strings.TrimSpace(item.Attributes.HostName)
		}
		if value != "" {
			hosts = append(hosts, value)
		}
	}

	cursor := strings.TrimSpace(payload.Meta.Cursor)
	if cursor == "" && strings.TrimSpace(payload.Links.Next) != "" {
		parsed, err := url.Parse(payload.Links.Next)
		if err == nil {
			cursor = parsed.Query().Get("cursor")
		}
	}

	return hosts, cursor, nil
}
