package source

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
)

type HackerTarget struct {
	rt *runtimeClient
}

func NewHackerTarget(client *http.Client) *HackerTarget {
	return &HackerTarget{rt: newRuntimeClient("hackertarget", client)}
}

func (s *HackerTarget) Name() string {
	return "hackertarget"
}

func (s *HackerTarget) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("q", domain)
	if key := s.rt.ProviderValue("HACKERTARGET_API_KEY", "hackertarget_api_key"); key != "" {
		query.Set("apikey", key)
	}
	endpoint := "https://api.hackertarget.com/hostsearch/?" + query.Encode()
	body, _, err := s.rt.Get(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}

	hosts, err := parseHackerTargetBody(body)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseHackerTargetBody(body []byte) ([]string, error) {
	hosts := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(strings.ToLower(line), "error") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) == 0 {
			continue
		}
		host := strings.TrimSpace(fields[0])
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}
