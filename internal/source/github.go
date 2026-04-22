package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type GitHub struct {
	rt *runtimeClient
}

func NewGitHub(client *http.Client) *GitHub {
	return &GitHub{rt: newRuntimeClient("github", client)}
}

func (s *GitHub) Name() string {
	return "github"
}

func (s *GitHub) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("q", "\"."+domain+"\" in:file")
	query.Set("per_page", "100")
	endpoint := "https://api.github.com/search/code?" + query.Encode()

	headers := map[string]string{
		"Accept":               "application/vnd.github.text-match+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token := s.rt.ProviderValue("GITHUB_TOKEN", "GH_TOKEN", "github_token"); token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	body, status, err := s.rt.Get(ctx, endpoint, headers)
	if err == nil {
		hosts, parseErr := parseGitHubBody(body, domain)
		if parseErr == nil && len(hosts) > 0 {
			return normalizeAndFilterHosts(hosts, domain), nil
		}
	}

	// Fallback to HTML search page for unauthenticated mode/rate-limit conditions.
	fallback := "https://github.com/search?q=" + url.QueryEscape("\"."+domain+"\"") + "&type=code"
	html, _, htmlErr := s.rt.Get(ctx, fallback, nil)
	if htmlErr != nil {
		if err != nil {
			return nil, err
		}
		if status > 0 {
			return nil, fmt.Errorf("github API returned status %d", status)
		}
		return nil, htmlErr
	}
	return normalizeAndFilterHosts(extractHostsFromText(string(html), domain), domain), nil
}

func parseGitHubBody(body []byte, domain string) ([]string, error) {
	var payload struct {
		Message string `json:"message"`
		Items   []struct {
			TextMatches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
			Path string `json:"path"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Message != "" && len(payload.Items) == 0 {
		return nil, fmt.Errorf(payload.Message)
	}

	hosts := []string{}
	for _, item := range payload.Items {
		for _, match := range item.TextMatches {
			hosts = append(hosts, extractHostsFromText(match.Fragment, domain)...)
		}
		hosts = append(hosts, extractHostsFromText(item.Path, domain)...)
	}
	return hosts, nil
}
