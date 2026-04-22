package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type GitLab struct {
	rt *runtimeClient
}

func NewGitLab(client *http.Client) *GitLab {
	return &GitLab{rt: newRuntimeClient("gitlab", client)}
}

func (s *GitLab) Name() string {
	return "gitlab"
}

func (s *GitLab) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("scope", "blobs")
	query.Set("search", "."+domain)
	query.Set("per_page", "100")
	endpoint := "https://gitlab.com/api/v4/search?" + query.Encode()

	headers := map[string]string{"Accept": "application/json"}
	if token := s.rt.ProviderValue("GITLAB_TOKEN", "gitlab_token"); token != "" {
		headers["Private-Token"] = token
		headers["Authorization"] = "Bearer " + token
	}

	body, status, err := s.rt.Get(ctx, endpoint, headers)
	if err == nil {
		hosts, parseErr := parseGitLabBody(body, domain)
		if parseErr == nil && len(hosts) > 0 {
			return normalizeAndFilterHosts(hosts, domain), nil
		}
	}

	fallback := "https://gitlab.com/search?search=" + url.QueryEscape("."+domain) + "&group_id=&project_id=&repository_ref=&scope=blobs"
	html, _, htmlErr := s.rt.Get(ctx, fallback, nil)
	if htmlErr != nil {
		if err != nil {
			return nil, err
		}
		if status > 0 {
			return nil, fmt.Errorf("gitlab API returned status %d", status)
		}
		return nil, htmlErr
	}
	return normalizeAndFilterHosts(extractHostsFromText(string(html), domain), domain), nil
}

func parseGitLabBody(body []byte, domain string) ([]string, error) {
	var payload []struct {
		Data     string `json:"data"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	hosts := []string{}
	for _, item := range payload {
		hosts = append(hosts, extractHostsFromText(item.Data, domain)...)
		hosts = append(hosts, extractHostsFromText(item.Filename, domain)...)
		hosts = append(hosts, extractHostsFromText(item.Path, domain)...)
	}
	return hosts, nil
}
