package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type CommonCrawl struct {
	rt *runtimeClient
}

func NewCommonCrawl(client *http.Client) *CommonCrawl {
	return &CommonCrawl{rt: newRuntimeClient("commoncrawl", client)}
}

func (s *CommonCrawl) Name() string {
	return "commoncrawl"
}

func (s *CommonCrawl) Enumerate(ctx context.Context, domain string) ([]string, error) {
	indexes, err := s.loadIndexes(ctx)
	if err != nil {
		return nil, err
	}

	collected := []string{}
	seen := map[string]struct{}{}
	var lastErr error

	for i, indexURL := range indexes {
		if i >= 4 {
			break
		}
		endpoint := indexURL + "?url=" + url.QueryEscape("*."+domain) + "&output=json"
		body, _, reqErr := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		hosts := extractHostsFromText(string(body), domain)
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}
	}

	if len(collected) > 0 {
		return normalizeAndFilterHosts(collected, domain), nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no commoncrawl records found")
}

func (s *CommonCrawl) loadIndexes(ctx context.Context) ([]string, error) {
	body, _, err := s.rt.Get(ctx, "https://index.commoncrawl.org/collinfo.json", map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	var rows []struct {
		API string `json:"cdx-api"`
		ID  string `json:"id"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rows))
	for _, row := range rows {
		switch {
		case row.API != "":
			out = append(out, row.API)
		case row.ID != "":
			out = append(out, "https://index.commoncrawl.org/"+row.ID+"-index")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no commoncrawl index metadata")
	}
	return out, nil
}
