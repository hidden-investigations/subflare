package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type WaybackArchive struct {
	rt *runtimeClient
}

func NewWaybackArchive(client *http.Client) *WaybackArchive {
	return &WaybackArchive{rt: newRuntimeClient("waybackarchive", client)}
}

func (s *WaybackArchive) Name() string {
	return "waybackarchive"
}

func (s *WaybackArchive) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("url", "*."+domain+"/*")
	query.Set("output", "json")
	query.Set("fl", "original")
	query.Set("collapse", "urlkey")
	query.Set("showNumPages", "false")

	endpoint := "https://web.archive.org/cdx/search/cdx?" + query.Encode()
	body, _, err := s.rt.Get(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}

	hosts := parseWaybackBody(body, domain)
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseWaybackBody(body []byte, domain string) []string {
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err == nil && len(rows) > 0 {
		out := []string{}
		for idx, row := range rows {
			if len(row) == 0 {
				continue
			}
			// First row is commonly a header row ("original").
			if idx == 0 && row[0] == "original" {
				continue
			}
			out = append(out, extractHostsFromText(row[0], domain)...)
		}
		return out
	}

	return extractHostsFromText(string(body), domain)
}
