package source

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

var siteDossierPagePattern = regexp.MustCompile(`/parentdomain/[^/"']+/(\d+)["']`)

type SiteDossier struct {
	rt *runtimeClient
}

func NewSiteDossier(client *http.Client) *SiteDossier {
	return &SiteDossier{rt: newRuntimeClient("sitedossier", client)}
}

func (s *SiteDossier) Name() string {
	return "sitedossier"
}

func (s *SiteDossier) Enumerate(ctx context.Context, domain string) ([]string, error) {
	bases := []string{
		"https://www.sitedossier.com/parentdomain/" + url.PathEscape(domain),
		"http://www.sitedossier.com/parentdomain/" + url.PathEscape(domain),
	}

	var lastErr error
	for _, base := range bases {
		hosts, err := s.enumerateBase(ctx, base, domain)
		if err != nil {
			lastErr = err
			continue
		}
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no sitedossier records found")
}

func (s *SiteDossier) enumerateBase(ctx context.Context, baseURL, domain string) ([]string, error) {
	collected := []string{}
	seen := map[string]struct{}{}
	maxPages := 1

	for page := 1; page <= maxPages; page++ {
		endpoint := baseURL
		if page > 1 {
			endpoint = fmt.Sprintf("%s/%d", baseURL, page)
		}
		body, _, err := s.rt.Get(ctx, endpoint, nil)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		html := string(body)
		hosts := extractHostsFromText(html, domain)
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}

		if page == 1 {
			parsedPages := parseSiteDossierMaxPage(html)
			if parsedPages > 1 {
				maxPages = parsedPages
				if maxPages > 20 {
					maxPages = 20
				}
			}
		}
	}

	return normalizeAndFilterHosts(collected, domain), nil
}

func parseSiteDossierMaxPage(html string) int {
	matches := siteDossierPagePattern.FindAllStringSubmatch(html, -1)
	maxPage := 1
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		page, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		if page > maxPage {
			maxPage = page
		}
	}
	return maxPage
}
