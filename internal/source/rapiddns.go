package source

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var rapidDNSPagePattern = regexp.MustCompile(`(?i)(?:\?|&)page=(\d+)`)

type RapidDNS struct {
	rt *runtimeClient
}

func NewRapidDNS(client *http.Client) *RapidDNS {
	return &RapidDNS{rt: newRuntimeClient("rapiddns", client)}
}

func (s *RapidDNS) Name() string {
	return "rapiddns"
}

func (s *RapidDNS) Enumerate(ctx context.Context, domain string) ([]string, error) {
	maxPages := 1
	collected := []string{}
	seen := map[string]struct{}{}

	for page := 1; page <= maxPages; page++ {
		endpoint := fmt.Sprintf("https://rapiddns.io/subdomain/%s?page=%d&full=1", domain, page)
		body, _, err := s.rt.Get(ctx, endpoint, nil)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		src := string(body)
		hosts := extractHostsFromText(src, domain)
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}

		if page == 1 {
			maxPages = parseRapidDNSMaxPage(src)
			if maxPages < 1 {
				maxPages = 1
			}
			if maxPages > 30 {
				maxPages = 30
			}
		}
	}

	return normalizeAndFilterHosts(collected, domain), nil
}

func parseRapidDNSMaxPage(body string) int {
	matches := rapidDNSPagePattern.FindAllStringSubmatch(body, -1)
	maxPage := 1
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			continue
		}
		if parsed > maxPage {
			maxPage = parsed
		}
	}
	return maxPage
}
