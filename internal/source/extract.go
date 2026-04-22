package source

import (
	"regexp"
	"strings"

	"github.com/hidden-investigations/subflare/internal/util"
)

func normalizeAndFilterHosts(raw []string, domain string) []string {
	domain = util.NormalizeDomain(domain)
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range raw {
		host := util.NormalizeHost(item)
		if !util.IsSubdomainOf(host, domain) {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return util.UniqueSorted(out)
}

func extractHostsFromText(text, domain string) []string {
	domain = util.NormalizeDomain(domain)
	if text == "" || domain == "" {
		return nil
	}

	pattern := regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
	matches := pattern.FindAllString(strings.ToLower(text), -1)
	return normalizeAndFilterHosts(matches, domain)
}
