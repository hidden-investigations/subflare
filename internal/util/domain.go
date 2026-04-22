package util

import (
	"regexp"
	"sort"
	"strings"
)

var validHostRegex = regexp.MustCompile(`^[a-z0-9.-]+$`)

func NormalizeDomain(input string) string {
	value := strings.TrimSpace(strings.ToLower(input))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimSuffix(value, "/")
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	return value
}

func NormalizeHost(input string) string {
	value := strings.TrimSpace(strings.ToLower(input))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	if idx := strings.IndexAny(value, "/,\t "); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func IsSubdomainOf(host, domain string) bool {
	host = NormalizeHost(host)
	domain = NormalizeDomain(domain)
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return false
	}
	if !strings.HasSuffix(host, "."+domain) {
		return false
	}
	return validHostRegex.MatchString(host)
}

func UniqueSorted(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func RelativeParts(host, domain string) []string {
	host = NormalizeHost(host)
	domain = NormalizeDomain(domain)
	if !IsSubdomainOf(host, domain) {
		return nil
	}
	relative := strings.TrimSuffix(host, "."+domain)
	if relative == "" {
		return nil
	}
	return strings.Split(relative, ".")
}
