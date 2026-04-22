package enum

import (
	"sort"
	"strconv"
	"strings"

	"github.com/hidden-investigations/subflare/internal/util"
)

func GeneratePermutations(domain string, existingHosts []string, depth, max int) []string {
	domain = util.NormalizeDomain(domain)
	if domain == "" || max < 1 || depth < 1 {
		return nil
	}

	seedWords := buildSeedWords(domain, existingHosts)
	if len(seedWords) == 0 {
		return nil
	}

	out := map[string]struct{}{}
	appendHost := func(label string) bool {
		label = sanitizeLabel(label)
		if label == "" {
			return false
		}
		host := label + "." + domain
		host = util.NormalizeHost(host)
		if !util.IsSubdomainOf(host, domain) {
			return false
		}
		out[host] = struct{}{}
		return len(out) >= max
	}

	level := append([]string{}, seedWords...)
	if len(level) > 40 {
		level = level[:40]
	}

	for _, word := range level {
		if appendHost(word) {
			return sortedHosts(out)
		}
		if appendHost(word+"-dev") || appendHost(word+"-stage") || appendHost(word+"-prod") {
			return sortedHosts(out)
		}
		for n := 1; n <= 2; n++ {
			if appendHost(word+strconv.Itoa(n)) || appendHost(strconv.Itoa(n)+"-"+word) {
				return sortedHosts(out)
			}
		}
	}

	if depth == 1 {
		return sortedHosts(out)
	}

	current := level
	for d := 2; d <= depth; d++ {
		next := []string{}
		for _, base := range current {
			for _, word := range seedWords {
				c1 := sanitizeLabel(base + "-" + word)
				c2 := sanitizeLabel(word + "-" + base)
				if c1 != "" {
					next = append(next, c1)
					if appendHost(c1) {
						return sortedHosts(out)
					}
				}
				if c2 != "" {
					next = append(next, c2)
					if appendHost(c2) {
						return sortedHosts(out)
					}
				}
			}
		}
		if len(next) == 0 {
			break
		}
		if len(next) > 100 {
			next = next[:100]
		}
		current = util.UniqueSorted(next)
	}

	return sortedHosts(out)
}

func buildSeedWords(domain string, hosts []string) []string {
	seedSet := map[string]struct{}{}
	appendWord := func(raw string) {
		word := sanitizeLabel(raw)
		if word == "" || len(word) < 2 {
			return
		}
		seedSet[word] = struct{}{}
	}

	for _, part := range strings.Split(domain, ".") {
		for _, token := range splitTokens(part) {
			appendWord(token)
		}
	}

	for _, host := range hosts {
		host = util.NormalizeHost(host)
		if !util.IsSubdomainOf(host, domain) {
			continue
		}
		trimmed := strings.TrimSuffix(host, "."+domain)
		for _, label := range strings.Split(trimmed, ".") {
			for _, token := range splitTokens(label) {
				appendWord(token)
			}
		}
	}

	common := []string{"api", "dev", "prod", "stage", "staging", "beta", "test", "internal", "cdn", "img"}
	for _, word := range common {
		appendWord(word)
	}

	out := make([]string, 0, len(seedSet))
	for word := range seedSet {
		out = append(out, word)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) < len(out[j])
	})
	return out
}

func splitTokens(input string) []string {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return nil
	}
	raw := strings.FieldsFunc(input, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = sanitizeLabel(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sanitizeLabel(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.Trim(input, "-.")
	if input == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(input))
	lastDash := false
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastDash = false
		case r == '-':
			if !lastDash {
				builder.WriteRune(r)
			}
			lastDash = true
		}
	}
	result := strings.Trim(builder.String(), "-")
	if len(result) > 63 {
		result = result[:63]
		result = strings.Trim(result, "-")
	}
	return result
}

func sortedHosts(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	return util.UniqueSorted(out)
}
