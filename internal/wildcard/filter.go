package wildcard

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/dnsresolve"
	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

type Filter struct {
	domain string
	tests  int

	resolver *dnsresolve.Resolver

	mu    sync.Mutex
	cache map[string]signature
	rng   *rand.Rand
}

type signature struct {
	wildcard bool
	answers  map[string]struct{}
}

func New(domain string, tests int, resolver *dnsresolve.Resolver) *Filter {
	return &Filter{
		domain:   util.NormalizeDomain(domain),
		tests:    tests,
		resolver: resolver,
		cache:    make(map[string]signature),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (f *Filter) Filter(ctx context.Context, in []model.Result) ([]model.Result, int) {
	clean := make([]model.Result, 0, len(in))
	dropped := 0

	for _, item := range in {
		wild, err := f.isWildcard(ctx, item)
		if err != nil {
			// Keep hosts on wildcard-check errors to avoid false negatives.
			clean = append(clean, item)
			continue
		}
		if wild {
			dropped++
			continue
		}
		clean = append(clean, item)
	}

	return clean, dropped
}

func (f *Filter) isWildcard(ctx context.Context, item model.Result) (bool, error) {
	candidateAnswers := answersFromResult(item)
	if len(candidateAnswers) == 0 {
		return false, nil
	}

	suffixes := parentSuffixes(item.Host, f.domain)
	for _, suffix := range suffixes {
		sig, err := f.getSignature(ctx, suffix)
		if err != nil {
			return false, err
		}
		if !sig.wildcard {
			continue
		}
		if isSubset(candidateAnswers, sig.answers) {
			return true, nil
		}
	}

	return false, nil
}

func (f *Filter) getSignature(ctx context.Context, suffix string) (signature, error) {
	f.mu.Lock()
	if sig, ok := f.cache[suffix]; ok {
		f.mu.Unlock()
		return sig, nil
	}
	f.mu.Unlock()

	answers := make(map[string]struct{})
	for i := 0; i < f.tests; i++ {
		probe := f.randLabel(12) + "." + suffix
		ips, cnames, err := f.resolver.QueryA(ctx, probe)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			answers[ip] = struct{}{}
		}
		for _, cname := range cnames {
			answers[strings.ToLower(cname)] = struct{}{}
		}
	}

	sig := signature{wildcard: len(answers) > 0, answers: answers}

	f.mu.Lock()
	f.cache[suffix] = sig
	f.mu.Unlock()

	return sig, nil
}

func parentSuffixes(host, domain string) []string {
	host = util.NormalizeHost(host)
	domain = util.NormalizeDomain(domain)

	relative := strings.TrimSuffix(host, "."+domain)
	relative = strings.TrimSuffix(relative, ".")
	parts := []string{}
	if relative != host && relative != "" {
		parts = strings.Split(relative, ".")
	}

	suffixes := []string{}
	if len(parts) > 1 {
		for i := 1; i < len(parts); i++ {
			suffix := strings.Join(parts[i:], ".") + "." + domain
			suffixes = append(suffixes, suffix)
		}
	}
	suffixes = append(suffixes, domain)

	seen := map[string]struct{}{}
	out := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		if _, ok := seen[suffix]; ok {
			continue
		}
		seen[suffix] = struct{}{}
		out = append(out, suffix)
	}
	return out
}

func answersFromResult(result model.Result) map[string]struct{} {
	answers := make(map[string]struct{}, len(result.IPs)+len(result.CNAMEs))
	for _, ip := range result.IPs {
		answers[ip] = struct{}{}
	}
	for _, cname := range result.CNAMEs {
		answers[strings.ToLower(cname)] = struct{}{}
	}
	return answers
}

func isSubset(candidate, wildcard map[string]struct{}) bool {
	if len(candidate) == 0 {
		return false
	}
	for answer := range candidate {
		if _, ok := wildcard[answer]; !ok {
			return false
		}
	}
	return true
}

func (f *Filter) randLabel(length int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = alphabet[f.rng.Intn(len(alphabet))]
	}
	return string(buf)
}
