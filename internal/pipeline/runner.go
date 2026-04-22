package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hidden-investigations/subflare/internal/dnsresolve"
	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/options"
	"github.com/hidden-investigations/subflare/internal/provider"
	"github.com/hidden-investigations/subflare/internal/source"
	"github.com/hidden-investigations/subflare/internal/util"
	"github.com/hidden-investigations/subflare/internal/wildcard"
)

type Report struct {
	Results []model.Result
	Stats   Stats
	Errors  []error
}

type Stats struct {
	PassiveDiscovered int
	PassiveCacheHits  int
	PassiveSources    int
	PassiveSucceeded  int
	PassiveFailed     int
	SourceCounts      map[string]int
	SourceCacheHits   map[string]int
	SourceErrors      map[string]string
	BruteforceSeeded  int
	CandidateTotal    int
	ResolvedFast      int
	FailedFast        int
	WildcardDropped   int
	TrustedDropped    int
	FinalTotal        int
}

func Run(ctx context.Context, opts options.Options) (Report, error) {
	report := Report{}
	report.Stats.SourceCounts = map[string]int{}
	report.Stats.SourceCacheHits = map[string]int{}
	report.Stats.SourceErrors = map[string]string{}
	candidateMap := map[string]model.Candidate{}

	providers, err := provider.Load(opts.ProviderConfig)
	if err != nil {
		return report, fmt.Errorf("load provider config: %w", err)
	}

	if opts.Passive {
		sources, err := source.BuildSources(source.BuildOptions{
			HTTPTimeout: opts.HTTPTimeout,
			Requested:   opts.Sources,
			Excluded:    opts.ExcludeSources,
			Runtime: source.RuntimeOptions{
				Providers:        providers,
				RateLimit:        opts.RateLimit,
				SourceRateLimits: opts.SourceRateLimits,
				SourceTimeout:    opts.SourceTimeout,
				SourceTimeouts:   opts.SourceTimeouts,
				SourceRetries:    opts.SourceRetries,
				SourceBackoff:    opts.SourceBackoff,
				SourceMaxBackoff: opts.SourceMaxBackoff,
			},
			RespectOrdering: true,
		})
		if err != nil {
			return report, fmt.Errorf("configure passive sources: %w", err)
		}
		report.Stats.PassiveSources = len(sources)
		passive := source.Collect(ctx, opts.Domain, sources, source.CollectOptions{
			Retries:        opts.SourceRetries,
			Backoff:        opts.SourceBackoff,
			Timeout:        opts.SourceTimeout,
			SourceTimeouts: opts.SourceTimeouts,
			CacheDir:       opts.CacheDir,
			CacheTTL:       opts.CacheTTL,
			NoCache:        opts.NoCache,
		})
		report.Errors = append(report.Errors, passive.Errors...)
		report.Stats.PassiveDiscovered = len(passive.Candidates)
		report.Stats.PassiveFailed = len(passive.SourceErrs)
		report.Stats.PassiveSucceeded = len(passive.Counts)
		for _, n := range passive.CacheHits {
			report.Stats.PassiveCacheHits += n
		}
		for name, count := range passive.Counts {
			report.Stats.SourceCounts[name] = count
		}
		for name, count := range passive.CacheHits {
			report.Stats.SourceCacheHits[name] = count
		}
		for name, sourceErr := range passive.SourceErrs {
			report.Stats.SourceErrors[name] = sourceErr.Error()
		}
		mergeCandidates(candidateMap, passive.Candidates)
	}

	if opts.Bruteforce {
		words, err := readWordlist(opts.Wordlist)
		if err != nil {
			return report, fmt.Errorf("read wordlist: %w", err)
		}
		now := time.Now().UTC().Unix()
		bf := make([]model.Candidate, 0, len(words))
		for _, word := range words {
			host := util.NormalizeHost(word + "." + opts.Domain)
			if !util.IsSubdomainOf(host, opts.Domain) {
				continue
			}
			bf = append(bf, model.Candidate{Host: host, Sources: map[string]struct{}{"wordlist": {}}, FirstSeenUnix: now})
		}
		report.Stats.BruteforceSeeded = len(bf)
		mergeCandidates(candidateMap, bf)
	}

	candidates := mapToCandidates(candidateMap)
	report.Stats.CandidateTotal = len(candidates)
	if len(candidates) == 0 {
		if len(report.Errors) > 0 {
			return report, fmt.Errorf("no candidates produced for domain %s (%d source error(s), first: %v)", opts.Domain, len(report.Errors), report.Errors[0])
		}
		return report, fmt.Errorf("no candidates produced for domain %s", opts.Domain)
	}

	fastResolver := dnsresolve.New(opts.Resolvers, opts.Timeout, opts.Retries)
	resolved, failed := dnsresolve.ResolveCandidates(ctx, candidates, fastResolver, opts.Threads)
	report.Stats.ResolvedFast = len(resolved)
	report.Stats.FailedFast = failed
	if len(resolved) == 0 {
		return report, nil
	}

	trustedResolver := dnsresolve.New(opts.TrustedResolvers, opts.Timeout, opts.Retries)
	wfilter := wildcard.New(opts.Domain, opts.WildcardTests, trustedResolver)
	clean, wildcardDropped := wfilter.Filter(ctx, resolved)
	report.Stats.WildcardDropped = wildcardDropped
	if len(clean) == 0 {
		return report, nil
	}

	validated, trustedDropped := dnsresolve.ValidateResults(ctx, clean, trustedResolver, opts.Threads)
	report.Stats.TrustedDropped = trustedDropped

	for i := range validated {
		validated[i].Domain = opts.Domain
	}
	sort.Slice(validated, func(i, j int) bool {
		if validated[i].SourceCount == validated[j].SourceCount {
			if validated[i].FirstSeen == validated[j].FirstSeen {
				return validated[i].Host < validated[j].Host
			}
			return validated[i].FirstSeen < validated[j].FirstSeen
		}
		return validated[i].SourceCount > validated[j].SourceCount
	})
	report.Results = validated
	report.Stats.FinalTotal = len(validated)

	return report, nil
}

func mergeCandidates(dst map[string]model.Candidate, items []model.Candidate) {
	for _, item := range items {
		existing, ok := dst[item.Host]
		if !ok {
			dst[item.Host] = item
			continue
		}
		if existing.Sources == nil {
			existing.Sources = map[string]struct{}{}
		}
		for src := range item.Sources {
			existing.Sources[src] = struct{}{}
		}
		if existing.FirstSeenUnix == 0 || (item.FirstSeenUnix > 0 && item.FirstSeenUnix < existing.FirstSeenUnix) {
			existing.FirstSeenUnix = item.FirstSeenUnix
		}
		dst[item.Host] = existing
	}
}

func mapToCandidates(m map[string]model.Candidate) []model.Candidate {
	out := make([]model.Candidate, 0, len(m))
	for _, candidate := range m {
		out = append(out, candidate)
	}
	return out
}

func readWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	words := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " /\\\t") {
			continue
		}
		words = append(words, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return util.UniqueSorted(words), nil
}
