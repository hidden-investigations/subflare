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
	"github.com/hidden-investigations/subflare/internal/enum"
	"github.com/hidden-investigations/subflare/internal/httpprobe"
	"github.com/hidden-investigations/subflare/internal/infra"
	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/options"
	"github.com/hidden-investigations/subflare/internal/provider"
	"github.com/hidden-investigations/subflare/internal/source"
	"github.com/hidden-investigations/subflare/internal/takeover"
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
	PermutationSeeded int
	CandidateTotal    int
	DNSBackend        string
	ResolvedFast      int
	FailedFast        int
	RDNSSeeded        int
	RDNSResolved      int
	WildcardDropped   int
	TrustedDropped    int
	AutoTuneEnabled   bool
	InfraEnabled      bool
	InfraEnriched     int
	HTTPProbeEnabled  bool
	HTTPProbed        int
	TakeoverEnabled   bool
	TakeoverChecked   int
	TakeoverSignals   int
	FinalTotal        int
}

func Run(ctx context.Context, opts options.Options) (Report, error) {
	report := Report{}
	report.Stats.SourceCounts = map[string]int{}
	report.Stats.SourceCacheHits = map[string]int{}
	report.Stats.SourceErrors = map[string]string{}
	report.Stats.AutoTuneEnabled = opts.AutoTune
	report.Stats.InfraEnabled = opts.EnrichInfra
	report.Stats.HTTPProbeEnabled = opts.HTTPProbe
	report.Stats.TakeoverEnabled = opts.TakeoverCheck
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
		bf := generateBruteforceCandidates(words, opts.Domain, opts.BruteforceDepth, opts.BruteforceMax, time.Now().UTC().Unix())
		report.Stats.BruteforceSeeded = len(bf)
		mergeCandidates(candidateMap, bf)
	}

	if opts.Permutation {
		baseHosts := make([]string, 0, len(candidateMap))
		for host := range candidateMap {
			baseHosts = append(baseHosts, host)
		}
		permutedHosts := enum.GeneratePermutations(opts.Domain, baseHosts, opts.PermutationDepth, opts.PermutationMax)
		if len(permutedHosts) > 0 {
			now := time.Now().UTC().Unix()
			permuted := make([]model.Candidate, 0, len(permutedHosts))
			for _, host := range permutedHosts {
				permuted = append(permuted, model.Candidate{
					Host:          host,
					Sources:       map[string]struct{}{"permutation": {}},
					FirstSeenUnix: now,
				})
			}
			report.Stats.PermutationSeeded = len(permuted)
			mergeCandidates(candidateMap, permuted)
		}
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
	report.Stats.DNSBackend = opts.DNSBackend
	resolveThreads := opts.Threads
	if opts.AutoTune {
		resolveThreads = tuneConcurrencyByVolume(opts.Threads, len(candidates))
	}
	resolved, failed, resolveErr := dnsresolve.ResolveCandidatesWithBackend(ctx, candidates, fastResolver, dnsresolve.BackendConfig{
		Backend:     opts.DNSBackend,
		Threads:     resolveThreads,
		MassDNSPath: opts.MassDNSPath,
	})
	if resolveErr != nil {
		return report, fmt.Errorf("resolve with backend %s: %w", opts.DNSBackend, resolveErr)
	}
	report.Stats.ResolvedFast = len(resolved)
	report.Stats.FailedFast = failed
	if len(resolved) == 0 {
		return report, nil
	}

	if opts.RDNSExpand {
		expanded := dnsresolve.ExpandByReverseDNS(ctx, resolved, fastResolver, opts.Domain, opts.RDNSLimit)
		report.Stats.RDNSSeeded = len(expanded)
		if len(expanded) > 0 {
			rdnsResolved, _, rdnsErr := dnsresolve.ResolveCandidatesWithBackend(ctx, expanded, fastResolver, dnsresolve.BackendConfig{
				Backend:     opts.DNSBackend,
				Threads:     resolveThreads,
				MassDNSPath: opts.MassDNSPath,
			})
			if rdnsErr == nil && len(rdnsResolved) > 0 {
				report.Stats.RDNSResolved = len(rdnsResolved)
				resolved = mergeResolvedResults(resolved, rdnsResolved)
			}
		}
	}

	trustedResolver := dnsresolve.New(opts.TrustedResolvers, opts.Timeout, opts.Retries)
	wfilter := wildcard.New(opts.Domain, opts.WildcardTests, trustedResolver)
	clean, wildcardDropped := wfilter.Filter(ctx, resolved)
	report.Stats.WildcardDropped = wildcardDropped
	if len(clean) == 0 {
		return report, nil
	}

	validateThreads := opts.Threads
	if opts.AutoTune {
		validateThreads = tuneConcurrencyByFailureRate(opts.Threads, report.Stats.FailedFast, report.Stats.ResolvedFast+report.Stats.FailedFast)
	}
	validated, trustedDropped := dnsresolve.ValidateResults(ctx, clean, trustedResolver, validateThreads)
	report.Stats.TrustedDropped = trustedDropped

	if opts.HTTPProbe {
		probeThreads := opts.HTTPProbeThreads
		if opts.AutoTune {
			probeThreads = tuneConcurrencyByFailureRate(opts.HTTPProbeThreads, trustedDropped, len(clean))
		}
		validated, report.Stats.HTTPProbed = httpprobe.ProbeResults(ctx, validated, probeThreads, opts.HTTPProbeTimeout)
	}
	if opts.TakeoverCheck {
		takeoverThreads := opts.TakeoverThreads
		if opts.AutoTune {
			takeoverThreads = tuneConcurrencyByFailureRate(opts.TakeoverThreads, trustedDropped, len(clean))
		}
		validated, report.Stats.TakeoverChecked, report.Stats.TakeoverSignals = takeover.CheckResults(ctx, validated, trustedResolver, opts.TakeoverTimeout, takeoverThreads)
	}
	if opts.EnrichInfra {
		enrichThreads := validateThreads
		if enrichThreads < 8 {
			enrichThreads = 8
		}
		validated, report.Stats.InfraEnriched = infra.EnrichResults(ctx, validated, opts.TrustedResolvers, opts.Timeout, enrichThreads)
	}

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

func tuneConcurrencyByFailureRate(base, failed, total int) int {
	if base < 1 {
		base = 1
	}
	if total < 1 {
		return base
	}
	failureRate := float64(failed) / float64(total)
	switch {
	case failureRate >= 0.70:
		return maxInt(base/3, 8)
	case failureRate >= 0.50:
		return maxInt(base/2, 12)
	case failureRate >= 0.30:
		return maxInt((base*7)/10, 16)
	case failureRate <= 0.05 && total >= 200:
		return minInt((base*12)/10, base+64)
	case failureRate <= 0.15 && total >= 100:
		return minInt((base*11)/10, base+32)
	default:
		return base
	}
}

func tuneConcurrencyByVolume(base, total int) int {
	if base < 1 {
		base = 1
	}
	if total <= 0 {
		return base
	}
	if total < base/2 {
		return minInt(base, maxInt(total, 16))
	}
	if total > 5000 {
		return minInt(base+64, 512)
	}
	if total > 2000 {
		return minInt(base+32, 400)
	}
	return base
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func generateBruteforceCandidates(words []string, domain string, depth, max int, now int64) []model.Candidate {
	if depth < 1 {
		depth = 1
	}
	if max < 1 {
		max = 1
	}

	limitWords := util.UniqueSorted(words)
	if len(limitWords) > 3000 {
		limitWords = limitWords[:3000]
	}

	hosts := map[string]struct{}{}
	current := make([]string, 0, len(limitWords))
	for _, word := range limitWords {
		word = strings.TrimSpace(strings.ToLower(word))
		if word == "" {
			continue
		}
		current = append(current, word)
	}

	appendHost := func(label string) bool {
		host := util.NormalizeHost(label + "." + domain)
		if !util.IsSubdomainOf(host, domain) {
			return false
		}
		hosts[host] = struct{}{}
		return len(hosts) >= max
	}

	for _, label := range current {
		if appendHost(label) {
			return candidatesFromHosts(hosts, "wordlist", now)
		}
	}

	if depth > 1 {
		level := current
		for d := 2; d <= depth; d++ {
			next := []string{}
			for _, prefix := range level {
				for _, word := range current {
					compound := prefix + "." + word
					next = append(next, compound)
					if appendHost(compound) {
						return candidatesFromHosts(hosts, "wordlist", now)
					}
				}
			}
			if len(next) == 0 {
				break
			}
			if len(next) > 10000 {
				next = next[:10000]
			}
			level = util.UniqueSorted(next)
		}
	}

	return candidatesFromHosts(hosts, "wordlist", now)
}

func candidatesFromHosts(hostSet map[string]struct{}, sourceName string, now int64) []model.Candidate {
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	hosts = util.UniqueSorted(hosts)
	out := make([]model.Candidate, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, model.Candidate{
			Host:          host,
			Sources:       map[string]struct{}{sourceName: {}},
			FirstSeenUnix: now,
		})
	}
	return out
}

func mergeResolvedResults(base, extra []model.Result) []model.Result {
	merged := make(map[string]model.Result, len(base)+len(extra))
	for _, item := range base {
		merged[item.Host] = item
	}
	for _, item := range extra {
		existing, ok := merged[item.Host]
		if !ok {
			merged[item.Host] = item
			continue
		}
		srcSet := map[string]struct{}{}
		for _, src := range existing.Sources {
			srcSet[src] = struct{}{}
		}
		for _, src := range item.Sources {
			srcSet[src] = struct{}{}
		}
		existing.Sources = model.SortedSources(srcSet)
		existing.SourceCount = len(srcSet)
		existing.DuplicatesMerged = maxInt(existing.SourceCount-1, 0)
		existing.IPs = util.UniqueSorted(append(existing.IPs, item.IPs...))
		existing.CNAMEs = util.UniqueSorted(append(existing.CNAMEs, item.CNAMEs...))
		merged[item.Host] = existing
	}

	out := make([]model.Result, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
