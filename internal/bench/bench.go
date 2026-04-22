package bench

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/hidden-investigations/subflare/internal/dnsresolve"
	"github.com/hidden-investigations/subflare/internal/options"
	"github.com/hidden-investigations/subflare/internal/provider"
	"github.com/hidden-investigations/subflare/internal/source"
)

type Result struct {
	Domain            string
	SourceCounts      map[string]int
	SourceCacheHits   map[string]int
	PassiveDuration   time.Duration
	PassiveCandidates int
	ResolveDuration   time.Duration
	Resolved          int
	ResolveFailed     int
}

func Run(ctx context.Context, opts options.Options) (Result, error) {
	result := Result{Domain: opts.Domain, SourceCounts: map[string]int{}, SourceCacheHits: map[string]int{}}

	providers, err := provider.Load(opts.ProviderConfig)
	if err != nil {
		return result, fmt.Errorf("load provider config: %w", err)
	}

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
		return result, fmt.Errorf("configure passive sources: %w", err)
	}

	passiveStart := time.Now()
	collected := source.Collect(ctx, opts.Domain, sources, source.CollectOptions{
		Retries:        opts.SourceRetries,
		Backoff:        opts.SourceBackoff,
		Timeout:        opts.SourceTimeout,
		SourceTimeouts: opts.SourceTimeouts,
		CacheDir:       opts.CacheDir,
		CacheTTL:       opts.CacheTTL,
		NoCache:        opts.NoCache,
	})
	result.PassiveDuration = time.Since(passiveStart)
	result.PassiveCandidates = len(collected.Candidates)
	result.SourceCounts = collected.Counts
	result.SourceCacheHits = collected.CacheHits

	resolver := dnsresolve.New(opts.Resolvers, opts.Timeout, opts.Retries)
	resolveStart := time.Now()
	resolved, failed := dnsresolve.ResolveCandidates(ctx, collected.Candidates, resolver, opts.Threads)
	result.ResolveDuration = time.Since(resolveStart)
	result.Resolved = len(resolved)
	result.ResolveFailed = failed

	return result, nil
}

func Render(result Result) string {
	lines := []string{}
	lines = append(lines, "[BENCH] domain: "+result.Domain)
	lines = append(lines, fmt.Sprintf("[BENCH] passive candidates: %d", result.PassiveCandidates))
	lines = append(lines, fmt.Sprintf("[BENCH] passive duration: %s", result.PassiveDuration))
	lines = append(lines, fmt.Sprintf("[BENCH] passive throughput: %.2f candidates/sec", perSecond(result.PassiveCandidates, result.PassiveDuration)))
	lines = append(lines, fmt.Sprintf("[BENCH] resolver duration: %s", result.ResolveDuration))
	lines = append(lines, fmt.Sprintf("[BENCH] resolved: %d, failed: %d", result.Resolved, result.ResolveFailed))
	lines = append(lines, fmt.Sprintf("[BENCH] resolver throughput: %.2f candidates/sec", perSecond(result.Resolved+result.ResolveFailed, result.ResolveDuration)))

	names := make([]string, 0, len(result.SourceCounts))
	for name := range result.SourceCounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		count := result.SourceCounts[name]
		cacheHit := result.SourceCacheHits[name]
		yieldPerMinute := perMinute(count, result.PassiveDuration)
		lines = append(lines, fmt.Sprintf("[BENCH] source=%s count=%d yield/min=%.2f cache_hits=%d", name, count, yieldPerMinute, cacheHit))
	}

	return joinLines(lines)
}

func perSecond(n int, d time.Duration) float64 {
	if n <= 0 || d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds()
}

func perMinute(n int, d time.Duration) float64 {
	if n <= 0 || d <= 0 {
		return 0
	}
	return float64(n) / d.Minutes()
}

func joinLines(lines []string) string {
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n"
		}
		out += line
	}
	return out
}
