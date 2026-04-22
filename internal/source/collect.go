package source

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/cache"
	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

type CollectOptions struct {
	Retries        int
	Backoff        time.Duration
	Timeout        time.Duration
	SourceTimeouts map[string]time.Duration
	CacheDir       string
	CacheTTL       time.Duration
	NoCache        bool
}

type CollectReport struct {
	Candidates []model.Candidate
	Errors     []error
	Counts     map[string]int
	CacheHits  map[string]int
	SourceErrs map[string]error
}

func Collect(ctx context.Context, domain string, sources []Source, opts CollectOptions) CollectReport {
	if opts.Retries < 1 {
		opts.Retries = 1
	}
	if opts.Backoff <= 0 {
		opts.Backoff = 300 * time.Millisecond
	}

	results := make(chan sourceResult, len(sources))
	wg := sync.WaitGroup{}

	for _, src := range sources {
		s := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			hosts, fromCache, err := collectSource(ctx, s, domain, opts)
			results <- sourceResult{name: s.Name(), hosts: hosts, err: err, fromCache: fromCache, collectedAt: time.Now().UTC().Unix()}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	merged := make(map[string]model.Candidate)
	errs := []error{}
	counts := make(map[string]int)
	cacheHits := make(map[string]int)
	sourceErrs := make(map[string]error)

	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", result.name, result.err))
			sourceErrs[result.name] = result.err
			continue
		}
		for _, raw := range result.hosts {
			host := util.NormalizeHost(raw)
			if !util.IsSubdomainOf(host, domain) {
				continue
			}
			candidate, ok := merged[host]
			if !ok {
				candidate = model.Candidate{
					Host:          host,
					Sources:       map[string]struct{}{},
					FirstSeenUnix: result.collectedAt,
				}
			}
			candidate.Sources[result.name] = struct{}{}
			if candidate.FirstSeenUnix == 0 || result.collectedAt < candidate.FirstSeenUnix {
				candidate.FirstSeenUnix = result.collectedAt
			}
			merged[host] = candidate
		}
		counts[result.name] = len(result.hosts)
		if result.fromCache {
			cacheHits[result.name]++
		}
	}

	candidates := make([]model.Candidate, 0, len(merged))
	for _, candidate := range merged {
		candidates = append(candidates, candidate)
	}

	return CollectReport{
		Candidates: candidates,
		Errors:     errs,
		Counts:     counts,
		CacheHits:  cacheHits,
		SourceErrs: sourceErrs,
	}
}

func collectSource(ctx context.Context, src Source, domain string, opts CollectOptions) ([]string, bool, error) {
	if !opts.NoCache {
		if hosts, hit, err := cache.Load(opts.CacheDir, src.Name(), domain, opts.CacheTTL); err == nil && hit {
			return hosts, true, nil
		}
	}

	hosts, err := runSourceWithRetry(ctx, src, domain, opts)
	if err != nil {
		return nil, false, err
	}
	if !opts.NoCache {
		_ = cache.Save(opts.CacheDir, src.Name(), domain, hosts)
	}
	return hosts, false, nil
}

func runSourceWithRetry(ctx context.Context, src Source, domain string, opts CollectOptions) ([]string, error) {
	attempts := opts.Retries
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		sourceCtx := ctx
		cancel := func() {}
		timeout := opts.Timeout
		if sourceTimeout, ok := opts.SourceTimeouts[src.Name()]; ok && sourceTimeout > 0 {
			timeout = sourceTimeout
		}
		if timeout > 0 {
			sourceCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		hosts, err := src.Enumerate(sourceCtx, domain)
		cancel()
		if err == nil {
			return hosts, nil
		}
		lastErr = err
		if attempt >= attempts {
			break
		}
		delay := opts.Backoff * time.Duration(1<<(attempt-1))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("source failed")
	}
	return nil, lastErr
}

type sourceResult struct {
	name        string
	hosts       []string
	err         error
	fromCache   bool
	collectedAt int64
}
