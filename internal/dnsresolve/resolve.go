package dnsresolve

import (
	"context"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/model"
)

func ResolveCandidates(ctx context.Context, candidates []model.Candidate, resolver *Resolver, threads int) ([]model.Result, int) {
	if threads < 1 {
		threads = 1
	}

	type workerOut struct {
		result model.Result
		ok     bool
	}

	jobs := make(chan model.Candidate)
	out := make(chan workerOut, len(candidates))
	wg := sync.WaitGroup{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				ips, cnames, err := resolver.QueryA(ctx, candidate.Host)
				if err != nil {
					out <- workerOut{ok: false}
					continue
				}
				out <- workerOut{
					ok: true,
					result: model.Result{
						Host:             candidate.Host,
						Sources:          model.SortedSources(candidate.Sources),
						SourceCount:      len(candidate.Sources),
						DuplicatesMerged: maxInt(len(candidate.Sources)-1, 0),
						Confidence:       confidenceFromSources(len(candidate.Sources)),
						FirstSeen:        time.Unix(candidate.FirstSeenUnix, 0).UTC().Format(time.RFC3339),
						IPs:              ips,
						CNAMEs:           cnames,
					},
				}
			}
		}()
	}

	go func() {
		for _, candidate := range candidates {
			jobs <- candidate
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	resolved := make([]model.Result, 0, len(candidates))
	failed := 0
	for result := range out {
		if !result.ok {
			failed++
			continue
		}
		resolved = append(resolved, result.result)
	}

	return resolved, failed
}

func ValidateResults(ctx context.Context, results []model.Result, resolver *Resolver, threads int) ([]model.Result, int) {
	if threads < 1 {
		threads = 1
	}
	type workerOut struct {
		result model.Result
		ok     bool
	}

	jobs := make(chan model.Result)
	out := make(chan workerOut, len(results))
	wg := sync.WaitGroup{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for record := range jobs {
				ips, cnames, err := resolver.QueryA(ctx, record.Host)
				if err != nil {
					out <- workerOut{ok: false}
					continue
				}
				record.IPs = ips
				record.CNAMEs = cnames
				record.Validated = true
				out <- workerOut{ok: true, result: record}
			}
		}()
	}

	go func() {
		for _, item := range results {
			jobs <- item
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	validated := make([]model.Result, 0, len(results))
	dropped := 0
	for result := range out {
		if !result.ok {
			dropped++
			continue
		}
		validated = append(validated, result.result)
	}

	return validated, dropped
}

func confidenceFromSources(sourceCount int) float64 {
	if sourceCount <= 0 {
		return 0
	}
	return 50 + float64(sourceCount*10)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
