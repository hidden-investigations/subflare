package dnsresolve

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

func ExpandByReverseDNS(ctx context.Context, resolved []model.Result, resolver *Resolver, domain string, limit int) []model.Candidate {
	if limit < 1 {
		limit = 1
	}
	ipSet := map[string]struct{}{}
	existing := map[string]struct{}{}
	for _, item := range resolved {
		existing[item.Host] = struct{}{}
		for _, ip := range item.IPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ipSet[ip] = struct{}{}
			}
		}
	}
	if len(ipSet) == 0 {
		return nil
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	type ptrResult struct {
		hosts []string
	}
	jobs := make(chan string)
	out := make(chan ptrResult, len(ips))
	workers := 32
	if workers > len(ips) {
		workers = len(ips)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				hosts, err := resolver.QueryPTR(ctx, ip)
				if err != nil {
					continue
				}
				out <- ptrResult{hosts: hosts}
			}
		}()
	}
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	now := time.Now().UTC().Unix()
	candidates := []model.Candidate{}
	added := map[string]struct{}{}
	for result := range out {
		for _, host := range result.hosts {
			host = util.NormalizeHost(host)
			if !util.IsSubdomainOf(host, domain) {
				continue
			}
			if _, ok := existing[host]; ok {
				continue
			}
			if _, ok := added[host]; ok {
				continue
			}
			added[host] = struct{}{}
			candidates = append(candidates, model.Candidate{
				Host:          host,
				Sources:       map[string]struct{}{"rdns": {}},
				FirstSeenUnix: now,
			})
			if len(candidates) >= limit {
				return candidates
			}
		}
	}

	return candidates
}
