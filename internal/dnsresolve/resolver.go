package dnsresolve

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/util"
	"github.com/miekg/dns"
)

// Resolver performs DNS A/CNAME lookups against a resolver pool.
type Resolver struct {
	servers []string
	timeout time.Duration
	retries int

	mu     sync.Mutex
	rng    *rand.Rand
	health map[string]*resolverHealth
}

type resolverHealth struct {
	Success         int
	Failure         int
	ConsecutiveFail int
	Disabled        bool
}

func New(servers []string, timeout time.Duration, retries int) *Resolver {
	health := make(map[string]*resolverHealth, len(servers))
	for _, server := range servers {
		health[server] = &resolverHealth{}
	}
	return &Resolver{
		servers: servers,
		timeout: timeout,
		retries: retries,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		health:  health,
	}
}

func (r *Resolver) QueryA(ctx context.Context, host string) ([]string, []string, error) {
	if len(r.servers) == 0 {
		return nil, nil, errors.New("no resolvers configured")
	}

	var lastErr error
	for attempt := 0; attempt < r.retries; attempt++ {
		server := r.pickResolver()
		queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
		ips, cnames, err := r.queryOnce(queryCtx, host, server)
		cancel()
		if err == nil {
			r.markSuccess(server)
			return util.UniqueSorted(ips), util.UniqueSorted(cnames), nil
		}
		r.markFailure(server)
		lastErr = err

		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}

	if lastErr == nil {
		lastErr = errors.New("lookup failed")
	}
	return nil, nil, lastErr
}

func (r *Resolver) queryOnce(ctx context.Context, host, server string) ([]string, []string, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(host), dns.TypeA)

	udpClient := &dns.Client{Net: "udp"}
	response, _, err := udpClient.ExchangeContext(ctx, message, server)
	if err != nil {
		return nil, nil, err
	}
	if response == nil {
		return nil, nil, errors.New("empty dns response")
	}

	if response.Truncated {
		tcpClient := &dns.Client{Net: "tcp"}
		response, _, err = tcpClient.ExchangeContext(ctx, message, server)
		if err != nil {
			return nil, nil, err
		}
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("dns rcode=%s", dns.RcodeToString[response.Rcode])
	}

	ips := []string{}
	cnames := []string{}
	for _, answer := range response.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.CNAME:
			target := strings.TrimSuffix(strings.ToLower(rr.Target), ".")
			if target != "" {
				cnames = append(cnames, target)
			}
		}
	}

	if len(ips) == 0 && len(cnames) == 0 {
		return nil, nil, errors.New("no a/cname answers")
	}
	return ips, cnames, nil
}

func (r *Resolver) pickResolver() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	type candidate struct {
		server string
		score  float64
	}
	candidates := []candidate{}

	for _, server := range r.servers {
		h := r.health[server]
		if h == nil {
			h = &resolverHealth{}
			r.health[server] = h
		}
		if h.Disabled {
			continue
		}
		score := (float64(h.Success) + 1) / (float64(h.Failure) + 1)
		score -= float64(h.ConsecutiveFail) * 0.08
		if score < 0.01 {
			score = 0.01
		}
		candidates = append(candidates, candidate{server: server, score: score})
	}

	if len(candidates) == 0 {
		for _, server := range r.servers {
			h := r.health[server]
			h.Disabled = false
			h.ConsecutiveFail = 0
			candidates = append(candidates, candidate{server: server, score: 1})
		}
	}

	maxScore := candidates[0].score
	for _, c := range candidates[1:] {
		if c.score > maxScore {
			maxScore = c.score
		}
	}
	best := []candidate{}
	for _, c := range candidates {
		if math.Abs(c.score-maxScore) < 0.20 {
			best = append(best, c)
		}
	}
	choice := best[r.rng.Intn(len(best))]
	return choice.server
}

func (r *Resolver) markSuccess(server string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.health[server]
	if h == nil {
		h = &resolverHealth{}
		r.health[server] = h
	}
	h.Success++
	h.ConsecutiveFail = 0
	h.Disabled = false
}

func (r *Resolver) markFailure(server string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.health[server]
	if h == nil {
		h = &resolverHealth{}
		r.health[server] = h
	}
	h.Failure++
	h.ConsecutiveFail++
	if h.ConsecutiveFail >= 8 && h.Success == 0 {
		h.Disabled = true
	}
	if h.Failure >= 20 && h.Success*5 < h.Failure {
		h.Disabled = true
	}
}
