package dnsresolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/hidden-investigations/subflare/internal/model"
)

type BackendConfig struct {
	Backend     string
	Threads     int
	MassDNSPath string
}

func ResolveCandidatesWithBackend(ctx context.Context, candidates []model.Candidate, resolver *Resolver, cfg BackendConfig) ([]model.Result, int, error) {
	backend := strings.TrimSpace(strings.ToLower(cfg.Backend))
	switch backend {
	case "", "standard":
		resolved, failed := ResolveCandidates(ctx, candidates, resolver, cfg.Threads)
		return resolved, failed, nil
	case "massdns":
		return resolveWithMassDNS(ctx, candidates, resolver, cfg)
	default:
		return nil, 0, fmt.Errorf("unknown dns backend: %s", cfg.Backend)
	}
}
