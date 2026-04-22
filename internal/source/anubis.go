package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Anubis struct {
	rt *runtimeClient
}

func NewAnubis(client *http.Client) *Anubis {
	return &Anubis{rt: newRuntimeClient("anubis", client)}
}

func (s *Anubis) Name() string {
	return "anubis"
}

func (s *Anubis) Enumerate(ctx context.Context, domain string) ([]string, error) {
	headers := map[string]string{"Accept": "application/json"}
	endpoints := []string{
		"https://jonlu.ca/anubis/subdomains/" + url.PathEscape(domain),
		"https://jldc.me/anubis/subdomains/" + url.PathEscape(domain),
		"https://anubisdb.com/subdomains/" + url.PathEscape(domain),
	}

	var lastErr error
	for idx, endpoint := range endpoints {
		body, status, err := s.rt.Get(ctx, endpoint, headers)
		if err != nil {
			if statusErr, ok := err.(*StatusError); ok {
				if statusErr.StatusCode == http.StatusNotFound {
					continue
				}
				if statusErr.StatusCode == http.StatusTooManyRequests {
					lastErr = err
					sleep := time.Duration(idx+1) * 500 * time.Millisecond
					timer := time.NewTimer(sleep)
					select {
					case <-ctx.Done():
						timer.Stop()
						return nil, ctx.Err()
					case <-timer.C:
					}
					continue
				}
			}
			lastErr = err
			continue
		}
		if status == http.StatusNotFound {
			continue
		}
		hosts, err := parseAnubisBody(body)
		if err != nil {
			lastErr = err
			continue
		}
		return normalizeAndFilterHosts(hosts, domain), nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no anubis endpoint returned data")
}

func parseAnubisBody(body []byte) ([]string, error) {
	var hosts []string
	if err := json.Unmarshal(body, &hosts); err != nil {
		var wrapped struct {
			Subdomains []string `json:"subdomains"`
			Data       []string `json:"data"`
		}
		if wrapErr := json.Unmarshal(body, &wrapped); wrapErr != nil {
			return nil, err
		}
		hosts = append(hosts, wrapped.Subdomains...)
		hosts = append(hosts, wrapped.Data...)
	}
	return hosts, nil
}
