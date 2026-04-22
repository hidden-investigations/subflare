package source

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type Digitorus struct {
	rt *runtimeClient
}

func NewDigitorus(client *http.Client) *Digitorus {
	return &Digitorus{rt: newRuntimeClient("digitorus", client)}
}

func (s *Digitorus) Name() string {
	return "digitorus"
}

func (s *Digitorus) Enumerate(ctx context.Context, domain string) ([]string, error) {
	endpoints := []string{
		"https://certificatedetails.com/" + url.PathEscape(domain),
		"https://certificatedetails.com/" + url.PathEscape("*."+domain),
	}

	var lastErr error
	for _, endpoint := range endpoints {
		body, _, err := s.rt.Get(ctx, endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		hosts := normalizeAndFilterHosts(extractHostsFromText(string(body), domain), domain)
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no digitorus records found")
}
