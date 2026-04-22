package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type FOFA struct {
	rt *runtimeClient
}

func NewFOFA(client *http.Client) *FOFA {
	return &FOFA{rt: newRuntimeClient("fofa", client)}
}

func (s *FOFA) Name() string {
	return "fofa"
}

func (s *FOFA) Enumerate(ctx context.Context, domain string) ([]string, error) {
	email := s.rt.ProviderValue("FOFA_EMAIL", "fofa_email")
	key := s.rt.ProviderValue("FOFA_KEY", "fofa_key", "FOFA_API_KEY")
	if email == "" || key == "" {
		return nil, fmt.Errorf("missing FOFA_EMAIL or FOFA_KEY")
	}

	qbase64 := base64.StdEncoding.EncodeToString([]byte(`domain="` + domain + `"`))
	collected := []string{}
	seen := map[string]struct{}{}

	for page := 1; page <= 3; page++ {
		query := url.Values{}
		query.Set("email", email)
		query.Set("key", key)
		query.Set("qbase64", qbase64)
		query.Set("fields", "host")
		query.Set("page", fmt.Sprintf("%d", page))
		query.Set("size", "100")
		endpoint := "https://fofa.info/api/v1/search/all?" + query.Encode()
		body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
		if err != nil {
			if page == 1 {
				return nil, err
			}
			break
		}

		hosts, parseErr := parseFOFABody(body, domain)
		if parseErr != nil {
			if page == 1 {
				return nil, parseErr
			}
			break
		}
		if len(hosts) == 0 {
			break
		}
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			collected = append(collected, host)
		}
	}

	return normalizeAndFilterHosts(collected, domain), nil
}

func parseFOFABody(body []byte, domain string) ([]string, error) {
	var payload struct {
		Error   bool            `json:"error"`
		ErrMsg  string          `json:"errmsg"`
		Results [][]interface{} `json:"results"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Error {
		return nil, fmt.Errorf(strings.TrimSpace(payload.ErrMsg))
	}

	out := []string{}
	for _, row := range payload.Results {
		if len(row) == 0 {
			continue
		}
		value, ok := row[0].(string)
		if !ok {
			continue
		}
		out = append(out, extractHostsFromText(value, domain)...)
	}
	return out, nil
}
