package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type CRTSh struct {
	rt *runtimeClient
}

func NewCRTSh(client *http.Client) *CRTSh {
	return &CRTSh{rt: newRuntimeClient("crtsh", client)}
}

func (s *CRTSh) Name() string {
	return "crtsh"
}

func (s *CRTSh) Enumerate(ctx context.Context, domain string) ([]string, error) {
	endpoint := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+domain))
	body, _, err := s.rt.Get(ctx, endpoint, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	hosts, err := parseCRTShBody(body)
	if err != nil {
		return nil, err
	}
	return normalizeAndFilterHosts(hosts, domain), nil
}

func parseCRTShBody(body []byte) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts := strings.Split(row.NameValue, "\n")
		hosts = append(hosts, parts...)
	}
	return hosts, nil
}
