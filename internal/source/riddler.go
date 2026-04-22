package source

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Riddler struct {
	rt *runtimeClient
}

func NewRiddler(client *http.Client) *Riddler {
	return &Riddler{rt: newRuntimeClient("riddler", client)}
}

func (s *Riddler) Name() string {
	return "riddler"
}

func (s *Riddler) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{}
	query.Set("q", "pld:"+domain)
	endpoint := "https://riddler.io/search/exportcsv?" + query.Encode()

	body, _, err := s.rt.Get(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}

	hosts := parseRiddlerCSV(body, domain)
	if len(hosts) == 0 {
		hosts = extractHostsFromText(string(body), domain)
	}
	hosts = normalizeAndFilterHosts(hosts, domain)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no riddler records found")
	}
	return hosts, nil
}

func parseRiddlerCSV(body []byte, domain string) []string {
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil
	}

	out := []string{}
	for _, row := range rows {
		for _, field := range row {
			value := strings.TrimSpace(field)
			if value == "" || strings.EqualFold(value, "host") {
				continue
			}
			if strings.Contains(strings.ToLower(value), strings.ToLower(domain)) {
				out = append(out, value)
			}
		}
	}
	return out
}
