package model

import "sort"

// Candidate is a discovered host before DNS validation.
type Candidate struct {
	Host          string
	Sources       map[string]struct{}
	FirstSeenUnix int64
}

// Result is a validated subdomain output record.
type Result struct {
	Host              string   `json:"host"`
	Domain            string   `json:"domain"`
	Sources           []string `json:"sources"`
	SourceCount       int      `json:"source_count"`
	DuplicatesMerged  int      `json:"duplicates_merged"`
	Confidence        float64  `json:"confidence"`
	FirstSeen         string   `json:"first_seen"`
	IPs               []string `json:"a,omitempty"`
	CNAMEs            []string `json:"cname,omitempty"`
	HTTPURL           string   `json:"http_url,omitempty"`
	HTTPStatus        int      `json:"http_status,omitempty"`
	HTTPTitle         string   `json:"http_title,omitempty"`
	HTTPTech          []string `json:"http_tech,omitempty"`
	TakeoverPotential bool     `json:"takeover_potential,omitempty"`
	TakeoverProvider  string   `json:"takeover_provider,omitempty"`
	TakeoverReason    string   `json:"takeover_reason,omitempty"`
	Validated         bool     `json:"validated"`
}

func SortedSources(src map[string]struct{}) []string {
	out := make([]string, 0, len(src))
	for source := range src {
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}
