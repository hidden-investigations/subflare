package takeover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultFingerprintURL = "https://raw.githubusercontent.com/hidden-investigations/subflare/main/data/takeover-fingerprints.json"
)

var defaultFingerprints = []fingerprint{
	{
		Provider:    "github-pages",
		Suffixes:    []string{".github.io"},
		Indicators:  []string{"there isn't a github pages site here"},
		StatusCodes: []int{404},
	},
	{
		Provider:   "heroku",
		Suffixes:   []string{".herokudns.com", ".herokussl.com", ".herokuapp.com"},
		Indicators: []string{"no such app", "there is no app configured at that hostname"},
		StatusCodes: []int{
			404,
		},
	},
	{
		Provider:    "readthedocs",
		Suffixes:    []string{".readthedocs.io"},
		Indicators:  []string{"unknown domain"},
		StatusCodes: []int{404},
	},
	{
		Provider:    "pantheon",
		Suffixes:    []string{".pantheonsite.io"},
		Indicators:  []string{"the gods are wise, but do not know of the domain", "404 error unknown site!"},
		StatusCodes: []int{404},
	},
	{
		Provider:   "aws-s3",
		Suffixes:   []string{".s3.amazonaws.com", ".s3-website-us-east-1.amazonaws.com", ".s3-website-us-west-2.amazonaws.com", ".s3-website.eu-west-1.amazonaws.com", ".s3-website.ap-south-1.amazonaws.com"},
		Indicators: []string{"nosuchbucket", "the specified bucket does not exist"},
		StatusCodes: []int{
			404,
		},
	},
	{
		Provider:    "azure-app-service",
		Suffixes:    []string{".azurewebsites.net"},
		Indicators:  []string{"404 web site not found", "web site not found"},
		StatusCodes: []int{404},
	},
	{
		Provider:    "vercel",
		Suffixes:    []string{".vercel.app"},
		Indicators:  []string{"deployment_not_found", "the deployment could not be found", "no such deployment"},
		StatusCodes: []int{404},
	},
	{
		Provider:    "surge",
		Suffixes:    []string{".surge.sh"},
		Indicators:  []string{"project not found"},
		StatusCodes: []int{404},
	},
}

var (
	fingerprintMu      sync.RWMutex
	activeFingerprints = cloneFingerprints(defaultFingerprints)
)

func fingerprintStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "takeover-fingerprints.json")
	}
	return filepath.Join(home, ".config", "subflare", "takeover-fingerprints.json")
}

func fingerprintSnapshot() []fingerprint {
	fingerprintMu.RLock()
	defer fingerprintMu.RUnlock()
	return cloneFingerprints(activeFingerprints)
}

func setActiveFingerprints(items []fingerprint) {
	if len(items) == 0 {
		items = cloneFingerprints(defaultFingerprints)
	}
	fingerprintMu.Lock()
	activeFingerprints = cloneFingerprints(items)
	fingerprintMu.Unlock()
}

func FingerprintCount() int {
	fingerprintMu.RLock()
	defer fingerprintMu.RUnlock()
	return len(activeFingerprints)
}

func ConfigureFingerprintsFromDisk() error {
	custom, err := readFingerprintFile(fingerprintStorePath())
	if err != nil {
		setActiveFingerprints(defaultFingerprints)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	setActiveFingerprints(mergeFingerprints(defaultFingerprints, custom))
	return nil
}

func UpdateFingerprints(ctx context.Context) (string, int, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultFingerprintURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Subflare/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", 0, fmt.Errorf("fingerprint update failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", 0, err
	}
	custom, err := decodeFingerprints(body)
	if err != nil {
		return "", 0, err
	}
	if len(custom) == 0 {
		return "", 0, fmt.Errorf("fingerprint update returned empty rules")
	}

	path := fingerprintStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	if err := writeFingerprintFile(path, custom); err != nil {
		return "", 0, err
	}

	merged := mergeFingerprints(defaultFingerprints, custom)
	setActiveFingerprints(merged)
	return path, len(custom), nil
}

func mergeFingerprints(base, extra []fingerprint) []fingerprint {
	out := make([]fingerprint, 0, len(base)+len(extra))
	seen := map[string]int{}
	appendList := func(list []fingerprint) {
		for _, fp := range list {
			normalized, ok := normalizeFingerprint(fp)
			if !ok {
				continue
			}
			key := fingerprintKey(normalized)
			if idx, exists := seen[key]; exists {
				out[idx] = normalized
				continue
			}
			seen[key] = len(out)
			out = append(out, normalized)
		}
	}
	appendList(base)
	appendList(extra)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return fingerprintKey(out[i]) < fingerprintKey(out[j])
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func normalizeFingerprint(fp fingerprint) (fingerprint, bool) {
	fp.Provider = strings.TrimSpace(strings.ToLower(fp.Provider))
	if fp.Provider == "" {
		return fingerprint{}, false
	}
	suffixes := make([]string, 0, len(fp.Suffixes))
	suffixSeen := map[string]struct{}{}
	for _, suffix := range fp.Suffixes {
		suffix = strings.TrimSpace(strings.ToLower(suffix))
		if suffix == "" {
			continue
		}
		if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if _, ok := suffixSeen[suffix]; ok {
			continue
		}
		suffixSeen[suffix] = struct{}{}
		suffixes = append(suffixes, suffix)
	}
	if len(suffixes) == 0 {
		return fingerprint{}, false
	}
	sort.Strings(suffixes)
	fp.Suffixes = suffixes

	fp.Indicators = normalizeIndicators(fp.Indicators)
	fp.ExcludeIndicators = normalizeIndicators(fp.ExcludeIndicators)
	fp.StatusCodes = uniqueStatusCodes(fp.StatusCodes)
	return fp, true
}

func normalizeIndicators(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func fingerprintKey(fp fingerprint) string {
	return fp.Provider + "|" + strings.Join(fp.Suffixes, ",")
}

func cloneFingerprints(in []fingerprint) []fingerprint {
	out := make([]fingerprint, 0, len(in))
	for _, item := range in {
		cloned := item
		cloned.Suffixes = append([]string{}, item.Suffixes...)
		cloned.Indicators = append([]string{}, item.Indicators...)
		cloned.ExcludeIndicators = append([]string{}, item.ExcludeIndicators...)
		cloned.StatusCodes = append([]int{}, item.StatusCodes...)
		out = append(out, cloned)
	}
	return out
}

func decodeFingerprints(content []byte) ([]fingerprint, error) {
	var rows []fingerprint
	if err := json.Unmarshal(content, &rows); err != nil {
		return nil, fmt.Errorf("decode fingerprints: %w", err)
	}
	out := mergeFingerprints(nil, rows)
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid fingerprints in payload")
	}
	return out, nil
}

func readFingerprintFile(path string) ([]fingerprint, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeFingerprints(content)
}

func writeFingerprintFile(path string, rows []fingerprint) error {
	tmpPath := path + ".tmp"
	encoded, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(tmpPath, encoded, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
