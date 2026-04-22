package workflow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

func HostsFromResults(results []model.Result) []string {
	hosts := make([]string, 0, len(results))
	for _, result := range results {
		host := util.NormalizeHost(result.Host)
		if host == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	return uniqueSorted(hosts)
}

func ReadHostsFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hosts := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "{") && strings.Contains(line, "\"host\"") {
			var row struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				return nil, fmt.Errorf("invalid JSONL row in %s: %w", path, err)
			}
			if row.Host != "" {
				hosts = append(hosts, row.Host)
			}
			continue
		}
		hosts = append(hosts, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return uniqueSorted(hosts), nil
}

func uniqueSorted(input []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range input {
		item = util.NormalizeHost(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
