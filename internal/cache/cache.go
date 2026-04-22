package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	Source    string    `json:"source"`
	Domain    string    `json:"domain"`
	FetchedAt time.Time `json:"fetched_at"`
	Hosts     []string  `json:"hosts"`
}

func ResolveDir(dir string) string {
	trimmed := strings.TrimSpace(dir)
	if trimmed != "" {
		return trimmed
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".subflare-cache"
	}
	return filepath.Join(home, ".cache", "subflare")
}

func Load(dir, source, domain string, ttl time.Duration) ([]string, bool, error) {
	path := cachePath(ResolveDir(dir), source, domain)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer file.Close()

	var entry Entry
	if err := json.NewDecoder(file).Decode(&entry); err != nil {
		return nil, false, err
	}
	if ttl > 0 && time.Since(entry.FetchedAt) > ttl {
		return nil, false, nil
	}
	return entry.Hosts, true, nil
}

func Save(dir, source, domain string, hosts []string) error {
	resolved := ResolveDir(dir)
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		return err
	}
	path := cachePath(resolved, source, domain)
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	entry := Entry{
		Source:    source,
		Domain:    domain,
		FetchedAt: time.Now().UTC(),
		Hosts:     hosts,
	}
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		file.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func cachePath(dir, source, domain string) string {
	name := sanitize(source) + "__" + sanitize(domain) + ".json"
	return filepath.Join(dir, name)
}

func sanitize(input string) string {
	value := strings.ToLower(strings.TrimSpace(input))
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "?", "_")
	value = strings.ReplaceAll(value, "*", "_")
	if value == "" {
		return "unknown"
	}
	return value
}

func DebugString(source, domain string) string {
	return fmt.Sprintf("%s:%s", source, domain)
}
