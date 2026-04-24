package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const indexVersion = 1

type Entry struct {
	Source    string    `json:"source"`
	Domain    string    `json:"domain"`
	FetchedAt time.Time `json:"fetched_at"`
	Hosts     []string  `json:"hosts"`
}

type IndexEntry struct {
	Source     string    `json:"source"`
	Domain     string    `json:"domain"`
	Path       string    `json:"path"`
	FetchedAt  time.Time `json:"fetched_at"`
	HostCount  int       `json:"host_count"`
	LastAccess time.Time `json:"last_access,omitempty"`
}

type IndexState struct {
	Version int                   `json:"version"`
	Entries map[string]IndexEntry `json:"entries"`
}

var indexMu sync.Mutex

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
	resolved := ResolveDir(dir)
	path := cachePath(resolved, source, domain)
	indexed := false

	if meta, ok, err := indexLookup(resolved, source, domain); err == nil && ok {
		indexed = true
		if meta.Path != "" {
			path = meta.Path
		}
		if ttl > 0 && time.Since(meta.FetchedAt) > ttl {
			_ = indexRemove(resolved, source, domain)
			return nil, false, nil
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = indexRemove(resolved, source, domain)
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
		_ = indexRemove(resolved, source, domain)
		return nil, false, nil
	}
	if !indexed {
		_ = indexUpsert(resolved, IndexEntry{
			Source:     source,
			Domain:     domain,
			Path:       path,
			FetchedAt:  entry.FetchedAt,
			HostCount:  len(entry.Hosts),
			LastAccess: time.Now().UTC(),
		})
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

	now := time.Now().UTC()
	entry := Entry{
		Source:    source,
		Domain:    domain,
		FetchedAt: now,
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
	_ = indexUpsert(resolved, IndexEntry{
		Source:     source,
		Domain:     domain,
		Path:       path,
		FetchedAt:  now,
		HostCount:  len(hosts),
		LastAccess: now,
	})
	return nil
}

func cachePath(dir, source, domain string) string {
	name := sanitize(source) + "__" + sanitize(domain) + ".json"
	return filepath.Join(dir, name)
}

func indexPath(dir string) string {
	return filepath.Join(dir, "index.json")
}

func indexKey(source, domain string) string {
	return sanitize(source) + "|" + sanitize(domain)
}

func indexLookup(dir, source, domain string) (IndexEntry, bool, error) {
	indexMu.Lock()
	defer indexMu.Unlock()

	state, err := readIndex(dir)
	if err != nil {
		return IndexEntry{}, false, err
	}
	entry, ok := state.Entries[indexKey(source, domain)]
	if !ok {
		return IndexEntry{}, false, nil
	}
	return entry, true, nil
}

func indexUpsert(dir string, entry IndexEntry) error {
	indexMu.Lock()
	defer indexMu.Unlock()

	state, err := readIndex(dir)
	if err != nil {
		return err
	}
	if state.Entries == nil {
		state.Entries = map[string]IndexEntry{}
	}
	state.Entries[indexKey(entry.Source, entry.Domain)] = entry
	return writeIndex(dir, state)
}

func indexRemove(dir, source, domain string) error {
	indexMu.Lock()
	defer indexMu.Unlock()

	state, err := readIndex(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	delete(state.Entries, indexKey(source, domain))
	return writeIndex(dir, state)
}

func readIndex(dir string) (IndexState, error) {
	path := indexPath(dir)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return IndexState{Version: indexVersion, Entries: map[string]IndexEntry{}}, nil
		}
		return IndexState{}, err
	}
	defer file.Close()

	var state IndexState
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return IndexState{}, err
	}
	if state.Version != indexVersion {
		state.Version = indexVersion
	}
	if state.Entries == nil {
		state.Entries = map[string]IndexEntry{}
	}
	return state, nil
}

func writeIndex(dir string, state IndexState) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if state.Version == 0 {
		state.Version = indexVersion
	}
	if state.Entries == nil {
		state.Entries = map[string]IndexEntry{}
	}

	path := indexPath(dir)
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(state); err != nil {
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
