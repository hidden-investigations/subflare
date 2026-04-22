package workflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Snapshot struct {
	Domain    string    `json:"domain"`
	SavedAt   time.Time `json:"saved_at"`
	Subdomain []string  `json:"subdomains"`
}

func ResolveStateDir(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed != "" {
		return trimmed
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".subflare-state"
	}
	return filepath.Join(home, ".local", "share", "subflare", "state")
}

func LoadSnapshot(stateDir, domain string) ([]string, bool, error) {
	path := snapshotPath(ResolveStateDir(stateDir), domain)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer file.Close()

	var snapshot Snapshot
	if err := json.NewDecoder(file).Decode(&snapshot); err != nil {
		return nil, false, err
	}
	return uniqueSorted(snapshot.Subdomain), true, nil
}

func SaveSnapshot(stateDir, domain string, hosts []string) error {
	resolved := ResolveStateDir(stateDir)
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		return err
	}
	path := snapshotPath(resolved, domain)
	tmpPath := path + ".tmp"

	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	snapshot := Snapshot{Domain: domain, SavedAt: time.Now().UTC(), Subdomain: uniqueSorted(hosts)}
	if err := json.NewEncoder(file).Encode(snapshot); err != nil {
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

func snapshotPath(stateDir, domain string) string {
	name := strings.ToLower(strings.TrimSpace(domain))
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	if name == "" {
		name = "unknown"
	}
	return filepath.Join(stateDir, name+".json")
}
