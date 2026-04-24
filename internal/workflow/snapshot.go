package workflow

import (
	"encoding/json"
	"fmt"
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
	return defaultStateDir()
}

func LoadSnapshot(stateDir, domain string) ([]string, bool, error) {
	dirs := stateDirCandidates(stateDir)
	for _, dir := range dirs {
		path := snapshotPath(dir, domain)
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if isPermissionLikeErr(err) && strings.TrimSpace(stateDir) == "" {
				continue
			}
			return nil, false, err
		}

		var snapshot Snapshot
		decodeErr := json.NewDecoder(file).Decode(&snapshot)
		file.Close()
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		return uniqueSorted(snapshot.Subdomain), true, nil
	}
	return nil, false, nil
}

func SaveSnapshot(stateDir, domain string, hosts []string) error {
	dirs := stateDirCandidates(stateDir)
	var lastErr error

	for _, dir := range dirs {
		if err := saveSnapshotToDir(dir, domain, hosts); err != nil {
			lastErr = err
			if strings.TrimSpace(stateDir) != "" || !isPermissionLikeErr(err) {
				return err
			}
			continue
		}
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unable to save snapshot")
	}
	return lastErr
}

func saveSnapshotToDir(stateDir, domain string, hosts []string) error {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	path := snapshotPath(stateDir, domain)
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

func stateDirCandidates(path string) []string {
	explicit := strings.TrimSpace(path)
	if explicit != "" {
		return []string{explicit}
	}
	primary := defaultStateDir()
	fallback := fallbackStateDir()
	if filepath.Clean(primary) == filepath.Clean(fallback) {
		return []string{primary}
	}
	return []string{primary, fallback}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".subflare-state"
	}
	return filepath.Join(home, ".local", "share", "subflare", "state")
}

func fallbackStateDir() string {
	return filepath.Join(os.TempDir(), "subflare-state")
}

func isPermissionLikeErr(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(lower, "read-only file system")
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
