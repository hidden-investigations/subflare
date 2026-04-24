package workflow

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestComputeDiff(t *testing.T) {
	oldHosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	newHosts := []string{"b.example.com", "c.example.com", "d.example.com"}
	delta := ComputeDiff(oldHosts, newHosts)

	if !reflect.DeepEqual(delta.New, []string{"d.example.com"}) {
		t.Fatalf("unexpected new: %v", delta.New)
	}
	if !reflect.DeepEqual(delta.Removed, []string{"a.example.com"}) {
		t.Fatalf("unexpected removed: %v", delta.Removed)
	}
	if !reflect.DeepEqual(delta.Stable, []string{"b.example.com", "c.example.com"}) {
		t.Fatalf("unexpected stable: %v", delta.Stable)
	}
}

func TestReadHostsFileTextAndJSONL(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "hosts.txt")
	jsonlPath := filepath.Join(dir, "hosts.jsonl")

	if err := os.WriteFile(textPath, []byte("a.example.com\nb.example.com\n"), 0o644); err != nil {
		t.Fatalf("write text fixture: %v", err)
	}
	if err := os.WriteFile(jsonlPath, []byte("{\"host\":\"c.example.com\"}\n{\"host\":\"d.example.com\"}\n"), 0o644); err != nil {
		t.Fatalf("write jsonl fixture: %v", err)
	}

	textHosts, err := ReadHostsFile(textPath)
	if err != nil {
		t.Fatalf("read text: %v", err)
	}
	jsonHosts, err := ReadHostsFile(jsonlPath)
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}

	if !reflect.DeepEqual(textHosts, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("unexpected text hosts: %v", textHosts)
	}
	if !reflect.DeepEqual(jsonHosts, []string{"c.example.com", "d.example.com"}) {
		t.Fatalf("unexpected json hosts: %v", jsonHosts)
	}
}

func TestSaveLoadSnapshot(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"b.example.com", "a.example.com"}
	if err := SaveSnapshot(dir, "example.com", hosts); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	loaded, ok, err := LoadSnapshot(dir, "example.com")
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if !ok {
		t.Fatal("expected snapshot to exist")
	}
	if !reflect.DeepEqual(loaded, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("unexpected loaded snapshot: %v", loaded)
	}
}

func TestStateDirCandidatesIncludeFallback(t *testing.T) {
	candidates := stateDirCandidates("")
	if len(candidates) < 1 {
		t.Fatal("expected at least one state-dir candidate")
	}
	if len(candidates) == 1 {
		return
	}
	if filepath.Clean(candidates[1]) != filepath.Clean(fallbackStateDir()) {
		t.Fatalf("expected fallback state dir as second candidate, got %v", candidates)
	}
}

func TestSaveSnapshotFallsBackToTempWhenHomeReadonly(t *testing.T) {
	homeRoot := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(homeRoot, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", homeRoot); err != nil {
		t.Fatalf("set HOME: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.Chmod(homeRoot, 0o755)
	})

	if err := os.Chmod(homeRoot, 0o555); err != nil {
		t.Skipf("unable to make HOME readonly: %v", err)
	}

	domain := "fallback-state-example.com"
	hosts := []string{"a.fallback-state-example.com"}
	primaryPath := snapshotPath(defaultStateDir(), domain)
	fallbackPath := snapshotPath(fallbackStateDir(), domain)
	_ = os.Remove(primaryPath)
	_ = os.Remove(fallbackPath)
	t.Cleanup(func() {
		_ = os.Remove(primaryPath)
		_ = os.Remove(fallbackPath)
	})

	if err := SaveSnapshot("", domain, hosts); err != nil {
		t.Fatalf("save snapshot with readonly HOME: %v", err)
	}

	if _, err := os.Stat(primaryPath); err == nil {
		t.Skip("primary state dir remained writable in this environment; fallback behavior cannot be asserted")
	}
	if _, err := os.Stat(fallbackPath); err != nil {
		t.Fatalf("expected fallback snapshot file, got error: %v", err)
	}

	loaded, ok, err := LoadSnapshot("", domain)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if !ok {
		t.Fatal("expected snapshot to exist from fallback state dir")
	}
	if !reflect.DeepEqual(loaded, []string{"a.fallback-state-example.com"}) {
		t.Fatalf("unexpected loaded snapshot: %v", loaded)
	}
}
