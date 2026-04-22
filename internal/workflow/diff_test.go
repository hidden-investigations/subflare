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
