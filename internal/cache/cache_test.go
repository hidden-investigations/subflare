package cache

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"a.example.com", "b.example.com"}
	if err := Save(dir, "crtsh", "example.com", hosts); err != nil {
		t.Fatalf("save cache: %v", err)
	}
	loaded, hit, err := Load(dir, "crtsh", "example.com", time.Hour)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	if !reflect.DeepEqual(loaded, hosts) {
		t.Fatalf("unexpected hosts: got %v want %v", loaded, hosts)
	}
}

func TestLoadExpired(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"a.example.com"}
	if err := Save(dir, "crtsh", "example.com", hosts); err != nil {
		t.Fatalf("save cache: %v", err)
	}
	_, hit, err := Load(dir, "crtsh", "example.com", time.Nanosecond)
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if hit {
		t.Fatal("expected cache miss due to expiration")
	}
}

func TestSaveCreatesIndex(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, "crtsh", "example.com", []string{"a.example.com"}); err != nil {
		t.Fatalf("save cache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		t.Fatalf("expected index file: %v", err)
	}
}

func TestResolveDirDefault(t *testing.T) {
	resolved := ResolveDir("")
	if filepath.Base(resolved) != "subflare" && filepath.Base(resolved) != ".subflare-cache" {
		t.Fatalf("unexpected default dir: %s", resolved)
	}
}
