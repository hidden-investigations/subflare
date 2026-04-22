package cache

import (
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

func TestResolveDirDefault(t *testing.T) {
	resolved := ResolveDir("")
	if filepath.Base(resolved) != "subflare" && filepath.Base(resolved) != ".subflare-cache" {
		t.Fatalf("unexpected default dir: %s", resolved)
	}
}
