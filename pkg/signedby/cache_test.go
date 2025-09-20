package signedby

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCacheDir(t *testing.T) {
	dir := cacheDir()
	if dir == "" {
		t.Error("cacheDir() returned empty string")
	}

	switch runtime.GOOS {
	case "darwin":
		expected := filepath.Join(os.Getenv("HOME"), "Library", "Caches", "signedby")
		if dir != expected {
			t.Errorf("Unexpected cache dir on macOS: got %s, want %s", dir, expected)
		}
	case "windows":
		expected := filepath.Join(os.Getenv("LOCALAPPDATA"), "signedby")
		if dir != expected {
			t.Errorf("Unexpected cache dir on Windows: got %s, want %s", dir, expected)
		}
	default:
		home := os.Getenv("HOME")
		xdgCache := os.Getenv("XDG_CACHE_HOME")
		if xdgCache != "" {
			expected := filepath.Join(xdgCache, "signedby")
			if dir != expected {
				t.Errorf("Unexpected cache dir with XDG_CACHE_HOME: got %s, want %s", dir, expected)
			}
		} else {
			expected := filepath.Join(home, ".cache", "signedby")
			if dir != expected {
				t.Errorf("Unexpected cache dir on Linux/Unix: got %s, want %s", dir, expected)
			}
		}
	}
}

func TestCacheOperations(t *testing.T) {
	c := newCache()
	if c == nil {
		t.Fatal("newCache() returned nil")
	}

	f, err := os.CreateTemp("", "test-binary-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(f.Name())
	testFile := f.Name()
	_, _ = f.WriteString("test content")
	f.Close()

	info := &SignatureInfo{
		Path:           testFile,
		IsPackaged:     true,
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		SignerOrg:      "Test Org",
		IsPlatform:     false,
		SigningMethod:  "test",
		SignatureValid: boolPtr(true),
	}

	c.set(testFile, info)

	retrieved, found := c.get(testFile)
	if !found {
		t.Error("Failed to retrieve cached item")
	}

	if retrieved == nil {
		t.Fatal("Retrieved nil from cache")
	}

	if retrieved.PackageName != info.PackageName {
		t.Errorf("Package name mismatch: got %s, want %s", retrieved.PackageName, info.PackageName)
	}

	time.Sleep(100 * time.Millisecond)
	_ = os.Chtimes(testFile, time.Now(), time.Now())

	_, found = c.get(testFile)
	if found {
		t.Error("Cache should not return item after file modification")
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	c := newCache()

	f, err := os.CreateTemp("", "test-cache-key-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("test")
	f.Close()

	key1 := c.makeKey(f.Name())
	if key1 == nil {
		t.Fatal("makeKey returned nil for existing file")
	}

	if key1.Path != f.Name() {
		t.Errorf("Key path mismatch: got %s, want %s", key1.Path, f.Name())
	}

	if key1.Size != 4 {
		t.Errorf("Key size mismatch: got %d, want 4", key1.Size)
	}

	key2 := c.makeKey("/non/existent/path")
	if key2 != nil {
		t.Error("makeKey should return nil for non-existent file")
	}
}

func TestCacheExpiration(t *testing.T) {
	c := &cache{
		entries: make(map[string]*cacheEntry),
		dir:     "",
	}

	f, err := os.CreateTemp("", "test-expiration-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("test")
	f.Close()

	key := c.makeKey(f.Name())
	if key == nil {
		t.Fatal("Failed to make key")
	}

	hash := c.hashKey(key)

	expiredEntry := &cacheEntry{
		Info: &SignatureInfo{
			Path: f.Name(),
		},
		Key:       *key,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	c.entries[hash] = expiredEntry

	_, found := c.get(f.Name())
	if found {
		t.Error("Cache returned expired entry")
	}

	if _, exists := c.entries[hash]; exists {
		t.Error("Expired entry not removed from cache")
	}
}
