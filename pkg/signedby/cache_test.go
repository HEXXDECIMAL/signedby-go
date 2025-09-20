package signedby

import (
	"os"
	"testing"
	"time"
)

func TestCacheOperations(t *testing.T) {
	c := newCache()
	if c == nil {
		t.Fatal("newCache() returned nil")
	}

	f, err := os.CreateTemp(t.TempDir(), "test-binary-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }() //nolint:errcheck // cleanup
	testFile := f.Name()
	if _, err := f.WriteString("test content"); err != nil {
		t.Fatalf("Failed to write test content: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

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
	if err := os.Chtimes(testFile, time.Now(), time.Now()); err != nil {
		t.Fatalf("Failed to change file times: %v", err)
	}

	_, found = c.get(testFile)
	if found {
		t.Error("Cache should not return item after file modification")
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	c := newCache()

	f, err := os.CreateTemp(t.TempDir(), "test-cache-key-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }() //nolint:errcheck // cleanup
	if _, err := f.WriteString("test"); err != nil {
		t.Fatalf("Failed to write test content: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

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

	f, err := os.CreateTemp(t.TempDir(), "test-expiration-*")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }() //nolint:errcheck // cleanup
	if _, err := f.WriteString("test"); err != nil {
		t.Fatalf("Failed to write test content: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

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
