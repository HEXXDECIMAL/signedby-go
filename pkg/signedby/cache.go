package signedby

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	dir     string
}

type cacheEntry struct {
	Info      *SignatureInfo `json:"info"`
	Key       cacheKey       `json:"key"`
	ExpiresAt time.Time      `json:"expires_at"`
}

type cacheKey struct {
	Path    string    `json:"path"`
	Inode   uint64    `json:"inode"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	UID     uint32    `json:"uid"`
	GID     uint32    `json:"gid"`
}

func newCache() *cache {
	dir := cacheDir()
	c := &cache{
		entries: make(map[string]*cacheEntry),
		dir:     dir,
	}

	_ = os.MkdirAll(dir, 0o755)
	c.loadFromDisk()

	return c
}

func cacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches", "signedby")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "signedby")
	default:
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			return filepath.Join(xdgCache, "signedby")
		}
		return filepath.Join(os.Getenv("HOME"), ".cache", "signedby")
	}
}

func (c *cache) get(path string) (*SignatureInfo, bool) {
	key := c.makeKey(path)
	if key == nil {
		return nil, false
	}

	hash := c.hashKey(key)

	c.mu.RLock()
	entry, exists := c.entries[hash]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		c.mu.Lock()
		delete(c.entries, hash)
		c.mu.Unlock()
		return nil, false
	}

	if !c.keyMatches(key, &entry.Key) {
		return nil, false
	}

	return entry.Info, true
}

func (c *cache) set(path string, info *SignatureInfo) {
	key := c.makeKey(path)
	if key == nil {
		return
	}

	hash := c.hashKey(key)
	entry := &cacheEntry{
		Info:      info,
		Key:       *key,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	c.mu.Lock()
	c.entries[hash] = entry
	c.mu.Unlock()

	go c.saveToDisk(hash, entry)
}

func (c *cache) makeKey(path string) *cacheKey {
	stat, err := os.Stat(path)
	if err != nil {
		return nil
	}

	key := &cacheKey{
		Path:    path,
		Size:    stat.Size(),
		ModTime: stat.ModTime(),
	}

	if runtime.GOOS != "windows" {
		if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
			key.Inode = sys.Ino
			key.UID = sys.Uid
			key.GID = sys.Gid
		}
	}

	return key
}

func (c *cache) hashKey(key *cacheKey) string {
	data := fmt.Sprintf("%s:%d:%d:%d:%d:%d",
		key.Path, key.Inode, key.Size,
		key.ModTime.Unix(), key.UID, key.GID)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (c *cache) keyMatches(a, b *cacheKey) bool {
	return a.Path == b.Path &&
		a.Inode == b.Inode &&
		a.Size == b.Size &&
		a.ModTime.Equal(b.ModTime) &&
		a.UID == b.UID &&
		a.GID == b.GID
}

func (c *cache) saveToDisk(hash string, entry *cacheEntry) {
	path := filepath.Join(c.dir, hash+".json")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

func (c *cache) loadFromDisk() {
	files, err := filepath.Glob(filepath.Join(c.dir, "*.json"))
	if err != nil {
		return
	}

	now := time.Now()
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var entry cacheEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			os.Remove(file)
			continue
		}

		if now.After(entry.ExpiresAt) {
			os.Remove(file)
			continue
		}

		hash := c.hashKey(&entry.Key)
		c.entries[hash] = &entry
	}
}
