package signedby

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
)

//nolint:govet // field alignment micro-optimization not needed
type cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	dir     string
}

//nolint:govet // field alignment micro-optimization not needed
type cacheEntry struct {
	Info      *SignatureInfo
	Key       cacheKey
	ExpiresAt time.Time
}

//nolint:govet // field alignment micro-optimization not needed
type cacheKey struct {
	Path    string
	ModTime time.Time
	Size    int64
	Inode   uint64
	UID     uint32
	GID     uint32
}

func newCache() *cache {
	return &cache{
		entries: make(map[string]*cacheEntry),
		dir:     "", // No longer using disk storage
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
}

func (*cache) makeKey(path string) *cacheKey {
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

func (*cache) hashKey(key *cacheKey) string {
	data := fmt.Sprintf("%s:%d:%d:%d:%d:%d",
		key.Path, key.Inode, key.Size,
		key.ModTime.Unix(), key.UID, key.GID)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (*cache) keyMatches(a, b *cacheKey) bool {
	return a.Path == b.Path &&
		a.Inode == b.Inode &&
		a.Size == b.Size &&
		a.ModTime.Equal(b.ModTime) &&
		a.UID == b.UID &&
		a.GID == b.GID
}
