// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	diskMapCacheVersion  = 2
	diskMapCacheMaxBytes = int64(16 << 20)
	diskMapCacheFilename = "derpmap-cache-v2.json"
)

type diskMapCacheEnvelope struct {
	Version int                          `json:"version"`
	Entries map[string]diskMapCacheEntry `json:"entries"`
}

type diskMapCacheEntry struct {
	Data     []byte    `json:"data"`
	ETag     string    `json:"etag,omitempty"`
	StoredAt time.Time `json:"stored_at"`
}

type diskMapCache struct {
	mu   sync.Mutex
	path string
}

func newDiskMapCache(path string) *diskMapCache {
	return &diskMapCache{path: path}
}

func (c *diskMapCache) Get(url string) (MapCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	envelope, err := readDiskMapCache(c.path)
	if err != nil {
		return MapCacheEntry{}, false
	}
	entry, ok := envelope.Entries[diskMapCacheKey(url)]
	if !ok {
		return MapCacheEntry{}, false
	}
	return mapCacheEntryFromDisk(entry), true
}

func (c *diskMapCache) Put(url string, entry MapCacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	envelope, err := readDiskMapCache(c.path)
	if err != nil {
		envelope = newDiskMapCacheEnvelope()
	}
	key := diskMapCacheKey(url)
	envelope.Entries[key] = mapCacheEntryToDisk(entry)

	single := newDiskMapCacheEnvelope()
	single.Entries[key] = mapCacheEntryToDisk(entry)
	singleData, err := json.Marshal(single)
	if err != nil {
		return fmt.Errorf("encode DERP map cache entry: %w", err)
	}
	if int64(len(singleData)) > diskMapCacheMaxBytes {
		return nil
	}

	data, err := encodeBoundedDiskMapCache(envelope)
	if err != nil {
		return err
	}
	return writeDiskMapCache(c.path, data)
}

func diskMapCacheKey(rawURL string) string {
	canonical := rawURL
	if parsed, err := url.Parse(rawURL); err == nil {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		host := strings.ToLower(parsed.Hostname())
		port := parsed.Port()
		if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
			port = ""
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if port != "" {
			host += ":" + port
		}
		parsed.Host = host
		parsed.Fragment = ""
		parsed.RawQuery = parsed.Query().Encode()
		canonical = parsed.String()
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
}

func newDiskMapCacheEnvelope() diskMapCacheEnvelope {
	return diskMapCacheEnvelope{
		Version: diskMapCacheVersion,
		Entries: make(map[string]diskMapCacheEntry),
	}
}

func readDiskMapCache(path string) (diskMapCacheEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return diskMapCacheEnvelope{}, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, diskMapCacheMaxBytes+1))
	if err != nil {
		return diskMapCacheEnvelope{}, fmt.Errorf("read DERP map cache: %w", err)
	}
	if int64(len(data)) > diskMapCacheMaxBytes {
		return diskMapCacheEnvelope{}, errors.New("DERP map cache exceeds size limit")
	}

	var envelope diskMapCacheEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return diskMapCacheEnvelope{}, fmt.Errorf("decode DERP map cache: %w", err)
	}
	if envelope.Version != diskMapCacheVersion {
		return diskMapCacheEnvelope{}, fmt.Errorf("unsupported DERP map cache version %d", envelope.Version)
	}
	if envelope.Entries == nil {
		envelope.Entries = make(map[string]diskMapCacheEntry)
	}
	return envelope, nil
}

func encodeBoundedDiskMapCache(envelope diskMapCacheEnvelope) ([]byte, error) {
	type entryAge struct {
		url      string
		storedAt time.Time
	}
	ages := make([]entryAge, 0, len(envelope.Entries))
	for url, entry := range envelope.Entries {
		ages = append(ages, entryAge{url: url, storedAt: entry.StoredAt})
	}
	sort.Slice(ages, func(i, j int) bool {
		if ages[i].storedAt.Equal(ages[j].storedAt) {
			return ages[i].url < ages[j].url
		}
		return ages[i].storedAt.Before(ages[j].storedAt)
	})

	for {
		data, err := json.Marshal(envelope)
		if err != nil {
			return nil, fmt.Errorf("encode DERP map cache: %w", err)
		}
		if int64(len(data)) <= diskMapCacheMaxBytes {
			return data, nil
		}
		if len(ages) == 0 {
			return nil, errors.New("DERP map cache cannot fit within size limit")
		}
		delete(envelope.Entries, ages[0].url)
		ages = ages[1:]
	}
}

func mapCacheEntryToDisk(entry MapCacheEntry) diskMapCacheEntry {
	return diskMapCacheEntry{
		Data:     append([]byte(nil), entry.Data...),
		ETag:     entry.ETag,
		StoredAt: entry.StoredAt.UTC(),
	}
}

func mapCacheEntryFromDisk(entry diskMapCacheEntry) MapCacheEntry {
	return MapCacheEntry{
		Data:     append([]byte(nil), entry.Data...),
		ETag:     entry.ETag,
		StoredAt: entry.StoredAt,
	}
}

type diskMapCacheOps struct {
	createTemp func(dir, pattern string) (*os.File, error)
	rename     func(oldPath, newPath string) error
	remove     func(path string) error
}

func writeDiskMapCache(path string, data []byte) error {
	return writeDiskMapCacheWithOps(path, data, diskMapCacheOps{
		createTemp: os.CreateTemp,
		rename:     os.Rename,
		remove:     os.Remove,
	})
}

func writeDiskMapCacheWithOps(path string, data []byte, ops diskMapCacheOps) error {
	dir, err := prepareDiskMapCacheDir(path)
	if err != nil {
		return err
	}

	temp, err := ops.createTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary DERP map cache: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = ops.remove(tempPath)
		}
	}()

	if err := writeDiskMapCacheTemp(temp, data); err != nil {
		return err
	}
	if err := ops.rename(tempPath, path); err != nil {
		return fmt.Errorf("replace DERP map cache: %w", err)
	}
	removeTemp = false
	return nil
}

func prepareDiskMapCacheDir(path string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create DERP map cache directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure DERP map cache directory: %w", err)
	}
	return dir, nil
}

func writeDiskMapCacheTemp(temp *os.File, data []byte) error {
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary DERP map cache: %w", err)
	}
	n, err := temp.Write(data)
	if err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary DERP map cache: %w", err)
	}
	if n != len(data) {
		_ = temp.Close()
		return fmt.Errorf("write temporary DERP map cache: %w", io.ErrShortWrite)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary DERP map cache: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary DERP map cache: %w", err)
	}
	return nil
}

type tieredMapCache struct {
	memory *memoryMapCache
	disk   *diskMapCache
}

func (c *tieredMapCache) Get(url string) (MapCacheEntry, bool) {
	if entry, ok := c.memory.Get(url); ok {
		return entry, true
	}
	entry, ok := c.disk.Get(url)
	if !ok {
		return MapCacheEntry{}, false
	}
	_ = c.memory.Put(url, entry)
	return entry, true
}

func (c *tieredMapCache) Put(url string, entry MapCacheEntry) error {
	_ = c.memory.Put(url, entry)
	return c.disk.Put(url, entry)
}

func newDefaultMapCache() MapCache {
	memory := newMemoryMapCache()
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return memory
	}
	return &tieredMapCache{
		memory: memory,
		disk:   newDiskMapCache(filepath.Join(cacheDir, "derphole", diskMapCacheFilename)),
	}
}
