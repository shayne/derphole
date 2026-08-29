// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDiskMapCacheRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cache", diskMapCacheFilename)
	cache := newDiskMapCache(path)
	want := MapCacheEntry{
		Data:     []byte(`{"Regions":{"7":{}}}`),
		ETag:     `"map-7"`,
		StoredAt: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
	}
	if err := cache.Put("https://example.test/map", want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := cache.Get("https://example.test/map")
	if !ok {
		t.Fatal("Get missed persisted entry")
	}
	if !bytes.Equal(got.Data, want.Data) || got.ETag != want.ETag || !got.StoredAt.Equal(want.StoredAt) {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}

	got.Data[0] = 'X'
	again, ok := cache.Get("https://example.test/map")
	if !ok {
		t.Fatal("second Get missed persisted entry")
	}
	if !bytes.Equal(again.Data, want.Data) {
		t.Fatalf("second data = %q, want %q", again.Data, want.Data)
	}
}

func TestDiskMapCacheTreatsInvalidFilesAsMisses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "missing"},
		{name: "truncated JSON", data: []byte(`{"version":`)},
		{name: "unknown version", data: []byte(`{"version":99,"entries":{}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), diskMapCacheFilename)
			if tt.data != nil {
				if err := os.WriteFile(path, tt.data, 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}
			if _, ok := newDiskMapCache(path).Get("https://example.test/map"); ok {
				t.Fatal("Get returned an entry from an invalid cache file")
			}
		})
	}
}

func TestDiskMapCacheRejectsOversizedEnvelope(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), diskMapCacheFilename)
	data := bytes.Repeat([]byte{'x'}, int(diskMapCacheMaxBytes+1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	if _, ok := newDiskMapCache(path).Get("https://example.test/map"); ok {
		t.Fatal("Get returned an entry from an oversized cache file")
	}
}

func TestDiskMapCacheWritesAtomicallyWithPrivateModes(t *testing.T) {
	t.Parallel()

	t.Run("private modes", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "nested", diskMapCacheFilename)
		cache := newDiskMapCache(path)
		if err := cache.Put("https://example.test/map", MapCacheEntry{Data: []byte("map")}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if runtime.GOOS == "windows" {
			t.Skip("Unix permission bits are not meaningful on Windows")
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("stat cache directory: %v", err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("directory mode = %#o, want 0700", got)
		}
		fileInfo, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat cache file: %v", err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("file mode = %#o, want 0600", got)
		}
	})

	t.Run("rename failure preserves previous file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, diskMapCacheFilename)
		if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
			t.Fatalf("write previous file: %v", err)
		}
		renameErr := errors.New("rename failed")
		err := writeDiskMapCacheWithOps(path, []byte("replacement"), diskMapCacheOps{
			createTemp: os.CreateTemp,
			rename: func(string, string) error {
				return renameErr
			},
			remove: os.Remove,
		})
		if !errors.Is(err, renameErr) {
			t.Fatalf("write error = %v, want %v", err, renameErr)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read previous file: %v", err)
		}
		if string(got) != "previous" {
			t.Fatalf("file contents = %q, want previous contents", got)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read cache directory: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != diskMapCacheFilename {
			t.Fatalf("directory entries = %v, want only completed cache file", entries)
		}
	})
}

func TestDiskMapCacheEvictsOldestEntries(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), diskMapCacheFilename)
	cache := newDiskMapCache(path)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	large := bytes.Repeat([]byte{'x'}, 7<<20)
	if err := cache.Put("https://old.example.test/map", MapCacheEntry{
		Data:     large,
		StoredAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("put old entry: %v", err)
	}
	if err := cache.Put("https://new.example.test/map", MapCacheEntry{
		Data:     large,
		StoredAt: now,
	}); err != nil {
		t.Fatalf("put new entry: %v", err)
	}

	if _, ok := cache.Get("https://old.example.test/map"); ok {
		t.Fatal("oldest entry was not evicted")
	}
	if _, ok := cache.Get("https://new.example.test/map"); !ok {
		t.Fatal("newest entry was evicted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if info.Size() > diskMapCacheMaxBytes {
		t.Fatalf("cache size = %d, limit = %d", info.Size(), diskMapCacheMaxBytes)
	}
}

func TestTieredMapCachePromotesDiskHitToMemory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), diskMapCacheFilename)
	disk := newDiskMapCache(path)
	want := MapCacheEntry{Data: []byte("persisted")}
	if err := disk.Put("https://example.test/map", want); err != nil {
		t.Fatalf("disk Put: %v", err)
	}
	cache := &tieredMapCache{memory: newMemoryMapCache(), disk: disk}
	if _, ok := cache.Get("https://example.test/map"); !ok {
		t.Fatal("tiered Get missed disk entry")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove disk cache: %v", err)
	}
	got, ok := cache.Get("https://example.test/map")
	if !ok {
		t.Fatal("tiered Get did not promote disk entry to memory")
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("promoted data = %q, want %q", got.Data, want.Data)
	}
}

func TestDiskMapCacheEnvelopeUsesCurrentVersion(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), diskMapCacheFilename)
	cache := newDiskMapCache(path)
	if err := cache.Put("https://example.test/map", MapCacheEntry{Data: []byte("map")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var envelope diskMapCacheEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	if envelope.Version != diskMapCacheVersion {
		t.Fatalf("version = %d, want %d", envelope.Version, diskMapCacheVersion)
	}
}
