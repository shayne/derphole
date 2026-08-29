// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestMapResolverUsesFreshCacheWithoutNetwork(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	mapURL := "https://control.example.test/derpmap"
	want := testDERPMap(17)
	cache := &recordingMapCache{
		entries: map[string]MapCacheEntry{
			mapURL: {
				Data:     marshalDERPMap(t, want),
				ETag:     `"map-17"`,
				StoredAt: now.Add(-30 * time.Minute),
			},
		},
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("fresh cache entry triggered a network request")
		return nil, nil
	})}

	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient:   client,
		Cache:        cache,
		Now:          func() time.Time { return now },
		FreshFor:     time.Hour,
		FetchTimeout: time.Second,
		MaxBytes:     1 << 20,
		Fallback:     func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceFreshCache {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceFreshCache)
	}
	if result.URL != mapURL {
		t.Fatalf("url = %q, want %q", result.URL, mapURL)
	}
	if !result.StoredAt.Equal(now.Add(-30 * time.Minute)) {
		t.Fatalf("stored at = %v, want %v", result.StoredAt, now.Add(-30*time.Minute))
	}
	if got := result.Map.Regions[17]; got == nil {
		t.Fatalf("resolved map does not contain region 17: %#v", result.Map)
	}
}

func TestResolveMapReturnsSourceMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"map-79"`)
		if err := json.NewEncoder(w).Encode(testDERPMap(79)); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	result, err := ResolveMap(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ResolveMap: %v", err)
	}
	if result.Source != MapSourceNetwork {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceNetwork)
	}
	if result.URL != server.URL {
		t.Fatalf("url = %q, want %q", result.URL, server.URL)
	}
	if got := result.Map.Regions[79]; got == nil {
		t.Fatalf("resolved map does not contain region 79: %#v", result.Map)
	}
}

func TestCompiledMapReturnsIsolatedValidatedMaps(t *testing.T) {
	t.Parallel()

	first, err := CompiledMap()
	if err != nil {
		t.Fatalf("CompiledMap(first): %v", err)
	}
	regionIDs := first.RegionIDs()
	if len(regionIDs) == 0 {
		t.Fatal("CompiledMap(first) has no regions")
	}
	regionID := regionIDs[0]
	if first.Regions[regionID] == nil || len(first.Regions[regionID].Nodes) == 0 {
		t.Fatalf("CompiledMap(first) region %d has no nodes", regionID)
	}
	first.Regions[regionID].Nodes[0].HostName = "mutated.example.test"

	second, err := CompiledMap()
	if err != nil {
		t.Fatalf("CompiledMap(second): %v", err)
	}
	if got := second.Regions[regionID].Nodes[0].HostName; got == "mutated.example.test" {
		t.Fatal("CompiledMap returned aliased maps")
	}
}

func TestMapResolverFetchesAndCachesNetworkMap(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	mapURL := "https://control.example.test/derpmap"
	cache := &recordingMapCache{}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != mapURL {
			t.Fatalf("request URL = %q, want %q", req.URL, mapURL)
		}
		response := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(marshalDERPMap(t, testDERPMap(23))))),
			Request:    req,
		}
		response.Header.Set("ETag", `"map-23"`)
		return response, nil
	})}

	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient:   client,
		Cache:        cache,
		Now:          func() time.Time { return now },
		FetchTimeout: time.Second,
		MaxBytes:     1 << 20,
		Fallback:     func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceNetwork {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceNetwork)
	}
	if got := result.Map.Regions[23]; got == nil {
		t.Fatalf("resolved map does not contain region 23: %#v", result.Map)
	}
	entry, ok := cache.entries[mapURL]
	if !ok {
		t.Fatal("network map was not cached")
	}
	if entry.ETag != `"map-23"` {
		t.Fatalf("cache ETag = %q, want %q", entry.ETag, `"map-23"`)
	}
	if !entry.StoredAt.Equal(now) {
		t.Fatalf("cache stored at = %v, want %v", entry.StoredAt, now)
	}
}

func TestMapResolverPersistsOnlyCanonicalRedactedDataAndUTCTime(t *testing.T) {
	t.Parallel()

	const queryCanary = "query-secret-canary"
	const responseCanary = "response-secret-canary"
	path := filepath.Join(t.TempDir(), diskMapCacheFilename)
	mapURL := "https://EXAMPLE.test:443/derpmap?access_token=" + queryCanary
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.FixedZone("test-zone", -4*60*60))
	body := `{"Regions":{"7":{"RegionID":7,"Nodes":[{"Name":"seven","RegionID":7,"HostName":"derp7.example.test"}]}},"unknown_secret":"` + responseCanary + `"}`
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Cache:      newDiskMapCache(path),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.StoredAt.Location() != time.UTC {
		t.Fatalf("result StoredAt location = %v, want UTC", result.StoredAt.Location())
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	for _, secret := range []string{mapURL, queryCanary, responseCanary, "unknown_secret"} {
		if bytes.Contains(persisted, []byte(secret)) {
			t.Fatalf("persistent cache contains secret canary %q: %s", secret, persisted)
		}
	}

	cached, ok := newDiskMapCache(path).Get(mapURL)
	if !ok {
		t.Fatal("canonical cache entry was not addressable by source URL")
	}
	if cached.StoredAt.Location() != time.UTC {
		t.Fatalf("cached StoredAt location = %v, want UTC", cached.StoredAt.Location())
	}
	if bytes.Contains(cached.Data, []byte(responseCanary)) {
		t.Fatal("cached typed map retained unknown response data")
	}
}

func TestMapResolverRevalidatesStaleCacheWithETag(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	mapURL := "https://control.example.test/derpmap"
	data := marshalDERPMap(t, testDERPMap(31))
	cache := &recordingMapCache{entries: map[string]MapCacheEntry{
		mapURL: {
			Data:     data,
			ETag:     `"map-31"`,
			StoredAt: now.Add(-2 * time.Hour),
		},
	}}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("If-None-Match"); got != `"map-31"` {
			t.Fatalf("If-None-Match = %q, want %q", got, `"map-31"`)
		}
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Status:     "304 Not Modified",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})}

	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient:   client,
		Cache:        cache,
		Now:          func() time.Time { return now },
		FreshFor:     time.Hour,
		FetchTimeout: time.Second,
		MaxBytes:     1 << 20,
		Fallback:     func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceRevalidated {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceRevalidated)
	}
	if got := result.Map.Regions[31]; got == nil {
		t.Fatalf("resolved map does not contain region 31: %#v", result.Map)
	}
	entry := cache.entries[mapURL]
	if !entry.StoredAt.Equal(now) {
		t.Fatalf("cache stored at = %v, want %v", entry.StoredAt, now)
	}
	if string(entry.Data) != string(data) {
		t.Fatal("revalidation replaced the cached map data")
	}
}

func TestMapResolverFallsBackAfterNetworkFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	mapURL := "https://control.example.test/derpmap"
	networkErr := errors.New("network unavailable")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, networkErr
	})}

	t.Run("stale cache", func(t *testing.T) {
		cache := &recordingMapCache{entries: map[string]MapCacheEntry{
			mapURL: {
				Data:     marshalDERPMap(t, testDERPMap(41)),
				StoredAt: now.Add(-24 * time.Hour),
			},
		}}
		resolver, err := NewMapResolver(MapResolverConfig{
			HTTPClient: client,
			Cache:      cache,
			Now:        func() time.Time { return now },
			Fallback:   func() *tailcfg.DERPMap { return testDERPMap(99) },
		})
		if err != nil {
			t.Fatalf("NewMapResolver: %v", err)
		}

		result, err := resolver.Resolve(context.Background(), mapURL)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if result.Source != MapSourceStaleCache {
			t.Fatalf("source = %q, want %q", result.Source, MapSourceStaleCache)
		}
		if got := result.Map.Regions[41]; got == nil {
			t.Fatalf("resolved map does not contain region 41: %#v", result.Map)
		}
	})

	t.Run("compiled map", func(t *testing.T) {
		resolver, err := NewMapResolver(MapResolverConfig{
			HTTPClient: client,
			Now:        func() time.Time { return now },
			Fallback:   func() *tailcfg.DERPMap { return testDERPMap(43) },
		})
		if err != nil {
			t.Fatalf("NewMapResolver: %v", err)
		}

		result, err := resolver.Resolve(context.Background(), mapURL)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if result.Source != MapSourceCompiled {
			t.Fatalf("source = %q, want %q", result.Source, MapSourceCompiled)
		}
		if got := result.Map.Regions[43]; got == nil {
			t.Fatalf("resolved map does not contain region 43: %#v", result.Map)
		}
	})
}

func TestMapResolverUsesDefaultMemoryCache(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	mapURL := "https://control.example.test/derpmap"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(marshalDERPMap(t, testDERPMap(47))))),
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Fallback:   func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	first, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	first.Map.Regions[47].Nodes[0].HostName = "mutated.example.test"
	second, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if first.Source != MapSourceNetwork || second.Source != MapSourceFreshCache {
		t.Fatalf("sources = %q then %q, want %q then %q", first.Source, second.Source, MapSourceNetwork, MapSourceFreshCache)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("network calls = %d, want 1", got)
	}
	if got := second.Map.Regions[47].Nodes[0].HostName; got != "derp.example.test" {
		t.Fatalf("second hostname = %q, want isolated cached value", got)
	}
}

func TestMapResolverBoundsNetworkResponses(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", 33))),
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		MaxBytes:   32,
		Fallback:   func() *tailcfg.DERPMap { return testDERPMap(53) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceCompiled {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceCompiled)
	}
}

func TestMapResolverReportsCacheWriteFailure(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	cache := &recordingMapCache{putErr: errors.New("disk full")}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(marshalDERPMap(t, testDERPMap(59))))),
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Cache:      cache,
		Fallback:   func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceNetwork {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceNetwork)
	}
	if !result.CacheWriteFailed {
		t.Fatal("CacheWriteFailed = false, want true")
	}
}

func TestMapResolverReturnsIsolatedResults(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	cache := &recordingMapCache{entries: map[string]MapCacheEntry{
		mapURL: {
			Data:     marshalDERPMap(t, testDERPMap(61)),
			StoredAt: time.Now(),
		},
	}}
	resolver, err := NewMapResolver(MapResolverConfig{
		Cache:    cache,
		Fallback: func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	first, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	first.Map.Regions[61].Nodes[0].HostName = "mutated.example.test"
	second, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if got := second.Map.Regions[61].Nodes[0].HostName; got != "derp.example.test" {
		t.Fatalf("second hostname = %q, want original value", got)
	}
}

func TestMapResolverHonorsCallerDeadline(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient:   client,
		FetchTimeout: time.Second,
		Fallback:     func() *tailcfg.DERPMap { return &tailcfg.DERPMap{} },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = resolver.Resolve(ctx, mapURL)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Resolve error = %v, want context deadline exceeded", err)
	}
}

func TestMapResolverRejectsUnsafeMapURLs(t *testing.T) {
	t.Parallel()

	resolver, err := NewMapResolver(MapResolverConfig{})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}
	for _, rawURL := range []string{
		"file:///tmp/derpmap.json",
		"https:///derpmap",
		"https://user:secret@control.example.test/derpmap",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := resolver.Resolve(context.Background(), rawURL); err == nil {
				t.Fatalf("Resolve(%q) succeeded, want validation error", rawURL)
			}
		})
	}
}

func TestMapResolverSkipsInvalidStaleCache(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	cache := &recordingMapCache{entries: map[string]MapCacheEntry{
		mapURL: {
			Data:     []byte(`{"Regions":{}}`),
			ETag:     `"invalid"`,
			StoredAt: time.Now().Add(-24 * time.Hour),
		},
	}}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("If-None-Match"); got != "" {
			t.Fatalf("If-None-Match = %q, want empty for invalid cache", got)
		}
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Cache:      cache,
		Fallback:   func() *tailcfg.DERPMap { return testDERPMap(67) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceCompiled {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceCompiled)
	}
}

func TestMapResolverTreatsFutureCacheAsStale(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	mapURL := "https://control.example.test/derpmap"
	cache := &recordingMapCache{entries: map[string]MapCacheEntry{
		mapURL: {
			Data:     marshalDERPMap(t, testDERPMap(71)),
			ETag:     `"future"`,
			StoredAt: now.Add(time.Hour),
		},
	}}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("If-None-Match"); got != `"future"` {
			t.Fatalf("If-None-Match = %q, want %q", got, `"future"`)
		}
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Status:     "304 Not Modified",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Cache:      cache,
		Now:        func() time.Time { return now },
		Fallback:   func() *tailcfg.DERPMap { return testDERPMap(99) },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	result, err := resolver.Resolve(context.Background(), mapURL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Source != MapSourceRevalidated {
		t.Fatalf("source = %q, want %q", result.Source, MapSourceRevalidated)
	}
}

func TestMapResolverReportsEveryUnusableSource(t *testing.T) {
	t.Parallel()

	mapURL := "https://control.example.test/derpmap"
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})}
	resolver, err := NewMapResolver(MapResolverConfig{
		HTTPClient: client,
		Fallback:   func() *tailcfg.DERPMap { return &tailcfg.DERPMap{} },
	})
	if err != nil {
		t.Fatalf("NewMapResolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), mapURL)
	if err == nil {
		t.Fatal("Resolve succeeded, want all-sources error")
	}
	for _, want := range []string{"502 Bad Gateway", "no usable relay nodes"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Resolve error = %q, want it to contain %q", err, want)
		}
	}
}

func TestNewMapResolverRejectsInvalidBounds(t *testing.T) {
	t.Parallel()

	for _, cfg := range []MapResolverConfig{
		{FreshFor: -time.Second},
		{FetchTimeout: -time.Second},
		{MaxBytes: -1},
	} {
		if _, err := NewMapResolver(cfg); err == nil {
			t.Fatalf("NewMapResolver(%+v) succeeded, want validation error", cfg)
		}
	}
}

func TestMemoryMapCacheCopiesEntries(t *testing.T) {
	t.Parallel()

	cache := newMemoryMapCache()
	data := []byte("original")
	if err := cache.Put("https://example.test/map", MapCacheEntry{Data: data}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data[0] = 'X'

	first, ok := cache.Get("https://example.test/map")
	if !ok {
		t.Fatal("Get missed cached entry")
	}
	if got := string(first.Data); got != "original" {
		t.Fatalf("first data = %q, want %q", got, "original")
	}
	first.Data[0] = 'Y'
	second, ok := cache.Get("https://example.test/map")
	if !ok {
		t.Fatal("second Get missed cached entry")
	}
	if got := string(second.Data); got != "original" {
		t.Fatalf("second data = %q, want %q", got, "original")
	}
}

func TestValidateDERPMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dm      *tailcfg.DERPMap
		wantErr bool
	}{
		{name: "nil", wantErr: true},
		{name: "empty", dm: &tailcfg.DERPMap{}, wantErr: true},
		{
			name: "STUN only",
			dm: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
				1: {Nodes: []*tailcfg.DERPNode{{STUNOnly: true, HostName: "stun.example.test"}}},
			}},
			wantErr: true,
		},
		{
			name: "disabled addresses",
			dm: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
				1: {Nodes: []*tailcfg.DERPNode{{IPv4: "none", IPv6: "NONE"}}},
			}},
			wantErr: true,
		},
		{name: "hostname", dm: testDERPMap(1)},
		{
			name: "IP-only relay lacks TLS authority",
			dm: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
				1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, IPv6: "2001:db8::1"}}},
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDERPMap(tt.dm)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDERPMap() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type recordingMapCache struct {
	entries map[string]MapCacheEntry
	putErr  error
}

func (c *recordingMapCache) Get(url string) (MapCacheEntry, bool) {
	entry, ok := c.entries[url]
	return entry, ok
}

func (c *recordingMapCache) Put(url string, entry MapCacheEntry) error {
	if c.putErr != nil {
		return c.putErr
	}
	if c.entries == nil {
		c.entries = make(map[string]MapCacheEntry)
	}
	c.entries[url] = entry
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testDERPMap(regionID int) *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		regionID: {
			RegionID: regionID,
			Nodes: []*tailcfg.DERPNode{{
				Name:     "test",
				RegionID: regionID,
				HostName: "derp.example.test",
			}},
		},
	}}
}

func marshalDERPMap(t *testing.T, dm *tailcfg.DERPMap) []byte {
	t.Helper()

	data, err := json.Marshal(dm)
	if err != nil {
		t.Fatalf("marshal DERP map: %v", err)
	}
	return data
}
