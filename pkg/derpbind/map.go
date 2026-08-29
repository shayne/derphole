// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/dnsfallback"
	"tailscale.com/tailcfg"
)

const PublicDERPMapURL = "https://controlplane.tailscale.com/derpmap/default"

const (
	defaultMapFreshFor     = time.Hour
	defaultMapFetchTimeout = 5 * time.Second
	defaultMapMaxBytes     = 8 << 20
	maxTokenRegionID       = 1<<16 - 1
)

// legacyOneShotRegionIDs is frozen to the public fallback regions bundled by
// Derphole v0.18.2 (Tailscale v1.96.5). One-shot tokens may be consumed by an
// older binary, so creators must not encode a region introduced after that
// compatibility boundary.
var legacyOneShotRegionIDs = map[int]struct{}{
	1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {},
	7: {}, 8: {}, 9: {}, 10: {}, 11: {}, 12: {},
}

// MapSource describes how a DERP map was resolved.
type MapSource string

const (
	MapSourceNetwork     MapSource = "network"
	MapSourceFreshCache  MapSource = "fresh-cache"
	MapSourceRevalidated MapSource = "revalidated-cache"
	MapSourceStaleCache  MapSource = "stale-cache"
	MapSourceCompiled    MapSource = "compiled-fallback"
	MapSourceEmbedded    MapSource = "embedded-route"
)

// MapCacheEntry is the serialized form of a cached DERP map.
type MapCacheEntry struct {
	Data     []byte
	ETag     string
	StoredAt time.Time
}

// MapCache stores serialized DERP maps by their source URL.
type MapCache interface {
	Get(url string) (MapCacheEntry, bool)
	Put(url string, entry MapCacheEntry) error
}

type memoryMapCache struct {
	mu      sync.RWMutex
	entries map[string]MapCacheEntry
}

func newMemoryMapCache() *memoryMapCache {
	return &memoryMapCache{entries: make(map[string]MapCacheEntry)}
}

func (c *memoryMapCache) Get(url string) (MapCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[url]
	return cloneMapCacheEntry(entry), ok
}

func (c *memoryMapCache) Put(url string, entry MapCacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[url] = cloneMapCacheEntry(entry)
	return nil
}

func cloneMapCacheEntry(entry MapCacheEntry) MapCacheEntry {
	entry.Data = append([]byte(nil), entry.Data...)
	return entry
}

// MapResolverConfig configures a DERP map resolver.
type MapResolverConfig struct {
	HTTPClient   *http.Client
	Cache        MapCache
	Now          func() time.Time
	FreshFor     time.Duration
	FetchTimeout time.Duration
	MaxBytes     int64
	Fallback     func() *tailcfg.DERPMap
}

// MapResolver resolves DERP maps from cache, network, and compiled fallback.
type MapResolver struct {
	httpClient   *http.Client
	cache        MapCache
	now          func() time.Time
	freshFor     time.Duration
	fetchTimeout time.Duration
	maxBytes     int64
	fallback     func() *tailcfg.DERPMap
}

// MapResult records the resolved DERP map and the source that supplied it.
type MapResult struct {
	Map              *tailcfg.DERPMap
	Source           MapSource
	URL              string
	StoredAt         time.Time
	CacheWriteFailed bool
}

// NewMapResolver returns a DERP map resolver with bounded production defaults.
func NewMapResolver(cfg MapResolverConfig) (*MapResolver, error) {
	cfg = mapResolverConfigWithDefaults(cfg)
	if err := validateMapResolverConfig(cfg); err != nil {
		return nil, err
	}

	return &MapResolver{
		httpClient:   cfg.HTTPClient,
		cache:        cfg.Cache,
		now:          cfg.Now,
		freshFor:     cfg.FreshFor,
		fetchTimeout: cfg.FetchTimeout,
		maxBytes:     cfg.MaxBytes,
		fallback:     cfg.Fallback,
	}, nil
}

func mapResolverConfigWithDefaults(cfg MapResolverConfig) MapResolverConfig {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Transport: http.DefaultTransport}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Cache == nil {
		cfg.Cache = newMemoryMapCache()
	}
	if cfg.FreshFor == 0 {
		cfg.FreshFor = defaultMapFreshFor
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = defaultMapFetchTimeout
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = defaultMapMaxBytes
	}
	if cfg.Fallback == nil {
		cfg.Fallback = dnsfallback.GetDERPMap
	}
	return cfg
}

func validateMapResolverConfig(cfg MapResolverConfig) error {
	if cfg.FreshFor < 0 {
		return errors.New("DERP map cache freshness must not be negative")
	}
	if cfg.FetchTimeout < 0 {
		return errors.New("DERP map fetch timeout must not be negative")
	}
	if cfg.MaxBytes < 0 {
		return errors.New("DERP map response limit must not be negative")
	}
	return nil
}

// Resolve returns an isolated DERP map for rawURL.
func (r *MapResolver) Resolve(ctx context.Context, rawURL string) (MapResult, error) {
	if err := validateMapURL(rawURL); err != nil {
		return MapResult{}, err
	}

	cachedEntry, cachedMap, fresh := r.cachedMap(rawURL)
	if fresh {
		return MapResult{
			Map:      cachedMap,
			Source:   MapSourceFreshCache,
			URL:      rawURL,
			StoredAt: cachedEntry.StoredAt,
		}, nil
	}

	result, fetchErr := r.fetch(ctx, rawURL, cachedEntry, cachedMap)
	if fetchErr == nil {
		return result, nil
	}
	if cachedMap != nil {
		return MapResult{
			Map:      cachedMap,
			Source:   MapSourceStaleCache,
			URL:      rawURL,
			StoredAt: cachedEntry.StoredAt,
		}, nil
	}

	return r.resolveCompiledFallback(rawURL, fetchErr)
}

func (r *MapResolver) cachedMap(rawURL string) (MapCacheEntry, *tailcfg.DERPMap, bool) {
	if r.cache == nil {
		return MapCacheEntry{}, nil, false
	}
	entry, ok := r.cache.Get(rawURL)
	if !ok {
		return MapCacheEntry{}, nil, false
	}
	dm, err := decodeAndValidateMap(entry.Data)
	if err != nil {
		return MapCacheEntry{}, nil, false
	}
	return entry, dm, isFreshMapEntry(entry, r.now(), r.freshFor)
}

func (r *MapResolver) resolveCompiledFallback(rawURL string, fetchErr error) (MapResult, error) {
	fallback := r.fallback()
	if fallback == nil {
		return invalidFallbackResult(fetchErr, errors.New("compiled DERP map is unavailable"))
	}
	fallback = fallback.Clone()
	if err := validateDERPMap(fallback); err != nil {
		return invalidFallbackResult(fetchErr, err)
	}
	return MapResult{Map: fallback, Source: MapSourceCompiled, URL: rawURL}, nil
}

func invalidFallbackResult(fetchErr, fallbackErr error) (MapResult, error) {
	return MapResult{}, fmt.Errorf(
		"resolve DERP map: %w",
		errors.Join(fetchErr, fmt.Errorf("validate compiled fallback: %w", fallbackErr)),
	)
}

func (r *MapResolver) fetch(
	ctx context.Context,
	rawURL string,
	cachedEntry MapCacheEntry,
	cachedMap *tailcfg.DERPMap,
) (MapResult, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, r.fetchTimeout)
	defer cancel()

	req, err := r.newMapRequest(fetchCtx, rawURL, cachedEntry, cachedMap)
	if err != nil {
		return MapResult{}, err
	}
	res, err := r.httpClient.Do(req)
	if err != nil {
		return MapResult{}, fmt.Errorf("fetch DERP map: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusNotModified && cachedMap != nil {
		return r.revalidatedResult(rawURL, cachedEntry, cachedMap), nil
	}
	if res.StatusCode != http.StatusOK {
		return MapResult{}, fmt.Errorf("fetch DERP map: %s", res.Status)
	}

	dm, err := r.readMap(res.Body)
	if err != nil {
		return MapResult{}, err
	}
	return r.networkResult(rawURL, res.Header.Get("ETag"), dm)
}

func (r *MapResolver) newMapRequest(
	ctx context.Context,
	rawURL string,
	cachedEntry MapCacheEntry,
	cachedMap *tailcfg.DERPMap,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create DERP map request: %w", err)
	}
	if cachedMap != nil && cachedEntry.ETag != "" {
		req.Header.Set("If-None-Match", cachedEntry.ETag)
	}
	return req, nil
}

func (r *MapResolver) revalidatedResult(
	rawURL string,
	cachedEntry MapCacheEntry,
	cachedMap *tailcfg.DERPMap,
) MapResult {
	now := r.now().UTC()
	cachedEntry.StoredAt = now
	result := MapResult{Map: cachedMap, Source: MapSourceRevalidated, URL: rawURL, StoredAt: now}
	if err := r.cache.Put(rawURL, cachedEntry); err != nil {
		result.CacheWriteFailed = true
	}
	return result
}

func (r *MapResolver) readMap(src io.Reader) (*tailcfg.DERPMap, error) {
	data, err := io.ReadAll(io.LimitReader(src, r.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read DERP map: %w", err)
	}
	if int64(len(data)) > r.maxBytes {
		return nil, fmt.Errorf("read DERP map: response exceeds %d bytes", r.maxBytes)
	}
	return decodeAndValidateMap(data)
}

func (r *MapResolver) networkResult(rawURL, etag string, dm *tailcfg.DERPMap) (MapResult, error) {
	now := r.now().UTC()
	result := MapResult{
		Map:      dm,
		Source:   MapSourceNetwork,
		URL:      rawURL,
		StoredAt: now,
	}
	if r.cache != nil {
		canonicalData, err := json.Marshal(dm)
		if err != nil {
			return MapResult{}, fmt.Errorf("encode validated DERP map: %w", err)
		}
		entry := MapCacheEntry{
			Data:     canonicalData,
			ETag:     etag,
			StoredAt: now,
		}
		if err := r.cache.Put(rawURL, entry); err != nil {
			result.CacheWriteFailed = true
		}
	}
	return result, nil
}

func validateMapURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse DERP map URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("DERP map URL scheme %q is not supported", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("DERP map URL must include a host")
	}
	if parsed.User != nil {
		return errors.New("DERP map URL must not include user information")
	}
	return nil
}

func isFreshMapEntry(entry MapCacheEntry, now time.Time, freshFor time.Duration) bool {
	age := now.Sub(entry.StoredAt)
	return !entry.StoredAt.IsZero() && age >= 0 && age < freshFor
}

func decodeAndValidateMap(data []byte) (*tailcfg.DERPMap, error) {
	var dm tailcfg.DERPMap
	if err := json.Unmarshal(data, &dm); err != nil {
		return nil, fmt.Errorf("decode DERP map: %w", err)
	}
	if err := validateDERPMap(&dm); err != nil {
		return nil, err
	}
	return &dm, nil
}

func validateDERPMap(dm *tailcfg.DERPMap) error {
	if dm == nil {
		return errors.New("DERP map is nil")
	}
	usable := false
	for regionID, region := range dm.Regions {
		regionUsable, err := validateDERPRegion(regionID, region)
		if err != nil {
			return err
		}
		usable = usable || regionUsable
	}
	if usable {
		return nil
	}
	return errors.New("DERP map contains no usable relay nodes")
}

func validateDERPRegion(regionID int, region *tailcfg.DERPRegion) (bool, error) {
	if region == nil {
		return false, nil
	}
	if regionID <= 0 || regionID > maxTokenRegionID {
		return false, fmt.Errorf("DERP map region ID %d is outside token range", regionID)
	}
	if region.RegionID != regionID {
		return false, fmt.Errorf("DERP map region key %d does not match region ID %d", regionID, region.RegionID)
	}
	usable := false
	for _, node := range region.Nodes {
		nodeUsable, err := validateDERPNode(node, regionID)
		if err != nil {
			return false, err
		}
		usable = usable || nodeUsable
	}
	return usable, nil
}

func validateDERPNode(node *tailcfg.DERPNode, regionID int) (bool, error) {
	if node == nil {
		return false, nil
	}
	if node.RegionID != regionID {
		return false, fmt.Errorf("DERP node %q region ID %d does not match region %d", node.Name, node.RegionID, regionID)
	}
	if !validDERPPort(node.DERPPort) {
		return false, fmt.Errorf("DERP node %q has invalid DERP port %d", node.Name, node.DERPPort)
	}
	if !validSTUNPort(node.STUNPort) {
		return false, fmt.Errorf("DERP node %q has invalid STUN port %d", node.Name, node.STUNPort)
	}
	if !validDERPAddress(node.IPv4, true) {
		return false, fmt.Errorf("DERP node %q has invalid IPv4 address %q", node.Name, node.IPv4)
	}
	if !validDERPAddress(node.IPv6, false) {
		return false, fmt.Errorf("DERP node %q has invalid IPv6 address %q", node.Name, node.IPv6)
	}
	if !node.STUNOnly && !validDERPHostName(node.HostName) {
		return false, fmt.Errorf("DERP node %q has invalid TLS authority %q", node.Name, node.HostName)
	}
	return usableDERPNode(node, regionID), nil
}

// CompiledMap returns an isolated, validated copy of the DERP map bundled with
// the current Tailscale dependency.
func CompiledMap() (*tailcfg.DERPMap, error) {
	dm := dnsfallback.GetDERPMap()
	if dm == nil {
		return nil, errors.New("compiled DERP map is unavailable")
	}
	dm = dm.Clone()
	if err := validateDERPMap(dm); err != nil {
		return nil, fmt.Errorf("validate compiled DERP map: %w", err)
	}
	return dm, nil
}

func validDERPPort(port int) bool {
	return port >= 0 && port <= 1<<16-1
}

func validSTUNPort(port int) bool {
	return port >= -1 && port <= 1<<16-1
}

func validDERPAddress(address string, wantIPv4 bool) bool {
	if address == "" || strings.EqualFold(address, "none") {
		return true
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	return parsed.Is4() == wantIPv4
}

func validDERPHostName(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@?#") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !validDERPHostLabel(label) {
			return false
		}
	}
	return true
}

func validDERPHostLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if !validDERPHostCharacter(ch) {
			return false
		}
	}
	return true
}

func validDERPHostCharacter(ch rune) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-'
}

func usableDERPNode(node *tailcfg.DERPNode, regionID int) bool {
	return node != nil &&
		!node.STUNOnly &&
		node.RegionID == regionID &&
		validDERPHostName(node.HostName) &&
		validDERPPort(node.DERPPort) &&
		validDERPAddress(node.IPv4, true) &&
		validDERPAddress(node.IPv6, false)
}

// NodeForRegion returns the first dialable relay in exactly regionID. It never
// substitutes a node from another region.
func NodeForRegion(dm *tailcfg.DERPMap, regionID int) *tailcfg.DERPNode {
	if dm == nil || regionID == 0 {
		return nil
	}
	region := dm.Regions[regionID]
	if region == nil || region.RegionID != regionID {
		return nil
	}
	for _, node := range region.Nodes {
		if usableDERPNode(node, regionID) {
			return node
		}
	}
	return nil
}

// FirstNode returns the first dialable relay in sorted region order.
func FirstNode(dm *tailcfg.DERPMap) *tailcfg.DERPNode {
	if dm == nil {
		return nil
	}
	for _, regionID := range dm.RegionIDs() {
		if node := NodeForRegion(dm, regionID); node != nil {
			return node
		}
	}
	return nil
}

// OneShotCompatibleMap returns an isolated public map restricted to the
// frozen region IDs understood by the pre-live-map one-shot consumers.
func OneShotCompatibleMap(dm *tailcfg.DERPMap) (*tailcfg.DERPMap, error) {
	if err := validateDERPMap(dm); err != nil {
		return nil, err
	}
	compatible := dm.Clone()
	for regionID := range compatible.Regions {
		if _, ok := legacyOneShotRegionIDs[regionID]; !ok || NodeForRegion(compatible, regionID) == nil {
			delete(compatible.Regions, regionID)
		}
	}
	if FirstNode(compatible) == nil {
		return nil, errors.New("DERP map contains no legacy-compatible relay regions")
	}
	return compatible, nil
}

var (
	defaultMapResolverOnce   sync.Once
	defaultMapResolver       *MapResolver
	defaultMapResolverErr    error
	ephemeralMapResolverOnce sync.Once
	ephemeralMapResolver     *MapResolver
	ephemeralMapResolverErr  error
)

// ResolveMap resolves a DERP map using the process-wide persistent cache.
func ResolveMap(ctx context.Context, url string) (MapResult, error) {
	if url != PublicDERPMapURL {
		ephemeralMapResolverOnce.Do(func() {
			ephemeralMapResolver, ephemeralMapResolverErr = NewMapResolver(MapResolverConfig{
				Cache:    newMemoryMapCache(),
				Fallback: dnsfallback.GetDERPMap,
			})
		})
		if ephemeralMapResolverErr != nil {
			return MapResult{}, ephemeralMapResolverErr
		}
		return ephemeralMapResolver.Resolve(ctx, url)
	}
	defaultMapResolverOnce.Do(func() {
		defaultMapResolver, defaultMapResolverErr = NewMapResolver(MapResolverConfig{
			Cache:    newDefaultMapCache(),
			Fallback: dnsfallback.GetDERPMap,
		})
	})
	if defaultMapResolverErr != nil {
		return MapResult{}, defaultMapResolverErr
	}
	return defaultMapResolver.Resolve(ctx, url)
}

// FetchMap resolves a DERP map while preserving the legacy map-only API.
func FetchMap(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
	result, err := ResolveMap(ctx, url)
	if err != nil {
		return nil, err
	}
	return result.Map, nil
}
