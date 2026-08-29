# Tailcat Shared Transport Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the supported Go and Tailscale baseline, identify DERP traffic as Derphole, resolve public DERP maps through a bounded live-and-cached pipeline, and select a nearby relay only when issuing new one-shot tokens.

**Architecture:** `pkg/derpbind` owns dependency-facing DERP behavior: application attribution, map resolution, persistent caching, structural validation, cloning, and region measurement. `pkg/session` and `pkg/derphole/webrelay` consume detached resolver results and preserve the existing custom-route and durable-token rules. Token encoding and all production data planes remain unchanged.

**Tech Stack:** Go 1.26.6, `tailscale.com` v1.102.3, standard-library HTTP/JSON/filesystem primitives, Tailscale `netcheck`, existing telemetry and test harnesses, GitButler.

**Spec:** `docs/superpowers/specs/2026-08-29-tailcat-derived-transport-modernization-design.md`

## Global Constraints

- Keep existing Derphole v5/v6 and Derptun dts1/dts2/DT1/DT2 token and wire encodings byte-compatible.
- Keep custom DERP routes self-contained; they never contact the public map resolver or fall back to public infrastructure.
- Keep current durable Derptun credentials deterministic when `BootstrapRegion == 0`; nearest-region selection applies only while issuing a new public one-shot token.
- Use `derphole` as the single `DERPAppName`/`AppName` for every product.
- Bound public map fetches to five seconds and 8 MiB; bound the disk envelope to 16 MiB.
- Create the cache directory with mode 0700 and the cache file with mode 0600; use fsync, close, and same-directory atomic rename.
- Never print map URLs, ETags, raw STUN addresses, tokens, private keys, or bearer secrets in diagnostics.
- Do not add a new third-party dependency, `replace` directive, pseudo-version, general utility package, or mutable package-global test hook.
- Use table-driven tests with named cases. Use `testing/synctest` for timer behavior when it makes the test deterministic.
- Run focused tests after each task, `mise run check:fast` during iteration, and the exhaustive `mise run check` plus approved smoke gates before landing.

---

### Task 1: Upgrade the dependency baseline and attribute DERP clients

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `pkg/derpbind/client.go:17-24,91-137`
- Modify: `pkg/derpbind/derpbind_test.go`

**Interfaces:**
- Produces: `const derpbind.AppName = "derphole"`
- Produces: `newDERPHTTPClient(key.NodePrivate, string, logger.Logf, *netmon.Monitor) (*derphttp.Client, error)`
- Preserves: `NewClient` and `NewClientWithPrivateKey` signatures

- [ ] **Step 1: Add the attribution test before changing production code**

Add this focused test in `pkg/derpbind/derpbind_test.go`:

```go
func TestNewDERPHTTPClientSetsAppName(t *testing.T) {
	client, err := newDERPHTTPClient(
		key.NewNode(),
		"https://derp.example.test/derp",
		logger.Discard,
		netmon.NewStatic(),
	)
	if err != nil {
		t.Fatalf("newDERPHTTPClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if got, want := client.AppName, AppName; got != want {
		t.Fatalf("AppName = %q, want %q", got, want)
	}
}
```

Add the required `tailscale.com/net/netmon`, `tailscale.com/types/key`, and
`tailscale.com/types/logger` imports if the test file does not already have
them.

- [ ] **Step 2: Run the test and verify the missing seam**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run TestNewDERPHTTPClientSetsAppName -count=1
```

Expected: compilation fails because `newDERPHTTPClient` and `AppName` do not
exist.

- [ ] **Step 3: Upgrade only the explicitly approved dependency set**

Run:

```bash
mise exec -- go mod edit -go=1.26.6
mise exec -- go get tailscale.com@v1.102.3 golang.org/x/crypto@v0.55.0 github.com/pion/dtls/v3@v3.1.4 github.com/pion/stun/v3@v3.1.5
mise exec -- go mod tidy
mise exec -- go mod verify
```

Inspect `go.mod` and `go.sum`. Accept higher indirect versions selected by
Minimal Version Selection, but reject a `replace` directive or an unexpected
new direct dependency.

- [ ] **Step 4: Add the application-name seam before `Connect`**

In `pkg/derpbind/client.go`, add:

```go
const AppName = "derphole"

func newDERPHTTPClient(
	priv key.NodePrivate,
	serverURL string,
	logf logger.Logf,
	netMon *netmon.Monitor,
) (*derphttp.Client, error) {
	client, err := derphttp.NewClient(priv, serverURL, logf, netMon)
	if err != nil {
		return nil, err
	}
	client.AppName = AppName
	return client, nil
}
```

Replace the direct `derphttp.NewClient` call in `newClientWithPrivateKey` with
`newDERPHTTPClient`. Keep `client.AppName = AppName` inside the helper so every
future direct client receives attribution before `Connect`.

- [ ] **Step 5: Verify compilation, attribution, and reachable vulnerabilities**

Run:

```bash
mise exec -- go test ./pkg/derpbind -count=1
mise run vuln
mise run check:fast
```

Expected: the focused package passes, all products compile, and
`govulncheck` no longer reports GO-2026-6303, GO-2026-6165, or GO-2026-6163.

- [ ] **Step 6: Create a dependency checkpoint with GitButler**

Run `but diff`, copy the whole-file IDs printed for `go.mod`, `go.sum`,
`pkg/derpbind/client.go`, and `pkg/derpbind/derpbind_test.go`, then pass those
exact IDs to `but commit tailcat-foundation -c` with message
`deps: update Tailscale transport baseline`.

Read the returned workspace state and leave the approved research/spec/plan
documents uncommitted until their own documentation checkpoint.

### Task 2: Implement the bounded in-memory map resolver

**Files:**
- Replace: `pkg/derpbind/map.go`
- Create: `pkg/derpbind/map_test.go`
- Modify: `pkg/derpbind/derpbind_test.go` (remove the two old `FetchMap` tests after equivalent coverage exists)

**Interfaces:**
- Produces: `MapSource`, `MapCacheEntry`, `MapCache`, `MapResolverConfig`, `MapResolver`, and `MapResult` exactly as declared in the spec
- Produces: `NewMapResolver(MapResolverConfig) (*MapResolver, error)`
- Produces: `(*MapResolver).Resolve(context.Context, string) (MapResult, error)`
- Consumes later: disk and tiered caches implement `MapCache`

- [ ] **Step 1: Write resolver contract tests**

Create `pkg/derpbind/map_test.go` with table-driven tests covering these exact
observable cases:

```go
func TestMapResolverResolve(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		cache      MapCacheEntry
		now        time.Time
		wantSource MapSource
		wantCalls  int
	}{
		{name: "fresh cache avoids network", cache: validCacheEntry(time.Hour), wantSource: MapSourceFreshCache, wantCalls: 0},
		{name: "network replaces stale cache", statusCode: http.StatusOK, body: validMapJSON(7), cache: validCacheEntry(2 * time.Hour), wantSource: MapSourceNetwork, wantCalls: 1},
		{name: "not modified refreshes stale cache", statusCode: http.StatusNotModified, cache: validCacheEntryWithETag(2 * time.Hour, `"map-1"`), wantSource: MapSourceRevalidated, wantCalls: 1},
		{name: "network failure uses stale cache", statusCode: http.StatusBadGateway, cache: validCacheEntry(2 * time.Hour), wantSource: MapSourceStaleCache, wantCalls: 1},
		{name: "network failure uses compiled map", statusCode: http.StatusBadGateway, wantSource: MapSourceCompiled, wantCalls: 1},
	}
	// Each subtest constructs a resolver with an httptest server, a memory
	// cache, an injected Now, and a one-region fallback, then asserts source,
	// request count, region ID, and conditional If-None-Match behavior.
}
```

Also add named tests for:

- URL rejection for missing host, userinfo, and non-HTTP schemes;
- exactly 8 MiB accepted and 8 MiB plus one rejected;
- an earlier caller deadline not extended by `FetchTimeout`;
- empty, STUN-only, and hostless maps rejected;
- future-dated cache treated as stale;
- cache `Put` failure reflected only in `CacheWriteFailed`;
- invalid stale cache skipped in favor of compiled fallback;
- no usable network, cache, or fallback returning an error;
- mutation of a returned region, node, and node slice not changing the next
  result.

Use a local `memoryMapCache` in the production package rather than adding a
test-only mock interface implementation.

- [ ] **Step 2: Run the new tests and verify the API is absent**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run 'TestMapResolver|TestValidateDERPMap' -count=1
```

Expected: compilation fails on the missing resolver types.

- [ ] **Step 3: Define the resolver types and normalized configuration**

In `pkg/derpbind/map.go`, define the spec's exported types and these private
defaults:

```go
const (
	PublicDERPMapURL  = "https://controlplane.tailscale.com/derpmap/default"
	defaultMapFreshFor = time.Hour
	defaultMapTimeout  = 5 * time.Second
	defaultMapMaxBytes = int64(8 << 20)
)

type MapResolver struct {
	httpClient   *http.Client
	cache        MapCache
	now          func() time.Time
	freshFor     time.Duration
	fetchTimeout time.Duration
	maxBytes     int64
	fallback     func() *tailcfg.DERPMap
}
```

`NewMapResolver` must reject negative freshness, non-positive fetch timeout,
non-positive byte bound, and a nil fallback. A nil `HTTPClient` becomes a
dedicated `&http.Client{Transport: http.DefaultTransport}`. A nil cache becomes
a new in-memory URL-keyed cache. A nil `Now` becomes `time.Now`.

- [ ] **Step 4: Implement cloning, decoding, and structural validation**

Add private helpers with these signatures:

```go
func decodeDERPMap(data []byte) (*tailcfg.DERPMap, error)
func validateDERPMap(dm *tailcfg.DERPMap) error
func cloneCacheEntry(entry MapCacheEntry) MapCacheEntry
func compiledMapResult(url string, fallback func() *tailcfg.DERPMap) (MapResult, error)
```

`validateDERPMap` succeeds only when at least one region contains a non-nil,
non-`STUNOnly` node with `HostName != ""`, `IPv4 != ""`, or `IPv6 != ""`.
`decodeDERPMap` uses `json.Unmarshal`, validates the result, and returns it.
`cloneCacheEntry` copies `Data`. `compiledMapResult` calls the fallback,
clones it with `DERPMap.Clone`, validates the clone, and records
`MapSourceCompiled`.

- [ ] **Step 5: Implement the exact resolver state machine**

`Resolve` must:

1. parse and validate the URL;
2. clone and decode any cached entry;
3. return a newly decoded fresh entry without HTTP;
4. derive `context.WithTimeout(ctx, r.fetchTimeout)`;
5. send GET and conditional `If-None-Match` only for a valid stale entry;
6. handle 304 by refreshing `StoredAt` and returning revalidated cache;
7. handle 200 through `io.LimitReader(body, r.maxBytes+1)`;
8. re-encode and cache the validated typed map, then return an isolated map;
9. fall back to a separately decoded stale entry for all request/status/size/decode failures;
10. fall back to a cloned compiled map;
11. return a joined contextual error only when every source is unusable.

Use one private helper to avoid duplicating stale/compiled fallback:

```go
func (r *MapResolver) fallbackResult(
	url string,
	stale MapCacheEntry,
	hasStale bool,
	cause error,
) (MapResult, error)
```

Do not log inside the resolver. Do not send `Tailcat-Mode` or expose ETags in
`MapResult`.

- [ ] **Step 6: Make the in-memory cache concurrency-safe and copy-safe**

Add:

```go
type memoryMapCache struct {
	mu      sync.RWMutex
	entries map[string]MapCacheEntry
}

func newMemoryMapCache() *memoryMapCache
func (c *memoryMapCache) Get(url string) (MapCacheEntry, bool)
func (c *memoryMapCache) Put(url string, entry MapCacheEntry) error
```

Both methods clone `Data`. `Get` uses `RLock`; `Put` uses `Lock`. Do not return
the internal map or byte slice.

- [ ] **Step 7: Run resolver tests and race coverage**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run 'TestMapResolver|TestValidateDERPMap' -count=1
mise exec -- go test -race ./pkg/derpbind -run TestMapResolver -count=1
mise run check:fast
```

Expected: all resolver cases pass and the race detector reports no findings.

- [ ] **Step 8: Checkpoint the resolver core**

Run `but diff`, copy only the file or hunk IDs for `pkg/derpbind/map.go`,
`pkg/derpbind/map_test.go`, and the equivalent old-test removal in
`pkg/derpbind/derpbind_test.go`, then pass those exact IDs to `but commit
tailcat-foundation` with message `derp: add bounded map resolver`.

### Task 3: Add the bounded persistent map cache

**Files:**
- Create: `pkg/derpbind/map_cache.go`
- Create: `pkg/derpbind/map_cache_test.go`
- Modify: `pkg/derpbind/map.go`

**Interfaces:**
- Produces: private `diskMapCache` and `tieredMapCache`, both satisfying `MapCache`
- Produces: `newDefaultMapCache() MapCache`
- Consumes: `MapCacheEntry`

- [ ] **Step 1: Write disk-cache behavior tests**

Create named tests that use `t.TempDir()` and a cache path inside it:

```go
func TestDiskMapCacheRoundTrip(t *testing.T)
func TestDiskMapCacheTreatsInvalidFilesAsMisses(t *testing.T)
func TestDiskMapCacheRejectsOversizedEnvelope(t *testing.T)
func TestDiskMapCacheWritesAtomicallyWithPrivateModes(t *testing.T)
func TestDiskMapCacheEvictsOldestEntries(t *testing.T)
func TestTieredMapCachePromotesDiskHitToMemory(t *testing.T)
```

The invalid-file table must include missing, truncated JSON, unknown version,
and 16 MiB plus one byte. The mode test asserts 0700 on the created directory
and 0600 on the completed file on Unix. The atomicity test injects a rename
failure through an unexported `writeFile` helper parameter rather than a
mutable package global.

- [ ] **Step 2: Run the tests and verify the cache types are absent**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run 'Test(Disk|Tiered)MapCache' -count=1
```

Expected: compilation fails on the missing cache constructors.

- [ ] **Step 3: Define the versioned disk envelope**

In `pkg/derpbind/map_cache.go`, add:

```go
const (
	diskMapCacheVersion = 2
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
```

`diskMapCache` stores only its explicit path and a process-local mutex. Its
constructor returns a concrete pointer and performs no I/O.

- [ ] **Step 4: Implement bounded reads as cache misses**

`(*diskMapCache).Get` locks, opens the file, reads through a 16 MiB plus one
limit, and returns a miss for every read/decode/version/size failure. It clones
the returned bytes. It does not surface cache corruption as a session error.

- [ ] **Step 5: Implement eviction and atomic durable writes**

`Put` must:

1. lock and load the last complete envelope, treating failure as empty;
2. clone and insert the requested entry;
3. sort entry URLs by `StoredAt` ascending, then URL ascending;
4. repeatedly evict the oldest entry until the encoded envelope is at most 16 MiB;
5. return nil without persisting if the new entry itself cannot fit;
6. `MkdirAll(dir, 0o700)` and `Chmod(dir, 0o700)`;
7. create a same-directory temporary file, chmod 0600, write all bytes, `Sync`, and `Close`;
8. rename the temporary file over the target;
9. remove the temporary file on every pre-rename failure.

Keep the write sequence in:

```go
func writeDiskMapCache(path string, data []byte) error
```

Tests exercise failure cleanup through a private function that accepts
filesystem operations as parameters; production calls the ordinary wrapper.

- [ ] **Step 6: Implement the memory-plus-disk tier**

Add:

```go
type tieredMapCache struct {
	memory *memoryMapCache
	disk   *diskMapCache
}
```

`Get` checks memory, then disk, and promotes a disk hit to memory. `Put` always
updates memory, attempts disk, and returns only the disk error so
`MapResult.CacheWriteFailed` can report degraded persistence.

`newDefaultMapCache` calls `os.UserCacheDir`. If it fails, return memory only;
otherwise use `<user-cache>/derphole/derpmap-cache-v2.json`. Do not read HOME or
invent another path.

- [ ] **Step 7: Verify cache behavior and resolver integration**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run 'Test(Disk|Tiered)MapCache|TestMapResolver' -count=1
mise exec -- go test -race ./pkg/derpbind -run 'Test(Disk|Tiered)MapCache|TestMapResolver' -count=1
mise run check:fast
```

- [ ] **Step 8: Checkpoint persistent caching**

Run `but diff`, copy the IDs for `pkg/derpbind/map_cache.go`,
`pkg/derpbind/map_cache_test.go`, and the default-cache hunk in
`pkg/derpbind/map.go`, then pass those exact IDs to `but commit
tailcat-foundation` with message `derp: persist validated relay maps`.

### Task 4: Add the process-wide resolver and compatibility facade

**Files:**
- Modify: `pkg/derpbind/map.go`
- Modify: `pkg/derpbind/map_test.go`
- Modify: `pkg/probe/discovery.go:31-36,124-139`
- Modify: `pkg/probe/discovery_test.go:43-88`

**Interfaces:**
- Produces: `ResolveMap(context.Context, string) (MapResult, error)`
- Preserves: `FetchMap(context.Context, string) (*tailcfg.DERPMap, error)`
- Preserves: `probe.DiscoverCandidates` behavior

- [ ] **Step 1: Write facade and copy-isolation tests**

Add tests that replace no package globals. Construct an explicit resolver for
behavior tests, and add one smoke-level test that calls `FetchMap` with a local
HTTP fixture. Assert that `FetchMap` returns only `result.Map` and that mutating
one explicit resolver result does not affect a later result.

- [ ] **Step 2: Implement lazy default initialization**

Add one process-wide resolver initialized through `sync.Once`:

```go
var (
	defaultMapResolverOnce sync.Once
	defaultMapResolver     *MapResolver
	defaultMapResolverErr  error
)

func ResolveMap(ctx context.Context, url string) (MapResult, error) {
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

func FetchMap(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
	result, err := ResolveMap(ctx, url)
	if err != nil {
		return nil, err
	}
	return result.Map, nil
}
```

Do not special-case the public URL to return `dnsfallback` before attempting
the cache/network algorithm.

- [ ] **Step 3: Keep probe discovery on the compatibility facade**

Leave `pkg/probe` consuming `derpbind.FetchMap`; update its test fixture only
as required by the dependency upgrade. Candidate discovery does not need map
source metadata.

- [ ] **Step 4: Verify all current `FetchMap` consumers**

Run:

```bash
mise exec -- go test ./pkg/derpbind ./pkg/probe -count=1
mise run check:fast
```

- [ ] **Step 5: Amend the resolver checkpoint**

Run `but diff`, copy the Task 4 file or hunk IDs, and amend them into the
resolver-core checkpoint rather than creating a tiny facade commit. Use `but
status -fv` to obtain the current resolver commit ID, then pass that commit ID
and the copied change IDs to `but amend`.

### Task 5: Thread map provenance through session bootstrap

**Files:**
- Modify: `pkg/session/derp_route.go`
- Modify: `pkg/session/derp_route_test.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_attach.go`
- Modify only where compilation requires: session tests that replace `fetchSessionDERPMap`

**Interfaces:**
- Produces: `derpBootstrap.mapSource derpbind.MapSource`
- Produces: `derpBootstrap.mapStoredAt time.Time`
- Produces: `emitDERPMapDebug(*telemetry.Emitter, derpBootstrap)`
- Preserves: deterministic `resolveDERPBootstrap` selection for token consumers

- [ ] **Step 1: Convert bootstrap tests to resolver results**

Rename the injectable package variable to:

```go
var resolveSessionDERPMap = derpbind.ResolveMap
```

Update tests to return:

```go
derpbind.MapResult{
	Map:      dm,
	Source:   derpbind.MapSourceNetwork,
	URL:      publicDERPMapURL(),
	StoredAt: now,
}, nil
```

Add assertions that public results retain source and stored time, custom
results use `MapSourceEmbedded`, and invalid custom routes never invoke the
public resolver.

- [ ] **Step 2: Add the redacted diagnostics test**

Add a table-driven test for `emitDERPMapDebug`:

```go
tests := []struct {
	name string
	boot derpBootstrap
	want string
}{
	{name: "network", boot: derpBootstrap{node: node7, mapSource: derpbind.MapSourceNetwork}, want: "derp-map-source=network region=7\n"},
	{name: "stale cache", boot: derpBootstrap{node: node7, mapSource: derpbind.MapSourceStaleCache, mapStoredAt: now.Add(-74 * time.Minute)}, want: "derp-map-source=stale-cache region=7 age=1h14m0s\n"},
	{name: "embedded route omitted", boot: derpBootstrap{node: node900, mapSource: derpbind.MapSourceEmbedded}, want: ""},
}
```

Use an injected `now time.Time` parameter in the private formatting helper so
the age assertion is deterministic. Assert that output contains neither a
fixture URL nor ETag canary.

- [ ] **Step 3: Update `derpBootstrap` and public resolution**

Change the struct to:

```go
type derpBootstrap struct {
	route       derpbind.Route
	dm          *tailcfg.DERPMap
	node        *tailcfg.DERPNode
	serverURL   string
	mapSource   derpbind.MapSource
	mapStoredAt time.Time
	selection   derpbind.RegionSelection
}
```

For public resolution, call `resolveSessionDERPMap`, select the requested
region using the existing deterministic `firstDERPNode`, and copy `Source` and
`StoredAt`. For custom routes, set `MapSourceEmbedded`; do not call the public
resolver.

- [ ] **Step 4: Emit map metadata at the existing client-open seam**

Call `emitDERPMapDebug` beside `emitDERPRouteDebug` in
`openSessionDERPClient`. Emit only source, region ID, and non-negative rounded
age for cached sources. Never emit `MapResult.URL`.

- [ ] **Step 5: Verify session compatibility**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestDERPBootstrap|TestDERPMapDebug|TestCustomDERPRoute' -count=1
mise exec -- go test ./pkg/session -run 'TestDerptun|TestIssue|TestAttach' -count=1
mise run check:fast
```

- [ ] **Step 6: Checkpoint session integration**

Run `but diff`, copy only the session-bootstrap and matching test change IDs,
then pass those exact IDs to `but commit tailcat-foundation` with message
`session: expose DERP map provenance`.

### Task 6: Use the same resolver in web relay

**Files:**
- Modify: `pkg/derphole/webrelay/relay.go:272-340,1921-1957`
- Modify: `pkg/derphole/webrelay/relay_test.go`
- Modify: `cmd/derphole-web/main.go` only if trace plumbing requires it

**Interfaces:**
- Produces: private `webRelayBootstrap` mirroring non-secret session bootstrap metadata
- Preserves: `NewOffer(context.Context) (*Offer, string, error)`
- Preserves: custom route isolation and token encoding

- [ ] **Step 1: Add public, stale-cache, and custom-route tests**

Replace `fetchWebRelayDERPMap` with:

```go
var resolveWebRelayDERPMap = derpbind.ResolveMap
```

Tests return explicit `MapResult` values and assert public source propagation,
custom `MapSourceEmbedded`, selected node/server URL, and no public resolver
call for custom routes.

- [ ] **Step 2: Introduce the private bootstrap value**

Add:

```go
type webRelayBootstrap struct {
	route       derpbind.Route
	dm          *tailcfg.DERPMap
	node        *tailcfg.DERPNode
	serverURL   string
	mapSource   derpbind.MapSource
	mapStoredAt time.Time
	selection   derpbind.RegionSelection
}
```

Change `resolveWebRelayDERP` to return this concrete private type. Public mode
uses `ResolveMap`; custom mode builds from `Route.DERPMap` and records
`MapSourceEmbedded`.

- [ ] **Step 3: Store metadata on offers and emit it through existing trace callbacks**

Add the bootstrap metadata to `Offer`. On the first `Send` trace callback,
emit the same redacted map-source and region-selection lines used by sessions.
Do not change standard status or progress output, and do not add a logger to
the library.

- [ ] **Step 4: Verify browser/web-relay paths**

Run:

```bash
mise exec -- go test ./pkg/derphole/webrelay -run 'Test(NewOffer|ResolveWebRelayDERP|WebRelayBootstrap)' -count=1
mise exec -- go test ./pkg/derphole/webrelay -count=1
mise run check:fast
```

- [ ] **Step 5: Checkpoint resolver consolidation**

Run `but diff`, copy the web-relay file IDs, then pass those exact IDs to `but
commit tailcat-foundation` with message `webrelay: share DERP map resolution`.

### Task 7: Implement deterministic nearest-region selection

**Files:**
- Create: `pkg/derpbind/region.go`
- Create: `pkg/derpbind/region_native.go`
- Create: `pkg/derpbind/region_js.go`
- Create: `pkg/derpbind/region_test.go`

**Interfaces:**
- Produces: `RegionSelection`
- Produces: `PickRegion(context.Context, *tailcfg.DERPMap) (RegionSelection, error)`
- Produces privately: `pickRegion(context.Context, *tailcfg.DERPMap, regionMeasurer) (RegionSelection, error)`

- [ ] **Step 1: Write deterministic selector tests**

Use a private injected function, not a mutable global:

```go
type regionMeasurer func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error)
```

Add named cases proving:

- lowest positive latency wins;
- equal latency chooses lower region ID;
- latencies for absent regions are ignored;
- zero and negative latency are ignored;
- measurement error returns the first structurally usable sorted region with
  `Measured == false` and no error;
- no reported latency returns deterministic fallback;
- nil/invalid/no-relay map returns an error;
- the input map is not mutated.

- [ ] **Step 2: Run tests and verify the API is absent**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run TestPickRegion -count=1
```

Expected: compilation fails on the missing selector.

- [ ] **Step 3: Implement the platform-independent decision function**

In `region.go`, define `RegionSelection`, `regionMeasurer`, and
`pickRegion`. First validate the map and compute the first usable region in
sorted `RegionIDs` order. Call the measurer. Select only positive latencies
whose region still contains a usable relay node. On measurement error or no
usable latency, return the deterministic region with `Measured: false` and
zero latency. Return an error only when the map has no usable relay.

- [ ] **Step 4: Implement native netcheck measurement**

In `region_native.go` with `//go:build !js`, implement:

```go
func PickRegion(ctx context.Context, dm *tailcfg.DERPMap) (RegionSelection, error) {
	return pickRegion(ctx, dm, func(ctx context.Context, dm *tailcfg.DERPMap) (map[int]time.Duration, error) {
		client := &netcheck.Client{
			NetMon: netmon.NewStatic(),
			Logf:   logger.Discard,
		}
		if err := client.Standalone(ctx, ":0"); err != nil {
			return nil, fmt.Errorf("start netcheck: %w", err)
		}
		report, err := client.GetReport(ctx, dm, &netcheck.GetReportOpts{})
		if err != nil {
			return nil, fmt.Errorf("measure DERP regions: %w", err)
		}
		return report.RegionLatency, nil
	})
}
```

Ensure any netmonitor/resource returned or owned by the updated upstream API
is closed according to v1.102.3's actual signature. Do not log the report.

- [ ] **Step 5: Implement the js/wasm deterministic fallback**

In `region_js.go` with `//go:build js`, call `pickRegion` with a measurer that
returns no latencies. Browser builds therefore select the first valid region
without attempting raw UDP.

- [ ] **Step 6: Verify native and wasm compilation**

Run:

```bash
mise exec -- go test ./pkg/derpbind -run TestPickRegion -count=1
wasm_test_dir=$(mktemp -d)
mise exec -- env GOOS=js GOARCH=wasm go test -c -o "$wasm_test_dir/derpbind.test.wasm" ./pkg/derpbind
rm "$wasm_test_dir/derpbind.test.wasm"
rmdir "$wasm_test_dir"
mise run check:fast
```

- [ ] **Step 7: Checkpoint region selection**

Run `but diff`, copy the four region file IDs, then pass those exact IDs to
`but commit tailcat-foundation` with message `derp: select nearby one-shot
relay`.

### Task 8: Apply nearest selection only while issuing one-shot tokens

**Files:**
- Modify: `pkg/session/derp_route.go`
- Modify: `pkg/session/derp_route_test.go`
- Modify: `pkg/session/external.go:147-204`
- Modify: `pkg/session/external_attach.go:77-130`
- Modify: `pkg/derphole/webrelay/relay.go:272-340`
- Modify matching tests in `pkg/session` and `pkg/derphole/webrelay`

**Interfaces:**
- Produces privately: `resolveNewDERPBootstrap(context.Context, derpbind.Route, string) (derpBootstrap, error)`
- Preserves: `resolveDERPBootstrap` for token consumers and durable credentials
- Consumes: `derpbind.PickRegion`

- [ ] **Step 1: Write the compatibility matrix tests first**

Add tests proving:

1. public one-shot creation writes the measured region into the existing
   `BootstrapRegion` field;
2. measurement failure writes the sorted deterministic fallback region and
   still succeeds;
3. custom one-shot creation does not invoke region measurement and keeps
   `CustomDERPRegionID`;
4. consuming an existing token requests its encoded region and never invokes
   region measurement;
5. current Derptun server/client session tokens with region zero retain the
   existing first-region behavior;
6. web-relay `NewOffer` uses measured selection, while web token consumption
   uses the token's region.

Inject measurement through a private function parameter on
`resolveNewDERPBootstrap`; do not add a mutable test global.

- [ ] **Step 2: Add a creation-only bootstrap helper**

Implement:

```go
func resolveNewDERPBootstrap(
	ctx context.Context,
	route derpbind.Route,
	missingNodeError string,
) (derpBootstrap, error) {
	return resolveNewDERPBootstrapWithPicker(ctx, route, missingNodeError, derpbind.PickRegion)
}
```

The private helper:

- delegates custom routes directly to `resolveDERPBootstrap` with the custom
  region;
- resolves a public map once;
- creates a child context bounded to two seconds without extending the caller
  deadline;
- calls the picker and selects the returned region from the already-resolved
  map;
- stores the `RegionSelection` in the bootstrap;
- does not refetch the map.

- [ ] **Step 3: Change only token-creation call sites**

Use `resolveNewDERPBootstrap` in:

- `issuePublicSessionWithCapabilities`;
- `issuePublicQUICSession`;
- other attach/offer functions that issue a fresh one-shot token;
- web-relay `NewOffer`.

Leave `resolveDERPBootstrap` in:

- all token-consumption paths;
- `pkg/session/derptun.go` server/client startup;
- web-relay claim/download paths consuming an encoded token.

- [ ] **Step 4: Emit redacted selection telemetry**

For creation bootstraps, emit exactly one of:

```text
derp-bootstrap-region=7 selection=measured latency=18ms
derp-bootstrap-region=1 selection=deterministic-fallback
```

Use `time.Duration.String()` and no raw endpoint. Custom routes retain their
existing sanitized route line and do not claim measured selection.

- [ ] **Step 5: Run focused compatibility tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'Test(NewDERPBootstrap|DERPBootstrap|Derptun.*Bootstrap|Issue.*Region|Attach.*Region)' -count=1
mise exec -- go test ./pkg/derphole/webrelay -run 'Test(NewOffer|ResolveWebRelayDERP|BootstrapRegion)' -count=1
mise run check:fast
```

- [ ] **Step 6: Checkpoint one-shot integration**

Run `but diff`, copy the creation-only integration and test IDs, then pass
those exact IDs to `but commit tailcat-foundation` with message `session:
choose relay when issuing tokens`.

### Task 9: Document and verify the completed foundation

**Files:**
- Modify: `docs/derp/client-runtime.md`
- Modify: `docs/superpowers/plans/2026-08-29-tailcat-shared-foundation.md` (check completed steps only)

**Interfaces:**
- Documents: live/fresh/stale/compiled map behavior, cache location and permissions, creation-only nearest selection, custom-route isolation, and unchanged durable semantics

- [ ] **Step 1: Update public technical documentation**

Add a compact section explaining:

- public sessions prefer a bounded live DERP map;
- fresh and stale disk caches make startup resilient;
- compiled data is the last fallback;
- new one-shot tokens record one measured or deterministic region;
- existing and durable tokens use their encoded/deterministic region;
- custom routes never contact public infrastructure.

Do not mention local paths, Tailcat implementation details, or internal ETags.

- [ ] **Step 2: Run the complete local verification sequence**

Run:

```bash
mise exec -- go test ./pkg/derpbind ./pkg/probe ./pkg/session ./pkg/derphole/webrelay -count=1
mise run vuln
mise run smoke-local
mise run check
```

If any tracked file changes during hooks, rerun the focused tests and
`mise run check` against the final content.

- [ ] **Step 3: Run one approved remote relay-to-direct smoke before landing**

Set `REMOTE_HOST` to a host selected through the repository's normal
configuration and run `mise run smoke-remote`.

Record relay connection, direct promotion, and successful payload completion.
Do not run a remote smoke against an invented or personal default host.

- [ ] **Step 4: Commit documentation and plan state**

Run `but diff`, copy the file IDs for the research report, approved program
spec, this plan, and `docs/derp/client-runtime.md`, then pass those exact IDs to
`but commit tailcat-foundation` with message `docs: specify Tailcat-derived
transport foundation`.

- [ ] **Step 5: Prepare the branch for review without publishing**

Run:

```bash
but pull --check
```

If clean and limited to this branch, run `but pull`. Then inspect `but status`
and report the local commit stack, verification commands, remote-smoke result,
and that nothing has been pushed or landed unless the user separately asks.
