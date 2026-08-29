# Tailcat-Derived Product, DERP, and Durable Transport Modernization

**Date:** 2026-08-29

**Status:** Approved

**Research basis:** [Tailcat at HEAD: implications and proposal for Derphole](../../tailcat-comparison-2026-08-29.md)

## Summary

Derphole should adopt the parts of Tailcat that improve its existing
architecture without replacing the capabilities that distinguish Derphole.
The update is a staged program:

1. Move to the current stable Tailscale and Go baseline, fix the reachable
   dependency vulnerabilities found during the comparison, and identify DERP
   connections as Derphole.
2. Replace the compiled-map shortcut with a bounded live DERP-map resolver
   that supports memory and disk caching, optional ETag revalidation, stale
   fallback, and a detached compiled fallback.
3. Select a nearby bootstrap relay when creating new one-shot sessions, while
   preserving the existing deterministic region behavior of durable tokens.
4. Add redacted token or invite inspection to all three products, an
   authenticated Derptun path probe, and a Derpssh doctor command that exposes
   the path information already maintained internally.
5. Add automation-ready access files so service managers and wrappers can
   receive tokens, invites, commands, and ready addresses without scraping
   terminal output.
6. Port Tailcat's multi-port and child-process proxy workflows into a scoped
   Derptun product design: named forwards only, per-client authorization, and
   no unrestricted exit-node behavior.
7. Build a non-release, Tailcat-derived magicsock carrier experiment for the
   existing Derptun app mux and measure it against equivalent and production
   baselines.

Milestones 0 through 2C preserve the production one-shot data plane, browser
transport, Derptun token formats, Derpssh approval model, and default Derptun
transport. The multi-service track requires its own versioned protocol design
before implementation. After the shared foundation, product-surface work and
the internal carrier experiment are parallel tracks with separate gates.

The carrier experiment will use stable Tailscale hooks directly rather than
importing Tailcat. Tailcat hard-codes the DERP application names
tailcat-client and tailcat-server, and its public API does not permit an
override. Importing it unchanged would misattribute Derphole traffic.
Direct use of the upstream hooks also lets Derphole authenticate the peer
before admitting it to the in-process WireGuard network.

## Snapshot and Evidence Boundary

This design is based on these exact revisions:

| Source | Revision | State |
| --- | --- | --- |
| Tailcat | [88929418b1a](https://github.com/tailscale/tailcat/commit/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb) | main equals origin/main |
| Derphole public source | [7c951e2e568b](https://github.com/shayne/derphole/commit/7c951e2e568b6ec09acb86b37a9ee1974142368e) | origin/main, v0.18.2 |
| Derphole workspace tree | 2dbb8ff041f1 | tree-identical to origin/main |
| Stable Tailscale module | [v1.102.3](https://github.com/tailscale/tailscale/releases/tag/v1.102.3) | requires Go 1.26.6 |

The required upstream Tailscale APIs are present in v1.102.3:

- ForceDiscoKey
- OnDERPRecv
- SendDERPPacketTo
- DERPAppName and derphttp.Client.AppName
- userspace engine and netstack startup without a LocalBackend

No special DERP-server frame, parser, routing path, or Tailcat-specific
open-source rate-limit branch is required. DERP remains an opaque packet
router keyed by node public identity.

## Correction to the Initial Proposal

The first comparison correctly identified Mux.ReplaceCarrier as a useful seam,
but its wording was too broad. The normal derptun serve, open, and connect
commands use native striped QUIC streams. The replaceable mux carrier is used
by Derpssh and the Derptun app API.

The experiment therefore cannot replace the normal Derptun carrier with one
assignment. It must:

- preserve quic-native as the production default;
- add quic-mux as the like-for-like app-mux control;
- add magicsock as the Tailcat-derived experimental carrier below that mux;
- compare all three, so app-mux overhead is not mistaken for path-engine
  overhead.

## Goals

- Use a current live public DERP map when the network permits it.
- Start reliably with a fresh cache, stale cache, or compiled offline map.
- Keep every map fetch bounded in time and bytes.
- Prevent callers from mutating a shared cached map.
- Select a nearby DERP region once when issuing new one-shot public tokens.
- Preserve custom DERP routes as authoritative and self-contained.
- Preserve all existing public and custom token bytes and versions.
- Attribute direct derphttp and experimental magicsock connections to
  derphole.
- Let operators inspect token metadata without exposing bearer authority.
- Let operators inspect Derpssh invite metadata without exposing the embedded
  Derptun credential.
- Let operators test a durable peer's authenticated relay and direct path
  without opening application traffic to the target.
- Let Derpssh users diagnose transport reachability without starting a shell
  or triggering host approval.
- Give wrappers and service managers a stable, permission-safe way to receive
  access artifacts and ready addresses.
- Let one durable Derptun endpoint expose multiple explicitly named TCP
  services with per-client scopes.
- Let a child process reach those named services through a temporary local
  proxy without manually assigning local ports.
- Determine whether upstream magicsock materially improves traversal or
  network-change recovery for long-lived app-mux sessions.
- Centralize DERP-map ownership, caching, validation, and mutation isolation
  instead of maintaining partially overlapping fetch behavior.
- Use stable upstream Tailscale seams behind project-owned boundaries so
  dependency churn does not leak through session and CLI packages.
- Make engine startup, peer admission, goroutine ownership, and shutdown
  bounded and testable under partial failure.
- Determine whether upstream path management can reduce bespoke traversal
  ownership without regressing product behavior or observability.
- Make the experiment removable without a token migration or production
  rollback.

## Non-Goals

- Replacing the one-shot transfer, bulk packet, direct TCP, QUIC, or browser
  data planes.
- Changing Derphole v5/v6 or Derptun dts1/dts2/DT1/DT2 wire formats.
- Redefining durable BootstrapRegion zero as nearest on each peer.
- Shipping the magicsock carrier in normal release artifacts.
- Using Tailcat's hosted DERP map or relays.
- Sending Tailcat's DERP application names.
- Importing Tailcat's unstable wire format or options API.
- Adding application UDP to a userspace WireGuard carrier.
- Providing an unrestricted SOCKS proxy, subnet router, exit node, or
  serve-all mode.
- Publishing bearer tokens or Derpssh invites in public DNS.
- Adding an authentication-free SSH mode.
- Silently selecting a saved default credential based on local files.
- Using reflection or unsafe to reach gVisor or Tailscale internals.
- Broadening Derpssh authorization or replacing its approval protocol.
- Solving durable multi-region failover in this change.

## Product and Internal Value Gate

Tailcat is prior art, not a feature checklist. This program has two peer value
tracks.

The product track must improve a user outcome in at least one shipped product:
connection speed, startup reliability, safe operability, automation,
least-privilege access, or recovery from network change.

The internal track must materially improve at least one engineering or
operational outcome:

- remove a reachable vulnerability or unsupported dependency pin;
- eliminate stale or duplicated DERP-map behavior;
- strengthen authentication, lifecycle, resource bounds, or failure cleanup;
- improve path observability and benchmarkability;
- reduce project-owned traversal complexity by adopting a stable upstream
  implementation with equal or better behavior.

An internal improvement does not need a new flag to be valuable, but
refactoring solely for architectural similarity, dependency churn without a
verified benefit, and hidden behavior changes do not qualify. Product and
internal work share compatibility and security constraints, then proceed as
independently reviewable tracks. The experimental carrier is removed if it
meets neither its product recovery gates nor a separately demonstrated
internal-ownership benefit without regression.

## Product Surface Port Decisions

| Tailcat surface | Derphole-family decision | Products | Rationale |
| --- | --- | --- | --- |
| parse token as JSON | Port with mandatory redaction | derphole, derptun, derpssh | Safe support and expiry checks |
| ping and until-direct | Port as probe and doctor | derptun, derpssh | Diagnoses the actual peer path |
| address output file and JSON | Port as a versioned access file | all three | Reliable automation without output scraping |
| serve several ports | Port as named, scoped forwards | derptun | One durable endpoint for related services |
| run a command through SOCKS | Port only for named forwards | derptun | Removes local-port plumbing without creating an exit node |
| persistent client identity and allowlist | Defer to an identity-policy spec | derptun, derpssh | Valuable, but requires revocation and guest identity state |
| DNS TXT token lookup | Do not port for current credentials | derptun, derpssh | Their tokens are bearer secrets |
| full-address embedded map | Do not port by default | all three | Live cache and compiled fallback solve the common case with shorter tokens |
| auth-free SSH, serve-all, exit node | Reject | all three | Conflicts with least privilege and existing product boundaries |

### App-by-app outcome

| Product | Product-surface outcome | Internal outcome | Deliberate boundary |
| --- | --- | --- | --- |
| derphole | Faster one-shot bootstrap, safe token inspection, richer path output, and access-file automation | One validated resolver/cache path and explicit region-selection telemetry | Existing bulk, browser, and one-shot data planes stay specialized |
| derptun | Safe credential inspection, authenticated probe, access-file automation, named services, and child-process proxying | Versioned forward protocol, stronger diagnostics, and a measured upstream carrier seam | Existing durable credentials and single-target commands stay compatible |
| derpssh | Safe invite inspection, transport doctor, and access-file automation | Shared routing and optional carrier improvements remain below the app mux | Approval, roles, chat, terminal protocol, and guest authorization remain Derpssh-owned |

Derpssh may exercise a successful experimental carrier through its existing
app mux, but carrier adoption is not counted as a Derpssh feature until
interactive latency, reconnect continuity, terminal correctness, and approval
flows pass product-specific tests.

## Approaches Considered

### Recommended: shared foundation with parallel product and internal tracks

Land the dependency, map, region, inspection, doctor, and automation
improvements as independent review units. Design scoped multi-service Derptun
as a separate versioned product feature. In parallel after the shared
dependency and observability foundation, build the carrier experiment directly
on stable Tailscale APIs behind a build tag and project-owned package, and
exercise it only through the Derptun app mux.

This yields useful production improvements even if the experiment is removed.
It also gives the internal experiment a fair baseline while keeping
Tailcat-derived risk outside the one-shot and browser paths.

### Rejected: import Tailcat at its current commit

This is attractive for a fast demo but unsuitable for Derphole's experiment:

- the module explicitly offers no API, CLI, or wire stability;
- DERP AppName is hard-coded to Tailcat values;
- Server.Start and client startup have known partial-start cleanup concerns;
- engine creation disables netns process-wide;
- TCP drain reaches into unexported gVisor state through reflect and unsafe;
- the high-level server callback does not expose enough peer identity for
  Derphole's desired pre-admission authorization.

An import can be reconsidered only if Tailcat exposes configurable application
attribution and lifecycle behavior that meets this specification.

### Rejected: replace Derphole traversal wholesale with magicsock

This would trade away optimized bulk transfer, browser WebRTC, authenticated
candidate behavior, direct TCP, and current token semantics before proving a
benefit. Tailcat is generic TCP over a userspace overlay; Derphole has several
specialized data planes that are intentionally not generic.

### Rejected: retain only the current compiled DERP map

The compiled map is a valuable final fallback, not a current service-discovery
mechanism. Treating it as the default makes the documented runtime fetch
untrue and prevents normal map updates from reaching users until a release.

### Rejected: copy Tailcat's nearest-region fallback exactly

Tailcat randomly selects a region when netcheck has no usable latency. Random
fallback makes failures and support reports harder to reproduce. Derphole will
use the first valid sorted region as a deterministic fallback.

### Rejected: persist the last selected region in the first implementation

A persisted region adds location-staleness and cache-migration policy before
measurement shows it is needed. The initial selector is bounded and falls back
deterministically. A last-success cache can be added later without changing
tokens.

## Program Architecture

### Track relationship

~~~text
shared dependency, attribution, map, and region foundation
    |
    +-- product track
    |     +-- inspect / doctor / access artifacts
    |     +-- scoped multi-service Derptun
    |
    +-- internal track
          +-- stable upstream API boundary
          +-- authenticated carrier admission and lifecycle
          +-- quic-native / quic-mux / magicsock evidence
~~~

The tracks reuse shared packages and telemetry but do not share release fate.
Product features do not need the experimental carrier. The internal experiment
does not wait for the multi-service wire design once milestones 0, 1, and the
probe/telemetry foundation are available.

### Production path after milestones 0 through 2C

~~~text
token creator
    |
    v
DERP map resolver
    |-- fresh memory/disk cache
    |-- bounded HTTPS fetch
    |-- stale last-known-good
    +-- detached compiled fallback
    |
    v
one-shot creator only: bounded nearest-region probe
    |
    v
existing token with explicit BootstrapRegion
    |
    v
existing derpbind + traversal.Manager + current data planes
~~~

### Scoped multi-service product path

~~~text
server credential with named forwards
    |
    v
client credential with signed allowed-name subset
    |
    v
existing authenticated Derptun claim and control connection
    |
    +-- open --forward NAME -> one local listener
    |
    +-- run -- COMMAND -> loopback SOCKS -> NAME.derptun.invalid only
    |
    v
versioned open-forward request -> authorized fixed local target
~~~

### Experimental app-mux path

~~~text
Derptun client credential
    |
    v
authenticated DERP carrier hello
    |
    v
dynamic WireGuard peer admission
    |
    v
stock encrypted CallMeMaybe + magicsock path selection
    |
    v
gVisor TCP carrier
    |
    v
existing derptun.Mux
    |
    v
Derptun app / Derpssh protocol
~~~

The DERP server sees opaque custom hello and WireGuard packets. It does not
parse Derphole authentication or participate in peer admission.

## Milestone 0: Dependency and DERP Attribution Baseline

### Versions

Update the module floor and dependencies as one compatibility change:

| Dependency | Current | Required target |
| --- | ---: | ---: |
| Go directive | 1.26.1 | 1.26.6 |
| tailscale.com | v1.96.5 | v1.102.3 |
| golang.org/x/crypto | v0.53.0 | at least v0.55.0 |
| github.com/pion/dtls/v3 | v3.1.2 | at least v3.1.4 |
| github.com/pion/stun/v3 | v3.1.1 | at least v3.1.5 |

The final versions are those selected by Minimal Version Selection after the
explicit upgrades and go mod tidy. No replace directive or pseudo-version is
allowed.

The existing .mise.toml already selects Go 1.26.6. The go directive must match
the minimum required by tailscale.com v1.102.3 so other build environments do
not silently select an older toolchain contract.

### DERP application name

pkg/derpbind owns one constant:

~~~go
const AppName = "derphole"
~~~

newClientWithPrivateKey sets the field before Connect:

~~~go
dc, err := derphttp.NewClient(priv, serverURL, logf, netMon)
if err != nil {
    return nil, err
}
dc.AppName = AppName
~~~

The magicsock experiment sets wgengine.Config.DERPAppName to the same value on
both sides. The value is usage metadata, not authentication or authorization.
Old DERP servers ignore the optional client-info field.

Per-tool names are deliberately not introduced. derphole, derptun, and
derpssh are one project and should aggregate under one honest application
identity.

### Milestone 0 verification

- go mod tidy produces no unexplained dependency.
- go mod verify succeeds.
- govulncheck ./... no longer reports the three reachable findings identified
  by the comparison.
- Focused derpbind tests pass.
- mise run check passes.
- smoke-local passes.
- At least one approved remote relay-to-direct smoke passes before landing,
  because the Tailscale update changes networking internals.

## Milestone 1A: DERP Map Resolution

### Ownership and API

pkg/derpbind remains the owner. No general utilities package is introduced.

~~~go
type MapSource string

const (
    MapSourceNetwork     MapSource = "network"
    MapSourceFreshCache  MapSource = "fresh-cache"
    MapSourceRevalidated MapSource = "revalidated-cache"
    MapSourceStaleCache  MapSource = "stale-cache"
    MapSourceCompiled    MapSource = "compiled-fallback"
    MapSourceEmbedded    MapSource = "embedded-route"
)

type MapCacheEntry struct {
    Data     []byte
    ETag     string
    StoredAt time.Time
}

type MapCache interface {
    Get(url string) (MapCacheEntry, bool)
    Put(url string, entry MapCacheEntry) error
}

type MapResolverConfig struct {
    HTTPClient   *http.Client
    Cache        MapCache
    Now          func() time.Time
    FreshFor     time.Duration
    FetchTimeout time.Duration
    MaxBytes     int64
    Fallback     func() *tailcfg.DERPMap
}

type MapResolver struct {
    // private normalized configuration
}

type MapResult struct {
    Map              *tailcfg.DERPMap
    Source           MapSource
    URL              string
    StoredAt         time.Time
    CacheWriteFailed bool
}

func NewMapResolver(cfg MapResolverConfig) (*MapResolver, error)
func (r *MapResolver) Resolve(ctx context.Context, url string) (MapResult, error)
func ResolveMap(ctx context.Context, url string) (MapResult, error)
func FetchMap(ctx context.Context, url string) (*tailcfg.DERPMap, error)
~~~

FetchMap remains as the compatibility facade. New session code uses ResolveMap
so bootstrap diagnostics retain source metadata.

The constructor returns a concrete type. MapCache is the only new interface;
it has two real implementations and is required for deterministic tests.
HTTP behavior is injected through a concrete http.Client and its
RoundTripper. Time is injected as a function rather than a clock interface.
The resolver clones Data on both sides of the cache boundary, so a cache
implementation cannot share mutable bytes with a caller.

### Defaults

| Setting | Default |
| --- | ---: |
| Freshness window | 1 hour |
| Fetch timeout | 5 seconds |
| Maximum response | 8 MiB |
| HTTP client | dedicated client using the default transport |
| Memory cache | process-wide, URL-keyed |
| Disk cache | user cache directory, derphole/derpmap-cache-v2.json |
| Compiled fallback | dnsfallback.GetDERPMap |

The timeout is an upper bound and never extends an earlier caller deadline.
The response reader uses MaxBytes plus one byte and rejects an oversized body;
reading exactly MaxBytes is valid.

The public control-plane endpoint did not advertise an ETag at the design
snapshot. ETag support remains required because custom or future map services
may provide one. An empty ETag results in a normal full fetch after the
freshness window.

### Cache format and filesystem behavior

The disk cache is a versioned JSON envelope keyed by the SHA-256 hash of the
canonical source URL. Each entry contains:

- validated typed DERP-map JSON re-encoded by Derphole;
- opaque ETag, possibly empty;
- UTC stored-at timestamp.

Raw URLs, URL query credentials, userinfo, and unknown response fields are not
persisted. The cache contains public routing data, not tokens or keys. It is
nevertheless created with a 0700 directory and 0600 file to avoid leaking
operational history by default.

Writes use a same-directory temporary file, fsync, close, and atomic rename.
Readers bound the whole cache file to 16 MiB. A missing, truncated, oversized,
unknown-version, or invalid cache is treated as a cache miss. It never prevents
network fetch or compiled fallback.

Before writing, the cache evicts the oldest URL entries until the encoded
envelope fits within 16 MiB. A single valid entry that cannot fit is not
persisted; its resolved map remains usable by the caller.

Concurrent processes use last-complete-writer-wins semantics. Atomic rename
prevents partial readers; no cross-process lock is introduced.

A successful map resolution does not fail because a cache write failed.
MapResult.CacheWriteFailed lets verbose diagnostics report the persistence
failure without converting an optimization failure into a session failure.

### Resolver algorithm

Resolve performs these steps in order:

1. Validate that the URL uses HTTP or HTTPS, has a host, and has no userinfo.
   Production public configuration always uses HTTPS; HTTP remains available
   for local test fixtures.
2. Load the cache entry and decode it. Invalid cached JSON is discarded.
3. If the decoded entry is not future-dated and is younger than FreshFor,
   return a newly decoded map with source fresh-cache and make no network
   request. A future timestamp is stale.
4. Create a child context with the five-second fetch bound.
5. Send GET. If a stale entry has an ETag, send If-None-Match.
6. On 304 with a valid stale entry, re-store it with the injected current time
   and return a newly decoded map with source revalidated-cache.
7. On 200, read at most MaxBytes plus one, reject overflow, decode, and
   structurally validate the map.
8. Re-encode and store the validated typed map, then return it with source
   network.
9. On request, status, size, or decode failure, return a newly decoded stale
   entry with source stale-cache when one exists.
10. Otherwise clone and validate the compiled fallback and return source
    compiled-fallback.
11. Return an error only when network, cache, and compiled fallback all fail.

The resolver sends no Tailcat-Mode header and uses no Tailcat URL.

### Structural validation and mutation isolation

A usable map must contain at least one region with at least one non-STUN-only
DERP node with a valid TLS hostname or IP authority. Region map keys, region
IDs, and node region IDs must agree and fit the existing uint16 token field.
Direct IPv4 and IPv6 fields and relay/STUN ports are parsed and range checked.
Empty, hostless, structurally inconsistent, and STUN-only maps are invalid as
relay maps. Node selection skips nil and STUN-only entries and never silently
substitutes a different region for an explicit nonzero region ID.

Raw JSON is the cache authority. Every cache result is decoded into a new
tailcfg.DERPMap. The compiled fallback is returned through DERPMap.Clone.
Callers may reorder nodes or attach runtime state without changing later
results.

Tests must mutate a returned region, node, and node slice, resolve again, and
prove the second result retains the cached values.

### Session integration

derpBootstrap gains non-secret metadata:

~~~go
type derpBootstrap struct {
    route            derpbind.Route
    dm               *tailcfg.DERPMap
    node             *tailcfg.DERPNode
    serverURL        string
    mapSource        derpbind.MapSource
    mapStoredAt      time.Time
    cacheWriteFailed bool
}
~~~

Public bootstrap uses ResolveMap. Custom routes continue constructing their
map from the token and record source embedded-route. A custom-route failure
never falls back to public infrastructure.

pkg/derphole/webrelay uses the same resolver and metadata semantics. It does
not maintain a second HTTP fetcher or cache policy.

Verbose output includes one sanitized line:

~~~text
derp-map-source=stale-cache region=7 age=1h14m
~~~

The URL and ETag are not printed. Custom mode retains the existing sanitized
route output.

## Milestone 1B: One-Shot Region Selection

### Scope

Nearest-region selection applies only while creating a new public one-shot
token:

- derphole listen, share, send/receive, and related one-shot listeners;
- web-relay-created one-shot sessions at the relay process;
- attach or offer flows that issue a new one-shot token.

It does not run while consuming a token. It does not apply to custom routes.
It does not change durable Derptun credential startup.

### Selection contract

pkg/derpbind exposes a concrete selector result:

~~~go
type RegionSelection struct {
    RegionID int
    Latency  time.Duration
    Measured bool
}

func PickRegion(ctx context.Context, dm *tailcfg.DERPMap) (RegionSelection, error)
~~~

The session creator gives PickRegion a two-second child context. The
implementation first restricts the resolved map to the frozen public region
IDs 1 through 12 bundled by Derphole v0.18.2, then uses Tailscale netcheck and
chooses the lowest positive RegionLatency among those regions still present.
Equal latencies choose the lower region ID. This prevents a new creator from
encoding a region unknown to a pre-update consumer.

When the probe fails, times out, or reports no usable region, issuance
continues with the first valid region in sorted RegionIDs order. The fallback
is recorded as Measured false. Region selection failure alone does not fail
token creation while a valid relay exists.

The selected ID is written into the existing BootstrapRegion field before the
DERP client connects. Both peers therefore use the same relay without any
token change.

A consumer resolves a nonzero encoded region exactly from its live or cached
map. If that region is absent, it uses the same exact region from a detached
compiled compatibility map. If neither map contains the region, consumption
fails; it never substitutes the first region from a different map.

### Durable token compatibility rule

Derptun server and client SessionToken values currently leave
BootstrapRegion zero. Both sides resolve zero from detached copies of the
compiled compatibility map, preserving the pre-live-map rendezvous rule even
when their live or cached maps differ.

That behavior is frozen for all current credential versions. Independently
selecting nearest on each side can place the server and client in different
DERP regions and break rendezvous. Durable nearest-region and failover require
a new credential/token design and are deferred.

### Region-selection observability

Verbose token-creation output may report:

~~~text
derp-bootstrap-region=7 selection=measured latency=18ms
~~~

or:

~~~text
derp-bootstrap-region=1 selection=deterministic-fallback
~~~

No raw STUN address or map URL is included.

## Milestone 2A: Redacted Token Inspection

### Package-owned metadata

CLI code must not decode a secret-bearing struct and decide ad hoc which
fields to print. Each token package returns a metadata-only type.

pkg/token adds:

~~~go
type Metadata struct {
    Kind            string
    Version         uint8
    SessionID       string
    ExpiresAt       time.Time
    Expired         bool
    Capabilities    []string
    Route           string
    BootstrapRegion uint16
}

func Inspect(encoded string, now time.Time) (Metadata, error)
~~~

pkg/derptun adds:

~~~go
type TokenMetadata struct {
    Kind          string
    Version       int
    SessionID     string
    ClientID      string
    TokenID       string
    ClientName    string
    ExpiresAt     time.Time
    Expired       bool
    Route         string
    CanMintClient bool
}

func InspectToken(encoded string, now time.Time) (TokenMetadata, error)
~~~

pkg/derpssh/session adds:

~~~go
type InviteMetadata struct {
    Kind       string
    Version    int
    ClientID   string
    TokenID    string
    ClientName string
    ExpiresAt  time.Time
    Expired    bool
    Route      string
}

func InspectInvite(encoded string, now time.Time) (InviteMetadata, error)
~~~

InspectInvite structurally decodes the DSH1 envelope and delegates embedded
credential inspection to pkg/derptun. It never returns the embedded client
token or an exported field capable of carrying it.

Identifiers are the first four bytes in lowercase hexadecimal followed by
three periods. Missing identifiers are omitted. Route is public or custom.
Capability names are stable lowercase strings in bit order. Unknown bits are
rendered as unknown-0x00000000 with the bit value in eight hexadecimal digits
rather than dropped.

Inspection validates the complete envelope, checksum, version, route, and
credential structure. A structurally valid expired token returns metadata with
Expired true and no error. A malformed token returns no partial metadata.

### Commands

~~~text
derphole token inspect (--token TOKEN|--token-file PATH|--token-stdin) [--json]
derptun token inspect (--token TOKEN|--token-file PATH|--token-stdin) [--json]
derpssh invite inspect (--invite INVITE|--invite-file PATH|--invite-stdin) [--json]
~~~

Exactly one source is required. --token-stdin reads only the first line and
returns the buffered reader to any command that later needs stdin; inspection
itself has no remaining stdin consumer. The Derpssh invite source flags follow
the same rule.

Human output is written to stdout. Errors and usage are written to stderr.
Exit codes are:

- 0: structurally valid token or invite, including expired access;
- 1: malformed, unsupported, unreadable, or checksum-invalid input;
- 2: invalid flags or input-source selection.

### JSON schema

All three commands emit schema version 1 and never serialize the internal token
struct directly.

One-shot example:

~~~json
{
  "schema_version": 1,
  "kind": "derphole-session",
  "wire_version": 5,
  "session_id": "02a17c44...",
  "expires_at": "2026-08-29T20:00:00Z",
  "expired": false,
  "capabilities": ["stdio", "transfer-v2"],
  "route": "public",
  "bootstrap_region": 7
}
~~~

Derptun client example:

~~~json
{
  "schema_version": 1,
  "kind": "derptun-client",
  "wire_version": 1,
  "session_id": "02a17c44...",
  "client_id": "918ab82e...",
  "token_id": "461f58aa...",
  "client_name": "client-918ab82e",
  "expires_at": "2026-11-27T20:00:00Z",
  "expired": false,
  "route": "public",
  "can_mint_client": false
}
~~~

Derpssh invite example:

~~~json
{
  "schema_version": 1,
  "kind": "derpssh-invite",
  "wire_version": 1,
  "client_id": "918ab82e...",
  "token_id": "461f58aa...",
  "client_name": "client-918ab82e",
  "expires_at": "2026-11-27T20:00:00Z",
  "expired": false,
  "route": "public"
}
~~~

### Mandatory redaction

Inspection never outputs:

- the input token;
- BearerSecret;
- SigningSecret;
- DERP private keys;
- QUIC private keys;
- complete public keys;
- ProofMAC;
- a complete session, client, or token ID;
- cache paths or local usernames;
- enough serialized fields to reconstruct a credential;
- the embedded Derptun client token from a Derpssh invite.

Golden tests scan human and JSON output using known fixture secret values.
Fuzz tests cover all three inspection entry points and require that malformed input
never panics.

## Milestone 2B: Authenticated Derptun Probe and Derpssh Doctor

### Command

~~~text
derptun probe (--service NAME|--token TOKEN|--token-file PATH|--token-stdin)
              [--registry PATH] [--until-direct] [--force-relay]
              [--timeout 10s] [--json] [--include-addresses]

derpssh doctor (--service NAME|--invite INVITE|--invite-file PATH|--invite-stdin)
                [--registry PATH] [--until-direct] [--force-relay]
                [--timeout 10s] [--json] [--include-addresses]
~~~

--until-direct and --force-relay are mutually exclusive. Timeout must be
positive and bounds map resolution, DERP connection, claim, QUIC control
connection, and optional direct wait.

The command is durable-token-only. There is no corresponding one-shot probe,
because a one-shot claim may consume or interfere with the intended transfer.

Derpssh doctor resolves or decodes the invite, calls the same authenticated
Derptun probe with the embedded client credential, and labels the result as a
Derpssh transport check. It does not enter the Derpssh app mux, request a host
approval, open a shell, or send terminal/chat data. Human and JSON output state
that application and approval behavior were not tested.

### Probe behavior

The probe:

1. Decodes and validates the Derptun client credential.
2. Resolves the actual bootstrap route and records map source.
3. Opens the normal derpbind client.
4. Sends the existing authenticated Derptun claim.
5. Requires an accepted decision.
6. Starts the existing transport.Manager.
7. Establishes the normal authenticated QUIC control stream without opening a
   target application stream.
8. Records the current PathSnapshot and subsequent PathEvents.
9. Returns after control connectivity when --until-direct is absent.
10. When --until-direct is present, returns only after direct selection or
    timeout.

The control stream proves that the remote Derptun server accepted the
credential and completed the existing QUIC identity check. The probe sends no
bytes to the configured target.

Running a probe while another client owns the durable session may receive the
normal claimed rejection. The probe does not evict an active client.
Before returning, a successful probe closes its control connection and waits
for claim release so a normal client can connect immediately afterward.

### Session API

pkg/session exposes one concrete operation rather than leaking
transport.Manager:

~~~go
type DerptunProbeConfig struct {
    ClientToken     string
    Timeout         time.Duration
    UntilDirect     bool
    ForceRelay      bool
    IncludeAddresses bool
    Emitter         *telemetry.Emitter
}

type DerptunProbeReport struct {
    // versioned JSON fields described below
}

func DerptunProbe(ctx context.Context, cfg DerptunProbeConfig) (DerptunProbeReport, error)
~~~

The report owns detached strings and durations. It does not expose net.Addr,
key types, the credential, or mutable transport snapshots.

pkg/derpssh/session owns the invite wrapper:

~~~go
type DoctorConfig struct {
    Invite           string
    Timeout          time.Duration
    UntilDirect      bool
    ForceRelay       bool
    IncludeAddresses bool
    Emitter          *telemetry.Emitter
}

type DoctorReport struct {
    Transport          coresession.DerptunProbeReport
    ApplicationTested  bool
}

func Doctor(ctx context.Context, cfg DoctorConfig) (DoctorReport, error)
~~~

coresession is the local import alias for github.com/shayne/derphole/pkg/session.
ApplicationTested is always false in schema version 1. The field is explicit
so automation cannot mistake transport reachability for a successful shell or
approval flow.

### JSON schema

~~~json
{
  "schema_version": 1,
  "bootstrap": {
    "route": "public",
    "region_id": 7,
    "map_source": "fresh-cache",
    "map_age_ms": 2412
  },
  "authentication": {
    "accepted": true,
    "elapsed_ms": 86
  },
  "control_connection": {
    "established": true,
    "elapsed_ms": 104
  },
  "path": {
    "selected": "direct",
    "selected_after_ms": 312,
    "rtt_ms": 21,
    "endpoint_class": "public",
    "upgrades": 1,
    "fallbacks": 0
  },
  "candidates": {
    "total": 3,
    "private": 1,
    "public": 2,
    "overlay": 0
  },
  "last_fallback_reason": ""
}
~~~

Derpssh doctor wraps that report rather than flattening or renaming its
transport fields:

~~~json
{
  "schema_version": 1,
  "product": "derpssh",
  "application": {
    "tested": false
  },
  "transport": {
    "schema_version": 1,
    "authentication": {"accepted": true, "elapsed_ms": 86},
    "control_connection": {"established": true, "elapsed_ms": 104},
    "path": {"selected": "direct", "selected_after_ms": 312, "rtt_ms": 21}
  }
}
~~~

Human doctor output ends with an explicit line:

~~~text
derpssh-application=not-tested
~~~

Fields with no measurement are omitted rather than encoded as a misleading
zero. --include-addresses adds selected_address and a candidate_addresses
array. Without it, neither human nor JSON output contains IP addresses.

Exit codes are:

- 0: authenticated control connection established, and direct selected when
  --until-direct was requested;
- 1: token, network, authentication, claimed-session, or direct-timeout
  failure;
- 2: usage error.

Derpssh doctor uses the same exit codes. A successful doctor means the invite
was structurally valid and the underlying authenticated transport reached the
requested path state; it does not mean a future guest will be approved.

### Verbose and network-debug output

Normal --verbose output gains redacted path details:

~~~text
transport-path=relay
transport-candidates private=1 public=2 overlay=0
transport-path=direct class=public rtt=21ms reason=probe-ack
transport-path=relay reason=direct-stale fallbacks=1
~~~

Add --debug-network as a mutually exclusive telemetry level alongside
--verbose, --quiet, and --silent. It includes verbose output and permits raw
addresses. The existing transport-direct-path address moves from verbose to
network-debug; endpoint class remains in verbose.

telemetry.Emitter gains NetworkDebug. Debug is enabled for verbose and
network-debug, while NetworkDebug writes only at the latter level.

## Milestone 2C: Automation-Ready Access Artifacts

### Command surface

Commands that create an access credential, invite, connect command, or local
ready address accept:

~~~text
--write-access PATH
~~~

The first production set is:

- derphole listen, share, send, and ssh invite;
- derptun serve and open;
- derpssh share.

Existing human output, stdout payloads, stderr diagnostics, and the Derpssh
TUI remain unchanged. PATH cannot be - because several commands already use
standard streams for payload or terminal rendering.

### File contract

pkg/accessartifact owns the versioned document and atomic writer:

~~~go
type Document struct {
    SchemaVersion  int        `json:"schema_version"`
    Product        string     `json:"product"`
    Kind           string     `json:"kind"`
    CreatedAt      time.Time  `json:"created_at"`
    ExpiresAt      *time.Time `json:"expires_at,omitempty"`
    ContainsSecret bool       `json:"contains_secret"`
    Access         string     `json:"access,omitempty"`
    Command        string     `json:"command,omitempty"`
    ReadyAddress   string     `json:"ready_address,omitempty"`
}

func Write(path string, doc Document) error
~~~

Schema version 1 permits these kinds:

- derphole-session-access;
- derptun-client-access;
- derptun-local-listener;
- derpssh-invite.

Access contains the exact token or invite when the kind carries authority.
Command contains the exact copyable command already shown to the user.
ReadyAddress contains only a local listening address. Unknown products,
kinds, empty required fields, relative expiry before creation, and documents
with no useful output are rejected before writing.

Example Derptun server artifact:

~~~json
{
  "schema_version": 1,
  "product": "derptun",
  "kind": "derptun-client-access",
  "created_at": "2026-08-29T20:00:00Z",
  "expires_at": "2026-11-27T20:00:00Z",
  "contains_secret": true,
  "access": "DT1...",
  "command": "npx -y derptun@latest open --token DT1..."
}
~~~

### Filesystem and failure behavior

The parent directory must already exist. Write creates a same-directory
temporary file with mode 0600, writes and fsyncs the complete JSON document,
closes it, and atomically replaces PATH. It does not follow a final-component
symlink and does not loosen an existing file's permissions.

The file remains after process exit because durable credentials and post-run
automation may still need it. One-shot access naturally stops working when
its owning session exits.

When --write-access was requested, inability to write the complete artifact
is a command failure. A listener or session opened before a ready artifact is
written is closed before returning the error. Logs and ordinary human output
never echo the access value as part of an access-file error.

This ports Tailcat's address-file automation outcome without introducing a
second JSON stream or changing current Unix composition.

## Milestone 3: Scoped Multi-Service Derptun

### Product outcome

One durable Derptun endpoint can expose several related TCP services, and a
client can either open one as a local listener or run a child command through
a temporary proxy. The feature copies Tailcat's multi-port and SOCKS
convenience while making the accessible destinations explicit and
credential-scoped.

The product shape is:

~~~text
derptun token server --forward web=127.0.0.1:3000 \
                      --forward metrics=127.0.0.1:9090 > server.dts

derptun token client --token-file server.dts \
                     --forward web --forward metrics > client.dt

derptun serve --token-file server.dts
derptun open --token-file client.dt --forward web --listen 127.0.0.1:8080
derptun run --token-file client.dt -- curl http://web.derptun.invalid/
~~~

--forward NAME=HOST:PORT on server-token creation is repeatable. Names are
lowercase ASCII letters, digits, and single hyphens, start with a letter, end
with a letter or digit, and are at most 32 bytes. Duplicate names, wildcard
addresses, port zero, and non-loopback targets are rejected by default.
--allow-non-loopback is required to expose another interface explicitly.

Client-token --forward NAME is repeatable and must be a subset of the server
credential's forward names. At least one name is required. The client token's
proof covers the sorted allowed-name set so it cannot be widened or renamed.

### Compatibility and versioning

Multi-service credentials use a new Derptun credential version and distinct
prefixes selected by the follow-up wire specification. Current dts1, dts2,
DT1, and DT2 credentials retain their single-target behavior forever. The
follow-up specification must choose the exact prefixes, byte encoding,
negotiation bit, and mixed-version errors before implementation begins.

ServerCredential already contains an unused Forwards field. That is useful
structural prior work, but its presence in old JSON is not a protocol contract.
The implementation must not activate it under an existing credential version,
because old binaries would ignore the scope and target semantics.

Current one-off syntax remains shorthand for one runtime target:

~~~text
derptun serve --tcp HOST:PORT
~~~

It does not silently mint a multi-service credential. Already released old
binaries reject the new prefixes through their existing unrecognized-token
path; new binaries give a sanitized requires-newer-version error for reserved
prefixes newer than they support.

### Named-forward protocol

After the existing authenticated claim and control connection, the server
advertises only the names authorized by the client credential. Each
application stream starts with a bounded, versioned open-forward request
containing one name. The server verifies the name against both the signed
client scope and its own configured target before dialing locally.

Targets, local addresses, and the complete forward table are never sent to
the client. Forward-open rejection is explicit and does not close unrelated
streams. Per-forward concurrent stream and idle limits are part of the new
server credential, with conservative defaults defined by the follow-up wire
specification.

### Restricted child-process proxy

derptun run starts an ephemeral loopback SOCKS5 listener, sets ALL_PROXY and
all_proxy for the child, and runs the command after --. It accepts only DNS
names in the form NAME.derptun.invalid whose NAME is authorized by the client
token. The reserved .invalid suffix prevents accidental public DNS routing if
an application bypasses the proxy. The URL port is ignored in favor of the
server credential's fixed target port; port zero, raw IPs, localhost,
arbitrary DNS, CONNECT to other destinations, UDP ASSOCIATE, and BIND are
rejected.

The proxy exits when the child exits, cancellation closes both, and the
child's exit status is preserved. Diagnostics go to stderr; the child's
stdin, stdout, and stderr remain directly connected to the caller.

This is not an exit node. It cannot reach the server's general network and
does not gain access to forwards omitted from the client credential.

### Decomposition gate

Milestone 3 is an approved product direction, not permission to improvise a
wire format inside implementation. Its credential and stream changes require
a focused companion specification and independent review before code work.
That spec must include revocation interaction, limits, version fixtures, and
mixed-version tests. Milestones 0 through 2C do not wait for it.

## Milestone 4: Tailcat-Derived Magicsock Carrier Experiment

### Experiment boundary

The experiment is compiled only with:

~~~text
-tags derphole_magicsock_experiment
~~~

Normal mise run build and release workflows do not use the tag and do not
compile or ship the package. A dedicated task builds experimental local and
Linux binaries for the benchmark matrix.

The standard CLI defaults remain unchanged. Experimental binaries accept:

~~~text
--experimental-transport=quic-native|quic-mux|magicsock
~~~

Both server and client must select the same value. quic-native is the current
production behavior. quic-mux uses the existing current transport and one
QUIC stream below derptun.Mux. magicsock uses the new userspace WireGuard TCP
connection below the same mux.

The flag is not written into current credentials. A production opt-in would
require a negotiation and compatibility design after this experiment.

### Package boundary

The build-tagged implementation lives in internal/magicsockcarrier. It owns
all direct use of:

- wgengine.NewUserspaceEngine;
- magicsock custom DERP send/receive hooks;
- ForceDiscoKey;
- netmap and dynamic peer configuration;
- gVisor netstack;
- stock disco.CallMeMaybe endpoint advertisement.

The rest of Derphole sees concrete Server and Client types that produce
net.Conn values and redacted path observations. No Tailscale engine, netmap,
or netstack type escapes the package.

The non-experimental build contains a small stub returning
ErrExperimentUnavailable if an experimental mode reaches package code.

The package API is deliberately narrow:

~~~go
type ServerConfig struct {
    Credential derptun.ServerCredential
    Region     *tailcfg.DERPRegion
    Logf       func(string, ...any)
    Now        func() time.Time
}

type ClientConfig struct {
    Credential derptun.ClientCredential
    Region     *tailcfg.DERPRegion
    Logf       func(string, ...any)
    Now        func() time.Time
}

func NewServer(ctx context.Context, cfg ServerConfig) (*Server, error)
func (s *Server) Accept(ctx context.Context) (net.Conn, error)
func (s *Server) Close() error

func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error)
func (c *Client) Dial(ctx context.Context) (net.Conn, error)
func (c *Client) Close() error
~~~

Constructors validate and copy the credential metadata and DERP region. The
fixed userspace address and carrier port are package constants, not caller
options. The package never returns credential, engine, netmap, magicsock, or
netstack values.

### Identity and addressing

The carrier reuses the existing Derptun server node identity:

- server private key: ServerCredential.DERPPrivate;
- server public key: ClientCredential.DERPPublic;
- client node key: ephemeral per process, retained for reconnects;
- server disco key: independent and ephemeral per server process;
- client disco key: independent and ephemeral per client process;
- bootstrap region: the current deterministic Derptun region resolution.

No current token field changes. The carrier derives one userspace-only IPv6
address per node from the node public key under Tailscale's ULA prefix, as
Tailcat does. These addresses never enter host routing or tokens.

Both disco keys come from crypto/rand and are supplied through ForceDiscoKey.
Unlike Tailcat, the experiment does not reuse node-key material for disco.
The admission exchange has room to communicate both independent disco public
keys, so key reuse is unnecessary.

The server filter admits inbound TCP SYN packets only to one fixed internal
carrier port on its own userspace address. It does not enable subnet routing,
UDP proxying, or an exit-node path.

### Authenticated peer admission

Tailcat's meow admits any node unless the server has a static node-key
allowlist. Derphole has stronger credentials and must authenticate before
adding a dynamic WireGuard peer.

The custom DERP packet is versioned and bounded:

~~~go
type Hello struct {
    Version     uint8
    SessionID   [16]byte
    ClientID    [16]byte
    TokenID     [16]byte
    ClientName  string
    ExpiresUnix int64
    ProofMAC    [32]byte
    NodePublic  [32]byte
    DiscoPublic [32]byte
    Nonce       [16]byte
    MAC         [32]byte
}
~~~

Wire encoding is network-byte-order and starts with this common header:

~~~text
magic       4 bytes, "DHMC"
version     uint8, 1
type        uint8, 1=hello or 2=ack
length      uint16, payload bytes
~~~

The hello payload is SessionID, ClientID, TokenID, ExpiresUnix, a uint8
ClientName length and at most 64 ASCII bytes, raw 32-byte ProofMAC, NodePublic,
DiscoPublic, Nonce, and MAC in that order. The overall frame maximum is 4 KiB
and trailing bytes are invalid.

The acknowledgment payload is status byte 1, hello Nonce, server NodePublic,
server DiscoPublic, client NodePublic, and a 32-byte MAC. Rejections are
silent and have no wire form.

The format is internal and not embedded in user tokens. ProofMAC is converted
to and from the existing credential's lowercase hexadecimal representation at
the boundary.

The server reconstructs the complete client credential from its session
credential plus the hello metadata: credential version, DERP and QUIC public
keys, route, and derived BearerSecret come from the server credential; the
remaining fields come from the hello. It then uses the existing credential
verifier.
The client computes MAC as HMAC-SHA256 with its derived BearerSecret over every
encoded byte from the common-header magic through the nonce, including type,
length, and ClientName length. The MAC field itself is excluded. The
acknowledgment MAC similarly covers its common header and all acknowledgment
fields preceding that MAC. Hello, acknowledgment, and bind-prelude HMACs all
use that same client BearerSecret.

OnDERPRecv validates in this order:

1. packet magic, version, exact length, and field bounds;
2. DERP source node key equals Hello.NodePublic;
3. session ID matches the server credential;
4. server and client credential expiry;
5. ProofMAC through derptun.VerifyClientCredential;
6. hello MAC with hmac.Equal;
7. pending-peer and active-client limits.

Only then does the server add the peer to its network map and lazy WireGuard
configuration. Invalid packets are silently dropped and logged only as a
redacted reason in network-debug mode.

The server replies with an authenticated acknowledgment bound to the hello
nonce and both node keys. The client does not start TCP until it verifies the
acknowledgment.

This preserves Derptun's capability boundary before the attacker can allocate
a gVisor TCP connection. DERP and WireGuard remain additional transport
layers, not replacements for the application credential.

### Direct-path discovery

After peer admission:

1. The normal WireGuard handshake can ride DERP.
2. Engine endpoint changes are collected and deduplicated.
3. The carrier constructs stock encrypted disco.CallMeMaybe messages.
4. SendDERPPacketTo carries them through the selected DERP region.
5. Stock magicsock pings, punches, selects, and falls back.

No custom disco message type is added. The only custom frame is the
authenticated admission hello handled before unknown-peer rejection.

### TCP binding and app mux

The client dials the server's fixed userspace carrier port through netstack.
Before passing the net.Conn to derptun.Mux, it writes a small authenticated
bind prelude containing the hello nonce and an HMAC over the TCP binding
context.

The bind prelude is fixed-size: magic "DHMB", version 1, SessionID, client
NodePublic, hello Nonce, and a 32-byte MAC. The MAC covers every preceding
prelude byte in encoded order. Any truncation, extra byte, identity mismatch,
or invalid MAC closes the connection.

The server's netstack flow callback retains the source userspace address,
resolves it to the admitted node, verifies the bind prelude under a five-second
deadline, and only then delivers the connection to the session adapter.

For quic-mux and magicsock modes, normal Derptun target serving is expressed
as an app-mux handler:

- each accepted mux stream dials the configured local target;
- each local open connection opens one mux stream;
- the existing mux owns replay and carrier replacement;
- target and stream limits remain those of the current Derptun app path.

Derpssh already uses the app mux. It receives no direct carrier code. After
the carrier passes the lower-level matrix, a build-tagged Derpssh flag may
select it for recovery testing.

### Lifecycle requirements

NewServer, NewClient, Server.Accept, and Client.Dial take context as their
first parameter. Context is never stored as request state and no
context.Background is introduced below a caller.

Every started goroutine has:

- an owning context or close channel;
- a wait group observed by Close;
- bounded input queues;
- an explicit sender responsible for channel closure.

Close is idempotent and executes this order:

1. stop new admissions and dials;
2. cancel endpoint and status watchers;
3. close active TCP carriers;
4. close netstack;
5. close the WireGuard engine and magicsock;
6. close netmon and remaining subsystems;
7. wait for owned goroutines.

Construction uses a cleanup stack so every completed subsystem is closed when
a later step fails. This specifically avoids Tailcat's partial-start concern.

The experiment does not call Tailcat DrainTCP and does not use reflect or
unsafe. If clean TCP shutdown cannot be made reliable through exported APIs
and the mux protocol, that is a failed promotion gate and an upstream API
request, not permission to pierce gVisor internals.

netns.SetEnabled(false) is a process-wide Tailscale setting. The experiment
sets it only in a build-tagged binary after magicsock mode is explicitly
selected. A process may run one experimental carrier mode at a time. This
global side effect is a production blocker unless upstream provides a scoped
alternative or analysis proves it harmless to all Derphole consumers.

### Bounded peer state

The server permits:

- one active Derptun client, matching current semantics;
- at most eight pending authenticated peers;
- at most 64 recently seen hello nonces;
- a 30-second pending-admission lifetime;
- a four-second DERP hello retry window;
- a five-second TCP bind deadline.

Nonce and pending maps are pruned on insert and by one owned timer loop.
Expired client credentials are removed even if no TCP connection arrives.

### Path observations

The package exposes detached observations:

~~~go
type Path string

const (
    PathUnknown Path = "unknown"
    PathRelay   Path = "relay"
    PathDirect  Path = "direct"
)

type Snapshot struct {
    At        time.Time
    Path      Path
    RTT       time.Duration
    Class     string
    Upgrades  int
    Fallbacks int
}

func (c *Client) Snapshot() Snapshot
func (c *Client) Events(ctx context.Context) <-chan Snapshot
~~~

Events are transition-only, have a bounded buffer, include context
cancellation, and never contain raw addresses. Network-debug obtains raw
addresses from a separate method so accidental JSON serialization cannot leak
them.

## Experimental Benchmark Design

### Matrix integration

derphole-probe matrix gains derptun as a tool and transport as a grouping
axis:

~~~text
derphole-probe matrix --tools derptun \
  --transports quic-native,quic-mux,magicsock \
  --hosts ... --iterations 10 --size-mib 1024
~~~

The existing promotion scripts exercise the one-shot derphole bulk path and
cannot measure this carrier. Add Derptun forward and reverse benchmark scripts
that reuse the existing remote installation, process-identity, storage
preflight, cleanup, and report conventions.

RunReport already has a Transport field. matrixSeries and baseline comparison
keys add Transport so distinct carriers are never pooled. Existing reports
without a transport normalize to the current production value.

### Required scenarios

| Scenario | quic-native | quic-mux | magicsock |
| --- | --- | --- | --- |
| Same LAN | yes | yes | yes |
| Home NAT to cloud | yes | yes | yes |
| Endpoint-dependent or symmetric NAT | yes | yes | yes |
| UDP blocked | yes | yes | yes |
| IPv6-only and dual-stack | yes | yes | yes |
| Interface change | yes | yes | yes |
| Suspend and resume | yes | yes | yes |
| Repeated start, fail, close | yes | yes | yes |
| Derpssh reconnect | later | yes | yes |
| Browser peer | current only | no | no |
| One-shot 1 GiB bulk | current only | no | no |

quic-mux is the architectural control for magicsock. quic-native remains the
product baseline for deciding whether a future Derptun opt-in is acceptable.

### Mandatory gates and promotion paths

Every candidate for a follow-up production design must satisfy these gates:

- 100 consecutive connect, authenticate, stream, close cycles complete with
  no unexpected failure.
- Authentication rejection tests show no WireGuard peer or TCP carrier is
  admitted for a malformed, expired, replayed-from-another-node, or
  bad-MAC hello.
- Direct-selection success rate is no lower than quic-mux in every measured
  topology.
- Relay control-connection p95 is no worse than the larger of 110 percent of
  quic-mux or quic-mux plus 50 ms.
- Direct-selection p95 is no worse than 110 percent of quic-mux.
- Median and p10 direct goodput are each at least 90 percent of quic-mux.
- The experimental binary grows by no more than 8 MiB over the equivalent
  quic-mux build.
- Idle RSS grows by no more than 25 MiB and transfer CPU by no more than 15
  percent at equal goodput.
- Repeated failed startup and close tests return to the baseline goroutine and
  file-descriptor counts.
- All existing Derptun app and Derpssh tests pass unchanged in quic-mux mode.

After those mandatory gates, the experiment must justify continued production
design through at least one of two paths:

1. Product path: interface-change or suspend/resume recovery is at least 20
   percent faster at p95, or magicsock recovers a measured topology where
   quic-mux repeatedly fails.
2. Internal path: a reviewed replacement plan removes project-owned endpoint
   discovery, NAT traversal, path selection, or network-change recovery from
   the adopted Derptun/Derpssh path; it does not retain permanent duplicate
   carriers; and existing redacted diagnostics remain equally actionable.

The internal path must name the concrete production files and state machines
that disappear. Merely moving code, adding an adapter beside the old path, or
depending on upstream without deleting project-owned responsibility is not an
internal benefit.

Passing the mandatory gates and one promotion path does not change the
default. It authorizes a separate production-carrier and negotiation spec.

## Security Model

### Trust boundaries

| Boundary | Attacker control | Required defense |
| --- | --- | --- |
| DERP map HTTP | response status, bytes, delay | HTTPS, context timeout, size bound, structural validation, stale/compiled fallback |
| Disk cache | local file contents and timestamp | size bound, versioning, full decode, structural validation, atomic writes |
| Token inspect input | arbitrary bytes | bounded decoders, no panic, metadata-only return |
| Probe token | bearer authority | no token logging, no target stream, normal credential proof |
| Custom DERP packet | arbitrary payload and source node | exact framing, source binding, expiry, proof, HMAC, bounded state |
| Userspace TCP | admitted or malicious peer traffic | narrow filter, source mapping, bind prelude, deadline, one active client |
| Diagnostic output | operational topology | class/count by default, addresses only by explicit flag |

### Relay confidentiality

Existing direct derpbind traffic retains its current end-to-end protection.
The experimental carrier sends WireGuard packets through DERP. Application
bytes are encrypted before DERP sees them. The custom hello contains public
identifiers, expiry, and MAC material but no bearer secret or private key.

### Denial of service

Map bodies, hello frames, caches, channels, peer maps, nonce maps, pending
connections, and deadlines are bounded. Invalid admission traffic is handled
before netstack TCP allocation. Expensive work is not spawned in an unbounded
goroutine per packet.

### Logging

Errors and debug events never include token strings, HMACs, proof MACs, private
keys, full public keys, or cache contents. Public keys and identifiers use the
same four-byte redaction as token inspection.

## Compatibility and Rollback

Milestones 0 through 2C require no token-version change. Existing tokens keep
their region and route behavior. New one-shot public tokens may carry a
different existing BootstrapRegion value because creation now measures it.

Custom tokens remain fully self-contained and never contact the public map.
Old binaries can consume newly created current-version tokens because the
wire format is unchanged.

Milestone 3 intentionally introduces a distinct multi-service credential and
stream version. Existing single-target credentials are neither rewritten nor
silently upgraded. Removing milestone 3 leaves every current token and command
behavior intact.

The carrier experiment is excluded from release builds and current
credentials do not select it. Removing its build tag, package, CLI flag, and
benchmark cases returns the exact production transport behavior. No user token
migration or credential rotation is required.

## Failure Semantics

| Failure | Behavior |
| --- | --- |
| Fresh cache decode fails | discard cache and continue |
| Public map fetch times out | stale cache, then compiled fallback |
| Public map returns non-200 | stale cache, then compiled fallback |
| Public map is oversized or invalid | stale cache, then compiled fallback |
| Cache write fails | continue and report only in verbose diagnostics |
| Region netcheck fails | deterministic first valid region |
| Custom route is invalid or unreachable | fail closed; no public fallback |
| Token inspection sees expired token | print metadata, expired true, exit 0 |
| Derptun probe cannot claim | exit 1 without opening target traffic |
| --until-direct times out | print final relay report, exit 1 |
| Derpssh doctor reaches transport but not app protocol | report application_tested false |
| Requested access artifact cannot be written | close newly opened resource and fail command |
| Multi-service client requests an unauthorized name | reject that stream without dialing target |
| Restricted run proxy receives arbitrary host, IP, or UDP request | reject locally without sending it |
| Experimental hello authentication fails | silent drop; no peer admission |
| Experimental carrier startup partially fails | close every completed subsystem |
| Experimental clean TCP shutdown is unreliable | fail promotion gate; do not use unsafe |

## Test Plan

### Map resolver unit tests

- fresh cache avoids HTTP;
- stale cache sends If-None-Match when ETag exists;
- stale cache without ETag performs a full fetch;
- 304 refreshes stored time and returns revalidated-cache;
- 304 without cached data is an error path;
- valid 200 replaces cache;
- exactly 8 MiB is accepted when valid;
- 8 MiB plus one byte is rejected;
- non-200, timeout, read error, and invalid JSON use stale cache;
- no stale cache uses a cloned compiled fallback;
- all sources invalid return an error;
- caller mutation does not affect a later result;
- future cache timestamps are treated as stale;
- cache write failure is nonfatal and visible in metadata;
- custom URLs use the injected HTTP client.

### Disk cache tests

- first write creates 0700 directory and 0600 file;
- writes use atomic replacement;
- corrupt, truncated, oversized, and unknown-version files are misses;
- two complete writers never produce a partial readable document;
- cache contains no token or key fields;
- paths are computed from os.UserCacheDir, not a developer-specific default.

### Region tests

- lowest latency wins;
- missing map region is ignored;
- equal latency chooses lower ID;
- zero and negative latency are ignored;
- timeout and empty report choose deterministic first;
- custom route bypasses netcheck;
- token consumer never reruns region selection;
- durable BootstrapRegion zero behavior is unchanged;
- golden public token fixtures retain their wire format and length.

### Inspection tests

- all supported one-shot, Derptun, and Derpssh invite versions;
- server and client credential kinds;
- expired valid input;
- DSH1 wrapping a malformed, unsupported, or expired client credential;
- unknown capability bit;
- malformed length, prefix, checksum, route, and key material;
- human and JSON golden output;
- Derpssh output never contains its embedded client token;
- secret canaries absent from output;
- fuzzing for panic freedom.

### Probe tests

- token source exclusivity and service lookup;
- accepted control connection without opening a target stream;
- claimed-session rejection;
- relay-only success without --until-direct;
- direct event already present before subscription;
- later direct event;
- fallback reason capture;
- --until-direct timeout prints final report and exits 1;
- --force-relay and --until-direct are rejected together;
- addresses omitted by default and present only when requested;
- Derpssh doctor resolves service names and direct invite sources;
- doctor never starts the app mux, shell, chat, or host approval flow;
- doctor always reports application_tested false;
- successful probe cleanup permits an immediate normal client claim;
- context cancellation closes DERP, packet, QUIC, and watcher resources.

### Access artifact tests

- every supported command writes the correct product and kind;
- secret-bearing files are mode 0600 on first write and replacement;
- same-directory atomic replacement never exposes partial JSON;
- final-component symlinks are rejected;
- unknown kind, missing required field, and invalid expiry fail validation;
- human output and stdout payload behavior are byte-for-byte unchanged;
- a write failure after listener creation closes the listener;
- errors contain neither access, token, invite, nor copyable command;
- concurrent complete writers produce one complete valid document.

### Multi-service Derptun tests

- forward-name grammar, duplicate, target, and loopback policy;
- client scopes are sorted, proof-bound, and strict subsets of server names;
- current credentials retain single-target behavior and golden encodings;
- old binaries reject new credentials through their existing unrecognized-token
  path, while new binaries recognize unsupported reserved versions;
- authenticated advertisement reveals authorized names only;
- unauthorized and unknown forward requests never dial a target;
- rejection of one stream does not close another forward;
- run accepts authorized NAME.derptun.invalid destinations only;
- run rejects raw IP, arbitrary DNS, UDP ASSOCIATE, BIND, and unknown names;
- child exit status, cancellation, and standard streams are preserved;
- per-forward concurrency and idle limits are enforced.

### Experimental carrier tests

- hello codec bounds and version rejection;
- source-node mismatch;
- invalid client proof and hello MAC;
- expired server and client credentials;
- replay from another DERP node;
- pending-peer and nonce limits;
- authenticated acknowledgment binding;
- TCP source-to-peer mapping and bind prelude;
- filter rejects every port except the carrier port;
- endpoint advertisement uses stock encrypted CallMeMaybe;
- relay path with a local test DERP server;
- direct promotion under topology simulation;
- network-change fallback and recovery;
- carrier replacement preserves mux streams;
- repeated failed construction and Close are leak-free;
- race detector on admission, endpoint, and close tests;
- build without the experiment tag has no magicsock carrier dependency.

## Implementation Map

This is a program specification, not one implementation plan. Milestones 0,
1, 2A, 2B, 2C, 3, and 4 are separate review and delivery units. Milestone 3
also requires its focused wire companion before its implementation plan.

### Milestone 0

- go.mod and go.sum
- .mise.toml verification only unless tool declarations need normalization
- pkg/derpbind/client.go and focused tests

### Milestone 1

- pkg/derpbind/map.go
- new pkg/derpbind/map_cache.go
- new pkg/derpbind/region.go
- matching test files
- pkg/session/derp_route.go
- one-shot issuance paths in pkg/session
- pkg/derphole/webrelay/relay.go
- public documentation correcting live-map behavior

### Milestone 2A

- new pkg/token/inspect.go
- new pkg/derptun/inspect.go
- pkg/derpssh/session invite metadata inspection
- cmd/derphole token command and root registration
- cmd/derptun token inspect registration
- cmd/derpssh invite inspect registration
- human, JSON, fuzz, and secret-canary tests

### Milestone 2B

- new pkg/session/derptun_probe.go
- new cmd/derptun/probe.go
- pkg/derpssh/session doctor wrapper
- new cmd/derpssh/doctor.go
- pkg/telemetry and path-emitter updates
- CLI, path, no-app-traffic, and redaction tests

### Milestone 2C

- new pkg/accessartifact document and atomic writer
- --write-access integration in selected derphole commands
- --write-access integration in derptun serve and open
- --write-access integration in derpssh share
- permission, atomicity, output-compatibility, and cleanup tests

### Milestone 3

- focused multi-service credential and stream companion specification
- versioned credential codecs and proof fixtures
- named-forward server configuration and stream request handling
- derptun open --forward
- restricted derptun run SOCKS5 child wrapper
- authorization, compatibility, proxy, and lifecycle tests

### Milestone 4

- build-tagged internal/magicsockcarrier
- non-experimental stub
- session adapters for quic-mux and magicsock
- experimental CLI transport flag
- Derptun target-to-mux bridge shared with app consumers
- derptun benchmark scripts
- cmd/derphole-probe matrix transport grouping
- topology, leak, race, and benchmark coverage

README changes made during implementation must follow the repository's
compressed technical prose guidance. Generated dist contents are not edited.

## Delivery Sequence

1. Land milestone 0 alone and verify local plus approved remote smoke.
2. Land the resolver and disk cache with FetchMap compatibility.
3. Thread resolver metadata through bootstrap and web relay.
4. Add one-shot region selection and verify unchanged durable behavior.
5. Add token and invite inspection across all three products.
6. Add the Derptun probe, Derpssh doctor, and telemetry privacy split.
7. Add automation-ready access artifacts without changing standard streams.
8. Start two independently reviewable tracks after the shared foundation:
   - product: write and approve the multi-service credential/stream companion,
     then implement scoped named forwards and restricted derptun run;
   - internal: record quic-native and quic-mux baselines, implement the
     build-tagged magicsock carrier, then run correctness, topology, resource,
     and performance matrices.
9. Verify and release the product track on its own compatibility and security
   gates; it does not wait for a carrier result.
10. Write the internal experiment result report. If its gates pass, create a
    separate production carrier/negotiation spec. If they fail, remove the
    experiment while retaining the shared and product improvements.
11. Design durable multi-region credentials independently when that product
    work is prioritized.

Milestones should be separate reviewable commits or GitButler branch series.
The dependency update must not be hidden inside the carrier experiment, and
neither post-foundation track may hold the other track's completed value for
an unrelated decision.

## Acceptance Criteria

Each track has its own completion state. The full program is delivered when
the shared foundation and product track are production-ready and the internal
track has a recorded keep-or-remove decision.

### Shared foundation

- the stable dependency and vulnerability baseline is verified;
- all DERP clients advertise AppName derphole;
- public map resolution follows the specified cache and fallback contract;
- cache and compiled maps are mutation-isolated;
- new one-shot public tokens record a measured or deterministic explicit
  region;
- current durable and custom route semantics remain byte-compatible;
- stable upstream types are contained behind derpbind, session, and the
  build-tagged carrier package rather than exposed through CLI APIs;
- normal verbose output has useful class and RTT data without raw addresses.

### Product track

- token and invite inspection are metadata-only and pass secret-canary tests;
- Derptun probe authenticates without opening target traffic and provides the
  stable redacted schema;
- Derpssh doctor reuses that proof without starting a shell or approval flow;
- every selected command can write a complete atomic access artifact without
  changing its established stdout, stderr, payload, or TUI behavior;
- multi-service credentials authorize an immutable named-forward subset;
- unauthorized forward requests never cause a target dial;
- derptun run reaches authorized NAME.derptun.invalid destinations and
  rejects all arbitrary network access;
- all current Derptun credentials and single-target commands retain their
  exact behavior.

### Internal track

- experimental peer admission authenticates before adding dynamic WireGuard
  or netstack state;
- startup failure and Close return goroutine, descriptor, and peer state to
  their measured baselines;
- engine, magicsock, netstack, netmon, and watcher ownership remain confined
  to internal/magicsockcarrier;
- standard release builds contain no experimental carrier;
- the experimental matrix produces separate quic-native, quic-mux, and
  magicsock results;
- the result report applies every promotion threshold;
- the result report also records whether stable upstream ownership would
  remove enough bespoke traversal code or failure surface to justify keeping
  the carrier when user-visible results are equivalent;
- the carrier is removed when it demonstrates neither a product benefit nor a
  verified internal-ownership benefit;
- no production transport default changes without a follow-up approved design.

## Required Companion and Follow-Up Specifications

### Multi-service credential and stream protocol

Required before milestone 3 code. It must assign exact credential prefixes and
wire versions, define proof bytes, forward limits, open/reject frames,
mixed-version behavior, revocation interaction, and golden fixtures. It may
refine field encoding but cannot weaken the named-forward or proxy restrictions
in this program spec.

### Trusted client identity and revocation

Tailcat's persistent client allowlist is useful prior art, but current
Derptun and Derpssh credentials do not provide the right revocable guest
identity state. A separate product design should compare per-client token
revocation, stable client keys, and remembered Derpssh roles. It must avoid a
magic saved-default identity and must preserve explicit host approval for
unknown guests.

### Production magicsock carrier and negotiation

Required only if the experiment passes. It must define peer capability
negotiation, mixed-version behavior, CLI exposure, packaging, long-term API
ownership, and whether the app mux becomes part of normal Derptun.

### Durable multi-region credentials

Required independently of carrier choice. It must define a new version with
server registration and client failover semantics. Existing zero-region
credentials remain deterministic forever.

Candidate designs to compare later are:

- two ordered region IDs with server dual registration;
- a preferred region plus an embedded bounded alternate node set;
- client racing against two server registrations.

The future design must survive relay removal without letting peers choose
different uncoordinated home regions.

## Final Decision

Approve milestones 0 through 2C as production improvements across derphole,
derptun, and derpssh.

Approve milestone 3 as the next product-surface direction, subject to its
focused credential and stream specification. It ports Tailcat's strongest
multi-service and command-proxy workflows while preserving least privilege.

Approve milestone 4 as the peer internal track: a build-tagged experiment
implemented directly on stable Tailscale hooks. It may proceed once the shared
foundation and measurement seams exist; it does not wait for milestone 3. Do
not import Tailcat unchanged, do not publish Tailcat application names, and do
not place the experiment under one-shot or browser transports.

Tailcat's valuable lessons are both product-level and architectural: simple
path testing, inspectable addresses, automation outputs, multi-service access,
and child-process proxying are worth porting when adapted to Derphole's secret
credentials and least-privilege model. Upstream path management remains an
experiment at the narrow app-mux boundary, not the reason to do the production
work.
