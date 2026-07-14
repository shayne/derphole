# Self-Contained Custom DERP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let derphole, derptun, and derpssh create self-contained tokens for one operator-selected HTTPS DERP server while keeping the existing public Tailscale DERP path and public token bytes unchanged.

**Architecture:** Add a validated, compact public-or-custom route value to `pkg/derpbind`. Keep the zero value as the public route. Encode custom one-shot sessions as v6 and custom durable credentials as `dts2_`/`DT2`, while continuing to emit the existing v5, `dts1_`, and `DT1` bytes when `DERPHOLE_DERP_SERVER` is empty. Root creators read the environment once; every consumer trusts only the decoded token route. Session startup branches once: public routes use the existing static Tailscale map path, while custom routes build a one-node synthetic map used for DERP and STUN with no public fallback.

**Tech Stack:** Go 1.26, `net/url`, `net/netip`, `encoding/binary`, existing Tailscale `tailcfg` and DERP client packages, existing local DERP and CONNECT-proxy fixtures, `mise`, and GitButler.

## Global Constraints

- `DERPHOLE_DERP_SERVER` is the only new operator setting. Do not add flags, config files, map URLs, or consumer-side overrides.
- Read the variable only at root token or durable server-credential creation. Treat unset and the exact empty string as public. Treat non-empty whitespace as invalid input rather than silently trimming it.
- Accept only HTTPS URLs with no userinfo, query, or fragment and with path empty, `/`, or `/derp`. Canonicalize to a structured host, DERP TCP port, and STUN UDP port.
- Default DERP to TCP 443 and STUN to UDP 3478. The first version does not support a separate STUN hostname or port in configuration.
- The route embedded in a consumed token is authoritative. Never consult `DERPHOLE_DERP_SERVER` while consuming a token.
- A custom route must never fetch, retain, probe, or fall back to the public Tailscale DERP map. A failed custom DERP connection fails closed.
- Custom STUN and direct-path discovery remain best-effort. Their failure must leave a healthy DERP relay session running. Custom mode does not imply `ForceRelay`.
- The existing proxy-aware `pkg/derpbind.Client` remains the only DERP dial path. HTTPS custom routes therefore inherit `HTTPS_PROXY`, lowercase variants, `NO_PROXY`, credential redaction, and no-direct-fallback behavior.
- Public one-shot v5 tokens, `dts1_` server credentials, and `DT1` client credentials must retain their exact current bytes, lengths, prefixes, and decoding behavior.
- Public startup must execute its current map and node-selection branch without constructing a synthetic map or allocating route extension storage.
- Old binaries must continue to accept newly created public tokens. They must clearly reject custom v6, `dts2_`, and `DT2` values through their existing unsupported/invalid token errors.
- Bind the v2 derptun client route into its proof MAC. Route bytes must not be mutable without the durable server signing secret.
- Errors and verbose diagnostics may name only a canonical host and port. Never print an opaque token, private key, bearer secret, proxy credentials, or URL userinfo.
- Do not hand-edit `dist/`. Do not change dependencies unless the implementation proves one is necessary.
- Preserve unrelated GitButler branches and dirty files. Every commit must select only the file or hunk IDs listed by its task.

## File Map

- Create `pkg/derpbind/route.go`: route constants, HTTPS parser, canonical validation, synthetic map, server URL, JSON shape, and shared compact wire codec.
- Create `pkg/derpbind/route_test.go`: accepted/rejected URLs, canonical hosts, IPv4/IPv6 URL rendering, wire bounds, JSON round trips, and single-node map assertions.
- Modify `pkg/token/token.go` and `pkg/token/token_test.go`: preserve fixed v5; add route-bearing v6 with exact length and CRC validation.
- Modify `pkg/derptun/token.go`, `pkg/derptun/client_token.go`, and their tests: preserve public v1 credentials; add custom v2 prefixes, route propagation, proof binding, and environment-aware root generation.
- Modify `cmd/derptun/serve.go`, `cmd/derptun/token.go`, and command tests: use environment-aware server credential creation only when a new root credential is created.
- Modify `cmd/derptun/token_source.go`: recognize both server-token prefixes in the existing client-token error path.
- Modify `pkg/derpssh/session/share.go` and its tests: create root server credentials through the shared environment-aware derptun helper; keep client derivation environment-free.
- Modify `pkg/derpholemobile/mobile.go` and tests: recognize both `DT1` and `DT2` client tokens.
- Create `pkg/session/derp_route.go` and `pkg/session/derp_route_test.go`: route-to-map bootstrap, public/custom branching, custom diagnostics, server URL test override, and fail-closed errors.
- Modify `pkg/session/external.go`, `pkg/session/external_attach.go`, `pkg/session/external_v2.go`, `pkg/session/external_v2_offer.go`, and `pkg/session/derptun.go`: route all one-shot, attach/share, durable tunnel, and derpssh-shared runtime connections through the decoded route.
- Modify `pkg/derphole/webrelay/relay.go` and tests: give web-file offers and consumers the same v5/v6 route rules, including WASM decoding of custom tokens.
- Create `pkg/session/custom_derp_test.go` and modify `pkg/session/proxy_test.go`: product-level relay, no-public-map, conflicting-consumer-env, STUN failure, direct promotion, derptun app mux, and proxy CONNECT coverage.
- Create `scripts/smoke-custom-derp.sh`: repeatable relay-only creator/consumer smoke test with the consumer environment cleared.
- Create `docs/derp/custom-server.md` and modify `docs/derp/client-runtime.md`: operator contract, proxy behavior, security boundary, and troubleshooting.

## Preparation Gate

- [ ] Run the workspace overlap check before implementation.

```sh
but status
but pull --check
```

Expected: identify whether any applied branch touches the files in this plan. If `but pull --check` reports only already-landed duplicate proxy commits, verify those branches are integrated before deleting only those branches. Stop if another active session overlaps a planned file.

- [ ] Continue on the existing `codex/custom-derp-server-design` branch so the approved design, this plan, and implementation stay together.

```sh
but branch show codex/custom-derp-server-design
git rev-parse origin/main
```

Expected: the branch contains the approved design and plan only, and the implementation is based on the current `origin/main` before production code is committed. If the base moved, use `but pull`, then rerun the first focused test before committing.

---

### Task 1: Canonical custom route and compact locator codec

**Files:**

- Create: `pkg/derpbind/route.go`
- Create: `pkg/derpbind/route_test.go`

**Interfaces:**

```go
const (
	CustomDERPServerEnv = "DERPHOLE_DERP_SERVER"
	DefaultDERPPort     = uint16(443)
	DefaultSTUNPort     = uint16(3478)
	CustomDERPRegionID  = 900
)

type Route struct {
	Host     string `json:"host"`
	DERPPort uint16 `json:"derp_port"`
	STUNPort uint16 `json:"stun_port"`
}

func RouteFromEnvironment() (Route, error)
func ParseCustomRoute(raw string) (Route, error)
func NewCustomRoute(host string, derpPort, stunPort uint16) (Route, error)
func (r Route) IsCustom() bool
func (r Route) Validate() error
func (r Route) DERPAuthority() string
func (r Route) STUNAuthority() string
func (r Route) ServerURL() string
func (r Route) DERPMap() *tailcfg.DERPMap
func (r Route) AppendWire(dst []byte) ([]byte, error)
func ParseRouteWire(src []byte) (Route, int, error)
```

The zero `Route{}` is public. Any non-zero field means the value is attempting to be custom and must pass full validation.

- [ ] **Step 1: Write failing parser and environment tests.**

Add table cases with these exact outcomes:

```go
var accepted = map[string]Route{
	"https://derp.example.com":           {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
	"https://DERP.EXAMPLE.COM./":         {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
	"https://derp.example.com/derp":      {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
	"https://derp.example.com:8443/derp": {Host: "derp.example.com", DERPPort: 8443, STUNPort: 3478},
	"https://192.0.2.10":                 {Host: "192.0.2.10", DERPPort: 443, STUNPort: 3478},
	"https://[2001:0db8::1]:8443/derp":   {Host: "2001:db8::1", DERPPort: 8443, STUNPort: 3478},
}

var rejected = []string{
	" ",
	"http://derp.example.com",
	"derp.example.com",
	"https://",
	"https://user:pass@derp.example.com",
	"https://derp.example.com?x=1",
	"https://derp.example.com#fragment",
	"https://derp.example.com/other",
	"https://derp.example.com/%64erp",
	"https://derp.example.com:0",
	"https://derp.example.com:65536",
	"https://-bad.example.com",
	"https://bad-.example.com",
	"https://café.example.com",
}
```

`TestRouteFromEnvironment` must cover missing, exact empty, valid, and invalid values. Use `t.Setenv`; do not call `t.Parallel`.

- [ ] **Step 2: Run the parser tests and confirm the compile failure.**

```sh
mise exec -- go test ./pkg/derpbind -run 'TestParseCustomRoute|TestRouteFromEnvironment' -count=1
```

Expected: FAIL because `Route`, `ParseCustomRoute`, and `RouteFromEnvironment` do not exist.

- [ ] **Step 3: Implement strict parsing and canonical validation.**

`ParseCustomRoute` must parse with `url.Parse`, require the exact `https` scheme, validate the unescaped and escaped path, reject userinfo/query/fragment, canonicalize `netip.Addr` values with `Addr.String`, and otherwise validate ASCII DNS labels. DNS labels are 1-63 bytes, contain only letters, digits, and interior hyphens, and the complete normalized host is at most 253 bytes. Strip one trailing DNS dot and lowercase DNS names. Reject IPv6 zones.

`RouteFromEnvironment` must use one `os.LookupEnv` call:

```go
func RouteFromEnvironment() (Route, error) {
	raw, ok := os.LookupEnv(CustomDERPServerEnv)
	if !ok || raw == "" {
		return Route{}, nil
	}
	return ParseCustomRoute(raw)
}
```

Wrap parser failures as `invalid DERPHOLE_DERP_SERVER: <reason>` without repeating the raw URL.

- [ ] **Step 4: Add failing map, URL, JSON, and wire-codec tests.**

Assert all of the following:

- Public `Route{}.DERPMap()` returns `nil` and `Route{}.ServerURL()` returns `""`.
- The custom map has `OmitDefaultRegions=true`, exactly region 900, exactly one node, no direct IP fields, canonical hostname, explicit DERP and STUN ports, and no public nodes.
- `ServerURL()` returns `https://derp.example.com/derp`, `https://derp.example.com:8443/derp`, and `https://[2001:db8::1]:8443/derp` for the respective routes.
- JSON emits exactly `{"host":"derp.example.com","derp_port":443,"stun_port":3478}` for the default custom locator.
- Wire bytes are `host_length`, host bytes, big-endian DERP port, and big-endian STUN port.
- `ParseRouteWire` returns the consumed byte count and rejects zero/254/255 host lengths, truncation, zero ports, non-canonical hosts, invalid UTF-8/non-ASCII bytes, and trailing callers can detect by comparing `consumed` with input length.

- [ ] **Step 5: Implement URL, map, and shared wire helpers.**

Use one fixed custom map shape:

```go
func (r Route) DERPMap() *tailcfg.DERPMap {
	if !r.IsCustom() || r.Validate() != nil {
		return nil
	}
	node := &tailcfg.DERPNode{
		Name:     "custom",
		RegionID: CustomDERPRegionID,
		HostName: r.Host,
		DERPPort: int(r.DERPPort),
		STUNPort: int(r.STUNPort),
	}
	return &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions: map[int]*tailcfg.DERPRegion{
			CustomDERPRegionID: {
				RegionID:   CustomDERPRegionID,
				RegionCode: "custom",
				RegionName: "Custom DERP",
				Nodes:      []*tailcfg.DERPNode{node},
			},
		},
	}
}
```

Use `net.JoinHostPort` only when rendering a non-default port or an IPv6 literal. The wire parser must call `NewCustomRoute`, so environment, JSON credentials, one-shot tokens, and compact credentials share one canonical validator.

- [ ] **Step 6: Run focused and package tests.**

```sh
mise exec -- go test ./pkg/derpbind -run 'TestParseCustomRoute|TestRouteFromEnvironment|TestRouteMap|TestRouteServerURL|TestRouteJSON|TestRouteWire' -count=1
mise exec -- go test ./pkg/derpbind -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit only Task 1 files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "net: define custom DERP routes" --changes <route.go-id>,<route_test.go-id>
```

Expected: the normal pre-commit hook passes; the commit contains only the two route files.

---

### Task 2: Route-bearing one-shot v6 tokens without changing v5

**Files:**

- Modify: `pkg/token/token.go`
- Modify: `pkg/token/token_test.go`

**Interfaces:**

```go
const (
	SupportedVersion  uint8 = 5
	CustomDERPVersion uint8 = 6
)

type Token struct {
	Version         uint8
	SessionID       [16]byte
	ExpiresUnix     int64
	BootstrapRegion uint16
	DERPPublic      [32]byte
	QUICPublic      [32]byte
	BearerSecret    [32]byte
	Capabilities    uint32
	DERPRoute       derpbind.Route
}

func VersionForRoute(route derpbind.Route) uint8
func IsSupportedVersion(version uint8) bool
```

- [ ] **Step 1: Strengthen the public v5 golden before changing the codec.**

Extend `TestEncodeWireFormatContract` to assert the current fixed fixture encodes to this exact 131-byte raw token and exact string:

```go
const publicV5Golden = "BQECAwQFBgcICQoLDA0ODxAAAAAAZVPxABI0ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gAAAAA3XU8cQ"
```

Run it against the unchanged v5 implementation:

```sh
mise exec -- go test ./pkg/token -run '^TestEncodeWireFormatContract$' -count=1
```

Expected: PASS. If it does not, stop; the checked-out base does not match the approved compatibility baseline.

- [ ] **Step 2: Add failing v6 and version/route mismatch tests.**

Cover:

- `VersionForRoute(Route{}) == 5` and custom route returns 6.
- zero version plus public route emits v5; zero version plus custom emits v6.
- explicit v5 plus custom and explicit v6 plus public return `ErrUnsupportedVersion`.
- a custom route with default and non-default DERP ports round-trips exactly.
- the v6 CRC covers the route extension.
- v6 rejects a zero host length, truncated host/ports/checksum, invalid host, zero port, and valid-checksum trailing bytes.
- v5 still rejects any trailing extension and decodes with `DERPRoute == (derpbind.Route{})`.
- version 7 remains `ErrUnsupportedVersion`.
- fuzz seeds include one valid v5 and two valid v6 values.

- [ ] **Step 3: Run the new tests and confirm red.**

```sh
mise exec -- go test ./pkg/token -run 'TestVersionForRoute|TestCustomDERP|TestEncodeRejectsVersionRouteMismatch|TestDecodeRejectsCustom' -count=1
```

Expected: FAIL because v6 and `DERPRoute` are not implemented.

- [ ] **Step 4: Implement the versioned envelope.**

Keep `writeTokenFixedPayload` byte-for-byte unchanged. `Encode` must validate the route/version pair, write the fixed payload, append route wire only for v6, then checksum the entire payload. `Decode` must inspect the version first:

```go
func VersionForRoute(route derpbind.Route) uint8 {
	if route.IsCustom() {
		return CustomDERPVersion
	}
	return SupportedVersion
}

func IsSupportedVersion(version uint8) bool {
	return version == SupportedVersion || version == CustomDERPVersion
}
```

For v5, require exactly `fixedPayloadSize + 4` bytes and leave `DERPRoute` zero. For v6, require at least one extension-length byte and two ports, derive the exact total from the host-length byte, verify the checksum, parse the extension with `derpbind.ParseRouteWire`, and require `consumed == len(payload)-fixedPayloadSize`. Never allocate route-extension storage on the v5 branch.

- [ ] **Step 5: Run token tests and fuzz smoke.**

```sh
mise exec -- go test ./pkg/token -count=1
mise exec -- go test ./pkg/token -run '^$' -fuzz '^FuzzDecode$' -fuzztime=5s
mise exec -- go test ./pkg/token -run '^$' -fuzz '^FuzzEncodeDecode$' -fuzztime=5s
```

Expected: PASS, with the literal v5 golden unchanged.

- [ ] **Step 6: Commit only token codec files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "token: encode custom DERP routes" --changes <token.go-id>,<token_test.go-id>
```

---

### Task 3: Versioned derptun credentials and creator-only environment lookup

**Files:**

- Modify: `pkg/derptun/token.go`
- Modify: `pkg/derptun/token_test.go`
- Modify: `pkg/derptun/client_token.go`
- Modify: `pkg/derptun/client_token_test.go`
- Modify: `cmd/derptun/serve.go`
- Modify: `cmd/derptun/token.go`
- Modify: `cmd/derptun/token_source.go`
- Modify: `cmd/derptun/command_test.go`
- Modify: `pkg/derpssh/session/share.go`
- Modify: `pkg/derpssh/session/share_connect_test.go`
- Modify: `pkg/derpholemobile/mobile.go`
- Modify: `pkg/derpholemobile/mobile_test.go`

**Interfaces:**

```go
const (
	ServerTokenPrefix       = "dts1_"
	CustomServerTokenPrefix = "dts2_"
	ClientTokenPrefix       = "DT1"
	CustomClientTokenPrefix = "DT2"
	TokenVersion            = 1
	CustomTokenVersion      = 2
)

type ServerTokenOptions struct {
	Now       time.Time
	Days      int
	Expires   time.Time
	DERPRoute derpbind.Route
}

type ServerCredential struct {
	Version       int             `json:"version"`
	SessionID     [16]byte        `json:"session_id"`
	ExpiresUnix   int64           `json:"expires_unix"`
	DERPPrivate   string          `json:"derp_private"`
	QUICPrivate   []byte          `json:"quic_private"`
	SigningSecret [32]byte        `json:"signing_secret"`
	Forwards      []ForwardSpec   `json:"forwards,omitempty"`
	DERPRoute     *derpbind.Route `json:"derp_route,omitempty"`
}

type ClientCredential struct {
	Version      int
	SessionID    [16]byte
	ClientID     [16]byte
	TokenID      [16]byte
	ClientName   string
	ExpiresUnix  int64
	DERPPublic   [32]byte
	QUICPublic   [32]byte
	BearerSecret [32]byte
	ProofMAC     string
	DERPRoute    *derpbind.Route
}

func GenerateServerTokenFromEnvironment(opts ServerTokenOptions) (string, error)
func HasServerTokenPrefix(value string) bool
func HasClientTokenPrefix(value string) bool
```

Use pointers only in durable credentials so `omitempty` preserves exact public JSON and public client values do not carry route storage. Clone a custom route when deriving the client to avoid shared mutable pointers.

- [ ] **Step 1: Add literal public credential goldens before codec changes.**

Use a fixed internal `ServerCredential` to assert `encodeJSONToken(ServerTokenPrefix, cred)` equals:

```go
const publicServerGolden = "dts1_eyJ2ZXJzaW9uIjoxLCJzZXNzaW9uX2lkIjpbMSwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMF0sImV4cGlyZXNfdW5peCI6MTcwMDAwMDAwMCwiZGVycF9wcml2YXRlIjoicHJpdmtleTpnb2xkZW4iLCJxdWljX3ByaXZhdGUiOiJBZ009Iiwic2lnbmluZ19zZWNyZXQiOls0LDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDBdfQ"
```

Use a fixed `ClientCredential` with `SessionID[0]=1`, `ClientID[0]=2`, `TokenID[0]=7`, expiry 1700000000, first DERP/QUIC/bearer bytes 3/4/5, and a 32-byte `0x06` proof. Assert `EncodeClientCredential` equals:

```go
const publicClientGolden = "DT1B60A60000000000000000000000KC0000000000000000000000T21000000000000000000000000000RHFWS+UI0000000000000000000000000000000000000000000000:O00000000000000000000000000000000000000000000009V0000000000000000000000000000000000000000000000P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0"
```

Run both against the unchanged implementation. Expected: PASS.

- [ ] **Step 2: Add failing custom credential tests.**

Test this complete flow:

1. `GenerateServerToken(ServerTokenOptions{DERPRoute: route})` emits `dts2_` and version 2.
2. `GenerateClientToken` is called while `DERPHOLE_DERP_SERVER=https://conflict.invalid`; it emits `DT2` containing the server route, proving derivation ignores environment.
3. Both credentials produce session tokens with version 6 and the same route.
4. Public generation still emits the literal v1 goldens and version 5 session tokens.
5. New decoders accept v1 and v2; `dts1_` with version 2/route, `dts2_` with version 1/no route, `DT1` with v2 bytes, and `DT2` without a valid route all fail with `ErrInvalidToken`.
6. Mutating any v2 route byte while preserving compact syntax causes `VerifyClientCredential` to fail, proving the route is in the proof MAC.
7. A maximum 253-byte host round-trips through `DT2`; 254-byte hosts fail before encoding.

- [ ] **Step 3: Implement server generation and decoding.**

Keep `GenerateServerToken` deterministic with respect to its options. Add the environment wrapper:

```go
func GenerateServerTokenFromEnvironment(opts ServerTokenOptions) (string, error) {
	route, err := derpbind.RouteFromEnvironment()
	if err != nil {
		return "", err
	}
	opts.DERPRoute = route
	return GenerateServerToken(opts)
}
```

`GenerateServerToken` validates `opts.DERPRoute`, selects version/prefix from the route, and attaches a cloned pointer only for custom. `DecodeServerToken` chooses the decoder from the prefix, validates the exact version/route pairing, validates the route, then performs existing key and expiry checks.

- [ ] **Step 4: Implement the DT2 variable-length compact codec.**

Keep the first 186 raw bytes and all DT1 constants unchanged. For DT2:

- set the compact header version to 2;
- append `Route.AppendWire` after the existing 32-byte proof;
- encode the complete raw bytes with the existing base-41 codec;
- decode the base-41 payload, require at least 186 bytes plus a route, parse the route, and require the parser consumed all remaining bytes;
- select exact DT1 versus DT2 behavior from the prefix, never by guessing from length.

Use proof labels `derptun-client-proof-v1` for public and `derptun-client-proof-v2` for custom. The v2 proof input is the existing identity/expiry material followed by the exact canonical route wire bytes. Do not change v1 proof input.

- [ ] **Step 5: Wire only root creators to the environment wrapper.**

Change these three creator boundaries:

```go
// cmd/derptun/serve.go
token, err = derptunpkg.GenerateServerTokenFromEnvironment(derptunpkg.ServerTokenOptions{})

// cmd/derptun/token.go
tokenValue, err := derptun.GenerateServerTokenFromEnvironment(
	derptun.ServerTokenOptions{Days: parsed.SubCommandFlags.Days, Expires: expires},
)

// pkg/derpssh/session/share.go
var generateServerToken = derptun.GenerateServerTokenFromEnvironment
```

Do not change `GenerateClientToken` call sites. Update CLI tests so invalid creator environment returns code 1 without printing a token, and a custom creator produces the new prefix. Clear the environment in existing public golden/command tests.

- [ ] **Step 6: Update prefix dispatch without widening token acceptance.**

`HasServerTokenPrefix` and `HasClientTokenPrefix` recognize exactly their two supported prefixes. Use them in `cmd/derptun/token_source.go` and `pkg/derpholemobile/mobile.go`; actual decoding still decides validity. Add mobile tests for valid DT1, valid DT2, malformed DT2, and non-token QR payloads.

- [ ] **Step 7: Run focused suites.**

```sh
mise exec -- go test ./pkg/derptun -count=1
mise exec -- go test ./cmd/derptun -count=1
mise exec -- go test ./pkg/derpssh/session -count=1
mise exec -- go test ./pkg/derpholemobile -count=1
```

Expected: PASS, including both literal public goldens.

- [ ] **Step 8: Commit only Task 3 files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "token: carry custom DERP through durable credentials" --changes <task-3-file-and-hunk-ids>
```

Expected: no session runtime or documentation file appears in this commit.

---

### Task 4: Shared session bootstrap and one-shot route authority

**Files:**

- Create: `pkg/session/derp_route.go`
- Create: `pkg/session/derp_route_test.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_attach.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`

**Interfaces:**

```go
type derpBootstrap struct {
	route     derpbind.Route
	dm        *tailcfg.DERPMap
	node      *tailcfg.DERPNode
	serverURL string
}

var fetchSessionDERPMap = derpbind.FetchMap

func resolveDERPBootstrap(ctx context.Context, route derpbind.Route, regionID int, missingNodeError string) (derpBootstrap, error)
func openSessionDERPClient(ctx context.Context, bootstrap derpBootstrap, emitter *telemetry.Emitter) (*derpbind.Client, error)
func emitDERPRouteDebug(emitter *telemetry.Emitter, route derpbind.Route)
```

- [ ] **Step 1: Add failing bootstrap branch tests.**

Test public with a stubbed `fetchSessionDERPMap`: the stub must be called exactly once with `publicDERPMapURL()`, its returned map and region selection are preserved, and `publicDERPServerURL(node)` is used. Test custom with the same stub configured to fail the test if called: the result must use the one-node custom map, ignore `regionID`, and use `route.ServerURL()`.

Also test that `DERPHOLE_TEST_DERP_SERVER_URL` overrides only the final dial URL for local fixtures in both branches. `DERPHOLE_TEST_DERP_MAP_URL` must never be fetched for a custom route.

- [ ] **Step 2: Implement bootstrap resolution and sanitized diagnostics.**

The public branch must remain the current code path:

```go
if !route.IsCustom() {
	dm, err := fetchSessionDERPMap(ctx, publicDERPMapURL())
	if err != nil {
		return derpBootstrap{}, err
	}
	node := firstDERPNode(dm, regionID)
	if node == nil {
		return derpBootstrap{}, errors.New(missingNodeError)
	}
	return derpBootstrap{dm: dm, node: node, serverURL: publicDERPServerURL(node)}, nil
}
```

The custom branch validates the route, calls `route.DERPMap`, selects region 900, and never invokes `fetchSessionDERPMap`. If the custom `NewClient` call fails, wrap it as `connect custom DERP <authority>: <cause>`; public errors retain their current text. On verbose emitters, print exactly:

```text
derp-route=custom derp=derp.example.com:443 stun=derp.example.com:3478
```

Public sessions emit no new route line. Continue to call `emitDERPProxyDebug` after client construction.

- [ ] **Step 3: Make root one-shot creators read the environment once.**

Update `issuePublicSessionWithCapabilities` and `issuePublicQUICSession` in place rather than adding parallel APIs. At the top of each creator:

```go
route, err := derpbind.RouteFromEnvironment()
if err != nil {
	return "", nil, err
}
bootstrap, err := resolveDERPBootstrap(ctx, route, 0, "no DERP node available")
```

Set token fields with:

```go
Version:         token.VersionForRoute(route),
BootstrapRegion: uint16(bootstrap.node.RegionID),
DERPRoute:       route,
```

Use `bootstrap.dm` everywhere the creator currently stores or passes the public map. For the public route this produces the same v5 bytes and follows the same map path. Local-only token creators in `listen.go`, `share.go`, and `attach_session.go` remain v5 and unchanged because they do not use public DERP bootstrap.

- [ ] **Step 4: Route every one-shot consumer from the decoded token.**

Replace public map/client setup in these exact methods:

- `externalV2SendRuntime.openDERP` in `external_v2.go`
- `externalV2OfferReceiveRuntime.openDERP` in `external_v2_offer.go`

Every call must pass `tok.DERPRoute` to `resolveDERPBootstrap`. None may call `RouteFromEnvironment`. Pass `bootstrap.dm` into existing traversal and transport code without adding route checks to the data plane.

The attach and external-share consumers already delegate DERP setup to `openDerptunDialDERP`; leave that delegation intact. Task 5 makes that shared helper route-aware, covering both consumers without duplicating bootstrap logic.

- [ ] **Step 5: Add creator/consumer authority tests.**

In `pkg/session/derp_route_test.go`:

- create a custom token under `DERPHOLE_DERP_SERVER=https://creator.invalid:8443`;
- decode and assert v6, canonical route, and region 900;
- change the process environment to `https://consumer-conflict.invalid` before constructing the consumer runtime;
- assert the runtime requests `creator.invalid:8443`, not the consumer value;
- set invalid creator configuration and assert failure occurs before a DERP-map fetch or client dial;
- clear configuration and assert a new public token is the existing v5 shape.

- [ ] **Step 6: Run one-shot and attach/share suites.**

```sh
mise exec -- go test ./pkg/session -run 'TestDERPBootstrap|TestCustomDERPRoute|TestExternalV2|TestExternalAttach|TestOffer' -count=1
mise exec -- go test ./pkg/session -count=1
```

Expected: PASS. Existing tests using `DERPHOLE_TEST_DERP_MAP_URL` continue to pass unchanged on the public path.

- [ ] **Step 7: Commit Task 4 files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "session: bootstrap from embedded DERP routes" --changes <task-4-file-and-hunk-ids>
```

---

### Task 5: Durable derptun and derpssh runtime routing

**Files:**

- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_test.go`
- Modify: `pkg/session/derptun_app_test.go`
- Modify: `pkg/session/external_attach_test.go`
- Modify: `pkg/session/session_test.go`
- Modify: `pkg/derpssh/session/share_connect_test.go`

- [ ] **Step 1: Add failing durable-route runtime tests.**

Create a `dts2_` server under a custom creator route, derive a `DT2` client after clearing `DERPHOLE_DERP_SERVER`, and assert:

- `loadDerptunServeIdentity` and `loadDerptunDialToken` return session-token v6 with identical routes;
- a conflicting environment on either runtime is ignored;
- the server private-key client and the client ephemeral-key client both resolve the custom map and URL;
- a malformed custom route is rejected during credential decoding, before map or network work;
- public `dts1_`/`DT1` fixtures still resolve through the public map branch.

- [ ] **Step 2: Replace both durable DERP open paths with shared bootstrap.**

`openDerptunServeDERP` must resolve `tok.DERPRoute`, then call `derpbind.NewClientWithPrivateKey` using `bootstrap.node` and `bootstrap.serverURL`. `openDerptunDialDERP` does the same through `openSessionDERPClient`. Both return `bootstrap.dm` so the existing candidate gathering uses only custom STUN in custom mode.

Do not read the environment in `newDerptunServeRuntime`, `newDerptunDialRuntime`, `DerptunAppServe`, `DerptunAppDialStream`, or any derpssh connect path.

Because `newAttachDialRuntime` and `newOpenExternalRuntime` already call `openDerptunDialDERP`, add attach and external-share assertions to their existing tests rather than adding another route resolver to either runtime.

- [ ] **Step 3: Prove custom STUN failure is relay-safe.**

Stub `gatherTraversalCandidates` to return a timeout for a custom map and run a force-relay=false derptun app-mux exchange. The exchange must still complete over DERP. Assert the gathered map has exactly the embedded custom node and never a public STUN node.

Then run the existing fake-direct test with a custom map and a successful candidate result. Assert the existing `connected-relay` then `connected-direct` transition remains possible. This guards against accidentally treating custom as force-relay.

- [ ] **Step 4: Exercise the derpssh-shared path.**

In `share_connect_test.go`, generate an invite under a custom environment, clear the variable, decode the invite, and assert its `DT2` client credential carries the same route as the `dts2_` server credential. The transport itself is covered by the derptun app-mux test because derpssh uses `DerptunAppServe`/`DerptunAppDialStream`; document that assertion in the test name.

- [ ] **Step 5: Run focused durable suites.**

```sh
mise exec -- go test ./pkg/session -run 'TestDerptun.*CustomDERP|TestDerptunApp.*CustomDERP|TestCustomSTUN|TestCustomDERP.*Direct' -count=1
mise exec -- go test ./pkg/derpssh/session -run 'Test.*Invite.*CustomDERP' -count=1
mise exec -- go test ./pkg/session ./pkg/derpssh/session -count=1
```

Expected: PASS with relay-safe STUN failure and unchanged direct-promotion behavior.

- [ ] **Step 6: Commit Task 5 files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "session: route durable tunnels through custom DERP" --changes <task-5-file-and-hunk-ids>
```

---

### Task 6: Web-relay tokens, product relay tests, and proxy enforcement

**Files:**

- Modify: `pkg/derphole/webrelay/relay.go`
- Modify: `pkg/derphole/webrelay/relay_test.go`
- Create: `pkg/session/custom_derp_test.go`
- Modify: `pkg/session/proxy_test.go`

- [ ] **Step 1: Add failing web-relay route tests.**

For native `webrelay.NewOffer`, set `DERPHOLE_DERP_SERVER`, use the existing DERP server URL test override, and assert the offer token is v6 with the custom route. Clear or conflict the environment before `Receive`; assert the receiver uses the token route. Introduce `var fetchWebRelayDERPMap = derpbind.FetchMap` and configure that public-map seam to fail if called in custom mode.

Keep the WASM path environment-neutral: a browser-created offer remains public v5 because browser processes do not receive this host environment variable, but a browser consumer can decode and use an externally created v6 web-file token.

- [ ] **Step 2: Implement web-relay route branching.**

`NewOffer` reads `RouteFromEnvironment` once, resolves public or custom node/URL, and passes the route into `newToken`. `newToken` sets `VersionForRoute` and `DERPRoute`. `receive` resolves solely from `tok.DERPRoute`. Public helper behavior and test overrides remain unchanged.

Do not add a second route type in `webrelay`; use `derpbind.Route` and the same one-node map.

- [ ] **Step 3: Add an end-to-end custom derphole relay test.**

Use `newSessionTestDERPServer` plus `DERPHOLE_TEST_DERP_SERVER_URL` to run a real force-relay `Listen`/`Send` payload exchange. Set the creator route to `https://custom.test.invalid`, capture the token, then clear `DERPHOLE_DERP_SERVER` before starting the sender. Assert:

- payload bytes match;
- decoded token is v6 and contains only `custom.test.invalid:443` plus STUN 3478;
- both verbose logs contain `derp-route=custom` and `connected-relay`;
- neither log names `tailscale.com` or a public DERP node;
- a public-map fetch counter remains zero.

Add the same real-relay assertion for `DerptunAppServe`/`DerptunAppDialStream` with `dts2_` and `DT2`.

- [ ] **Step 4: Extend the subprocess proxy fixture for custom route authority.**

Add scenarios `custom-relay` and `custom-derptun-app`. Give the embedded route `https://derp.proxy-test.invalid:80`, keep the fixture's test-only final URL `http://derp.proxy-test.invalid:80/derp`, and set `HTTP_PROXY` to the CONNECT fixture. The proxy must accept only:

```text
CONNECT derp.proxy-test.invalid:80 HTTP/1.1
```

After the creator emits its token, clear `DERPHOLE_DERP_SERVER` for the consumer. Assert at least two CONNECTs, no public-map request, successful payload/app-mux round trip, and redacted diagnostics. Existing public proxy scenarios must remain unchanged.

The production route remains HTTPS and therefore uses `HTTPS_PROXY`; this HTTP target exists only because the local DERP fixture is plaintext. Retain the existing `pkg/derpbind` HTTPS proxy tests as the production-scheme proof.

- [ ] **Step 5: Add fail-closed destination tests.**

Use a custom token whose host cannot resolve and a public-map provider that would succeed. Assert the session error contains the sanitized custom authority, the provider count remains zero, and no public client is created. Add the inverse public test to ensure an unset route still uses the public provider.

- [ ] **Step 6: Run product, proxy, mobile/WASM, and race-focused checks.**

```sh
mise exec -- go test ./pkg/derphole/webrelay -count=1
mise exec -- go test ./pkg/session -run 'TestCustomDERP|TestSessionProxySubprocess|Test.*ThroughHTTPProxy' -count=1
mise exec -- go test ./pkg/derpholemobile -count=1
mise exec -- env GOOS=js GOARCH=wasm go test ./cmd/derphole-web ./pkg/derphole/webrelay -run '^$'
mise exec -- go test -race ./pkg/derpbind ./pkg/token ./pkg/derptun ./pkg/session ./pkg/derphole/webrelay -count=1
```

Expected: PASS. The custom proxy fixture records only the embedded authority; the custom public-map counter remains zero.

- [ ] **Step 7: Commit Task 6 files.**

```sh
but diff
but commit codex/custom-derp-server-design -m "test: verify custom DERP product routing" --changes <task-6-file-and-hunk-ids>
```

---

### Task 7: Operator documentation and repeatable live smoke

**Files:**

- Create: `docs/derp/custom-server.md`
- Modify: `docs/derp/client-runtime.md`
- Create: `scripts/smoke-custom-derp.sh`

- [ ] **Step 1: Write the smoke script before documenting success.**

The script must:

- require `DERPHOLE_DERP_SERVER` and default `DERPHOLE_BIN` to `dist/derphole`;
- create a temporary directory and clean up the listener on every exit;
- start the listener with the custom variable and `--verbose --force-relay`;
- capture the first token-shaped stderr line;
- pipe a fixed payload through a consumer launched with `env -u DERPHOLE_DERP_SERVER`;
- compare payload bytes;
- require `derp-route=custom` and `connected-relay` in both logs;
- reject `connected-direct`, `derp1`, `derp2`, `tailscale.com`, and `controlplane.tailscale.com` in the logs;
- when `DERPHOLE_SMOKE_INSPECT=1` and `lsof` is available, keep both peers alive for five seconds, capture each PID's established TCP sockets, require the custom DERP address, and reject public Tailscale DERP destinations;
- when `DERPHOLE_LEGACY_BIN` is set, feed the captured v6 token to that pre-feature binary and require an immediate unsupported-version failure before starting the new consumer;
- print both logs on failure and a one-line success result on pass.

Validate shell syntax first:

```sh
bash -n scripts/smoke-custom-derp.sh
```

Expected: PASS.

- [ ] **Step 2: Document the creator/consumer contract.**

`docs/derp/custom-server.md` must include these exact operational facts:

- creator example: `DERPHOLE_DERP_SERVER=https://derp.example.com derphole --verbose listen`;
- accepted URL forms and HTTPS/certificate requirement;
- route is embedded; consumers do not set or override it;
- public v5/`dts1_`/`DT1` behavior remains the default;
- custom mode does not contact public Tailscale DERP or STUN infrastructure;
- STUN is the same host on UDP 3478 and is fail-soft;
- direct promotion remains enabled unless `--force-relay` is explicit;
- `HTTPS_PROXY` and `NO_PROXY` govern the DERP TCP connection, while STUN/direct UDP do not use HTTP proxy;
- a selected proxy failure and a custom DERP failure do not fall back direct/public;
- accepting a custom token authorizes an outbound TLS connection to its embedded host and port;
- operators of the custom relay see connection metadata, while peer payload protection remains end-to-end;
- both sides need a version containing custom-token support.

Link the new page from `docs/derp/client-runtime.md` beside the proxy section. Keep the prose mechanism-first and concise.

- [ ] **Step 3: Run the live relay-only smoke against the approved endpoint.**

```sh
mise run build
DERPHOLE_DERP_SERVER=https://derp.shayne.in \
  DERPHOLE_BIN=dist/derphole \
  DERPHOLE_SMOKE_INSPECT=1 \
  scripts/smoke-custom-derp.sh
```

Expected: payload round trip succeeds; both sides report the custom route and `connected-relay`; no direct transition or public DERP name appears.

The script's captured socket evidence must show the current address for `derp.shayne.in:443` and no public Tailscale DERP connection. Record DNS/IP observations as time-specific smoke evidence, not as product configuration.

- [ ] **Step 4: Build the pre-feature reference and prove it rejects only the custom format.**

```sh
legacy_dir="$(mktemp -d /tmp/derphole-custom-legacy.XXXXXX)"
git clone --quiet --no-local /Users/shayne/code/derphole "$legacy_dir"
git -C "$legacy_dir" checkout --quiet --detach "$(git rev-parse origin/main)"
(
  cd "$legacy_dir"
  mise run build
)
DERPHOLE_DERP_SERVER=https://derp.shayne.in \
  DERPHOLE_BIN=dist/derphole \
  DERPHOLE_LEGACY_BIN="$legacy_dir/dist/derphole" \
  scripts/smoke-custom-derp.sh
rm -rf "$legacy_dir"
```

Expected: the pre-feature binary reports the existing unsupported token version error for v6 without dialing a relay; the new consumer completes through the custom relay. The literal v5/`dts1_`/`DT1` tests remain the proof that newly generated public values are old-format compatible.

- [ ] **Step 5: Where a constrained proxy is available, repeat through it.**

```sh
DERPHOLE_DERP_SERVER=https://derp.shayne.in \
  HTTPS_PROXY="$https_proxy" \
  NO_PROXY= \
  DERPHOLE_BIN=dist/derphole \
  scripts/smoke-custom-derp.sh
```

Expected: PASS only if the proxy permits `CONNECT derp.shayne.in:443`. A target-policy timeout is an environmental result; do not bypass the embedded route or fall back public.

- [ ] **Step 6: Run full repository verification.**

```sh
mise run test
mise run check
```

Expected: PASS, including license, formatting, vet, tidy, static analysis, vulnerability, dependency, build, and full test gates. If `go mod tidy` changes dependency files unexpectedly, inspect the current `origin/main` baseline before committing them.

- [ ] **Step 7: Commit documentation and smoke harness.**

```sh
but diff
but commit codex/custom-derp-server-design -m "docs: explain custom DERP operation" --changes <custom-server-doc-id>,<client-runtime-hunk-id>,<smoke-script-id>
```

Expected: the normal hook passes and no generated `dist/` artifact is selected.

---

## Final Review Gate

- [ ] Confirm every approved behavior has a named test.

```sh
rg -n 'DERPHOLE_DERP_SERVER|CustomDERPVersion|CustomServerTokenPrefix|CustomClientTokenPrefix|derp-route=custom' pkg cmd docs scripts
rg -n 'FetchMap\(|PublicDERPMapURL' pkg/session pkg/derphole/webrelay
```

Expected: environment reads appear only at root creators; consumers route from decoded values; every public-map call is behind a public-route branch.

- [ ] Confirm compatibility and bounded custom formats.

```sh
mise exec -- go test ./pkg/token -run 'TestEncodeWireFormatContract|TestCustomDERP' -count=1
mise exec -- go test ./pkg/derptun -run 'Test.*Golden|Test.*CustomDERP' -count=1
```

Expected: v5, `dts1_`, and `DT1` literals match exactly; v6, `dts2_`, and `DT2` route bounds pass.

- [ ] Review only this branch's changes and scan for unfinished text.

```sh
but status -fv
but diff
rg -n '\b(TODO|FIXME|XXX)\b|implement later|left for follow-up' pkg cmd docs scripts \
  -g '!docs/superpowers/plans/2026-07-13-custom-derp-server.md'
```

Expected: the diff contains only custom DERP work, no unrelated dirty files, and no unfinished implementation notes.

- [ ] Create a recovery point, tidy the branch to reviewable commits, and rerun the full gate after any history edit.

```sh
but oplog snapshot -m "before custom DERP history cleanup"
mise run check
```

Expected: PASS on the exact final tree. Do not push or land on `main` unless the user explicitly asks.

## Acceptance Evidence Checklist

- [ ] Unset configuration emits the exact public v5, `dts1_`, and `DT1` goldens.
- [ ] `DERPHOLE_DERP_SERVER=https://derp.shayne.in` emits canonical custom route host, DERP 443, and STUN 3478.
- [ ] A consumer without the variable joins the embedded custom relay.
- [ ] A conflicting consumer variable is ignored.
- [ ] No custom path calls the public map provider or probes public STUN nodes.
- [ ] derphole completes a real relay-only payload transfer through the custom relay.
- [ ] derptun completes an app-mux exchange; derpssh invite credentials carry the identical route through that shared runtime.
- [ ] Custom HTTPS DERP uses the existing proxy-aware client and exact embedded CONNECT authority.
- [ ] Custom DERP failure is fail-closed; custom STUN/direct failure is relay-safe.
- [ ] Direct promotion still works when custom STUN/candidates succeed and force-relay is false.
- [ ] Old formats remain accepted by old/new binaries; custom versions fail clearly on old binaries.
- [ ] Focused tests, race tests, WASM compile, live smoke, `mise run test`, and `mise run check` pass.
