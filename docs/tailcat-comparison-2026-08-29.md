# Tailcat at HEAD: implications and proposal for Derphole

Research snapshot: 2026-08-29

## Executive conclusion

Tailcat validates Derphole's central premise: DERP can be used as an accountless rendezvous and relay while a userspace process promotes traffic to direct UDP. It also proves that Tailscale's full open-source data plane can now run without a control plane in a regular Go module.

It does **not** reveal a private DERP protocol or an open-source DERP-server fast path that Derphole is missing. Tailcat uses ordinary DERP packets and standard encrypted disco messages. The important Tailscale changes are client-side library hooks in `wgengine` and `magicsock`, plus an opaque application name in DERP client metadata. The public DERP server has no Tailcat-specific routing or rate-limit branch.

The best course is therefore:

1. Adopt the low-risk upstream improvements now: a current stable Tailscale module, honest DERP application attribution, live-and-cached DERP maps, nearest-region selection for ephemeral sessions, and clearer path diagnostics.
2. Run a bounded Tailcat-carrier experiment under `derptun`'s existing replaceable mux carrier. Do not put it under the optimized one-shot bulk path.
3. Keep Derphole's current transport as the production default unless the experiment either demonstrates better recovery or traversal on difficult networks, or provides an evidence-backed replacement that removes meaningful project-owned traversal machinery, without unacceptable startup, resource, security, or throughput regressions.
4. Do not switch to Tailcat's hosted relays, publish Derphole bearer tokens in DNS, or copy Tailcat's unstable wire format.

This is a hybrid proposal, not a rewrite.

## Scope and exact snapshots

The comparison used fresh repository state, not product descriptions alone:

| Repository | Compared revision | State |
|---|---:|---|
| Tailcat | [`88929418b1a`](https://github.com/tailscale/tailcat/commit/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb) | `main`, clean, equal to `origin/main` |
| Derphole working tree | `2dbb8ff041f1` | clean GitButler workspace commit |
| Derphole public source | [`7c951e2e568b`](https://github.com/shayne/derphole/commit/7c951e2e568b6ec09acb86b37a9ee1974142368e) | `main` / `origin/main`, v0.18.2 release commit |

The Derphole working commit and `origin/main` have identical trees, so the public-source links in this report describe the requested working HEAD exactly.

A local Tailcat checkout was compared without modifying either repository for
the analysis.

## The short architectural comparison

| Area | Tailcat | Derphole |
|---|---|---|
| Primary abstraction | Small userspace IP network with WireGuard identities | Session/tunnel transport with explicit bearer capabilities |
| Initial signaling | Custom `meow` payload over DERP | Authenticated claim/decision envelopes over DERP |
| Relay data | WireGuard IP packets over DERP | Derphole-encrypted packets / authenticated QUIC over DERP |
| Direct path | Tailscale `magicsock` and stock disco | Derphole candidate exchange, authenticated probes, selector, QUIC/raw UDP/direct TCP |
| TCP | gVisor netstack inside the process | OS TCP at edges; QUIC/app mux across the transport |
| Authorization | Server WireGuard address plus optional client-node allowlist | Expiring bearer secret, capability, listener QUIC identity; Derptun separates server and client credentials |
| Region bootstrap | Server node key plus region ID or embedded DERP node | Token region ID plus optional embedded custom DERP route |
| Bulk transfer | TCP over userspace WireGuard | Rate-probed/paced multi-lane direct UDP, repair/replay, QUIC fallback, direct TCP fast path |
| Browser direct | Not yet; browser is DERP-only | WebRTC direct path exists |
| Stability | Explicitly no API, CLI, or wire guarantees | Released CLI and token versions with compatibility tests |

Tailcat is smaller in its own source tree—25 Go files and about 6,271 Go lines at the snapshot—but it delegates most networking behavior to a large Tailscale/gVisor dependency graph. A clean arm64 `-trimpath` build produced a 28,404,802-byte Tailcat binary with 519 listed packages, versus a 24,047,090-byte Derphole binary with 457 listed packages. Those figures are directional standalone-build observations, not the incremental cost of adding Tailcat to Derphole.

## How Tailcat actually works

Tailcat describes itself as a control-plane-free remix of Tailscale's data plane: WireGuard for encryption, magicsock for DERP/direct UDP selection, and gVisor netstack for application TCP without a TUN device or host routing changes. Its README and package documentation make that architecture explicit. [Tailcat overview](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L9-L35), [package model](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L4-L30)

The connection flow is:

1. The server creates or loads a Tailscale node key, chooses one DERP region, starts `wgengine`, magicsock, and gVisor netstack, then publishes a `tc...` `ConnBlob`.
2. The blob contains the server node public key and either a DERP region ID or embedded DERP node metadata. It does not contain a symmetric bearer secret. [ConnBlob types](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L133-L203), [compact CBOR wire fields](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/wire.go#L10-L64)
3. The client connects to the same DERP region and sends an unencrypted-at-the-Tailcat-layer—but DERP-transport-protected—`meow` payload containing its node and disco public keys. [Meow framing](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/disco.go#L11-L67)
4. `OnDERPRecv` intercepts that payload before magicsock rejects an unknown peer. The server checks its optional client allowlist, adds the peer to an in-memory network map, and replies `meowed`. [Server interception](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L402-L423), [peer admission](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L1236-L1300)
5. WireGuard traffic can now flow over DERP. The engine obtains peer configuration lazily through `SetPeerConfigFunc`, `SetPeerByIPPacketFunc`, and `SetPeerForIPFunc`, rather than from a Tailscale control plane. [Engine configuration](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L1141-L1234)
6. When local UDP endpoints change, Tailcat constructs the stock encrypted `disco.CallMeMaybe` message and sends it through DERP. Stock magicsock then performs its normal pings and hole punching. This is not a custom disco extension. [Endpoint advertisement](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L1057-L1125)
7. gVisor netstack terminates application TCP and dispatches connections to `OnTCP` or `OnTCPForward`. This powers netcat piping, local port exposure, SOCKS, exit-node mode, and Tailcat's no-auth SSH server. [Server/netstack wiring](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L257-L337), [startup handlers](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L340-L470)

An unusual trick makes the server discoverable without an extra disco-key exchange: Tailcat deterministically reinterprets the node private key as a disco private key, so the client can predict the server's disco public key from the token. The upstream API explicitly labels forced disco keys as experimental/special-case behavior. [Tailcat engine setup](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L1337-L1370), [stable Tailscale API](https://github.com/tailscale/tailscale/blob/53a0d659afa51835dd7a9283873cca44261454f8/wgengine/userspace.go#L251-L263)

## Did Tailscale change DERP servers specially for Tailcat?

### What changed upstream

Three upstream change sets matter:

1. [`16fa81e8`](https://github.com/tailscale/tailscale/commit/16fa81e8047c51c7f25caaff485d5a91c08f10f2) added `ForceDiscoKey` for experiments and special cases.
2. [`073a9a8c`](https://github.com/tailscale/tailscale/commit/073a9a8c9ed449c1a620106084e43b0d38d1c5cb) added `OnDERPRecv`, `SendDERPPacketTo`, and the ability to start netstack with no `LocalBackend`. Its public commit message says these hooks are for out-of-tree projects to exchange custom signaling over DERP without a disco extension.
3. [`246c82a6`](https://github.com/tailscale/tailscale/commit/246c82a658b35851f5ca07fe503ce6b20b39e806) added an opaque application name to DERP `ClientInfo`, plumbed through `derphttp`, magicsock, and `wgengine`. Tailcat pins exactly that commit and sets `tailcat-client` or `tailcat-server`.

Tailcat switched from a private Tailscale branch to upstream immediately after the March hook commit, and added its application names immediately after the July commit. That chronology strongly suggests these were Tailcat-enabling changes. The public commits reference a private `tailscale/corp` issue rather than naming Tailcat, so the motivation is an evidence-backed inference rather than a publicly confirmed statement.

All of the required APIs are now present in stable [`tailscale.com v1.102.3`](https://github.com/tailscale/tailscale/releases/tag/v1.102.3), so Derphole does not need Tailcat's pseudo-version or an unreleased Tailscale fork.

### What did not change

The public DERP server still routes opaque packets by node public key. It does not parse `meow`, perform WireGuard setup, execute Tailcat's allowlist, or do Tailcat-specific path selection. `AppName` is optional metadata carried in encrypted client info; the open-source server patch stores/parses it and exposes a test hook, but contains no Tailcat-specific policy branch.

The earlier experimental custom-disco approach exists on an unmerged branch at [`adc96135`](https://github.com/tailscale/tailscale/commit/adc961352c92edf608eb752a84434a29093a5c5d). Mainline Tailcat deliberately uses the simpler generic DERP hooks and ordinary stock disco messages instead.

The dedicated Tailcat relay service is operational infrastructure, not a protocol requirement. On the research date, `https://tailcat.dev/derpmap.json` returned four regions—New York, San Francisco, Frankfurt, and Tokyo—with ETag and CORS headers. Sending `Tailcat-Mode: client` or `server` returned the same map from the test location, although Tailcat's code treats the header as a server-side filtering hint. The README calls these relays free and rate-limited and explicitly disclaims uptime and throughput guarantees. [Hosted-relay terms](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L492-L500)

Derphole should identify itself as Derphole on the normal public DERP network. It should not send Tailcat's application names or assume it is authorized to use Tailcat's dedicated map and relays.

## What Tailcat does better today

### 1. It delegates ordinary NAT traversal to the upstream owner

Tailcat gets interface monitoring, STUN, port mapping, endpoint refresh, disco pings, path switching, and network-change behavior from magicsock. That reduces the amount of project-specific traversal logic and keeps it close to Tailscale's production implementation.

This is most attractive for long-lived tunnels that must survive interface and NAT changes. It is less obviously attractive for Derphole's highly tuned one-shot bulk plane, where the project-specific behavior is the product.

### 2. Its DERP-map lifecycle is substantially more robust

Tailcat's resolver has:

- one-hour cache freshness;
- ETag revalidation;
- a 10-second fetch timeout;
- an 8 MiB response limit;
- stale-last-known-good fallback;
- process-memory and CLI disk-cache implementations;
- optional self-contained tokens with embedded DERP node data.

[Tailcat cache contract](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L90-L129), [fetch behavior](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L820-L885)

Derphole's default public-map path currently returns Tailscale's compiled `dnsfallback` map instead of making the URL request. Custom URLs use `http.DefaultClient` with status checking but no explicit timeout, size limit, ETag, or stale fallback. [Derphole map resolver](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/derpbind/map.go#L17-L44)

This also exposes a documentation mismatch: the README says public sessions fetch the map at runtime, while the default code path uses the dependency's compiled snapshot. [README statement](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/README.md#L36-L39)

### 3. It chooses a nearby bootstrap relay

Tailcat runs Tailscale netcheck against the current map and selects the lowest-latency region, with a fallback when measurement fails. [Selection flow](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L900-L993)

Derphole's new-session path currently calls `firstDERPNode` with region zero; that selects the first sorted region and stores it in the token. [Session issuance](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/session/external.go#L147-L204), [region selection](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/session/external.go#L463-L478)

For an ephemeral one-shot listener this is a straightforward opportunity: choose a relay near the listener once and put that region in the existing token.

It is **not** safe to redefine region zero as “nearest to each peer” for durable Derptun credentials. Server and client can independently choose different relays and never rendezvous. Tailcat has the same durable single-region problem and tracks multi-region/failover work in [issue #7](https://github.com/tailscale/tailcat/issues/7).

### 4. Its CLI makes path state easy to interrogate

`tailcat ping --until-direct` reports relay versus direct RTT and returns failure if a direct path does not appear within the timeout. It also has `parse` and `resolve` commands for its public-only address blobs. [Tailcat diagnostic CLI](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L121-L196)

Derphole already has much richer internal data—candidate snapshots, selected RTT, upgrade/fallback counts, and sequenced path events—but normal user output reduces that mostly to `connected-relay` and `connected-direct`. [Path event model](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/transport/path_events.go#L12-L75), [README output](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/README.md#L255-L276)

## What Derphole should keep

### Explicit capability tokens

Derphole's one-shot token contains a session ID, expiry, bootstrap region, DERP public key, QUIC public identity, 32-byte bearer secret, capability bits, and optional custom route. [Token schema](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/token/token.go#L19-L75)

Tailcat's blob is an address. Unless the server configures a client-node allowlist, anyone who knows it can initiate a WireGuard peer connection. Saved Tailcat keys intentionally make that address stable across restarts. [Tailcat key model](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L198-L245)

Those models serve different jobs. Derphole should retain expiry, capability scoping, separate QUIC identity, and Derptun's server/client credential separation.

### The optimized data planes

Derphole already has its own authenticated candidate updates and `call-me-maybe`, direct-path probes, stale demotion, endpoint ranking, path snapshots, and recovery loop. [Control messages](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/transport/control.go#L17-L114), [manager configuration](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/transport/manager.go#L31-L124)

More importantly, Derphole's one-shot transfer path does work Tailcat does not attempt: multi-lane rate probing, pacing, adaptive rate control, targeted replay/repair, a direct TCP fast path, authenticated QUIC streams, and browser WebRTC. Tailcat's application-layer UDP is still [issue #23](https://github.com/tailscale/tailcat/issues/23), and browser direct connectivity is still [issue #4](https://github.com/tailscale/tailcat/issues/4).

A wholesale Tailcat replacement would give up differentiated functionality in exchange for a simpler generic TCP tunnel.

### Derpssh's approval model

Tailcat's built-in SSH server uses SSH `NoClientAuth`; it relies on the WireGuard peer identity and optional Tailcat client-key allowlist. Derpssh has explicit host approval, read/write roles, kick/revoke behavior, chat, and a purpose-built terminal UI. Those are product semantics, not transport details, and should remain above any carrier experiment.

## Tailcat's current risks

Tailcat is unusually clear that its API, CLI, and wire format can change. [Stability statement](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L27-L30)

Specific HEAD-level risks include:

- [`Server.Start` / `Client.initLocked` partial-start leaks](https://github.com/tailscale/tailcat/issues/18);
- a PTY lifecycle hang under active work in [issue #17](https://github.com/tailscale/tailcat/issues/17);
- `DrainTCP` using reflection and `unsafe` to reach an unexported gVisor stack, with a panic if upstream internals move; [source](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/tailcat.go#L525-L570)
- a process-wide `netns.SetEnabled(false)` side effect during engine creation;
- single-region durable addresses with unresolved failover behavior;
- no application UDP and no browser direct path;
- hosted relays with no service guarantee.

The exact Tailcat HEAD has a successful upstream GitHub `Test` run ([33233768836](https://github.com/tailscale/tailcat/actions/runs/33233768836)). Locally, `go test -count=1 -timeout 120s ./...` passed every package except `TestSSHSuite/EnvForwarding`; this machine's configured user shell reset `LANG` and `LC_ALL`, making that test non-hermetic here. That local result is not evidence of a transport failure, but it reinforces the project's early-stage status.

## Proposed Derphole update

### Phase 0: dependency and attribution foundation

Do this first, independently of any Tailcat carrier:

1. Raise the toolchain floor from Go 1.26.1 to Go 1.26.6.
2. Upgrade `tailscale.com` from v1.96.5 to stable v1.102.3, which contains all three Tailcat-enabling API sets.
3. Set `derphttp.Client.AppName = "derphole"` before connecting.
4. Update the reachable vulnerable dependencies found in this snapshot's `govulncheck` run:
   - `golang.org/x/crypto` to at least v0.55.0 for GO-2026-6303;
   - Pion DTLS to at least v3.1.4 for GO-2026-6165;
   - Pion STUN to at least v3.1.5 for GO-2026-6163.
5. Run the full repository gate plus local/remote transport smoke tests because the Tailscale jump spans several internal networking changes.

The AppName is for transparent usage statistics, not an authentication claim. Old DERP servers ignore the new optional JSON field. Use the umbrella name `derphole`; do not pretend to be `tailcat-client` or `tailcat-server`.

Likely code impact:

- `go.mod`, `go.sum`, `.mise.toml` or equivalent toolchain declaration;
- `pkg/derpbind/client.go` for AppName;
- dependency compatibility fixes and tests.

### Phase 1: a real DERP-map resolver and better ephemeral region choice

Replace the special-case function in `pkg/derpbind/map.go` with a typed resolver, for example:

```go
type MapResolver struct {
	HTTPClient *http.Client
	Cache      MapCache
	MaxAge     time.Duration
	MaxBytes   int64
	Timeout    time.Duration
	Fallback   func() *tailcfg.DERPMap
}
```

Required semantics:

- fetch the current public map rather than always returning the compiled snapshot;
- bound time and response bytes;
- revalidate with ETag after a freshness window;
- use stale last-known-good data on fetch failure;
- retain `dnsfallback.GetDERPMap()` as the final offline seed;
- keep custom token-embedded DERP routes self-contained;
- use an injected HTTP client and clock in tests;
- never mutate a cached map shared by callers;
- record whether the result was fresh, revalidated, stale, or compiled fallback.

Then, for **new ephemeral one-shot sessions only**:

1. Run a bounded Tailscale netcheck against that map.
2. Pick the lowest-latency usable region.
3. Fall back to the first valid region in the frozen legacy-compatible set if the probe budget expires. Persisting the last successful region was considered and rejected for the initial implementation because it adds location-staleness and migration policy without changing the token contract.
4. Put the selected region in the existing `BootstrapRegion` token field.

Do not change existing token decoding or custom-DERP behavior in this phase.

Likely code impact:

- `pkg/derpbind/map.go` plus a cache file;
- a small `RegionSelector` interface using Tailscale netcheck;
- `pkg/session/derp_route.go` and one-shot issuance;
- `pkg/derphole/webrelay` so browser and native clients share resolver semantics;
- focused cache, stale-fallback, map-mutation, and selection tests.

### Phase 2: expose the path data Derphole already has

Add two diagnostics rather than copying Tailcat's commands literally.

#### Redacted token inspection

Add `derphole token inspect`, `derptun token inspect`, and `derpssh invite
inspect`, accepting the same inline/file/stdin sources as the corresponding
connection commands. Output only:

- token kind and wire version;
- expiration and expired/not-expired state;
- capabilities;
- public/custom route kind and bootstrap region;
- redacted session/client identifiers.

Never print `BearerSecret`, Derptun `SigningSecret`, server private keys, full client proof material, or a reconstructable token. Tailcat can safely print its public-only address metadata; Derphole cannot copy that behavior because its tokens are passwords.

#### Peer-specific direct-path diagnostics for durable tokens

Add a command shaped like:

```text
derptun probe --token-file client.dt1 --until-direct --timeout 10s --json
```

It should perform the ordinary authenticated Derptun claim, establish the
existing QUIC control connection without opening a target stream, and use
`transport.Manager.PathEvents` to report:

- time to authenticated relay connectivity;
- time to direct selection, if any;
- selected path class and RTT;
- candidate count/classes and fallback reason;
- map source/freshness and bootstrap region;
- a stable JSON schema for automation.

Do not add the same command for a one-shot Derphole token until the claim semantics can guarantee the probe does not consume or invalidate the transfer.

For normal `--verbose` flows, enrich path transitions from bare state names to selected RTT and endpoint class. Keep raw IP addresses behind a more explicit debug mode because they are operationally sensitive.

Derpssh should also expose `derpssh doctor`, which unwraps an invite and runs
the same transport proof without starting a shell, sending terminal data, or
triggering host approval. Its output must say that the application protocol
was not tested.

Add `--write-access PATH` to commands that create tokens, invites, connect
commands, or ready addresses. Write one atomic 0600 JSON document instead of
putting another machine-readable stream on stdout, where Derphole payloads and
the Derpssh TUI already live. [Tailcat JSON and address-file
output](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/cmd/tailcat/tailcat.go#L776-L802)

### Phase 3: scoped multi-service Derptun

Tailcat's multi-port serving and one-command SOCKS workflow are worth porting,
but not its broad `--serve=all` or exit-node authority.
[Multi-port serving](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L85-L103),
[child-process SOCKS](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md#L134-L153)

The Derptun version should provide:

- named server forwards such as `web=127.0.0.1:3000` and
  `metrics=127.0.0.1:9090`;
- client credentials whose proof covers an immutable allowed-name subset;
- `derptun open --forward web` for an ordinary local listener;
- `derptun run -- curl http://web.derptun.invalid/`, backed by an ephemeral
  loopback SOCKS proxy that accepts authorized names only;
- a new credential and stream version, leaving all current credentials on
  their permanent single-target behavior.

The proxy must reject raw IPs, arbitrary DNS, UDP, BIND, and unknown names.
This work needs a focused credential/wire spec before implementation. It is
the product track after the shared foundation; the carrier experiment is a
peer internal track, not a prerequisite or a subordinate cleanup task.

### Phase 4: optional Tailcat carrier under Derptun

This is the experiment, not the default implementation.

The deeper design trace refined this recommendation. The normal
`derptun serve/open/connect` path uses native striped QUIC streams;
`Mux.ReplaceCarrier(io.ReadWriteCloser)` is the existing seam for Derpssh and
the Derptun app API. A fair experiment therefore needs a `quic-mux` control
and a Tailcat-derived carrier below that same mux, while `quic-native` remains
the production baseline. [Mux carrier seam](https://github.com/shayne/derphole/blob/7c951e2e568b6ec09acb86b37a9ee1974142368e/pkg/derptun/mux.go#L41-L152)

Do not import Tailcat unchanged. Tailcat hard-codes `tailcat-client` and
`tailcat-server` as its DERP application names and exposes no override, so an
unchanged import would misattribute Derphole traffic. Build a build-tagged
`internal/magicsockcarrier` experiment directly on the stable Tailscale hooks
instead. It should:

1. own all direct interaction with the stable upstream hooks;
2. derive/load the server node identity from the existing Derptun server credential;
3. authenticate the custom DERP admission hello before adding a WireGuard peer;
4. establish one userspace TCP connection and give it to the Derptun mux as an `io.ReadWriteCloser`;
5. set `DERPAppName="derphole"`;
6. export redacted path and lifecycle observations through a small project-owned API;
7. be selectable only in an experimental build until evaluation completes.

The implementation-grade contract and acceptance thresholds are in the
[Tailcat-derived transport modernization
spec](superpowers/specs/2026-08-29-tailcat-derived-transport-modernization-design.md).

Do not initially wire this carrier to:

- `listen/pipe` or `send/receive` bulk transfer;
- browser transport;
- raw UDP/data-plane APIs;
- the default `derptun` or `derpssh` path.

`derpssh` needs no direct Tailcat integration. If the carrier works under Derptun, Derpssh inherits it below its existing app mux and approval protocol.

### Phase 5: durable multi-region bootstrap

Treat relay failover as an independent durable-product design rather than a
carrier prerequisite. When it is prioritized, design a new durable token
version that supports relay failover. Reasonable candidates are:

- two ordered region IDs;
- one preferred region plus approximate location for nearest surviving-region fallback;
- an embedded small set of DERP nodes;
- server registration in two regions with client racing.

Requirements:

- old tokens retain their current deterministic bootstrap behavior;
- both peers can rendezvous after a region disappears or the map renumbers;
- token growth is bounded;
- no client-selected arbitrary relay URL bypasses route validation;
- failover does not leak server credentials or broaden client authority;
- custom DERP routes keep working without contacting a public map.

Tailcat issue #7 is useful prior art, but its single-region wire format should not be copied as the final Derptun design.

## Carrier experiment and acceptance gates

Extend `derphole-probe matrix` with a carrier axis rather than creating a separate benchmark harness:

| Scenario | Current carrier | Tailcat carrier | Required observation |
|---|---|---|---|
| Same LAN | yes | yes | startup, direct time, throughput, CPU |
| Typical home NAT ↔ cloud | yes | yes | relay TTFB, direct promotion p50/p95 |
| Symmetric / endpoint-dependent NAT | yes | yes | success rate and sustained fallback behavior |
| UDP blocked | yes | yes | relay correctness and reconnect |
| IPv6-only / dual-stack | yes | yes | address-family selection and recovery |
| Interface change during tunnel | yes | yes | interruption and recovery time |
| Suspend/resume | yes | yes | reconnect correctness and resource cleanup |
| Browser peer | current only initially | no | explicit non-goal, no regression |
| 1 GiB bulk | current only | no | protect current optimized path |

Promotion gates:

- no authentication or token-scope regression;
- no plaintext application data visible at DERP;
- all existing Derptun/Derpssh smoke and reconnect tests pass;
- direct promotion succeeds at least as often as the current carrier across the matrix;
- relay time-to-first-byte and steady-state direct throughput are not materially worse;
- network-change recovery is measurably better or fixes cases the current carrier misses;
- no goroutine/resource leak across repeated start/fail/close cycles;
- binary/RSS/dependency cost is recorded and accepted;
- rollback is a carrier selection change, not a token migration.

Do not set a production default from a single successful LAN demo.

## Things specifically not to copy

1. **Tailcat's hosted map or AppName.** Use public Tailscale DERP or explicit custom DERP configuration and identify as `derphole`.
2. **DNS publication of connection tokens.** Every Derphole and Derptun client token carries bearer authority. DNS publication would publish a password. Tailcat's protected DNS example is safe only because a separately held client private key is allowlisted.
3. **Tailcat's wire format.** It is explicitly unstable and lacks Derphole's expiry/capability/auth fields.
4. **`opts ...any`.** Use typed configs and interfaces for resolver/carrier behavior.
5. **Reflection/unsafe into netstack internals.** If a necessary accessor is missing, contribute it upstream or avoid the dependency.
6. **A silent saved-key default.** Derphole's durable credentials are explicit files/flags and should remain so.
7. **A broad no-auth SSH server.** Preserve Derphole SSH invitation semantics and Derpssh host approval.
8. **One-region durable tokens without a migration plan.** Tailcat itself identifies that as unfinished.
9. **An unrestricted SOCKS proxy, serve-all mode, or exit node.** Named,
   credential-scoped forwards provide the useful workflow without ambient
   network authority.

## Prioritized implementation backlog

| Priority | Work | Benefit | Risk |
|---:|---|---|---|
| P0 | Go 1.26.6, Tailscale v1.102.3, vulnerable dependency updates | security baseline and stable upstream hooks | medium dependency churn |
| P0 | Set DERP AppName to `derphole` | transparent upstream usage attribution | very low after upgrade |
| P1 | Typed live/cached/stale DERP map resolver with compiled fallback | current relay data and startup resilience | low/medium |
| P1 | Nearest relay for new ephemeral sessions | lower rendezvous and relay latency outside the first map region | medium; probe budget |
| P1 | Redacted token and invite inspection | supportability without credential leakage | low if redaction is tested |
| P1 | `derptun probe` and `derpssh doctor` | peer-specific diagnostics using existing path events | low/medium |
| P1 | Atomic access artifacts across all three products | reliable service-manager and wrapper integration | low/medium |
| P2 product | Scoped multi-service Derptun and restricted `run` proxy | one credential for related services without local-port plumbing | high; new credential/stream version |
| P2 internal | Tailcat carrier spike below Derptun mux | tests upstream magicsock recovery and whether stable upstream machinery can replace custom traversal ownership | medium/high, experimental |
| P2 internal | Add carrier dimension to production benchmark matrix | evidence for the default decision and internal ownership tradeoff | low |
| P3 shared | Durable multi-region token/bootstrap version | relay outage and map-change resilience | high protocol/migration work |
| Reject | Replace all Derphole transports with Tailcat | would discard differentiated bulk/browser/security behavior | unacceptable without evidence |

## Final recommendation

Approve Phases 0–2 as ordinary Derphole improvements. They are valuable even if Tailcat is never linked.

After the shared foundation, treat Phases 3 and 4 as independently reviewable
peer tracks. Neither should block the other.

Approve Phase 3 as the product-surface track after a focused credential and
stream specification. It ports the useful multi-service and child-process
workflow without granting general network access.

Approve Phase 4 as an isolated internal app-mux carrier experiment with
explicit measurements. The existing `Mux.ReplaceCarrier` boundary makes this
disciplined for Derpssh and the Derptun app API; the normal Derptun CLI needs an
explicit mux comparison mode because it is not already on that seam. The
experiment can justify a separate production negotiation design through either
of two outcomes: materially better hard-network recovery, or a concrete plan
that removes project-owned endpoint discovery, NAT traversal, path-selection,
or network-change state without a product regression. It must name the files
and state machines that would disappear; moving or duplicating the same logic
does not count as an internal benefit.

Defer Phase 5 until durable relay resilience is separately prioritized and a
token-compatibility design is approved. It need not wait for, or block, the
carrier experiment. Do not solve durable rendezvous by letting both peers
independently pick “nearest”; that creates a correctness bug.

The core lesson from Tailcat is not that Derphole should become a WireGuard
overlay. Its simple inspect, ping, multi-service, automation, and command-proxy
workflows are worth adapting, and upstream Tailscale now exposes enough
supported seams to test its path engine where Derphole is most generic.
Derphole should continue owning the capability model, least-privilege product
UX, optimized bulk plane, browser path, and application protocols that make it
distinct.

## Primary sources

- [Tailcat repository at the compared HEAD](https://github.com/tailscale/tailcat/tree/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb)
- [Tailcat architecture and stability documentation](https://github.com/tailscale/tailcat/blob/88929418b1a3f3c74904a3136d6a9e87b1b5b9bb/README.md)
- [Tailscale DERP protocol documentation](https://github.com/tailscale/tailscale/blob/main/derp/README.md)
- [Tailscale DERP server documentation](https://github.com/tailscale/tailscale/blob/main/cmd/derper/README.md)
- [Tailscale generic DERP hooks commit](https://github.com/tailscale/tailscale/commit/073a9a8c9ed449c1a620106084e43b0d38d1c5cb)
- [Tailscale forced disco key commit](https://github.com/tailscale/tailscale/commit/16fa81e8047c51c7f25caaff485d5a91c08f10f2)
- [Tailscale DERP AppName commit](https://github.com/tailscale/tailscale/commit/246c82a658b35851f5ca07fe503ce6b20b39e806)
- [Derphole source at the tree compared](https://github.com/shayne/derphole/tree/7c951e2e568b6ec09acb86b37a9ee1974142368e)
