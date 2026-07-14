# Self-Contained Custom DERP Servers

**Date:** 2026-07-13

## Summary

Allow derphole, derptun, and derpssh to use one operator-supplied DERP server
instead of the public Tailscale DERP network. The token creator opts in with:

```sh
export DERPHOLE_DERP_SERVER=https://derp.example.com
```

The creator validates the endpoint and embeds a compact relay locator in the
token or durable credential. The other peer does not need matching local
configuration. It reads the locator from the token, connects to the same DERP
server, and uses that host for STUN candidate discovery when direct probing is
enabled.

The normal case stays normal. When `DERPHOLE_DERP_SERVER` is unset, derphole
continues to emit the current token versions and use the current bundled public
DERP map. Default tokens do not get larger, existing peers do not need an
upgrade, and custom-route machinery does not enter packet or transfer hot
paths.

## Motivation

HTTP proxy support solves only half of constrained egress. A proxy may support
`CONNECT` while still denying Tailscale-operated DERP hostnames. In that
environment, a perfectly good proxy-aware dialer reaches the proxy and then
waits forever for a tunnel the proxy will never grant. Changing the client
headers does not fix an egress policy.

An operator-controlled DERP server gives the environment a destination it can
actually reach and allowlist. The awkward part is telling the other peer where
that relay lives. A local environment variable on both machines sounds simple,
but it makes a shared token depend on invisible state on the receiving machine.
The token is supposed to carry what the peer needs. The relay locator belongs
there too.

`derp.shayne.in` is the initial live smoke target. It currently presents a
valid public TLS certificate and accepts an HTTP/1.1 DERP upgrade at
`https://derp.shayne.in/derp`.

## Goals

- Select one custom DERP server with `DERPHOLE_DERP_SERVER` when creating a
  token or durable credential.
- Make custom tokens self-contained so consuming peers need no matching
  environment variable.
- Use the custom server for DERP relay and its hostname on UDP 3478 for STUN.
- Avoid all public Tailscale DERP and STUN infrastructure in custom mode.
- Preserve direct discovery and promotion when the network permits them.
- Remain relay-capable when custom STUN or every direct path fails.
- Keep HTTP proxy handling below the product layer and apply it to the custom
  DERP URL through the existing proxy-aware dialer.
- Preserve current public token bytes, credential formats, map selection, and
  runtime behavior when the environment variable is unset.
- Apply the same route semantics to derphole, derptun, and derpssh.

## Non-goals

- Multiple custom DERP nodes, regional selection, or custom-relay failover.
- Embedding or fetching an arbitrary DERP map.
- A custom STUN hostname or port in the first version.
- Plaintext HTTP DERP endpoints in production configuration.
- CLI flags or configuration files for DERP selection.
- Letting a token consumer override the token route with local environment.
- Falling back to public DERP after a custom-route failure.
- Automatically enabling `--force-relay` in custom mode.
- Making DERP work through a proxy that does not permit `CONNECT` to the custom
  hostname and port.

## The Default Path Stays Boring

Most users should never know this feature exists. An unset
`DERPHOLE_DERP_SERVER` keeps the current public path:

1. Token creators emit the existing one-shot v5 token.
2. Derptun emits the existing `dts1_` server credential and `DT1` client
   credential.
3. Derpssh continues to use those derptun credentials.
4. Session startup uses the existing static Tailscale fallback map and current
   node-selection logic.
5. Transport and packet processing remain unchanged.

The only additional work on token creation is one environment lookup. Public
token consumption does not consult the custom-server environment at all. No
custom locator is allocated, serialized, decoded, or carried through the data
plane for public sessions.

Golden tests must prove that representative public tokens and credentials keep
their exact version, length, and bytes. Compatibility should be measured, not
described hopefully.

## Configuration and Canonicalization

`DERPHOLE_DERP_SERVER` is read only while creating a token or durable
credential. It is not a runtime override for a token supplied by another peer.

Accepted values use one of these forms:

```text
https://derp.example.com
https://derp.example.com/
https://derp.example.com/derp
https://derp.example.com:8443/derp
```

The parser requires:

- the `https` scheme
- a non-empty ASCII hostname or IP literal
- a valid optional port in the range 1 through 65535
- no URL userinfo
- no query string or fragment
- an empty path, `/`, or `/derp`

DNS names are lowercased and normalized without a trailing dot. IP literals
are stored in canonical textual form. Operators who need an internationalized
name supply its ASCII punycode form. The canonical DERP path is always
`/derp`, the default DERP port is TCP 443, and the default STUN port is UDP
3478.

The token stores a structured locator rather than the original URL:

```text
host       derp.example.com
derp_port  443
stun_port  3478
```

Both creation and decoding validate the structured locator. A malformed value
fails before any network connection is attempted.

## Route Model

`pkg/derpbind` owns a small route type with two states:

- public, represented by the zero/default value
- custom, represented by a validated hostname, DERP port, and STUN port

The public state calls the current map and server-selection functions without
constructing a synthetic map. The custom state builds one in-memory
`tailcfg.DERPMap` containing one region and one node:

- the node hostname is the embedded custom hostname
- `DERPPort` is the embedded DERP TCP port
- `STUNPort` is the embedded STUN UDP port
- configured direct IP fields remain empty so normal DNS and proxy behavior
  apply

The custom map is the only DERP map passed into traversal and transport setup
for that session. Custom mode does not call the public-map fallback and does
not retain public nodes as alternate STUN targets.

Session constructors should accept or derive this route at connection setup
rather than reading package-global environment in every helper. The route is
bootstrap state. Once DERP and traversal are configured, the transfer hot path
does not need to know where the route came from.

## Token and Credential Formats

Public formats remain unchanged. Custom routes use distinct versions so an old
binary rejects them instead of silently joining the wrong relay.

### One-shot session tokens

Public sessions continue to encode the current fixed v5 payload. A custom
session uses v6 and appends a bounded locator extension after the current
fixed fields and before the checksum:

```text
host_length  uint8
host         host_length bytes
derp_port    uint16
stun_port    uint16
```

The host length is between 1 and 253 bytes. The existing CRC covers the fixed
payload and custom extension. A v6 decoder derives the exact expected size
from the length byte and rejects truncation, trailing data, invalid ports, and
non-canonical hosts.

The synthetic custom map uses a fixed internal region ID. Custom consumers do
not interpret `BootstrapRegion` against the public map.

### Derptun credentials

Public derptun generation keeps the current version 1 formats:

- `dts1_` JSON server credential
- fixed-size compact `DT1` client credential

A custom server credential uses `dts2_` and stores the same structured locator
alongside its existing private identity. Client credentials derived from it use
`DT2` and copy the locator into their versioned compact payload. The v2 client
codec shares the locator wire rules with the one-shot token codec instead of
inventing a similar-but-different parser.

New binaries decode both public v1 and custom v2 credentials. Old binaries
reject the new prefixes. Public credentials remain readable by old and new
binaries.

### Derpssh credentials

Derpssh continues to use the derptun-backed session and credential model. It
does not add another DERP field, parser, or token version. Custom DERP support
arrives through the same `dts2_` and `DT2` route propagation used by derptun.

## Creation and Consumption Rules

Any command that creates a root session token or durable server credential
checks `DERPHOLE_DERP_SERVER` once:

- unset means generate the existing public format
- valid means generate the custom version and embed the locator
- invalid means fail before printing or persisting a token

Deriving a client credential from an existing derptun server credential does
not read the environment. It inherits the server credential's public or custom
route. Otherwise changing one shell variable while issuing a client token
would quietly split the server and client across different relays, which is an
impressive amount of trouble for one lookup.

Any command that consumes a token uses the token as the route authority:

- a public token uses the public Tailscale DERP map
- a custom token uses its embedded custom route
- the consumer's `DERPHOLE_DERP_SERVER` value is ignored in both cases

This distinction matters for durable credentials. A derptun server remembers
the route in its server credential. Every later client credential derived from
that server credential copies the same route. Restarting either side under a
different environment does not move the service to another relay by accident.

## Connection and Traversal Flow

Custom session startup proceeds as follows:

1. Decode and validate the token locator.
2. Build the single-node custom DERP map.
3. Construct `https://<host>[:port]/derp` from the structured locator.
4. Connect the DERP client to that URL.
5. Pass the same custom map into candidate gathering and transport setup.
6. Try local interface candidates, port mapping, and custom STUN when direct
   probing is enabled.
7. Continue on DERP when direct discovery or validation fails.
8. Promote to a validated direct path normally when one succeeds.

`--force-relay` still skips direct probing. Merely selecting a custom DERP
server does not set force-relay policy. The likely outcome in a locked-down
environment is relay-only, but likely is not the same thing as mandatory.

Custom STUN is fail-soft. A custom derper normally exposes STUN on UDP 3478.
If it does not, or UDP egress is blocked, candidate gathering records the
failure and continues with the relay connection. There is no fallback probe
against public STUN nodes.

## HTTP Proxy Interaction

The custom DERP URL goes through the existing `pkg/derpbind` proxy-aware
dialer. For an HTTPS custom route:

- `HTTPS_PROXY` and its lowercase form select the proxy
- `NO_PROXY` and its lowercase form can exempt the custom hostname
- an applicable proxy receives `CONNECT <custom-host>:<derp-port>`
- a selected proxy failure does not fall back to direct DERP TCP

The proxy must permit a long-lived CONNECT tunnel to the custom destination.
Once the tunnel succeeds, DERP TLS and the DERP HTTP upgrade run inside it as
they do for a public node. Direct UDP and STUN traffic do not use the HTTP
proxy.

## Failure Behavior

Custom configuration is authoritative and fails closed:

- Invalid `DERPHOLE_DERP_SERVER` prevents token creation.
- Invalid custom token data prevents token consumption.
- DNS, TCP, proxy CONNECT, TLS, or DERP upgrade failure for the custom server
  fails the session explicitly.
- A custom DERP failure never falls back to the public map.
- Custom STUN failure is nonfatal while DERP remains connected.
- Direct-path failure is nonfatal while DERP remains connected.

Errors should name the failed stage and sanitized custom hostname and port.
They must not dump opaque token contents. Proxy errors retain their existing
credential redaction rules.

## Security and Privacy

A custom token is a connection capability. Accepting it authorizes an outbound
TLS connection to the embedded hostname and port. That is new authority
compared with a public token, which selects only a compiled public map, so the
constraint must be visible in documentation rather than hidden behind the
word "custom."

The feature narrows token-controlled destinations by requiring HTTPS, a fixed
DERP path, no credentials, and bounded hostname and port fields. It does not
ban private DNS or private IP destinations because private custom relays are a
valid deployment. TLS certificate and hostname validation remain mandatory.

The custom DERP operator can observe client source addresses, DERP identities,
connection timing, duration, and byte volume. Peer payload protection remains
end-to-end and does not depend on trusting the relay with plaintext. The route
locator itself is not secret and is visible to anyone holding the token.

## Observability

Default output remains unchanged. In verbose diagnostics, custom sessions
should emit one sanitized bootstrap event such as:

```text
derp-route=custom derp=derp.example.com:443 stun=derp.example.com:3478
```

Proxy diagnostics continue to report the selected proxy and the custom DERP
target without credentials. Existing `connected-relay`, `probing-direct`, and
`connected-direct` states remain authoritative for transport behavior.

Public sessions do not emit a new route event merely because custom support
exists.

## Testing Strategy

### Default compatibility tests

- Golden-test representative public v5 session token bytes and length.
- Golden-test public `dts1_` and `DT1` credential bytes and prefixes.
- Verify unset configuration takes the current public-map path.
- Verify public session startup does not allocate or construct a custom map.
- Run existing public DERP, relay, direct-promotion, derptun, and derpssh tests
  unchanged.

### Configuration and codec tests

- Accept the supported HTTPS URL forms and canonicalize them identically.
- Reject HTTP, missing hosts, invalid ports, userinfo, query strings,
  fragments, unexpected paths, oversized hosts, and non-canonical token data.
- Round-trip one-shot v6 tokens across default and custom ports.
- Round-trip `dts2_` server and `DT2` client credentials.
- Verify derived clients preserve the exact server locator.
- Verify new decoders accept legacy public formats.
- Verify legacy-version paths reject custom extensions and trailing bytes.

### Route and failure tests

- Build a synthetic map containing exactly one custom node.
- Verify custom mode never asks the public-map provider for a map.
- Verify token route wins over conflicting consumer environment.
- Verify custom DERP connection failure does not attempt a public node.
- Verify unreachable custom STUN remains relay-capable.
- Verify successful custom STUN still permits normal direct promotion.

### Product integration tests

- Exchange a real derphole payload through a local custom DERP fixture.
- Exercise derptun's application mux through the same custom route; this also
  covers derpssh's shared transport path.
- Generate a custom credential on one process and consume it in a process with
  no custom-server environment.
- Route custom DERP through an HTTP CONNECT fixture and verify the CONNECT
  authority is the embedded custom host and port.
- Block every public DERP destination in the fixture and verify the custom
  relay still completes.

### Live smoke test

Use `derp.shayne.in` for an explicit relay-only transfer:

```sh
DERPHOLE_DERP_SERVER=https://derp.shayne.in \
  derphole --verbose listen --force-relay

printf 'custom derp smoke' | \
  derphole --verbose pipe --force-relay <token>
```

The consuming process runs without `DERPHOLE_DERP_SERVER`. The payload must
round-trip, both peers must report `connected-relay`, and connection inspection
must show the custom hostname with no public Tailscale DERP connection.

Where a constrained HTTP proxy is available, repeat with `HTTPS_PROXY` and
verify the proxy permits CONNECT to `derp.shayne.in:443`. A proxy-policy failure
is an environment result, not a reason to bypass the embedded route.

After focused package tests, run:

```sh
mise run test
mise run check
```

## Documentation

Document the creator-side configuration with the command that emits the token:

```sh
DERPHOLE_DERP_SERVER=https://derp.example.com derphole listen
```

The documentation must explain:

- the setting applies when a token or durable credential is created
- the custom route is embedded and the consumer needs no matching setting
- consumer environment does not override token routing
- public behavior and token formats stay unchanged when the setting is unset
- custom mode does not contact public Tailscale DERP or STUN infrastructure
- custom STUN defaults to the same hostname on UDP 3478
- STUN failure leaves the session on relay
- HTTPS and certificate validation are mandatory
- HTTP proxy variables still govern the custom DERP TCP connection
- accepting a custom token authorizes a connection to its embedded endpoint

## Acceptance Criteria

- Unset `DERPHOLE_DERP_SERVER` produces current public token and credential
  bytes and follows the existing public-map path.
- Setting `DERPHOLE_DERP_SERVER=https://derp.shayne.in` produces a custom token
  containing the canonical host, DERP port 443, and STUN port 3478.
- A peer with no custom environment consumes that token and joins the same
  custom relay.
- Custom mode makes no connection to public Tailscale DERP or STUN nodes.
- derphole completes a real relay-only transfer through the custom server.
- derptun and derpssh share the same custom route through their common token
  and transport path.
- The custom DERP connection honors standard proxy environment variables.
- Failed custom DERP setup never falls back to public DERP.
- Failed custom STUN or direct probing leaves a healthy relay session running.
- Old binaries continue to consume newly generated public tokens, while custom
  token versions fail clearly on old binaries.
- Focused tests and `mise run check` pass.

## Rollout

Ship custom token decoding, custom token creation, shared route handling,
documentation, and tests together. There is no migration for public users.
They keep emitting the formats they emit today.

Custom deployments require new binaries on both sides because the relay
locator is a new wire field. That cost belongs to the uncommon path that asked
for the feature. The common path stays small, compatible, and dull. That is the
point.
