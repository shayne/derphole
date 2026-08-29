# Derptun Scoped Multi-Service Credential and Stream Protocol

**Date:** 2026-08-29

**Status:** Approved companion design

**Parent:** [Tailcat-derived transport modernization](2026-08-29-tailcat-derived-transport-modernization-design.md)

## Summary

Derptun will let one durable server credential expose several explicitly named
TCP services. Each client credential carries an immutable, signed subset of
those names. A connection identifies its service with a bounded prelude before
application bytes flow, and the server verifies both the signed client scope
and its own target table before dialing.

This is a new protocol, not an interpretation of the unused `Forwards` field
in current credentials. Existing `dts1_`, `dts2_`, `DT1`, and `DT2`
credentials and their single-target behavior remain unchanged.

The exact new versions are:

| Credential | Public DERP | Custom DERP |
| --- | --- | --- |
| Server | version 3, `dts3_` | version 4, `dts4_` |
| Client | version 3, `DT3` | version 4, `DT4` |

The product remains TCP-only and destination-scoped. It does not expose an
exit node, arbitrary SOCKS proxy, subnet route, wildcard target, or UDP
association.

## User Outcome

An operator can issue one durable server credential for a small application
stack, delegate only the required services to each client, and run either a
local listener or a child command without manually managing several tunnels:

~~~text
derptun token server \
  --forward web=127.0.0.1:3000 \
  --forward metrics=127.0.0.1:9090 > server.dts

derptun token client --token-file server.dts \
  --forward web --forward metrics > client.dt

derptun serve --token-file server.dts
derptun open --token-file client.dt --forward web --listen 127.0.0.1:8080
derptun run --token-file client.dt -- curl http://web.derptun.invalid/
~~~

The client never receives target addresses or names it was not granted.

## Compatibility Boundary

- Versions 1 and 2 retain the current single-target CLI and wire behavior.
- Versions 3 and 4 always mean named, scoped TCP forwards.
- A current credential is never upgraded in place and its existing prefix is
  never reused.
- New binaries accept versions 1 through 4.
- Already released old binaries reject `dts3_`, `dts4_`, `DT3`, and `DT4`
  through their existing unrecognized-token path and never interpret them as
  legacy credentials. New binaries recognize the reserved prefix family and
  report a sanitized `credential version requires a newer derptun` error when
  the exact version is newer than they support.
- `derptun open --forward` and `derptun run` reject versions 1 and 2 with
  `named forwards require a DT3 or DT4 client credential`.
- `derptun open` with a version 3 or 4 credential requires `--forward` unless
  the credential contains exactly one name, in which case that name is used
  and printed in verbose diagnostics.
- `derptun connect` requires `--forward` for versions 3 and 4. Stdio behavior
  after the open acknowledgment is unchanged.
- The server rejects a mismatched credential version, route form, protocol
  version, capability bit, or scope digest before opening a data stream.

## Credential Model

### Named server forwards

New code introduces a separate type rather than assigning protocol meaning to
the legacy `ForwardSpec`:

~~~go
type NamedForward struct {
    Name               string `json:"name"`
    TargetAddr         string `json:"target_addr"`
    MaxConcurrent      int    `json:"max_concurrent"`
    IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
}
~~~

Server credentials versions 3 and 4 contain `named_forwards` and do not use
the legacy `forwards` field. Forward records are sorted by name before token
encoding.

Names must:

- be 1 through 32 ASCII bytes;
- begin with `a` through `z`;
- contain only lowercase letters, digits, and single hyphens;
- end with a lowercase letter or digit;
- be unique after exact byte comparison.

At most 32 forwards may exist in a server credential. Targets must parse with
`net.SplitHostPort`, use a non-zero TCP port, and be canonicalized before
encoding. Loopback IPv4, loopback IPv6, and `localhost` are accepted by
default. Any other host requires the explicit token-creation flag
`--allow-non-loopback`; wildcard and unspecified addresses are always
rejected.

`MaxConcurrent` defaults to 32 and is bounded to 1 through 256 per forward.
`IdleTimeoutSeconds` defaults to 900 and is bounded to 30 through 86400. These
limits are part of the server credential and therefore travel with the server
configuration without being disclosed to clients.

### Client scope

Versions 3 and 4 add this field to `ClientCredential`:

~~~go
ForwardNames []string `json:"forward_names"`
~~~

The set is required, sorted, duplicate-free, and limited to 16 names. Token
creation checks that every requested name exists in the decoded server
credential. The proof MAC covers the complete sorted set, so removing,
renaming, reordering into a non-canonical form, or adding a name invalidates
the credential.

The server reconstructs `ForwardNames` from the authenticated claim and
verifies the proof against its signing secret. It never trusts a scope merely
because it was present in rendezvous JSON.

### Server-token encoding

Server credentials remain JSON encoded with base64url without padding after
their exact prefix. Versions 3 and 4 use the existing key and identity fields,
replace `forwards` with `named_forwards`, and otherwise preserve the current
server-token structure. Version 3 requires no DERP route. Version 4 requires a
valid custom route. Unknown JSON fields are rejected for versions 3 and 4 so a
misspelled limit cannot silently fall back to a default.

### Client-token encoding

Client credentials retain the current base-41 alphabet and the first 186 raw
bytes. The first byte is 3 for `DT3` and 4 for `DT4`; the kind byte remains TCP
value 1. After byte 185, append this canonical scope block:

~~~text
name_count       uint8, 1..16
repeated name_count times in sorted order:
  name_length    uint8, 1..32
  name           name_length ASCII bytes
~~~

`DT4` appends the existing custom DERP route wire encoding after the complete
scope block. `DT3` permits no trailing bytes. Decoders enforce exact
consumption, canonical name ordering, all name rules, and an overall decoded
raw-token maximum of 1,024 bytes.

The client proof MAC is HMAC-SHA256 with the server signing secret. Versions 3
and 4 use domain strings `derptun-client-proof-v3` and
`derptun-client-proof-v4`. The MAC input is, in order:

1. the domain string;
2. SessionID, ClientID, and TokenID raw bytes;
3. one-byte ClientName length and ClientName ASCII bytes;
4. DERP public key, QUIC public key, and BearerSecret raw bytes;
5. ExpiresUnix as an unsigned 64-bit big-endian value;
6. the complete canonical scope block;
7. for version 4 only, the complete custom route wire bytes.

This encoding is intentionally independent of JSON field order and locale.
Verification uses `hmac.Equal`.

## Rendezvous Negotiation

Add `CapabilityDerptunNamedTCP` as a distinct session capability. Versions 3
and 4 produce that capability; versions 1 and 2 continue to produce
`CapabilityDerptunTCP`.

The optional Derptun section of `rendezvous.ClientProof` becomes:

~~~go
ProtocolVersion uint8    `json:"protocol_version,omitempty"`
ForwardNames    []string `json:"forward_names,omitempty"`
ScopeDigest     [32]byte `json:"scope_digest,omitempty"`
~~~

For versions 3 and 4, `ProtocolVersion` is 1. `ScopeDigest` is SHA-256 of the
canonical scope block. The existing credential proof covers the same scope
block. The claim's authenticated envelope covers the full rendezvous JSON.

`AcceptInfo` echoes `ProtocolVersion` and `ScopeDigest`. The client requires
both to match before dialing any application stream. A mismatch returns the
existing version or capability rejection family and never falls through to
single-target service.

The server advertises no forward table. The echoed digest only proves both
sides agreed on the signed client subset.

## Open-Forward Wire Protocol

Every application connection in versions 3 and 4 begins with an open request
inside the authenticated QUIC or mux stream. It is above the carrier, so the
same bytes work for native striped QUIC, quic-mux, and any future negotiated
carrier.

The request is:

~~~text
magic        4 bytes, "DMSO"
version      uint8, 1
flags        uint8, 0
name_length  uint8, 1..32
reserved     uint8, 0
name         name_length ASCII bytes
~~~

The response is:

~~~text
magic          4 bytes, "DMSR"
version        uint8, 1
status         uint8, 0=accepted, 1=rejected
code           uint8
message_length uint8, 0..96
message        message_length UTF-8 bytes
~~~

Success uses code 0 and an empty message. Rejection codes are:

| Code | Meaning | Public message |
| --- | --- | --- |
| 1 | name absent from signed scope or server table | `forward unavailable` |
| 2 | per-forward or per-client concurrency limit | `forward busy` |
| 3 | backend dial failed or timed out | `forward unavailable` |
| 4 | malformed or unsupported request | `invalid forward request` |
| 5 | client token was revoked after rendezvous | `client credential revoked` |

The server reads the request under a 10-second deadline and a 40-byte hard
bound. It checks canonical syntax, signed client scope, server configuration,
revocation state, and concurrency limits before dialing. Backend dial timeout
is five seconds. It sends success only after the backend connection exists.
No application byte may precede a successful response.

A rejected stream closes after the response without closing the carrier or
unrelated streams. Truncation, unknown flags, invalid UTF-8 response text, or a
wrong magic/version closes that stream and records only a redacted diagnostic.

Native striped mode assembles all lanes into one logical connection before
reading one open request. Reconnect replay in `derptun.Mux` replays the same
name and never changes scope. Stream counters are reserved before backend dial
and released exactly once on every rejection, cancellation, and close path.

## Runtime Authorization and Limits

Authorization is the intersection of three sets:

~~~text
signed client ForwardNames
        intersect
server credential NamedForward names
        intersect
current non-revoked TokenID
~~~

The runtime also applies a hard 64-stream total limit for the active client.
The lower of that limit and the forward's `MaxConcurrent` applies. Idle time is
measured as absence of bytes in either direction; the configured forward idle
timeout closes both sides. Active byte transfer is never terminated merely
because its wall-clock duration exceeds the idle timeout.

Target addresses and full forward tables are excluded from normal and verbose
client output. Server network-debug may log a selected forward name and a
redacted backend failure class, but not bearer credentials or environment
contents.

## Revocation Interaction

Versions 3 and 4 continue to include a random TokenID. Servers may accept:

~~~text
--revocation-file PATH
~~~

The file is operator-trusted local state with this bounded format:

~~~json
{"version":1,"revoked_token_ids":["00112233445566778899aabbccddeeff"]}
~~~

The file is limited to 1 MiB, requires exact 32-character lowercase hex IDs,
rejects duplicates and unknown fields, and is read without following a final
symlink. On Unix, group- or world-readable files are rejected. The server
loads it before rendezvous and checks for an atomic replacement every five
seconds. A malformed replacement leaves the last valid snapshot active and
emits one rate-limited warning.

Newly revoked credentials are rejected at claim and open-forward time. If the
active TokenID becomes revoked, the server cancels that client's tunnel and
all streams. Removing an ID permits future claims but does not resurrect a
closed connection. Versions 1 and 2 do not gain revocation semantics through
this file.

The initial CLI may manage this file with `derptun token revoke --token-file
CLIENT --revocation-file PATH`; it writes through a same-directory temporary
file, fsync, and atomic rename with mode 0600. It prints only the TokenID, never
the client credential.

## Restricted Child-Process Proxy

`derptun run` binds an ephemeral loopback SOCKS5 listener and accepts CONNECT
only for `NAME.derptun.invalid`. `NAME` must be present in the signed client
scope. The destination port supplied by the child is ignored because the
server credential fixes the actual port.

The proxy rejects raw IPs, localhost, arbitrary DNS names, empty names,
non-canonical names, BIND, UDP ASSOCIATE, and all authentication methods other
than no-auth on the private loopback listener. It sets `ALL_PROXY` and
`all_proxy` only in the child environment, preserves stdin/stdout/stderr and
the child exit status, and closes the proxy and tunnel on child exit or
cancellation.

No proxy listener address or token is inherited through unrelated environment
variables. The listener is closed before temporary state is removed.

## Failure Semantics

- Invalid server configuration fails before DERP connection or listener
  creation.
- Invalid client scope fails token creation without producing a partial token.
- Unsupported credential prefixes fail before secret decoding is attempted.
- Rendezvous mismatch fails before QUIC or direct-path setup.
- Open rejection affects one stream and is safe to retry unless the code is
  malformed request or revoked.
- Backend failure does not disclose whether the name exists outside the
  client's scope.
- Revocation-file startup failure is fatal when the flag is present; reload
  failure retains the last good state.
- Cancellation closes listeners, child processes, streams, backend sockets,
  and owned goroutines within the existing Derptun shutdown bound.

## Security Properties

- A client cannot widen or rename its signed scope.
- A copied open request is useful only inside an already authenticated client
  session with the same scope.
- The server remains the sole owner of target addresses.
- A service name never becomes a network destination without an explicit
  server credential entry.
- Non-loopback targets require an operator decision at token creation.
- Resource allocation is bounded before backend dial and application traffic.
- Revocation state is local operator policy, not attacker-controlled relay
  input.
- Relays see encrypted transport traffic and no target table.

## Golden Fixtures and Tests

Implementation must check literal golden strings into
`pkg/derptun/testdata/`. Fixtures use fixed keys, timestamps, IDs, a public
two-forward server, a custom-route two-forward server, and a client scoped to
one forward. Required fixtures are:

- `server-v3.golden` with `dts3_`;
- `server-v4.golden` with `dts4_`;
- `client-v3.golden` with `DT3`;
- `client-v4.golden` with `DT4`;
- canonical scope block hex;
- proof-MAC input hex and expected MAC;
- open request and every response-code byte fixture.

Tests must cover:

- every name, target, count, size, route, and timeout bound;
- deterministic sorting and byte-for-byte token stability;
- altered scope, route, expiry, TokenID, proof, and prefix rejection;
- unknown fields in new server JSON;
- old/new and public/custom mixed-version failures;
- exact rendezvous scope-digest echo;
- unauthorized, busy, backend-failed, malformed, and revoked opens;
- no backend dial before authorization;
- concurrent limit release on every exit path;
- idle timeout with active-transfer exemption;
- mux carrier replacement preserving the requested name;
- revocation startup, atomic reload, invalid reload, and active cancellation;
- SOCKS destination and command-lifecycle restrictions;
- versions 1 and 2 golden and behavior tests remaining unchanged.

Fuzz targets cover server JSON decoding, compact client token decoding, scope
block decoding, open request decoding, response decoding, and revocation-file
parsing. Every fuzz target has an explicit size limit before allocation.

## Rollout and Rollback

Ship decoding and inspection support before token creation is advertised.
Then ship token generation, server handling, `open --forward`, and finally
`run`. Current defaults remain versions 1 and 2 unless `--forward` is supplied
at server-token creation.

Rollback disables creation and CLI routing for versions 3 and 4 but retains
their decoders long enough to produce actionable errors. It never changes the
meaning of old credentials. No database or remote migration is required.

## Acceptance Criteria

- One server exposes at least two named loopback TCP services concurrently.
- Two clients with disjoint scopes cannot open each other's services.
- Tampering with a scope invalidates the client credential.
- A backend failure or unauthorized name reveals no ungranted target details.
- Revoking an active TokenID closes its tunnel and blocks reconnection.
- `derptun run` reaches only scoped `.derptun.invalid` names and preserves the
  child exit status.
- Versions 1 and 2 pass their existing golden and end-to-end tests unchanged.
- Focused race tests, local smoke, remote forward/reverse smoke, and the full
  repository gate pass before publication.
