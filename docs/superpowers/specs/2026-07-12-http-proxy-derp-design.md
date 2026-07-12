# HTTP Proxy Support for DERP Connections

**Date:** 2026-07-12

## Summary

Make DERP connections honor the standard `HTTP_PROXY`, `HTTPS_PROXY`, and
`NO_PROXY` environment variables. This allows derphole, derptun, and derpssh
to establish their shared DERP rendezvous, control, and relay path from
environments where outbound connections must pass through an HTTP proxy.

Proxy configuration enables DERP connectivity; it does not force relay-only
operation. Direct discovery and promotion continue normally and may succeed
when the environment permits them. The existing `--force-relay` option remains
the explicit way to disable direct probing.

## Motivation

Some execution environments block direct Internet egress but provide an HTTP
proxy for outbound HTTPS. In those environments, direct UDP traversal is
unlikely to work, and the current DERP client also fails because
`pkg/derpbind` installs a custom TCP dialer that bypasses HTTP proxy handling.

DERP is already the correct fallback carrier for this case. It uses a
long-lived HTTPS connection for rendezvous, control messages, and encrypted
relay packets. Establishing the DERP connection through an HTTP `CONNECT`
tunnel should therefore make all three products usable without changing their
tokens, commands, session protocol, or application data plane.

## Goals

- Honor standard Go proxy environment semantics for DERP server URLs.
- Support HTTP and HTTPS proxy endpoints.
- Support optional Basic authentication supplied in proxy URL userinfo.
- Preserve the existing direct DERP dial path when no proxy applies.
- Preserve direct-path discovery and promotion independently of proxy use.
- Make the change once in the shared `pkg/derpbind` layer so derphole,
  derptun, and derpssh all benefit.
- Provide errors and telemetry that diagnose proxy failures without exposing
  credentials.
- Prove with an integration test that real DERP packets cross a proxy when the
  target cannot be reached directly.

## Non-goals

- New CLI flags or configuration files for proxy settings.
- Automatically enabling `ForceRelay` when a proxy applies.
- Falling back to direct DERP TCP after an applicable proxy fails.
- SOCKS proxy support.
- NTLM, Kerberos, PAC, or other challenge-based proxy authentication.
- Changing DERP selection, session tokens, the peer protocol, QUIC framing,
  or direct-path negotiation.
- Making DERP work through a proxy that rejects `CONNECT`, long-lived tunnels,
  or the DERP HTTP upgrade.
- Adding a WebSocket DERP carrier in this iteration.

## Existing Architecture

Public sessions fetch the static Tailscale DERP map, choose a node, construct
its DERP URL, and call `derpbind.NewClient`. `pkg/derpbind` constructs a
Tailscale `derphttp.Client` and installs a URL dialer that races the node's
configured IPv4 and IPv6 targets. That custom dialer opens raw TCP connections
and therefore does not use `net/http` proxy handling.

The resulting DERP client is shared by the session implementations used by
derphole, derptun, and derpssh. It carries rendezvous and control messages and
also supplies the relay packet path to `pkg/transport`. Direct UDP discovery
and promotion are configured separately.

The public DERP map does not require a network fetch because
`derpbind.FetchMap` returns Tailscale's static fallback map for the public map
URL. Test-only or custom map URLs already use `http.DefaultClient`, which
honors the standard proxy environment independently of this design.

## Selected Approach

Keep the existing URL-oriented DERP client and add proxy awareness to its
custom dialer. This preserves current node selection, test overrides, and
IPv4/IPv6 behavior while putting the egress decision at the lowest shared
layer.

The alternatives were rejected for this iteration:

- Switching to Tailscale's region-oriented DERP client would reuse upstream
  proxy code but conflict with explicit DERP server URL overrides and local
  test-server construction. It would likely leave the repository with two
  connection paths.
- A WebSocket carrier may help with a different class of restrictive proxy,
  but it adds another transport and server compatibility assumption without
  being necessary for ordinary HTTPS `CONNECT` environments.

## Proxy Selection

The dialer evaluates the original DERP server URL with Go's standard proxy
resolver. This gives the expected behavior for uppercase and lowercase forms
of:

- `HTTPS_PROXY` for HTTPS DERP URLs
- `HTTP_PROXY` for HTTP DERP URLs used by tests or explicit overrides
- `NO_PROXY` exclusions by hostname, domain, IP, CIDR, or port

Proxy selection must use the DERP URL hostname, not the node's direct IPv4 or
IPv6 address. This ensures that `NO_PROXY` matches what the operator configured
and lets the proxy resolve the DERP hostname when local DNS is unavailable.

The proxy resolver should be an injectable package-level dependency for
deterministic tests, with the production default set to the standard resolver.
The production path must not reinterpret or supplement standard proxy
selection rules.

## Connection Flow

For every DERP connection or reconnection:

1. Parse and validate the DERP server URL.
2. Resolve the applicable proxy for that URL.
3. If no proxy applies, call the existing direct node dialer unchanged. It
   continues to select configured node IPs and race eligible address families.
4. If a proxy applies, validate that its scheme is `http` or `https`.
5. Dial the proxy hostname and port. Use port 80 by default for `http` and 443
   by default for `https`.
6. For an HTTPS proxy, establish TLS to the proxy using the proxy hostname as
   the server name.
7. Send an HTTP/1.1 request of the form:

   ```text
   CONNECT derp-host:443 HTTP/1.1
   Host: derp-host:443
   Proxy-Authorization: Basic ...
   ```

   The authorization header is omitted when the proxy URL does not contain a
   username and password.
8. Require `200 OK`. Close the connection and return a sanitized error for any
   other response.
9. Return the tunneled connection to the existing Tailscale DERP client.
10. The DERP client performs its normal end-to-end TLS handshake to the DERP
    hostname and its normal HTTP/DERP upgrade through the tunnel.

The proxy path does not race a direct DERP connection. Once the standard proxy
resolver says a proxy applies, that proxy is authoritative. An operator who
wants a direct exception uses `NO_PROXY`.

## Transport Behavior

Proxy use changes only how the local process reaches its selected DERP server.
It does not alter peer capability negotiation or path policy.

- Rendezvous and authenticated control messages use the proxied DERP
  connection.
- Relay payloads use the same proxied DERP connection.
- Direct UDP candidate gathering and probing continue normally.
- If direct promotion succeeds, payload traffic may leave DERP as it does
  today.
- If direct promotion fails, the session remains on DERP.
- `--force-relay` continues to disable direct probing explicitly and works in
  combination with proxy configuration.

No product-specific wiring is required because all three products reach DERP
through the shared session and `derpbind` layers.

## Security and Privacy

The proxy terminates the local proxy connection but not the TLS connection to
the DERP server. DERP authentication and encrypted relay payloads remain inside
the CONNECT tunnel. The proxy can still observe the DERP destination, timing,
connection duration, and byte volume.

Proxy credentials must never be included in error text, telemetry, or debug
output. Any proxy URL rendered for diagnostics must have userinfo removed.
CONNECT response bodies must be bounded before they are included in an error,
and their content should be treated as untrusted.

Basic credentials in environment variables have the ordinary exposure risks
of process environments. Documentation should mention this without inventing
a separate credential store in this iteration.

A TLS-intercepting corporate proxy may cause the DERP client to use its normal
non-fast-start HTTP upgrade path. The feature does not weaken TLS validation or
add a custom certificate bypass. If the environment's trusted root set and
proxy behavior do not permit the DERP TLS and upgrade exchange, the connection
fails explicitly.

## Error Handling

Errors identify the failed stage and safe endpoints while preserving wrapped
causes for programmatic checks:

- invalid proxy configuration
- unsupported proxy scheme
- proxy DNS or TCP dial
- TLS handshake to an HTTPS proxy
- writing the CONNECT request
- reading or parsing the CONNECT response
- proxy authentication required or rejected (`407`)
- other non-200 CONNECT response
- DERP TLS or HTTP upgrade after the tunnel is established

Context cancellation and deadlines apply to proxy dialing, proxy TLS, and the
CONNECT exchange. Any partially established connection is closed promptly. A
deadline installed for setup is cleared before returning a successful tunnel
so it does not interfere with the long-lived DERP connection.

There is no direct fallback after an applicable proxy error. This avoids both
surprising policy bypass and slow duplicate failures in constrained
environments.

## Observability

`pkg/derpbind.Client` records a redacted `ProxyInfo` value after its first
successful proxy tunnel. The value contains only:

- proxy scheme
- redacted proxy hostname and port
- DERP hostname and port

The client exposes this immutable value through an accessor. The shared
session layer reads it after connection setup and emits one verbose/debug event
per client, formatted as
`derp-proxy=<scheme>://<host:port> target=<host:port>`. This avoids a dependency
from `pkg/derpbind` back to `pkg/telemetry` and avoids default-output noise.
Reconnects on the same client do not repeat the event.

`ProxyInfo` and its formatted event must not contain proxy userinfo,
authorization headers, or CONNECT response bodies. Existing relay/direct path
events remain the source of truth for whether application payloads stayed on
DERP or promoted to a direct path.

## Testing Strategy

### Proxy selection unit tests

Cover:

- no proxy
- `HTTP_PROXY` and `HTTPS_PROXY`
- lowercase variable forms
- `HTTPS_PROXY` precedence over `HTTP_PROXY`
- `NO_PROXY` hostname, domain, IP, CIDR, and port exclusions
- invalid proxy URL
- unsupported proxy scheme

Tests should inject proxy resolution rather than mutate process-global proxy
state in parallel. At least one subprocess test should exercise the production
standard environment resolver end to end.

### CONNECT dialer unit tests

Use local proxy fixtures to verify:

- correct CONNECT authority and `Host` header
- proxy-side hostname resolution
- HTTP proxy connection
- HTTPS proxy connection and TLS server-name validation
- Basic proxy authorization
- omission of authorization without credentials
- `407` and other non-200 handling
- bounded response-body errors
- cancellation during dial, TLS, write, and response wait
- successful setup deadline clearing
- credential redaction in every error path
- no direct dial fallback after a selected proxy fails

### DERP integration test

Start a local DERP server and a local CONNECT proxy. Advertise a DERP hostname
and direct address that cannot be reached by the client. Configure the proxy to
map that hostname to the local DERP listener. Connect two `derpbind.Client`
instances, exchange a real DERP packet, and verify that the proxy observed both
CONNECT tunnels to the expected authority.

This test is the primary acceptance proof: the feature is not complete if only
the CONNECT request helper passes.

### Product regression tests

- Exercise a relay session for derphole through the proxied DERP fixture.
- Exercise a derptun stream round trip through the proxied DERP fixture.
- Exercise derpssh through its shared derptun-backed session path.
- Verify proxy presence does not set `ForceRelay` or suppress direct probing.
- Verify explicit `--force-relay` still works through the proxy.

Run focused tests for `pkg/derpbind`, `pkg/session`, `pkg/derphole`, and
`pkg/derpssh`, followed by:

```sh
mise run test
mise run check
```

## Documentation

Add a constrained-egress section to the DERP/networking documentation with a
minimal example:

```sh
export HTTPS_PROXY=http://proxy.example:3128
export NO_PROXY=localhost,127.0.0.1
derphole send
```

The documentation must explain:

- proxy use is automatic for all three products
- direct promotion remains enabled unless `--force-relay` is supplied
- the proxy must permit CONNECT to the selected DERP host and port
- long-lived tunnels and DERP's HTTP upgrade must be allowed
- supported proxy schemes and Basic URL credentials
- payload encryption and the metadata visible to the proxy
- representative errors for authentication and CONNECT-policy failures

## Acceptance Criteria

- With a valid applicable HTTP or HTTPS proxy, derphole, derptun, and derpssh
  can establish DERP-backed sessions when the DERP server cannot be dialed
  directly.
- With no applicable proxy, current direct DERP dialing behavior is unchanged.
- `NO_PROXY` causes direct DERP dialing for matching destinations.
- Proxy selection does not imply relay-only mode.
- An applicable proxy failure does not fall back to direct DERP TCP.
- Direct promotion remains possible when the network permits it.
- Proxy credentials are absent from errors, events, and logs.
- The integration test exchanges an actual DERP packet through CONNECT.
- The full repository test and check suites pass.

## Rollout

This is backward-compatible and requires no token or configuration migration.
Ship the proxy-aware dialer and documentation together. Constrained-environment
operators opt in by setting standard proxy variables already understood by
their environment.

If real deployments reveal proxies that allow WebSockets but reject the DERP
upgrade inside CONNECT, collect those failures separately before considering a
WebSocket carrier. Do not broaden the initial implementation preemptively.
