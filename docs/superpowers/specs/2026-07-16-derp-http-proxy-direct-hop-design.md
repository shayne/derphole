# Direct Dialing for Selected DERP HTTP Proxies

**Date:** 2026-07-16

## Summary

When `HTTP_PROXY` or `HTTPS_PROXY` selects an HTTP(S) proxy for a DERP URL,
the TCP connection to that proxy is the terminal proxy hop. Dial it directly
instead of passing it through the `ALL_PROXY`-aware Tailscale network dialer.

This prevents a local HTTP proxy such as `127.0.0.1:39969` from being routed
recursively through a SOCKS proxy when `ALL_PROXY` is also present. Users must
not need a loopback entry in `NO_PROXY` to avoid that recursion.

## Observed Failure

With `HTTPS_PROXY=http://127.0.0.1:39969`, `ALL_PROXY` set to a local SOCKS
proxy, and an empty `NO_PROXY`, the DERP client selected the HTTP proxy and
then used `netns.NewDialer` to reach it. That dialer honors `ALL_PROXY`,
producing a nested route:

```text
DERP client -> SOCKS proxy -> selected HTTP proxy -> DERP
```

The connection failed before the HTTP proxy received a CONNECT request. Adding
loopback to `NO_PROXY` avoided the nesting, proving that the selected proxy hop
was being sent through the lower SOCKS layer.

## Selected Design

Introduce a dedicated package-level proxy-hop dial function. Its production
implementation uses a plain `net.Dialer` and therefore does not consult
`ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

`dialDERPThroughProxy` uses this direct dial function only for the connection
to the already-selected HTTP(S) proxy. The existing `derpDialContext` remains
unchanged for direct DERP targets, where Tailscale's `netns.NewDialer` and its
`ALL_PROXY` SOCKS support remain intentional.

The rest of the proxy sequence is unchanged:

1. Select the HTTP(S) proxy from the original DERP URL.
2. Directly dial the selected proxy address.
3. Perform TLS to the proxy itself when its URL uses `https`.
4. Send CONNECT for the DERP authority.
5. Perform DERP TLS through the established tunnel.

## Environment Semantics

- `HTTP_PROXY` and `HTTPS_PROXY` continue to select HTTP proxies.
- `NO_PROXY` continues to decide whether the original DERP URL bypasses the
  HTTP proxy.
- `ALL_PROXY` continues to provide SOCKS behavior when the DERP connection is
  otherwise direct.
- `ALL_PROXY` never chains underneath an explicitly selected HTTP(S) proxy.
- No environment variables are mutated or cached by derphole.

An operator who intentionally wants a SOCKS-to-HTTP proxy chain must provide a
single endpoint that implements that chain. It is not inferred by combining
standard proxy variables.

## Error Handling and Diagnostics

Existing error boundaries and redaction remain intact. Failure to reach the
selected proxy still reports:

```text
dial DERP proxy <scheme>://<sanitized-address>: <cause>
```

The cause will now describe the direct TCP dial rather than an unexpected
`socks connect` layer. Proxy credentials remain excluded.

## Testing

Add a subprocess regression test so `golang.org/x/net/proxy` reads a fresh
environment before its internal `sync.Once` cache is populated. The parent
test provides:

- a working local HTTP CONNECT proxy;
- a local SOCKS endpoint that fails immediately if contacted;
- `HTTPS_PROXY` pointing at the HTTP proxy;
- `ALL_PROXY` pointing at the SOCKS endpoint;
- an empty `NO_PROXY`.

The child calls the real DERP HTTP proxy dial path. Before the fix it contacts
SOCKS and fails. After the fix it reaches the HTTP proxy directly and receives
the CONNECT response. Existing tests continue to verify HTTP proxy TLS,
authentication, cancellation, IP fallback, and fail-closed behavior.

## Acceptance Criteria

- A selected HTTP(S) proxy is dialed directly even when `ALL_PROXY` is set.
- The regression test proves the SOCKS endpoint is not contacted.
- Users do not need loopback in `NO_PROXY` for the proxy hop itself.
- Direct DERP connections retain existing `ALL_PROXY` behavior.
- HTTP proxy selection, authentication, TLS, CONNECT, IP fallback, and
  diagnostics remain unchanged.
- Focused, race-enabled, and full repository checks pass.
