# DERP Proxy IP Fallback

**Date:** 2026-07-16

## Summary

Keep the existing hostname-based HTTP `CONNECT` attempt, but recover from
proxies whose own DNS path silently fails for an otherwise reachable DERP
hostname. When the proxy closes or times out before returning an HTTP
response, `pkg/derpbind` retries through the same proxy with up to two known or
locally resolved IP addresses. The original DERP URL hostname remains
unchanged and continues to control TLS SNI, certificate verification, and the
HTTP DERP upgrade.

This extends the existing proxy-aware dialer. It does not add a new proxy
setting, change tokens, bypass the selected proxy, or fall back to another
DERP server.

## Motivation

Some constrained environments provide a local HTTP proxy whose TCP routing
works but whose resolver does not consistently resolve external hostnames. In
the observed failure, hostname-based requests such as
`CONNECT derp.shayne.dev:443` either returned no bytes or closed. The same
proxy successfully tunneled `CONNECT 5.161.28.73:443`; TLS then succeeded with
`derp.shayne.dev` as SNI and the DERP endpoint returned its expected HTTP
upgrade response.

The current client cannot express that split. It always derives the CONNECT
authority from the DERP URL hostname. It also collapses every non-timeout
`http.ReadResponse` failure into `invalid HTTP response`, hiding whether the
proxy returned EOF, a truncated response, or malformed bytes.

## Goals

- Preserve the standard hostname CONNECT attempt as the fast and normal path.
- Recover when a selected proxy cannot resolve the DERP hostname but accepts
  a literal IP CONNECT authority.
- Keep the original DERP hostname for end-to-end TLS SNI and certificate
  verification.
- Preserve the underlying CONNECT response read error for diagnosis and
  programmatic classification.
- Apply the behavior once in `pkg/derpbind` for derphole, derptun, and derpssh.
- Keep the selected proxy authoritative and preserve fail-closed DERP routing.
- Add no work or latency to a successful hostname CONNECT.

## Non-goals

- Changing `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` selection semantics.
- Adding proxy flags, configuration files, or retry-count settings.
- Retrying explicit proxy rejection statuses such as 403, 407, or 502.
- Retrying proxy TCP, proxy TLS, or CONNECT write failures.
- Falling back to direct TCP, the public DERP map, or another custom server.
- Changing DERP route or token wire formats to embed IP addresses.
- Working around proxies that reject literal IP CONNECT authorities.
- Adding generic retries for transient network failures.

## Selected Approach

`newDERPNodeDialer` continues to select the proxy from the original DERP URL.
When a proxy applies, a small proxy-target coordinator performs these steps:

1. Build the canonical hostname authority from the DERP URL.
2. Call the existing CONNECT dialer with that authority.
3. Return immediately on success.
4. Return immediately on caller cancellation, an explicit HTTP response,
   malformed HTTP, proxy dial/TLS/write failure, or any failure after CONNECT
   succeeds.
5. Only when response reading ends in EOF, unexpected EOF, or an attempt-local
   timeout while the caller context remains active, collect literal IP
   candidates.
6. Retry each unique candidate once, sequentially, through the same proxy.
7. Return the first successful tunnel, or a joined error that preserves every
   attempted cause.

The existing direct DERP dialer remains unchanged. An applicable proxy never
races or falls back to direct TCP.

## IP Candidate Selection

Prefer IP addresses already supplied by the selected `tailcfg.DERPNode`:

1. valid `IPv4`
2. valid `IPv6`

Public Tailscale DERP map nodes normally provide these fields, so public-node
fallback does not require local DNS. Custom routes intentionally contain only
a hostname and ports, so their synthetic nodes have empty IP fields. Resolve
the original DERP hostname locally only for address families whose node field
is empty. A non-empty invalid value such as `none` continues to disable that
family, matching the existing direct dialer's semantics.

Candidate collection must:

- accept only valid unzoned unicast IP addresses;
- respect node-level IPv4 or IPv6 disable markers;
- preserve resolver order when local DNS is used;
- remove duplicates and the original authority when it is already an IP;
- retain the DERP URL port;
- return at most two candidates.

The resolver is an injectable package dependency for deterministic tests. A
local DNS failure is reported alongside the original hostname CONNECT error.
It does not cause a direct connection or public-map lookup.

## Time and Retry Bounds

The caller's context remains the overall authority. Each CONNECT attempt keeps
the existing five-second maximum and receives only the time left on the caller
context. The Tailscale DERP client's existing ten-second connection deadline
therefore remains the outer bound in ordinary use.

A hostname attempt that times out because the caller context itself expired is
not retryable. A hostname attempt whose private five-second setup deadline
expires while the caller remains active is retryable. Candidate resolution and
IP attempts stop immediately when the caller context is canceled.

At most two unique IP authorities are attempted. Repeating the hostname or the
same IP is forbidden.

## TLS and DERP Identity

The CONNECT authority controls only where the proxy opens its TCP tunnel.
`derphttp.Client` continues to create TLS using the hostname from its original
URL. Consequently an IP fallback still sends the DERP hostname as SNI,
verifies the certificate against that hostname, and sends the original URL in
the DERP HTTP upgrade.

No TLS verification setting changes. A certificate valid only for the IP must
not be accepted unless the original DERP URL itself used that IP.

## Errors and Observability

The CONNECT response read path wraps the original `http.ReadResponse` error
with `%w`. It must retain safe stage and proxy-address context while continuing
to omit proxy credentials and untrusted response bytes.

The fallback classifier operates on wrapped causes rather than error strings.
It recognizes EOF, unexpected EOF, and timeout errors only. A parsable HTTP
status is never retryable, even if the status is 502 or 504. A malformed status
line remains an explicit diagnostic and is not treated as evidence of proxy
DNS failure.

On success, `ProxyInfo.TargetAddr` records the CONNECT authority that actually
succeeded. Normal hostname tunnels keep the hostname; IP fallback tunnels
report the IP authority. Proxy userinfo remains redacted.

If all attempts fail, the returned error identifies the hostname attempt and
each IP authority without exposing credentials or response bodies.

## Security and Policy

The selected proxy remains in control of every attempt and may reject literal
IP authorities. The client does not bypass `NO_PROXY` decisions: proxy
selection is still evaluated exactly once against the original hostname URL.
It also does not open a direct socket to a resolved IP.

Literal IP fallback can alter how a proxy applies hostname-based policy. It is
therefore restricted to silent pre-response failures and does not override an
explicit proxy response. If the proxy accepts an IP CONNECT, that acceptance
is authoritative for the tunnel; end-to-end TLS still authenticates the DERP
hostname.

## Testing Strategy

### Response diagnostics

- A proxy that closes without a response preserves the resulting
  `io.ErrUnexpectedEOF` in the error.
- A truncated response preserves `io.ErrUnexpectedEOF`.
- A malformed status line retains the parsing cause and is not retryable.
- Attempt-local timeout and caller cancellation remain distinguishable.

### Candidate selection

- Node-provided IPv4 and IPv6 addresses avoid local DNS.
- Custom nodes with empty IP fields use the injected local resolver.
- Invalid, zoned, duplicate, and excess addresses are excluded.
- Existing literal-IP URLs do not produce duplicate fallback targets.

### CONNECT fallback

- Hostname CONNECT silently closes, IP CONNECT succeeds, and the returned
  `ProxyInfo` records the IP authority.
- Hostname CONNECT times out, then an IP CONNECT succeeds within the caller's
  remaining budget.
- Explicit 403/407/502 responses do not resolve or retry.
- Proxy dial, proxy TLS, CONNECT write, malformed HTTP, and caller cancellation
  do not retry.
- Two failed IP candidates are each attempted once and errors remain joined.
- A successful hostname CONNECT performs no resolution and exactly one proxy
  connection.

### DERP integration

Use a real local DERP server and a CONNECT proxy that silently closes the
hostname authority but forwards the literal IP authority. Connect two clients,
exchange a real DERP packet, and assert that both clients used the IP fallback
without any direct DERP dial.

Focused package tests run first, followed by race-enabled `pkg/derpbind` tests,
the full repository test suite, and the repository check gate.

## Documentation

Update the constrained-egress documentation to explain that hostname CONNECT
is tried first and that silent proxy DNS failures may fall back to literal IP
CONNECT through the same proxy. Note that TLS continues to authenticate the
DERP hostname and that explicit proxy rejections remain final.

## Acceptance Criteria

- The observed silent hostname-proxy failure succeeds through an IP CONNECT
  when local DNS or DERP map IPs provide a reachable address.
- Successful hostname proxy behavior is byte-for-byte unchanged and performs
  no resolver work.
- TLS still authenticates the original DERP hostname after IP fallback.
- Explicit proxy policy responses are never bypassed by IP fallback.
- The client never dials the DERP host directly after selecting a proxy.
- Custom route and token formats remain unchanged.
- Errors preserve their underlying read causes without leaking credentials or
  response bodies.
- Focused, race, full-suite, and repository checks pass.

## Rollout

This is backward-compatible and requires no configuration or token migration.
The normal case pays no new cost. Only a selected proxy that silently fails
before returning an HTTP response triggers IP collection and another CONNECT
attempt.
