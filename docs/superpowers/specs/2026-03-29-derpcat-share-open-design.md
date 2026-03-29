# derpcat Share/Open Design

## Summary

`derpcat` should stop treating TCP as a one-shot attachment bolted onto the
stdio session model. The current TCP flags on `listen` and `send` only bridge a
single local TCP connection into a single derpcat byte stream, which is not a
useful abstraction for sharing a real local service such as a dev server or web
UI.

This design replaces one-shot TCP bridging with a persistent service-sharing
model:

- `listen` / `send` remain the one-shot stdio commands
- `share <target-addr>` becomes the long-lived command for exposing a local TCP
  service
- `open <token> [bind-addr]` becomes the long-lived command for consuming that
  shared service on another machine

One token may be claimed by exactly one `open` peer. Once claimed, that peer
session may carry many concurrent local TCP connections until interrupted or the
transport fails.

## Goals

- Make TCP sharing useful for real services like `localhost:3000`
- Keep the successful DERP bootstrap and direct-path promotion work intact
- Preserve the simple one-shot `listen` / `send` stdio story
- Keep the CLI greenfield and purpose-based
- Support long-lived sessions that run for hours or days
- Support multiple concurrent forwarded TCP connections over one claimed session

## Non-Goals

- Multi-claimer sharing from a single token
- UDP forwarding in this iteration
- Generic SOCKS or full VPN semantics
- Backward compatibility with the current one-shot TCP flags

## CLI Model

### Commands

- `derpcat listen`
- `derpcat send <token>`
- `derpcat share <target-addr>`
- `derpcat open <token> [bind-addr]`
- `derpcat version`

### Semantics

`listen` and `send` remain one-shot stdio-oriented commands. They no longer
accept `--tcp-listen` or `--tcp-connect`.

`share <target-addr>` exposes a local TCP service until Ctrl-C or fatal
transport failure. Example:

```bash
derpcat share 127.0.0.1:3000
```

`open <token> [bind-addr]` claims the shared service and exposes it locally.
Example:

```bash
derpcat open <token>
derpcat open <token> 127.0.0.1:8080
```

If `bind-addr` is omitted, `open` binds `127.0.0.1:<ephemeral-port>` and prints
the chosen address clearly.

### Shared Flags

The existing global verbosity flags remain:

- `-v`, `--verbose`
- `-q`, `--quiet`
- `-s`, `--silent`

`--force-relay` remains meaningful for `share` and `open`, because the
underlying peer session still performs direct-path promotion with DERP relay
fallback.

`--print-token-only` is still useful for `share`, because the token is often
handed to another process or copied into another terminal.

## Token Model

The token remains a single-use bearer capability:

- one token produces exactly one successful claimant
- after claim, the token is burned
- additional `open` attempts are rejected deterministically

The token should carry the same bootstrap/authentication information as the
current public DERP session token, plus service-sharing metadata for UX:

- shared target address
- default local bind host suggestion
- default local bind port suggestion or zero when ephemeral is preferred
- capability bits indicating service-sharing mode

The token does not become a control plane. It remains a self-contained session
capability for exactly one long-lived peer session.

## Transport Architecture

### Reused Pieces

The existing DERP bootstrap, rendezvous, direct probing, relay fallback, and
userspace WireGuard session machinery should remain the transport underlay.

The successful path today is:

1. `share` issues a token and waits for one claimant
2. `open` claims the token
3. both sides establish the long-lived peer session
4. traffic prefers direct UDP when available and falls back to DERP relay

That underlay is still correct. What changes is the application layer above it.

### New Data Model

The current model assumes one overlay TCP connection becomes one in-process byte
stream. That must be replaced for `share` / `open`.

Recommended architecture:

- keep one long-lived peer session per token claim
- after the peer session is ready, `open` starts a local TCP listener
- each accepted local TCP connection is forwarded independently over the claimed
  session
- `share` receives each forwarded connection and dials the target service for
  that connection
- forwarding continues for any number of sequential or concurrent connections
  until the session ends

This should be implemented by promoting the overlay from “single byte stream”
to “forwarded listener carrying many TCP connections,” rather than by treating
each forwarded connection as a brand-new derpcat session.

## Lifecycle

### `share`

- start
- issue token
- print token
- wait for one claimant
- once claimed, keep the peer session alive until Ctrl-C or fatal failure

### `open`

- decode token
- claim token
- bind local listener
- print chosen local bind address
- accept and forward local TCP connections until Ctrl-C or fatal failure

### Per-Connection Behavior

- one failed backend dial only kills that forwarded connection
- one local client disconnect only kills that forwarded connection
- other active forwarded connections continue running
- if the peer session dies, all active forwarded connections are torn down

## Status And Output

Default output stays sparse:

- `share`: `waiting-for-claim`, `claimed`, `connected-direct` or
  `connected-relay`
- `open`: local bind announcement plus connection state

Verbose mode may add:

- current path changes
- connection open/close events
- active connection counts
- backend dial failures

Example:

```text
$ derpcat share 127.0.0.1:3000
dcat1...
waiting-for-claim
claimed
connected-direct
```

```text
$ derpcat open <token>
listening on 127.0.0.1:48231
connected-direct
```

## Code Changes

### Remove

- one-shot TCP flags from `listen`
- one-shot TCP flags from `send`
- tests that encode the one-shot TCP behavior

### Add

- `share` command
- `open` command
- a long-lived forwarding subsystem distinct from the current
  single-source/single-sink attachment helpers
- session support for many forwarded TCP connections over one claimed session

The existing `openSendSource` / `openListenSink` abstraction is intentionally
too narrow for this feature and should not be stretched to represent persistent
multi-connection forwarding.

## Testing

### Remove Or Rewrite

- one-shot TCP tests for `listen` / `send`

### Add

- `share` help and parsing tests
- `open` help and parsing tests
- default ephemeral localhost bind for `open`
- explicit bind override for `open`
- one token, one claimant
- many sequential forwarded TCP connections over one session
- many concurrent forwarded TCP connections over one session
- backend service failure affecting only one forwarded connection
- Ctrl-C / context cancellation tearing down all active forwarded connections
- relay-only forwarding
- direct-path forwarding

## Migration

This is a greenfield CLI cleanup. Backward compatibility for the removed one-shot
TCP flags is not required.

The repo should move to a cleaner split:

- stdio transfer commands
- service-sharing commands

That is simpler for users and better aligned with the actual product behavior.
