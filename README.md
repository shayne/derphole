# derpcat

`derpcat` is a standalone CLI for moving bytes between two hosts and sharing local TCP services with a single copy-paste token.

It uses the public Tailscale DERP relay network for rendezvous and relay fallback, but it is **not** affiliated with Tailscale, does **not** require a Tailscale account or tailnet, and does **not** use `tailscaled` for transport.

It does **not** require:

- a Tailscale account
- a tailnet
- `tailscaled`
- any separate control plane you have to run yourself

Everything needed to authenticate and connect is encoded into the session token printed by `listen` or `share`.

`derpcat` supports two primary modes:

- one-shot byte-stream transfer with `listen` and `send`
- long-lived local service sharing with `share` and `open`

## Quick Start

Run the published package directly:

```bash
npx -y derpcat@latest listen
```

Send data from another machine:

```bash
printf 'hello\n' | npx -y derpcat@latest send <token>
```

Share a local web app or API until Ctrl-C:

```bash
npx -y derpcat@latest share 127.0.0.1:3000
```

Expose that shared service locally on another machine:

```bash
npx -y derpcat@latest open <token>
```

Bind `open` to a specific local port:

```bash
npx -y derpcat@latest open <token> 127.0.0.1:8080
```

Use the development channel for the latest commit published from `main`:

```bash
npx -y derpcat@dev version
```

Use `--verbose` to see state transitions such as `connected-relay` and `connected-direct`:

```bash
npx -y derpcat@latest --verbose listen
```

## How It Works

At a high level:

1. `listen` or `share` creates an ephemeral session and prints an opaque bearer token.
2. That token contains the session ID, expiry, DERP bootstrap hints, the listener's public peer identity, a bearer secret, and the allowed session capability.
3. `send` or `open` uses the token to contact the listener through DERP and claim the session.
4. The listener validates the claim, checks the requested capability, and returns its current direct-path candidates.
5. Both sides start on the first working path immediately, including DERP relay if direct connectivity is not ready yet.
6. In parallel, they continue NAT traversal and direct-path probing. If a direct path succeeds, the live session upgrades in place without restarting the transfer.

### Under The Hood

DERP is used for **rendezvous** and **relay fallback**:

- rendezvous: exchange the initial claim, decision, and direct-path coordination messages without a separate account-backed control plane
- relay fallback: keep the session working even when NAT traversal fails or a direct path has not been found yet

The data plane is selected per session:

- `share/open` uses multiplexed QUIC streams over `derpcat`'s relay/direct UDP transport, so one claimed session can carry many independent TCP connections to the shared service.
- `listen/send` uses a one-shot byte stream. If a route-local native TCP path is available, `derpcat` can use it as a fast path; otherwise it falls back to an authenticated QUIC stream over the relay/direct UDP transport.

Candidate discovery is split into two phases:

- fast local candidates first: immediately advertise local socket/interface candidates and any cached port mapping
- background traversal discovery: run STUN and UPnP / NAT-PMP / PCP refresh, then send updated candidates and `call-me-maybe` probes if a new direct endpoint appears

That keeps startup latency low while still allowing relay-to-direct promotion.

## Security Model

The session token is a **bearer capability**. Anyone who has the token can claim that session until it expires, so share it over a channel you trust. Tokens expire after one hour.

DERP relays do **not** get the secret material needed to read or impersonate the session:

- On the public Internet path, traffic is carried over QUIC with the peer certificate pinned to the public identity encoded in the token. If packets are relayed through DERP, DERP only forwards encrypted bytes.
- On local/private native TCP fast paths, the connection is authenticated with a per-session handshake derived from the token's bearer secret and both peers' public identities. Internet-facing direct paths stay on authenticated QUIC.

That gives a simple operational rule: possession of the token authorizes the session, but intermediaries that only see DERP traffic do not have the keys needed to decrypt it.

## Behavior

Sessions can start on DERP relay and later promote to a direct path without restarting. Use `--verbose` to inspect path changes and NAT traversal state.

## Use Cases

- easy cross-host transfer with no account setup
- useful behind NATs where direct connectivity may or may not work
- good for quick sharing of local web apps, APIs, and admin interfaces
- can be used entirely through `npx` without a manual install

## Development

```bash
mise install
mise run install-githooks
mise run check
mise run build
```

## Verification

Local smoke test:

```bash
mise run smoke-local
```

Remote smoke tests against a host you control:

```bash
REMOTE_HOST=my-server.example.com mise run smoke-remote
REMOTE_HOST=my-server.example.com mise run smoke-remote-share
REMOTE_HOST=my-server.example.com mise run promotion-1g
```

## Releases

- npm package: `derpcat`
- production channel: `@latest`
- development channel: `@dev`
- bootstrap runbook: [docs/releases/npm-bootstrap.md](docs/releases/npm-bootstrap.md)
