# derpcat

`derpcat` is a standalone CLI for moving bytes between two hosts using the public Tailscale DERP network for bootstrap and relay fallback, with direct UDP promotion when the network allows it.

It does **not** require:

- a Tailscale account
- a tailnet
- `tailscaled`
- any separate control plane you have to run yourself

Everything needed to authenticate and connect is encoded into the session token printed by `listen` or `share`.

`derpcat` supports two primary modes:

- one-shot byte-stream transfer with `listen` and `send`
- long-lived local service sharing with `share` and `open`

## What DERP Means Here

Tailscale DERP is Tailscale's public encrypted relay system. In `derpcat`, DERP is used for two things:

- bootstrap and rendezvous, so two peers can find each other without a separate login-backed control plane
- relay fallback, so the session still works when a direct UDP path is unavailable or not ready yet

If direct UDP becomes available after the session starts, `derpcat` promotes the active session in place without restarting the transfer.

## Quick Start

Run the published package directly:

```bash
npx -y derpcat@latest version
```

Use the development channel for the latest commit published from `main`:

```bash
npx -y derpcat@dev version
```

## Examples

Receive one stream on one machine:

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

## How It Works

At a high level:

1. `listen` or `share` creates an ephemeral session and prints an opaque bearer token.
2. That token contains the bootstrap information the other side needs, including the session ID, expiry, DERP bootstrap hints, the listener's DERP and transport identity material, a bearer secret, and the allowed session capability.
3. `send` or `open` uses the token to reach the listening side over the public DERP network and claim the session.
4. The listener validates the claim, checks the capability, returns its own direct-path candidates, and both sides immediately start on the first working path, including DERP relay if needed.
5. In parallel, both peers continue endpoint discovery and direct probing. If a better direct path appears later, the live session upgrades in place without restarting the transfer.

### Under The Hood

`derpcat` has two data-plane implementations, selected dynamically after DERP rendezvous:

- **Public Internet / NAT path:** `listen/send` and `share/open` run QUIC over `derpcat`'s relay/direct UDP transport. That transport starts on DERP packets, exchanges endpoint candidates, sends direct probes, and promotes to direct UDP when a probe succeeds. The QUIC peer certificate is pinned to the identity encoded in the token, so DERP relays ciphertext but does not terminate the session.
- **Route-local fast path:** if both peers advertise a route-local address (`100.64.0.0/10` or `fd7a:115c:a1e0::/48` from Tailscale, loopback, or RFC1918 private LAN), `listen/send` can switch the bulk byte stream onto native TCP while preserving the same DERP bootstrap and fallback behavior. Tailscale-route TCP is authenticated with a per-session HMAC handshake derived from the token bearer secret and both peers' transport identities; non-Tailscale TCP candidates use TLS with the peer identity pinned from the token.

`share/open` stays on multiplexed QUIC streams so a single claimed session can carry many independent TCP connections to the shared local service. `listen/send` uses one or more native TCP stripes on route-local direct paths, and otherwise falls back to a QUIC stream over the relay/direct UDP transport.

Candidate discovery has two phases:

- **Fast local candidates first:** immediately advertise the bound socket's local interface addresses and any cached UPnP / NAT-PMP / PCP mapping.
- **Background traversal discovery:** run STUN and port-mapping refresh in parallel, then send updated candidates and `call-me-maybe` probes if a new direct endpoint appears.

That split keeps startup latency low while still allowing NAT traversal and relay-to-direct promotion.

## Behavior

Sessions can start on DERP relay and later promote to a direct UDP path without restarting. Use `--verbose` to observe path changes such as `connected-relay` and `connected-direct`.

## Why Use It

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
