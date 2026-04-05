# derpcat

`derpcat` is a standalone CLI for moving bytes between two hosts and sharing local TCP services with a single copy-paste token.

It uses the public Tailscale [DERP](#what-is-derp) relay network for rendezvous and relay fallback, but it is **not** affiliated with Tailscale, does **not** require a Tailscale account or tailnet, and does **not** use `tailscaled` for transport.

`derpcat` is **not** a WireGuard overlay and **not** a VPN. Tailscale is built around WireGuard and is optimized as a general-purpose secure network between machines. `derpcat` is optimized for a different job: one session, one token, one transfer or shared service, with the shortest secure path it can find for that session. See [Transport Model](#transport-model), [Why It Is Fast](#why-it-is-fast), and [Security Model](#security-model).

That difference matters. For one-shot transfers and temporary service sharing, `derpcat` can outperform sending the same traffic through a WireGuard-based overlay because it does not first build a general-purpose encrypted network path and then send your application traffic through it. Instead, it uses DERP for rendezvous and fallback, then moves the live session onto direct QUIC or, when a suitable path is available, authenticated native TCP. The details are in [Transport Model](#transport-model) and [How This Differs From Tailscale / WireGuard](#how-this-differs-from-tailscale--wireguard).

It does **not** require:

- a Tailscale account
- a tailnet
- `tailscaled`
- any separate control plane you have to run yourself

Everything needed to authorize the session is encoded into the token printed by `listen` or `share`. Public sessions still fetch the DERP map at runtime so both sides can find relay/bootstrap nodes. See [Security Model](#security-model) for what the token authorizes and what intermediaries can and cannot see.

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

If you want the transport details after trying the examples, jump to [Transport Model](#transport-model), [Behavior](#behavior), or [Security Model](#security-model).

## Transport Model

At a high level:

1. `listen` or `share` creates an ephemeral session and prints an opaque bearer token.
2. That token contains the session ID, expiry, DERP bootstrap hints, the listener's public peer identity, a bearer secret, and the allowed session capability.
3. `send` or `open` uses the token to contact the listener through DERP and claim the session.
4. The listener validates the claim, checks the requested capability, and returns its current direct-path candidates.
5. Both sides start on the first working path immediately, including DERP relay if direct connectivity is not ready yet.
6. In parallel, they continue NAT traversal and direct-path probing. If a direct path succeeds, the live session upgrades in place without restarting the transfer.

### Data Plane Selection

DERP is used for **rendezvous** and **relay fallback**. If you do not already know the term, see [What Is DERP?](#what-is-derp):

- rendezvous: exchange the initial claim, decision, and direct-path coordination messages without a separate account-backed control plane
- relay fallback: keep the session working even when NAT traversal fails or a direct path has not been found yet

The data plane is selected per session:

- `share/open` uses multiplexed QUIC streams over `derpcat`'s relay/direct UDP transport, so one claimed session can carry many independent TCP connections to the shared service.
- `listen/send` uses a one-shot byte stream. If an allowed native TCP path is available, `derpcat` can use it as a fast path; otherwise it falls back to an authenticated QUIC stream over the relay/direct UDP transport.

Candidate discovery is split into two phases:

- fast local candidates first: immediately advertise local socket/interface candidates and any cached port mapping
- background traversal discovery: run STUN and UPnP / NAT-PMP / PCP refresh, then send updated candidates and `call-me-maybe` probes if a new direct endpoint appears

That keeps startup latency low while still allowing relay-to-direct promotion.

## How This Differs From Tailscale / WireGuard

Tailscale uses WireGuard to build a secure general-purpose network between peers. That is the right abstraction when you want durable machine-to-machine connectivity, stable private addressing, ACLs, subnet routing, exit nodes, and a long-lived encrypted overlay.

`derpcat` does something narrower and faster for its target workload. It creates a session-scoped transport for a single transfer or a single shared service:

- no WireGuard tunnel device
- no overlay network interface
- no persistent mesh control plane
- no need to route arbitrary traffic through a general encrypted network

Instead, `derpcat` uses a bearer token to authorize exactly one session, uses DERP to get both peers talking immediately, and then promotes the session onto the best direct path it can establish for that workload. The supporting details are in [Transport Model](#transport-model) and [Security Model](#security-model).

For `send/listen` and `share/open`, that can beat routing the same traffic through a WireGuard-based overlay because `derpcat` is purpose-built for the active session rather than for a general secure network abstraction. See [Why It Is Fast](#why-it-is-fast) for the concrete transport reasons.

## Why It Is Fast

`derpcat` gets its performance from the transport design:

- DERP is used for rendezvous and relay fallback, not as the preferred steady-state data plane.
- Sessions can start relayed immediately and then promote in place to direct without restarting the transfer.
- Public-Internet direct paths use QUIC over UDP, which gives fast setup, stream multiplexing, and encrypted user-space transport without requiring a kernel VPN interface.
- `listen/send` can use authenticated native TCP fast paths when the selected path allows it, which avoids extra overlay encapsulation on suitable direct routes.
- Native QUIC can use multiple striped connections for higher throughput on difficult paths where a single UDP flow is not enough.
- Candidate discovery is front-loaded with local interface candidates and cached mappings, then refined in the background with STUN and port mapping refresh. That keeps the first byte moving quickly instead of stalling the session until every traversal probe finishes.

In practice, that means `derpcat` is optimized to get bytes moving early, keep them moving through relay if necessary, and then shift the live session onto a faster direct path as soon as direct connectivity is ready.

## Security Model

The session token is a **bearer capability**. Anyone who has the token can claim that session until it expires, so share it over a channel you trust. Tokens expire after one hour.

DERP relays do **not** get the secret material needed to read or impersonate the session:

- On the public Internet path, traffic is carried over QUIC with the peer certificate pinned to the public identity encoded in the token. If packets are relayed through DERP, DERP only forwards encrypted bytes.
- On native TCP fast paths, the connection is authenticated either with a per-session bearer-secret handshake on Tailscale-addressed paths or with pinned TLS on other direct TCP paths. Public direct paths also support authenticated QUIC.

The important security property is that `derpcat` does not trade speed for plaintext shortcuts:

- the token authorizes the session, but does not turn DERP into a trusted decrypting proxy
- QUIC peers are pinned to the expected public identity from the token
- native TCP fast paths are only used where allowed and are authenticated per session
- DERP forwards encrypted traffic but does not have the keys required to decrypt or impersonate the session

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

## What Is DERP?

DERP stands for **Designated Encrypted Relay for Packets**. In plain terms, it is a globally reachable relay network that both peers can talk to even when they cannot yet talk directly to each other.

DERP was built by Tailscale for Tailscale's networking stack, and the public Tailscale-operated DERP network is reachable without running your own relays. The same DERP model is also used by Headscale, the open-source Tailscale control server implementation, which can serve its own DERP map and DERP servers.

In `derpcat`, DERP has two jobs:

- rendezvous: carry the initial claim, decision, and direct-path coordination messages so the two peers can find each other without a separate account-backed control plane
- fallback relay: carry encrypted session traffic when NAT traversal has not succeeded yet or when direct connectivity is unavailable

DERP is not the preferred steady-state path. It is the safety net that gets the session started and keeps it working. If a direct QUIC or native TCP path becomes available, `derpcat` promotes the live session onto that direct path. DERP only forwards bytes; it does not get the session keys needed to decrypt the traffic.
