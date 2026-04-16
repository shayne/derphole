# derphole

This repository ships one standalone CLI, `derphole`, for session-scoped transfers and temporary local TCP service sharing.

It includes raw byte streams with `listen` and `pipe`, wormhole-shaped text/file/directory transfer with `send` and `receive`, service sharing with `share` and `open`, and SSH invite flows with `ssh invite` and `ssh accept`.

`derphole` uses the public Tailscale [DERP](#what-is-derp) relay network for rendezvous and relay fallback, but it is **not** affiliated with Tailscale, does **not** require a Tailscale account or tailnet, and does **not** use `tailscaled` for transport.

`derphole` is **not** a WireGuard overlay and **not** a VPN. Tailscale builds a general-purpose secure network on WireGuard. `derphole` is optimized for a different job: one session, one token, one transfer or shared service, on the shortest secure path it can find for that session. See [Transport Model](#transport-model), [Why It Is Fast](#why-it-is-fast), and [Security Model](#security-model).

For one-shot transfers and temporary service sharing, `derphole` can beat sending the same traffic through a WireGuard-based overlay because it does not first build a general-purpose encrypted network path and then send application traffic through it. It uses DERP for rendezvous and fallback, then moves the live session onto the best direct path it can establish for that workload. Details are in [Transport Model](#transport-model) and [How This Differs From Tailscale / WireGuard](#how-this-differs-from-tailscale--wireguard).

It does **not** require:

- a Tailscale account
- a tailnet
- `tailscaled`
- any separate control plane you have to run yourself

The token printed by `listen` or `share` carries session authorization. Public sessions still fetch the DERP map at runtime so both sides can find relay/bootstrap nodes. See [Security Model](#security-model) for what the token authorizes and what intermediaries can and cannot see.

## Pick the Workflow

- raw byte-stream transfer with `listen` and `pipe`
- text, file, and directory transfer with `send` and `receive`
- long-lived local service sharing with `share` and `open`
- SSH public key exchange with `ssh invite` and `ssh accept`

## Quick Start

`listen` receives bytes and prints a token. `pipe` sends stdin into that token. `share` and `open` do the same thing for a local TCP service instead of a byte stream.

### Transfer a File

On the receiving machine:

```bash
npx -y derphole@latest listen > received.img
```

`listen` prints a token to stderr. Copy that token to the sending machine.

On the sending machine:

```bash
cat ./disk.img | npx -y derphole@latest pipe <token>
```

For a quick text example:

```bash
printf 'hello\n' | npx -y derphole@latest pipe <token>
```

### Send a File with a Receive Code

On the sending machine:

```bash
npx -y derphole@latest send ./photo.jpg
```

`send` prints a command for the receiving machine. Run that command there:

```bash
npx -y derphole@latest receive <code>
```

For known-size file and directory transfers, `derphole` prints wormhole-shaped progress and rate output on stderr. Use `--hide-progress` if you want a quiet transfer UI.

Text uses the same shape:

```bash
npx -y derphole@latest send hello
```

Directories stream as tar on the wire and re-materialize on the receiver:

```bash
npx -y derphole@latest send ./project-dir
```

For SSH access exchange, the host receiving access runs:

```bash
npx -y derphole@latest ssh invite --user deploy
```

The other side accepts with:

```bash
npx -y derphole@latest ssh accept <token>
```

### Watch Progress with `pv`

`derphole` is plain stdin/stdout, so `pv` fits naturally in the pipe.

Install `pv` if needed:

```bash
brew install pv
sudo apt install -y pv
```

On the receiving machine:

```bash
npx -y derphole@latest listen | pv -brt > received.img
```

On the sending machine:

```bash
cat ./disk.img | pv -brt | npx -y derphole@latest pipe <token>
```

Want a concrete Internet/NAT version of the same idea? See [Real-World Example: Tar Pipe Over Internet](#real-world-example-tar-pipe-over-internet).

### Share a Local TCP Service

On the machine running the local web app or API:

```bash
npx -y derphole@latest share 127.0.0.1:3000
```

`share` prints a token to stderr. Copy that token to the machine that will open the shared service.

On another machine, expose that shared service locally:

```bash
npx -y derphole@latest open <token>
```

`open` prints the local listening address to stderr.

Bind `open` to a specific local port if you want:

```bash
npx -y derphole@latest open <token> 127.0.0.1:8080
```

### Useful Extras

Use the development channel for the latest commit published from `main`:

```bash
npx -y derphole@dev version
```

By default, `listen`, `pipe`, `send`, `receive`, `share`, and `open` keep transport status quiet. `listen` and `share` print the token you need, `open` prints the local listening address, and `send` / `receive` print the instruction or token needed to complete the transfer. Known-size transfers show wormhole-shaped progress on stderr. Use `--hide-progress` to suppress the progress bar. Use `--verbose` to see state transitions like `connected-relay` and `connected-direct`:

```bash
npx -y derphole@latest --verbose listen
npx -y derphole@latest --verbose pipe <token>
npx -y derphole@latest --verbose send ./photo.jpg
```

Want transport details after the examples? Jump to [Transport Model](#transport-model), [Behavior](#behavior), or [Security Model](#security-model).

## Transport Model

High level:

1. `listen`, `share`, or `receive` creates an ephemeral session and prints an opaque bearer token.
2. That token contains the session ID, expiry, DERP bootstrap hints, the listener's public peer identity, a bearer secret, and the allowed session capability.
3. `pipe`, `send`, or `open` uses the token to contact the listener through DERP and claim the session.
4. The listener validates the claim, checks the requested capability, and returns its current direct-path candidates.
5. Both sides start on the first working path immediately, including DERP relay if direct connectivity is not ready yet.
6. In parallel, both sides continue NAT traversal and direct-path probing. If a direct path succeeds, the live session upgrades in place without restarting the transfer.

### Data Plane Selection

DERP is used for **rendezvous** and **relay fallback**. If the term is new, see [What Is DERP?](#what-is-derp):

- rendezvous: exchange initial claim, decision, and direct-path coordination messages without a separate account-backed control plane
- relay fallback: keep the session working even when NAT traversal fails or a direct path is not ready yet

The data plane is selected per session:

- `share/open` uses multiplexed QUIC streams over `derphole`'s relay/direct UDP transport, so one claimed session can carry many independent TCP connections to the shared service.
- `listen/pipe` uses a one-shot byte stream. By default, `derphole` coordinates through DERP, promotes to a rate-adaptive direct UDP blast when traversal succeeds, and stays on encrypted relay fallback when no direct path is available.
- `send/receive` wraps the same one-shot stream with text, file, directory, and progress metadata.

Candidate discovery splits into two phases:

- fast local candidates first: immediately advertise local socket/interface candidates and any cached port mapping
- background traversal discovery: run STUN and UPnP / NAT-PMP / PCP refresh, then send updated candidates and `call-me-maybe` probes if a new direct endpoint appears

That keeps startup latency low while still allowing relay-to-direct promotion.

## How This Differs From Tailscale / WireGuard

Tailscale uses WireGuard to build a secure general-purpose network between peers. That is the right abstraction when you want durable machine-to-machine connectivity, stable private addressing, ACLs, subnet routing, exit nodes, and a long-lived encrypted overlay.

`derphole` does something narrower and faster for its target workload. It creates session-scoped transport for a single transfer or a single shared service:

- no WireGuard tunnel device
- no overlay network interface
- no persistent mesh control plane
- no need to route arbitrary traffic through a general encrypted network

Instead, `derphole` uses a bearer token to authorize exactly one session, uses DERP to get both peers talking immediately, and then promotes the session onto the best direct path it can establish for that workload. Supporting details are in [Transport Model](#transport-model) and [Security Model](#security-model).

For `listen/pipe`, `send/receive`, and `share/open`, that can beat routing the same traffic through a WireGuard-based overlay because `derphole` is purpose-built for the active session, not for a general secure network abstraction. See [Why It Is Fast](#why-it-is-fast) for the concrete transport reasons.

## Why It Is Fast

`derphole` gets its performance from the transport design:

- DERP is for rendezvous and relay fallback, not the preferred steady-state data plane.
- Sessions can start relayed immediately, then promote in place to direct without restarting the transfer.
- `listen/pipe` and `send/receive` can scale from one to multiple direct UDP lanes, run a short path-rate probe, then use paced sending, adaptive rate control, and targeted replay/repair. That lets fast links run near their WAN ceiling without forcing slower links into the same send rate.
- Direct UDP payload packets are AEAD-protected with a per-session key derived from the bearer secret. The packet header stays visible for sequencing and repair, while user bytes stay encrypted and authenticated.
- `share/open` keeps QUIC stream multiplexing for service sharing, where many independent TCP streams need one claimed session.
- Candidate discovery is front-loaded with local interface candidates and cached mappings, then refined in the background with STUN and port mapping refresh. That keeps the first byte moving quickly instead of stalling the session until every traversal probe finishes.

In practice: get bytes moving early, keep them moving through relay if needed, then shift the live session onto a faster direct path as soon as direct connectivity is ready.

## Security Model

The session token is a **bearer capability**. Anyone who has the token can claim the session until it expires, so share it over a channel you trust. Tokens expire after one hour.

DERP relays do **not** get the secret material needed to read or impersonate the session:

- On the default `listen/pipe` and `send/receive` direct UDP path, payload packets are encrypted and authenticated with session AEAD derived from the bearer secret in the token.
- On `share/open`, stream traffic is carried over authenticated QUIC streams for the claimed session.
- If packets are relayed through DERP, DERP only forwards encrypted session bytes.

Important security property: `derphole` does not trade speed for plaintext shortcuts:

- the token authorizes the session, but does not turn DERP into a trusted decrypting proxy
- direct UDP data packets are encrypted and authenticated per session
- QUIC stream-mode peers are pinned to the expected public identity from the token
- DERP forwards encrypted traffic but does not have the keys required to decrypt or impersonate the session

Simple rule: possession of the token authorizes the session, but intermediaries that only see DERP traffic do not have the keys needed to decrypt it.

## Behavior

Sessions can start on DERP relay and later promote to a direct path without restarting. In default mode, the CLI keeps transport status quiet and prints only the user-facing token, bind address, or transfer UI needed to use the session. Use `--verbose` to inspect path changes, NAT traversal state, and direct-path tuning details.

## Use Cases

- easy cross-host transfer with no account setup
- useful behind NATs where direct connectivity may or may not work
- good for quick sharing of local web apps, APIs, and admin interfaces
- can be used entirely through `npx` without a manual install

## Real-World Example: Tar Pipe Over Internet

Classic tar pipe is fast because it streams bytes directly from `tar` on one host into `tar` on another host. Good reference: [Using netcat and tar to quickly transfer files between machines, aka tar pipe](https://toast.djw.org.uk/tarpipe.html).

Problem: classic `tar | nc` assumes receiver can expose a listening port and sender can reach it. That breaks down fast when both hosts are on the public Internet, both sit behind NAT, and neither side should expose an inbound port.

`derphole` keeps the same streaming shape, but removes the open-port requirement.

Receiver:

```bash
npx -y derphole@latest listen | tar -xpf - -C /restore/path
```

`listen` prints a token on stderr. Copy that token to the sender over a channel you trust.

Sender:

```bash
tar -cpf - /srv/data | npx -y derphole@latest pipe <token>
```

This is still tar pipe. Difference: no public listener to expose, no SSH daemon required for data path, no VPN to join, and no permanent mesh to set up. `derphole` starts with DERP if needed, then promotes the live transfer onto direct UDP when a faster direct path becomes available.

## Development

```bash
mise install
mise run install-githooks
mise run check
mise run build
```

`mise run build` writes `dist/derphole`.

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

- npm package: `derphole`
- production channel: `derphole@latest`
- development channel: `derphole@dev`
- bootstrap runbook: [docs/releases/npm-bootstrap.md](docs/releases/npm-bootstrap.md)

## What Is DERP?

DERP stands for **Designated Encrypted Relay for Packets**. In plain terms, it is a globally reachable relay network that both peers can talk to even when they cannot yet talk directly to each other.

DERP was built by Tailscale for the Tailscale networking stack, and the public Tailscale-operated DERP network is reachable without running your own relays. The same DERP model is also used by Headscale, the open-source Tailscale control server implementation, which can serve its own DERP map and DERP servers.

In `derphole`, DERP has two jobs:

- rendezvous: carry the initial claim, decision, and direct-path coordination messages so the two peers can find each other without a separate account-backed control plane
- fallback relay: carry encrypted session traffic when NAT traversal has not succeeded yet or when direct connectivity is unavailable

DERP is not the preferred steady-state path. It is the safety net that gets the session started and keeps it working. If a direct UDP path becomes available, `derphole` promotes the live session onto that direct path. DERP only forwards bytes; it does not get the session keys needed to decrypt the traffic.
