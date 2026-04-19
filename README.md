# derphole

`derphole` is a standalone CLI for session-scoped byte transfer and temporary local TCP service sharing. Use it for one-shot transfers, receive-code flows, and short-lived service sharing.

[`derptun`](#long-lived-tcp-tunnels) is its companion for long-lived TCP tunnels. Use it when a tunnel needs stable tokens, restartable endpoints, and repeated client reconnects.

`derphole` supports:

- raw byte streams with `listen` and `pipe`
- text, file, and directory transfer with `send` and `receive`
- local TCP service sharing with `share` and `open`
- SSH access exchange with `ssh invite` and `ssh accept`

Both tools use the public Tailscale [DERP](#what-is-derp) relay network for rendezvous and fallback, then promote live traffic to direct encrypted UDP when possible. They are **not** affiliated with Tailscale and do **not** use `tailscaled`.

Neither tool is a WireGuard overlay or VPN. `derphole` handles one token, one session, one transfer or shared service. `derptun` handles one long-lived tunnel. See [Transport Model](#transport-model), [Why It Is Fast](#why-it-is-fast), and [Security Model](#security-model).

Neither tool requires:

- a Tailscale account
- a tailnet
- `tailscaled`
- a separate control plane to run yourself

Session tokens carry authorization. Public sessions fetch the DERP map at runtime so both sides can find relay and bootstrap nodes. See [Security Model](#security-model) for token and relay details.

## Pick the Workflow

- Use `listen` and `pipe` for raw byte streams and shell pipelines.
- Use `send` and `receive` for text, files, directories, progress, and receive-code UX.
- Use `share` and `open` for temporary access to a local TCP service.
- Use `ssh invite` and `ssh accept` for SSH public key exchange.
- Use [`derptun`](#long-lived-tcp-tunnels) for long-lived TCP tunnels with reusable tokens.

## Quick Start

`listen` receives bytes and prints a token. `pipe` sends stdin into that token. `share` and `open` do the same for local TCP services. Use [`derptun`](#long-lived-tcp-tunnels) for reusable, longer-lived tunnels.

### Stream a Raw File

Receiver:

```bash
npx -y derphole@latest listen > received.img
```

`listen` prints a token to stderr, keeping stdout clean. Copy the token to the sender.

Sender:

```bash
cat ./disk.img | npx -y derphole@latest pipe <token>
```

For quick text:

```bash
printf 'hello\n' | npx -y derphole@latest pipe <token>
```

### Send with a Receive Code

Sender:

```bash
npx -y derphole@latest send ./photo.jpg
```

`send` prints the receiver command:

```bash
npx -y derphole@latest receive <code>
```

Known-size files and directories show progress on stderr. Use `--hide-progress` for quiet output.

Text uses the same flow:

```bash
npx -y derphole@latest send hello
```

Directories stream as tar and re-materialize on the receiver:

```bash
npx -y derphole@latest send ./project-dir
```

### Exchange SSH Access

Host granting access:

```bash
npx -y derphole@latest ssh invite --user deploy
```

Client:

```bash
npx -y derphole@latest ssh accept <token>
```

### Share a Local TCP Service

Service host:

```bash
npx -y derphole@latest share 127.0.0.1:3000
```

`share` prints a token to stderr. Copy it to the client machine.

Client:

```bash
npx -y derphole@latest open <token>
```

`open` prints the local listening address to stderr.

Bind `open` to a specific local port:

```bash
npx -y derphole@latest open <token> 127.0.0.1:8080
```

### Long-Lived TCP Tunnels

`derptun` is the long-lived TCP tunnel companion to `derphole`. It uses stable tokens, survives restarts on either side, and lets one client reconnect many times without opening ports on `vps-server`. It fits SSH well.

On `vps-server`:

```bash
npx -y derptun@latest token server > server.dts
npx -y derptun@latest token client --token-file server.dts > client.dtc
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:22
```

Copy only `client.dtc` to `alice-laptop`.

On `alice-laptop`:

```bash
npx -y derptun@latest open --token-file client.dtc --listen 127.0.0.1:2222
ssh -p 2222 user@127.0.0.1
```

For SSH without a separate local listener, use `ProxyCommand`:

```bash
ssh -o ProxyCommand='npx -y derptun@latest connect --token-file ./client.dtc --stdio' foo@127.0.0.1
```

The server token is serving authority. Keep it on the serving machine or in its secret manager. The client token can connect until expiry, but cannot serve or mint tokens.

Server tokens default to 180 days. Client tokens default to 90 days and cannot outlive their server token. Set a relative lifetime with `--days`, or use an absolute expiry:

```bash
npx -y derptun@latest token server --expires 2026-05-01T00:00:00Z > server.dts
npx -y derptun@latest token client --token-file server.dts --expires 2026-04-25T00:00:00Z > client.dtc
```

Use `--token TOKEN` for inline one-off commands. Prefer `--token-file PATH` for durable tokens. `--token-stdin` reads the token from the first stdin line.

`derptun` is TCP-only for now. UDP forwarding is planned for use cases like Minecraft Bedrock servers.

### Useful Extras

Use the development channel for the latest commit from `main`:

```bash
npx -y derphole@dev version
npx -y derptun@dev version
```

Default output stays quiet: tokens, bind addresses, receive commands, and progress only. Use `--hide-progress` to suppress progress, or `--verbose` to see transitions like `connected-relay` and `connected-direct`:

```bash
npx -y derphole@latest --verbose listen
npx -y derphole@latest --verbose pipe <token>
npx -y derphole@latest --verbose send ./photo.jpg
```

For transport details, see [Transport Model](#transport-model), [Behavior](#behavior), and [Security Model](#security-model).

## Transport Model

Flow:

1. `listen`, `share`, or `receive` creates a session and prints an opaque bearer token or receive code.
2. The token carries session ID, expiry, DERP bootstrap hints, listener public identity, bearer secret, and allowed capability.
3. `pipe`, `send`, or `open` uses that token to contact the listener through DERP and claim the session.
4. The listener validates the claim, checks the requested capability, and returns current direct-path candidates.
5. Both sides start on the first working path, including DERP relay if needed.
6. Both sides keep probing for a better direct path. Successful direct paths upgrade the live session in place.

### Data Plane Selection

DERP provides **rendezvous** and **relay fallback**. See [What Is DERP?](#what-is-derp):

- rendezvous: exchange claim, decision, and direct-path coordination messages without an account-backed control plane
- relay fallback: keep the session working when NAT traversal fails or direct connectivity is not ready

The data plane is selected per session:

- `share/open` uses multiplexed QUIC streams over `derphole`'s relay/direct UDP transport. One claimed session can carry many TCP connections to the shared service.
- `derptun` uses a stable tunnel token and the same transport for reconnectable TCP streams. It is built for longer-lived access, such as SSH to a host behind NAT.
- `listen/pipe` uses a one-shot byte stream. It coordinates through DERP, promotes to rate-adaptive direct UDP when traversal succeeds, and stays on encrypted relay fallback when direct paths fail.
- `send/receive` wraps the same one-shot stream with text, file, directory, and progress metadata.

Candidate discovery splits into two phases:

- fast local candidates first: advertise local sockets, interfaces, and cached port mappings immediately
- background traversal discovery: run STUN and UPnP / NAT-PMP / PCP refresh, then send updated candidates and `call-me-maybe` probes

This keeps startup latency low while preserving relay-to-direct promotion.

## How This Differs From Tailscale / WireGuard

Tailscale uses WireGuard for a secure general-purpose network: durable machine connectivity, private addresses, ACLs, subnet routing, exit nodes, and long-lived overlays.

`derphole` is narrower. It creates session-scoped transport for one transfer or one shared service:

- no WireGuard tunnel device
- no overlay network interface
- no persistent mesh control plane
- no need to route arbitrary traffic through a general encrypted network

Instead, `derphole` authorizes one session with a bearer token, uses DERP to connect peers immediately, then promotes onto the best direct path it can establish. See [Transport Model](#transport-model) and [Security Model](#security-model).

For `listen/pipe`, `send/receive`, and `share/open`, this can beat routing the same traffic through a WireGuard-based overlay because `derphole` optimizes one active session. See [Why It Is Fast](#why-it-is-fast).

## Why It Is Fast

Performance comes from transport shape:

- DERP handles rendezvous and fallback, not preferred steady-state data.
- Sessions can start relayed, then promote in place to direct without restarting.
- `listen/pipe` and `send/receive` can scale across direct UDP lanes, run path-rate probes, then use paced sending, adaptive rate control, and targeted replay/repair. Fast links can run near WAN ceiling without forcing slower links into the same send rate.
- Direct UDP payloads use AEAD with a per-session key derived from the bearer secret. Headers stay visible for sequencing and repair; user bytes stay encrypted and authenticated.
- `share/open` keeps QUIC stream multiplexing for service sharing, where many independent TCP streams need one claimed session.
- Candidate discovery starts with local interfaces and cached mappings, then refines in the background with STUN and port mapping refresh.

Result: move bytes early, keep relay fallback, and shift live sessions to direct paths when ready.

## Security Model

Tokens are **bearer capabilities**. Anyone with a token can claim the matching session or tunnel until expiry, so share tokens over a trusted channel. `derphole` session tokens expire after one hour. `derptun` server tokens default to 180 days and can mint shorter-lived client tokens. Client tokens default to 90 days and cannot serve.

DERP relays do **not** get keys needed to read or impersonate sessions:

- On the default `listen/pipe` and `send/receive` direct UDP path, payload packets are encrypted and authenticated with session AEAD derived from the bearer secret.
- On `share/open`, stream traffic uses authenticated QUIC streams for the claimed session.
- On `derptun`, stream traffic uses authenticated QUIC streams pinned to the stable tunnel identity in the token.
- If packets are relayed through DERP, DERP only forwards encrypted session bytes.

Simple rule: token possession authorizes the session. Intermediaries that only see DERP traffic do not have decrypt keys.

## Behavior

Sessions can start on DERP relay and later promote to direct paths without restarting. By default, CLI output stays minimal. Use `--verbose` for path changes, NAT traversal state, and direct-path tuning.

## Use Cases

- cross-host transfer with no account setup
- NAT-heavy networks where direct connectivity may or may not work
- quick sharing of local web apps, APIs, and admin interfaces
- `npx` use without manual install

## Development

```bash
mise install
mise run install-githooks
mise run check
mise run build
```

`mise run build` writes `dist/derphole` and `dist/derptun`.

## Verification

Local smoke test:

```bash
mise run smoke-local
```

Remote smoke tests against a host you control:

```bash
REMOTE_HOST=my-server.example.com mise run smoke-remote
REMOTE_HOST=my-server.example.com mise run smoke-remote-share
REMOTE_HOST=my-server.example.com mise run smoke-remote-derptun
REMOTE_HOST=my-server.example.com mise run promotion-1g
```

## Releases

- npm packages: `derphole`, `derptun`
- production channels: `derphole@latest`, `derptun@latest`
- development channels: `derphole@dev`, `derptun@dev`

## What Is DERP?

DERP stands for **Designated Encrypted Relay for Packets**. It is a globally reachable relay network that both peers can use when they cannot yet talk directly.

DERP was built by Tailscale for the Tailscale networking stack. The public Tailscale-operated DERP network is reachable without running your own relays. Headscale, the open-source Tailscale control server, can also serve DERP maps and DERP servers.

In `derphole`, DERP has two jobs:

- rendezvous: carry claim, decision, and direct-path coordination messages without a separate account-backed control plane
- fallback relay: carry encrypted session traffic when NAT traversal has not succeeded or direct connectivity is unavailable

DERP is not the preferred steady-state path. It starts the session and keeps it working. If direct UDP becomes available, `derphole` promotes the live session. DERP forwards bytes; it does not get session decrypt keys.
