# derphole

`derphole` is a small CLI for the network job that should not require a new
network: move bytes, expose a local TCP service, or exchange SSH access for one
short session when neither side has an inbound port to offer.

The obvious answer is "use a VPN." Sometimes that is correct. If you need
stable private IPs, ACLs, subnet routes, exit nodes, and machines that remember
each other, use a VPN. If you need one transfer, one tunnel, or one shared
terminal, a VPN is a lot of state for a short conversation.

This repo ships three tools:

- `derphole` for one-shot files, byte streams, receive-code flows, temporary
  localhost shares, and SSH access exchange.
- [`derptun`](#tcp-tunnels) for longer-lived TCP tunnels with stable server and
  client tokens.
- [`derpssh`](#share-a-terminal) for shared terminal sessions with host approval
  and no open ports.

The tools use the public Tailscale [DERP](#what-is-derp) relay network for
rendezvous and fallback, then promote live traffic to direct encrypted UDP when
possible. Payload bytes stay end-to-end encrypted on relay fallback, direct UDP,
and authenticated QUIC stream paths. DERP sees routing metadata and packet
timing, not contents.

These tools are **not** affiliated with Tailscale and do **not** use
`tailscaled`.

They are also not a WireGuard overlay or a VPN. `derphole` handles one token,
one session, one transfer or shared service. `derptun` handles one tunnel with
reusable scoped tokens. `derpssh` handles one approved PTY session. See
[Transport Model](#transport-model), [Why It Is Fast](#why-it-is-fast), and
[Security Model](#security-model).

No Tailscale account, tailnet, daemon, or self-hosted control plane is required.
Session tokens carry authorization. Treat them like passwords with a shorter
half-life. Public sessions fetch the DERP map at runtime so both sides can find
relay and bootstrap nodes.

## Pick the Workflow

- Use `listen` and `pipe` when you want raw bytes and shell pipelines.
- Use `send` and `receive` when you want text, files, directories, progress, and
  receive-code UX.
- Use `share` and `open` when you want temporary access to a local TCP service.
- Use `ssh invite` and `ssh accept` when you want to exchange SSH access.
- Use [`derpssh`](#share-a-terminal) when two people need one approved terminal.
- Use [`derptun`](#tcp-tunnels) when the TCP tunnel needs reusable tokens and
  reconnects.

## Quick Start

`listen` receives bytes and prints a token. `pipe` sends stdin into that token.
`share` and `open` do the same shape of thing for local TCP services. The trick
is small on purpose: one token, one capability, one session.

Use [`derptun`](#tcp-tunnels) when the tunnel should live longer than a one-off
share.

### Stream a Raw File

Receiver:

```bash
npx -y derphole@latest listen > received.img
```

`listen` prints a token to stderr, keeping stdout clean. Copy the token to the
sender.

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

Known-size files and directories show progress on stderr. Use `--hide-progress`
when quiet output matters more than watching the counter move.

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

### Share a Terminal

Host:

```bash
npx -y derpssh@latest share
```

`share` prints a connect command. Send it to the guest:

```bash
npx -y derpssh@latest connect <invite>
```

The host normally approves each guest as read-only or read/write. To use one
policy for every join attempt while the host is running:

```bash
npx -y derpssh@latest share --auto-accept read
npx -y derpssh@latest share --auto-accept write
```

Anyone with the valid invite is accepted. `read` lets the guest watch and chat.
`write` also gives the guest control of the shared shell. The host can still
change the role or kick the guest.

The session uses the `derptun` transport path, so neither side needs an inbound
port.

Optional local lookup keeps the invite behind a service name on the connecting
machine:

```bash
npx -y derpssh@latest service set ops-shell <invite>
npx -y derpssh@latest connect --service ops-shell
```

The service name only finds the invite. It does not change the host's approval
policy.

### TCP Tunnels

`derptun` exposes a local TCP service without asking either side to open an
inbound port. Start with a one-off tunnel:

On the serving machine:

```bash
npx -y derptun@latest serve --tcp 127.0.0.1:3000
```

`serve` prints the command for the other side:

```bash
npx -y derptun@latest open --token DT1...
```

Run that command on the connecting machine. It opens a local listener and
forwards connections through the tunnel.

For a persistent tunnel, create both tokens on the serving machine and keep the
server token there:

```bash
npx -y derptun@latest token server > server.dts
npx -y derptun@latest token client --token-file server.dts > client.dt1
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:3000
```

Copy only `client.dt1` to the connecting machine.

On the connecting machine:

```bash
npx -y derptun@latest open --token-file client.dt1 --listen 127.0.0.1:3001
```

The server token is serving authority. Keep it on the serving machine or in a
secret manager. Client tokens can connect until expiry, but cannot serve or mint
tokens.

Server tokens default to 180 days. Client tokens default to 90 days and cannot
outlive their server token. Set a relative lifetime with `--days`, or use an
absolute expiry:

```bash
npx -y derptun@latest token server --expires 2026-05-01T00:00:00Z > server.dts
npx -y derptun@latest token client --token-file server.dts --expires 2026-04-25T00:00:00Z > client.dt1
```

Use `--token TOKEN` for inline one-off commands. Prefer `--token-file PATH` for
durable tokens. `--token-stdin` reads the token from the first stdin line.

Optional local lookup keeps the client token behind a service name on the
connecting machine:

```bash
npx -y derptun@latest service set web --token-file client.dt1
npx -y derptun@latest open --service web --listen 127.0.0.1:3001
```

The registry is local name-to-token storage. It is not a hosted control plane,
and no lookup server is contacted by default.

### Useful Extras

Use the development channel for the latest commit from `main`:

```bash
npx -y derphole@dev version
npx -y derptun@dev version
npx -y derpssh@dev version
```

Default output stays quiet: tokens, bind addresses, receive commands, and
progress only. Use `--hide-progress` to suppress progress, or `--verbose` to see
path changes such as `connected-relay` and `connected-direct`:

```bash
npx -y derphole@latest --verbose listen
npx -y derphole@latest --verbose pipe <token>
npx -y derphole@latest --verbose send ./photo.jpg
```

For transport details, see [Transport Model](#transport-model),
[Behavior](#behavior), and [Security Model](#security-model).

## Transport Model

The session flow is deliberately boring. Boring is good here.

1. `listen`, `share`, or `receive` creates a session and prints an opaque bearer
   token or receive code.
2. The token carries session ID, expiry, DERP bootstrap hints, listener public
   identity, bearer secret, and allowed capability.
3. `pipe`, `send`, or `open` uses that token to contact the listener through
   DERP and claim the session.
4. The listener validates the claim, checks the requested capability, and returns
   current direct-path candidates.
5. Both sides start on the first working path, including DERP relay if needed.
6. Both sides keep probing for a better direct path. Successful direct paths
   upgrade the live session in place.

### Data Plane Selection

DERP provides **rendezvous** and **relay fallback**. See
[What Is DERP?](#what-is-derp):

- rendezvous: exchange claim, decision, and direct-path coordination messages
  without an account-backed control plane
- relay fallback: keep the session working when NAT traversal fails or direct
  connectivity is not ready

The data plane is selected per session:

- `share/open` uses multiplexed QUIC streams over `derphole`'s relay/direct UDP
  transport. One claimed session can carry many TCP connections to the shared
  service.
- `derptun` uses a stable tunnel token and the same transport for reconnectable
  TCP streams. It is built for longer-lived access, such as a private service
  behind NAT.
- `derpssh` uses the `derptun` app mux for approved terminal streams and
  side-channel control.
- `listen/pipe` uses a one-shot byte stream. It coordinates through DERP,
  promotes to rate-adaptive direct UDP when traversal succeeds, and stays on
  encrypted relay fallback when direct paths fail.
- `send/receive` wraps the same one-shot stream with text, file, directory, and
  progress metadata.

Candidate discovery splits into two phases:

- fast local candidates first: advertise local sockets, interfaces, and cached
  port mappings immediately
- background traversal discovery: run STUN and UPnP / NAT-PMP / PCP refresh,
  then send updated candidates and `call-me-maybe` probes

This keeps startup latency low while preserving relay-to-direct promotion.

## How This Differs From Tailscale / WireGuard

Tailscale uses WireGuard for a secure general-purpose network: durable machine
connectivity, private addresses, ACLs, subnet routing, exit nodes, and
long-lived overlays.

That is the right tool when you want a network.

`derphole` is narrower. It creates session-scoped transport for one transfer or
one shared service:

- no WireGuard tunnel device
- no overlay network interface
- no persistent mesh control plane
- no need to route arbitrary traffic through a general encrypted network

Instead, `derphole` authorizes one session with a bearer token, uses DERP to get
peers connected immediately, then promotes onto the best direct path it can
establish. See [Transport Model](#transport-model) and
[Security Model](#security-model).

For `listen/pipe`, `send/receive`, and `share/open`, this can beat routing the
same traffic through a WireGuard-based overlay because `derphole` optimizes one
active session instead of maintaining a whole private network. Not magic. Less
machinery.

## Why It Is Fast

Performance comes from the transport shape:

- DERP handles rendezvous and fallback, not preferred steady-state data.
- Sessions can start relayed, then promote in place to direct without
  restarting.
- `listen/pipe` and `send/receive` can scale across direct UDP lanes, run
  path-rate probes, then use paced sending, adaptive rate control, and targeted
  replay/repair. Fast links can run near WAN ceiling without forcing slower
  links into the same send rate.
- Direct UDP payloads use AEAD with a per-session key derived from the bearer
  secret. Headers stay visible for sequencing and repair; user bytes stay
  encrypted and authenticated.
- `share/open` keeps QUIC stream multiplexing for service sharing, where many
  independent TCP streams need one claimed session.
- Candidate discovery starts with local interfaces and cached mappings, then
  refines in the background with STUN and port mapping refresh.

The practical result: move bytes early, keep relay fallback, and shift live
sessions to direct paths when ready.

## Security Model

Tokens are **bearer capabilities**. Anyone with a token can claim the matching
session or tunnel until expiry, so share tokens over a trusted channel.

`derphole` session tokens expire after one hour. `derptun` server tokens default
to 180 days and can mint shorter-lived client tokens. Client tokens default to
90 days and cannot serve.

Local service registry entries are bearer secrets because they contain derptun
client tokens or derpssh invites. Protect the registry file like token files.
List output redacts token and invite values, and no lookup server is contacted
by default.

Payload bytes are always end-to-end encrypted between token holders. Session and
tunnel encryption is pinned to token-derived identity, so DERP relays do **not**
get keys needed to read or impersonate sessions. DERP can see routing metadata
and packet timing, but not plaintext user payload bytes:

- On `listen/pipe` and `send/receive`, direct UDP and relay fallback both encrypt
  and authenticate user payloads with session AEAD derived from the bearer
  secret.
- Relay-prefix startup frames leave frame kind and byte offsets visible for flow
  control, but encrypt user payload bytes.
- On `share/open`, stream traffic uses authenticated QUIC streams for the
  claimed session.
- On `derptun`, stream traffic uses authenticated QUIC streams pinned to the
  stable tunnel identity in the token.
- On `derpssh`, terminal streams use authenticated QUIC streams pinned to the
  invite identity.

Simple rule: token possession authorizes the session. Relays move packets; they
do not hold decrypt keys for user payloads.

## Behavior

Sessions can start on DERP relay and later promote to direct paths without
restarting. By default, CLI output stays minimal. Use `--verbose` for path
changes, NAT traversal state, and direct-path tuning.

## Use Cases

Use this when you need:

- cross-host transfer with no account setup
- useful behavior on NAT-heavy networks where direct connectivity may or may not
  work
- quick sharing of local web apps, APIs, and admin interfaces
- `npx` execution without manual install

Do not use this as a replacement for a real private network when you actually
need one. That is how small tools become infrastructure nobody remembers
owning. Oops.

## Development

```bash
mise install
mise run install-githooks
go test ./pkg/token -run TestEncode
mise run check:fast
```

Run focused tests and the build-only `mise run check:fast` during iteration. It
compiles every product without running formatting or commit hooks. When making
a checkpoint commit, let the installed commit hook format changed Go files and
run deterministic hygiene; retry the commit if formatting changed tracked
content. Do not run the exhaustive gate as part of the normal coding loop.
Immediately before a push or landing, run it once:

```bash
mise run check
```

`mise run build` writes `dist/derphole`, `dist/derptun`, and `dist/derpssh`.

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
REMOTE_HOST=my-server.example.com mise run smoke-remote-derpssh
REMOTE_HOST=my-server.example.com mise run promotion-1g
```

## Releases

- npm packages: `derphole`, `derptun`, `derpssh`
- production channels: `derphole@latest`, `derptun@latest`, `derpssh@latest`
- development channels: `derphole@dev`, `derptun@dev`, `derpssh@dev`

## What Is DERP?

DERP stands for **Designated Encrypted Relay for Packets**. It is a globally
reachable relay network that both peers can use when they cannot yet talk
directly.

DERP was built by Tailscale for the Tailscale networking stack. The public
Tailscale-operated DERP network is reachable without running your own relays.
Headscale, the open-source Tailscale control server, can also serve DERP maps
and DERP servers.

In `derphole`, DERP has two jobs:

- rendezvous: carry claim, decision, and direct-path coordination messages
  without a separate account-backed control plane
- fallback relay: carry encrypted session traffic when NAT traversal has not
  succeeded or direct connectivity is unavailable

DERP is not the preferred steady-state path. It starts the session and keeps it
working. If direct UDP becomes available, `derphole` promotes the live session.
DERP forwards bytes; it does not get session decrypt keys.
