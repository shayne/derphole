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
2. That token contains the bootstrap information the other side needs, including session metadata, peer identity material, relay bootstrap hints, and authorization state.
3. `send` or `open` uses the token to reach the listening side over the public DERP network and claim the session.
4. Once the peers are connected, `derpcat` carries traffic immediately over whatever path is available first, including DERP relay.
5. In parallel, both peers continue endpoint discovery and direct UDP probing.
6. If a direct path succeeds, the live session upgrades from relay to direct without interrupting the transfer.

Public sessions use a QUIC stream layer over `derpcat`'s transport manager. That gives:

- a single stream for `listen` and `send`
- multiplexed streams for `share` and `open`, so one claimed session can carry many TCP connections

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
