# derpcat

`derpcat` is a standalone CLI for moving data between two hosts over the public Tailscale DERP network, with direct UDP promotion when the network allows it.

It supports two primary modes:

- one-shot byte-stream transfer with `listen` and `send`
- long-lived local service sharing with `share` and `open`

## Quick Start

Use the published package directly:

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

## Behavior

Sessions can start on DERP relay and later promote to a direct UDP path without restarting. Use `--verbose` to observe path changes such as `connected-relay` and `connected-direct`.

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
