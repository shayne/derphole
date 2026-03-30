# derpcat

`derpcat` is a standalone Go CLI for moving one bidirectional byte stream or sharing a local TCP service between two hosts using the public Tailscale DERP network for bootstrap and relay fallback, with direct UDP promotion when possible.

## npm

The npm packaging and release workflow now exist.
The first `0.0.1` publish is still manual until npm trusted publishing is configured.
The install commands below are post-publish examples.

### Production install example

```bash
npx derpcat version
```

### Dev channel install example

```bash
npx derpcat@dev version
```

## Build

```bash
mise run build
```

## Runtime Notes

`derpcat` sessions can start on DERP relay and later promote to direct UDP without restarting. Use `--verbose` when you want to observe status transitions such as `connected-relay` and `connected-direct`; the live smoke scripts now inspect the full trace instead of only a final state.

## Development

```bash
mise install
mise run install-githooks
mise run check
```

## Test

```bash
mise run check
./scripts/smoke-local.sh
mise run smoke-remote
mise run smoke-remote-share
./scripts/promotion-test.sh hetz 1024
./scripts/promotion-test.sh pve1 1024
```

## Usage

One-shot stdin/stdout transfer:

```bash
derpcat listen
printf 'hello\n' | derpcat send <token>
```

Share a local service until Ctrl-C:

```bash
derpcat share 127.0.0.1:3000
derpcat open <token>
```

## Publishing

- Manual bootstrap runbook: [docs/releases/npm-bootstrap.md](docs/releases/npm-bootstrap.md)
- `main` publishes the npm `dev` dist-tag once trusted publishing is configured
- version tags like `v0.1.0` publish production releases through GitHub Actions once trusted publishing is configured
