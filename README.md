# derpcat

`derpcat` is a standalone Go CLI for moving one bidirectional byte stream between two hosts using the public Tailscale DERP network for bootstrap and relay fallback, with direct UDP promotion when possible.

## npm

The npm packaging and release workflow now exist.
The first `0.0.1` publish is still manual until npm trusted publishing is configured.
The install commands below are post-publish examples.

### Production install example

```bash
npx derpcat --version
```

### Dev channel install example

```bash
npx derpcat@dev --version
```

## Build

```bash
mise run build
```

## Development

```bash
mise install
mise run install-githooks
mise run check
```

## Test

```bash
mise run test
mise run smoke-local
```

## Publishing

- Manual bootstrap runbook: [docs/releases/npm-bootstrap.md](docs/releases/npm-bootstrap.md)
- `main` publishes the npm `dev` dist-tag once trusted publishing is configured
- version tags like `v0.1.0` publish production releases through GitHub Actions once trusted publishing is configured
