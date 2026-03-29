# derpcat

`derpcat` is a standalone Go CLI for moving one bidirectional byte stream between two hosts using the public Tailscale DERP network for bootstrap and relay fallback, with direct UDP promotion when possible.

## Install

### npm (production)

```bash
npx derpcat --version
```

### npm (dev channel)

```bash
npx derpcat@dev --version
```

## Build

```bash
mise run build
```

## Test

```bash
mise run test
mise run smoke-local
```

## Release

`main` publishes the `dev` npm dist-tag.
Version tags like `v0.1.0` publish production releases.
The first `0.0.1` npm publish is performed manually from `dist/npm`.
