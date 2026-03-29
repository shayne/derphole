# Manual npm Bootstrap Publish

This runbook covers the first npm publish before GitHub trusted publishing is configured.

## Prerequisites

- npm account that can claim and publish the `derpcat` package name
- local `npm whoami` succeeds
- run from the repository root
- `mise` and the release toolchain are available locally
- clean git working tree

## Build and validate `0.0.1`

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
VERSION=v0.0.1 mise run release:npm-dry-run
node ./dist/npm/bin/derpcat.js --version
```

Expected output:

- `npm publish --dry-run` succeeds
- `node ./dist/npm/bin/derpcat.js --version` prints `v0.0.1`

## Publish

```bash
npm publish ./dist/npm --access public
```

## After trusted publisher setup

Once npm trusted publishing is configured for `shayne/derpcat`:

```bash
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

After that, pushes to `main` update the npm `dev` dist-tag, and pushes of `v*` tags publish production releases through GitHub Actions. The manual `0.0.1` bootstrap path is no longer needed once trusted publishing is configured.
