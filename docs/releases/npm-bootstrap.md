# Manual npm Bootstrap Publish

This runbook covers the first npm publish before GitHub trusted publishing is configured. The repository now ships one npm package: `derphole`.

## Prerequisites

- npm account that can claim and publish the `derphole` package name
- local `npm whoami` succeeds
- run from the repository root
- `mise` and the release toolchain are available locally
- clean git working tree

## Build and validate release artifacts

Build the binaries, release tarballs, and npm package directory:

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
```

Validate the npm payload with an unpublished prerelease version. This avoids dry-run failures when `0.0.1` already exists:

```bash
VERSION=v0.0.1-dev.$(date -u +%Y%m%d%H%M%S) mise run release:npm-dry-run
node ./dist/npm-derphole/bin/derphole.js version
```

Expected output:

- `npm publish --dry-run` succeeds for `dist/npm-derphole`
- `node ./dist/npm-derphole/bin/derphole.js version` prints `v0.0.1`

## Publish

Publish the package if it is being bootstrapped:

```bash
npm publish ./dist/npm-derphole --access public
```

## After trusted publisher setup

Once npm trusted publishing is configured for `shayne/derphole`:

```bash
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

Before the package is bootstrapped and publishable by this workflow, pushes to `main` still build and dry-run the npm artifact, but the dev publish job skips registry ownership or permission failures instead of failing CI. After bootstrap and trusted publisher setup, pushes to `main` update the npm `dev` dist-tag, and pushes of `v*` tags publish production releases through GitHub Actions. The manual `0.0.1` bootstrap path is no longer needed once trusted publishing is configured.
