# Repository Guidelines

## Project Structure & Module Organization

`cmd/derpcat/` contains the CLI entrypoint and subcommand wiring. Core transport and session logic lives under `pkg/` (`pkg/session`, `pkg/wg`, `pkg/traversal`, `pkg/derpbind`, etc.). Packaging assets live in `packaging/npm/` and `tools/packaging/`. Verification scripts are in `scripts/`. Design and release docs live in `docs/derp/`, `docs/releases/`, and `docs/superpowers/`.

`dist/` is generated output for local builds, release packaging, and npm assembly. Treat it as ephemeral.

## Build, Test, and Development Commands

Use `mise` for toolchain consistency.

- `mise run build` builds `dist/derpcat`
- `mise run test` runs `go test ./...`
- `mise run vet` runs `go vet ./...`
- `mise run install-githooks` installs the local `pre-commit` and `prepare-commit-msg` hooks
- `mise run check:hooks` runs the full `pre-commit` hook set across the repo
- `mise run check` runs hooks, build, and tests in the same order CI uses
- `mise run smoke-local` runs the local end-to-end smoke test
- `mise run release:build-all` builds vendored binaries, release tarballs, and `dist/npm`
- `mise run release:npm-dry-run` validates the npm package without publishing

For remote verification, use tasks such as `mise run smoke-remote`, `mise run smoke-remote-tcp`, and `mise run promotion-1g-hetz`.

## Coding Style & Naming Conventions

Write idiomatic Go and keep files ASCII unless the file already requires otherwise. Use `gofmt` formatting conventions: tabs for indentation, mixedCaps for exported names, and short, package-scoped helpers where possible. Keep package boundaries clear: CLI code in `cmd/`, reusable logic in `pkg/`, packaging logic in shell scripts under `tools/packaging/`.

Do not hand-edit generated `dist/` contents. Update the source script or template instead.

## Testing Guidelines

Tests live alongside code in `*_test.go` files. Prefer focused package tests first, then full-suite verification.

- Package-level example: `go test ./pkg/token -run TestEncode`
- Full suite: `mise run test`
- Network/regression coverage: `mise run smoke-local`

When changing release or packaging behavior, also run `mise run release:npm-dry-run`.

## Commit & Pull Request Guidelines

Recent history uses scoped, imperative subjects such as `release: gate npm publishing on verification`, `docs: add npm bootstrap publish runbook`, and `ci: update workflow actions`. Follow that pattern: `<scope>: <change>`.

PRs should include:

- a short summary of user-visible impact
- linked issue or rationale when applicable
- exact verification commands run
- release or packaging implications if workflows, npm assets, or `docs/releases/` changed
