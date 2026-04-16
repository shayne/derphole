# Derphole Single Product Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `derphole` the only product, while preserving the useful raw stream and TCP sharing features from the retiring CLI.

**Architecture:** Keep `cmd/derphole` as the only native CLI and move lower-level command wrappers into it. Preserve shared session and transport packages, then mechanically rename module imports, environment variables, packaging metadata, workflows, scripts, and docs to the new single-product surface.

**Tech Stack:** Go 1.26.1, `github.com/shayne/yargs`, shell release scripts, GitHub Actions, npm package templates, `gh`.

---

## File Structure

- Modify: `cmd/derphole/root.go`
  - Register `listen`, `pipe`, `share`, and `open`.
  - Dispatch those commands.
  - Keep structured `send` / `receive` behavior.
- Create: `cmd/derphole/listen.go`
  - Raw byte-stream receiver.
- Create: `cmd/derphole/pipe.go`
  - Raw stdin sender.
- Create: `cmd/derphole/share.go`
  - TCP service share wrapper.
- Create: `cmd/derphole/open.go`
  - TCP service open wrapper.
- Modify: `cmd/derphole/*_test.go`
  - Add CLI tests for migrated commands.
- Delete: `cmd/derpcat/`
  - Remove retired CLI after behavior is covered in `cmd/derphole`.
- Move: `cmd/derpcat-probe/` to `cmd/derphole-probe/`
  - Rename probe command and tests.
- Modify: `go.mod`
  - Change module path to `github.com/shayne/derphole`.
- Modify: all `.go` files
  - Rewrite internal imports to `github.com/shayne/derphole/...`.
- Modify: `pkg/session`, `pkg/quicpath`, `pkg/transport`, `pkg/portmap`, `pkg/probe`, scripts, and tests
  - Rename `DERPCAT_` variables and internal branded string constants to `DERPHOLE_` / `derphole`.
- Modify: `.mise.toml`, `.github/workflows/release.yml`, `tools/packaging/*.sh`, `packaging/npm/`, `scripts/release-package-smoke.sh`
  - Build and publish only `derphole`.
- Delete: `packaging/npm/derpcat/`
  - Retire npm package template.
- Modify: `README.md`, `AGENTS.md`, `docs/**/*.md`, `scripts/**/*.sh`, `web/derphole/*`
  - Remove retired product references and document the single-product command surface.

## Task 1: Add migrated command tests to `cmd/derphole`

**Files:**
- Modify: `cmd/derphole/root_test.go`
- Create or modify: `cmd/derphole/listen_test.go`
- Create or modify: `cmd/derphole/pipe_test.go`
- Create or modify: `cmd/derphole/share_test.go`
- Create or modify: `cmd/derphole/open_test.go`

- [ ] **Step 1: Write failing root help and unknown-command tests**

Add tests that assert root help includes `listen`, `pipe`, `share`, and `open`, and unknown commands say `Run 'derphole --help' for usage`.

- [ ] **Step 2: Write failing raw command wrapper tests**

Use the existing retired CLI tests as behavior reference, but update expected help text, command names, function names, and error messages for `derphole`.

- [ ] **Step 3: Verify the tests fail**

Run:

```bash
go test ./cmd/derphole -run 'TestRunHelp(Listen|Pipe|Share|Open)|TestRunRejectsUnknownCommand|TestRun(Listen|Pipe|Share|Open)' -count=1
```

Expected: FAIL because the migrated commands are not registered or implemented yet.

## Task 2: Move raw stream and share/open commands into `cmd/derphole`

**Files:**
- Modify: `cmd/derphole/root.go`
- Create: `cmd/derphole/listen.go`
- Create: `cmd/derphole/pipe.go`
- Create: `cmd/derphole/share.go`
- Create: `cmd/derphole/open.go`
- Modify: `cmd/derphole/version.go`

- [ ] **Step 1: Implement root registry and dispatch**

Add `listen`, `pipe`, `share`, and `open` to `rootRegistry.SubCommands` and dispatch them from `run`.

- [ ] **Step 2: Implement `listen`**

Port the raw listener wrapper into `cmd/derphole/listen.go`, keeping `--print-token-only` and `--force-relay`.

- [ ] **Step 3: Implement `pipe`**

Port the raw sender wrapper into `cmd/derphole/pipe.go`, rename the command from raw `send` to `pipe`, and keep `--force-relay` plus `--parallel`.

- [ ] **Step 4: Implement `share` and `open`**

Port TCP sharing wrappers into `cmd/derphole/share.go` and `cmd/derphole/open.go`.

- [ ] **Step 5: Verify migrated command tests pass**

Run:

```bash
go test ./cmd/derphole -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/derphole
git commit -m "feat: move raw and share commands into derphole"
```

## Task 3: Remove retired CLI and rename the probe command

**Files:**
- Delete: `cmd/derpcat/`
- Move: `cmd/derpcat-probe/` to `cmd/derphole-probe/`
- Modify: `.mise.toml`
- Modify: scripts that build or call the probe command

- [ ] **Step 1: Remove retired CLI directory**

Delete `cmd/derpcat` after `cmd/derphole` covers its features.

- [ ] **Step 2: Rename probe command directory and executable names**

Move the probe command to `cmd/derphole-probe` and update build scripts and tests to use `derphole-probe`.

- [ ] **Step 3: Verify command packages**

Run:

```bash
go test ./cmd/derphole ./cmd/derphole-probe -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd .mise.toml scripts
git commit -m "refactor: remove retired cli entrypoints"
```

## Task 4: Rename Go module imports and environment variables

**Files:**
- Modify: `go.mod`
- Modify: all Go source files
- Modify: scripts and docs that reference `DERPCAT_`

- [ ] **Step 1: Rewrite module path**

Change `go.mod` to `module github.com/shayne/derphole`.

- [ ] **Step 2: Rewrite internal imports**

Replace `github.com/shayne/derpcat` with `github.com/shayne/derphole` in Go files.

- [ ] **Step 3: Rename environment variables**

Replace `DERPCAT_` with `DERPHOLE_` in Go code, tests, scripts, and docs.

- [ ] **Step 4: Rename internal branded string constants**

Replace internal `derpcat-` string constants with `derphole-` where used for filenames, probes, ALPN, temp files, and bus client names.

- [ ] **Step 5: Verify core packages**

Run:

```bash
gofmt -w $(find . -path ./dist -prune -o -name '*.go' -print)
go test ./cmd/derphole ./cmd/derphole-probe ./pkg/session ./pkg/transport ./pkg/quicpath -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod cmd pkg scripts docs
git commit -m "refactor: rename module and environment prefix"
```

## Task 5: Collapse release and npm packaging to one product

**Files:**
- Modify: `.mise.toml`
- Modify: `.github/workflows/release.yml`
- Modify: `tools/packaging/build-vendor.sh`
- Modify: `tools/packaging/build-npm.sh`
- Modify: `tools/packaging/build-release-assets.sh`
- Modify: `tools/packaging/publish-npm-if-missing.sh`
- Modify: `scripts/release-package-smoke.sh`
- Delete: `packaging/npm/derpcat/`
- Modify: `packaging/npm/derphole/package.json`
- Modify: `packaging/npm/README.md`

- [ ] **Step 1: Update build tasks**

Make `mise run build`, `build-linux-amd64`, `release:build-all`, and `release:npm-dry-run` build only `derphole`.

- [ ] **Step 2: Update packaging scripts**

Make vendor, npm, release tarball, and release smoke scripts stage only `derphole`.

- [ ] **Step 3: Update GitHub Actions release workflow**

Remove retired product matrix entries, artifacts, npm publish steps, dry-runs, and npm environment URLs.

- [ ] **Step 4: Verify build and npm staging**

Run:

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
test -x dist/derphole
test -f dist/npm-derphole/package.json
test ! -e dist/npm-derpcat
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .mise.toml .github tools scripts packaging
git commit -m "build: publish only derphole"
```

## Task 6: Update documentation and scrub source references

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `docs/**/*.md`
- Modify: `scripts/**/*.sh`
- Modify: `web/derphole/*`

- [ ] **Step 1: Rewrite README as single-product docs**

Document structured send/receive, raw `listen`/`pipe`, `share`/`open`, SSH, npm install, transport model, and release artifacts.

- [ ] **Step 2: Rewrite release and benchmark docs**

Update package names, commands, environment variables, and examples to use only `derphole`.

- [ ] **Step 3: Rewrite historical planning docs**

Edit historical specs and plans so the retired product literal no longer appears in the source tree.

- [ ] **Step 4: Verify scrub**

Run:

```bash
rg -i 'derpcat' -g '!dist'
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add README.md AGENTS.md docs scripts web
git commit -m "docs: document derphole-only project"
```

## Task 7: Rename GitHub repository and update local remote

**Files:**
- No source files expected after previous tasks.

- [ ] **Step 1: Rename repository with `gh`**

Run:

```bash
gh repo rename derphole --yes
```

Expected: repository becomes `shayne/derphole`.

- [ ] **Step 2: Update local remote**

Run:

```bash
git remote set-url origin git@github.com:shayne/derphole.git
git remote -v
```

Expected: both fetch and push URLs point at `shayne/derphole`.

## Task 8: Final verification, push, and CI watch

**Files:**
- Any final fixes required by verification.

- [ ] **Step 1: Run focused tests**

```bash
go test ./cmd/derphole ./cmd/derphole-probe ./pkg/derphole ./pkg/session -count=1
```

Expected: PASS, except known pre-existing timing failures should be rerun once before classification.

- [ ] **Step 2: Run full local checks**

```bash
mise run build
mise run test
mise run vet
```

Expected: PASS, except known pre-existing timing failures should be noted with exact test names and rerun output.

- [ ] **Step 3: Run release checks**

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
VERSION=v0.0.1-dev.$(date -u +%Y%m%d%H%M%S) mise run release:npm-dry-run
```

Expected: PASS.

- [ ] **Step 4: Run scrub check**

```bash
rg -i 'derpcat' -g '!dist'
```

Expected: no matches.

- [ ] **Step 5: Push and watch CI**

```bash
git push origin main
gh run list --limit 5
gh run watch
```

Expected: latest `main` workflow runs complete successfully.
