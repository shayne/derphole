# derpcat npm Publishing Design

Date: 2026-03-29

## Summary

`derpcat` should adopt the same release and npm-publishing structure used by `viberun`: a single GitHub Actions workflow that publishes development artifacts from `main` and production artifacts from version tags, with npm packages built from vendored native binaries and a thin Node launcher.

The initial rollout has two phases:

1. add the release skeleton, packaging files, local `mise` tasks, and CI workflow
2. manually publish `0.0.1` from the CLI before trusted publishing is enabled

After npm trusted publisher configuration is in place, tagged releases such as `v0.1.0` should publish automatically from GitHub Actions.

## Background

`derpcat` currently has a working Go CLI and verification scripts but no release metadata injection, no root README, no npm packaging template, and no GitHub release workflow.

The reference implementation is `viberun`, especially:

- `/Users/shayne/code/viberun/.github/workflows/release.yml`
- `/Users/shayne/code/viberun/tools/packaging/build-npm.sh`
- `/Users/shayne/code/viberun/packaging/npm/package.json`
- `/Users/shayne/code/viberun/packaging/npm/bin/viberun.js`

The `viberun` pattern is appropriate here because it already solves the same problem:

- package a Go CLI as an npm package
- publish dev builds from `main`
- publish prod builds from tags
- use npm trusted publishing from GitHub Actions
- keep version computation outside `package.json`

## Goals

- Publish `derpcat` to npm as a public package named `derpcat`.
- Mirror `viberun`’s dual-channel release model:
  - `main` pushes publish dev versions to npm under the `dev` dist-tag
  - `v*` tags publish production versions to npm
- Build a self-contained npm package with vendored native binaries.
- Support `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`.
- Add local `mise` tasks so packaging and manual publishing can be exercised outside CI.
- Stamp binaries with version, commit, and build-date metadata.
- Create GitHub release assets in parallel with npm artifacts for traceability and debugging.
- Make the initial manual `0.0.1` publish straightforward before trusted publishing is configured.

## Non-Goals

- Windows packaging in the first pass.
- Homebrew, apt, Docker, or other distribution channels.
- Rewriting the CLI or transport implementation.
- Making `package.json` the source of truth for versions.
- Supporting ad hoc prerelease channels beyond `dev`.

## Chosen Approach

### Selected

Use a full `viberun`-style release skeleton:

- one release workflow at `.github/workflows/release.yml`
- version metadata computed inside the workflow
- native binaries built per target
- GitHub release assets for both dev and prod channels
- npm package assembled from `packaging/npm` plus vendored binaries
- local release tasks in `.mise.toml`

This keeps local manual publishing and CI publishing on the same packaging path.

### Rejected Alternative: npm-only publishing

This would be smaller, but it would discard the GitHub release artifacts that make debugging and manual validation easier. It also diverges from the pattern we are intentionally copying.

### Rejected Alternative: download binaries lazily from GitHub at runtime

This would shrink the npm tarball, but it adds network dependency and install-time failure modes. The reference pattern vendors binaries into the npm package instead.

## Package And Artifact Model

### npm Package Shape

The npm package should be assembled into `dist/npm` and contain:

- `package.json`
- `bin/derpcat.js`
- `vendor/<target-triple>/derpcat/<binary>`
- root `README.md`
- `LICENSE`

The Node entrypoint should:

- detect the host platform and architecture
- map that pair to one of the supported target triples
- locate the vendored native binary
- execute it with inherited stdio
- forward process exit codes and signals correctly

This is the same launcher role played by `viberun`’s `bin/viberun.js`.

### Native Vendor Layout

The vendor tree should use stable target-triple directories, for example:

- `vendor/x86_64-unknown-linux-musl/derpcat/derpcat`
- `vendor/aarch64-unknown-linux-musl/derpcat/derpcat`
- `vendor/x86_64-apple-darwin/derpcat/derpcat`
- `vendor/aarch64-apple-darwin/derpcat/derpcat`

The build pipeline should produce this layout first, then assemble the npm package from it.

### GitHub Release Assets

Each workflow run should also package native release tarballs and checksums for the same target set.

For tagged releases, these assets become a normal GitHub release.
For `main`, they become a force-updated prerelease tagged `dev`.

## Versioning Model

### Production

On tag pushes matching `v*`:

- workflow version = exact tag name, for example `v0.1.0`
- Go binary version metadata = `v0.1.0`
- npm package version = `0.1.0`

### Development

On pushes to `main`:

- workflow version = `0.0.0-dev.<UTC_TIMESTAMP>+<shortsha>`
- Go binary version metadata = that same dev version string
- npm publish target = dist-tag `dev`

This matches `viberun` and preserves a clean separation between dev and prod installs.

### Source Of Truth

`package.json` should keep a placeholder version such as `0.0.0`.
The actual package version should be injected during packaging by the release script or workflow.

This avoids version skew between:

- git tags
- Go ldflags
- npm package metadata

## Repository Changes

### Files To Add

- `/Users/shayne/code/derpcat/.github/workflows/release.yml`
- `/Users/shayne/code/derpcat/packaging/npm/package.json`
- `/Users/shayne/code/derpcat/packaging/npm/bin/derpcat.js`
- `/Users/shayne/code/derpcat/packaging/npm/README.md`
- `/Users/shayne/code/derpcat/tools/packaging/build-vendor.sh`
- `/Users/shayne/code/derpcat/tools/packaging/build-npm.sh`
- `/Users/shayne/code/derpcat/README.md`

### Files To Modify

- `/Users/shayne/code/derpcat/.mise.toml`
- `/Users/shayne/code/derpcat/cmd/derpcat/main.go`
- `/Users/shayne/code/derpcat/cmd/derpcat/root.go`
- `/Users/shayne/code/derpcat/cmd/derpcat/root_test.go`

## CLI Version Metadata

The release workflow should inject:

- `main.version`
- `main.commit`
- `main.buildDate`

The CLI must expose that information in a stable way so CI can verify that built artifacts contain the expected version before packaging and publishing.

The CLI should expose `derpcat --version`.
That keeps the release verification surface minimal and fits naturally with the existing root-flag parsing style.

## Local Build And Publish Tasks

`.mise.toml` should keep the existing build and smoke tasks and add release-oriented tasks, including:

- build vendored native binaries for all supported targets
- assemble `dist/npm`
- package GitHub release tarballs and checksums
- perform local npm publish dry-runs

These tasks should be composable so both local manual release steps and CI can call the same scripts.

## GitHub Actions Workflow

The release workflow should mirror `viberun` at a smaller scope.

### Triggers

- push to `main`
- push of tags matching `v*`

### Jobs

- `meta`: compute booleans and version strings
- `check`: run build, test, and basic validation with `mise`
- matrix build job for native `derpcat` binaries
- `release-prod`: publish tagged GitHub release assets
- `release-dev`: update the `dev` prerelease tag and assets
- `publish-packages-prod`: assemble npm package artifact
- `publish-packages-dev`: assemble npm package artifact for dev
- `publish-npm-prod`: publish npm package with OIDC trusted publishing
- `publish-npm-dev`: publish npm package with `--tag dev`

### Permissions And Environment

The npm publish jobs should use:

- `permissions.id-token: write`
- `actions/setup-node`
- npm registry URL `https://registry.npmjs.org`
- an `npm` GitHub environment tied to the trusted publisher configuration

## Initial Manual Bootstrap

Trusted publishing will not exist yet for the first publish.

The rollout should therefore support this sequence:

1. implement the release skeleton
2. make a working-copy release change for `0.0.1`
3. build and validate `dist/npm` locally
4. run a manual `npm publish ./dist/npm --access public`
5. push the repository changes
6. configure npm trusted publisher
7. later tag `v0.1.0` and let CI publish automatically

The implementation should make the manual step use the same packaged artifact layout as CI.

## Error Handling And Validation

The packaging and CI flow should fail fast on:

- missing vendor binaries
- unsupported target names
- missing version metadata
- non-executable vendored binaries
- mismatch between expected workflow version and CLI-reported version
- missing `README.md` or `LICENSE` in the npm package assembly step

## Testing Strategy

### Unit And CLI Coverage

- test version reporting
- test any binary path or asset name helpers introduced for packaging
- preserve existing Go test coverage for the product itself

### Packaging Validation

- local packaging tasks should verify that `dist/npm/package.json` gets the injected version
- verify the vendored binary files exist and are executable
- use `npm pack` or `npm publish --dry-run` against `dist/npm`

### Workflow Validation

The workflow should be validated locally as much as practical by reusing the same shell scripts that CI will call.

The release design intentionally minimizes bespoke GitHub-only logic so local validation can catch most mistakes before a push.

## Success Criteria

This design is successful when:

- `derpcat` can be packaged locally into a valid npm package with vendored binaries
- the first `0.0.1` package can be published manually from `dist/npm`
- pushes to `main` are ready to publish dev builds once trusted publishing is configured
- tags like `v0.1.0` are ready to publish prod builds once trusted publishing is configured
- the release structure closely matches `viberun`, making it easy to maintain both repos consistently
