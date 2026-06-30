# Repository Guidelines

If `AGENTS.local.md` exists, read it and merge its instructions with this file.

## Project Structure & Module Organization

`cmd/derphole/` contains the CLI entrypoint and subcommand wiring. Core transport and session logic lives under `pkg/` (`pkg/session`, `pkg/wg`, `pkg/traversal`, `pkg/derpbind`, `pkg/derphole`, etc.). Packaging assets live in `packaging/npm/` and `tools/packaging/`. Verification scripts are in `scripts/`. Public documentation lives in `docs/derp/` and `docs/releases/`.

`dist/` is generated output for local builds, release packaging, and npm assembly. Treat it as ephemeral.

## Version Control

Use GitButler (`but`) for normal agent version-control write operations, including branching, committing, branch pushes, and history edits.

Assume multiple agents may be working in this repository. Do not move, amend, squash, discard, commit, push, or otherwise modify another agent's work unless the user asks.

Use a dedicated GitButler branch for each agent session unless the user asks for a different branch structure. Commit only changes that belong to that session.

Agents may create local checkpoint commits after a coherent unit of work is complete. Avoid micro-commits; prefer commits that match the current objective and would make sense when read later.

Pre-commit hooks are intentionally expensive and should run normally. Report any pre-commit failure with the fix or remaining blocker.

Treat checkpoint commits as local savepoints, not final history. Before finishing to `main`, use GitButler to tidy, squash, reword, or amend unpublished session commits into a clean final shape.

At safe boundaries, such as before starting substantial work, before a checkpoint commit, or before finishing to `main`, run `but pull --check`. If it is clean and affects only this session's branch, `but pull` is allowed. If it conflicts or touches another active branch, stop and ask.

If follow-up fixes clearly belong to an unpublished local commit, amend or absorb them into that commit instead of creating tiny fixup commits.

Before large history edits or branch restructuring, create a GitButler recovery point with `but oplog snapshot -m "before history cleanup"`.

If another active branch or session touches the same files, generated output, or runtime state, call out the overlap before committing or finishing.

Do not push or open pull requests unless the user asks. Pull requests are not the default workflow.

When the user asks to finish or integrate a session, the default outcome is that the session's work lands on both local `main` and `origin/main` without a pull request, unless the user asks for a different integration path.

This repo normally targets `origin/main` in GitButler. Do not use `but merge` as the default finish command here: it is for `gb-local` targets and creates a merge commit, which is not the desired no-PR squash-to-main workflow.

For a finish-to-main request, first use `but` to make the session branch a single commit when needed, then verify the commit is based on current `origin/main` and contains only this session's work. The final direct update of local `main` and `origin/main` is the only allowed raw `git` write exception for branch/commit publication, and it still requires explicit user authorization.

Fast path for direct finish-to-main: if the session branch is already a single commit based on current `origin/main`, do not create a detached worktree or cherry-pick. After tests and `but pull --check`, publish with `git push origin <session-commit>:main`. Treat a non-fast-forward rejection as the race check; run `but pull`, retest if the base changed, and retry only when clean. `but push <branch>` only publishes the GitButler branch; it does not land work on `main`.

After a session lands on `main`, run `but pull` so GitButler can mark the branch integrated, then preview cleanup with `but clean --dry-run` before running `but clean`. Delete non-empty branches or raw local `codex/*` refs only when they belong to this session and are confirmed merged; never clean up another agent's branch unless the user asks.

After the direct push, verify `main`, `origin/main`, and `git ls-remote origin refs/heads/main` all point at the landed commit. If local `main` is stale after `but pull`, update only local `main` to `origin/main` as part of the same explicit finish-to-main publication exception.

For explicit patch/minor/major release requests, finish and verify `origin/main` first, then use the Prepare Release workflow. Do not hand-edit `Package.swift` and do not hand-push a `v*` tag for the normal release path. The workflow computes the SwiftPM framework checksum on the pinned macOS runner, commits the `Package.swift` binary target update to `main`, creates the annotated release tag on that commit, and dispatches the Release workflow for the prepared tag.

Release version bumps are tag-driven in this repo. The npm package templates intentionally keep `"version": "0.0.0"` and `tools/packaging/build-npm.sh` stamps package versions from `VERSION`, so do not edit package JSON templates just to bump semver. For a patch release, compute the next `vX.Y.Z`, then dry-run packaging with `VERSION=vX.Y.Z COMMIT=$(git rev-parse origin/main) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:npm-dry-run`. Start the release with `gh workflow run prepare-release.yml --ref main -f version=vX.Y.Z`, then watch the dispatched Release workflow to completion. Raw `git tag` and `git push origin <tag>` are reserved for explicit recovery from a failed unpublished release tag because `but` does not manage tags.

After Prepare Release pushes the release tag and dispatches the Release workflow, watch the GitHub Release workflow to completion, then verify the published state: `git ls-remote origin refs/tags/vX.Y.Z refs/tags/vX.Y.Z^{}` must peel to the prepared commit, `gh release view vX.Y.Z` must show a non-draft release, and `npm view derphole@X.Y.Z version`, `npm view derptun@X.Y.Z version`, and `npm view derpssh@X.Y.Z version` must all return `X.Y.Z`.

If a direct squash-to-main publication is used while the GitButler session branch is still applied, `but pull` may try to rebase duplicate checkpoint commits onto the squash commit and report conflicts even though raw `git status` is clean. In that case, verify `main` and `origin/main` contain the squash commit, then delete only this session's GitButler branch instead of resolving duplicate conflicts. If the current `but` build prompts to delete "unpushed" duplicate commits and does not accept `--force`, pipe a single `y` into `but branch delete <branch>`.

Final status must distinguish local checkpoint commits from branch pushes and from work that has landed on `origin/main`. If the user asked to push everything, finish only after verifying `origin/main` contains the session commit.

Keep commit messages and any explicitly requested pull request descriptions succinct: explain what changed, why it changed, and any important decision.

## Build, Test, and Development Commands

Use `mise` for toolchain consistency.

- Run `mise trust` only when setting up a workspace for the first time or when `mise` reports the workspace is untrusted.
- `mise run build` builds `dist/derphole`
- `mise run test` runs `go test ./...`
- `mise run vet` runs `go vet ./...`
- `mise run install-githooks` installs the local `pre-commit` and `prepare-commit-msg` hooks
- `mise run check:hooks` runs the repository's `pre-commit` checks across all files
- `mise run check` runs the same hook, build, and test sequence as the dedicated checks workflow
- `mise run smoke-local` runs the local end-to-end smoke test
- `mise run release:build-all` builds vendored binaries, release tarballs, and `dist/npm-derphole`
- `mise run release:npm-dry-run` validates the npm package without publishing

For remote verification, set `REMOTE_HOST` and use `mise run smoke-remote`, `mise run smoke-remote-share`, or `mise run promotion-1g`.

## Coding Style & Naming Conventions

Write idiomatic Go and keep files ASCII unless the file already requires otherwise. Use `gofmt` formatting conventions: tabs for indentation, mixedCaps for exported names, and short, package-scoped helpers where possible. Keep package boundaries clear: CLI code in `cmd/`, reusable logic in `pkg/`, packaging logic in shell scripts under `tools/packaging/`.

When editing `README.md`, use the `Caveman` skill for tight, direct prose. Keep the writing compressed and technical, but still use proper grammar and readable full sentences. Do not write the README in broken-English or fragment style.

Do not hand-edit generated `dist/` contents. Update the source script or template instead.

Do not commit machine-specific or personal details unless the user explicitly allows it. This includes absolute local paths, local usernames, hostnames, device names, private filesystem layouts, and environment-variable defaults that point at one developer's machine. Prefer repo-relative paths, generated runtime values, or documented user-provided configuration.

## Testing Guidelines

Tests live alongside code in `*_test.go` files. Prefer focused package tests first, then full-suite verification.

- Package-level example: `go test ./pkg/token -run TestEncode`
- Full suite: `mise run test`
- Network/regression coverage: `mise run smoke-local` or `./scripts/smoke-local.sh`

For live transport verification, prefer `REMOTE_HOST=my-server.example.com mise run smoke-remote`, `REMOTE_HOST=my-server.example.com mise run smoke-remote-share`, and `REMOTE_HOST=my-server.example.com mise run promotion-1g` when you need to inspect relay-first to direct-upgrade traces.

For throughput benchmarks and safe harness rules, read `docs/benchmarks.md` before writing one-off loops or custom benchmark binaries.

When changing release or packaging behavior, also run `mise run release:npm-dry-run`.

## Commit & Pull Request Guidelines

Recent history uses scoped, imperative subjects such as `release: gate npm publishing on verification`, `docs: add npm bootstrap publish runbook`, and `ci: update workflow actions`. Follow that pattern: `<scope>: <change>`.

PRs should include:

- a short summary of user-visible impact
- linked issue or rationale when applicable
- exact verification commands run
- release or packaging implications if workflows, npm assets, or `docs/releases/` changed
