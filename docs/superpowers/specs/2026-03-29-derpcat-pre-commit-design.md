# Derpcat Pre-Commit And CI Checks Design

## Summary

`derpcat` should adopt the same developer ergonomics pattern used in `~/code/viberun` for repository checks:

- local git hooks installed through `pre-commit`
- tool installation managed by `mise`
- CI enforcing the same checks on every push and pull request

The implementation should copy the structure from `viberun` while keeping the actual hook set specific to this repository.

## Goals

- Make common repository hygiene checks run automatically before commit.
- Ensure CI runs the same checks developers see locally.
- Keep the hook set small, deterministic, and relevant to a Go CLI repository.
- Reuse the `viberun` layout so future maintenance is familiar.

## Non-Goals

- Importing `viberun`-specific dependency boundary or license-header checks.
- Replacing the existing release workflow.
- Adding broad lint tooling beyond what the repository already needs.

## Reference Pattern

The implementation should mirror these `viberun` files structurally:

- `/Users/shayne/code/viberun/.pre-commit-config.yaml`
- `/Users/shayne/code/viberun/.mise.toml`
- `/Users/shayne/code/viberun/tools/hooks/gofmt-check`
- `/Users/shayne/code/viberun/tools/hooks/go-vet`
- `/Users/shayne/code/viberun/tools/hooks/go-mod-tidy-check`
- `/Users/shayne/code/viberun/tools/hooks/staticcheck`
- `/Users/shayne/code/viberun/tools/hooks/prepare-commit-msg`

## Desired Repository Changes

### 1. Mise Tooling

Update `/Users/shayne/code/derpcat/.mise.toml` to add:

- `pre-commit = "latest"`
- `staticcheck = "latest"`

Add tasks for:

- `install-githooks`
- `check`
- `check:hooks`

`install-githooks` should unset any local `core.hooksPath` override and install both `pre-commit` and `prepare-commit-msg` hooks.

`check:hooks` should run `pre-commit run --all-files`.

`check` should be a single entrypoint for CI and local verification, running:

- `mise run check:hooks`
- `mise run build`
- `mise run test`

## 2. Pre-Commit Configuration

Add `/Users/shayne/code/derpcat/.pre-commit-config.yaml` using local hooks only.

Hook set:

- `derpcat-gofmt-check`
- `derpcat-go-vet`
- `derpcat-go-mod-tidy`
- `derpcat-staticcheck`
- `derpcat-prepare-commit-msg`

The prepare-commit hook should run only for the `prepare-commit-msg` stage.

## 3. Hook Scripts

Add `/Users/shayne/code/derpcat/tools/hooks/` with executable scripts adapted from `viberun`.

Required scripts:

- `gofmt-check`
- `go-vet`
- `go-mod-tidy-check`
- `staticcheck`
- `prepare-commit-msg`

Behavior:

- `gofmt-check` should inspect staged or tracked `.go` files and fail if `gofmt -w` changes them.
- `go-vet` should run `go vet ./...`.
- `go-mod-tidy-check` should run `go mod tidy` and fail if `go.mod` or `go.sum` changes.
- `staticcheck` should use the `mise`-managed toolchain.
- `prepare-commit-msg` should match the `viberun` pattern: run `uvx cmtr@latest prepare-commit-msg "$@"` when `uvx` exists, otherwise exit successfully.

## 4. CI Workflow

Add a new workflow at `/Users/shayne/code/derpcat/.github/workflows/checks.yml`.

Trigger conditions:

- `push`
- `pull_request`

The workflow should:

- check out the repository
- install tools via `jdx/mise-action`
- run `mise run check`

The existing release workflow should remain focused on release packaging and publication.

## 5. Verification

Before completion, verify:

- `mise run install-githooks`
- `mise run check:hooks`
- `mise run check`

The implementation should also inspect the new workflow for syntax correctness and confirm the worktree stays clean except for intended changes.

## Acceptance Criteria

- A contributor can run `mise run install-githooks` and get working `pre-commit` and `prepare-commit-msg` hooks.
- `pre-commit run --all-files` passes through `mise run check:hooks`.
- CI runs the same hook suite plus build and test through `mise run check`.
- No `viberun`-specific checks are imported if they do not apply to `derpcat`.
