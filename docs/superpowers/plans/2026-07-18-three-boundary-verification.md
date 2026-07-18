# Three-Boundary Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make iteration compile-only and fast, enforce formatting and lightweight hygiene at commit time, run the exhaustive local gate once before push, and block versioned publication on an exhaustive CI gate.

**Architecture:** Split the current overloaded fast task into a build-only `check:fast`, a commit-only `check:fast:hooks`, and a CI composite `check:ci-fast`. Keep the four parallel Checks jobs, restore direct main-push dev builds, and make the production-only Release `check` job run `mise run check` before publishing.

**Tech Stack:** Go 1.26 tests, mise, pre-commit, GitHub Actions YAML, actionlint, GitButler.

## Global Constraints

- During dirty iteration, agents run focused tests plus build-only `mise run check:fast`; it must not invoke formatting or commit hooks.
- The installed pre-commit hook runs `mise run check:fast:hooks`, formats changed Go files, and blocks a commit when formatting changes tracked content.
- GitHub Checks uses `mise run check:ci-fast` so commit hygiene and compilation remain enforced in CI.
- Run `mise run check` once after final history cleanup and immediately before an authorized push or direct landing to `main`.
- If tracked content changes after the exhaustive run, rerun `mise run check` before publication.
- Do not add a pre-push hook.
- Preserve all existing license, formatting, tidy, private-scan, vet, staticcheck, govulncheck, coverage, CRAP, golangci-lint, hotspots, depaware, dependency-policy, build, and topology gates.
- Direct main-push dev artifacts do not wait for Checks.
- Tag and prepared version releases run `mise run check`; production publishing remains unreachable unless it succeeds.
- Do not run the exhaustive local gate during Tasks 1-4.
- Do not push, land main, create a tag, or dispatch a release without explicit user authorization.

---

## File Map

- `.mise.toml`: build-only iteration task, commit hook task, CI composite, and exhaustive task.
- `.github/workflows/checks.yml`: calls the CI composite while retaining four parallel jobs.
- `.github/workflows/release.yml`: direct dev trigger and production-only exhaustive release gate.
- `tools/hooks/pre-commit`: unchanged; commit-time entrypoint remains `check:fast:hooks`.
- `.pre-commit-config.yaml`: unchanged; gofmt and deterministic hygiene remain in the commit stage.
- `scripts/ci_pipeline_test.go`: structural contracts for all three local boundaries and both workflow graphs.
- `scripts/release_workflow_test.go`: existing version-release artifact dependency contract.
- `AGENTS.md`: authoritative agent policy.
- `README.md`: contributor-facing policy.

### Task 1: Separate iteration, commit, and CI fast lanes

**Files:**
- Modify: `.mise.toml`
- Modify: `.github/workflows/checks.yml`
- Modify: `scripts/ci_pipeline_test.go`

**Interfaces:**
- Produces: `check:fast` for build-only dirty iteration, `check:fast:hooks` for commit hygiene, and `check:ci-fast` for clean CI hygiene plus compilation.
- Preserves: `tools/hooks/pre-commit` invoking `check:fast:hooks`; `check` invoking the complete hook set once.

- [ ] **Step 1: Strengthen the mise lane contract**

In `TestMiseSeparatesFastAndFullCheckLanes`, replace the current fast-task assertions with:

```go
	fast := miseTaskBlock(t, body, `[tasks."check:fast"]`)
	requireCIPipelineContains(t, "check:fast", fast,
		`mise run build`,
	)
	requireCIPipelineExcludes(t, "check:fast", fast,
		`check:fast:hooks`,
		`check:full:hooks`,
		`pre-commit`,
		`--hook-stage`,
		`quality`,
		`test`,
	)

	ciFast := miseTaskBlock(t, body, `[tasks."check:ci-fast"]`)
	requireCIPipelineContains(t, "check:ci-fast", ciFast,
		`mise run check:fast:hooks`,
		`mise run check:fast`,
	)
	requireCIPipelineExcludes(t, "check:ci-fast", ciFast,
		`check:full:hooks`,
		`--hook-stage manual`,
		`quality`,
		`test`,
	)
```

Keep the existing `check:fast:hooks`, `check:full:hooks`, `check:hooks`, `check:static`, and `check` assertions.

- [ ] **Step 2: Scope the Checks fast job to the CI composite**

In `TestChecksWorkflowRunsIndependentLanes`, change only the `fast` map entry:

```go
	jobs := map[string]string{
		"fast":     "run: mise run check:ci-fast",
		"quality":  "run: mise run quality",
		"static":   "run: mise run check:static",
		"topology": "run: mise run toposim",
	}
```

Add this assertion after the per-job loop:

```go
	fastJob := workflowYAMLBlock(t, body, 2, "fast")
	requireCIPipelineExcludes(t, "fast job", fastJob,
		"run: mise run check:fast\n",
		"run: mise run check:fast:hooks",
	)
```

- [ ] **Step 3: Run RED tests**

Run:

```bash
mise exec -- go test ./scripts -run 'TestMiseSeparatesFastAndFullCheckLanes|TestChecksWorkflowRunsIndependentLanes|TestPreCommitWrapperUsesFastLane' -count=1
```

Expected: FAIL because `check:fast` still invokes commit hooks, `check:ci-fast` does not exist, and Checks calls the overloaded task.

- [ ] **Step 4: Implement the three mise boundaries**

Replace the current `check:fast` task and add `check:ci-fast`:

```toml
[tasks."check:fast"]
description = "Compile all products without running commit or exhaustive gates"
run = "mise run build"

[tasks."check:ci-fast"]
description = "Run commit hygiene and compile all products"
shell = "bash -c"
run = """
set -euo pipefail
mise run check:fast:hooks
mise run check:fast
"""
```

Do not change `check:fast:hooks`, `check:full:hooks`, `check:hooks`, `check:static`, or `check`.

- [ ] **Step 5: Point the Checks fast job at the CI composite**

In `.github/workflows/checks.yml`, make the fast job step:

```yaml
      - name: Run fast checks
        run: mise run check:ci-fast
```

Do not change the quality, static, topology, or concurrency blocks.

- [ ] **Step 6: Prove dirty iteration no longer invokes formatting**

Before committing the dirty Go test change, run:

```bash
mise run check:fast
```

Expected: `check:fast` passes while `scripts/ci_pipeline_test.go` remains an
intended dirty Go file. The output must contain the build task and no
pre-commit hook names; this step does not invoke gofmt.

- [ ] **Step 7: Run focused GREEN tests**

Run:

```bash
gofmt -w scripts/ci_pipeline_test.go
mise exec -- go test ./scripts -run 'TestMiseSeparatesFastAndFullCheckLanes|TestChecksWorkflowRunsIndependentLanes|TestPreCommitWrapperUsesFastLane' -count=1
actionlint .github/workflows/checks.yml
```

Expected: PASS.

- [ ] **Step 8: Commit and verify the clean CI composite**

Run `but diff` and confirm only `.mise.toml`, `.github/workflows/checks.yml`, and `scripts/ci_pipeline_test.go` are dirty. Then run:

```bash
but commit codex/ci-feedback-loop -m "ci: separate iteration and commit checks"
mise run check:ci-fast
```

Expected: the commit succeeds through the commit hook, the clean CI composite passes, and nothing is pushed.

### Task 2: Align agent and contributor instructions

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `AGENTS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 1's build-only `check:fast` and commit-only `check:fast:hooks`.
- Produces: precise instructions for iteration, commit, and push boundaries.

- [ ] **Step 1: Add a scoped Markdown-section helper**

Add beside the other test helpers:

```go
func markdownSection(t *testing.T, body, heading string) string {
	t.Helper()
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatalf("markdown missing heading %q", heading)
	}
	rest := body[start+len(heading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	return strings.Join(strings.Fields(strings.ToLower(rest)), " ")
}
```

- [ ] **Step 2: Replace the brittle documentation contract**

Replace `TestDeveloperDocsMakeFullCheckAPushBoundary` with:

```go
func TestDeveloperDocsExplainIterationCommitAndPushBoundaries(t *testing.T) {
	t.Parallel()
	readme := readCIPipelineFile(t, "README.md")
	agents := readCIPipelineFile(t, "AGENTS.md")

	sections := map[string]string{
		"README development guidance": markdownSection(t, readme, "## Development"),
		"AGENTS version-control guidance": markdownSection(t, agents, "## Version Control"),
	}
	for name, section := range sections {
		requireExactCommand(t, name, section, "mise run check:fast")
		requireExactCommand(t, name, section, "mise run check")
		requireCIPipelineContains(t, name, section,
			"focused tests",
			"build-only",
			"commit hook",
			"format",
			"immediately before",
			"push",
		)
	}
	if strings.Contains(agents, "Pre-commit hooks are intentionally expensive") {
		t.Fatal("AGENTS still describes checkpoint hooks as intentionally expensive")
	}
}
```

- [ ] **Step 3: Run the docs RED test**

Run:

```bash
mise exec -- go test ./scripts -run TestDeveloperDocsExplainIterationCommitAndPushBoundaries -count=1
```

Expected: FAIL because the current docs describe `check:fast` as running hygiene and do not assign formatting exclusively to the commit hook.

- [ ] **Step 4: Update the AGENTS policy**

Use this exact paragraph in `AGENTS.md`:

```markdown
During iteration, run focused tests for the code you change, followed by the
build-only `mise run check:fast`. It does not run formatting or commit hooks.
When creating a checkpoint commit, let the installed commit hook format changed
Go files and run deterministic hygiene; retry the commit if formatting changed
tracked content. Do not run the exhaustive `mise run check` gate as part of the
normal coding loop. Immediately before any push or direct landing to `main`, run
`mise run check` once against the final commit stack. If tracked content changes
afterward, run the exhaustive gate again. Report failures with the fix or
remaining blocker.
```

- [ ] **Step 5: Update README development guidance**

Use this exact prose after the Development command block:

````markdown
Run focused tests and the build-only `mise run check:fast` during iteration. It
compiles every product without running formatting or commit hooks. When making
a checkpoint commit, let the installed commit hook format changed Go files and
run deterministic hygiene; retry the commit if formatting changed tracked
content. Do not run the exhaustive gate as part of the normal coding loop.
Immediately before a push or landing, run it once:

```bash
mise run check
```
````

- [ ] **Step 6: Run focused verification while the Go test file is dirty**

Run:

```bash
gofmt -w scripts/ci_pipeline_test.go
mise exec -- go test ./scripts -run 'TestDeveloperDocsExplainIterationCommitAndPushBoundaries|TestPreCommitWrapperUsesFastLane|TestPreCommitSeparatesFastAndManualHooks' -count=1
mise run check:fast
```

Expected: PASS. `check:fast` must pass with the intended dirty Go test and must not print pre-commit hooks.

- [ ] **Step 7: Commit**

Run `but diff` and confirm only `AGENTS.md`, `README.md`, and `scripts/ci_pipeline_test.go` are dirty. Then run:

```bash
but commit codex/ci-feedback-loop -m "docs: define iteration commit and push checks"
```

Expected: commit-time formatting and hygiene pass; nothing is pushed.

### Task 3: Restore direct dev builds and gate version publication

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `.github/workflows/release.yml`
- Test: `scripts/release_workflow_test.go`

**Interfaces:**
- Produces: direct main-push dev builds with no exhaustive dependency; tag and prepared production releases blocked by `mise run check`.
- Removes: abandoned `workflow_run`, `source_sha`, and exact-SHA propagation machinery.

- [ ] **Step 1: Replace the abandoned dev-gating test**

Delete `workflowYAMLListBlocks` and `requireCheckoutStepsUseSourceSHA`. Replace `TestDevReleaseWaitsForSuccessfulFirstPartyMainChecks` with:

```go
func TestDevReleaseRunsDirectlyFromMainPush(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "release.yml")

	trigger := workflowYAMLBlock(t, body, 0, "on")
	requireCIPipelineExcludes(t, "release trigger", trigger, "workflow_run:")
	push := workflowYAMLBlock(t, trigger, 2, "push")
	requireCIPipelineContains(t, "release push trigger", push,
		"branches:\n      - \"main\"",
		"tags:\n      - \"v*\"",
	)

	meta := workflowYAMLBlock(t, body, 2, "meta")
	requireCIPipelineContains(t, "release meta job", meta,
		`if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then is_tag=true; fi`,
		`if [ "${GITHUB_REF_NAME:-}" = "main" ]; then is_main=true; fi`,
		`short_sha="${GITHUB_SHA::7}"`,
	)
	requireCIPipelineExcludes(t, "release meta job", meta,
		"workflow_run", "source_sha", "WORKFLOW_RUN_HEAD_SHA",
	)

	releaseDev := workflowYAMLBlock(t, body, 2, "release-dev")
	requireCIPipelineContains(t, "release-dev", releaseDev,
		"needs: [meta, build-binaries, build-web, publish-npm-dev]",
		`git tag -f dev "$GITHUB_SHA"`,
	)
	requireCIPipelineExcludes(t, "release-dev", releaseDev,
		"needs: [meta, check", "SOURCE_SHA:", "source_sha",
	)
	if strings.Contains(body, "needs.meta.outputs.source_sha") {
		t.Fatal("release workflow retains abandoned workflow_run source SHA plumbing")
	}
}
```

- [ ] **Step 2: Require an exhaustive version-only check**

In `TestReleaseKeepsProductionCheckAndRemovesDevDuplicate`, require:

```go
	check := workflowYAMLBlock(t, body, 2, "check")
	requireCIPipelineContains(t, "check", check,
		"needs: [meta]",
		"if: needs.meta.outputs.is_tag == 'true'",
		"run: mise run check",
	)
	requireCIPipelineExcludes(t, "check", check,
		"run: mise run build", "run: mise run test", "run: mise run vet",
	)
```

Retain the existing production `needs` map with `check` in `release-prod`, `publish-packages-prod`, and `publish-npm-prod`, and retain the dev `needs` map without `check`.

- [ ] **Step 3: Run RED tests**

Run:

```bash
mise exec -- go test ./scripts -run 'TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestReleaseWorkflowPublishesSwiftPMFramework' -count=1
```

Expected: FAIL on the current `workflow_run` trigger, `source_sha` plumbing, and partial Build/Test/Vet check.

- [ ] **Step 4: Restore the direct Release trigger**

Use:

```yaml
on:
  workflow_dispatch:
    inputs:
      version:
        description: "Prepared release tag to publish, for example v0.15.6"
        required: true
        type: string
  push:
    branches:
      - "main"
    tags:
      - "v*"
    paths-ignore:
      - "README.md"
```

Remove the `meta` job-level `if`, `source_sha` output, and `WORKFLOW_RUN_HEAD_SHA`. Restore:

```bash
is_tag=false
is_main=false
input_version="${INPUT_VERSION:-}"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then is_tag=true; fi
if [ "${GITHUB_REF_NAME:-}" = "main" ]; then is_main=true; fi
```

Use `short_sha="${GITHUB_SHA::7}"`. Keep prepared-version validation unchanged.

- [ ] **Step 5: Make the production check exhaustive**

Use:

```yaml
  check:
    name: Exhaustive version checks
    runs-on: ubuntu-latest
    needs: [meta]
    if: needs.meta.outputs.is_tag == 'true'
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v4
        with:
          install: true
          cache: true
      - name: Run exhaustive checks
        run: mise run check
```

- [ ] **Step 6: Remove source-SHA plumbing**

Remove checkout `ref: ${{ needs.meta.outputs.source_sha }}` from `check`,
`build-binaries`, `build-web`, `build-swiftpm-framework`, `release-prod`,
`release-dev`, `publish-packages-prod`, `publish-packages-dev`,
`publish-npm-prod`, and `publish-npm-dev`. Preserve `fetch-depth: 0` in
`release-prod` and `release-dev`. Use:

```yaml
          COMMIT: ${{ github.sha }}
```

and:

```bash
git tag -f dev "$GITHUB_SHA"
```

Remove the dev-tag `SOURCE_SHA` environment block.

- [ ] **Step 7: Run focused verification**

Run:

```bash
if rg -n 'workflow_run|source_sha|WORKFLOW_RUN_HEAD_SHA|SOURCE_SHA' .github/workflows/release.yml; then exit 1; fi
gofmt -w scripts/ci_pipeline_test.go
mise exec -- go test ./scripts -run 'TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestReleaseWorkflowPublishesSwiftPMFramework' -count=1
pre-commit validate-config
actionlint .github/workflows/checks.yml .github/workflows/release.yml
mise run check:fast
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
```

Expected: PASS while the Go test remains dirty; no exhaustive local check runs.

- [ ] **Step 8: Commit**

Run `but diff` and confirm only `.github/workflows/release.yml` and `scripts/ci_pipeline_test.go` are dirty. Then run:

```bash
but commit codex/ci-feedback-loop -m "release: gate version publishing on exhaustive checks"
```

Expected: commit succeeds; nothing is pushed.

### Task 4: Review and stop at the publication boundary

**Files:**
- Inspect: all files changed from `origin/main` through the session head.

**Interfaces:**
- Consumes: Tasks 1-3 and the earlier parallel/full-lane implementation.
- Produces: reviewed unpublished content ready for one exhaustive pre-push run.

- [ ] **Step 1: Run focused contracts and fast iteration only**

Run:

```bash
mise exec -- go test ./scripts -run 'TestMiseSeparatesFastAndFullCheckLanes|TestPreCommitWrapperUsesFastLane|TestPreCommitSeparatesFastAndManualHooks|TestChecksWorkflowRunsIndependentLanes|TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestDeveloperDocsExplainIterationCommitAndPushBoundaries' -count=1
mise run check:fast
mise run check:ci-fast
git diff --check "$(git merge-base origin/main HEAD)"..HEAD
```

Expected: PASS. Do not run `mise run check`.

- [ ] **Step 2: Request independent full-branch review**

Give the reviewer the approved design, this plan, and the complete base-to-head diff. Require findings categorized Critical, Important, or Minor. The reviewer must confirm the iteration task is build-only, commit formatting remains enforced, CI retains every fast gate, production publication depends on `check`, and dev does not.

Expected: approval with no unresolved findings. Fix findings with focused tests, `check:fast`, and clean-commit `check:ci-fast`; do not run the exhaustive gate.

- [ ] **Step 3: Stop for authorization**

Report focused/fast evidence, review result, stack head, and unchanged remote `main`. Ask for explicit authorization to land and push. Do not run `mise run check` or publish before authorization.

### Task 5: Run one exhaustive gate, land, and observe CI

**Authorization:** Execute only after explicit authorization to land and push.

**Files:**
- No source edits expected.

**Interfaces:**
- Consumes: approved Task 4 stack.
- Produces: one clean commit on local and remote main, plus live Checks and dev evidence.

- [ ] **Step 1: Synchronize and tidy history**

Run:

```bash
but pull --check
but status
but oplog snapshot -m "before final three-boundary CI cleanup"
```

If upstream advanced, run `but pull` and repeat Task 4 focused verification. Squash only this session's planning and implementation commits into:

```text
ci: separate iteration commit and release gates
```

- [ ] **Step 2: Run the exhaustive gate once**

Run:

```bash
mise run check
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
git diff --check "$(git merge-base origin/main HEAD)"..HEAD
```

Expected: PASS. Any later tracked change invalidates this result and requires rerunning `mise run check`.

- [ ] **Step 3: Publish directly to main**

Obtain the one session commit from GitButler and push it through the repository's authorized raw-git publication exception:

```bash
SESSION_COMMIT="$(but status --format json | jq -r '.stacks[].branches[] | select(.name == "codex/ci-feedback-loop") | .commits[0].commitId')"
test "$SESSION_COMMIT" != "null"
git push origin "$SESSION_COMMIT":main
```

Do not force-push. Treat non-fast-forward rejection as a race: pull with GitButler, repeat focused verification and `mise run check`, then retry only when clean.

- [ ] **Step 4: Verify refs and clean the integrated session**

Run:

```bash
but pull
but clean --dry-run
but clean
git rev-parse main
git rev-parse origin/main
git ls-remote origin refs/heads/main
```

Expected: all main refs equal the landed commit. Clean only this session's integrated branches.

- [ ] **Step 5: Observe live CI**

Verify the landed main push starts direct dev Release and four-job Checks independently. Require all Checks jobs to pass within five minutes, rerun Checks once, and require a second green attempt. Record both durations and the slowest job.

- [ ] **Step 6: Defer destructive production proof**

Do not create a version tag. Record the tested production dependency graph and verify live blocking on the next real Prepare Release run.
