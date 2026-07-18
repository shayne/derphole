# Agent Push and Version Release Gating Implementation Plan

> **Superseded:** Do not execute this plan. Use `docs/superpowers/plans/2026-07-18-three-boundary-verification.md`, which separates dirty iteration from commit-time formatting.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep agent iteration and checkpoint commits fast, run the exhaustive local gate once immediately before publication, allow provisional dev builds without waiting for Checks, and block versioned publication on an exhaustive release-local CI gate.

**Architecture:** Preserve the already-implemented fast/full `mise` lanes and four parallel Checks jobs. Tighten the human and agent contract around the push boundary, restore the Release workflow's direct `main` trigger for dev builds, and make the production-only `check` job run `mise run check` before any versioned publication job can proceed. Remove the now-unneeded `workflow_run` trust and `source_sha` machinery.

**Tech Stack:** Go 1.26 tests, GitHub Actions YAML, mise, pre-commit, actionlint, GitButler.

## Global Constraints

- During iteration and checkpoint commits, run focused tests plus `mise run check:fast`; do not run the exhaustive gate as part of the normal coding loop.
- Run `mise run check` exactly once after final history cleanup and immediately before an authorized push or direct landing to `main`.
- If tracked content changes after the exhaustive run, the result is stale and `mise run check` must run again before publication.
- Keep the installed `pre-commit` hook fast and instruction-driven; do not add a `pre-push` hook.
- Preserve all existing license, formatting, tidy, private-scan, vet, staticcheck, govulncheck, coverage, CRAP, golangci-lint, hotspots, depaware, dependency-policy, build, and topology gates.
- Keep the four `Checks` jobs independent and preserve cancellation of superseded runs.
- Direct `main` pushes may publish provisional dev artifacts without waiting for `Checks`.
- Tag and prepared version releases must run `mise run check`; production publishing remains unreachable unless it succeeds.
- Do not create a throwaway production tag to test the gate. Live proof occurs on the next actual version release.
- Use GitButler for normal version-control writes. Do not push, land `main`, create a tag, or dispatch a release without explicit user authorization.

---

## File Map

- `AGENTS.md`: authoritative agent-development and pre-push verification policy.
- `README.md`: concise contributor-facing fast-iteration and exhaustive-push guidance.
- `scripts/ci_pipeline_test.go`: repository contracts for documentation, hook cost boundaries, direct dev triggering, and production gating.
- `.github/workflows/release.yml`: direct dev trigger and production-only exhaustive gate.
- `.github/workflows/checks.yml`: unchanged; four parallel jobs remain the ordinary push/PR CI path.
- `.mise.toml`, `.pre-commit-config.yaml`, `tools/hooks/pre-commit`: unchanged; the existing fast/full split already matches the corrected design.

### Task 1: Make the agent-development boundary explicit

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `AGENTS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: existing `requireExactCommand` and `TestPreCommitWrapperUsesFastLane` contracts in `scripts/ci_pipeline_test.go`.
- Produces: an instruction-driven policy where focused tests and `check:fast` are iterative, while `check` runs once immediately before push or landing.

- [ ] **Step 1: Strengthen the documentation contract test**

Replace `TestDeveloperDocsExplainFastAndFullLanes` with:

```go
func TestDeveloperDocsMakeFullCheckAPushBoundary(t *testing.T) {
	t.Parallel()
	readme := readCIPipelineFile(t, "README.md")
	agents := readCIPipelineFile(t, "AGENTS.md")

	for name, body := range map[string]string{
		"README development guidance": readme,
		"AGENTS guidance":             agents,
	} {
		requireExactCommand(t, name, body, "mise run check:fast")
		requireExactCommand(t, name, body, "mise run check")
		requireCIPipelineContains(t, name, body,
			"focused tests",
			"checkpoint commits",
			"immediately before",
			"push",
		)
	}
	if strings.Contains(agents, "Pre-commit hooks are intentionally expensive") {
		t.Fatal("AGENTS still describes checkpoint hooks as intentionally expensive")
	}
}
```

- [ ] **Step 2: Run the focused test to prove the current wording is incomplete**

Run:

```bash
mise exec -- go test ./scripts -run TestDeveloperDocsMakeFullCheckAPushBoundary -count=1
```

Expected: FAIL because the current README and AGENTS guidance does not contain both `checkpoint commits` and an `immediately before ... push` boundary.

- [ ] **Step 3: Update the agent contract**

Replace the current checkpoint-check paragraph in `AGENTS.md` with:

```markdown
During iteration and checkpoint commits, run focused tests for the code you
change, followed by `mise run check:fast`. Do not run the exhaustive
`mise run check` gate as part of the normal coding loop. Immediately before any
push or direct landing to `main`, run `mise run check` once against the final
commit stack. If tracked content changes afterward, run the exhaustive gate
again. Report any failure with the fix or remaining blocker.
```

This text supplements, rather than removes, the later finish-to-main rule that requires testing before publication.

- [ ] **Step 4: Update the contributor guidance**

Replace the prose after the Development command block in `README.md` with:

````markdown
Run focused tests and `mise run check:fast` during iteration and checkpoint
commits. The fast lane checks repository hygiene and compiles every product
without running the full suite. Do not run the exhaustive gate as part of the
normal coding loop. Immediately before a push or landing, run it once:

```bash
mise run check
```
````

- [ ] **Step 5: Run the focused documentation and hook contracts**

Run:

```bash
mise exec -- go test ./scripts -run 'TestDeveloperDocsMakeFullCheckAPushBoundary|TestPreCommitWrapperUsesFastLane|TestPreCommitSeparatesFastAndManualHooks' -count=1
mise run check:fast
```

Expected: PASS. The fast command should complete without printing the coverage-backed quality suite.

- [ ] **Step 6: Commit the coherent documentation boundary**

Run `but diff` and confirm the only uncommitted files are `AGENTS.md`, `README.md`, and `scripts/ci_pipeline_test.go`. If any unrelated file appears, stop. Otherwise run:

```bash
but commit codex/ci-feedback-loop -m "docs: make exhaustive checks a push boundary"
```

Expected: the three intended files are committed on `codex/ci-feedback-loop`; nothing is pushed.

### Task 2: Restore direct dev builds and gate version publication

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `.github/workflows/release.yml`
- Test: `scripts/release_workflow_test.go`

**Interfaces:**
- Consumes: existing `workflowYAMLBlock`, `requireCIPipelineContains`, and `requireCIPipelineExcludes` helpers.
- Produces: `main` push dev builds with no exhaustive dependency; tag or prepared-release production jobs blocked by the `check` job running `mise run check`.

- [ ] **Step 1: Replace the abandoned dev-gating contract**

Delete `workflowYAMLListBlocks` and `requireCheckoutStepsUseSourceSHA`; they exist only for the abandoned `workflow_run` design. Replace `TestDevReleaseWaitsForSuccessfulFirstPartyMainChecks` with:

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
		"workflow_run",
		"source_sha",
		"WORKFLOW_RUN_HEAD_SHA",
	)

	releaseDev := workflowYAMLBlock(t, body, 2, "release-dev")
	requireCIPipelineContains(t, "release-dev", releaseDev,
		"needs: [meta, build-binaries, build-web, publish-npm-dev]",
		`git tag -f dev "$GITHUB_SHA"`,
	)
	requireCIPipelineExcludes(t, "release-dev", releaseDev,
		"needs: [meta, check",
		"SOURCE_SHA:",
		"source_sha",
	)

	if strings.Contains(body, "needs.meta.outputs.source_sha") {
		t.Fatal("release workflow retains abandoned workflow_run source SHA plumbing")
	}
}
```

- [ ] **Step 2: Strengthen the version-release gate contract**

In `TestReleaseKeepsProductionCheckAndRemovesDevDuplicate`, extend the `check` assertions to require the exhaustive command and reject the old partial command trio:

```go
	check := workflowYAMLBlock(t, body, 2, "check")
	requireCIPipelineContains(t, "check", check,
		"needs: [meta]",
		"if: needs.meta.outputs.is_tag == 'true'",
		"run: mise run check",
	)
	requireCIPipelineExcludes(t, "check", check,
		"run: mise run build",
		"run: mise run test",
		"run: mise run vet",
	)
```

Keep these exact production dependencies:

```go
	productionNeeds := map[string]string{
		"release-prod":          "needs: [meta, check, build-binaries, build-web, build-swiftpm-framework, publish-npm-prod]",
		"publish-packages-prod": "needs: [meta, check, build-binaries]",
		"publish-npm-prod":      "needs: [meta, check, publish-packages-prod, build-swiftpm-framework]",
	}
```

Keep these exact dev dependencies, none of which include `check`:

```go
	devNeeds := map[string]string{
		"release-dev":          "needs: [meta, build-binaries, build-web, publish-npm-dev]",
		"publish-packages-dev": "needs: [meta, build-binaries]",
		"publish-npm-dev":      "needs: [meta, publish-packages-dev]",
	}
```

- [ ] **Step 3: Run the release contracts to prove they fail against the abandoned design**

Run:

```bash
mise exec -- go test ./scripts -run 'TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestReleaseWorkflowPublishesSwiftPMFramework' -count=1
```

Expected: FAIL because the workflow still uses `workflow_run`, lacks a direct `main` push trigger, retains `source_sha`, and runs separate build/test/vet steps instead of `mise run check`.

- [ ] **Step 4: Restore the direct push trigger and simple event metadata**

Make the Release trigger:

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

Remove the `meta` job-level `if`, remove the `source_sha` output, and replace the metadata shell prelude and short SHA assignment with:

```bash
is_tag=false
is_main=false
input_version="${INPUT_VERSION:-}"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then is_tag=true; fi
if [ "${GITHUB_REF_NAME:-}" = "main" ]; then is_main=true; fi
```

```bash
short_sha="${GITHUB_SHA::7}"
```

Keep the existing prepared-version validation unchanged. Remove `WORKFLOW_RUN_HEAD_SHA`, source-SHA validation, and `echo "source_sha=..."`.

- [ ] **Step 5: Make the production-only check exhaustive**

Replace the `check` job's Build, Test, and Vet steps with one step while preserving `needs: [meta]` and the production-only condition:

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

- [ ] **Step 6: Remove abandoned source-SHA plumbing**

For `check`, `build-binaries`, `build-web`, `build-swiftpm-framework`, `release-prod`, `release-dev`, `publish-packages-prod`, `publish-packages-dev`, `publish-npm-prod`, and `publish-npm-dev`, remove checkout `ref: ${{ needs.meta.outputs.source_sha }}`. Preserve `fetch-depth: 0` in `release-prod` and `release-dev`.

Use direct event SHA values in the two places that need them:

```yaml
          COMMIT: ${{ github.sha }}
```

```bash
git tag -f dev "$GITHUB_SHA"
```

Remove the `SOURCE_SHA` environment block from the dev-tag step.

- [ ] **Step 7: Prove the workflow no longer contains the abandoned path**

Run:

```bash
if rg -n 'workflow_run|source_sha|WORKFLOW_RUN_HEAD_SHA|SOURCE_SHA' .github/workflows/release.yml; then
  exit 1
fi
```

Expected: exit 0 with no matches.

- [ ] **Step 8: Run focused workflow verification**

Run:

```bash
gofmt -w scripts/ci_pipeline_test.go
mise exec -- go test ./scripts -run 'TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestReleaseWorkflowPublishesSwiftPMFramework' -count=1
pre-commit validate-config
actionlint .github/workflows/checks.yml .github/workflows/release.yml
mise run check:fast
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
```

Expected: every command passes. Do not run `mise run check` yet; no push is authorized at this task boundary.

- [ ] **Step 9: Commit the corrected release policy**

Run `but diff` and confirm the only uncommitted files are `.github/workflows/release.yml` and `scripts/ci_pipeline_test.go`. If any unrelated file appears, stop. Otherwise run:

```bash
but commit codex/ci-feedback-loop -m "release: gate version publishing on exhaustive checks"
```

Expected: the two intended files are committed; nothing is pushed or landed.

### Task 3: Review the corrected unpublished stack

**Files:**
- Inspect: `.github/workflows/checks.yml`
- Inspect: `.github/workflows/release.yml`
- Inspect: `.mise.toml`
- Inspect: `.pre-commit-config.yaml`
- Inspect: `tools/hooks/pre-commit`
- Inspect: `AGENTS.md`
- Inspect: `README.md`
- Inspect: `scripts/ci_pipeline_test.go`

**Interfaces:**
- Consumes: Tasks 1-2 and the already-reviewed fast/full and parallel Checks implementation.
- Produces: an approved local stack ready for the single exhaustive pre-push gate.

- [ ] **Step 1: Run focused repository contracts only**

Run:

```bash
mise exec -- go test ./scripts -run 'TestMiseSeparatesFastAndFullCheckLanes|TestPreCommitWrapperUsesFastLane|TestPreCommitSeparatesFastAndManualHooks|TestChecksWorkflowRunsIndependentLanes|TestDevReleaseRunsDirectlyFromMainPush|TestReleaseKeepsProductionCheckAndRemovesDevDuplicate|TestDeveloperDocsMakeFullCheckAPushBoundary' -count=1
mise run check:fast
```

Expected: PASS. Do not run the exhaustive gate during this review task.

- [ ] **Step 2: Review the complete unpublished diff**

Compare the current stack with `origin/main` and confirm:

- the commit hook invokes only `check:fast:hooks`
- the full suite appears once in local `check`, through the quality hook
- Checks has independent fast, quality, static, and topology jobs
- dev Release starts directly from a `main` push and has no `check` dependency
- version Release runs `mise run check` and all production publication jobs depend on `check`
- no `workflow_run` or `source_sha` code remains
- docs require the exhaustive gate immediately before push, not per checkpoint

Run:

```bash
git diff --check "$(git merge-base origin/main HEAD)"..HEAD
```

Expected: exit 0.

- [ ] **Step 3: Request independent final review**

Give the reviewer the approved design, this plan, and the complete base-to-head diff. Require findings categorized as Critical, Important, or Minor, with special attention to GitHub Actions `needs` skip behavior and accidental production publication without `check`.

Expected: approval with no unresolved findings. Fix findings with focused tests and `check:fast`; do not run the exhaustive gate yet.

- [ ] **Step 4: Stop at the publication boundary**

Report the focused/fast evidence, final review result, current stack head, and unchanged remote `main`. Ask for explicit authorization to land and push. Do not push or run `mise run check` before that authorization.

### Task 4: Run the single exhaustive gate, land, and observe CI

**Authorization:** Execute this task only after the user explicitly authorizes landing and pushing to `main`.

**Files:**
- No source edits expected.
- Inspect: GitButler stack and live GitHub Actions runs.

**Interfaces:**
- Consumes: approved Task 3 stack and explicit publication authorization.
- Produces: one clean CI-oriented commit on local `main` and `origin/main`, plus live Checks/dev evidence.

- [ ] **Step 1: Synchronize and tidy unpublished history**

Run:

```bash
but pull --check
but status
but oplog snapshot -m "before final CI history cleanup"
```

If `origin/main` advanced, run `but pull`, rerun the focused Task 3 tests, and continue only if the stack remains conflict-free. Use `but squash` to combine only this session's planning and implementation commits into one commit named:

```text
ci: separate fast development from release gates
```

Do not include another session's branch or commit.

- [ ] **Step 2: Run the exhaustive gate once against final content**

Run:

```bash
mise run check
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
git diff --check "$(git merge-base origin/main HEAD)"..HEAD
```

Expected: all commands pass. If tracked content changes for any reason, rerun `mise run check` after the change before pushing.

- [ ] **Step 3: Publish directly to main**

Confirm the squashed session is one commit based on current `origin/main` and contains only the planned files. Then use the repository's authorized direct-publication exception:

```bash
SESSION_COMMIT="$(but status --format json | jq -r '.stacks[].branches[] | select(.name == "codex/ci-feedback-loop") | .commits[0].commitId')"
test "$SESSION_COMMIT" != "null"
git push origin "$SESSION_COMMIT":main
```

Treat a non-fast-forward rejection as the race check. Do not force-push. If rejected, run `but pull`, resolve only this session's conflicts, rerun `mise run check`, and retry once clean.

- [ ] **Step 4: Verify landed refs and clean GitButler state**

Run:

```bash
but pull
but clean --dry-run
but clean
git rev-parse main
git rev-parse origin/main
git ls-remote origin refs/heads/main
```

Expected: local `main`, `origin/main`, and live remote `main` all equal the landed commit. Clean only this session's integrated branches.

- [ ] **Step 5: Observe the direct dev and parallel Checks workflows**

Use `gh run list` and `gh run watch` to verify:

- Release was triggered directly by the landed `main` push
- the dev build uses the landed SHA and does not wait for Checks
- all four Checks jobs pass
- Checks critical-path duration is no more than five minutes

Rerun the landed Checks workflow once and require a second green attempt. Record both durations and the slowest job.

- [ ] **Step 6: Record the deferred version-release proof**

Do not create a version tag. Record that local contracts and the landed workflow graph prove production publication depends on `check`; confirm live behavior when the next real Prepare Release workflow creates a version tag.

Expected final report: fast-lane timing, the one exhaustive pre-push timing, both Checks timings, direct dev Release status, landed commit SHA, and the explicitly deferred next-version live gate proof.
