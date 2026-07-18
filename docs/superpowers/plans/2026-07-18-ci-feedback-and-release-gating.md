# CI Feedback and Release Gating Implementation Plan

> **Superseded — do not execute.** Use
> [`2026-07-18-three-boundary-verification.md`](2026-07-18-three-boundary-verification.md)
> instead. The `workflow_run` release gating below is abandoned and remains only
> as historical context.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut local and GitHub verification latency by removing duplicated full-suite runs, parallelizing independent CI gates, and publishing dev artifacts only after the exact `main` commit passes Checks.

**Architecture:** Keep the existing hook scripts and quality thresholds as the source of truth, but expose them through explicit fast, full, static, quality, and topology lanes. The installed commit hook runs the fast lane; full local verification invokes both pre-commit stages. GitHub Actions schedules the four independent lanes concurrently, and the Release workflow consumes the successful first-party `Checks` event and its `head_sha` for dev publication while retaining an independent production tag gate.

**Tech Stack:** Go 1.26.5, mise, pre-commit, shell, GitHub Actions, GitHub CLI, GitButler

## Global Constraints

- Preserve every existing license, formatting, tidy, private-scan, vet, staticcheck, govulncheck, coverage, CRAP, golangci-lint, hotspots, depaware, dependency-policy, build, and topology gate.
- The full Go suite runs exactly once in `mise run check` and exactly once in the `Checks` workflow, through `tools/quality/check` with `-covermode=atomic`.
- The installed pre-commit hook must not run the full test or quality suite.
- Agents must run focused tests for changed code before `mise run check:fast`; the fast lane is not a substitute for focused tests.
- Warm `mise run check:fast` must finish below 60 seconds in three consecutive runs on the development Mac.
- The `Checks` critical path must finish within five minutes on two consecutive attempts; 3-4 minutes is the target.
- Dev publishing may consume only a successful first-party `push` run of `Checks` on `main`, and every checkout/build/tag operation must use that run's exact `head_sha`.
- Tagged and prepared production releases retain an independent build/test/vet gate.
- Do not add self-hosted runners, external CI services, host modifications, retries around normal tests, or new repository dependencies.
- Keep `mise run check:hooks` as the backward-compatible full-hook command.
- Use the Caveman skill before editing `README.md`, as required by repository policy.
- Use GitButler for branch and commit writes. Do not push or update `main` until the user explicitly authorizes publication.

## File Map

- Create `scripts/ci_pipeline_test.go`: orchestration contract tests for mise tasks, pre-commit stages, Checks jobs, release gating, and developer documentation.
- Modify `scripts/release_workflow_test.go`: keep the existing SwiftPM release dependency assertion aligned with the production graph.
- Modify `.pre-commit-config.yaml`: classify deterministic hooks as `pre-commit` and expensive analysis hooks as `manual`.
- Modify `.mise.toml`: add fast/full/static task boundaries and remove the duplicate test pass from `check`.
- Modify `tools/hooks/pre-commit`: make the legacy wrapper invoke the named fast hook task so it cannot drift from the installed hook contract.
- Modify `.github/workflows/checks.yml`: run fast, quality, static, and topology jobs concurrently and cancel superseded runs.
- Modify `.github/workflows/release.yml`: trigger dev builds from a successful Checks `workflow_run`, propagate the exact source SHA, and retain production verification.
- Modify `README.md`: document the fast iteration command and full landing gate.
- Modify `AGENTS.md`: update the agent contract to require focused tests plus the fast lane during iteration and the full lane before integration.

---

### Task 1: Define and implement the local fast/full verification lanes

**Files:**
- Create: `scripts/ci_pipeline_test.go`
- Modify: `.pre-commit-config.yaml`
- Modify: `.mise.toml`
- Modify: `tools/hooks/pre-commit`

**Interfaces:**
- Consumes: existing executable hook scripts under `tools/hooks/` and `tools/quality/check`
- Produces: mise tasks `check:fast:hooks`, `check:full:hooks`, `check:hooks`, `check:static`, `check:fast`, and `check`
- Produces: pre-commit stage contract where normal commits run fast hooks and manual invocation runs expensive hooks

- [ ] **Step 1: Confirm a clean, current GitButler base**

Run:

```bash
but diff
but pull --check
```

Expected: `but diff` reports no unrelated changes, and `but pull --check` says `origin/main` is up to date. If another active branch touches any file in this task, stop and report the overlap instead of committing across branches.

- [ ] **Step 2: Add failing local-lane contract tests**

Create `scripts/ci_pipeline_test.go` with:

```go
// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readCIPipelineFile(t *testing.T, parts ...string) string {
	t.Helper()
	pathParts := append([]string{".."}, parts...)
	data, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(data)
}

func miseTaskBlock(t *testing.T, body, header string) string {
	t.Helper()
	start := strings.Index(body, header)
	if start < 0 {
		t.Fatalf("mise config missing task header %q", header)
	}
	rest := body[start+len(header):]
	if end := strings.Index(rest, "\n[tasks."); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func preCommitHookBlock(t *testing.T, body, id string) string {
	t.Helper()
	marker := "      - id: " + id
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("pre-commit config missing hook %q", id)
	}
	rest := body[start+len(marker):]
	if end := strings.Index(rest, "\n      - id: "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func TestMiseSeparatesFastAndFullCheckLanes(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".mise.toml")

	for _, required := range []string{
		`[tasks."check:fast:hooks"]`,
		`pre-commit run --all-files --hook-stage pre-commit`,
		`[tasks."check:full:hooks"]`,
		`pre-commit run --all-files --hook-stage manual`,
		`[tasks."check:static"]`,
		`[tasks."check:fast"]`,
		`mise run check:fast:hooks`,
		`[tasks.check]`,
		`mise run check:full:hooks`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("mise config missing %q", required)
		}
	}

	full := miseTaskBlock(t, body, "[tasks.check]")
	if strings.Contains(full, "mise run test") || strings.Contains(full, "go test ./...") {
		t.Fatalf("full check duplicates the quality gate's full test suite:\n%s", full)
	}
}

func TestPreCommitSeparatesFastAndManualHooks(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".pre-commit-config.yaml")

	fast := []string{
		"derphole-license-check",
		"derphole-gofmt-check",
		"derphole-go-mod-tidy",
		"derphole-private-info-scan",
		"derphole-depaware-deps",
	}
	heavy := []string{
		"derphole-go-vet",
		"derphole-staticcheck",
		"derphole-govulncheck",
		"derphole-quality",
		"derphole-depaware",
	}

	for _, id := range fast {
		block := preCommitHookBlock(t, body, id)
		if !strings.Contains(block, "stages: [pre-commit]") {
			t.Fatalf("fast hook %s is not in the pre-commit stage", id)
		}
	}
	for _, id := range heavy {
		block := preCommitHookBlock(t, body, id)
		if !strings.Contains(block, "stages: [manual]") {
			t.Fatalf("heavy hook %s is not in the manual stage", id)
		}
	}
}
```

- [ ] **Step 3: Run the focused tests and verify they fail for the expected missing contracts**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(MiseSeparatesFastAndFullCheckLanes|PreCommitSeparatesFastAndManualHooks)$' -count=1 -v
```

Expected: FAIL because `.mise.toml` lacks `check:fast:hooks` and the heavy hooks still use `stages: [pre-commit]`.

- [ ] **Step 4: Move the expensive hooks to the manual stage**

In `.pre-commit-config.yaml`, keep these exact stage assignments:

```yaml
# Normal commit stage.
derphole-license-check: stages: [pre-commit]
derphole-gofmt-check: stages: [pre-commit]
derphole-go-mod-tidy: stages: [pre-commit]
derphole-private-info-scan: stages: [pre-commit]
derphole-depaware-deps: stages: [pre-commit]

# Explicit full/manual stage.
derphole-go-vet: stages: [manual]
derphole-staticcheck: stages: [manual]
derphole-govulncheck: stages: [manual]
derphole-quality: stages: [manual]
derphole-depaware: stages: [manual]
```

Apply the stage value to each existing hook block; do not replace the hook records with the compact mapping above. Leave `derphole-prepare-commit-msg` at `stages: [prepare-commit-msg]`.

- [ ] **Step 5: Add the named mise tasks and remove the duplicate full-suite pass**

Replace the current `check:hooks` and `check` task block in `.mise.toml` with:

```toml
[tasks."check:fast:hooks"]
description = "Run deterministic pre-commit hygiene checks"
run = "pre-commit run --all-files --hook-stage pre-commit"

[tasks."check:full:hooks"]
description = "Run fast and exhaustive pre-commit checks"
shell = "bash -c"
run = """
set -euo pipefail
pre-commit run --all-files --hook-stage pre-commit
pre-commit run --all-files --hook-stage manual
"""

[tasks."check:hooks"]
description = "Compatibility alias for the exhaustive hook set"
run = "mise run check:full:hooks"

[tasks."check:static"]
description = "Run static, vulnerability, and dependency analysis"
shell = "bash -c"
run = """
set -euo pipefail
tools/hooks/go-vet
tools/hooks/staticcheck
tools/hooks/govulncheck
tools/hooks/depaware-check
tools/hooks/depaware-deps-check
"""

[tasks."check:fast"]
description = "Run fast repository checks and compile all products"
shell = "bash -c"
run = """
set -euo pipefail
mise run check:fast:hooks
mise run build
"""

[tasks.check]
description = "Run the exhaustive local verification gate"
shell = "bash -c"
run = """
set -euo pipefail
mise run check:full:hooks
mise run build
"""
```

Do not add `mise run test` to `tasks.check`; the manual `derphole-quality` hook invokes `tools/quality/check`, which already runs the full suite with coverage.

- [ ] **Step 6: Align the legacy hook wrapper with the fast contract**

Replace the command list at the end of `tools/hooks/pre-commit` with:

```bash
if ! command -v mise >/dev/null 2>&1; then
  echo "mise is required to run the repository pre-commit checks." >&2
  echo "Install and run: mise install" >&2
  exit 1
fi

exec mise run check:fast:hooks
```

Keep the existing shebang, copyright header, `set -euo pipefail`, repository-root calculation, and `cd` intact.

- [ ] **Step 7: Run the focused tests and both new local task boundaries**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(MiseSeparatesFastAndFullCheckLanes|PreCommitSeparatesFastAndManualHooks)$' -count=1 -v
mise run check:fast
mise run check:static
```

Expected: all commands PASS. `check:fast` must not print the coverage-backed quality gate. `check:static` must run vet, staticcheck, govulncheck, depaware generation, and dependency-policy validation.

- [ ] **Step 8: Commit the local-lane implementation on a dedicated GitButler branch**

Run:

```bash
but diff
but commit codex/ci-feedback-loop -c -m "ci: split fast and exhaustive local checks"
```

Expected: GitButler creates `codex/ci-feedback-loop`, the now-fast installed pre-commit stage passes, and the returned workspace state assigns only the four Task 1 files to the new commit.

---

### Task 2: Parallelize the GitHub Checks workflow

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `.github/workflows/checks.yml`
- Verify: `scripts/toposim_script_test.go`

**Interfaces:**
- Consumes: `mise run check:fast`, `mise run quality`, `mise run check:static`, and `mise run toposim`
- Produces: four independently reported jobs in the workflow named `Checks`
- Preserves: topology tool installation and `TestToposimIsWiredIntoMiseAndChecksWorkflow`

- [ ] **Step 1: Add a failing parallel-workflow contract test**

Append to `scripts/ci_pipeline_test.go`:

```go
func TestChecksWorkflowRunsIndependentLanes(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "checks.yml")

	for _, required := range []string{
		"group: checks-${{ github.workflow }}-${{ github.ref }}",
		"cancel-in-progress: true",
		"\n  fast:\n",
		"run: mise run check:fast",
		"\n  quality:\n",
		"run: mise run quality",
		"\n  static:\n",
		"run: mise run check:static",
		"\n  topology:\n",
		"run: mise run toposim",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("checks workflow missing %q", required)
		}
	}
	if strings.Contains(body, "\n  checks:\n") {
		t.Fatal("checks workflow still contains the old serial checks job")
	}
	if strings.Contains(body, "run: mise run check\n") {
		t.Fatal("checks workflow still invokes the serial full local gate")
	}

	topology := body[strings.Index(body, "\n  topology:\n"):]
	for _, tool := range []string{"iproute2", "iptables", "iputils-ping"} {
		if !strings.Contains(topology, tool) {
			t.Fatalf("topology job missing %s", tool)
		}
	}
	beforeTopology := body[:strings.Index(body, "\n  topology:\n")]
	if strings.Contains(beforeTopology, "Install topology tools") {
		t.Fatal("topology packages are installed outside the topology job")
	}
}
```

- [ ] **Step 2: Run the focused test and verify the old serial workflow fails it**

Run:

```bash
mise exec -- go test ./scripts -run 'TestChecksWorkflowRunsIndependentLanes$' -count=1 -v
```

Expected: FAIL because the workflow contains one `checks` job and no concurrency group.

- [ ] **Step 3: Replace the serial Checks job with four independent jobs**

Replace `.github/workflows/checks.yml` with:

```yaml
name: Checks

on:
  push:
    paths-ignore:
      - "README.md"
  pull_request:
    paths-ignore:
      - "README.md"

concurrency:
  group: checks-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  fast:
    name: Fast contract
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v4
        with:
          install: true
          cache: true
      - name: Run fast checks
        run: mise run check:fast

  quality:
    name: Tests + quality
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v4
        with:
          install: true
          cache: true
      - name: Run coverage-backed quality gate
        run: mise run quality

  static:
    name: Static + dependency
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v4
        with:
          install: true
          cache: true
      - name: Run static and dependency analysis
        run: mise run check:static

  topology:
    name: Topology
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Setup mise
        uses: jdx/mise-action@v4
        with:
          install: true
          cache: true
      - name: Install topology tools
        run: sudo apt-get update && sudo apt-get install -y iproute2 iptables iputils-ping
      - name: Run topology simulations
        run: mise run toposim
```

- [ ] **Step 4: Run the workflow and topology contract tests**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(ChecksWorkflowRunsIndependentLanes|ToposimIsWiredIntoMiseAndChecksWorkflow)$' -count=1 -v
```

Expected: PASS. The test output must show both contract tests succeeded.

- [ ] **Step 5: Confirm the workflow has one full-suite invocation and no YAML syntax problem**

Run:

```bash
test "$(rg -n 'run: mise run quality' .github/workflows/checks.yml | wc -l | tr -d ' ')" = 1
test "$(rg -n 'run: mise run check$|run: mise run test' .github/workflows/checks.yml | wc -l | tr -d ' ')" = 0
mise exec -- go test ./scripts -count=1
```

Expected: both shell assertions exit 0 and the complete `scripts` package passes.

- [ ] **Step 6: Commit the parallel Checks workflow**

Run:

```bash
but diff
but commit codex/ci-feedback-loop -m "ci: parallelize repository checks"
```

Expected: the returned workspace state shows a new commit containing only `scripts/ci_pipeline_test.go` and `.github/workflows/checks.yml` changes from Task 2.

---

### Task 3: Gate dev publication on the exact successful main SHA

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `scripts/release_workflow_test.go`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: completed workflow named `Checks`
- Produces: metadata outputs `is_tag`, `is_main`, `version`, and `source_sha`
- Produces: privileged dev publication only for a successful first-party `push` check on `main`
- Preserves: independent `check` dependency for prepared/tagged production publication

- [ ] **Step 1: Add failing tests for the dev release trust boundary and source SHA**

Append to `scripts/ci_pipeline_test.go`:

```go
func TestDevReleaseWaitsForSuccessfulFirstPartyMainChecks(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "release.yml")

	for _, required := range []string{
		"workflow_run:",
		`workflows: ["Checks"]`,
		"types: [completed]",
		`branches: ["main"]`,
		"github.event.workflow_run.conclusion == 'success'",
		"github.event.workflow_run.event == 'push'",
		"github.event.workflow_run.head_branch == 'main'",
		"github.event.workflow_run.head_repository.full_name == github.repository",
		"source_sha: ${{ steps.meta.outputs.source_sha }}",
		"WORKFLOW_RUN_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}",
		`[[ ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]`,
		"ref: ${{ needs.meta.outputs.source_sha }}",
		"COMMIT: ${{ needs.meta.outputs.source_sha }}",
		"SOURCE_SHA: ${{ needs.meta.outputs.source_sha }}",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("release workflow missing %q", required)
		}
	}

	if strings.Contains(body, "branches:\n      - \"main\"") {
		t.Fatal("release workflow still publishes dev artifacts directly from a main push")
	}
	if strings.Contains(body, "COMMIT: ${{ github.sha }}") || strings.Contains(body, `git tag -f dev "$GITHUB_SHA"`) {
		t.Fatal("release workflow still uses the workflow event SHA instead of the checked source SHA")
	}
}

func TestReleaseKeepsProductionCheckAndRemovesDevDuplicate(t *testing.T) {
	t.Parallel()
	body := readCIPipelineFile(t, ".github", "workflows", "release.yml")

	for _, required := range []string{
		"needs: [meta, check, build-binaries, build-web, build-swiftpm-framework, publish-npm-prod]",
		"needs: [meta, check, build-binaries]",
		"needs: [meta, check, publish-packages-prod, build-swiftpm-framework]",
		"needs: [meta, build-binaries, build-web, publish-npm-dev]",
		"needs: [meta, build-binaries]",
		"needs: [meta, publish-packages-dev]",
		"if: needs.meta.outputs.is_tag == 'true'",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("release dependency graph missing %q", required)
		}
	}
}
```

- [ ] **Step 2: Run the new tests and verify they fail against direct main-push publishing**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(DevReleaseWaitsForSuccessfulFirstPartyMainChecks|ReleaseKeepsProductionCheckAndRemovesDevDuplicate)$' -count=1 -v
```

Expected: FAIL because `release.yml` has no `workflow_run`, uses `github.sha`/`GITHUB_SHA`, and keeps `check` in the dev dependency chain.

- [ ] **Step 3: Change the Release triggers without changing prepared/tagged release entry points**

Replace the `on.push` block in `.github/workflows/release.yml` with:

```yaml
  workflow_run:
    workflows: ["Checks"]
    types: [completed]
    branches: ["main"]
  push:
    tags:
      - "v*"
```

Keep the existing `workflow_dispatch.version` input. Remove the now-irrelevant `paths-ignore` block from the tag-only push trigger.

- [ ] **Step 4: Add a guarded exact-SHA metadata output**

Add this condition and output to the `meta` job:

```yaml
    if: >-
      github.event_name != 'workflow_run' ||
      (github.event.workflow_run.conclusion == 'success' &&
       github.event.workflow_run.event == 'push' &&
       github.event.workflow_run.head_branch == 'main' &&
       github.event.workflow_run.head_repository.full_name == github.repository)
    outputs:
      is_tag: ${{ steps.meta.outputs.is_tag }}
      is_main: ${{ steps.meta.outputs.is_main }}
      version: ${{ steps.meta.outputs.version }}
      source_sha: ${{ steps.meta.outputs.source_sha }}
```

Add the workflow-run SHA to the metadata step environment:

```yaml
        env:
          INPUT_VERSION: ${{ inputs.version }}
          WORKFLOW_RUN_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
```

Replace the beginning of the metadata script through the `short_sha` assignment with:

```bash
is_tag=false
is_main=false
input_version="${INPUT_VERSION:-}"
source_sha="$GITHUB_SHA"
if [ "$GITHUB_EVENT_NAME" = "workflow_run" ]; then
  is_main=true
  source_sha="$WORKFLOW_RUN_HEAD_SHA"
elif [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  is_tag=true
fi
if [ -n "$input_version" ]; then
  if [[ ! "$input_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "workflow_dispatch version must look like vX.Y.Z: $input_version" >&2
    exit 1
  fi
  if [ "$GITHUB_REF_NAME" != "$input_version" ]; then
    echo "workflow_dispatch ref must be the prepared tag $input_version; got $GITHUB_REF_NAME" >&2
    exit 1
  fi
  is_tag=true
  is_main=false
fi
if [[ ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release source SHA is invalid: $source_sha" >&2
  exit 1
fi
ts=$(date -u +%Y%m%d%H%M%S)
short_sha="${source_sha::7}"
```

Keep the existing version selection, then append the fourth output:

```bash
echo "is_tag=$is_tag" >> "$GITHUB_OUTPUT"
echo "is_main=$is_main" >> "$GITHUB_OUTPUT"
echo "version=$version" >> "$GITHUB_OUTPUT"
echo "source_sha=$source_sha" >> "$GITHUB_OUTPUT"
```

- [ ] **Step 5: Restrict the release-local check job to production tags**

Change the `check` job header and checkout to:

```yaml
  check:
    name: Build + test
    runs-on: ubuntu-latest
    needs: [meta]
    if: needs.meta.outputs.is_tag == 'true'
    steps:
      - name: Checkout
        uses: actions/checkout@v5
        with:
          ref: ${{ needs.meta.outputs.source_sha }}
```

Leave its Build, Test, and Vet steps unchanged. This job remains the independent production gate and is skipped for dev workflow-run publication.

- [ ] **Step 6: Propagate `source_sha` through every release checkout and binary build**

For every `actions/checkout@v5` step in `.github/workflows/release.yml`, add:

```yaml
        with:
          ref: ${{ needs.meta.outputs.source_sha }}
```

For the `release-dev` checkout, preserve its existing history requirement:

```yaml
        with:
          ref: ${{ needs.meta.outputs.source_sha }}
          fetch-depth: 0
```

Every job containing one of these checkouts must include `meta` in `needs`. Add `meta` to `publish-npm-prod` and `publish-npm-dev`; the other jobs already consume it directly or already list it.

Change binary build metadata from:

```yaml
          COMMIT: ${{ github.sha }}
```

to:

```yaml
          COMMIT: ${{ needs.meta.outputs.source_sha }}
```

Change the dev-tag step to:

```yaml
      - name: Update dev tag
        env:
          SOURCE_SHA: ${{ needs.meta.outputs.source_sha }}
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git tag -f dev "$SOURCE_SHA"
          git push -f origin refs/tags/dev
```

- [ ] **Step 7: Remove only the redundant dev check dependencies**

Use these exact dependency lists:

```yaml
# Production paths retain check.
release-prod:
  needs: [meta, check, build-binaries, build-web, build-swiftpm-framework, publish-npm-prod]
publish-packages-prod:
  needs: [meta, check, build-binaries]
publish-npm-prod:
  needs: [meta, check, publish-packages-prod, build-swiftpm-framework]

# Dev paths consume the already-green Checks workflow.
release-dev:
  needs: [meta, build-binaries, build-web, publish-npm-dev]
publish-packages-dev:
  needs: [meta, build-binaries]
publish-npm-dev:
  needs: [meta, publish-packages-dev]
```

Do not remove the `check` job or any production dependency on it.

In `scripts/release_workflow_test.go`, update the SwiftPM dependency assertion
from:

```go
"needs: [check, publish-packages-prod, build-swiftpm-framework]",
```

to:

```go
"needs: [meta, check, publish-packages-prod, build-swiftpm-framework]",
```

- [ ] **Step 8: Run release graph, security, and existing packaging workflow tests**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(DevReleaseWaitsForSuccessfulFirstPartyMainChecks|ReleaseKeepsProductionCheckAndRemovesDevDuplicate|ReleaseWorkflow|PrepareReleaseWorkflow)' -count=1 -v
test "$(rg -n '\$\{\{ github\.sha \}\}|\$GITHUB_SHA' .github/workflows/release.yml | wc -l | tr -d ' ')" = 1
```

Expected: all Go tests PASS. The shell assertion finds only `source_sha="$GITHUB_SHA"` in the metadata fallback for tag/dispatch events; there must be no direct checkout, build metadata, or dev-tag use of the event SHA.

- [ ] **Step 9: Run the required packaging dry run**

Run:

```bash
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
```

Expected: the npm dry run builds all three packages, validates their launchers and manifests, and exits 0 without publishing. This command does not create or push a tag.

- [ ] **Step 10: Commit the gated dev release graph**

Run:

```bash
but diff
but commit codex/ci-feedback-loop -m "release: gate dev publishing on checks"
```

Expected: the returned workspace state shows a commit containing only `scripts/ci_pipeline_test.go`, `scripts/release_workflow_test.go`, and `.github/workflows/release.yml` changes from Task 3.

---

### Task 4: Document the agent contract and prove local performance

**Files:**
- Modify: `scripts/ci_pipeline_test.go`
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: the fast/full mise commands from Task 1
- Produces: a documented workflow for humans and agents
- Produces: three-run local timing evidence against the 60-second fast-lane target

- [ ] **Step 1: Invoke the Caveman skill before editing the README**

Read and follow the available Caveman skill in `lite` intensity for the Development section. Keep the copy compressed, grammatical, and technical.

- [ ] **Step 2: Add a failing developer-documentation contract test**

Append to `scripts/ci_pipeline_test.go`:

```go
func TestDeveloperDocsExplainFastAndFullLanes(t *testing.T) {
	t.Parallel()
	readme := readCIPipelineFile(t, "README.md")
	agents := readCIPipelineFile(t, "AGENTS.md")

	for _, required := range []string{
		"mise run check:fast",
		"mise run check",
		"focused tests",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README development guidance missing %q", required)
		}
		if !strings.Contains(agents, required) {
			t.Fatalf("AGENTS guidance missing %q", required)
		}
	}
	if strings.Contains(agents, "Pre-commit hooks are intentionally expensive") {
		t.Fatal("AGENTS still describes checkpoint hooks as intentionally expensive")
	}
}
```

- [ ] **Step 3: Run the documentation test and verify the old guidance fails it**

Run:

```bash
mise exec -- go test ./scripts -run 'TestDeveloperDocsExplainFastAndFullLanes$' -count=1 -v
```

Expected: FAIL because the current Development section has no fast lane and `AGENTS.md` still says the installed hook is intentionally expensive.

- [ ] **Step 4: Update the README Development section**

Use this content in `README.md`:

````markdown
## Development

```bash
mise install
mise run install-githooks
go test ./pkg/token -run TestEncode
mise run check:fast
```

Run focused tests while iterating. `mise run check:fast` checks repository
hygiene and compiles every product without running the full suite. Before
landing, run the exhaustive gate:

```bash
mise run check
```

`mise run build` writes `dist/derphole`, `dist/derptun`, and `dist/derpssh`.
````

- [ ] **Step 5: Update the agent verification policy**

Replace the expensive-hook sentence in `AGENTS.md` with:

```markdown
Checkpoint commits run deterministic pre-commit hygiene checks. Run focused
tests for the code you change, then use `mise run check:fast` during iteration.
Before finishing to `main`, run the exhaustive `mise run check` gate. Report any
failure with the fix or remaining blocker.
```

Update the Build, Test, and Development Commands list to include:

```markdown
- `mise run check:fast` runs deterministic repository checks and builds every product without the full test suite
- `mise run check:hooks` runs both the fast and exhaustive pre-commit stages across all files
- `mise run check` runs the exhaustive hook set and builds every product; the coverage-backed quality hook supplies the single full-suite test pass
```

Retain the existing focused-test guidance under Testing Guidelines.

- [ ] **Step 6: Run the documentation and complete orchestration test set**

Run:

```bash
mise exec -- go test ./scripts -run 'Test(MiseSeparatesFastAndFullCheckLanes|PreCommitSeparatesFastAndManualHooks|ChecksWorkflowRunsIndependentLanes|DevReleaseWaitsForSuccessfulFirstPartyMainChecks|ReleaseKeepsProductionCheckAndRemovesDevDuplicate|DeveloperDocsExplainFastAndFullLanes|ToposimIsWiredIntoMiseAndChecksWorkflow)$' -count=1 -v
```

Expected: PASS for every named contract.

- [ ] **Step 7: Measure the warm fast lane three times**

Warm the Go and mise caches once, then collect three acceptance samples:

```bash
mise run check:fast
for run in 1 2 3; do
  echo "check:fast sample ${run}"
  /usr/bin/time -p mise run check:fast
done 2>&1 | tee .tmp/check-fast-timings.txt
```

Expected: each sample exits 0 and reports `real` below 60 seconds. Keep `.tmp/check-fast-timings.txt` uncommitted; `.tmp/` is ignored.

- [ ] **Step 8: Run the exhaustive local gate and verify the task graph does not start a second plain suite**

Run:

```bash
/usr/bin/time -p mise run check 2>&1 | tee .tmp/check-full-timing.txt
test "$(rg -n '^mise run test$|^go test ./\.\.\.$' .tmp/check-full-timing.txt | wc -l | tr -d ' ')" = 0
```

Expected: the full gate passes, prints the coverage-backed `go test` phase once, builds all products, and never starts a later plain `mise run test`/`go test ./...` phase.

- [ ] **Step 9: Commit the documentation and policy update**

Run:

```bash
but diff
but commit codex/ci-feedback-loop -m "docs: explain fast and full verification"
```

Expected: the returned workspace state shows a commit containing only `scripts/ci_pipeline_test.go`, `README.md`, and `AGENTS.md` changes from Task 4. Timing files remain ignored.

---

### Task 5: Final local verification and publication checkpoint

**Files:**
- Verify only: all files changed in Tasks 1-4

**Interfaces:**
- Consumes: complete implementation branch `codex/ci-feedback-loop`
- Produces: local evidence ready for an explicit land-and-push decision
- Produces after authorization: landed `main`, two green Checks attempts, and a gated dev release for the same SHA

- [ ] **Step 1: Check for upstream or branch overlap before final verification**

Run:

```bash
but pull --check
but status
```

Expected: no upstream changes conflict with this branch, no unrelated active branch owns the changed files, and all Task 1-4 commits are on `codex/ci-feedback-loop`.

- [ ] **Step 2: Run the complete local verification set**

Run:

```bash
mise exec -- go test ./scripts -count=1
mise run check:fast
mise run check
VERSION=v0.17.1 COMMIT="$(git rev-parse origin/main)" BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" mise run release:npm-dry-run
```

Expected: all four commands exit 0. Record the `check:fast` and `check` wall-clock durations in the implementation handoff.

- [ ] **Step 3: Self-review the complete branch diff**

Run:

```bash
but diff
but status -fv
git diff --check origin/main...HEAD
```

Expected: no uncommitted diff, no whitespace errors, and only the files named in this plan differ from `origin/main`. If GitButler's workspace commit makes `origin/main...HEAD` unsuitable, use the session commit IDs printed by `but status -fv` with read-only `git show --check` instead.

- [ ] **Step 4: Stop for explicit publication authorization**

Report:

- three `check:fast` timings
- full `check` timing
- focused and full test results
- packaging dry-run result
- the exact session commit IDs
- that nothing has been pushed

Ask the user to authorize landing and pushing. Do not perform the remaining steps without an explicit yes.

- [ ] **Step 5: After authorization, tidy the session branch and refresh the base**

Create a recovery point and inspect the commit stack:

```bash
but oplog snapshot -m "before CI feedback branch cleanup"
but status
but pull --check
```

If the four checkpoint commits are best presented as one CI change, use the commit IDs printed by `but status` to squash them into the oldest session commit with message `ci: shorten feedback and gate dev releases`. Re-run `mise run check` after any history rewrite. Do not squash, move, or amend commits from another branch.

- [ ] **Step 6: Land the verified session commit on main using the repository fast path**

Confirm the final session commit is based on current `origin/main`. Copy the
literal hexadecimal commit ID from the immediately preceding `but status`
output and use it as the source ref in the repository's documented direct
`git push origin` update to `main`. A non-fast-forward rejection is the race
check: run `but pull`, repeat affected verification if the base changes, and
retry only when clean.

- [ ] **Step 7: Verify local and remote refs, then reconcile GitButler**

Run:

```bash
landed="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$landed" = "$(git rev-parse origin/main)"
test "$landed" = "$(git rev-parse main)"
but pull
but clean --dry-run
```

Expected: all three main refs identify the landed commit. Run `but clean` only for this integrated session branch after the dry run proves it will not touch another agent's branch.

- [ ] **Step 8: Watch the first parallel Checks run and its gated dev Release**

Run:

```bash
checks_run="$(gh run list --workflow checks.yml --commit "$landed" --limit 1 --json databaseId --jq '.[0].databaseId')"
test -n "$checks_run"
gh run watch "$checks_run" --exit-status
gh run view "$checks_run" --json conclusion,createdAt,updatedAt,jobs,url

release_run="$(gh run list --workflow release.yml --branch main --event workflow_run --limit 10 --json databaseId,createdAt --jq 'sort_by(.createdAt) | last | .databaseId')"
test -n "$release_run"
gh run watch "$release_run" --exit-status
gh run view "$release_run" --json conclusion,createdAt,updatedAt,jobs,url
```

Expected: all four Checks jobs succeed, the Release workflow starts only after Checks completes, and the dev publish jobs succeed.

- [ ] **Step 9: Verify the dev artifacts identify the landed SHA**

Run:

```bash
test "$(git ls-remote origin refs/tags/dev | awk '{print $1}')" = "$landed"
short="${landed:0:7}"
for package in derphole derptun derpssh; do
  version="$(npm view "${package}@dev" version)"
  case "$version" in
    0.0.0-dev.*."$short") ;;
    *) echo "${package}@dev does not identify ${short}: ${version}" >&2; exit 1 ;;
  esac
done
```

Expected: the remote `dev` tag points to `main`, and all three npm dev versions end in the landed seven-character SHA.

- [ ] **Step 10: Deliberately rerun Checks once to test flake resistance**

Run:

```bash
gh run rerun "$checks_run"
gh run watch "$checks_run" --exit-status
gh run view "$checks_run" --attempt 2 --json conclusion,createdAt,updatedAt,jobs,url
```

Expected: attempt 2 succeeds with all four jobs green. Compare both attempts with the 7 minute 40 second baseline; each workflow critical path must be at or below five minutes.

- [ ] **Step 11: Report the final evidence**

The final handoff must include:

- landed commit SHA and confirmation that local `main`, `origin/main`, and remote `main` match
- three local fast-lane timings and the full-lane timing
- Checks attempt 1 and 2 durations, slowest job, and conclusions
- gated dev Release duration and conclusion
- `dev` tag and npm dev package SHA match
- any remaining bottleneck, especially whether `pkg/session` still dominates the quality job

Do not claim the optimization succeeded unless every acceptance threshold and publication check above passes.
