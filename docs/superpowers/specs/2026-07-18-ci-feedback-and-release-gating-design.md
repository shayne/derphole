# CI Feedback and Release Gating Design

## Summary

Derphole's verification is comprehensive, but the current task graph repeats
expensive work and serializes independent checks. A normal checkpoint commit
runs the full coverage and quality suite. `mise run check` then runs that suite
again without coverage. GitHub Actions places the same local gate and the Linux
topology simulation in one serial job, while the Release workflow starts
another build/test/vet job.

The fix is to separate feedback by purpose:

1. A fast iteration lane compiles every product without enforcing commit
   hygiene against dirty work.
2. The installed commit hook formats changed Go files and runs deterministic
   hygiene before a checkpoint can be recorded.
3. A full local lane retains every existing gate but runs the full Go test suite
   only once, through the coverage-backed quality check.
4. GitHub Actions runs the commit contract plus compilation, quality suite,
   static/dependency analysis, and topology simulation as independent jobs.
5. Main-branch dev publishing remains a direct, non-blocking feedback path.
   Versioned production releases retain an independent exhaustive release gate
   and cannot publish when that gate fails.

This changes orchestration, not quality thresholds or product behavior.

## Measured Baseline

Measurements from the current `main` revision established the following
baseline:

| Path | Observed duration | Important detail |
| --- | ---: | --- |
| Local pre-commit | about 3 minutes 22-30 seconds | Runs every configured gate, including coverage-backed tests |
| Warm local `mise run check` | 3 minutes 59 seconds to 4 minutes 3 seconds | Runs the full suite in the quality hook and then runs `go test ./...` again |
| GitHub `Checks` | about 7 minutes 40 seconds | One serial job; the `Run checks` step alone took about 7 minutes 16 seconds |
| GitHub `Release` | about 6 minutes 37 seconds | Main release verification duplicates work already running in `Checks` |
| GitHub Pages | about 44 seconds | Not part of the bottleneck |

The dominant local package was `pkg/session` at roughly 150 seconds uncached.
The full `scripts` package took roughly 212-217 seconds locally. This design
does not shard those packages yet; it first removes duplication and exposes
independent work to the CI scheduler.

## Goals

- Make a warm `mise run check:fast` complete in less than 60 seconds on the
  development Mac in three consecutive runs.
- Make the installed pre-commit hook suitable for checkpoint commits by
  running only deterministic hygiene checks.
- Preserve the full coverage, CRAP, golangci-lint, vet, staticcheck,
  govulncheck, depaware, dependency-policy, build, and topology gates.
- Ensure one full local `mise run check` executes `go test ./...` exactly once,
  through `tools/quality/check` with atomic coverage.
- Reduce the `Checks` workflow's normal wall-clock critical path to 3-5
  minutes by running independent jobs concurrently.
- Cancel superseded checks for the same branch or pull request.
- Make focused tests and the build-only `mise run check:fast` the normal
  agent-development loop.
- Enforce formatting and deterministic hygiene through the installed commit
  hook when a checkpoint commit is created, not during dirty iteration.
- Require one instruction-driven `mise run check` immediately before an agent
  pushes or lands work, rather than once per checkpoint commit.
- Keep main-branch `dev` artifacts available without waiting for `Checks`.
- Block tagged and prepared version releases on an independent exhaustive CI
  check before any production publication job can run.
- Prove the new path with repeated local timings and two successful GitHub
  `Checks` attempts before declaring the optimization complete.

## Non-Goals

- Changing quality thresholds, baselines, lint policy, or vulnerability policy.
- Weakening focused testing during development. Agents still run focused tests
  for the code they change before using the fast lane.
- Sharding `pkg/session`, rewriting slow tests, or changing test semantics in
  this change.
- Adding self-hosted runners, host modifications, external CI services, or new
  repository dependencies.
- Changing release asset contents, npm package names, semver behavior, or the
  Prepare Release workflow's SwiftPM process.
- Making Pages wait for `Checks`; its current independent 44-second path is
  already healthy.

## Approaches Considered

### Recommended: explicit local lanes, parallel checks, gated version releases

Keep the existing scripts as the source of truth, group them into named `mise`
tasks, and schedule those groups according to cost. Mark expensive pre-commit
hooks as `manual`, while `mise run check:hooks` invokes both the normal and
manual stages for backward-compatible full verification. Split the `Checks`
workflow into jobs, use a CI-only composite for commit hygiene plus compilation,
keep main-branch dev publishing direct, and make only the versioned production
graph depend on the Release workflow's exhaustive check.

This is the smallest approach that removes duplicated work, improves feedback,
and preserves every gate at the boundary where it matters.

### Rejected: automatic exhaustive pre-push hook

An automatic hook would enforce the boundary, but it would also rerun the slow
gate when an agent has already verified the exact commit, surprise developers
on ordinary branch pushes, and make recovery pushes unnecessarily expensive.
The repository instead makes the pre-push requirement explicit in `AGENTS.md`
and keeps the installed commit hook fast.

### Rejected: run commit hygiene during dirty iteration

Making gofmt tolerate correctly formatted dirty files would fix one symptom,
but iteration would still spend time enforcing a commit boundary that has not
been reached. Editors may format continuously, but repository enforcement
belongs to the commit hook. The iteration lane therefore compiles only, while
the commit and CI lanes retain formatting and deterministic hygiene.

### Rejected: reusable or `workflow_run`-gated release orchestration

A reusable checks workflow could reduce YAML duplication, while a
`workflow_run` trigger could gate dev publication. Both add event, permission,
and SHA-correlation complexity. Dev artifacts are allowed to be provisional,
and the existing version-release graph already has a natural blocking `check`
job, so neither mechanism is needed.

### Rejected: keep one Checks job and rely on caches

Caching toolchains and Go artifacts helps setup time, but it does not remove
the second full test pass or allow topology and static analysis to overlap the
quality suite. It leaves the main structural bottleneck intact.

### Rejected: self-hosted runners or a third-party CI service

More CPU could hide some latency, but it adds host maintenance and violates the
no-host-modification constraint. It also leaves redundant work in the task
graph. The repository should first become efficient on standard GitHub-hosted
runners.

## Local Verification Architecture

### Fast hook stage

The installed `pre-commit` stage runs:

- license headers
- gofmt on changed Go files
- `go mod tidy` drift detection
- private-information scanning
- dependency-policy checks against the committed depaware snapshots

These checks are deterministic, catch common checkpoint mistakes, and do not
run the full test suite.

### Manual full stage

The pre-commit `manual` stage runs:

- `go vet ./...`
- staticcheck
- govulncheck
- the coverage-backed quality gate, including CRAP and golangci-lint
- depaware snapshot generation and dependency-policy validation

`mise run check:hooks` remains the compatibility command for the complete hook
set. It runs the fast stage and then the manual stage.

### Named `mise` tasks

- `check:fast:hooks`: normal pre-commit stage only
- `check:full:hooks`: normal stage followed by manual stage
- `check:hooks`: compatibility alias to `check:full:hooks`
- `check:static`: vet, staticcheck, govulncheck, depaware generation, and
  dependency-policy validation
- `check:fast`: all product builds, with no hook or formatting enforcement
- `check:ci-fast`: fast hooks followed by `check:fast`
- `check`: full hooks plus all product builds

`check` does not call `mise run test` after the full hooks. The manual quality
hook already runs `go test -coverprofile=... -covermode=atomic ./...`, so a
second plain full-suite invocation adds time without adding coverage.

### Agent development and push boundary

Agents run focused tests for the package or behavior they change, followed by
the build-only `mise run check:fast` during iteration. This command neither
formats files nor rejects a correctly formatted dirty Go diff.

When the agent creates a checkpoint commit, the installed pre-commit hook runs
`check:fast:hooks`. Gofmt may update an unformatted file and stop that commit;
the next commit attempt records the formatted content. License, module-tidy,
private-information, and dependency-policy checks run at the same boundary.

Immediately before any push or direct landing to `main`, the agent runs
`mise run check` once against the exact commit stack being published. If the
stack changes after that run, the exhaustive gate is stale and must run again.
This is instruction-driven; the repository does not install a slow pre-push
hook.

## GitHub Checks Architecture

The workflow keeps the public name `Checks` and uses four independent jobs:

| Job | Command | Responsibility |
| --- | --- | --- |
| Fast contract | `mise run check:ci-fast` | Commit hygiene, private scan, dependency policy, and compilation |
| Tests + quality | `mise run quality` | Full test suite once, coverage, CRAP, golangci-lint, hotspots |
| Static + dependency | `mise run check:static` | Vet, staticcheck, vulnerabilities, depaware generation and policy |
| Topology | `mise run toposim` | Linux namespaces, NAT, and path-promotion simulation |

Only the topology job installs `iproute2`, `iptables`, and `iputils-ping`.
Failures remain independently attributable. The workflow fails if any job
fails. A concurrency group keyed by workflow and ref cancels stale runs without
cancelling unrelated branches.

The quality job is the only CI job that runs the full Go suite. Build and
analysis jobs may compile packages through normal Go tooling, but they do not
start a second `go test ./...` pass.

## Dev and Production Release Gating

The Release workflow continues listening directly to pushes on `main`, tag
pushes, and prepared-release dispatches.

For a `main` push, metadata marks the run as a dev build. Dev build and publish
jobs use the pushed commit and do not depend on the release-local exhaustive
`check` job. The repository-wide `Checks` workflow still runs independently on
the push, but it does not block provisional dev artifacts.

For a version tag or a prepared-release dispatch, metadata marks the run as a
production release. The Release workflow's `check` job runs `mise run check`
for that source commit. Every production packaging, npm publishing, GitHub
release, and SwiftPM publication path remains downstream of that successful
job. A failed or cancelled check leaves production publication jobs skipped.

This keeps the production safety boundary inside the workflow that owns the
versioned release. It avoids trusting a separate workflow event, correlating a
second event's SHA, or delaying disposable dev builds.

## Tests

Repository-level Go tests under `scripts/` will lock down orchestration without
adding a YAML parser:

- the `mise` task names and full/fast responsibilities
- the build-only iteration lane remaining independent of commit hooks
- manual versus normal pre-commit hook classification
- four independent Checks jobs and their commands
- topology package installation remaining isolated to the topology job
- direct main-push dev triggering without an exhaustive check dependency
- production dependencies retaining `check`
- versioned publication jobs being unreachable when `check` fails or skips

Existing release artifact, npm, SwiftPM, and shell-interpolation tests remain
unchanged except where an exact dependency string must reflect the new dev
and production release graph.

Verification runs focused orchestration tests first, then `check:fast`, full
`check`, and `release:npm-dry-run`. After explicit publication approval, the
landed commit must produce a successful `Checks` run, a direct dev Release run
for the same pushed SHA, and a successful deliberate rerun of `Checks`.

## Documentation and Agent Contract

`README.md` will explain the three boundaries:

- use focused tests plus the build-only `mise run check:fast` while iterating
- let the installed hook format and run deterministic hygiene at commit time
- use `mise run check` before landing

`AGENTS.md` will stop describing pre-commit as intentionally expensive. It will
require focused tests plus the build-only fast lane during development, make
the installed hook responsible for checkpoint formatting and hygiene,
explicitly discourage the exhaustive gate during normal iteration, and require
one exhaustive full check immediately before push or integration.
Existing plans that name `mise run check:hooks` continue to work because that
command remains the full compatibility entry point.

## Rollout and Acceptance

The implementation lands as one CI-oriented change after local validation.
Publication requires separate explicit authorization. Once authorized:

1. Land the commit on `main`.
2. Confirm all four Checks jobs succeed for the landed SHA.
3. Confirm the direct main-push dev Release run uses the landed SHA; it need not
   wait for Checks.
4. Rerun Checks once and require a second clean attempt.
5. Record durations for the two attempts and compare them with the 7 minute 40
   second baseline.

The next actual version release provides the live production-gate proof: its
publication jobs must remain blocked until the release-local exhaustive check
succeeds. Contract tests verify that dependency before landing; the rollout
does not create a throwaway production tag merely to exercise it.

Acceptance requires three consecutive warm local `check:fast` runs below 60
seconds, no missing gate in the full lane, two green Checks attempts, and a
main CI critical path no slower than five minutes. A 3-4 minute result is the
target; five minutes is the regression threshold.

If the split exposes a previously hidden flaky test, diagnose the exact failing
job with repeated coverage-backed focused tests. Do not merge retries into
normal test commands or weaken assertions to manufacture a green result.

## References

- [GitHub Actions job dependencies](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs#defining-prerequisite-jobs)
