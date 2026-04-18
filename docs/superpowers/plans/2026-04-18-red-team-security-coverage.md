# Red Team Security Coverage Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans when implementing fixes from this audit. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Exercise derphole and derptun as an adversary would, then close test gaps around token authority, rendezvous claims, tunnel durability, transport path confidence, packaging, and release integrity.

**Architecture:** Split audit work into independent tracks: token/auth, transport/live harnesses, and CLI/package/release surfaces. Use adversarial unit tests for deterministic security boundaries, then remote smoke tests against `ktzlxc` with Tailscale candidates disabled to prove real direct-path behavior.

**Tech Stack:** Go tests, `mise`, repository smoke scripts, GitHub Actions, npm package wrappers, SSH-accessible remote host `ktzlxc`.

---

### Task 1: Token And Claim Authority

**Files:**
- Modify: `pkg/derptun/token_test.go`
- Modify if needed: `pkg/derptun/token.go`
- Inspect: `pkg/rendezvous/state.go`
- Inspect: `pkg/session/derptun.go`

- [x] **Step 1: Add malformed-proof red test**

Add a test that mutates a valid `dtc1_` client token so `proof_mac` is non-hex and asserts `DecodeClientToken` returns `ErrInvalidToken`.

- [x] **Step 2: Verify the red test fails**

Run: `go test ./pkg/derptun -run TestDecodeClientTokenRejectsMalformedProofMAC -count=1`

Expected before fix: test fails because malformed `proof_mac` currently decodes.

- [x] **Step 3: Harden proof MAC validation**

Validate client-token `ProofMAC` as a 32-byte hex-encoded HMAC during decode.

- [x] **Step 4: Verify the red test passes**

Run: `go test ./pkg/derptun -run TestDecodeClientTokenRejectsMalformedProofMAC -count=1`

Expected after fix: pass.

- [x] **Step 5: Run token/session adversarial tests**

Run: `go test ./pkg/derptun ./pkg/rendezvous ./pkg/session -run 'Derptun|Gate|Token|Claim|Proof|Decode|Reject' -count=1`

Expected: pass.

### Task 2: Derptun Live Direct-Path Abuse Coverage

**Files:**
- Inspect: `scripts/smoke-remote-derptun.sh`
- Inspect: `pkg/session/derptun.go`
- Inspect: `pkg/transport/manager.go`

- [x] **Step 1: Run live derptun smoke against ktzlxc**

Run: `REMOTE_HOST=ktzlxc mise run smoke-remote-derptun`

Expected: pass, and logs must contain `connected-direct` with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`.

- [x] **Step 2: Record whether harness covers reconnect abuse**

Confirm the script covers first connect, server restart with stable token, active-client contender rejection, dead-client recovery, second connect, local `open`, and direct evidence on both local and remote logs.

### Task 3: Generic Derphole Remote Coverage

**Files:**
- Inspect: `scripts/smoke-remote.sh`
- Inspect: `scripts/smoke-remote-share.sh`
- Inspect: `scripts/promotion-benchmark-driver.sh`

- [x] **Step 1: Run remote stdio smoke if host is reachable**

Run: `REMOTE_HOST=ktzlxc mise run smoke-remote`

Expected: pass or record exact environmental failure.

- [x] **Step 2: Run remote share/open smoke if host is reachable**

Run: `REMOTE_HOST=ktzlxc mise run smoke-remote-share`

Expected: pass or record exact environmental failure.

### Task 4: Packaging And Release Boundary Review

**Files:**
- Inspect: `packaging/npm/derphole/bin/derphole.js`
- Inspect: `packaging/npm/derptun/bin/derptun.js`
- Inspect: `tools/packaging/build-npm.sh`
- Inspect: `.github/workflows/release.yml`

- [x] **Step 1: Review local wrapper execution path**

Confirm npm wrappers execute vendored binaries without shell interpolation of user input.

- [x] **Step 2: Run package dry-run verification**

Run: `VERSION=v0.9.1-redteam.20260418 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:npm-dry-run`

Expected: pass or record exact failure.

### Task 5: Report

**Files:**
- Create: `docs/security/2026-04-18-red-team-security-report.md`

- [x] **Step 1: Record scope and evidence**

Write the tested scope, exact commands run, host used, and pass/fail outcomes.

- [x] **Step 2: Record findings**

List confirmed vulnerabilities, hardening changes, residual risks, and recommended follow-up tests. Include file and command evidence.
