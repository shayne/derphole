# Authenticated Control Envelopes And Remote Mktemp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the remaining security recommendations by authenticating DERP control envelopes and replacing predictable remote smoke paths with remote `mktemp -d` directories.

**Architecture:** Add a token-derived envelope MAC alongside the existing heartbeat and rate-probe MACs. Signing is applied to low-rate control envelopes after claim/decision, and receivers verify before acting on ACK, abort, direct UDP, QUIC mode, transport control, and parallel growth messages. Remote smoke scripts create one private remote temp directory and put binaries, logs, pid files, and tokens inside it.

**Tech Stack:** Go standard library HMAC/SHA-256, existing `pkg/session` envelope transport, Bash, existing `mise` tasks.

---

### Task 1: Guard Remote Smoke Scripts

**Files:**
- Modify: `scripts/smoke-remote.sh`
- Modify: `scripts/smoke-remote-share.sh`
- Modify: `scripts/smoke-remote-relay.sh`
- Modify: `scripts/smoke-remote-derptun.sh`
- Create: `scripts/remote_smoke_scripts_test.go`

- [ ] Add a Go test that scans remote smoke scripts and fails if they use predictable `/tmp/...-$$` paths.
- [ ] Update each script to allocate `remote_tmp="$(remote 'mktemp -d "${TMPDIR:-/tmp}/name.XXXXXXXXXX"')"` after `remote()` is defined.
- [ ] Place all remote pid/log/binary/token files under that temp directory.
- [ ] Make cleanup remove the remote temp directory with `rm -rf -- "$remote_tmp"` and tolerate unset temp variables.
- [ ] Run `go test ./scripts -run TestRemoteSmokeScriptsUseRemoteMktemp -count=1`.

### Task 2: Add Generic Envelope MACs

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_control_security.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_wg.go`
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/external_parallel.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] Add a `mac` field to the envelope wrapper.
- [ ] Extend `externalPeerControlAuth` with an `EnvelopeKey` derived from the token bearer secret and session ID.
- [ ] Add helpers to sign envelopes, verify envelopes, and send signed envelopes.
- [ ] Write tests proving unsigned/tampered ACKs, direct UDP starts, and transport controls are ignored when auth is configured.
- [ ] Wire signing and verification into ACK, abort, heartbeat wrapper, direct UDP ready/start/rate-probe control, transport control, QUIC mode control, and parallel growth control.
- [ ] Preserve zero-auth behavior for existing tests and legacy helper paths.
- [ ] Run focused `pkg/session` security tests.

### Task 3: Verify, Document, And Publish

**Files:**
- Modify: `docs/security/2026-04-18-red-team-security-report.md`

- [ ] Update the report residuals so remote smoke temp handling and remaining envelope MAC work are marked addressed.
- [ ] Run `rg` old-name scan.
- [ ] Run `mise run check`.
- [ ] Run `REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-derptun`.
- [ ] Run at least one regular remote smoke script with the same direct-only environment.
- [ ] Commit, push `main`, and watch Checks, Release, and Pages.
