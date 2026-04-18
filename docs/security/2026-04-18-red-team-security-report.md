# 2026-04-18 Red Team Security Report

## Scope

This audit covered derptun token authority, rendezvous claim handling, derptun reconnect behavior, shared derphole direct-path transport, npm packaging wrappers, and the GitHub release workflow. Live transport checks used `ktzlxc` and the repository smoke harnesses with Tailscale candidates disabled where the harness supports that mode.

Three parallel review tracks were used:

- Token, rendezvous, and derptun authorization boundaries.
- Transport, direct promotion, reconnect, and cleanup behavior.
- CLI, npm packaging, release workflow, and test harness exposure.

## Fixed Findings

### 1. Malformed derptun client proof MAC accepted at decode

`DecodeClientToken` accepted any non-empty `proof_mac`, leaving malformed proofs to fail later. This was tightened so client tokens require a 32-byte hex HMAC at decode time, and verification now compares decoded MAC bytes.

Evidence:

- Added `TestDecodeClientTokenRejectsMalformedProofMAC` in `pkg/derptun/token_test.go`.
- Changed `pkg/derptun/token.go` to validate proof MAC shape and compare decoded bytes.
- Red phase: the new test failed before the fix.
- Fixed phase: `go test ./pkg/derptun -run TestDecodeClientTokenRejectsMalformedProofMAC -count=1` passed.

### 2. Rendezvous Gate leaked claimed state before authenticating later claims

`Gate.Accept` returned `session already claimed` for a second non-identical claim before validating that claim's MAC and token fields. An unauthenticated actor could distinguish an occupied session. `Gate.Accept` now validates the claim first, then applies duplicate or claimed logic.

Evidence:

- Added `TestGateAuthenticatesSecondClaimBeforeClaimedRejection` in `pkg/rendezvous/rendezvous_test.go`.
- Changed `pkg/rendezvous/state.go` to reuse `validateClaimForToken` before claimed-state checks.
- Red phase: the new test returned `ErrClaimed` before the fix.
- Fixed phase: the test returns `ErrDenied` with `RejectBadMAC`.

### 3. derptun serve trusted claimed DERP key instead of authenticated sender

`handleDerptunServeClaim` derived the reply peer from `claim.DERPPublic` without first checking that the DERP packet sender matched that key. A forged relay packet could cause the server to process a claim as if it came from the embedded DERP key. The serve path now ignores claim packets whose DERP sender does not match `claim.DERPPublic`.

Evidence:

- Added `TestHandleDerptunServeClaimRejectsSourceMismatch` in `pkg/session/derptun_test.go`.
- Changed `pkg/session/derptun.go` to reject sender/key mismatches before token construction or replies.
- Red phase: the test reached the send path with a nil DERP client before the fix.
- Fixed phase: the forged claim is ignored and no tunnel state is claimed.

### 4. derptun server credential expiry was not enforced at claim time

A long-running `serve` process decoded the server token at startup, then later claims could continue using an expired server credential. The claim boundary now checks server expiry and rejects client credentials whose expiry exceeds the server credential.

Evidence:

- Added `TestDerptunServerTokenForClaimRejectsExpiredServerCredential`.
- Added `TestDerptunServerTokenForClaimRejectsClientExpiryPastServerExpiry`.
- Changed `pkg/session/derptun.go` to return structured `RejectExpired` decisions for both cases.
- Fixed phase: `go test ./pkg/rendezvous ./pkg/session -run 'TestGateAuthenticatesSecondClaimBeforeClaimedRejection|TestDerptunServerTokenForClaimRejectsExpiredServerCredential|TestDerptunServerTokenForClaimRejectsClientExpiryPastServerExpiry|TestHandleDerptunServeClaimRejectsSourceMismatch' -count=1` passed.

### 5. Release workflow version values were interpolated into shell bodies

The release workflow inserted `${{ needs.meta.outputs.version }}` directly into shell scripts in build and verification steps. A hostile tag name matching `v*` could become shell syntax. Version data now flows through step `env`, and shell bodies read `$VERSION`.

Evidence:

- Changed `.github/workflows/release.yml` build, binary-version, and npm-artifact steps.
- Added `TestReleaseWorkflowDoesNotInterpolateVersionInShell` in `scripts/release_workflow_test.go`.
- Fixed phase: `go test ./scripts -run TestReleaseWorkflow -count=1` passed.

## Live Evidence

Commands run:

- `REMOTE_HOST=ktzlxc mise run smoke-remote-derptun`
- `REMOTE_HOST=ktzlxc mise run smoke-remote`
- `REMOTE_HOST=ktzlxc mise run smoke-remote-share`
- `VERSION=v0.9.1-redteam.20260418 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:npm-dry-run`

Results:

- `smoke-remote-derptun` passed. The harness covers first connect, server restart with a stable token, active-client contender rejection, dead-client recovery, a second connect, local `open`, and direct-path evidence with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`.
- `smoke-remote` passed and showed `connected-relay` followed by `connected-direct` on local sender, remote listener, local listener, and remote sender traces.
- `smoke-remote-share` passed and showed `connected-relay` followed by `connected-direct` for both share and open traces.
- npm dry-run passed for `derphole@0.9.1-redteam.20260418` and `derptun@0.9.1-redteam.20260418`.

Final repository verification:

- `mise run check` passed after staging formatted Go changes. The command ran `pre-commit run --all-files`, built `dist/derphole` and `dist/derptun`, and ran `go test ./...`.

## Residual Risks

### High: Lossless DERP subscriber queues can grow without a hard cap

`pkg/derpbind/client.go` has `losslessSubscriberQueueSize = 64`, but `packetSubscriber.enqueue` still appends without enforcing that bound. Existing tests currently expect more than 64 backed-up packets to be retained, so fixing this requires an explicit semantic decision: block the receive path, drop with telemetry, close the subscriber, or split critical control streams onto protocol-specific bounded queues.

Recommended next test:

- Add a red test that dispatches far more than `losslessSubscriberQueueSize` matching packets to an unread lossless subscriber and asserts memory is bounded or the subscriber is closed with an explicit error path.

### Medium: Direct UDP promotion probes are not cryptographically bound

Direct promotion uses simple probe and ack payloads. QUIC and session tokens still protect derptun data once the carrier is established, but the promotion probes themselves can be spoofed on-path or same-LAN. Future UDP serving, such as a Minecraft use case, should bind direct probes to the session token with a nonce/MAC and include source-address pinning once a probe is accepted.

Recommended next test:

- Inject forged direct probe, ack, and rate-probe packets from a non-peer source and assert they cannot advance transport state.

### Medium: Remote smoke harnesses use predictable remote paths

The remote shell harnesses use `/tmp/...-$$` names. This is acceptable for controlled hosts like `ktzlxc`, but not for untrusted multi-user systems. Use remote `mktemp -d` and quote host inputs through positional parameters before relying on these harnesses for adversarial shared-host testing.

### Medium: derptun long-lived tokens are commonly passed through argv

Docs and smoke scripts still use `--token "$(cat file)"`. That is ergonomic but exposes long-lived tokens to process listings on some systems. Add `--token-file` or `--token-stdin` support for `serve`, `open`, `connect`, and `token client`.

### Medium: Candidate validation is syntactic, not policy-aware

Claim candidates are bounded by count and string length, but not by candidate class, address family policy, private/public address expectations, or repeated/unreachable endpoints. This should be tightened before UDP service exposure expands.

## Follow-Up Priority

1. Bound or redesign `SubscribeLossless` queues.
2. MAC-bind direct UDP promotion, heartbeat, and rate-probe control packets.
3. Add `--token-file` and update docs/scripts to avoid argv token exposure.
4. Harden remote smoke scripts for untrusted shared hosts.
5. Add adversarial candidate validation tests before enabling UDP tunnel mode.
