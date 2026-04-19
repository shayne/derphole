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

## Post-Report Remediations

### 6. Lossless DERP subscriber queues are bounded

`SubscribeLossless` now enforces a bounded queue instead of appending without a hard cap. This removes the high-priority unbounded memory risk for critical DERP control subscribers.

Evidence:

- Added bounded-queue regression coverage for backed-up lossless subscribers.
- Focused derpbind tests passed with `go test ./pkg/derpbind -run 'TestClientSubscribeLossless' -count=1`.

### 7. Direct UDP promotion probes are MAC-bound

Direct promotion now derives a transport discovery key from the bearer token and DERP identities. MAC-bound probe and ack payloads replace static probe acceptance for token-backed sessions, and legacy discovery payloads are rejected when a discovery key is configured.

Evidence:

- Added MAC-bound discovery tests in `pkg/transport` and token-derived discovery-key tests in `pkg/session`.
- Focused transport/session tests passed for MAC-bound direct promotion and legacy-payload rejection.

### 8. derptun tokens can avoid argv exposure

The derptun CLI now supports file/stdin token inputs in addition to inline tokens. This lets operators keep long-lived server and client credentials out of process listings while preserving the simple inline-token path for low-risk local use.

Evidence:

- Added CLI coverage for token file/stdin inputs across derptun serve, open, connect, and client-token flows.
- Focused derptun command tests passed with token-file and token-stdin paths.

### 9. Candidate validation rejects policy-invalid claims

Candidate handling now validates beyond raw string shape. Claim candidates are bounded and policy-checked before they can influence rendezvous or transport setup.

Evidence:

- Added adversarial candidate validation tests in `pkg/candidate`, `pkg/rendezvous`, `pkg/session`, and `pkg/transport`.
- Focused candidate/rendezvous/session/transport tests passed for malformed, repeated, and policy-invalid candidate inputs.

### 10. Direct UDP rate probes and heartbeats are authenticated

Direct UDP rate-probe packets now include a per-transfer nonce and HMAC derived from the token bearer secret and session ID. The receiver accepts only MAC-valid probe packets from selected remote UDP addresses. Peer heartbeat envelopes now include a monotonic sequence and HMAC, and authenticated sessions ignore unauthenticated or replayed heartbeat envelopes.

Evidence:

- Added `TestExternalDirectUDPRateProbeIndexRejectsForgedMAC`.
- Added `TestExternalDirectUDPReceiveRateProbesRejectsUnexpectedSource`.
- Added `TestPeerControlContextIgnoresUnauthenticatedHeartbeatWhenAuthConfigured`.
- Added `TestPeerHeartbeatRejectsReplay`.
- Fixed phase: `go test ./pkg/session -run 'TestExternalDirectUDPRateProbeIndexRejectsForgedMAC|TestExternalDirectUDPReceiveRateProbesRejectsUnexpectedSource|TestPeerControlContextIgnoresUnauthenticatedHeartbeatWhenAuthConfigured|TestPeerHeartbeatRejectsReplay' -count=1` passed.

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

### Accepted development risk: Remote smoke harnesses use predictable remote paths

The remote shell harnesses use `/tmp/...-$$` names. This is acceptable for controlled hosts like `ktzlxc`, but not for untrusted multi-user systems. Use remote `mktemp -d` and quote host inputs through positional parameters before relying on these harnesses for adversarial shared-host testing.

### Low: Not every DERP control envelope has its own MAC

Heartbeat envelopes now have a message MAC and replay check, and DERP sender identity filtering still gates abort, ack, mode, and rendezvous control traffic. If the threat model expands to include malicious relays or compromised peer identities, extend the same envelope-level MAC pattern to those remaining control message types.

## Follow-Up Priority

1. Keep ktzlxc smoke coverage in the release loop with `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1` so direct-path claims are not accidentally satisfied by Tailscale.
2. Harden remote smoke scripts with `mktemp -d` before using them on untrusted multi-user hosts.
3. Consider envelope-level MACs for abort, ack, and mode-control messages if the DERP relay threat model becomes stricter.
