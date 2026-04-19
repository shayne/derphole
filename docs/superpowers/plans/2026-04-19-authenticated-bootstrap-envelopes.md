# Authenticated Bootstrap Envelopes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require token-derived MACs on claim and decision DERP envelopes so the bootstrap path has the same generic envelope authentication as post-claim control traffic.

**Architecture:** Reuse the existing `externalPeerControlAuth.EnvelopeKey` and envelope MAC helpers. Claim senders sign claim envelopes with the token bearer secret, listeners verify the claim envelope before `Gate.Accept`, and decision senders sign decisions so claim callers ignore forged or unsigned decisions. Derptun serve derives the per-client envelope key from client token fields, verifies the outer claim envelope before accepting the claim, and keeps the existing client proof plus rendezvous bearer MAC checks.

**Tech Stack:** Go standard library HMAC/SHA-256, existing `pkg/session` DERP envelope helpers, existing `pkg/rendezvous` bearer MAC validation, existing smoke scripts with `ktzlxc`.

---

### Task 1: Add Bootstrap Envelope Regression Tests

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `pkg/session/derptun_test.go`

- [x] Add `TestSendClaimAndReceiveDecisionIgnoresUnsignedDecisionWhenAuthConfigured` in `pkg/session/external_direct_udp_test.go`. It uses `newSessionTestDERPServer`, sends an unsigned reject decision before a signed accept decision, and expects the signed decision to win.

- [x] Add `TestHandleDerptunServeClaimRejectsUnsignedEnvelope` in `pkg/session/derptun_test.go`. It sends an unsigned claim envelope carrying a valid derptun client bearer claim and expects `handleDerptunServeClaim` to ignore it without claiming the gate.

- [x] Run the focused tests before production changes:

```bash
go test ./pkg/session -run 'TestSendClaimAndReceiveDecisionIgnoresUnsignedDecisionWhenAuthConfigured|TestHandleDerptunServeClaimRejectsUnsignedEnvelope' -count=1
```

Observed red phase: build failed because `sendClaimAndReceiveDecision` did not yet accept `externalPeerControlAuth`.

### Task 2: Sign and Verify Claim/Decision Envelopes

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_wg.go`
- Modify: `pkg/session/external_attach.go`
- Modify: `pkg/session/derptun.go`

- [x] Change `sendClaimAndReceiveDecision` to accept an optional `externalPeerControlAuth`, sign claim sends with `sendAuthenticatedEnvelope`, and decode decisions with `decodeAuthenticatedEnvelope`.

- [x] In listener-side claim loops, use `externalPeerControlAuthForToken(session.token)` to decode claim envelopes before deriving `peerDERP` or calling `Gate.Accept`.

- [x] Send all accept/reject decision envelopes with `sendAuthenticatedEnvelope` when auth is available.

- [x] In derptun serve, decode the raw claim to identify the client token fields, derive the client envelope key, then require `verifyEnvelopeMAC` before accepting or replying.

- [x] Keep the existing rendezvous bearer MAC validation in place. The generic envelope MAC is an outer DERP envelope authentication layer, not a replacement for claim bearer validation.

- [x] Run the focused tests again:

```bash
go test ./pkg/session -run 'TestSendClaimAndReceiveDecisionIgnoresUnsignedDecisionWhenAuthConfigured|TestHandleDerptunServeClaimRejectsUnsignedEnvelope' -count=1
```

Observed green phase: both tests passed.

### Task 3: Update Security Report and Run Live Share Smoke

**Files:**
- Modify: `docs/security/2026-04-18-red-team-security-report.md`

- [x] Update the report to mark claim/decision generic envelope MAC coverage addressed.

- [x] Run local package verification:

```bash
mise run check
```

- [x] Run live share coverage without Tailscale candidates:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-share
```

- [ ] Commit and push:

```bash
git add pkg/session docs/security docs/superpowers/plans
git commit -m "security: authenticate bootstrap envelopes"
git push origin main
```

- [ ] Watch CI:

```bash
gh run list --repo shayne/derphole --branch main --limit 5
gh run watch --repo shayne/derphole <run-id> --exit-status
```

Expected: local verification, live share smoke, and CI pass.
