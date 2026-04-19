# MAC-Bound Rate-Probe Heartbeats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind direct UDP rate-probe packets and peer heartbeat envelopes to the session bearer secret, reject forged or stale packets, and update the red-team report to reflect the current residual risks.

**Architecture:** Direct UDP rate probes keep the existing fixed magic prefix but add a per-transfer nonce and HMAC derived from the token bearer secret and session ID. The receiver gets the nonce from the authenticated DERP start envelope, accepts only MAC-valid packets from selected remote UDP addresses, and ignores forged probes. Heartbeats add a monotonic sequence and HMAC derived from the same token authority; unauthenticated heartbeat envelopes no longer reset the disconnect timer when auth is configured.

**Tech Stack:** Go standard library `crypto/hmac`, `crypto/rand`, `crypto/sha256`, `encoding/base64`, package-local tests in `pkg/session`, existing `mise` tasks, and the ktzlxc remote smoke harness.

---

### Task 1: Rate-Probe Authentication Tests

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `pkg/session/external_direct_udp.go`

- [ ] **Step 1: Write failing tests for authenticated probe payloads**

Add tests near the existing rate-probe payload/index tests:

```go
func TestExternalDirectUDPRateProbeIndexRejectsForgedMAC(t *testing.T) {
	auth := externalDirectUDPRateProbeAuth{
		Key:   [32]byte{1, 2, 3},
		Nonce: [16]byte{4, 5, 6},
	}
	payload, err := externalDirectUDPRateProbePayload(0, 128, auth)
	if err != nil {
		t.Fatalf("externalDirectUDPRateProbePayload() error = %v", err)
	}
	payload[len(payload)-1] ^= 0x01
	if _, ok := externalDirectUDPRateProbeIndex(payload, 1, auth); ok {
		t.Fatal("forged rate-probe packet was accepted")
	}
}

func TestExternalDirectUDPReceiveRateProbesRejectsUnexpectedSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	allowedSender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer allowedSender.Close()
	forgedSender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer forgedSender.Close()

	auth := externalDirectUDPRateProbeAuth{Key: [32]byte{1}, Nonce: [16]byte{2}}
	payload, err := externalDirectUDPRateProbePayload(0, 128, auth)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp", receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forgedSender.WriteTo(payload, remote); err != nil {
		t.Fatal(err)
	}

	samples, err := externalDirectUDPReceiveRateProbes(ctx, []net.PacketConn{receiver}, []string{allowedSender.LocalAddr().String()}, []int{8}, auth)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveRateProbes() error = %v", err)
	}
	if samples[0].BytesReceived != 0 {
		t.Fatalf("forged source counted %d bytes, want 0", samples[0].BytesReceived)
	}
}
```

- [ ] **Step 2: Run red tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalDirectUDPRateProbeIndexRejectsForgedMAC|TestExternalDirectUDPReceiveRateProbesRejectsUnexpectedSource' -count=1
```

Expected: fail to compile or fail because the production functions do not yet accept auth/source parameters.

- [ ] **Step 3: Implement minimal rate-probe auth**

In `pkg/session/external_direct_udp.go`, add `externalDirectUDPRateProbeAuth`, HMAC helpers, nonce encoding/decoding, and source allow-list checks. Change the rate-probe send/receive helpers and their function variables to accept auth and selected remote addresses.

- [ ] **Step 4: Verify green rate-probe tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalDirectUDPRateProbeIndexRejectsForgedMAC|TestExternalDirectUDPReceiveRateProbesRejectsUnexpectedSource|TestExternalDirectUDPRateProbePayloadEncodesIndex|TestExternalDirectUDPSendRateProbes' -count=1
```

Expected: pass.

### Task 2: Heartbeat Authentication Tests

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `pkg/session/external.go`
- Create or modify: `pkg/session/external_control_security.go`

- [ ] **Step 1: Write failing tests for authenticated heartbeats**

Add tests near `TestPeerControlContextCancelsWhenHeartbeatsStop`:

```go
func TestPeerControlContextIgnoresUnauthenticatedHeartbeatWhenAuthConfigured(t *testing.T) {
	prevTimeout := peerHeartbeatTimeout
	peerHeartbeatTimeout = 25 * time.Millisecond
	t.Cleanup(func() { peerHeartbeatTimeout = prevTimeout })

	heartbeatCh := make(chan derpbind.Packet, 1)
	payload, err := json.Marshal(envelope{Type: envelopeHeartbeat, Heartbeat: newPeerHeartbeat(0)})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatCh <- derpbind.Packet{Payload: payload}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := externalPeerControlAuth{HeartbeatKey: [32]byte{1, 2, 3}}
	transferCtx, stop := withPeerControlContext(ctx, nil, key.NodePublic{}, nil, heartbeatCh, nil, auth)
	defer stop()

	select {
	case <-transferCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("unauthenticated heartbeat kept context alive")
	}
	if !errors.Is(context.Cause(transferCtx), ErrPeerDisconnected) {
		t.Fatalf("context cause = %v, want %v", context.Cause(transferCtx), ErrPeerDisconnected)
	}
}

func TestPeerHeartbeatRejectsReplay(t *testing.T) {
	auth := externalPeerControlAuth{HeartbeatKey: [32]byte{1, 2, 3}}
	hb := newAuthenticatedPeerHeartbeat(12, 1, auth)
	var last uint64
	if !verifyPeerHeartbeat(hb, auth, &last) {
		t.Fatal("first authenticated heartbeat was rejected")
	}
	if verifyPeerHeartbeat(hb, auth, &last) {
		t.Fatal("replayed heartbeat was accepted")
	}
}
```

- [ ] **Step 2: Run red tests**

Run:

```bash
go test ./pkg/session -run 'TestPeerControlContextIgnoresUnauthenticatedHeartbeatWhenAuthConfigured|TestPeerHeartbeatRejectsReplay' -count=1
```

Expected: fail to compile or fail because heartbeat auth is not implemented yet.

- [ ] **Step 3: Implement minimal heartbeat auth**

Add `externalPeerControlAuth`, derive it from `token.Token`, add `sequence` and `mac` fields to `peerHeartbeat`, sign heartbeats in the sender goroutine, and verify MAC plus increasing sequence in the receiver goroutine when auth is enabled. Update all `withPeerControlContext` call sites to pass token-derived auth.

- [ ] **Step 4: Verify green heartbeat tests**

Run:

```bash
go test ./pkg/session -run 'TestPeerControlContext|TestPeerHeartbeat' -count=1
```

Expected: pass.

### Task 3: Report Update and Verification

**Files:**
- Modify: `docs/security/2026-04-18-red-team-security-report.md`

- [ ] **Step 1: Update residual-risk status**

Move the previously fixed residuals into a post-remediation section, keep the controlled-host `/tmp` harness note as accepted development risk, and list only remaining lower-priority work.

- [ ] **Step 2: Run local verification**

Run:

```bash
OLD_NAME="$(printf 'derp%s' 'cat')"
OLD_PREFIX="$(printf 'derp-%s' 'c')"
OLD_SPLIT="$(printf \"d', 'e', 'r', 'p', '%s'\" c)"
rg -n "${OLD_NAME}|${OLD_PREFIX}|${OLD_SPLIT}" --hidden -g '!dist/**' -g '!node_modules/**' -g '!.git/**' .
go test ./pkg/session -run 'RateProbe|PeerControlContext|PeerHeartbeat|ExternalDirectUDP' -count=1
mise run check
```

Expected: the old-name scan has no matches, focused tests pass, and `mise run check` exits 0.

- [ ] **Step 3: Run live ktzlxc smoke**

Run:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-derptun
```

Expected: pass with only known remote locale warnings.

- [ ] **Step 4: Commit, push, and watch CI**

Use scoped commits:

```bash
git add pkg/session/external.go pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go docs/security/2026-04-18-red-team-security-report.md
git commit -m "session: authenticate direct udp control packets"
git push origin main
gh run list --repo shayne/derphole --branch main --limit 10 --json databaseId,headSha,status,conclusion,name,workflowName,url,createdAt
```

Watch `Checks`, `Release`, and `Pages` for the pushed SHA.

---

## Self-Review

- Spec coverage: The plan covers report update, authenticated/source-pinned rate probes, authenticated heartbeats, adversarial tests, ktzlxc live smoke, push, and CI watching.
- Placeholder scan: No `TBD`, `TODO`, or open-ended implementation placeholders remain.
- Type consistency: The plan uses one `externalDirectUDPRateProbeAuth` type for rate probes and one `externalPeerControlAuth` type for heartbeat control. All production call sites pass token-derived auth.
