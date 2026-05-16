# Peer Cancel Abort Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make local Ctrl-C/context cancellation notify the peer immediately with authenticated abort semantics across send, receive, relay, WireGuard, and direct-UDP receive paths.

**Architecture:** The existing authenticated peer-control envelope already supports `abort`, heartbeat, progress, and ACK messages. The fix is to install the existing `notifyPeerAbortOnLocalCancel` hook in every function that owns a `withPeerControlContext`, keeping it before peer-control teardown so DERP subscriptions and clients are still live. A focused offer/receive regression test proves the user-visible bug: canceling the receiver makes the sender return `ErrPeerAborted` within seconds instead of waiting for heartbeat or ACK timeout.

**Tech Stack:** Go, DERP peer-control envelopes, existing session package test DERP server, `mise` verification tasks.

---

## File Structure

- Modify `pkg/session/offer_test.go`
  - Add an external offer/receive regression test where the receive side is canceled and the offer side must exit with `ErrPeerAborted` quickly.
  - Add the `errors` import used by the new assertions and pipe-writer cleanup.
- Modify `pkg/session/external_offer.go`
  - Add local-cancel abort notification to `sendExternalAcceptedOffer`.
  - Add local-cancel abort notification to `receiveExternal`.
- Modify `pkg/session/external_wg.go`
  - Add local-cancel abort notification to `sendExternalViaWGTunnel`.
  - Add local-cancel abort notification to `receiveExternalWGAcceptedClaim`.
- Modify `pkg/session/external_direct_udp.go`
  - Add local-cancel abort notification to `externalDirectUDPListenRuntime.receiveAccepted`.
- Verify with focused tests, full session tests, full project tests, and live cancel runs against user-approved hosts.

## Task 1: Add the Receiver-Cancel Regression Test

**Files:**
- Modify: `pkg/session/offer_test.go`

- [ ] **Step 1: Add the missing import**

Add `errors` to the import block:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
```

- [ ] **Step 2: Add the failing regression test**

Add this test after `TestPublicRelayOnlyOfferedStdioRoundTrip`:

```go
func TestPublicRelayOnlyOfferExitsWhenReceiverCancels(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var senderStatus syncBuffer
	var receiverStatus syncBuffer
	pipeReader, pipeWriter := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		chunk := bytes.Repeat([]byte("receiver-cancel-offer:"), 32*1024/len("receiver-cancel-offer:"))
		for {
			if _, err := pipeWriter.Write(chunk); err != nil {
				if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled) {
					writeDone <- nil
					return
				}
				writeDone <- err
				return
			}
		}
	}()
	defer func() {
		_ = pipeWriter.CloseWithError(context.Canceled)
		_ = pipeReader.Close()
		select {
		case err := <-writeDone:
			if err != nil {
				t.Errorf("pipe writer error = %v", err)
			}
		case <-time.After(time.Second):
			t.Errorf("pipe writer did not exit")
		}
	}()

	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioIn:       pipeReader,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		offerErr <- err
	}()

	var tok string
	select {
	case tok = <-tokenSink:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offered token: %v; sender=%q receiver=%q", ctx.Err(), senderStatus.String(), receiverStatus.String())
	}

	receiveCtx, cancelReceive := context.WithCancel(ctx)
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(receiveCtx, ReceiveConfig{
			Token:         tok,
			Emitter:       telemetry.New(&receiverStatus, telemetry.LevelVerbose),
			StdioOut:      io.Discard,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
	if err := waitForSessionTestStatusContains(waitCtx, &receiverStatus, string(StateRelay)); err != nil {
		waitCancel()
		t.Fatalf("receiver did not reach relay before cancellation: %v; sender=%q receiver=%q", err, senderStatus.String(), receiverStatus.String())
	}
	waitCancel()

	cancelReceive()

	select {
	case err := <-receiveErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive() error = %v, want %v; sender=%q receiver=%q", err, context.Canceled, senderStatus.String(), receiverStatus.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Receive() did not exit after cancellation; sender=%q receiver=%q", senderStatus.String(), receiverStatus.String())
	}

	select {
	case err := <-offerErr:
		if !errors.Is(err, ErrPeerAborted) {
			t.Fatalf("Offer() error = %v, want %v; sender=%q receiver=%q", err, ErrPeerAborted, senderStatus.String(), receiverStatus.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Offer() did not exit after receiver cancellation; sender=%q receiver=%q", senderStatus.String(), receiverStatus.String())
	}
}
```

- [ ] **Step 3: Run the new test and verify it fails before the fix**

Run:

```bash
go test ./pkg/session -run TestPublicRelayOnlyOfferExitsWhenReceiverCancels -count=1
```

Expected before implementation:

```text
FAIL: Offer() did not exit after receiver cancellation
```

## Task 2: Install Local-Cancel Abort Hooks

**Files:**
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/external_wg.go`
- Modify: `pkg/session/external_direct_udp.go`

- [ ] **Step 1: Add offer-side sender local-cancel notification and normalize its returned error**

In `sendExternalAcceptedOffer`, use a named return and change the peer-control defers to:

```go
func sendExternalAcceptedOffer(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, peerDERP key.NodePublic, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg OfferConfig, callerRetErr *error) (retErr error) {
	var countedSrc *byteCountingReadCloser
	abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalOfferPeerControl(session, peerDERP)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)
	defer stopPeerAbort()
	defer func() {
		if callerRetErr != nil {
			*callerRetErr = retErr
		}
	}()
	defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)
```

- [ ] **Step 2: Add offer-side receiver local-cancel notification**

In `receiveExternal`, change the peer-control defers to:

```go
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedDstCount, runtime.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedDstCount, runtime.auth)
```

- [ ] **Step 3: Add WireGuard sender local-cancel notification**

In `sendExternalViaWGTunnel`, change the peer-control defers to:

```go
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedSrc.Count, runtime.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedSrc.Count, runtime.auth)
```

- [ ] **Step 4: Add WireGuard receiver local-cancel notification and normalize its returned error**

In `receiveExternalWGAcceptedClaim`, use a named return and change the peer-control defers to:

```go
func receiveExternalWGAcceptedClaim(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, peerDERP key.NodePublic, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg ListenConfig, callerRetErr *error) (retErr error) {
	var countedDst *byteCountingWriteCloser
	abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalWGListenPeer(session, peerDERP)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
		return externalWGCountedDstCount(countedDst)
	}, auth)
	defer stopPeerAbort()
	defer func() {
		if callerRetErr != nil {
			*callerRetErr = retErr
		}
	}()
	defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalWGCountedDstCount(countedDst)
	}, auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalWGCountedDstCount(countedDst)
	}, auth)
```

- [ ] **Step 5: Add direct-UDP listener local-cancel notification**

In `externalDirectUDPListenRuntime.receiveAccepted`, change the peer-control defers to:

```go
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, rt.session.derp, accepted.peerDERP, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, rt.session.derp, accepted.peerDERP, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)
```

- [ ] **Step 6: Run gofmt**

Run:

```bash
gofmt -w pkg/session/offer_test.go pkg/session/external_offer.go pkg/session/external_wg.go pkg/session/external_direct_udp.go
```

- [ ] **Step 7: Run the focused regression test and verify it passes**

Run:

```bash
go test ./pkg/session -run TestPublicRelayOnlyOfferExitsWhenReceiverCancels -count=1
```

Expected after implementation:

```text
ok  	github.com/shayne/derphole/pkg/session
```

## Task 3: Verify Existing Peer-Abort Semantics Still Hold

**Files:**
- Test only

- [ ] **Step 1: Run existing peer-control unit tests**

Run:

```bash
go test ./pkg/session -run 'TestNotifyPeerAbortOnLocalCancelSendsAbortEnvelope|TestPeerAbortErrorShouldNotifySkipsLocalContextCancellation|TestPeerControlContextCancelsOnPeerAbort|TestWaitForPeerAckReturnsPeerAborted|TestSendClaimAndReceiveDecisionReturnsPeerAborted' -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

- [ ] **Step 2: Run session package tests**

Run:

```bash
go test ./pkg/session -count=1
```

Expected:

```text
ok  	github.com/shayne/derphole/pkg/session
```

- [ ] **Step 3: Run project checks**

Run:

```bash
mise run test
mise run vet
mise run check
```

Expected:

```text
All three commands exit 0.
```

## Task 4: Live Cancel Validation

**Files:**
- Test only

- [ ] **Step 1: Build the local binary**

Run:

```bash
mise run build
```

Expected:

```text
dist/derphole exists and is executable.
```

- [ ] **Step 2: Validate relay receiver-cancel against `pve1` and `canlxc`**

Run one sender on the local machine and one receiver on the remote host using the locally built binary copied or available through the existing harness path. Use `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1` to force the public relay path:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./dist/derphole --verbose send ~/1GBFile
```

On the remote host:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./derphole --verbose receive <token-from-sender>
```

After the receiver reaches `connected-relay`, press `Ctrl-C` on the receiver. Expected sender behavior:

```text
context canceled or peer aborted state appears within 3 seconds, and the sender process exits without waiting for heartbeat timeout.
```

- [ ] **Step 3: Validate direct-UDP receiver-cancel against `pve1` and `canlxc`**

Run the same transfer without `DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1`. After the receiver reaches `connected-direct` or `udp-blast=true`, press `Ctrl-C` on the receiver. Expected sender behavior:

```text
the sender exits within 3 seconds with peer-abort semantics, without hanging in final ACK wait.
```

- [ ] **Step 4: Check for UDP socket buildup after live cancellation**

Before and after each live cancellation run, sample UDP sockets:

```bash
lsof -nP -iUDP | rg 'derphole|node|npx' || true
```

Expected:

```text
no growing set of leftover derphole UDP sockets after both sides exit.
```

## Task 5: Commit and Push

**Files:**
- Commit all modified source and test files

- [ ] **Step 1: Inspect final diff**

Run:

```bash
git diff -- pkg/session/offer_test.go pkg/session/external_offer.go pkg/session/external_wg.go pkg/session/external_direct_udp.go
git status --short
```

Expected:

```text
Only the planned files are modified, plus this plan file.
```

- [ ] **Step 2: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-16-peer-cancel-abort-hardening.md pkg/session/offer_test.go pkg/session/external_offer.go pkg/session/external_wg.go pkg/session/external_direct_udp.go
git commit -m "fix: abort peer on local transfer cancel"
```

Expected:

```text
commit succeeds.
```

- [ ] **Step 3: Push main**

Run:

```bash
git push origin main
```

Expected:

```text
push succeeds.
```

## Self-Review

- Spec coverage: The plan covers receiver Ctrl-C sending an authenticated abort, sender Ctrl-C parity in offer and WireGuard paths, direct-UDP receive local cancel, final ACK interruption through existing peer-control context cancellation, returned-error normalization after peer abort, and test/live validation.
- Placeholder scan: The plan contains no `TBD`, `TODO`, deferred implementation, or unnamed test work.
- Type consistency: The snippets use existing functions and types: `notifyPeerAbortOnLocalCancel`, `externalOfferCountedSrcCount`, `externalWGCountedDstCount`, `externalDirectUDPCountedDstBytes`, `syncBuffer`, `Offer`, `Receive`, and `ErrPeerAborted`.
