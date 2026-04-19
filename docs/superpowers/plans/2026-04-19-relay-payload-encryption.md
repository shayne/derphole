# Relay Payload Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure DERP relay paths never carry plaintext user payload bytes after token authorization.

**Architecture:** Reuse the token-derived one-shot session AEAD for every one-shot data path. Direct UDP keeps its current packet protection, force-relay probe packets get the same `PacketAEAD`, and relay-prefix `Data` frames encrypt only user payload bytes while authenticating the visible frame header as associated data.

**Tech Stack:** Go, AES-GCM through `crypto/cipher`, existing `pkg/probe` `PacketAEAD`, existing `pkg/session` relay-prefix handoff, `mise` tasks, remote smoke tests against `ktzlxc`.

---

## File Structure

- Modify `pkg/session/external_direct_udp.go`
  - Rename the direct-UDP AEAD helper to a transport-neutral session AEAD helper.
  - Add relay-prefix data-frame AEAD encode/decode helpers.
  - Pass AEAD through relay-prefix send/receive paths.
  - Pass AEAD into force-relay probe send/receive configs.
  - Add a test-only plaintext marker guard for live smoke instrumentation.
- Modify `pkg/session/external.go`
  - Run the test-only marker guard before transport data is handed to DERP.
- Modify `pkg/session/external_offer.go`
  - Pass the full token into force-relay helpers instead of only `SessionID`.
- Modify `pkg/session/external_direct_udp_test.go`
  - Add red tests for relay-prefix encryption, wrong-key rejection, tamper rejection, plaintext rejection, force-relay `PacketAEAD` wiring, and the marker guard.
  - Update existing relay-prefix tests to pass AEAD into changed helper signatures.
- Modify `scripts/smoke-remote-relay.sh`
  - Add a live marker that fails if outbound DERP relay payloads contain plaintext.
- Modify `README.md`
  - Update Security Model after tests pass.

## Task 1: Add Red Tests For Relay-Prefix Data Encryption

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add test imports**

Add `crypto/cipher` and `encoding/binary` to the import block in `pkg/session/external_direct_udp_test.go`:

```go
import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)
```

- [ ] **Step 2: Add token and legacy-frame helpers**

Add these helpers near the other test helpers at the bottom of `pkg/session/external_direct_udp_test.go`:

```go
func testExternalSessionToken(seed byte) token.Token {
	var tok token.Token
	tok.Version = token.SupportedVersion
	tok.ExpiresUnix = time.Now().Add(time.Hour).Unix()
	tok.Capabilities = token.CapabilityStdio
	for i := range tok.SessionID {
		tok.SessionID[i] = seed + byte(i)
	}
	for i := range tok.BearerSecret {
		tok.BearerSecret[i] = seed ^ byte(i+1)
	}
	return tok
}

func testExternalSessionAEAD(t *testing.T, seed byte) cipher.AEAD {
	t.Helper()
	aead, err := externalSessionPacketAEAD(testExternalSessionToken(seed))
	if err != nil {
		t.Fatalf("externalSessionPacketAEAD() error = %v", err)
	}
	return aead
}

func legacyRelayPrefixDERPDataFrame(t *testing.T, offset int64, payload []byte) []byte {
	t.Helper()
	if offset < 0 {
		t.Fatalf("negative offset %d", offset)
	}
	out := make([]byte, 25+len(payload))
	copy(out[:16], externalRelayPrefixDERPMagic[:])
	out[16] = byte(externalRelayPrefixDERPFrameData)
	binary.BigEndian.PutUint64(out[17:25], uint64(offset))
	copy(out[25:], payload)
	return out
}
```

- [ ] **Step 3: Add relay-prefix AEAD tests**

Add these tests near the existing relay-prefix DERP tests in `pkg/session/external_direct_udp_test.go`:

```go
func TestExternalRelayPrefixDERPDataFrameEncryptsAndAuthenticates(t *testing.T) {
	aead := testExternalSessionAEAD(t, 0x41)
	wrongAEAD := testExternalSessionAEAD(t, 0x42)
	plaintext := []byte("relay-prefix-secret-marker")

	wire, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameData, 64, plaintext, aead)
	if err != nil {
		t.Fatalf("externalRelayPrefixDERPPayload() error = %v", err)
	}
	if externalRelayPrefixDERPFrameKindOf(wire) != externalRelayPrefixDERPFrameData {
		t.Fatalf("frame kind = %v, want data", externalRelayPrefixDERPFrameKindOf(wire))
	}
	if bytes.Contains(wire, plaintext) {
		t.Fatalf("encrypted relay-prefix frame contains plaintext marker: %x", wire)
	}

	got, err := externalRelayPrefixDERPDecodeChunk(wire, aead)
	if err != nil {
		t.Fatalf("externalRelayPrefixDERPDecodeChunk() error = %v", err)
	}
	if got.Offset != 64 {
		t.Fatalf("offset = %d, want 64", got.Offset)
	}
	if !bytes.Equal(got.Payload, plaintext) {
		t.Fatalf("payload = %q, want %q", got.Payload, plaintext)
	}

	if _, err := externalRelayPrefixDERPDecodeChunk(wire, wrongAEAD); err == nil {
		t.Fatal("DecodeChunk() with wrong AEAD succeeded, want authentication failure")
	}
}

func TestExternalRelayPrefixDERPDataFrameRejectsPlaintextAndTamper(t *testing.T) {
	aead := testExternalSessionAEAD(t, 0x51)
	plaintext := []byte("legacy-plaintext-marker")

	legacy := legacyRelayPrefixDERPDataFrame(t, 7, plaintext)
	if _, err := externalRelayPrefixDERPDecodeChunk(legacy, aead); err == nil {
		t.Fatal("DecodeChunk() accepted legacy plaintext relay-prefix data frame")
	}

	wire, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameData, 7, plaintext, aead)
	if err != nil {
		t.Fatalf("externalRelayPrefixDERPPayload() error = %v", err)
	}

	tamperedCiphertext := append([]byte(nil), wire...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0x80
	if _, err := externalRelayPrefixDERPDecodeChunk(tamperedCiphertext, aead); err == nil {
		t.Fatal("DecodeChunk() accepted tampered ciphertext")
	}

	tamperedHeader := append([]byte(nil), wire...)
	tamperedHeader[24] ^= 0x01
	if _, err := externalRelayPrefixDERPDecodeChunk(tamperedHeader, aead); err == nil {
		t.Fatal("DecodeChunk() accepted tampered associated-data header")
	}
}
```

- [ ] **Step 4: Run red tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalRelayPrefixDERPDataFrame' -count=1
```

Expected: FAIL to compile because `externalSessionPacketAEAD` does not exist and `externalRelayPrefixDERPPayload` / `externalRelayPrefixDERPDecodeChunk` do not yet accept `cipher.AEAD`.

## Task 2: Implement Session AEAD And Relay-Prefix Data Encryption

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Rename the direct-UDP AEAD helper**

In `pkg/session/external_direct_udp.go`, replace:

```go
var externalDirectUDPPacketAEADDomain = []byte("derphole-direct-udp-packet-aead-v1")
```

with:

```go
var externalSessionPacketAEADDomain = []byte("derphole-session-packet-aead-v1")
var externalRelayPrefixDERPDataNonceDomain = []byte("derphole-relay-prefix-derp-data-nonce-v1")
```

Replace `externalDirectUDPPacketAEAD` with:

```go
func externalSessionPacketAEAD(tok token.Token) (cipher.AEAD, error) {
	hash := sha256.New()
	_, _ = hash.Write(externalSessionPacketAEADDomain)
	_, _ = hash.Write(tok.SessionID[:])
	_, _ = hash.Write(tok.BearerSecret[:])
	block, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
```

Then replace the existing direct UDP calls:

```go
packetAEAD, err := externalDirectUDPPacketAEAD(tok)
```

with:

```go
packetAEAD, err := externalSessionPacketAEAD(tok)
```

- [ ] **Step 2: Add relay-prefix header and nonce helpers**

Replace `externalRelayPrefixDERPPayload` with this implementation and add the helper functions directly above it:

```go
const externalRelayPrefixDERPHeaderSize = 25

func externalRelayPrefixDERPHeader(kind externalRelayPrefixDERPFrameKind, offset int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("negative relay-prefix DERP offset %d", offset)
	}
	out := make([]byte, externalRelayPrefixDERPHeaderSize)
	copy(out[:16], externalRelayPrefixDERPMagic[:])
	out[16] = byte(kind)
	binary.BigEndian.PutUint64(out[17:25], uint64(offset))
	return out, nil
}

func externalRelayPrefixDERPDataNonce(header []byte) ([12]byte, error) {
	var nonce [12]byte
	if len(header) != externalRelayPrefixDERPHeaderSize {
		return nonce, fmt.Errorf("relay-prefix DERP header length = %d, want %d", len(header), externalRelayPrefixDERPHeaderSize)
	}
	hash := sha256.New()
	_, _ = hash.Write(externalRelayPrefixDERPDataNonceDomain)
	_, _ = hash.Write(header)
	sum := hash.Sum(nil)
	copy(nonce[:], sum[:len(nonce)])
	return nonce, nil
}

func externalRelayPrefixDERPPayload(kind externalRelayPrefixDERPFrameKind, offset int64, payload []byte, packetAEAD cipher.AEAD) ([]byte, error) {
	header, err := externalRelayPrefixDERPHeader(kind, offset)
	if err != nil {
		return nil, err
	}
	if kind != externalRelayPrefixDERPFrameData {
		if len(payload) != 0 {
			return nil, errors.New("relay-prefix DERP control frame cannot carry payload")
		}
		return header, nil
	}
	if packetAEAD == nil {
		return nil, errors.New("nil relay-prefix DERP data AEAD")
	}
	if packetAEAD.NonceSize() != 12 {
		return nil, errors.New("unsupported relay-prefix DERP data AEAD nonce size")
	}
	nonce, err := externalRelayPrefixDERPDataNonce(header)
	if err != nil {
		return nil, err
	}
	return packetAEAD.Seal(header, nonce[:], payload, header), nil
}
```

- [ ] **Step 3: Update relay-prefix send/decode helpers**

Change `externalRelayPrefixDERPSendChunk` to require AEAD:

```go
func externalRelayPrefixDERPSendChunk(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, chunk externalHandoffChunk, packetAEAD cipher.AEAD) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameData, chunk.Offset, chunk.Payload, packetAEAD)
	if err != nil {
		return err
	}
	if err := externalAssertNoPlaintextRelayMarker(payload); err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}
```

Update the control-frame helpers to pass `nil`:

```go
payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameAck, watermark, nil, nil)
payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameEOF, finalOffset, nil, nil)
payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameHandoff, watermark, nil, nil)
payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameHandoffAck, watermark, nil, nil)
```

Change `externalRelayPrefixDERPDecodeChunk` to require AEAD:

```go
func externalRelayPrefixDERPDecodeChunk(payload []byte, packetAEAD cipher.AEAD) (externalHandoffChunk, error) {
	if externalRelayPrefixDERPFrameKindOf(payload) != externalRelayPrefixDERPFrameData {
		return externalHandoffChunk{}, errors.New("unexpected relay-prefix DERP data frame")
	}
	offset, err := externalRelayPrefixDERPDecodeOffset(payload)
	if err != nil {
		return externalHandoffChunk{}, err
	}
	if packetAEAD == nil {
		return externalHandoffChunk{}, errors.New("nil relay-prefix DERP data AEAD")
	}
	if packetAEAD.NonceSize() != 12 {
		return externalHandoffChunk{}, errors.New("unsupported relay-prefix DERP data AEAD nonce size")
	}
	header := payload[:externalRelayPrefixDERPHeaderSize]
	nonce, err := externalRelayPrefixDERPDataNonce(header)
	if err != nil {
		return externalHandoffChunk{}, err
	}
	plaintext, err := packetAEAD.Open(nil, nonce[:], payload[externalRelayPrefixDERPHeaderSize:], header)
	if err != nil {
		return externalHandoffChunk{}, fmt.Errorf("decrypt relay-prefix DERP data: %w", err)
	}
	return externalHandoffChunk{Offset: offset, Payload: plaintext}, nil
}
```

- [ ] **Step 4: Pass AEAD through relay-prefix send and receive**

Change the relay-prefix function signatures:

```go
func sendExternalHandoffDERP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, spool *externalHandoffSpool, stop <-chan struct{}, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error

func receiveExternalHandoffDERP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, rx *externalHandoffReceiver, packets <-chan derpbind.Packet, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error
```

Inside `sendExternalHandoffDERP`, update the data send:

```go
if err := externalRelayPrefixDERPSendChunk(ctx, client, peerDERP, chunk, packetAEAD); err != nil {
	return err
}
```

Inside `receiveExternalHandoffDERP`, update the data decode:

```go
chunk, err := externalRelayPrefixDERPDecodeChunk(pkt.Payload, packetAEAD)
if err != nil {
	return err
}
```

Inside `sendExternalViaRelayPrefixThenDirectUDP`, compute AEAD before starting the relay goroutine:

```go
packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
if err != nil {
	return err
}
```

Then pass it into the goroutine call:

```go
relayErrCh <- externalSendExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.listenerDERP, spool, relayStopCh, metrics, packetAEAD)
```

Inside `receiveExternalViaRelayPrefixThenDirectUDP`, compute AEAD before starting the relay goroutine:

```go
packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
if err != nil {
	return err
}
```

Then pass it into the goroutine call:

```go
relayErrCh <- externalReceiveExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.peerDERP, rx, rcfg.relayPackets, nil, packetAEAD)
```

- [ ] **Step 5: Update existing relay-prefix tests for new signatures**

Use `rg` to find call sites:

```bash
rg -n 'sendExternalHandoffDERP\\(|receiveExternalHandoffDERP\\(|externalRelayPrefixDERPSendChunk\\(|externalRelayPrefixDERPDecodeChunk\\(|externalRelayPrefixDERPPayload\\(' pkg/session/external_direct_udp_test.go
```

For each direct test call, create one AEAD per test and pass it consistently:

```go
aead := testExternalSessionAEAD(t, 0x61)
```

Then update calls in that test:

```go
errCh <- sendExternalHandoffDERP(ctx, senderDERP, listenerDERP.PublicKey(), spool, stopCh, metrics, aead)
chunk, err := externalRelayPrefixDERPDecodeChunk(pkt.Payload, aead)
if err := externalRelayPrefixDERPSendChunk(ctx, senderDERP, listenerDERP.PublicKey(), externalHandoffChunk{Offset: 0, Payload: []byte("abcd")}, aead); err != nil {
	t.Fatal(err)
}
errCh <- receiveExternalHandoffDERP(ctx, listenerDERP, senderDERP.PublicKey(), rx, relayFrames, metrics, aead)
```

For test stubs assigned to `externalSendExternalHandoffDERPFn`, add the final ignored parameter:

```go
externalSendExternalHandoffDERPFn = func(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, spool *externalHandoffSpool, stop <-chan struct{}, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error {
	return nil
}
```

For test stubs assigned to `externalReceiveExternalHandoffDERPFn`, add the final ignored parameter:

```go
externalReceiveExternalHandoffDERPFn = func(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, rx *externalHandoffReceiver, packets <-chan derpbind.Packet, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error {
	return nil
}
```

- [ ] **Step 6: Run relay-prefix tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalRelayPrefixDERPDataFrame|TestSendExternalHandoffDERP|TestReceiveExternalHandoffDERP' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit relay-prefix encryption**

Run:

```bash
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "security: encrypt relay-prefix payload frames"
```

## Task 3: Encrypt Force-Relay Probe Payloads

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add red tests for force-relay PacketAEAD wiring**

Add these tests to `pkg/session/external_direct_udp_test.go` near the relay helper tests:

```go
func TestSendExternalRelayUDPConfiguresPacketAEAD(t *testing.T) {
	prevSend := externalDirectUDPProbeSendFn
	t.Cleanup(func() { externalDirectUDPProbeSendFn = prevSend })

	tok := testExternalSessionToken(0x71)
	var captured probe.SendConfig
	externalDirectUDPProbeSendFn = func(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
		captured = cfg
		_, _ = io.Copy(io.Discard, src)
		if cfg.PacketAEAD == nil {
			return probe.TransferStats{}, errors.New("missing PacketAEAD")
		}
		return probe.TransferStats{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		RelaySend: func(context.Context, []byte) error {
			return nil
		},
	})
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("manager.Start() error = %v", err)
	}
	defer manager.Wait()

	if err := sendExternalRelayUDP(ctx, strings.NewReader("force-relay-secret-marker"), manager, tok, nil); err != nil {
		t.Fatalf("sendExternalRelayUDP() error = %v", err)
	}
	if captured.RunID != tok.SessionID {
		t.Fatalf("RunID = %x, want %x", captured.RunID, tok.SessionID)
	}
	if captured.PacketAEAD == nil {
		t.Fatal("PacketAEAD = nil, want token-derived AEAD")
	}
}

func TestReceiveExternalRelayUDPConfiguresPacketAEAD(t *testing.T) {
	prevReceive := externalDirectUDPProbeReceiveToWriterFn
	t.Cleanup(func() { externalDirectUDPProbeReceiveToWriterFn = prevReceive })

	tok := testExternalSessionToken(0x72)
	var captured probe.ReceiveConfig
	externalDirectUDPProbeReceiveToWriterFn = func(ctx context.Context, conn net.PacketConn, remoteAddr string, dst io.Writer, cfg probe.ReceiveConfig) (probe.TransferStats, error) {
		captured = cfg
		if cfg.PacketAEAD == nil {
			return probe.TransferStats{}, errors.New("missing PacketAEAD")
		}
		return probe.TransferStats{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		RelaySend: func(context.Context, []byte) error {
			return nil
		},
	})
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("manager.Start() error = %v", err)
	}
	defer manager.Wait()

	var out bytes.Buffer
	if err := receiveExternalRelayUDP(ctx, &out, manager, tok, nil); err != nil {
		t.Fatalf("receiveExternalRelayUDP() error = %v", err)
	}
	if captured.ExpectedRunID != tok.SessionID {
		t.Fatalf("ExpectedRunID = %x, want %x", captured.ExpectedRunID, tok.SessionID)
	}
	if captured.PacketAEAD == nil {
		t.Fatal("PacketAEAD = nil, want token-derived AEAD")
	}
}
```

- [ ] **Step 2: Run force-relay red tests**

Run:

```bash
go test ./pkg/session -run 'TestSendExternalRelayUDPConfiguresPacketAEAD|TestReceiveExternalRelayUDPConfiguresPacketAEAD' -count=1
```

Expected: FAIL to compile because `externalDirectUDPProbeReceiveToWriterFn` does not exist and force-relay helpers still accept `runID [16]byte`.

- [ ] **Step 3: Add receive hook and update force-relay helpers**

Near the existing function variables in `pkg/session/external_direct_udp.go`, add:

```go
var externalDirectUDPProbeReceiveToWriterFn = probe.ReceiveToWriter
```

Change `sendExternalRelayUDP` and `receiveExternalRelayUDP` signatures:

```go
func sendExternalRelayUDP(ctx context.Context, src io.Reader, manager *transport.Manager, tok token.Token, emitter *telemetry.Emitter) error

func receiveExternalRelayUDP(ctx context.Context, dst io.Writer, manager *transport.Manager, tok token.Token, emitter *telemetry.Emitter) error
```

Inside `sendExternalRelayUDP`, derive AEAD and set it on `probe.SendConfig`:

```go
packetAEAD, err := externalSessionPacketAEAD(tok)
if err != nil {
	return err
}
_, err = externalDirectUDPProbeSendFn(ctx, packetConn, packetConn.remoteAddr.String(), externalDirectUDPBufferedReader(src), probe.SendConfig{
	Raw:        true,
	Transport:  "legacy",
	ChunkSize:  externalDirectUDPChunkSize,
	WindowSize: 4096,
	RunID:      tok.SessionID,
	PacketAEAD: packetAEAD,
})
return err
```

Inside `receiveExternalRelayUDP`, derive AEAD and use the receive hook:

```go
packetAEAD, err := externalSessionPacketAEAD(tok)
if err != nil {
	return err
}
_, err = externalDirectUDPProbeReceiveToWriterFn(ctx, packetConn, "", receiveDst, probe.ReceiveConfig{
	Raw:           true,
	ExpectedRunID: tok.SessionID,
	PacketAEAD:    packetAEAD,
})
```

- [ ] **Step 4: Update force-relay call sites**

Replace these call patterns in `pkg/session/external_direct_udp.go`:

```go
sendExternalRelayUDP(ctx, countedSrc, transportManager, tok.SessionID, cfg.Emitter)
sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
receiveExternalRelayUDP(ctx, countedDst, transportManager, session.token.SessionID, cfg.Emitter)
receiveExternalRelayUDP(ctx, dst, transportManager, tok.SessionID, cfg.Emitter)
```

with:

```go
sendExternalRelayUDP(ctx, countedSrc, transportManager, tok, cfg.Emitter)
sendExternalRelayUDP(ctx, src, transportManager, tok, cfg.Emitter)
receiveExternalRelayUDP(ctx, countedDst, transportManager, session.token, cfg.Emitter)
receiveExternalRelayUDP(ctx, dst, transportManager, tok, cfg.Emitter)
```

Replace these call patterns in `pkg/session/external_offer.go`:

```go
sendExternalRelayUDP(ctx, countedSrc, transportManager, session.token.SessionID, cfg.Emitter)
receiveExternalRelayUDP(ctx, countedDst, transportManager, tok.SessionID, cfg.Emitter)
```

with:

```go
sendExternalRelayUDP(ctx, countedSrc, transportManager, session.token, cfg.Emitter)
receiveExternalRelayUDP(ctx, countedDst, transportManager, tok, cfg.Emitter)
```

- [ ] **Step 5: Run force-relay tests**

Run:

```bash
go test ./pkg/session -run 'TestSendExternalRelayUDPConfiguresPacketAEAD|TestReceiveExternalRelayUDPConfiguresPacketAEAD|TestPublicRelayOnlyStdioRoundTrip|TestExternalSendIgnoresTokenNativeTCPBootstrapHint' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit force-relay encryption**

Run:

```bash
git add pkg/session/external_direct_udp.go pkg/session/external_offer.go pkg/session/external_direct_udp_test.go
git commit -m "security: encrypt force-relay payload packets"
```

## Task 4: Add Plaintext Marker Guard And Remote Relay Smoke Instrumentation

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `scripts/smoke-remote-relay.sh`

- [ ] **Step 1: Add red test for marker guard**

Add this test to `pkg/session/external_direct_udp_test.go`:

```go
func TestExternalAssertNoPlaintextRelayMarker(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER", "relay-secret-marker")
	if err := externalAssertNoPlaintextRelayMarker([]byte("ciphertext bytes only")); err != nil {
		t.Fatalf("externalAssertNoPlaintextRelayMarker() clean payload error = %v", err)
	}
	if err := externalAssertNoPlaintextRelayMarker([]byte("prefix relay-secret-marker suffix")); err == nil {
		t.Fatal("externalAssertNoPlaintextRelayMarker() accepted payload containing marker")
	}
}
```

Run:

```bash
go test ./pkg/session -run TestExternalAssertNoPlaintextRelayMarker -count=1
```

Expected: FAIL to compile because `externalAssertNoPlaintextRelayMarker` does not exist.

- [ ] **Step 2: Implement marker guard**

Add this helper to `pkg/session/external_direct_udp.go` near the relay-prefix helper functions:

```go
const externalTestRelayPlaintextMarkerEnv = "DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER"

func externalAssertNoPlaintextRelayMarker(payload []byte) error {
	marker := os.Getenv(externalTestRelayPlaintextMarkerEnv)
	if marker == "" {
		return nil
	}
	if strings.Contains(string(payload), marker) {
		return errors.New("relay payload contains plaintext marker")
	}
	return nil
}
```

The `externalRelayPrefixDERPSendChunk` implementation from Task 2 already calls this helper before `client.Send`.

- [ ] **Step 3: Guard transport-manager DERP data sends**

In `pkg/session/external.go`, update the `RelaySend` callback inside `startExternalTransportManager`:

```go
RelaySend: func(ctx context.Context, payload []byte) error {
	if err := externalAssertNoPlaintextRelayMarker(payload); err != nil {
		return err
	}
	return derpClient.Send(ctx, peerDERP, payload)
},
```

- [ ] **Step 4: Add marker to remote relay smoke**

In `scripts/smoke-remote-relay.sh`, after `remote_env=()` add:

```bash
relay_plaintext_marker="relay-plaintext-marker-${target}-$(date +%s)-$$"
export DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER="${relay_plaintext_marker}"
remote_env+=(DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER="${relay_plaintext_marker}")
```

Change both payload definitions so live forced-relay data contains the marker:

```bash
payload_local_to_remote="hello relay local-to-${target}-${relay_plaintext_marker}-$(date +%s)"
payload_remote_to_local="hello relay ${target}-to-local-${relay_plaintext_marker}-$(date +%s)"
```

- [ ] **Step 5: Run marker guard tests and shell syntax check**

Run:

```bash
go test ./pkg/session -run TestExternalAssertNoPlaintextRelayMarker -count=1
bash -n scripts/smoke-remote-relay.sh
```

Expected: PASS.

- [ ] **Step 6: Commit marker instrumentation**

Run:

```bash
git add pkg/session/external_direct_udp.go pkg/session/external.go pkg/session/external_direct_udp_test.go scripts/smoke-remote-relay.sh
git commit -m "test: guard relay smoke against plaintext payloads"
```

## Task 5: Add End-To-End Relay-Prefix Ciphertext Regression

**Files:**
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add round-trip test that captures DERP frames**

Add this test near the existing `sendExternalHandoffDERP` and `receiveExternalHandoffDERP` tests:

```go
func TestExternalHandoffDERPRoundTripEncryptsRelayFrames(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node := srv.Map.Regions[1].Nodes[0]
	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(listener) error = %v", err)
	}
	defer listenerDERP.Close()
	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(sender) error = %v", err)
	}
	defer senderDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)
	warmExternalQUICModeTestDERPRoute(t, ctx, listenerDERP, senderDERP)

	relayFrames, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	defer unsubscribe()

	receiverPackets := make(chan derpbind.Packet, 32)
	captured := make(chan derpbind.Packet, 32)
	go func() {
		defer close(receiverPackets)
		for {
			select {
			case pkt, ok := <-relayFrames:
				if !ok {
					return
				}
				select {
				case captured <- pkt:
				default:
				}
				select {
				case receiverPackets <- pkt:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	marker := []byte("relay-prefix-live-secret-marker")
	payload := append([]byte{}, marker...)
	payload = append(payload, bytes.Repeat([]byte("-payload"), 64)...)
	aead := testExternalSessionAEAD(t, 0x81)

	spool, err := newExternalHandoffSpool(bytes.NewReader(payload), len(payload), int64(len(payload))*2)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, int64(len(payload))*2)
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- receiveExternalHandoffDERP(ctx, listenerDERP, senderDERP.PublicKey(), rx, receiverPackets, nil, aead)
	}()

	if err := sendExternalHandoffDERP(ctx, senderDERP, listenerDERP.PublicKey(), spool, nil, nil, aead); err != nil {
		t.Fatalf("sendExternalHandoffDERP() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("receiveExternalHandoffDERP() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiveExternalHandoffDERP(): %v", ctx.Err())
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("receiver payload = %q, want %q", out.Bytes(), payload)
	}

	sawData := false
	for {
		select {
		case pkt := <-captured:
			if externalRelayPrefixDERPFrameKindOf(pkt.Payload) != externalRelayPrefixDERPFrameData {
				continue
			}
			sawData = true
			if bytes.Contains(pkt.Payload, marker) {
				t.Fatalf("captured relay-prefix data frame contains plaintext marker: %x", pkt.Payload)
			}
		default:
			if !sawData {
				t.Fatal("captured no relay-prefix data frames")
			}
			return
		}
	}
}
```

- [ ] **Step 2: Run round-trip regression**

Run:

```bash
go test ./pkg/session -run TestExternalHandoffDERPRoundTripEncryptsRelayFrames -count=1
```

Expected: PASS.

- [ ] **Step 3: Commit round-trip regression**

Run:

```bash
git add pkg/session/external_direct_udp_test.go
git commit -m "test: assert relay-prefix frames hide payloads"
```

## Task 6: Update README Security Model

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Edit Security Model prose**

Use the repository instruction for README edits: keep prose tight and direct.

Replace the Security Model bullets with:

```markdown
DERP relays do **not** get keys needed to read or impersonate sessions. DERP can see routing metadata and packet timing, but not plaintext user payload bytes:

- On `listen/pipe` and `send/receive`, direct UDP and relay fallback both encrypt and authenticate user payloads with session AEAD derived from the bearer secret.
- Relay-prefix startup frames leave frame kind and byte offsets visible for flow control, but encrypt user payload bytes.
- On `share/open`, stream traffic uses authenticated QUIC streams for the claimed session.
- On `derptun`, stream traffic uses authenticated QUIC streams pinned to the stable tunnel identity in the token.

Simple rule: token possession authorizes the session. Relays move packets; they do not hold decrypt keys for user payloads.
```

- [ ] **Step 2: Run README grep check**

Run:

```bash
rg -n 'DERP only forwards encrypted session bytes|plaintext user payload|Security Model|relay-prefix' README.md
```

Expected: the stale phrase `DERP only forwards encrypted session bytes` is gone, and the new relay-prefix/security wording is present.

- [ ] **Step 3: Commit README update**

Run:

```bash
git add README.md
git commit -m "docs: clarify relay payload encryption"
```

## Task 7: Full Verification And Live ktzlxc Checks

**Files:**
- No source edits unless a verification command exposes a defect.

- [ ] **Step 1: Run targeted package tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalRelayPrefixDERPDataFrame|TestExternalHandoffDERPRoundTripEncryptsRelayFrames|TestExternalAssertNoPlaintextRelayMarker|TestSendExternalRelayUDPConfiguresPacketAEAD|TestReceiveExternalRelayUDPConfiguresPacketAEAD|TestPublicRelayOnlyStdioRoundTrip|TestExternalSendIgnoresTokenNativeTCPBootstrapHint' -count=1
go test ./pkg/probe -run 'TestBlastPacketAEADEncryptsWirePayloadAndRoundTrips|TestRunBlastParallelSendLaneEncodesQueuedPayloads' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full local suite**

Run:

```bash
mise run test
mise run vet
mise run build
```

Expected: PASS.

- [ ] **Step 3: Run forced-relay live smoke against ktzlxc without Tailscale candidates**

Run:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-relay
```

Expected: PASS, output includes `relay smoke passed`, and no process prints `relay payload contains plaintext marker`.

- [ ] **Step 4: Run non-forced live smoke against ktzlxc without Tailscale candidates**

Run:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote
```

Expected: PASS, output shows path evidence and at least one side records `connected-direct` for each transfer direction.

- [ ] **Step 5: Run full check before final push**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 6: Commit any verification fixes**

If any verification command required a code or docs fix, commit the fix with a scoped security/test/docs subject. If no fixes were needed, do not create an empty commit.

## Self-Review

- Spec coverage: Tasks cover token-derived AEAD reuse, force-relay `PacketAEAD`, relay-prefix `Data` frame AEAD, fail-closed plaintext/wrong-key/tamper behavior, README security wording, and ktzlxc non-Tailscale live verification.
- Placeholder scan: The plan contains no placeholder sections and no compatibility mode.
- Type consistency: New helper names are `externalSessionPacketAEAD`, `externalRelayPrefixDERPPayload`, `externalRelayPrefixDERPDecodeChunk`, `externalDirectUDPProbeReceiveToWriterFn`, and `externalAssertNoPlaintextRelayMarker`. Every later step uses those exact names.
