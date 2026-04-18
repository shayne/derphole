# MAC-Bound Direct UDP Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate direct UDP promotion probes so the shared transport manager only promotes to direct after receiving a session-bound proof from the expected peer path.

**Architecture:** Keep the existing transport manager state machine, DERP control messages, STUN handling, and direct UDP data plane intact. Replace transport promotion payloads in `pkg/transport/disco.go` with optional MAC-bound probe/ack packets derived from the session bearer secret. Production session call sites always set the key; zero-key transport unit tests can keep legacy static probes until migrated.

**Tech Stack:** Go, `crypto/hmac`, `crypto/sha256`, existing `pkg/transport.Manager`, existing session token bearer secret, existing derptun shared QUIC-over-transport path.

---

## File Structure

- Create: `pkg/transport/disco_mac.go`
- Create: `pkg/transport/disco_mac_test.go`
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/disco.go`
- Modify: `pkg/transport/state.go`
- Modify: `pkg/transport/fake_test.go`
- Modify: `pkg/transport/manager_test.go`
- Create: `pkg/session/external_transport_security.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/external_attach.go`
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/external_direct_udp_test.go`
- Modify: `pkg/session/derptun_test.go`

## Live ktzlxc Safety Rules

- Do not change `externalDirectUDPRateProbe*`, data start-rate selection, `externalDirectUDPPacketAEAD`, or probe data-plane packet format.
- Do not change `probe.Send`, `probe.Receive`, or `quicpath.Adapter`.
- In `handleDirectPacket`, keep `stun.Is(payload)` before all discovery MAC logic.
- Only `pkg/transport` promotion packets change; DERP relay remains the fallback if direct promotion fails.
- Pass the discovery key through every shared transport call site, including derptun server and client.
- Validate with `REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-derptun`.

---

### Task 1: Add MAC-Bound Discovery Packets

**Files:**
- Create: `pkg/transport/disco_mac.go`
- Create: `pkg/transport/disco_mac_test.go`

- [ ] **Step 1: Write failing packet tests**

Create `pkg/transport/disco_mac_test.go`:

```go
package transport

import "testing"

func TestDiscoveryMACProbeAndAckRoundTrip(t *testing.T) {
	key := DiscoveryKey{1, 2, 3}
	probe, probeToken, err := newDirectProbePayload(key)
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	if !probeToken.mac {
		t.Fatal("probe token mac = false, want true")
	}
	ack, ok := directAckPayloadForProbe(key, probe)
	if !ok {
		t.Fatal("directAckPayloadForProbe() ok = false, want true")
	}
	ackToken, ok := directAckTokenForPayload(key, ack)
	if !ok {
		t.Fatal("directAckTokenForPayload() ok = false, want true")
	}
	if ackToken != probeToken {
		t.Fatalf("ack token = %+v, want %+v", ackToken, probeToken)
	}
}

func TestDiscoveryMACRejectsWrongKey(t *testing.T) {
	probe, _, err := newDirectProbePayload(DiscoveryKey{1})
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	if _, ok := directAckPayloadForProbe(DiscoveryKey{2}, probe); ok {
		t.Fatal("directAckPayloadForProbe(wrong key) ok = true, want false")
	}
}

func TestDiscoveryMACRejectsWrongKind(t *testing.T) {
	key := DiscoveryKey{1}
	probe, _, err := newDirectProbePayload(key)
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	probe[len(discoMACMagic)] = 99
	if _, ok := directAckPayloadForProbe(key, probe); ok {
		t.Fatal("directAckPayloadForProbe(wrong kind) ok = true, want false")
	}
}

func TestDiscoveryMACUsesLegacyStaticPacketsWhenKeyMissing(t *testing.T) {
	probe, token, err := newDirectProbePayload(DiscoveryKey{})
	if err != nil {
		t.Fatalf("newDirectProbePayload(zero) error = %v", err)
	}
	if token.mac {
		t.Fatal("legacy token mac = true, want false")
	}
	if string(probe) != directProbePayload {
		t.Fatalf("probe = %q, want legacy %q", probe, directProbePayload)
	}
	ack, ok := directAckPayloadForProbe(DiscoveryKey{}, []byte(directProbePayload))
	if !ok {
		t.Fatal("legacy directAckPayloadForProbe() ok = false, want true")
	}
	if string(ack) != directAckPayload {
		t.Fatalf("ack = %q, want legacy %q", ack, directAckPayload)
	}
}
```

- [ ] **Step 2: Run red packet tests**

Run:

```bash
go test ./pkg/transport -run 'TestDiscoveryMAC' -count=1
```

Expected: FAIL because helpers do not exist.

- [ ] **Step 3: Implement helper API**

Create `pkg/transport/disco_mac.go`:

```go
package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type DiscoveryKey [32]byte

type directProbeToken struct {
	mac   bool
	nonce [16]byte
}

var discoMACMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'd', 'i', 's', 'c', 'o', '1'}

const (
	discoMACKindProbe byte = 1
	discoMACKindAck   byte = 2
	discoMACSize           = len(discoMACMagic) + 1 + 16 + sha256.Size
)

func (k DiscoveryKey) IsZero() bool {
	return k == DiscoveryKey{}
}
```

Add these functions in the same file:

```go
func newDirectProbePayload(key DiscoveryKey) ([]byte, directProbeToken, error) {
	if key.IsZero() {
		return []byte(directProbePayload), directProbeToken{}, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, directProbeToken{}, err
	}
	return encodeDiscoveryMAC(key, discoMACKindProbe, nonce), directProbeToken{mac: true, nonce: nonce}, nil
}

func directAckPayloadForProbe(key DiscoveryKey, payload []byte) ([]byte, bool) {
	if key.IsZero() {
		if string(payload) != directProbePayload {
			return nil, false
		}
		return []byte(directAckPayload), true
	}
	nonce, ok := decodeDiscoveryMAC(key, payload, discoMACKindProbe)
	if !ok {
		return nil, false
	}
	return encodeDiscoveryMAC(key, discoMACKindAck, nonce), true
}

func directAckTokenForPayload(key DiscoveryKey, payload []byte) (directProbeToken, bool) {
	if key.IsZero() {
		return directProbeToken{}, string(payload) == directAckPayload
	}
	nonce, ok := decodeDiscoveryMAC(key, payload, discoMACKindAck)
	if !ok {
		return directProbeToken{}, false
	}
	return directProbeToken{mac: true, nonce: nonce}, true
}

func isDirectDiscoveryMACPayload(payload []byte) bool {
	return len(payload) == discoMACSize && string(payload[:len(discoMACMagic)]) == string(discoMACMagic[:])
}
```

Add private helpers:

```go
func encodeDiscoveryMAC(key DiscoveryKey, kind byte, nonce [16]byte) []byte {
	payload := make([]byte, 0, discoMACSize)
	payload = append(payload, discoMACMagic[:]...)
	payload = append(payload, kind)
	payload = append(payload, nonce[:]...)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload)
	payload = mac.Sum(payload)
	return payload
}

func decodeDiscoveryMAC(key DiscoveryKey, payload []byte, kind byte) ([16]byte, bool) {
	var nonce [16]byte
	if len(payload) != discoMACSize {
		return nonce, false
	}
	if string(payload[:len(discoMACMagic)]) != string(discoMACMagic[:]) {
		return nonce, false
	}
	if payload[len(discoMACMagic)] != kind {
		return nonce, false
	}
	copy(nonce[:], payload[len(discoMACMagic)+1:len(discoMACMagic)+1+len(nonce)])
	macStart := len(discoMACMagic) + 1 + len(nonce)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload[:macStart])
	return nonce, hmac.Equal(payload[macStart:], mac.Sum(nil))
}
```

- [ ] **Step 4: Run packet tests green**

Run:

```bash
go test ./pkg/transport -run 'TestDiscoveryMAC' -count=1
```

Expected: PASS.

### Task 2: Require MAC Acks In Transport Promotion

**Files:**
- Modify: `pkg/transport/manager.go`
- Modify: `pkg/transport/disco.go`
- Modify: `pkg/transport/state.go`
- Modify: `pkg/transport/fake_test.go`
- Modify: `pkg/transport/manager_test.go`

- [ ] **Step 1: Add failing manager tests**

Add tests in `pkg/transport/manager_test.go`:

```go
func TestManagerSendsMACBoundDirectProbeWhenDiscoveryKeyConfigured(t *testing.T)
func TestManagerPromotesDirectWithMACBoundAck(t *testing.T)
func TestManagerRejectsStaticAckWhenDiscoveryKeyConfigured(t *testing.T)
func TestManagerRespondsToMACBoundInboundProbe(t *testing.T)
func TestManagerHandleDirectPacketRequiresMACWhenDiscoveryKeyConfigured(t *testing.T)
```

Use an existing fake direct connection test helper. Set `ManagerConfig.DiscoveryKey = DiscoveryKey{1, 2, 3}` and assert:

- outbound probe payload satisfies `isDirectDiscoveryMACPayload`
- static `[]byte(directAckPayload)` does not promote direct
- MAC ack from `directAckPayloadForProbe(key, probePayload)` promotes direct
- inbound MAC probe gets a MAC ack, not the static ack

- [ ] **Step 2: Run red manager tests**

Run:

```bash
go test ./pkg/transport -run 'TestManager.*MAC|TestManagerRejectsStaticAckWhenDiscoveryKeyConfigured|TestManagerPromotesDirectWithMACBoundAck' -count=1
```

Expected: FAIL because `ManagerConfig.DiscoveryKey` and MAC promotion are not wired.

- [ ] **Step 3: Add config and pending token storage**

Change `ManagerConfig` in `pkg/transport/manager.go`:

```go
DiscoveryKey DiscoveryKey
```

Change `pathState.pendingProbes` in `pkg/transport/state.go`:

```go
pendingProbes map[string]pendingDirectProbe
```

Add:

```go
type pendingDirectProbe struct {
	sentAt time.Time
	token  directProbeToken
}
```

Update signatures:

```go
func (s *pathState) noteProbeSent(now time.Time, addr net.Addr, token directProbeToken)
func (s *pathState) consumeProbe(addr net.Addr, maxAge time.Duration, now time.Time, token directProbeToken) bool
func (m *Manager) noteProbeSentIfCurrent(generation uint64, now time.Time, addr net.Addr, token directProbeToken)
func (m *Manager) tryPromoteDirect(now time.Time, addr net.Addr, token directProbeToken) bool
```

`consumeProbe` must compare token equality, not just address and age.

- [ ] **Step 4: Wire `disco.go`**

In `discoveryTick`, generate one fresh probe per target:

```go
payload, token, err := newDirectProbePayload(m.cfg.DiscoveryKey)
if err != nil {
	continue
}
if _, err := m.cfg.DirectConn.WriteTo(payload, target); err == nil {
	m.noteProbeSentIfCurrent(plan.generation, m.now(), target, token)
}
```

In `handleDirectPacket`, keep STUN first, then:

```go
if ack, ok := directAckPayloadForProbe(m.cfg.DiscoveryKey, payload); ok {
	_, _ = m.cfg.DirectConn.WriteTo(ack, addr)
	return
}
if token, ok := directAckTokenForPayload(m.cfg.DiscoveryKey, payload); ok {
	m.tryPromoteDirect(m.now(), addr, token)
	return
}
if isDirectDiscoveryMACPayload(payload) {
	m.directRecvRejects.Add(1)
	return
}
```

Mirror that behavior in `HandleDirectPacket`.

- [ ] **Step 5: Update fake responder**

In `pkg/transport/fake_test.go`, add:

```go
func (c *fakePacketConn) useDiscoveryKey(key DiscoveryKey) {
	c.discoveryKey = key
}
```

Then make fake responders answer either static or MAC-bound probes:

```go
if ack, ok := directAckPayloadForProbe(c.discoveryKey, payload); ok {
	_, _ = c.WriteToPeer(ack, addr)
}
```

- [ ] **Step 6: Run transport tests green**

Run:

```bash
go test ./pkg/transport -count=1
```

Expected: PASS.

### Task 3: Derive Session Discovery Keys

**Files:**
- Create: `pkg/session/external_transport_security.go`
- Modify: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Add failing key tests**

Add tests in `pkg/session/external_direct_udp_test.go`:

```go
func TestExternalTransportDiscoveryKeyIsSymmetricForSessionPeers(t *testing.T)
func TestExternalTransportDiscoveryKeyChangesWithBearerSecret(t *testing.T)
func TestExternalTransportDiscoveryKeyChangesWithPeerIdentity(t *testing.T)
```

Each test should build a `token.Token` with a fixed `SessionID` and `BearerSecret`, two `key.NodePublic` values, and compare `externalTransportDiscoveryKey` outputs.

- [ ] **Step 2: Run red key tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransportDiscoveryKey' -count=1
```

Expected: FAIL because helper does not exist.

- [ ] **Step 3: Add key derivation helper**

Create `pkg/session/external_transport_security.go`:

```go
package session

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/types/key"
)

var externalTransportDiscoveryMACDomain = []byte("derphole-transport-direct-udp-disco-mac-v1")

func externalTransportDiscoveryKey(tok token.Token, localDERP, peerDERP key.NodePublic) transport.DiscoveryKey {
	localRaw := localDERP.AppendTo(nil)
	peerRaw := peerDERP.AppendTo(nil)
	first, second := localRaw, peerRaw
	if bytes.Compare(first, second) > 0 {
		first, second = second, first
	}
	mac := hmac.New(sha256.New, tok.BearerSecret[:])
	mac.Write(externalTransportDiscoveryMACDomain)
	mac.Write(tok.SessionID[:])
	mac.Write(first)
	mac.Write(second)
	var out transport.DiscoveryKey
	copy(out[:], mac.Sum(nil))
	return out
}
```

- [ ] **Step 4: Run key tests green**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransportDiscoveryKey' -count=1
```

Expected: PASS.

### Task 4: Pass Discovery Keys Through Shared Transport

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_direct_udp.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/external_attach.go`
- Modify: `pkg/session/external_offer.go`
- Modify: `pkg/session/derptun.go`

- [ ] **Step 1: Change helper signature**

Change `startExternalTransportManager` from:

```go
func startExternalTransportManager(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, derpClient *derpbind.Client, peerDERP key.NodePublic, localCandidates []net.Addr, pm publicPortmap, forceRelay bool) (*transport.Manager, func(), error)
```

to:

```go
func startExternalTransportManager(ctx context.Context, tok token.Token, conn net.PacketConn, dm *tailcfg.DERPMap, derpClient *derpbind.Client, peerDERP key.NodePublic, localCandidates []net.Addr, pm publicPortmap, forceRelay bool) (*transport.Manager, func(), error)
```

Set:

```go
DiscoveryKey: externalTransportDiscoveryKey(tok, derpClient.PublicKey(), peerDERP),
```

- [ ] **Step 2: Update every call site**

Pass `tok` in normal session sender/client paths.

Pass `claimToken` in `handleDerptunServeClaim`, because that token has the client-specific bearer secret after proof validation.

- [ ] **Step 3: Compile session package**

Run:

```bash
go test ./pkg/session -run '^$' -count=1
```

Expected: compile pass.

### Task 5: Prove Derptun Uses The Same MAC Key

**Files:**
- Modify: `pkg/session/derptun_test.go`

- [ ] **Step 1: Add failing derptun key test**

Add:

```go
func TestDerptunServerAndClientDeriveSameTransportDiscoveryKey(t *testing.T) {
	now := time.Now()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 97)
	serverTok, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
	if err != nil {
		t.Fatalf("derptunServerTokenForClaim() error = %v reject=%+v", err, reject)
	}
	clientTok, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	serverDERP, err := serverCred.DERPKey()
	if err != nil {
		t.Fatalf("DERPKey() error = %v", err)
	}
	clientDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
	serverKey := externalTransportDiscoveryKey(serverTok, serverDERP.Public(), clientDERP)
	clientKey := externalTransportDiscoveryKey(clientTok, clientDERP, serverDERP.Public())
	if serverKey != clientKey {
		t.Fatalf("server key = %x, client key = %x", serverKey, clientKey)
	}
}
```

Add imports for `go4.org/mem` if not already present in the test file.

- [ ] **Step 2: Run red derptun key test**

Run:

```bash
go test ./pkg/session -run 'TestDerptunServerAndClientDeriveSameTransportDiscoveryKey' -count=1
```

Expected: FAIL until Task 3 helper exists and derptun call sites are updated.

- [ ] **Step 3: Run derptun-focused tests green**

Run:

```bash
go test ./pkg/session -run 'TestDerptun|TestExternalTransportDiscoveryKey' -count=1
```

Expected: PASS.

### Task 6: Regression And ktzlxc Verification

**Files:**
- Test: `pkg/transport`
- Test: `pkg/session`

- [ ] **Step 1: Package-level red/green**

Run:

```bash
go test ./pkg/transport ./pkg/session -count=1
```

Expected: PASS.

- [ ] **Step 2: Full suite**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Live derptun smoke against ktzlxc**

Run:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-derptun
```

Expected: PASS with `connected-direct` evidence.

- [ ] **Step 4: Live direct UDP promotion smoke**

Run:

```bash
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024
```

Expected: PASS. Throughput may vary, but the run must not fail due to direct promotion timeout, MAC rejection, or relay-only behavior when direct was previously available.

- [ ] **Step 5: Final repository gate**

Run:

```bash
mise run check
```

Expected: PASS.

## Commit Plan

1. `transport: authenticate direct udp discovery probes`
2. `session: bind transport discovery to bearer secret`
3. `test: cover mac-bound derptun promotion`
