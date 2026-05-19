# V2 QUIC Transfer Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the default `send` / `receive` transfer path with a v2 QUIC-first protocol that stays reliable over relay, promotes direct below the stream layer, and eliminates legacy relay-prefix / UDP-blast handoff stalls.

**Architecture:** Add a versioned v2 transfer protocol in `pkg/session` and a focused `pkg/dataplane` boundary for QUIC-over-transport-manager streams. Wire v2 through `sendExternal` / `listenExternal` behind an explicit selector, then flip the default to v2 once package and live gates pass. Keep legacy UDP blast reachable only as an explicit diagnostic path.

**Tech Stack:** Go, quic-go, existing `pkg/transport.Manager`, DERP-backed authenticated envelopes, existing transfer trace and live harness scripts.

---

## File Structure

- Create `pkg/session/external_transfer_protocol.go`: transfer protocol selector and env parsing.
- Modify `pkg/token/token.go`: add an explicit v2 transfer capability bit.
- Create `pkg/session/external_v2_protocol.go`: v2 envelope payload structs, validators, and helper constructors.
- Create `pkg/session/external_v2_protocol_test.go`: selector and protocol validation coverage.
- Create `pkg/dataplane/types.go`: small public data-plane interfaces and stats types.
- Create `pkg/dataplane/quic.go`: QUIC data plane over an existing `transport.Manager`.
- Create `pkg/dataplane/quic_test.go`: loopback relay/direct tests for QUIC data plane behavior.
- Create `pkg/session/external_v2.go`: sender and receiver v2 runtimes.
- Create `pkg/session/external_v2_test.go`: end-to-end v2 session tests with the in-process DERP server.
- Modify `pkg/session/external.go`: route `sendExternal` and `listenExternal` through v2 or legacy.
- Modify `pkg/session/external_direct_transport.go`: keep legacy selector scoped to legacy transfers only.
- Modify `scripts/transfer-stall-harness.sh`: record v2 protocol metadata and allow forcing legacy for diagnostics.
- Modify `scripts/direct-transport-benchmark.sh`: use v2 selector instead of the old direct-QUIC experiment.
- Modify `docs/benchmarks.md`: document v2 default and legacy diagnostic override.

---

### Task 1: Add Transfer Protocol Selector And V2 Capability

**Files:**
- Modify: `pkg/token/token.go`
- Create: `pkg/session/external_transfer_protocol.go`
- Create: `pkg/session/external_transfer_protocol_test.go`

- [ ] **Step 1: Write failing selector tests**

Add `pkg/session/external_transfer_protocol_test.go`:

```go
package session

import "testing"

func TestExternalTransferProtocolFromEnvDefaultsToV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}

func TestExternalTransferProtocolFromEnvAcceptsLegacy(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolLegacy {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolLegacy)
	}
}

func TestExternalTransferProtocolFromEnvAcceptsV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}

func TestExternalTransferProtocolFromEnvTreatsUnknownAsV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "typo")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}
```

- [ ] **Step 2: Run selector tests and confirm they fail**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransferProtocolFromEnv' -count=1
```

Expected: FAIL because `externalTransferProtocolFromEnv` and constants do not exist.

- [ ] **Step 3: Add selector implementation**

Create `pkg/session/external_transfer_protocol.go`:

```go
package session

import "os"

type externalTransferProtocolKind string

const (
	externalTransferProtocolV2     externalTransferProtocolKind = "v2"
	externalTransferProtocolLegacy externalTransferProtocolKind = "legacy"
)

func externalTransferProtocolFromEnv() externalTransferProtocolKind {
	switch os.Getenv("DERPHOLE_TRANSFER_PROTOCOL") {
	case string(externalTransferProtocolLegacy):
		return externalTransferProtocolLegacy
	case string(externalTransferProtocolV2), "":
		return externalTransferProtocolV2
	default:
		return externalTransferProtocolV2
	}
}
```

- [ ] **Step 4: Add token capability bit**

Modify `pkg/token/token.go` so the capability block includes v2:

```go
const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
	CapabilityStdioOffer
	CapabilityWebFile
	CapabilityDerptunTCP
	CapabilityDirectQUIC
	CapabilityTransferV2
)
```

- [ ] **Step 5: Verify selector tests pass**

Run:

```bash
go test ./pkg/session -run 'TestExternalTransferProtocolFromEnv' -count=1
go test ./pkg/token -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/token/token.go pkg/session/external_transfer_protocol.go pkg/session/external_transfer_protocol_test.go
git commit -m "session: add v2 transfer protocol selector"
```

---

### Task 2: Define V2 Protocol Messages

**Files:**
- Create: `pkg/session/external_v2_protocol.go`
- Create: `pkg/session/external_v2_protocol_test.go`

- [ ] **Step 1: Write failing protocol validation tests**

Add `pkg/session/external_v2_protocol_test.go`:

```go
package session

import (
	"errors"
	"testing"

	"github.com/shayne/derphole/pkg/token"
)

func TestExternalV2TokenSupportsTransferV2(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio | token.CapabilityTransferV2}
	if err := validateExternalV2SendToken(tok); err != nil {
		t.Fatalf("validateExternalV2SendToken() error = %v", err)
	}
}

func TestExternalV2TokenRejectsMissingCapability(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio}
	if err := validateExternalV2SendToken(tok); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2SendToken() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2ClaimValidationRequiresProtocol(t *testing.T) {
	claim := externalV2Claim{Protocol: "legacy"}
	if err := validateExternalV2Claim(claim); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2Claim() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2AcceptValidationRequiresAccepted(t *testing.T) {
	accept := externalV2Accept{Protocol: externalV2Protocol}
	if err := validateExternalV2Accept(accept); !errors.Is(err, errExternalV2Rejected) {
		t.Fatalf("validateExternalV2Accept() error = %v, want %v", err, errExternalV2Rejected)
	}
}
```

- [ ] **Step 2: Run protocol tests and confirm they fail**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2' -count=1
```

Expected: FAIL because v2 protocol types do not exist.

- [ ] **Step 3: Add v2 protocol types and validators**

Create `pkg/session/external_v2_protocol.go`:

```go
package session

import (
	"errors"

	"github.com/shayne/derphole/pkg/token"
)

const externalV2Protocol = "derphole-transfer-v2"

var (
	errExternalV2Unsupported = errors.New("external v2 transfer unsupported")
	errExternalV2Rejected    = errors.New("external v2 transfer rejected")
)

type externalV2Claim struct {
	Protocol        string   `json:"protocol"`
	QUICPublic      [32]byte `json:"quic_public"`
	Candidates      []string `json:"candidates,omitempty"`
	RelayCapable    bool     `json:"relay_capable"`
	ReceiverLimited bool     `json:"receiver_limited,omitempty"`
}

type externalV2Accept struct {
	Protocol     string   `json:"protocol"`
	Accepted     bool     `json:"accepted"`
	Candidates   []string `json:"candidates,omitempty"`
	RelayCapable bool     `json:"relay_capable"`
	Reason       string   `json:"reason,omitempty"`
}

type externalV2Complete struct {
	Protocol      string `json:"protocol"`
	BytesReceived int64  `json:"bytes_received"`
}

func validateExternalV2SendToken(tok token.Token) error {
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Claim(claim externalV2Claim) error {
	if claim.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Accept(accept externalV2Accept) error {
	if accept.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	if !accept.Accepted {
		return errExternalV2Rejected
	}
	return nil
}
```

- [ ] **Step 4: Wire v2 payloads into authenticated envelopes**

Modify `pkg/session/external.go` by adding constants and fields:

```go
const (
	envelopeV2Claim    = "v2_claim"
	envelopeV2Accept   = "v2_accept"
	envelopeV2Complete = "v2_complete"
)

type envelope struct {
	// existing fields stay unchanged
	V2Claim    *externalV2Claim    `json:"v2_claim,omitempty"`
	V2Accept   *externalV2Accept   `json:"v2_accept,omitempty"`
	V2Complete *externalV2Complete `json:"v2_complete,omitempty"`
}
```

Place the new constants near the other envelope constants and the new fields near `Claim`, `Decision`, `Ack`, and `Progress`.

- [ ] **Step 5: Verify v2 protocol tests pass**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external.go pkg/session/external_v2_protocol.go pkg/session/external_v2_protocol_test.go
git commit -m "session: add v2 transfer envelopes"
```

---

### Task 3: Add Data Plane Interface And QUIC Implementation

**Files:**
- Create: `pkg/dataplane/types.go`
- Create: `pkg/dataplane/quic.go`
- Create: `pkg/dataplane/quic_test.go`

- [ ] **Step 1: Write failing QUIC data-plane test**

Create `pkg/dataplane/quic_test.go`:

```go
package dataplane

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

type relayPipe struct {
	inbound chan []byte
	peer    *relayPipe
	addr    net.Addr
}

func newRelayPipePair() (*relayPipe, *relayPipe) {
	a := &relayPipe{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}}
	b := &relayPipe{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *relayPipe) send(_ context.Context, payload []byte) error {
	p.peer.inbound <- append([]byte(nil), payload...)
	return nil
}

func (p *relayPipe) receive(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-p.inbound:
		return append([]byte(nil), payload...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestQUICDataPlaneCopiesOverRelayManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayA, relayB := newRelayPipePair()
	managerA := transport.NewManager(transport.ManagerConfig{RelaySend: relayA.send, ReceiveRelay: relayA.receive, RelayAddr: relayA.addr})
	managerB := transport.NewManager(transport.ManagerConfig{RelaySend: relayB.send, ReceiveRelay: relayB.receive, RelayAddr: relayB.addr})
	if err := managerA.Start(ctx); err != nil {
		t.Fatalf("managerA.Start() error = %v", err)
	}
	if err := managerB.Start(ctx); err != nil {
		t.Fatalf("managerB.Start() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		managerA.Wait()
		managerB.Wait()
	})

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	var got bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		dp := NewQUICServer(managerB, serverIdentity, clientIdentity.Public)
		stream, err := dp.Accept(ctx)
		if err != nil {
			recvErr <- err
			return
		}
		_, copyErr := io.Copy(&got, stream)
		closeErr := stream.Close()
		if copyErr != nil {
			recvErr <- copyErr
			return
		}
		recvErr <- closeErr
	}()

	dp := NewQUICClient(managerA, clientIdentity, serverIdentity.Public)
	stream, err := dp.Open(ctx)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-recvErr; err != nil {
		t.Fatalf("receive error = %v", err)
	}
	if got.String() != "payload" {
		t.Fatalf("received = %q, want payload", got.String())
	}
	if dp.Stats().BytesSent == 0 {
		t.Fatal("Stats().BytesSent = 0, want positive")
	}
}
```

- [ ] **Step 2: Run data-plane test and confirm it fails**

Run:

```bash
go test ./pkg/dataplane -run TestQUICDataPlaneCopiesOverRelayManager -count=1
```

Expected: FAIL because `pkg/dataplane` does not exist.

- [ ] **Step 3: Add data-plane interfaces**

Create `pkg/dataplane/types.go`:

```go
package dataplane

import (
	"context"
	"io"
	"time"
)

type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

type Client interface {
	Open(context.Context) (Stream, error)
	Stats() Stats
	CloseWithError(uint64, string) error
}

type Server interface {
	Accept(context.Context) (Stream, error)
	Stats() Stats
	CloseWithError(uint64, string) error
}

type Stats struct {
	BytesSent     int64
	BytesReceived int64
	HandshakeMS   int64
	FirstByteMS   int64
	OpenedAt      time.Time
	HandshakeAt   time.Time
	FirstByteAt   time.Time
	ClosedAt      time.Time
	CloseReason   string
}
```

- [ ] **Step 4: Add QUIC implementation**

Create `pkg/dataplane/quic.go`:

```go
package dataplane

import (
	"context"
	"io"

	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

type QUICClient struct {
	manager  *transport.Manager
	identity quicpath.SessionIdentity
	peer     [32]byte
	endpoint *directquic.Endpoint
}

type QUICServer struct {
	manager  *transport.Manager
	identity quicpath.SessionIdentity
	peer     [32]byte
	endpoint *directquic.Endpoint
}

func NewQUICClient(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICClient {
	return &QUICClient{manager: manager, identity: identity, peer: peer}
}

func NewQUICServer(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICServer {
	return &QUICServer{manager: manager, identity: identity, peer: peer}
}

func (q *QUICClient) Open(ctx context.Context) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: peerConn,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   q.identity,
		PeerPublic: q.peer,
	})
	if err != nil {
		return nil, err
	}
	q.endpoint = endpoint
	return endpoint.OpenSendStream(ctx)
}

func (q *QUICServer) Accept(ctx context.Context) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	endpoint, err := directquic.Listen(ctx, directquic.ListenConfig{
		PacketConn: peerConn,
		Identity:   q.identity,
		PeerPublic: q.peer,
	})
	if err != nil {
		return nil, err
	}
	q.endpoint = endpoint
	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	return readOnlyStream{ReadCloser: stream}, nil
}

func (q *QUICClient) Stats() Stats { return convertStats(q.endpoint.Stats()) }
func (q *QUICServer) Stats() Stats { return convertStats(q.endpoint.Stats()) }

func (q *QUICClient) CloseWithError(code uint64, reason string) error {
	if q.endpoint == nil {
		return nil
	}
	return q.endpoint.CloseWithError(code, reason)
}

func (q *QUICServer) CloseWithError(code uint64, reason string) error {
	if q.endpoint == nil {
		return nil
	}
	return q.endpoint.CloseWithError(code, reason)
}

type readOnlyStream struct{ io.ReadCloser }

func (s readOnlyStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func convertStats(stats directquic.Stats) Stats {
	return Stats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		HandshakeMS:   stats.HandshakeMS,
		FirstByteMS:   stats.FirstByteMS,
		OpenedAt:      stats.OpenedAt,
		HandshakeAt:   stats.HandshakeAt,
		FirstByteAt:   stats.FirstByteAt,
		ClosedAt:      stats.ClosedAt,
		CloseReason:   stats.CloseReason,
	}
}
```

- [ ] **Step 5: Verify data-plane tests pass**

Run:

```bash
go test ./pkg/dataplane -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/dataplane
git commit -m "dataplane: add quic transfer stream"
```

---

### Task 4: Implement V2 Sender And Receiver Runtime

**Files:**
- Create: `pkg/session/external_v2.go`
- Create: `pkg/session/external_v2_test.go`
- Modify: `pkg/session/external.go`

- [ ] **Step 1: Write failing v2 end-to-end test**

Create `pkg/session/external_v2_test.go`:

```go
package session

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestExternalV2SendReceiveRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	const payload = "external v2 payload"
	if received := runExternalV2RoundTrip(t, payload, nil, nil); received != payload {
		t.Fatalf("received = %q, want %q", received, payload)
	}
}

func runExternalV2RoundTrip(t *testing.T, payload string, sendTrace *transfertrace.Recorder, receiveTrace *transfertrace.Recorder) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var received bytes.Buffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &received,
			UsePublicDERP: true,
			Trace:         receiveTrace,
		})
		listenErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-listenErr:
		t.Fatalf("listenExternal() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}
	tok, err := token.Decode(raw, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		t.Fatalf("token capabilities = %08b, want transfer v2", tok.Capabilities)
	}

	if err := sendExternal(ctx, SendConfig{
		Token:         raw,
		StdioIn:       strings.NewReader(payload),
		UsePublicDERP: true,
		Trace:         sendTrace,
	}); err != nil {
		t.Fatalf("sendExternal() error = %v", err)
	}
	select {
	case err := <-listenErr:
		if err != nil {
			t.Fatalf("listenExternal() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener: %v", ctx.Err())
	}
	return received.String()
}
```

- [ ] **Step 2: Run v2 end-to-end test and confirm it fails**

Run:

```bash
go test ./pkg/session -run TestExternalV2SendReceiveRoundTrip -count=1
```

Expected: FAIL because v2 send/listen routing and runtime do not exist.

- [ ] **Step 3: Add v2 runtime skeleton**

Create `pkg/session/external_v2.go` with the concrete helpers below. Use existing helpers from `external_direct_udp.go` and `external_direct_quic.go` where possible instead of duplicating candidate gathering or sink/source opening.

```go
package session

import (
	"context"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/types/key"
)

func sendExternalViaV2(ctx context.Context, cfg SendConfig) (retErr error) {
	rt, err := newExternalV2SendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run(ctx)
}

func listenExternalViaV2(ctx context.Context, cfg ListenConfig) (string, error) {
	rt, err := newExternalV2ListenRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.run(ctx)
}

type externalV2SendRuntime struct {
	cfg          SendConfig
	tok          token.Token
	source       *byteCountingReadCloser
	derpClient   *derpbind.Client
	listenerDERP key.NodePublic
	identity     quicpath.SessionIdentity
	auth         externalPeerControlAuth
}

type externalV2ListenRuntime struct {
	cfg       ListenConfig
	tok       string
	session   *relaySession
	identity  quicpath.SessionIdentity
	auth      externalPeerControlAuth
	claimCh   <-chan derpbind.Packet
	closeFunc func()
}

func (rt *externalV2SendRuntime) run(ctx context.Context) error {
	return errExternalV2Unsupported
}

func (rt *externalV2ListenRuntime) run(ctx context.Context) (string, error) {
	return rt.tok, errExternalV2Unsupported
}
```

The skeleton intentionally returns `errExternalV2Unsupported` so the test still fails until the next steps fill behavior.

- [ ] **Step 4: Wire `sendExternal` / `listenExternal` to v2 selector**

Modify `pkg/session/external.go`:

```go
var sendExternalViaV2Fn = sendExternalViaV2
var listenExternalViaV2Fn = listenExternalViaV2

func sendExternal(ctx context.Context, cfg SendConfig) error {
	if externalTransferProtocolFromEnv() == externalTransferProtocolV2 {
		return sendExternalViaV2Fn(ctx, cfg)
	}
	switch externalDirectTransportFromEnv() {
	case externalDirectTransportQUIC:
		return sendExternalViaDirectQUICFn(ctx, cfg)
	default:
		return sendExternalViaDirectUDPFn(ctx, cfg)
	}
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	if externalTransferProtocolFromEnv() == externalTransferProtocolV2 {
		return listenExternalViaV2Fn(ctx, cfg)
	}
	switch externalDirectTransportFromEnv() {
	case externalDirectTransportQUIC:
		return listenExternalViaDirectQUICFn(ctx, cfg)
	default:
		return listenExternalViaDirectUDPFn(ctx, cfg)
	}
}
```

- [ ] **Step 5: Implement v2 token creation and send decode**

In `external_v2.go`, implement runtime constructors by adapting existing token/session setup:

```go
func newExternalV2ListenRuntime(ctx context.Context, cfg ListenConfig) (*externalV2ListenRuntime, error) {
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityTransferV2)
	if err != nil {
		return nil, err
	}
	claimCh, unsubscribe := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		env, ok := decodeAuthenticatedEnvelope(pkt.Payload, externalPeerControlAuthForToken(session.token))
		return ok && env.Type == envelopeV2Claim && env.V2Claim != nil
	})
	return &externalV2ListenRuntime{
		cfg:       cfg,
		tok:       tok,
		session:   session,
		identity:  session.quicIdentity,
		auth:      externalPeerControlAuthForToken(session.token),
		claimCh:   claimCh,
		closeFunc: unsubscribe,
	}, nil
}

func newExternalV2SendRuntime(ctx context.Context, cfg SendConfig) (*externalV2SendRuntime, error) {
	tok, err := decodeExternalDirectSendToken(cfg.Token)
	if err != nil {
		return nil, err
	}
	if err := validateExternalV2SendToken(tok); err != nil {
		return nil, err
	}
	identity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return nil, err
	}
	source, err := openSendSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	client, err := newPublicDERPClient(ctx, tok, cfg.Emitter)
	if err != nil {
		_ = source.Close()
		return nil, err
	}
	return &externalV2SendRuntime{
		cfg:          cfg,
		tok:          tok,
		source:       source,
		derpClient:   client,
		listenerDERP: key.NodePublicFromRaw32(tok.DERPPublic),
		identity:     identity,
		auth:         externalPeerControlAuthForToken(tok),
	}, nil
}
```

Use the existing `newExternalDirectSendRuntime` and `issuePublicQUICSession` patterns rather than creating a second DERP bootstrap path. If a constructor needs shared setup, extract a private helper in `pkg/session/external_v2.go` and keep existing legacy constructors unchanged.

- [ ] **Step 6: Implement manager startup and QUIC stream copy**

In `external_v2.go`, finish `run` methods with this shape:

```go
func (rt *externalV2SendRuntime) run(ctx context.Context) error {
	defer rt.source.Close()
	claim, peerDERP, err := rt.sendClaimAndWaitAccept(ctx)
	if err != nil {
		return err
	}
	manager, cleanup, err := rt.startManager(ctx, claim, peerDERP)
	if err != nil {
		return err
	}
	defer cleanup()
	dp := dataplane.NewQUICClient(manager, rt.identity, rt.tok.QUICPublic)
	stream, err := dp.Open(ctx)
	if err != nil {
		_ = dp.CloseWithError(1, "open send stream failed")
		return err
	}
	if _, err := io.CopyBuffer(stream, rt.source, make([]byte, externalDirectQUICCopyBufferSize)); err != nil {
		_ = dp.CloseWithError(1, "copy send stream failed")
		return err
	}
	if err := stream.Close(); err != nil {
		_ = dp.CloseWithError(1, "close send stream failed")
		return err
	}
	return rt.waitComplete(ctx, peerDERP)
}

func (rt *externalV2ListenRuntime) receive(ctx context.Context, claim externalV2Claim, peerDERP key.NodePublic) error {
	manager, cleanup, err := rt.startManager(ctx, claim, peerDERP)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := rt.sendAccept(ctx, peerDERP); err != nil {
		return err
	}
	dst, err := openListenSink(ctx, rt.cfg)
	if err != nil {
		return err
	}
	defer dst.Close()
	dp := dataplane.NewQUICServer(manager, rt.identity, claim.QUICPublic)
	stream, err := dp.Accept(ctx)
	if err != nil {
		_ = dp.CloseWithError(1, "accept receive stream failed")
		return err
	}
	n, copyErr := io.CopyBuffer(dst, stream, make([]byte, externalDirectQUICCopyBufferSize))
	closeErr := stream.Close()
	if copyErr != nil {
		_ = dp.CloseWithError(1, "copy receive stream failed")
		return copyErr
	}
	if closeErr != nil {
		_ = dp.CloseWithError(1, "close receive stream failed")
		return closeErr
	}
	return rt.sendComplete(ctx, peerDERP, n)
}
```

Fill `sendClaimAndWaitAccept`, `waitComplete`, `sendAccept`, `sendComplete`, and `startManager` with existing authenticated envelope and `startExternalTransportManager` patterns. Keep each helper under 50 lines and unit-test any non-trivial validation.

- [ ] **Step 7: Verify v2 end-to-end test passes**

Run:

```bash
go test ./pkg/session -run TestExternalV2SendReceiveRoundTrip -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/session/external.go pkg/session/external_v2.go pkg/session/external_v2_test.go
git commit -m "session: add v2 quic transfer runtime"
```

---

### Task 5: Add Abort, Completion, And Relay-Only Coverage

**Files:**
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_test.go`

- [ ] **Step 1: Add failing peer-cancel test**

Append to `pkg/session/external_v2_test.go`:

```go
func TestExternalV2ReceiverCancelAbortsSender(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenCtx, cancelListen := context.WithCancel(ctx)
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(listenCtx, ListenConfig{
			TokenSink:     tokenSink,
			StdioOut:      &bytes.Buffer{},
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	raw := <-tokenSink
	cancelListen()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sendExternal(ctx, SendConfig{
			Token:         raw,
			StdioIn:       strings.NewReader(strings.Repeat("x", 8<<20)),
			UsePublicDERP: true,
		})
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("sendExternal() error = nil, want peer abort or context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not return promptly after receiver cancel")
	}
	<-listenErr
}
```

- [ ] **Step 2: Run cancel test and confirm it fails if abort is not wired**

Run:

```bash
go test ./pkg/session -run TestExternalV2ReceiverCancelAbortsSender -count=1
```

Expected: FAIL or timeout until v2 uses existing peer abort helpers.

- [ ] **Step 3: Wire peer-control helpers into v2 runtime**

In `sendExternalViaV2` and `receive` paths, wrap contexts with the existing helpers:

```go
ctx, stopPeerAbort := rt.withPeerControlNoHeartbeatWatch(ctx)
defer stopPeerAbort()
defer rt.notifyPeerAbortOnError(&retErr, ctx)
defer rt.notifyPeerAbortOnLocalCancel(&retErr, ctx)
```

For receiver runtime, mirror the existing direct QUIC receiver pattern:

```go
ctx, stopPeerAbort := withPeerControlContext(ctx, rt.session.derp, peerDERP, peerSubs.abortCh, nil, func() int64 {
	return countedDst.Count()
}, rt.auth)
defer stopPeerAbort()
defer notifyPeerAbortOnError(&retErr, ctx, rt.session.derp, peerDERP, func() int64 {
	return countedDst.Count()
}, rt.auth)
defer notifyPeerAbortOnLocalCancel(&retErr, ctx, rt.session.derp, peerDERP, func() int64 {
	return countedDst.Count()
}, rt.auth)
```

Use `subscribePeer` from the direct UDP listen runtime or extract a small shared helper if needed.

- [ ] **Step 4: Add relay-only test**

Append a test that forces no direct candidates and expects completion:

```go
func TestExternalV2RelayOnlyCompletes(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")
	if got := runExternalV2RoundTrip(t, "relay-only-v2", nil, nil); got != "relay-only-v2" {
		t.Fatalf("received = %q, want relay-only-v2", got)
	}
}
```

- [ ] **Step 5: Verify abort and relay-only tests pass**

Run:

```bash
go test ./pkg/session -run 'TestExternalV2(ReceiverCancelAbortsSender|RelayOnlyCompletes|SendReceiveRoundTrip)' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external_v2.go pkg/session/external_v2_test.go
git commit -m "session: harden v2 transfer abort and relay completion"
```

---

### Task 6: Wire Telemetry And Harness Metadata

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `scripts/transfer-stall-harness.sh`
- Modify: `scripts/direct-transport-benchmark.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Add failing telemetry assertion**

In `pkg/session/external_v2_test.go`, add a trace-backed test:

```go
func TestExternalV2TraceRecordsProtocol(t *testing.T) {
	var traceOut bytes.Buffer
	rec, err := transfertrace.NewRecorder(&traceOut, transfertrace.RoleSend, time.Unix(200, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	runExternalV2RoundTrip(t, "trace-v2", rec, nil)
	rows := readTransferTraceRows(t, traceOut.String())
	if len(rows) == 0 {
		t.Fatal("trace rows = 0, want v2 trace rows")
	}
	if got := rows[len(rows)-1]["protocol"]; got != "v2" {
		t.Fatalf("final trace protocol = %q, want v2", got)
	}
}
```

- [ ] **Step 2: Run telemetry test and confirm it fails**

Run:

```bash
go test ./pkg/session -run TestExternalV2TraceRecordsProtocol -count=1
```

Expected: FAIL because protocol trace field is missing.

- [ ] **Step 3: Add trace protocol field**

Modify the transfer trace row type and CSV header in `pkg/transfertrace` to include:

```go
Protocol string
```

Set it from v2 runtime:

```go
metrics.SetProtocol("v2")
metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-v2-quic")
```

Add a protocol setter to `pkg/session/external_transfer_metrics.go`:

```go
func (m *externalTransferMetrics) SetProtocol(protocol string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protocol = protocol
}
```

Then include `protocol` in snapshot rows.

- [ ] **Step 4: Update harness metadata**

In `scripts/transfer-stall-harness.sh`, add the selector to the environment forwarding block:

```bash
if [[ -n "${DERPHOLE_TRANSFER_PROTOCOL:-}" ]]; then
  prefix+=(DERPHOLE_TRANSFER_PROTOCOL="$(quote "${DERPHOLE_TRANSFER_PROTOCOL}")")
fi
```

Add metadata output:

```bash
echo "transfer_protocol=${DERPHOLE_TRANSFER_PROTOCOL:-v2}"
```

In `scripts/direct-transport-benchmark.sh`, replace the old QUIC experiment selector with:

```bash
DERPHOLE_TRANSFER_PROTOCOL="${DERPHOLE_TRANSFER_PROTOCOL:-v2}"
```

Keep `DERPHOLE_DIRECT_TRANSPORT=quic` only for legacy diagnostic runs.

- [ ] **Step 5: Document selectors**

Update `docs/benchmarks.md`:

```markdown
Default transfer benchmarks use v2 QUIC transfer protocol. To compare against the retired UDP blast path, set:

```bash
DERPHOLE_TRANSFER_PROTOCOL=legacy DERPHOLE_DIRECT_TRANSPORT=blast
```

Use legacy results only as diagnostics, not release promotion proof.
```

- [ ] **Step 6: Verify telemetry and scripts**

Run:

```bash
go test ./pkg/transfertrace ./pkg/session -run 'TestExternalV2TraceRecordsProtocol|TestExternalV2SendReceiveRoundTrip' -count=1
bash -n scripts/transfer-stall-harness.sh scripts/direct-transport-benchmark.sh
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/transfertrace pkg/session scripts/transfer-stall-harness.sh scripts/direct-transport-benchmark.sh docs/benchmarks.md
git commit -m "trace: mark v2 transfer protocol"
```

---

### Task 7: Flip Default Path And Quarantine Legacy Blast

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_direct_transport.go`
- Modify: `pkg/session/external_direct_transport_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Update selector tests for default v2 and explicit legacy**

Modify `pkg/session/external_direct_transport_test.go` so tests assert:

```go
func TestSendExternalDefaultsToV2(t *testing.T) {
	prevV2 := sendExternalViaV2Fn
	prevLegacy := sendExternalViaDirectUDPFn
	defer func() {
		sendExternalViaV2Fn = prevV2
		sendExternalViaDirectUDPFn = prevLegacy
	}()
	called := ""
	sendExternalViaV2Fn = func(context.Context, SendConfig) error {
		called = "v2"
		return nil
	}
	sendExternalViaDirectUDPFn = func(context.Context, SendConfig) error {
		called = "legacy"
		return nil
	}
	if err := sendExternal(context.Background(), SendConfig{}); err != nil {
		t.Fatalf("sendExternal() error = %v", err)
	}
	if called != "v2" {
		t.Fatalf("called = %q, want v2", called)
	}
}
```

Also add an explicit legacy test:

```go
func TestSendExternalUsesLegacyWhenRequested(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	// same function swap shape as the default test, but expect "legacy"
}
```

- [ ] **Step 2: Run selector routing tests**

Run:

```bash
go test ./pkg/session -run 'TestSendExternal(Default|UsesLegacy)|TestListenExternal(Default|UsesLegacy)' -count=1
```

Expected: PASS after routing was already added in Task 4. If it fails, fix routing only; do not alter v2 runtime behavior here.

- [ ] **Step 3: Rename old selector semantics in code comments**

In `pkg/session/external_direct_transport.go`, make it explicit that this selector is legacy-only:

```go
// externalDirectTransportFromEnv selects the retired legacy direct transport.
// New transfers use externalTransferProtocolFromEnv and v2 unless
// DERPHOLE_TRANSFER_PROTOCOL=legacy is set.
func externalDirectTransportFromEnv() externalDirectTransportKind {
	...
}
```

- [ ] **Step 4: Verify broader package tests**

Run:

```bash
go test ./pkg/session ./pkg/dataplane ./pkg/directquic ./pkg/transport -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session docs/benchmarks.md
git commit -m "session: default transfers to v2 quic"
```

---

### Task 8: Full Local Verification

**Files:**
- No source edits expected unless a verification failure requires a fix.

- [ ] **Step 1: Run full repository checks**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 2: Run local smoke**

Run:

```bash
mise run smoke-local
```

Expected: PASS, including payload integrity.

- [ ] **Step 3: Run focused stall harness locally if available**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh pve1 canlxc 128
```

Expected:

```text
stall-harness-success=true
transfer_protocol=v2
```

If `pve1` is not reachable from the current shell, skip this step and run Task 9 live gates instead.

- [ ] **Step 4: Commit any verification fixes**

If verification required source edits:

```bash
git add pkg/session pkg/dataplane pkg/transport pkg/transfertrace scripts docs
git commit -m "test: fix v2 transfer verification"
```

If no edits were required, run `git status --short --branch` and do not create an empty commit.

---

### Task 9: Live Correctness Gates

**Files:**
- No source edits expected unless a live gate exposes a bug.

- [ ] **Step 1: Run pve1 to canlxc**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh pve1 canlxc 1024
```

Expected:

```text
stall-harness-success=true
transfer_protocol=v2
```

Do not record throughput if SHA, trace, or leak checks fail.

- [ ] **Step 2: Run canlxc to pve1**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc pve1 1024
```

Expected:

```text
stall-harness-success=true
transfer_protocol=v2
```

- [ ] **Step 3: Run canlxc to lotus**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh canlxc lotus-stalemate.exe.xyz 1024
```

Expected:

```text
stall-harness-success=true
transfer_protocol=v2
```

This gate may complete relay-only. That is acceptable if it completes, traces pass, and no leaks remain.

- [ ] **Step 4: Run lotus to canlxc**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/transfer-stall-harness.sh lotus-stalemate.exe.xyz canlxc 1024
```

Expected:

```text
stall-harness-success=true
transfer_protocol=v2
```

- [ ] **Step 5: Fix any live failure with a reproducing test first**

If a live gate fails, add the closest package-level reproduction before patching:

```go
func TestExternalV2LiveGateRegression(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")
	got := runExternalV2RoundTrip(t, "live-gate-regression", nil, nil)
	if got != "live-gate-regression" {
		t.Fatalf("received = %q, want live-gate-regression", got)
	}
}
```

```bash
go test ./pkg/session -run TestExternalV2LiveGateRegression -count=1
```

Expected before fix: FAIL for the observed failure mode.

Then patch the smallest v2 or data-plane component and rerun the package test plus the failed live gate.

- [ ] **Step 6: Commit live-gate fixes**

```bash
git add pkg/session pkg/dataplane pkg/transport scripts docs
git commit -m "session: fix v2 live transfer gate"
```

Skip this commit if no live-gate fixes were needed.

---

### Task 10: Performance Baseline And First Optimization Decision

**Files:**
- Modify only if diagnostics show a clear local bottleneck with a small fix.

- [ ] **Step 1: Capture iperf baseline**

For pve1/canlxc, run the existing benchmark command or the equivalent direct iperf commands documented in `docs/benchmarks.md`:

```bash
DERPHOLE_IPERF_PORT=8321 ./scripts/iperf-benchmark.sh canlxc 1024
DERPHOLE_IPERF_PORT=8321 ./scripts/iperf-benchmark-reverse.sh canlxc 1024
```

Expected: summary contains TCP and UDP goodput.

- [ ] **Step 2: Capture v2 transfer benchmark**

Run:

```bash
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-transport-benchmark.sh pve1 canlxc 1024
DERPHOLE_TRANSFER_PROTOCOL=v2 DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-transport-benchmark.sh canlxc pve1 1024
```

Expected: successful transfers with `diagnostic-direct-transport` replaced or accompanied by `diagnostic-transfer-protocol=v2`.

- [ ] **Step 3: Decide the first bottleneck class**

Use the benchmark summary:

```text
if iperf high and QUIC handshake/stream blocked high -> inspect quic-go config and stream flow control
if iperf high and peer recv queue depth high -> inspect transport.Manager peer receive queue / relay packet adapter
if iperf high and CPU high -> inspect pprof copy path and buffer sizes
if direct bytes low and relay bytes high -> inspect candidate validation and path promotion
```

Do not tune the legacy UDP blast path in this task.

- [ ] **Step 4: Write a focused follow-up issue or spec**

If v2 correctness passes but throughput remains under 90% of iperf, create a follow-up benchmark note under `docs/benchmarks/` or a new superpowers spec. Include:

```markdown
# V2 Throughput Follow-Up

- host pair:
- direction:
- iperf TCP Mbps:
- iperf UDP Mbps:
- derphole v2 Mbps:
- relay bytes:
- direct bytes:
- peer recv max depth:
- QUIC blocked/loss/retransmit notes:
- chosen first bottleneck:
```

- [ ] **Step 5: Commit benchmark docs if created**

```bash
git add docs/benchmarks docs/superpowers/specs
git commit -m "bench: record v2 throughput baseline"
```

Skip this commit if no benchmark doc was created.

---

## Final Verification

- [ ] Run `mise run check`
- [ ] Run `mise run smoke-local`
- [ ] Run pve1/canlxc live gates in both directions
- [ ] Run canlxc/lotus live gates in both directions
- [ ] Verify `git status --short --branch` is clean or contains only intentional committed changes
- [ ] Push the branch
- [ ] Watch GitHub workflows until completion

---

## Self-Review Notes

- Spec coverage: v2 default, QUIC data plane, relay-first behavior, direct promotion below the stream, abort handling, telemetry, legacy quarantine, local checks, live gates, and performance baseline all map to named tasks in this plan.
- Completeness scan: each task has concrete file paths, commands, and expected results; no unresolved steps remain.
- Type consistency: plan uses `externalTransferProtocolV2`, `CapabilityTransferV2`, `externalV2Claim`, `externalV2Accept`, `dataplane.NewQUICClient`, and `dataplane.NewQUICServer` consistently across tasks.
