# Direct QUIC Data Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the custom reliable direct UDP send/receive data path with an env-gated QUIC direct transport that can be benchmarked against iperf and promoted to default after live gates pass.

**Architecture:** Add a focused `pkg/directquic` wrapper around quic-go and the existing `pkg/quicpath` identity/config helpers. Integrate it into `pkg/session` behind `DERPHOLE_DIRECT_TRANSPORT=quic`, using the existing DERP rendezvous, `transport.Manager`, and relay-first packet path. Keep the current direct UDP blast path available as `DERPHOLE_DIRECT_TRANSPORT=blast` until QUIC passes the live benchmark gate.

**Tech Stack:** Go 1.26, quic-go v0.59, existing `pkg/quicpath`, existing `pkg/transport.Manager`, existing transfer trace CSV, shell benchmark harnesses under `scripts/`.

---

## Scope Check

This plan covers one subsystem: send/receive direct data transport. It does not rewrite attach/share/derptun, browser WebRTC, npm packaging, or DERP rendezvous.

## File Structure

- Create `pkg/directquic/endpoint.go`: small QUIC endpoint API for one connected QUIC connection and one send/receive stream.
- Create `pkg/directquic/endpoint_test.go`: loopback transfer, peer identity rejection, close behavior, and stats tests.
- Create `pkg/session/external_direct_transport.go`: direct transport selector and env parsing.
- Create `pkg/session/external_direct_transport_test.go`: selector tests and send/listen dispatch tests.
- Create `pkg/session/external_direct_quic.go`: send/receive QUIC session adapter using `transport.Manager`, `quicpath.Adapter`, and `pkg/directquic`.
- Create `pkg/session/external_direct_quic_test.go`: in-process relay/direct manager tests, cancellation tests, and fallback tests.
- Modify `pkg/session/external.go`: route `sendExternal` and `listenExternal` through the selector.
- Modify `pkg/session/external_transfer_metrics.go`: record QUIC transport fields.
- Modify `pkg/transfertrace/trace.go`: add direct transport and QUIC diagnostic columns.
- Modify `pkg/transfertrace/trace_test.go`, `pkg/transfertrace/checker.go`, `pkg/transfertrace/checker_test.go`, `tools/transfertracecheck/main.go`, `tools/transfertracecheck/main_test.go`: QUIC trace summaries.
- Create `scripts/direct-transport-benchmark.sh`: compare iperf, direct QUIC, and full derphole.
- Create `scripts/direct_transport_benchmark_script_test.go`: script behavior tests.
- Modify `docs/benchmarks.md`: document the QUIC benchmark gate and env flags.

## Task 1: Add The Direct QUIC Endpoint Package

**Files:**
- Create: `pkg/directquic/endpoint.go`
- Create: `pkg/directquic/endpoint_test.go`

- [ ] **Step 1: Write the failing loopback transfer test**

Add this test to `pkg/directquic/endpoint_test.go`:

```go
package directquic

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/quicpath"
)

func TestEndpointTransfersOneUnidirectionalStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverErr := make(chan error, 1)
	received := make(chan string, 1)
	go func() {
		server, err := Listen(ctx, ListenConfig{
			PacketConn: serverConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if err != nil {
			serverErr <- err
			return
		}
		defer server.Close()
		stream, err := server.AcceptReceiveStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer stream.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, stream); err != nil {
			serverErr <- err
			return
		}
		received <- buf.String()
		serverErr <- nil
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientConn,
		RemoteAddr: serverConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: serverIdentity.Public,
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()
	stream, err := client.OpenSendStream(ctx)
	if err != nil {
		t.Fatalf("OpenSendStream() error = %v", err)
	}
	if _, err := stream.Write([]byte("hello over quic")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() error = %v", err)
	}

	select {
	case got := <-received:
		if got != "hello over quic" {
			t.Fatalf("received = %q, want %q", got, "hello over quic")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for receive")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./pkg/directquic -run TestEndpointTransfersOneUnidirectionalStream -count=1
```

Expected: FAIL because `pkg/directquic` or `Listen` and `Dial` do not exist.

- [ ] **Step 3: Implement the endpoint API**

Create `pkg/directquic/endpoint.go` with these public types and methods:

```go
package directquic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/quicpath"
)

type ListenConfig struct {
	PacketConn net.PacketConn
	Identity   quicpath.SessionIdentity
	PeerPublic [32]byte
	QUICConfig *quic.Config
	Now        func() time.Time
}

type DialConfig struct {
	PacketConn net.PacketConn
	RemoteAddr net.Addr
	Identity   quicpath.SessionIdentity
	PeerPublic [32]byte
	QUICConfig *quic.Config
	Now        func() time.Time
}

type Stats struct {
	Role           string
	HandshakeMS    int64
	FirstByteMS    int64
	BytesSent      int64
	BytesReceived  int64
	OpenedAt       time.Time
	HandshakeAt    time.Time
	FirstByteAt    time.Time
	ClosedAt       time.Time
	CloseReason    string
}

type Endpoint struct {
	conn       *quic.Conn
	listener   *quic.Listener
	packetConn net.PacketConn
	now        func() time.Time

	mu     sync.Mutex
	stats  Stats
	closed bool
}

func Listen(ctx context.Context, cfg ListenConfig) (*Endpoint, error) {
	if cfg.PacketConn == nil {
		return nil, errors.New("directquic: nil packet conn")
	}
	now := directNow(cfg.Now)
	start := now()
	listener, err := quic.Listen(cfg.PacketConn, quicpath.ServerTLSConfig(cfg.Identity, cfg.PeerPublic), directQUICConfig(cfg.QUICConfig))
	if err != nil {
		return nil, err
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	handshakeAt := now()
	return &Endpoint{
		conn:       conn,
		listener:   listener,
		packetConn: cfg.PacketConn,
		now:        now,
		stats: Stats{
			Role:        "server",
			OpenedAt:    start,
			HandshakeAt: handshakeAt,
			HandshakeMS: handshakeAt.Sub(start).Milliseconds(),
		},
	}, nil
}

func Dial(ctx context.Context, cfg DialConfig) (*Endpoint, error) {
	if cfg.PacketConn == nil {
		return nil, errors.New("directquic: nil packet conn")
	}
	if cfg.RemoteAddr == nil {
		return nil, errors.New("directquic: nil remote addr")
	}
	now := directNow(cfg.Now)
	start := now()
	conn, err := quic.Dial(ctx, cfg.PacketConn, cfg.RemoteAddr, quicpath.ClientTLSConfig(cfg.Identity, cfg.PeerPublic), directQUICConfig(cfg.QUICConfig))
	if err != nil {
		return nil, err
	}
	handshakeAt := now()
	return &Endpoint{
		conn:       conn,
		packetConn: cfg.PacketConn,
		now:        now,
		stats: Stats{
			Role:        "client",
			OpenedAt:    start,
			HandshakeAt: handshakeAt,
			HandshakeMS: handshakeAt.Sub(start).Milliseconds(),
		},
	}, nil
}

func (e *Endpoint) OpenSendStream(ctx context.Context) (io.WriteCloser, error) {
	if e == nil || e.conn == nil {
		return nil, net.ErrClosed
	}
	stream, err := e.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &countingWriteCloser{WriteCloser: stream, observe: e.recordSend}, nil
}

func (e *Endpoint) AcceptReceiveStream(ctx context.Context) (io.ReadCloser, error) {
	if e == nil || e.conn == nil {
		return nil, net.ErrClosed
	}
	stream, err := e.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return &countingReadCloser{ReadCloser: stream, observe: e.recordReceive}, nil
}

func (e *Endpoint) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

func (e *Endpoint) Close() error {
	if e == nil {
		return nil
	}
	return e.CloseWithError(0, "")
}

func (e *Endpoint) CloseWithError(code uint64, msg string) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.stats.ClosedAt = e.now()
	e.stats.CloseReason = msg
	e.mu.Unlock()
	if e.conn != nil {
		_ = e.conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	return nil
}

type countingWriteCloser struct {
	io.WriteCloser
	observe func(int)
}

func (c *countingWriteCloser) Write(p []byte) (int, error) {
	n, err := c.WriteCloser.Write(p)
	if n > 0 {
		c.observe(n)
	}
	return n, err
}

type countingReadCloser struct {
	io.ReadCloser
	observe func(int)
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.observe(n)
	}
	return n, err
}

func (e *Endpoint) recordSend(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.BytesSent += int64(n)
	e.recordFirstByteLocked()
}

func (e *Endpoint) recordReceive(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.BytesReceived += int64(n)
	e.recordFirstByteLocked()
}

func (e *Endpoint) recordFirstByteLocked() {
	if e.stats.FirstByteAt.IsZero() {
		e.stats.FirstByteAt = e.now()
		e.stats.FirstByteMS = e.stats.FirstByteAt.Sub(e.stats.OpenedAt).Milliseconds()
	}
}

func directQUICConfig(cfg *quic.Config) *quic.Config {
	if cfg != nil {
		return cfg
	}
	return quicpath.DefaultQUICConfig()
}

func directNow(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}
```

- [ ] **Step 4: Run the package test**

Run:

```bash
go test ./pkg/directquic -run TestEndpointTransfersOneUnidirectionalStream -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/directquic/endpoint.go pkg/directquic/endpoint_test.go
git commit -m "transport: add direct quic endpoint"
```

## Task 2: Prove Identity Rejection, Close Behavior, And Stats

**Files:**
- Modify: `pkg/directquic/endpoint_test.go`
- Modify: `pkg/directquic/endpoint.go`

- [ ] **Step 1: Add identity rejection and stats tests**

Append these tests to `pkg/directquic/endpoint_test.go`:

```go
func TestDialRejectsUnexpectedPeerIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	wrongServerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(wrong) error = %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		server, err := Listen(ctx, ListenConfig{
			PacketConn: serverConn,
			Identity:   serverIdentity,
			PeerPublic: clientIdentity.Public,
		})
		if server != nil {
			defer server.Close()
		}
		serverErr <- err
	}()

	client, err := Dial(ctx, DialConfig{
		PacketConn: clientConn,
		RemoteAddr: serverConn.LocalAddr(),
		Identity:   clientIdentity,
		PeerPublic: wrongServerIdentity.Public,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("Dial() error = nil, want peer identity mismatch")
	}
}

func TestStatsRecordBytesAndCloseReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientConn.Close()

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	serverReady := make(chan *Endpoint, 1)
	serverDone := make(chan error, 1)
	go func() {
		server, err := Listen(ctx, ListenConfig{PacketConn: serverConn, Identity: serverIdentity, PeerPublic: clientIdentity.Public})
		if err != nil {
			serverDone <- err
			return
		}
		serverReady <- server
		stream, err := server.AcceptReceiveStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = io.Copy(io.Discard, stream)
		_ = stream.Close()
		serverDone <- err
	}()

	client, err := Dial(ctx, DialConfig{PacketConn: clientConn, RemoteAddr: serverConn.LocalAddr(), Identity: clientIdentity, PeerPublic: serverIdentity.Public})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	stream, err := client.OpenSendStream(ctx)
	if err != nil {
		t.Fatalf("OpenSendStream() error = %v", err)
	}
	if _, err := stream.Write([]byte("abcdef")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() error = %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("serverDone error = %v", err)
	}
	server := <-serverReady
	if err := client.CloseWithError(7, "test-close"); err != nil {
		t.Fatalf("CloseWithError(client) error = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close(server) error = %v", err)
	}

	clientStats := client.Stats()
	if clientStats.BytesSent != 6 {
		t.Fatalf("client BytesSent = %d, want 6", clientStats.BytesSent)
	}
	if clientStats.CloseReason != "test-close" {
		t.Fatalf("client CloseReason = %q, want test-close", clientStats.CloseReason)
	}
	serverStats := server.Stats()
	if serverStats.BytesReceived != 6 {
		t.Fatalf("server BytesReceived = %d, want 6", serverStats.BytesReceived)
	}
}
```

- [ ] **Step 2: Run tests to verify behavior**

Run:

```bash
go test ./pkg/directquic -count=1
```

Expected: PASS. If identity rejection hangs, ensure the test context is passed to `Dial` and `Listen`.

- [ ] **Step 3: Commit**

```bash
git add pkg/directquic/endpoint.go pkg/directquic/endpoint_test.go
git commit -m "transport: harden direct quic endpoint"
```

## Task 3: Add Direct Transport Selection

**Files:**
- Create: `pkg/session/external_direct_transport.go`
- Create: `pkg/session/external_direct_transport_test.go`
- Modify: `pkg/session/external.go`

- [ ] **Step 1: Write selector tests**

Create `pkg/session/external_direct_transport_test.go`:

```go
package session

import (
	"context"
	"errors"
	"testing"
)

func TestExternalDirectTransportFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want externalDirectTransportKind
	}{
		{name: "empty defaults blast", env: "", want: externalDirectTransportBlast},
		{name: "blast", env: "blast", want: externalDirectTransportBlast},
		{name: "quic", env: "quic", want: externalDirectTransportQUIC},
		{name: "auto", env: "auto", want: externalDirectTransportAuto},
		{name: "unknown defaults blast", env: "nope", want: externalDirectTransportBlast},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DERPHOLE_DIRECT_TRANSPORT", tt.env)
			if got := externalDirectTransportFromEnv(); got != tt.want {
				t.Fatalf("externalDirectTransportFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSendExternalDispatchesQUICWhenSelected(t *testing.T) {
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")
	wantErr := errors.New("quic selected")
	prevQUIC := sendExternalViaDirectQUICFn
	prevBlast := sendExternalViaDirectUDPFn
	sendExternalViaDirectQUICFn = func(context.Context, SendConfig) error { return wantErr }
	sendExternalViaDirectUDPFn = func(context.Context, SendConfig) error { t.Fatal("blast sender called"); return nil }
	defer func() {
		sendExternalViaDirectQUICFn = prevQUIC
		sendExternalViaDirectUDPFn = prevBlast
	}()
	if err := sendExternal(context.Background(), SendConfig{}); !errors.Is(err, wantErr) {
		t.Fatalf("sendExternal() error = %v, want %v", err, wantErr)
	}
}

func TestListenExternalDispatchesQUICWhenSelected(t *testing.T) {
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")
	wantErr := errors.New("quic selected")
	prevQUIC := listenExternalViaDirectQUICFn
	prevBlast := listenExternalViaDirectUDPFn
	listenExternalViaDirectQUICFn = func(context.Context, ListenConfig) (string, error) { return "", wantErr }
	listenExternalViaDirectUDPFn = func(context.Context, ListenConfig) (string, error) { t.Fatal("blast listener called"); return "", nil }
	defer func() {
		listenExternalViaDirectQUICFn = prevQUIC
		listenExternalViaDirectUDPFn = prevBlast
	}()
	if _, err := listenExternal(context.Background(), ListenConfig{}); !errors.Is(err, wantErr) {
		t.Fatalf("listenExternal() error = %v, want %v", err, wantErr)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/session -run 'Test(ExternalDirectTransportFromEnv|SendExternalDispatchesQUICWhenSelected|ListenExternalDispatchesQUICWhenSelected)$' -count=1
```

Expected: FAIL because selector and hook variables do not exist.

- [ ] **Step 3: Implement selector and dispatch hooks**

Create `pkg/session/external_direct_transport.go`:

```go
package session

import "os"

type externalDirectTransportKind string

const (
	externalDirectTransportBlast externalDirectTransportKind = "blast"
	externalDirectTransportQUIC  externalDirectTransportKind = "quic"
	externalDirectTransportAuto  externalDirectTransportKind = "auto"
)

func externalDirectTransportFromEnv() externalDirectTransportKind {
	switch externalDirectTransportKind(os.Getenv("DERPHOLE_DIRECT_TRANSPORT")) {
	case externalDirectTransportQUIC:
		return externalDirectTransportQUIC
	case externalDirectTransportAuto:
		return externalDirectTransportAuto
	case externalDirectTransportBlast, "":
		return externalDirectTransportBlast
	default:
		return externalDirectTransportBlast
	}
}
```

Modify `pkg/session/external.go` so `sendExternal` and `listenExternal` dispatch through hookable functions:

```go
var sendExternalViaDirectUDPFn = sendExternalViaDirectUDP
var listenExternalViaDirectUDPFn = listenExternalViaDirectUDP
var sendExternalViaDirectQUICFn = sendExternalViaDirectQUIC
var listenExternalViaDirectQUICFn = listenExternalViaDirectQUIC

func sendExternal(ctx context.Context, cfg SendConfig) error {
	switch externalDirectTransportFromEnv() {
	case externalDirectTransportQUIC:
		return sendExternalViaDirectQUICFn(ctx, cfg)
	default:
		return sendExternalViaDirectUDPFn(ctx, cfg)
	}
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	switch externalDirectTransportFromEnv() {
	case externalDirectTransportQUIC:
		return listenExternalViaDirectQUICFn(ctx, cfg)
	default:
		return listenExternalViaDirectUDPFn(ctx, cfg)
	}
}
```

- [ ] **Step 4: Add temporary QUIC stubs**

Create `pkg/session/external_direct_quic.go` with stubs that compile until the next task fills them in:

```go
package session

import (
	"context"
	"errors"
)

var errExternalDirectQUICNotImplemented = errors.New("direct QUIC transport is not implemented")

func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) error {
	return errExternalDirectQUICNotImplemented
}

func listenExternalViaDirectQUIC(ctx context.Context, cfg ListenConfig) (string, error) {
	return "", errExternalDirectQUICNotImplemented
}
```

- [ ] **Step 5: Run selector tests**

Run:

```bash
go test ./pkg/session -run 'Test(ExternalDirectTransportFromEnv|SendExternalDispatchesQUICWhenSelected|ListenExternalDispatchesQUICWhenSelected)$' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external.go pkg/session/external_direct_transport.go pkg/session/external_direct_transport_test.go pkg/session/external_direct_quic.go
git commit -m "session: add direct transport selector"
```

## Task 4: Implement QUIC Session Send And Receive Over Transport Manager

**Files:**
- Modify: `pkg/session/external_direct_quic.go`
- Create: `pkg/session/external_direct_quic_test.go`

- [ ] **Step 1: Write a relay-manager QUIC round-trip test**

Create `pkg/session/external_direct_quic_test.go` with a small test that uses `transport.Manager`, `quicpath.Adapter`, and `pkg/directquic` through session helper functions:

```go
package session

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

type directQUICTestRelay struct {
	inbound chan []byte
	peer    *directQUICTestRelay
	addr    net.Addr
}

func newDirectQUICTestRelayPair() (*directQUICTestRelay, *directQUICTestRelay) {
	a := &directQUICTestRelay{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}}
	b := &directQUICTestRelay{inbound: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10002}}
	a.peer = b
	b.peer = a
	return a, b
}

func (r *directQUICTestRelay) send(_ context.Context, p []byte) error {
	r.peer.inbound <- append([]byte(nil), p...)
	return nil
}

func (r *directQUICTestRelay) receive(ctx context.Context) ([]byte, error) {
	select {
	case p := <-r.inbound:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestDirectQUICCopiesPayloadOverTransportManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayA, relayB := newDirectQUICTestRelayPair()
	connA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(A) error = %v", err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(B) error = %v", err)
	}
	defer connB.Close()

	managerA := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayA.send,
		ReceiveRelay:       relayA.receive,
		RelayAddr:          relayA.addr,
		DirectConn:         connA,
		DisableDirectReads: false,
		DiscoveryInterval:  50 * time.Millisecond,
		DirectStaleTimeout: 2 * time.Second,
	})
	managerB := transport.NewManager(transport.ManagerConfig{
		RelaySend:          relayB.send,
		ReceiveRelay:       relayB.receive,
		RelayAddr:          relayB.addr,
		DirectConn:         connB,
		DisableDirectReads: false,
		DiscoveryInterval:  50 * time.Millisecond,
		DirectStaleTimeout: 2 * time.Second,
	})
	if err := managerA.Start(ctx); err != nil {
		t.Fatalf("managerA.Start() error = %v", err)
	}
	defer managerA.Wait()
	if err := managerB.Start(ctx); err != nil {
		t.Fatalf("managerB.Start() error = %v", err)
	}
	defer managerB.Wait()
	managerA.SeedRemoteCandidates(ctx, []net.Addr{connB.LocalAddr()})
	managerB.SeedRemoteCandidates(ctx, []net.Addr{connA.LocalAddr()})

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	var received bytes.Buffer
	recvErr := make(chan error, 1)
	go func() {
		recvErr <- externalDirectQUICReceiveOverManager(ctx, &received, managerB, serverIdentity, clientIdentity.Public)
	}()
	if err := externalDirectQUICSendOverManager(ctx, bytes.NewBufferString("payload"), managerA, clientIdentity, serverIdentity.Public); err != nil {
		t.Fatalf("externalDirectQUICSendOverManager() error = %v", err)
	}
	if err := <-recvErr; err != nil {
		t.Fatalf("externalDirectQUICReceiveOverManager() error = %v", err)
	}
	if got := received.String(); got != "payload" {
		t.Fatalf("received = %q, want payload", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestDirectQUICCopiesPayloadOverTransportManager -count=1
```

Expected: FAIL because `externalDirectQUICSendOverManager` and `externalDirectQUICReceiveOverManager` do not exist.

- [ ] **Step 3: Implement manager copy helpers**

Replace the stubs in `pkg/session/external_direct_quic.go` with these helper imports and functions, preserving the top-level stubs until Task 5 connects full rendezvous:

```go
import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

const externalDirectQUICCopyBufferSize = 1 << 20

func externalDirectQUICSendOverManager(ctx context.Context, src io.Reader, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer adapter.Close()
	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer endpoint.Close()
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(stream, externalDirectQUICCopyBufferSize)
	if _, err := io.CopyBuffer(writer, src, make([]byte, externalDirectQUICCopyBufferSize)); err != nil {
		_ = stream.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Close()
		return err
	}
	return stream.Close()
}

func externalDirectQUICReceiveOverManager(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer adapter.Close()
	endpoint, err := directquic.Listen(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer endpoint.Close()
	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	_, err = io.CopyBuffer(dst, stream, make([]byte, externalDirectQUICCopyBufferSize))
	return err
}

func externalDirectQUICWaitForCommittedBytes(ctx context.Context, committed func() int64, before int64) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if committed() > before {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
```

- [ ] **Step 4: Run the manager test**

Run:

```bash
go test ./pkg/session -run TestDirectQUICCopiesPayloadOverTransportManager -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/session/external_direct_quic.go pkg/session/external_direct_quic_test.go
git commit -m "session: copy transfers over direct quic"
```

## Task 5: Connect QUIC To Send/Receive Rendezvous

**Files:**
- Modify: `pkg/session/external_direct_quic.go`
- Modify: `pkg/session/external_direct_quic_test.go`
- Modify: `pkg/session/external_direct_udp.go` only to reuse small helpers if needed; do not thread QUIC through UDP blast control.

- [ ] **Step 1: Add full send/receive round-trip test**

Add a test in `pkg/session/external_direct_quic_test.go` that uses public send/listen APIs with fake DERP:

Add `strings` to the test file import block.

```go
func TestExternalSendReceiveViaDirectQUICRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var received bytes.Buffer
	receiveErr := make(chan error, 1)
	tokenCh := make(chan string, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenCh,
			StdioOut:      &received,
			Emitter:       nil,
			UsePublicDERP: true,
		})
		receiveErr <- err
	}()

	var tok string
	select {
	case tok = <-tokenCh:
	case err := <-receiveErr:
		t.Fatalf("listenExternal() early error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for token")
	}

	err := sendExternal(ctx, SendConfig{
		Token:              tok,
		StdioIn:            strings.NewReader("quic file bytes"),
		StdioExpectedBytes: int64(len("quic file bytes")),
		UsePublicDERP:      true,
	})
	if err != nil {
		t.Fatalf("sendExternal() error = %v", err)
	}
	if err := <-receiveErr; err != nil {
		t.Fatalf("listenExternal() error = %v", err)
	}
	if got := received.String(); got != "quic file bytes" {
		t.Fatalf("received = %q, want quic file bytes", got)
	}
}
```

- [ ] **Step 2: Run the full test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalSendReceiveViaDirectQUICRoundTrip -count=1
```

Expected: FAIL because the QUIC top-level functions still return `errExternalDirectQUICNotImplemented`.

- [ ] **Step 3: Implement `sendExternalViaDirectQUIC`**

Implement `sendExternalViaDirectQUIC` by following the existing `sendExternalViaDirectUDP` structure:

```go
func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) (retErr error) {
	runtime, err := newExternalDirectUDPSendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()

	ackCh, abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalDirectUDPSendPeer(runtime)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, runtime.derpClient, runtime.listenerDERP, abortCh, heartbeatCh, runtime.countedSrc.Count, runtime.auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedSrc.Count, runtime.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedSrc.Count, runtime.auth)

	decision, err := externalDirectQUICClaim(ctx, runtime, ackCh)
	if err != nil {
		return err
	}
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		runtime.tok,
		runtime.probeConn,
		runtime.dm,
		runtime.derpClient,
		runtime.listenerDERP,
		parseCandidateStrings(runtime.localCandidates),
		runtime.pm,
		cfg.ForceRelay,
		runtime.auth,
	)
	if err != nil {
		return err
	}
	defer transportCleanup()
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("direct-transport=quic")
		cfg.Emitter.Debug("trying-direct-quic")
	}
	return externalDirectQUICSendOverManager(ctx, runtime.countedSrc, transportManager, runtime.quicIdentity, runtime.tok.QUICPublic)
}
```

Add `externalDirectQUICClaim` as a narrow wrapper around the existing claim send/decision path used by direct UDP. It must send the same claim with candidates and return the accepted decision.

- [ ] **Step 4: Implement `listenExternalViaDirectQUIC`**

Implement `listenExternalViaDirectQUIC` by following the existing listener runtime structure:

```go
func listenExternalViaDirectQUIC(ctx context.Context, cfg ListenConfig) (retTok string, retErr error) {
	session, cleanup, err := newPublicSession(ctx, token.CapabilityStdio)
	if err != nil {
		return "", err
	}
	defer func() {
		if retErr != nil {
			cleanup()
		}
	}()
	auth := externalPeerControlAuthForToken(session.token)
	claimCh, unsubscribeClaim := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From != session.derp.PublicKey() && isExternalClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaim()

	retTok = session.token.Encode()
	claim, peerDERP, err := receiveExternalClaim(ctx, claimCh, auth)
	if err != nil {
		return "", err
	}
	decision := rendezvous.Decision{Accept: &rendezvous.Accept{
		Candidates: publicProbeCandidates(ctx, session.probeConn, session.derpMap, publicSessionPortmap(session)),
	}}
	if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
		return "", err
	}

	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		session.token,
		session.probeConn,
		session.derpMap,
		session.derp,
		peerDERP,
		parseCandidateStrings(decision.Accept.Candidates),
		publicSessionPortmap(session),
		cfg.ForceRelay,
		auth,
	)
	if err != nil {
		return "", err
	}
	defer transportCleanup()
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("direct-transport=quic")
		cfg.Emitter.Debug("trying-direct-quic")
	}
	if err := externalDirectQUICReceiveOverManager(ctx, cfg.Out, transportManager, session.quicIdentity, claim.QUICPublic); err != nil {
		return retTok, err
	}
	cleanup()
	return retTok, nil
}
```

Use the current repository helper names for receiving claims and creating sessions. If a helper name differs, use the helper that already serves `listenExternalViaDirectUDP`.

- [ ] **Step 5: Run focused session tests**

Run:

```bash
go test ./pkg/session -run 'TestExternalSendReceiveViaDirectQUICRoundTrip|TestExternalDirectTransportFromEnv|TestSendExternalDispatchesQUICWhenSelected|TestListenExternalDispatchesQUICWhenSelected' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external_direct_quic.go pkg/session/external_direct_quic_test.go
git commit -m "session: wire direct quic send receive"
```

## Task 6: Add QUIC Transfer Telemetry

**Files:**
- Modify: `pkg/session/external_transfer_metrics.go`
- Modify: `pkg/session/external_direct_quic.go`
- Modify: `pkg/transfertrace/trace.go`
- Modify: `pkg/transfertrace/trace_test.go`
- Modify: `pkg/transfertrace/checker.go`
- Modify: `pkg/transfertrace/checker_test.go`
- Modify: `tools/transfertracecheck/main.go`
- Modify: `tools/transfertracecheck/main_test.go`

- [ ] **Step 1: Add trace test for QUIC fields**

Append a test to `pkg/transfertrace/trace_test.go`:

```go
func TestRecorderWritesDirectQUICFields(t *testing.T) {
	var buf bytes.Buffer
	rec, err := NewRecorder(&buf, RoleSend, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Update(func(snap *Snapshot) {
		snap.At = time.Unix(0, int64(time.Second))
		snap.Phase = PhaseDirectExecute
		snap.AppBytes = 1024
		snap.DirectTransport = "quic"
		snap.QUICHandshakeMS = 12
		snap.QUICFirstByteMS = 18
		snap.QUICStreamBytesSent = 1024
		snap.QUICStreamGoodputMbps = "8.19"
		snap.LastState = "connected-direct-quic"
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rows := parseTraceCSV(t, buf.String())
	header := rows[0]
	record := rows[1]
	assertCSVValue(t, header, record, "direct_transport", "quic")
	assertCSVValue(t, header, record, "quic_handshake_ms", "12")
	assertCSVValue(t, header, record, "quic_first_byte_ms", "18")
	assertCSVValue(t, header, record, "quic_stream_bytes_sent", "1024")
	assertCSVValue(t, header, record, "quic_stream_goodput_mbps", "8.19")
}
```

- [ ] **Step 2: Run trace test to verify it fails**

Run:

```bash
go test ./pkg/transfertrace -run TestRecorderWritesDirectQUICFields -count=1
```

Expected: FAIL because QUIC fields are not in `Snapshot` or the CSV header.

- [ ] **Step 3: Add QUIC fields to `transfertrace.Snapshot`**

Add these fields to `pkg/transfertrace/trace.go`:

```go
DirectTransport         string
QUICHandshakeMS         int64
QUICFirstByteMS         int64
QUICStreamBytesSent     int64
QUICStreamBytesReceived int64
QUICStreamGoodputMbps   string
QUICSmoothedRTTMS       string
QUICLossEvents          int64
QUICCloseReason         string
```

Add matching header columns:

```go
"direct_transport",
"quic_handshake_ms",
"quic_first_byte_ms",
"quic_stream_bytes_sent",
"quic_stream_bytes_received",
"quic_stream_goodput_mbps",
"quic_smoothed_rtt_ms",
"quic_loss_events",
"quic_close_reason",
```

Add row output using existing formatting helpers:

```go
snap.DirectTransport,
formatOptionalInt64(snap.QUICHandshakeMS),
formatOptionalInt64(snap.QUICFirstByteMS),
formatOptionalInt64(snap.QUICStreamBytesSent),
formatOptionalInt64(snap.QUICStreamBytesReceived),
snap.QUICStreamGoodputMbps,
snap.QUICSmoothedRTTMS,
formatOptionalInt64(snap.QUICLossEvents),
snap.QUICCloseReason,
```

- [ ] **Step 4: Add metrics setter and wire endpoint stats**

In `pkg/session/external_transfer_metrics.go`, add:

```go
func (m *externalTransferMetrics) SetDirectQUICStats(stats directquic.Stats) {
	if m == nil {
		return
	}
	m.UpdateTrace(func(snap *transfertrace.Snapshot) {
		snap.DirectTransport = "quic"
		snap.QUICHandshakeMS = stats.HandshakeMS
		snap.QUICFirstByteMS = stats.FirstByteMS
		snap.QUICStreamBytesSent = stats.BytesSent
		snap.QUICStreamBytesReceived = stats.BytesReceived
		snap.QUICCloseReason = stats.CloseReason
	})
}
```

In `externalDirectQUICSendOverManager` and `externalDirectQUICReceiveOverManager`, read `externalTransferMetricsFromContext(ctx)` and call `SetDirectQUICStats(endpoint.Stats())` after first byte, after copy, and before return.

- [ ] **Step 5: Add checker summary test**

Add to `pkg/transfertrace/checker_test.go`:

```go
func TestCheckReportsQUICDiagnosticsSummary(t *testing.T) {
	trace := strings.Join([]string{
		HeaderLine,
		"1000,1000,send,direct-execute,0,1024,1024,0,1024,1024,1000,1000,true,,0,0,0,0,,0,0,0,0,connected-direct-quic,,0,0,0,0,0,0,0,0,,,8.19,,,0,0,0,0,0,0,0,0,quic,12,18,1024,0,8.19,,0,",
		"",
	}, "\n")
	result, err := Check(strings.NewReader(trace), Options{Role: RoleSend, StallWindow: time.Second})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Diagnostics.DirectTransport != "quic" {
		t.Fatalf("DirectTransport = %q, want quic", result.Diagnostics.DirectTransport)
	}
}
```

Adjust the CSV row if the final header order differs after Step 3.

- [ ] **Step 6: Run trace and checker tests**

Run:

```bash
go test ./pkg/transfertrace ./tools/transfertracecheck -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/session/external_transfer_metrics.go pkg/session/external_direct_quic.go pkg/transfertrace/trace.go pkg/transfertrace/trace_test.go pkg/transfertrace/checker.go pkg/transfertrace/checker_test.go tools/transfertracecheck/main.go tools/transfertracecheck/main_test.go
git commit -m "trace: add direct quic diagnostics"
```

## Task 7: Add Direct Transport Benchmark Harness

**Files:**
- Create: `scripts/direct-transport-benchmark.sh`
- Create: `scripts/direct_transport_benchmark_script_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write script test**

Create `scripts/direct_transport_benchmark_script_test.go`:

```go
package scripts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectTransportBenchmarkDocumentsQUICSelector(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "scripts", "direct-transport-benchmark.sh"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"DERPHOLE_DIRECT_TRANSPORT=quic",
		"diagnostic-direct-transport=quic",
		"diagnostic-iperf-tcp-goodput-mbps",
		"diagnostic-transfer-sender-goodput-mbps",
		"diagnostic-transfer-receiver-goodput-mbps",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run script test to verify it fails**

Run:

```bash
go test ./scripts -run TestDirectTransportBenchmarkDocumentsQUICSelector -count=1
```

Expected: FAIL because the script does not exist.

- [ ] **Step 3: Create benchmark wrapper**

Create `scripts/direct-transport-benchmark.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 sender-host receiver-host [size-mib]" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

sender_host="${1:?missing sender host}"
receiver_host="${2:?missing receiver host}"
size_mib="${3:-1024}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${DERPHOLE_DIRECT_TRANSPORT_LOG_DIR:-/tmp/derphole-direct-transport-${stamp}}"
mkdir -p "${log_dir}"

DERPHOLE_DIAG_LOG_DIR="${log_dir}/diag" \
DERPHOLE_DIRECT_TRANSPORT=quic \
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES="${DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES:-1}" \
./scripts/direct-udp-diagnostic-benchmark.sh "${sender_host}" "${receiver_host}" "${size_mib}"

summary="${log_dir}/diag/diagnostic-summary.env"
{
  echo "diagnostic-direct-transport=quic"
  if [[ -f "${summary}" ]]; then
    cat "${summary}"
  fi
} | tee "${log_dir}/diagnostic-summary.env"
```

Make it executable:

```bash
chmod +x scripts/direct-transport-benchmark.sh
```

- [ ] **Step 4: Document the harness**

Add this section to `docs/benchmarks.md` near the direct UDP diagnostic section:

````markdown
## Direct Transport QUIC Comparison

Use this when validating the QUIC direct data plane:

```bash
: "${DERPHOLE_BENCH_SENDER:?set sender host}"
: "${DERPHOLE_BENCH_RECEIVER:?set receiver host}"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-transport-benchmark.sh "${DERPHOLE_BENCH_SENDER}" "${DERPHOLE_BENCH_RECEIVER}" 1024
```

The script forces `DERPHOLE_DIRECT_TRANSPORT=quic`, runs the existing iperf-plus-transfer diagnostic flow, and writes `diagnostic-direct-transport=quic` in `diagnostic-summary.env`.

Do not compare QUIC runs to blast runs unless the same host pair, direction, payload size, and Tailscale-candidate setting are used.
````

- [ ] **Step 5: Run script tests**

Run:

```bash
go test ./scripts -run TestDirectTransportBenchmarkDocumentsQUICSelector -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/direct-transport-benchmark.sh scripts/direct_transport_benchmark_script_test.go docs/benchmarks.md
git commit -m "bench: add direct quic transport benchmark"
```

## Task 8: Run Local Gates And Live QUIC Validation

**Files:**
- Modify only files required by failures found in this task.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./pkg/directquic ./pkg/session ./pkg/transfertrace ./tools/transfertracecheck ./scripts -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full repository checks**

Run:

```bash
mise run check
```

Expected: PASS.

- [ ] **Step 3: Run local smoke test**

Run:

```bash
DERPHOLE_DIRECT_TRANSPORT=quic mise run smoke-local
```

Expected: PASS with matching payload integrity.

- [ ] **Step 4: Run live fast-path benchmark**

Run with user-provided hosts:

```bash
: "${DERPHOLE_FAST_SENDER:?set fast sender host}"
: "${DERPHOLE_FAST_RECEIVER:?set fast receiver host}"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-transport-benchmark.sh "${DERPHOLE_FAST_SENDER}" "${DERPHOLE_FAST_RECEIVER}" 1024
```

Expected:

- `diagnostic-direct-transport=quic`
- `stall-harness-success=true`
- sender and receiver SHA match
- `diagnostic-transfer-sender-goodput-mbps` is at least 75% of the lower clean iperf baseline
- `diagnostic-transfer-receiver-goodput-mbps` is at least 75% of the lower clean iperf baseline
- leak checks report `processes=0 udp_sockets=0`

- [ ] **Step 5: Run live relay-only or blocked-direct benchmark**

Run with a user-provided relay endpoint:

```bash
: "${DERPHOLE_RELAY_SENDER:?set relay sender host}"
: "${DERPHOLE_RELAY_RECEIVER:?set relay receiver host}"
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/direct-transport-benchmark.sh "${DERPHOLE_RELAY_SENDER}" "${DERPHOLE_RELAY_RECEIVER}" 128
```

Expected:

- transfer completes or exits with explicit fallback diagnostics
- no orphaned `derphole` process
- no leaked UDP sockets

- [ ] **Step 6: Commit live-gate fixes**

If code changed during live validation:

```bash
git status --short
git add pkg/directquic pkg/session pkg/transfertrace tools/transfertracecheck scripts docs/benchmarks.md
git commit -m "transport: validate direct quic live path"
```

If no code changed, do not create an empty commit.

## Task 9: Promote QUIC To Default After Benchmark Gate

**Files:**
- Modify: `pkg/session/external_direct_transport.go`
- Modify: `pkg/session/external_direct_transport_test.go`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Change default selector test**

In `pkg/session/external_direct_transport_test.go`, change the empty env case to:

```go
{name: "empty defaults quic", env: "", want: externalDirectTransportQUIC},
```

Add a specific blast override case:

```go
{name: "blast override", env: "blast", want: externalDirectTransportBlast},
```

- [ ] **Step 2: Run selector test to verify it fails**

Run:

```bash
go test ./pkg/session -run TestExternalDirectTransportFromEnv -count=1
```

Expected: FAIL because empty env still returns blast.

- [ ] **Step 3: Change the default**

In `pkg/session/external_direct_transport.go`, change empty env handling:

```go
func externalDirectTransportFromEnv() externalDirectTransportKind {
	switch externalDirectTransportKind(os.Getenv("DERPHOLE_DIRECT_TRANSPORT")) {
	case externalDirectTransportBlast:
		return externalDirectTransportBlast
	case externalDirectTransportQUIC, "":
		return externalDirectTransportQUIC
	case externalDirectTransportAuto:
		return externalDirectTransportAuto
	default:
		return externalDirectTransportQUIC
	}
}
```

- [ ] **Step 4: Document fallback override**

Add to `docs/benchmarks.md`:

```markdown
Set `DERPHOLE_DIRECT_TRANSPORT=blast` to compare the retired custom reliable UDP path during the validation window. New benchmark runs should leave the variable unset or set it to `quic`.
```

- [ ] **Step 5: Run final gates**

Run:

```bash
go test ./pkg/session -run TestExternalDirectTransportFromEnv -count=1
mise run check
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external_direct_transport.go pkg/session/external_direct_transport_test.go docs/benchmarks.md
git commit -m "transport: default direct transfers to quic"
```

## Task 10: Push And Watch CI

**Files:**
- No code changes unless CI fails.

- [ ] **Step 1: Push main**

Run:

```bash
git push origin main
```

Expected: push succeeds.

- [ ] **Step 2: Watch Checks**

Run:

```bash
gh run list --branch main --limit 5 --json databaseId,name,headSha,status,conclusion,url
```

Find the newest Checks run for the pushed SHA, then run:

```bash
head_sha="$(git rev-parse HEAD)"
checks_run_id="$(gh run list --branch main --limit 20 --json databaseId,name,headSha \
  --jq '.[] | select(.name == "Checks" and .headSha == "'"${head_sha}"'") | .databaseId' | head -n 1)"
test -n "${checks_run_id}"
gh run watch "${checks_run_id}" --exit-status
```

Expected: Checks passes.

- [ ] **Step 3: Watch Release and Pages**

Run:

```bash
gh run list --branch main --limit 10 --json databaseId,name,headSha,status,conclusion,url
```

For Release and Pages runs on the pushed SHA, watch any run still in progress:

```bash
head_sha="$(git rev-parse HEAD)"
for name in Release Pages; do
  run_id="$(gh run list --branch main --limit 20 --json databaseId,name,headSha,status \
    --jq '.[] | select(.name == "'"${name}"'" and .headSha == "'"${head_sha}"'" and .status != "completed") | .databaseId' | head -n 1)"
  if [[ -n "${run_id}" ]]; then
    gh run watch "${run_id}" --exit-status
  fi
done
```

Expected: Release and Pages pass.

- [ ] **Step 4: Report evidence**

Final report must include:

- pushed commit SHA
- `mise run check` result
- live benchmark log directories
- iperf TCP/UDP baselines
- derphole QUIC sender/receiver goodput
- direct state or fallback state
- leak check result
- GitHub Checks, Release, and Pages run IDs
