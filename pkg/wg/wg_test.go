package wg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDeriveAddressesIsDeterministic(t *testing.T) {
	var sessionID [16]byte
	sessionID[0] = 7

	aPrefix, aListener, aSender := DeriveAddresses(sessionID)
	bPrefix, bListener, bSender := DeriveAddresses(sessionID)

	if aPrefix != bPrefix || aListener != bListener || aSender != bSender {
		t.Fatalf("DeriveAddresses() is not deterministic: %v %v %v vs %v %v %v", aPrefix, aListener, aSender, bPrefix, bListener, bSender)
	}
	if aPrefix.Bits() != 64 {
		t.Fatalf("prefix bits = %d, want 64", aPrefix.Bits())
	}
	if got := aPrefix.Addr().As16()[0]; got != 0xfd {
		t.Fatalf("prefix first byte = 0x%x, want fd", got)
	}
	if !aPrefix.Contains(aListener) || !aPrefix.Contains(aSender) {
		t.Fatalf("derived addresses %v %v not in prefix %v", aListener, aSender, aPrefix)
	}
	if aListener == aSender {
		t.Fatal("listener and sender addresses are identical")
	}

	var otherSessionID [16]byte
	otherSessionID[0] = 8
	otherPrefix, otherListener, otherSender := DeriveAddresses(otherSessionID)
	if aPrefix == otherPrefix && aListener == otherListener && aSender == otherSender {
		t.Fatal("different session IDs derived identical addresses")
	}
}

func TestMemoryTransportExchangesPackets(t *testing.T) {
	a, b := NewMemoryTransportPair()

	if err := a.Send([]byte("ping")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("Receive() = %q, want ping", got)
	}
}

func TestMemoryTransportReceiveRespectsContext(t *testing.T) {
	_, b := NewMemoryTransportPair()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.Receive(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive() error = %v, want context.Canceled", err)
	}
}

func TestBindCloseAfterReopenUnblocksReceive(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	bind := NewBind(BindConfig{PacketConn: pc})

	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("first Open() receive funcs = %d, want 1", len(fns))
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	fns, _, err = bind.Open(0)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("second Open() receive funcs = %d, want 1", len(fns))
	}

	done := make(chan error, 1)
	go func() {
		packet := make([][]byte, 1)
		packet[0] = make([]byte, 64<<10)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](packet, sizes, eps)
		done <- err
	}()

	if err := bind.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not unblock after Close")
	}
}

func TestBindDoesNotInferDirectFromArbitraryInboundUDP(t *testing.T) {
	pc := newLoopPacketConn(t)
	defer pc.Close()

	bind := NewBind(BindConfig{
		PacketConn:   pc,
		PathSelector: fakeSelector{},
	})
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer bind.Close()

	sender := newLoopPacketConn(t)
	defer sender.Close()

	done := make(chan error, 1)
	go func() {
		packet := make([][]byte, 1)
		packet[0] = make([]byte, 64<<10)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fns[0](packet, sizes, eps)
		if err != nil {
			done <- err
			return
		}
		if n != 1 {
			done <- errors.New("receive count != 1")
			return
		}
		if got := string(packet[0][:sizes[0]]); got != "noise" {
			done <- errors.New("unexpected payload: " + got)
			return
		}
		done <- nil
	}()

	if _, err := sender.WriteTo([]byte("noise"), pc.LocalAddr()); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("receive error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not complete")
	}

	if got := bind.directUDPAddr(); got != nil {
		t.Fatalf("directUDPAddr() = %v, want nil", got)
	}
	if got := bind.DirectEndpoint(); got != "" {
		t.Fatalf("DirectEndpoint() = %q, want empty", got)
	}
	if got := bind.activeDirectAddr(); got != nil {
		t.Fatalf("activeDirectAddr() = %v, want nil", got)
	}
	if bind.DirectConfirmed() {
		t.Fatal("DirectConfirmed() = true, want false")
	}
}

func TestBindNonSelectorDirectRequiresValidationBeforeConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	derpA, derpB := newTestDERPClientPair(t, ctx)
	pc := newLoopPacketConn(t)
	defer pc.Close()
	directPeer := newLoopPacketConn(t)
	defer directPeer.Close()

	bind := NewBind(BindConfig{
		PacketConn:     pc,
		DERPClient:     derpA,
		PeerDERP:       derpB.PublicKey(),
		DirectEndpoint: directPeer.LocalAddr().String(),
	})
	if bind.DirectConfirmed() {
		t.Fatal("DirectConfirmed() before validation = true, want false")
	}

	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer bind.Close()

	directDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64<<10)
		_ = directPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := directPeer.ReadFrom(buf)
		if err != nil {
			directDone <- nil
			return
		}
		directDone <- append([]byte(nil), buf[:n]...)
	}()

	payload := []byte("probe")
	if err := bind.Send([][]byte{payload}, &Endpoint{dst: "derp"}, 0); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case got := <-directDone:
		if string(got) != string(payload) {
			t.Fatalf("direct payload = %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct send did not reach configured endpoint")
	}

	pkt, err := derpB.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := string(pkt.Payload); got != string(payload) {
		t.Fatalf("DERP payload = %q, want %q", got, payload)
	}
	if bind.DirectConfirmed() {
		t.Fatal("DirectConfirmed() after send without inbound validation = true, want false")
	}
}

func TestBindSelectorSendUsesCoherentDirectPathSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	derpA, derpB := newTestDERPClientPair(t, ctx)
	pc := newLoopPacketConn(t)
	defer pc.Close()
	directA := newLoopPacketConn(t)
	defer directA.Close()
	directB := newLoopPacketConn(t)
	defer directB.Close()

	selector := &scriptedSelector{
		current: selectorPath{endpoint: directA.LocalAddr().String(), active: false},
		next:    selectorPath{endpoint: directB.LocalAddr().String(), active: true},
	}
	bind := NewBind(BindConfig{
		PacketConn:   pc,
		DERPClient:   derpA,
		PeerDERP:     derpB.PublicKey(),
		PathSelector: selector,
	})
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer bind.Close()

	directADone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64<<10)
		_ = directA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := directA.ReadFrom(buf)
		if err != nil {
			directADone <- nil
			return
		}
		directADone <- append([]byte(nil), buf[:n]...)
	}()

	payload := []byte("coherent")
	if err := bind.Send([][]byte{payload}, &Endpoint{dst: "derp"}, 0); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case got := <-directADone:
		if string(got) != string(payload) {
			t.Fatalf("direct A payload = %q, want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct send did not use first snapshot endpoint")
	}

	_ = directB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 64<<10)
	if _, _, err := directB.ReadFrom(buf); err == nil {
		t.Fatal("direct send used churned endpoint instead of first snapshot")
	}

	pkt, err := derpB.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := string(pkt.Payload); got != string(payload) {
		t.Fatalf("DERP payload = %q, want %q", got, payload)
	}
	if calls := selector.calls(); calls != 1 {
		t.Fatalf("selector DirectPath() calls = %d, want 1", calls)
	}
}

func TestNodeTCPRoundTripOverUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	aConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer aConn.Close()

	bConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer bConn.Close()

	listenerAddr := netip.MustParseAddr("192.168.4.29")
	senderAddr := netip.MustParseAddr("192.168.4.28")

	listenerPriv := mustHex32(t, "003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641")
	listenerPub := mustHex32(t, "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28")
	senderPriv := mustHex32(t, "087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379")
	senderPub := mustHex32(t, "f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c")

	listener, err := NewNode(Config{
		PrivateKey:     listenerPriv,
		PeerPublicKey:  senderPub,
		LocalAddr:      listenerAddr,
		PeerAddr:       senderAddr,
		PacketConn:     aConn,
		DirectEndpoint: bConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("NewNode(listener) error = %v", err)
	}
	defer listener.Close()

	sender, err := NewNode(Config{
		PrivateKey:     senderPriv,
		PeerPublicKey:  listenerPub,
		LocalAddr:      senderAddr,
		PeerAddr:       listenerAddr,
		PacketConn:     bConn,
		DirectEndpoint: aConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("NewNode(sender) error = %v", err)
	}
	defer sender.Close()

	ln, err := listener.ListenTCP(7000)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "hello" {
			serverDone <- errors.New("unexpected client payload")
			return
		}
		_, err = conn.Write([]byte("world"))
		serverDone <- err
	}()

	conn, err := sender.DialTCP(ctx, netip.AddrPortFrom(listenerAddr, 7000))
	if err != nil {
		listenerSent, listenerRecv := listener.bind.Stats()
		senderSent, senderRecv := sender.bind.Stats()
		t.Fatalf("DialTCP() error = %v (listener opened=%t sent=%d recv=%d sender opened=%t sent=%d recv=%d listener endpoint=%q sender endpoint=%q)", err, listener.bind.opened, listenerSent, listenerRecv, sender.bind.opened, senderSent, senderRecv, listener.DirectEndpoint(), sender.DirectEndpoint())
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}

	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}
	if string(reply) != "world" {
		t.Fatalf("reply = %q, want %q", reply, "world")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not complete")
	}
}

func TestNodeTCPCloseWritePropagatesEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	aConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer aConn.Close()

	bConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer bConn.Close()

	var sessionID [16]byte
	sessionID[0] = 9
	_, listenerAddr, senderAddr := DeriveAddresses(sessionID)

	listenerPriv := mustHex32(t, "003ed5d73b55806c30de3f8a7bdab38af13539220533055e635690b8b87ad641")
	listenerPub := mustHex32(t, "c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28")
	senderPriv := mustHex32(t, "087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379")
	senderPub := mustHex32(t, "f928d4f6c1b86c12f2562c10b07c555c5c57fd00f59e90c8d8d88767271cbf7c")

	listener, err := NewNode(Config{
		PrivateKey:     listenerPriv,
		PeerPublicKey:  senderPub,
		LocalAddr:      listenerAddr,
		PeerAddr:       senderAddr,
		PacketConn:     aConn,
		DirectEndpoint: bConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("NewNode(listener) error = %v", err)
	}
	defer listener.Close()

	sender, err := NewNode(Config{
		PrivateKey:     senderPriv,
		PeerPublicKey:  listenerPub,
		LocalAddr:      senderAddr,
		PeerAddr:       listenerAddr,
		PacketConn:     bConn,
		DirectEndpoint: aConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatalf("NewNode(sender) error = %v", err)
	}
	defer sender.Close()

	ln, err := listener.ListenTCP(7001)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf, err := io.ReadAll(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "hello" {
			serverDone <- errors.New("unexpected client payload")
			return
		}
		serverDone <- nil
	}()

	conn, err := sender.DialTCP(ctx, netip.AddrPortFrom(listenerAddr, 7001))
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
	} else {
		t.Fatal("DialTCP() connection does not support CloseWrite")
	}
	defer conn.Close()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not observe EOF")
	}
}

func mustHex32(t *testing.T, v string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(v)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", v, err)
	}
	if len(raw) != 32 {
		t.Fatalf("DecodeString(%q) len = %d, want 32", v, len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

type fakeSelector struct {
	endpoint string
	direct   bool
}

func (f fakeSelector) DirectPath() (string, bool) { return f.endpoint, f.direct }

type selectorPath struct {
	endpoint string
	active   bool
}

type scriptedSelector struct {
	mu      sync.Mutex
	current selectorPath
	next    selectorPath
	called  int
}

func (s *scriptedSelector) DirectPath() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called++
	path := s.current
	if s.called == 1 {
		s.current = s.next
	}
	return path.endpoint, path.active
}

func (s *scriptedSelector) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.called
}

func newLoopPacketConn(t *testing.T) net.PacketConn {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	return pc
}

func newTestDERPClientPair(t *testing.T, ctx context.Context) (*derpbind.Client, *derpbind.Client) {
	t.Helper()

	node, serverURL := newTestDERPNode(t)
	a, err := derpbind.NewClient(ctx, node, serverURL)
	if err != nil {
		t.Fatalf("NewClient(a) error = %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	b, err := derpbind.NewClient(ctx, node, serverURL)
	if err != nil {
		t.Fatalf("NewClient(b) error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	readyPayload := []byte("ready")
	for {
		if err := a.Send(ctx, b.PublicKey(), readyPayload); err != nil {
			t.Fatalf("Send(ready) error = %v", err)
		}

		recvCtx, recvCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		pkt, err := b.Receive(recvCtx)
		recvCancel()
		if err == nil {
			if !bytes.Equal(pkt.Payload, readyPayload) {
				t.Fatalf("ready payload = %q, want %q", pkt.Payload, readyPayload)
			}
			break
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive(ready) error = %v", err)
		}
		if ctx.Err() != nil {
			t.Fatalf("Receive(ready) error = %v", ctx.Err())
		}
	}
	return a, b
}

func newTestDERPNode(t *testing.T) (*tailcfg.DERPNode, string) {
	t.Helper()

	server := derpserver.New(key.NewNode(), t.Logf)
	t.Cleanup(func() { _ = server.Close() })

	derpHTTP := httptest.NewServer(derpserver.Handler(server))
	t.Cleanup(derpHTTP.Close)

	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "test-1",
						RegionID: 1,
						HostName: "127.0.0.1",
						IPv4:     "127.0.0.1",
						STUNPort: -1,
						DERPPort: 0,
					},
				},
			},
		},
	}

	mapHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(dm)
	}))
	t.Cleanup(mapHTTP.Close)

	return dm.Regions[1].Nodes[0], derpHTTP.URL + "/derp"
}
