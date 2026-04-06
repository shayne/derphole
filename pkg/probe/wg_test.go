package probe

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWireGuardTransferCompletesAcrossLoopback(t *testing.T) {
	t.Run("batched", func(t *testing.T) {
		testWireGuardTransfer(t, probeTransportBatched)
	})
}

func TestWireGuardParallelShares(t *testing.T) {
	shares, err := wireGuardParallelShares(17, 4)
	if err != nil {
		t.Fatalf("wireGuardParallelShares() error = %v", err)
	}
	want := []int64{5, 4, 4, 4}
	if !bytes.Equal(int64SliceToBytes(shares), int64SliceToBytes(want)) {
		t.Fatalf("wireGuardParallelShares() = %v, want %v", shares, want)
	}

	shares, err = wireGuardParallelShares(0, 4)
	if err != nil {
		t.Fatalf("wireGuardParallelShares(0) error = %v", err)
	}
	want = []int64{0, 0, 0, 0}
	if !bytes.Equal(int64SliceToBytes(shares), int64SliceToBytes(want)) {
		t.Fatalf("wireGuardParallelShares(0) = %v, want %v", shares, want)
	}
}

func int64SliceToBytes(v []int64) []byte {
	out := make([]byte, 0, len(v)*8)
	for _, n := range v {
		out = append(out, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return out
}

func TestNewWireGuardPlanChoosesNonDefaultPort(t *testing.T) {
	plan, err := newWireGuardPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.port == defaultWireGuardProbePort {
		t.Fatalf("newWireGuardPlan() port = %d, want non-default ephemeral port", plan.port)
	}
	if plan.port <= 0 || plan.port > 65535 {
		t.Fatalf("newWireGuardPlan() port = %d, want valid TCP port", plan.port)
	}
}

func TestWireGuardTransferRejectsLegacyTransport(t *testing.T) {
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	plan, err := newWireGuardPlan()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReceiveWireGuardToWriter(context.Background(), serverConn, io.Discard, WireGuardConfig{
		Transport:      probeTransportLegacy,
		PrivateKeyHex:  plan.listenerPrivHex,
		PeerPublicHex:  plan.senderPubHex,
		LocalAddr:      plan.listenerAddr.String(),
		PeerAddr:       plan.senderAddr.String(),
		DirectEndpoint: "127.0.0.1:1",
		Port:           uint16(plan.port),
	})
	if err == nil || !strings.Contains(err.Error(), "requires \"batched\" transport") {
		t.Fatalf("ReceiveWireGuardToWriter() error = %v, want batched transport rejection", err)
	}
}

func testWireGuardTransfer(t *testing.T, transport string) {
	t.Helper()

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	plan, err := newWireGuardPlan()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("derpcat"), 16<<10)
	var dst bytes.Buffer
	serverDone := make(chan error, 1)
	go func() {
		_, err := ReceiveWireGuardToWriter(ctx, serverConn, &dst, WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  plan.listenerPrivHex,
			PeerPublicHex:  plan.senderPubHex,
			LocalAddr:      plan.listenerAddr.String(),
			PeerAddr:       plan.senderAddr.String(),
			DirectEndpoint: clientConn.LocalAddr().String(),
			Port:           uint16(plan.port),
		})
		serverDone <- err
	}()

	if _, err := SendWireGuard(ctx, clientConn, bytes.NewReader(payload), WireGuardConfig{
		Transport:      transport,
		PrivateKeyHex:  plan.senderPrivHex,
		PeerPublicHex:  plan.listenerPubHex,
		LocalAddr:      plan.senderAddr.String(),
		PeerAddr:       plan.listenerAddr.String(),
		DirectEndpoint: serverConn.LocalAddr().String(),
		Port:           uint16(plan.port),
	}); err != nil {
		t.Fatalf("SendWireGuard() error = %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("ReceiveWireGuardToWriter() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for ReceiveWireGuardToWriter; received=%d want=%d", dst.Len(), len(payload))
	}

	if !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("received payload mismatch: got %d bytes want %d", dst.Len(), len(payload))
	}
}
