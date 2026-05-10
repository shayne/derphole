// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"fmt"
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

func TestReceiveWireGuardParallelReturnsAfterExpectedBytesWithoutAllStreams(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := bytes.Repeat([]byte("parallel"), 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := conn.Write(payload); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}()

	stats, err := receiveWireGuardParallel(ctx, &TransferStats{StartedAt: time.Now()}, ln, io.Discard, WireGuardConfig{
		Streams:   4,
		SizeBytes: int64(len(payload)),
	})
	if err != nil {
		t.Fatalf("receiveWireGuardParallel() error = %v", err)
	}
	if stats.BytesReceived != int64(len(payload)) {
		t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
	}
	<-done
}

func TestReceiveWireGuardParallelAcksAllStreamsAfterTargetReached(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const streams = 4
	payload := bytes.Repeat([]byte("parallel-ack"), 2048)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		go func() {
			conn, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			if _, err := conn.Write(payload); err != nil {
				errCh <- err
				return
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				errCh <- err
				return
			}
			ack := make([]byte, len(wireGuardDrainAck))
			if _, err := io.ReadFull(conn, ack); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(ack, wireGuardDrainAck) {
				errCh <- fmt.Errorf("ack = %q, want %q", ack, wireGuardDrainAck)
				return
			}
			errCh <- nil
		}()
	}

	stats, err := receiveWireGuardParallel(ctx, &TransferStats{StartedAt: time.Now()}, ln, io.Discard, WireGuardConfig{
		Streams:   streams,
		SizeBytes: int64(len(payload) * streams),
	})
	if err != nil {
		t.Fatalf("receiveWireGuardParallel() error = %v", err)
	}
	if stats.BytesReceived != int64(len(payload)*streams) {
		t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload)*streams)
	}
	for i := 0; i < streams; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("stream %d error = %v", i+1, err)
		}
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

	payload := bytes.Repeat([]byte("derphole"), 16<<10)
	var dst bytes.Buffer
	serverDone := make(chan error, 1)
	serverReady := make(chan struct{})
	sendDone := make(chan error, 1)
	senderFinished := make(chan struct{})
	go func() {
		cfg := WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  plan.listenerPrivHex,
			PeerPublicHex:  plan.senderPubHex,
			LocalAddr:      plan.listenerAddr.String(),
			PeerAddr:       plan.senderAddr.String(),
			DirectEndpoint: clientConn.LocalAddr().String(),
			Port:           uint16(plan.port),
		}
		node, resolved, err := newWireGuardNode(serverConn, cfg)
		if err != nil {
			serverDone <- err
			return
		}
		defer node.Close()

		ln, err := node.ListenTCP(resolved.port)
		if err != nil {
			serverDone <- err
			return
		}
		defer ln.Close()
		close(serverReady)

		tcpConn, err := acceptConn(ctx, ln)
		if err != nil {
			serverDone <- err
			return
		}
		defer tcpConn.Close()

		if _, err := io.CopyN(&dst, tcpConn, int64(len(payload))); err != nil {
			serverDone <- err
			return
		}
		if err := writeWireGuardDrainAck(tcpConn); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.Copy(io.Discard, tcpConn); err != nil {
			serverDone <- err
			return
		}
		select {
		case <-senderFinished:
		case <-ctx.Done():
		}
		serverDone <- nil
	}()
	select {
	case <-serverReady:
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server setup error = %v", err)
		}
		t.Fatal("server exited before becoming ready")
	case <-ctx.Done():
		t.Fatalf("timed out waiting for server readiness: %v", ctx.Err())
	}

	go func() {
		defer close(senderFinished)
		_, err := SendWireGuard(ctx, clientConn, bytes.NewReader(payload), WireGuardConfig{
			Transport:      transport,
			PrivateKeyHex:  plan.senderPrivHex,
			PeerPublicHex:  plan.listenerPubHex,
			LocalAddr:      plan.senderAddr.String(),
			PeerAddr:       plan.listenerAddr.String(),
			DirectEndpoint: serverConn.LocalAddr().String(),
			Port:           uint16(plan.port),
			SizeBytes:      int64(len(payload)),
		})
		sendDone <- err
	}()

	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("SendWireGuard() error = %v", err)
		}
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("ReceiveWireGuardToWriter() error = %v", err)
		}
		select {
		case err := <-sendDone:
			if err != nil {
				t.Fatalf("SendWireGuard() error = %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for SendWireGuard after receiver completed; received=%d want=%d", dst.Len(), len(payload))
		}
		if !bytes.Equal(dst.Bytes(), payload) {
			t.Fatalf("received payload mismatch: got %d bytes want %d", dst.Len(), len(payload))
		}
		return
	case <-ctx.Done():
		t.Fatalf("timed out waiting for SendWireGuard; received=%d want=%d", dst.Len(), len(payload))
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
