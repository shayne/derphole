// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"errors"
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

func TestResolveWireGuardConfigDefaultsTransportAndPort(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	plan, err := newWireGuardPlan()
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveWireGuardConfig(conn, WireGuardConfig{
		PrivateKeyHex: plan.listenerPrivHex,
		PeerPublicHex: plan.senderPubHex,
		LocalAddr:     plan.listenerAddr.String(),
		PeerAddr:      plan.senderAddr.String(),
	})
	if err != nil {
		t.Fatalf("resolveWireGuardConfig() error = %v", err)
	}
	if resolved.port != defaultWireGuardProbePort {
		t.Fatalf("resolved port = %d, want default %d", resolved.port, defaultWireGuardProbePort)
	}
	if resolved.localAddr != plan.listenerAddr || resolved.peerAddr != plan.senderAddr {
		t.Fatalf("resolved addrs = %s/%s, want %s/%s", resolved.localAddr, resolved.peerAddr, plan.listenerAddr, plan.senderAddr)
	}
}

func TestResolveWireGuardConfigRejectsInvalidInputs(t *testing.T) {
	plan, err := newWireGuardPlan()
	if err != nil {
		t.Fatal(err)
	}
	valid := WireGuardConfig{
		Transport:     probeTransportBatched,
		PrivateKeyHex: plan.listenerPrivHex,
		PeerPublicHex: plan.senderPubHex,
		LocalAddr:     plan.listenerAddr.String(),
		PeerAddr:      plan.senderAddr.String(),
		Port:          uint16(plan.port),
	}

	tests := []struct {
		name string
		conn net.PacketConn
		cfg  WireGuardConfig
		want string
	}{
		{name: "nil conn", cfg: valid, want: "nil packet conn"},
		{name: "legacy transport", conn: mustPacketConn(t), cfg: withWireGuardTransport(valid, probeTransportLegacy), want: `requires "batched" transport`},
		{name: "private key", conn: mustPacketConn(t), cfg: withWireGuardPrivateKey(valid, "nope"), want: "parse wg private key"},
		{name: "peer public key", conn: mustPacketConn(t), cfg: withWireGuardPeerPublicKey(valid, "nope"), want: "parse wg peer public key"},
		{name: "local addr", conn: mustPacketConn(t), cfg: withWireGuardLocalAddr(valid, "nope"), want: "parse wg local addr"},
		{name: "peer addr", conn: mustPacketConn(t), cfg: withWireGuardPeerAddr(valid, "nope"), want: "parse wg peer addr"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.conn != nil {
				defer tc.conn.Close()
			}
			_, err := resolveWireGuardConfig(tc.conn, tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("resolveWireGuardConfig() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func mustPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func withWireGuardTransport(cfg WireGuardConfig, transport string) WireGuardConfig {
	cfg.Transport = transport
	return cfg
}

func withWireGuardPrivateKey(cfg WireGuardConfig, key string) WireGuardConfig {
	cfg.PrivateKeyHex = key
	return cfg
}

func withWireGuardPeerPublicKey(cfg WireGuardConfig, key string) WireGuardConfig {
	cfg.PeerPublicHex = key
	return cfg
}

func withWireGuardLocalAddr(cfg WireGuardConfig, addr string) WireGuardConfig {
	cfg.LocalAddr = addr
	return cfg
}

func withWireGuardPeerAddr(cfg WireGuardConfig, addr string) WireGuardConfig {
	cfg.PeerAddr = addr
	return cfg
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

func TestSendWireGuardParallelSendsSharesAndWaitsForAcks(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const streams = 4
	const totalBytes = 17
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	receivedCh := make(chan int64, streams)
	for i := 0; i < streams; i++ {
		go func() {
			conn, err := acceptConn(ctx, ln)
			if err != nil {
				t.Error(err)
				receivedCh <- 0
				return
			}
			defer conn.Close()
			n, err := io.Copy(io.Discard, conn)
			if err != nil {
				t.Error(err)
				receivedCh <- n
				return
			}
			if err := writeWireGuardDrainAck(conn); err != nil {
				t.Error(err)
			}
			receivedCh <- n
		}()
	}

	stats, err := sendWireGuardParallel(ctx, &TransferStats{StartedAt: time.Now()}, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp4", ln.Addr().String())
	}, WireGuardConfig{Streams: streams, SizeBytes: totalBytes})
	if err != nil {
		t.Fatalf("sendWireGuardParallel() error = %v", err)
	}
	if stats.BytesSent != totalBytes {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, totalBytes)
	}

	var received int64
	for i := 0; i < streams; i++ {
		received += <-receivedCh
	}
	if received != totalBytes {
		t.Fatalf("received bytes = %d, want %d", received, totalBytes)
	}
}

func TestReceiveWireGuardSingleWritesPayloadAndAck(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := []byte("wireguard-single")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
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

	var dst bytes.Buffer
	stats, err := receiveWireGuardSingle(ctx, &TransferStats{StartedAt: time.Now()}, &dst, WireGuardConfig{
		SizeBytes: int64(len(payload)),
	}, func(ctx context.Context) (net.Conn, error) {
		return acceptConn(ctx, ln)
	})
	if err != nil {
		t.Fatalf("receiveWireGuardSingle() error = %v", err)
	}
	if !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("received = %q, want %q", dst.Bytes(), payload)
	}
	if stats.BytesReceived != int64(len(payload)) {
		t.Fatalf("BytesReceived = %d, want %d", stats.BytesReceived, len(payload))
	}
	if err := <-errCh; err != nil {
		t.Fatalf("sender error = %v", err)
	}
}

func TestWireGuardParallelReceiverHelperErrors(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	receiver := newWireGuardParallelReceiver(ctx, &TransferStats{StartedAt: time.Now()}, ln, WireGuardConfig{SizeBytes: 100})

	if err := receiver.checkReaderDrain(true); err != nil {
		t.Fatalf("checkReaderDrain(accepting) error = %v", err)
	}

	connA, connB := net.Pipe()
	receiver.activeConn = []net.Conn{connA}
	if err := receiver.checkReaderDrain(false); err != nil {
		t.Fatalf("checkReaderDrain(active) error = %v", err)
	}
	_ = connB.Close()
	_ = connA.Close()
	receiver.activeConn = nil

	if err := receiver.checkReaderDrain(false); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("checkReaderDrain(drained) error = %v, want unexpected EOF", err)
	}

	reportErr := errors.New("receiver failed")
	receiver.reportErr(reportErr)
	receiver.reportErr(errors.New("dropped"))
	if got := <-receiver.errCh; !errors.Is(got, reportErr) {
		t.Fatalf("reportErr() = %v, want first error", got)
	}

	stats, err := receiver.stopAndWaitErr(reportErr)
	if !errors.Is(err, reportErr) || stats != (TransferStats{}) {
		t.Fatalf("stopAndWaitErr() = %#v, %v; want zero stats and error", stats, err)
	}
}

func TestWireGuardParallelReceiverAckAndReadError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	receiver := newWireGuardParallelReceiver(ctx, &TransferStats{StartedAt: time.Now()}, ln, WireGuardConfig{SizeBytes: 100})

	connA, connB := net.Pipe()
	ackDone := make(chan error, 1)
	go func() {
		ack := make([]byte, len(wireGuardDrainAck))
		_, err := io.ReadFull(connB, ack)
		if err == nil && !bytes.Equal(ack, wireGuardDrainAck) {
			err = fmt.Errorf("ack = %q, want %q", ack, wireGuardDrainAck)
		}
		ackDone <- err
	}()
	receiver.ackStreamEOF(1, connA, 10)
	if err := <-ackDone; err != nil {
		t.Fatalf("ack read error = %v", err)
	}
	_ = connA.Close()
	_ = connB.Close()

	brokenA, brokenB := net.Pipe()
	_ = brokenB.Close()
	receiver.ackStreamEOF(2, brokenA, 10)
	if err := <-receiver.errCh; err == nil {
		t.Fatal("ackStreamEOF(broken) error = nil, want reported error")
	}
	_ = brokenA.Close()

	readErr := errors.New("read failed")
	receiver.reportReadError(3, readErr, 10)
	if err := <-receiver.errCh; !errors.Is(err, readErr) {
		t.Fatalf("reportReadError() = %v, want read error", err)
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
