package derptun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMuxCarriesOneTCPStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientMux, serverMux := newMuxPair(t, time.Second)
	defer clientMux.Close()
	defer serverMux.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := serverMux.Accept(ctx)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("Accept() error = %v", err)
	case serverConn = <-serverConnCh:
	case <-ctx.Done():
		t.Fatal("Accept() did not return")
	}
	defer serverConn.Close()

	if _, err := clientConn.Write([]byte("hello over mux")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}

	got := make([]byte, len("hello over mux"))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server Read() error = %v", err)
	}
	if !bytes.Equal(got, []byte("hello over mux")) {
		t.Fatalf("server got %q, want %q", got, "hello over mux")
	}

	if _, err := serverConn.Write([]byte("reply")); err != nil {
		t.Fatalf("server Write() error = %v", err)
	}

	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("client Read() error = %v", err)
	}
	if !bytes.Equal(reply, []byte("reply")) {
		t.Fatalf("client got %q, want %q", reply, "reply")
	}
}

func TestMuxResendsUnackedDataAfterCarrierReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientMux, serverMux := newMuxPair(t, 2*time.Second)
	defer clientMux.Close()
	defer serverMux.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := serverMux.Accept(ctx)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("Accept() error = %v", err)
	case serverConn = <-serverConnCh:
	case <-ctx.Done():
		t.Fatal("Accept() did not return")
	}
	defer serverConn.Close()

	if _, err := clientConn.Write([]byte("before")); err != nil {
		t.Fatalf("initial client Write() error = %v", err)
	}
	before := make([]byte, len("before"))
	if _, err := io.ReadFull(serverConn, before); err != nil {
		t.Fatalf("initial server Read() error = %v", err)
	}
	if !bytes.Equal(before, []byte("before")) {
		t.Fatalf("initial payload = %q, want %q", before, "before")
	}
	time.Sleep(50 * time.Millisecond)

	clientA, serverA := net.Pipe()
	clientMux.ReplaceCarrier(clientA)

	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("after reconnect"))
		writeDone <- err
	}()

	header, payload, err := readFrame(serverA)
	if err != nil {
		t.Fatalf("read old carrier frame error = %v", err)
	}
	if header.Type != frameTypeData || string(payload) != "after reconnect" {
		t.Fatalf("old carrier frame = (%#v, %q), want data after reconnect", header, payload)
	}

	_ = serverA.Close()
	closeBoth(t, clientMux.ReplaceCarrier, serverMux.ReplaceCarrier)

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("client Write() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("client Write() did not complete after carrier replacement")
	}

	got := make([]byte, len("after reconnect"))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server Read() error = %v", err)
	}
	if !bytes.Equal(got, []byte("after reconnect")) {
		t.Fatalf("server got %q, want %q", got, "after reconnect")
	}
}

func TestMuxCloseFramePropagatesEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientMux, serverMux := newMuxPair(t, time.Second)
	defer clientMux.Close()
	defer serverMux.Close()

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, _ := serverMux.Accept(ctx)
		serverConnCh <- conn
	}()

	clientConn, err := clientMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	serverConn := <-serverConnCh
	defer serverConn.Close()

	if err := clientConn.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}
	if err := serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
			return
		}
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, err := serverConn.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("server Read() = %d, nil; want EOF/closed error", n)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("server Read() timed out waiting for close frame")
	}
}

func TestMuxAcceptReturnsWhenCarrierCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientCarrier, serverCarrier := net.Pipe()
	defer clientCarrier.Close()

	mux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer mux.Close()
	mux.ReplaceCarrier(serverCarrier)

	errCh := make(chan error, 1)
	go func() {
		conn, err := mux.Accept(ctx)
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()

	if err := clientCarrier.Close(); err != nil {
		t.Fatalf("client carrier Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() error = %v, want net.ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("Accept() did not return after carrier close")
	}
}

func TestMuxReplaysOpenAfterCarrierReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientMux := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Second})
	serverMux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer clientMux.Close()
	defer serverMux.Close()

	clientA, serverA := net.Pipe()
	clientMux.ReplaceCarrier(clientA)

	type openResult struct {
		conn net.Conn
		err  error
	}
	openCh := make(chan openResult, 1)
	go func() {
		conn, err := clientMux.OpenStream(ctx)
		openCh <- openResult{conn: conn, err: err}
	}()

	header, _, err := readFrame(serverA)
	if err != nil {
		t.Fatalf("read old carrier frame error = %v", err)
	}
	if header.Type != frameTypeOpen {
		t.Fatalf("old carrier frame type = %q, want %q", header.Type, frameTypeOpen)
	}

	_ = serverA.Close()
	clientB, serverB := net.Pipe()
	clientMux.ReplaceCarrier(clientB)
	serverMux.ReplaceCarrier(serverB)

	var clientConn net.Conn
	select {
	case result := <-openCh:
		if result.err != nil {
			t.Fatalf("OpenStream() error = %v", result.err)
		}
		clientConn = result.conn
	case <-ctx.Done():
		t.Fatal("OpenStream() did not replay open on replacement carrier")
	}
	defer clientConn.Close()

	serverConn, err := serverMux.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer serverConn.Close()

	if _, err := clientConn.Write([]byte("open replay")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	got := make([]byte, len("open replay"))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}
	if string(got) != "open replay" {
		t.Fatalf("server got %q, want open replay", got)
	}
}

func TestMuxOpenStreamTimesOutWithoutCarrier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	mux := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: 50 * time.Millisecond})
	defer mux.Close()

	conn, err := mux.OpenStream(ctx)
	if err == nil {
		_ = conn.Close()
		t.Fatal("OpenStream() error = nil, want reconnect timeout")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("OpenStream() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestMuxOpenStreamHonorsContextWithoutCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mux := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Hour})
	defer mux.Close()

	conn, err := mux.OpenStream(ctx)
	if err == nil {
		_ = conn.Close()
		t.Fatal("OpenStream() error = nil, want context canceled")
	}
	if err != context.Canceled {
		t.Fatalf("OpenStream() error = %v, want %v", err, context.Canceled)
	}
}

func TestMuxSuppressesDuplicateDeliveryWhileFirstWriteBlocks(t *testing.T) {
	serverMux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer serverMux.Close()

	stream, appConn := serverMux.getOrCreateRemoteStream(2)
	defer appConn.Close()

	payload := []byte("duplicate")
	firstDone := make(chan error, 1)
	go func() {
		_, err := stream.deliver(0, payload)
		firstDone <- err
	}()
	time.Sleep(20 * time.Millisecond)

	secondDone := make(chan error, 1)
	go func() {
		_, err := stream.deliver(0, payload)
		secondDone <- err
	}()
	time.Sleep(20 * time.Millisecond)

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(appConn, got); err != nil {
		t.Fatalf("first ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("first payload = %q, want %q", got, payload)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first deliver() error = %v", err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second deliver() error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second duplicate deliver() did not return")
	}

	if err := appConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, err := appConn.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("duplicate Read() = (%d, %v), want no duplicate bytes", n, err)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("duplicate Read() error = %v, want timeout after no duplicate bytes", err)
	}
}

func TestMuxFailedDeliveryDoesNotAdvanceRecvSeq(t *testing.T) {
	serverMux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer serverMux.Close()

	stream, appConn := serverMux.getOrCreateRemoteStream(2)
	payload := []byte("lost")
	done := make(chan error, 1)
	go func() {
		_, err := stream.deliver(0, payload)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = appConn.Close()

	if err := <-done; err == nil {
		t.Fatal("deliver() error = nil, want local close error")
	}
	stream.stateMu.Lock()
	recvSeq := stream.recvSeq
	stream.stateMu.Unlock()
	if recvSeq != 0 {
		t.Fatalf("recvSeq = %d, want 0 after failed delivery", recvSeq)
	}
}

func TestMuxRemovesStreamOnCloseFrame(t *testing.T) {
	serverMux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer serverMux.Close()

	_, appConn := serverMux.getOrCreateRemoteStream(2)
	defer appConn.Close()
	if stream := serverMux.getStream(2); stream == nil {
		t.Fatal("stream missing before close")
	}
	if err := serverMux.handleFrame(frameHeader{Type: frameTypeClose, StreamID: 2}, nil); err != nil {
		t.Fatalf("handleFrame(close) error = %v", err)
	}
	if stream := serverMux.getStream(2); stream != nil {
		t.Fatal("stream still present after close frame")
	}
}

func TestReadFrameRejectsInvalidPayloadLength(t *testing.T) {
	header := []byte(`{"type":"data","stream_id":1,"length":-1}`)
	var raw bytes.Buffer
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(header)))
	raw.Write(prefix[:])
	raw.Write(header)

	_, _, err := readFrame(&raw)
	if err == nil {
		t.Fatal("readFrame() error = nil, want invalid frame length error")
	}
}

func TestReadFrameRejectsOversizedHeaderLength(t *testing.T) {
	var raw bytes.Buffer
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(maxFrameHeaderBytes+1))
	raw.Write(prefix[:])

	_, _, err := readFrame(&raw)
	if err == nil {
		t.Fatal("readFrame() error = nil, want invalid frame length error")
	}
}

func TestReadFrameRejectsOversizedPayloadLength(t *testing.T) {
	header := []byte(`{"type":"data","stream_id":1,"length":1048577}`)
	var raw bytes.Buffer
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(header)))
	raw.Write(prefix[:])
	raw.Write(header)

	_, _, err := readFrame(&raw)
	if err == nil {
		t.Fatal("readFrame() error = nil, want invalid frame length error")
	}
}

func newMuxPair(t *testing.T, reconnectTimeout time.Duration) (*Mux, *Mux) {
	t.Helper()

	clientCarrier, serverCarrier := net.Pipe()

	clientMux := NewMux(MuxConfig{
		Role:             MuxRoleClient,
		ReconnectTimeout: reconnectTimeout,
	})
	serverMux := NewMux(MuxConfig{
		Role:             MuxRoleServer,
		ReconnectTimeout: reconnectTimeout,
	})

	clientMux.ReplaceCarrier(clientCarrier)
	serverMux.ReplaceCarrier(serverCarrier)

	return clientMux, serverMux
}

func closeBoth(t *testing.T, replaceClient func(io.ReadWriteCloser), replaceServer func(io.ReadWriteCloser)) {
	t.Helper()

	nextClient, nextServer := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		replaceClient(nextClient)
	}()
	go func() {
		defer wg.Done()
		replaceServer(nextServer)
	}()
	wg.Wait()
}
