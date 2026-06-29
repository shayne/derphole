// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
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

func TestMuxPipelinesSmallWritesWithoutWaitingForAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientMux := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Second})
	defer clientMux.Close()

	clientCarrier, serverCarrier := net.Pipe()
	defer serverCarrier.Close()
	clientMux.ReplaceCarrier(clientCarrier)

	type openResult struct {
		conn net.Conn
		err  error
	}
	openCh := make(chan openResult, 1)
	go func() {
		conn, err := clientMux.OpenStream(ctx)
		openCh <- openResult{conn: conn, err: err}
	}()

	openHeader, _, err := readFrame(serverCarrier)
	if err != nil {
		t.Fatalf("read open frame error = %v", err)
	}
	if openHeader.Type != frameTypeOpen {
		t.Fatalf("open frame type = %q, want %q", openHeader.Type, frameTypeOpen)
	}
	writeTestFrame(t, serverCarrier, frameHeader{
		Type:     frameTypeAck,
		StreamID: openHeader.StreamID,
		Seq:      0,
	}, nil)

	var clientConn net.Conn
	select {
	case result := <-openCh:
		if result.err != nil {
			t.Fatalf("OpenStream() error = %v", result.err)
		}
		clientConn = result.conn
	case <-ctx.Done():
		t.Fatal("OpenStream() did not return after open ACK")
	}
	defer clientConn.Close()

	firstDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("a"))
		firstDone <- err
	}()

	firstHeader, firstPayload, err := readFrame(serverCarrier)
	if err != nil {
		t.Fatalf("read first data frame error = %v", err)
	}
	if firstHeader.Type != frameTypeData || string(firstPayload) != "a" {
		t.Fatalf("first frame = (%#v, %q), want data a", firstHeader, firstPayload)
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("b"))
		secondDone <- err
	}()

	type frameResult struct {
		header  frameHeader
		payload []byte
		err     error
	}
	secondFrame := make(chan frameResult, 1)
	go func() {
		header, payload, err := readFrame(serverCarrier)
		secondFrame <- frameResult{header: header, payload: payload, err: err}
	}()

	select {
	case result := <-secondFrame:
		if result.err != nil {
			t.Fatalf("read second data frame error = %v", result.err)
		}
		if result.header.Type != frameTypeData || string(result.payload) != "b" {
			t.Fatalf("second frame = (%#v, %q), want data b", result.header, result.payload)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second small write did not send before first ACK")
	}

	writeTestFrame(t, serverCarrier, frameHeader{
		Type:     frameTypeAck,
		StreamID: openHeader.StreamID,
		Seq:      2,
	}, nil)

	for name, ch := range map[string]<-chan error{
		"first write":  firstDone,
		"second write": secondDone,
	} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s error = %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s did not return", name)
		}
	}
}

func TestMuxReplaysUnackedDataBeforeNewWritesAfterCarrierReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientMux := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Second})
	defer clientMux.Close()

	clientA, serverA := net.Pipe()
	defer serverA.Close()
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

	openHeader, _, err := readFrame(serverA)
	if err != nil {
		t.Fatalf("read open frame error = %v", err)
	}
	writeTestFrame(t, serverA, frameHeader{
		Type:     frameTypeAck,
		StreamID: openHeader.StreamID,
		Seq:      0,
	}, nil)

	var clientConn net.Conn
	select {
	case result := <-openCh:
		if result.err != nil {
			t.Fatalf("OpenStream() error = %v", result.err)
		}
		clientConn = result.conn
	case <-ctx.Done():
		t.Fatal("OpenStream() did not return")
	}
	defer clientConn.Close()

	firstDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("a"))
		firstDone <- err
	}()

	firstHeader, firstPayload, err := readFrame(serverA)
	if err != nil {
		t.Fatalf("read first data frame error = %v", err)
	}
	if firstHeader.Type != frameTypeData || string(firstPayload) != "a" {
		t.Fatalf("first frame = (%#v, %q), want data a", firstHeader, firstPayload)
	}
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first Write() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first Write() did not return")
	}

	clientB, serverB := net.Pipe()
	defer serverB.Close()
	clientMux.ReplaceCarrier(clientB)

	secondDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("b"))
		secondDone <- err
	}()

	replayHeader, replayPayload, err := readFrame(serverB)
	if err != nil {
		t.Fatalf("read replay frame error = %v", err)
	}
	if replayHeader.Type != frameTypeData || string(replayPayload) != "a" {
		t.Fatalf("replay frame = (%#v, %q), want data a", replayHeader, replayPayload)
	}

	secondHeader, secondPayload, err := readFrame(serverB)
	if err != nil {
		t.Fatalf("read second data frame error = %v", err)
	}
	if secondHeader.Type != frameTypeData || string(secondPayload) != "b" {
		t.Fatalf("second frame = (%#v, %q), want data b", secondHeader, secondPayload)
	}

	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("second Write() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("second Write() did not return")
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

func TestMuxDeliversPendingDataBeforeCloseFrame(t *testing.T) {
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
	defer clientConn.Close()
	serverConn := <-serverConnCh

	if _, err := clientConn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	got := make([]byte, len("hello\n"))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}
	if _, err := serverConn.Write([]byte("echo: hello\n")); err != nil {
		t.Fatalf("server Write() error = %v", err)
	}
	if err := serverConn.Close(); err != nil {
		t.Fatalf("server Close() error = %v", err)
	}

	reply := make([]byte, len("echo: hello\n"))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}
	if string(reply) != "echo: hello\n" {
		t.Fatalf("client reply = %q, want echo: hello", reply)
	}
}

func TestMuxCloseFrameWaitsForQueuedInboundData(t *testing.T) {
	serverMux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: 10 * time.Millisecond})
	defer serverMux.Close()

	_, appConn := serverMux.getOrCreateRemoteStream(2)
	defer appConn.Close()

	payload := []byte("reply before close")
	if err := serverMux.handleFrame(frameHeader{Type: frameTypeData, StreamID: 2, Seq: 0}, payload); err != nil {
		t.Fatalf("handleFrame(data) error = %v", err)
	}
	if err := serverMux.handleFrame(frameHeader{Type: frameTypeClose, StreamID: 2}, nil); err != nil {
		t.Fatalf("handleFrame(close) error = %v", err)
	}

	if err := appConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(appConn, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}

	if err := appConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, err := appConn.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("Read() after close = (%d, %v), want EOF/closed error", n, err)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("Read() timed out waiting for close frame")
	}
}

func TestMuxPingPongReportsAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientMux, serverMux := newMuxPair(t, time.Second)
	defer clientMux.Close()
	defer serverMux.Close()

	if err := serverMux.Ping(ctx, 200*time.Millisecond); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if err := clientMux.Ping(ctx, 200*time.Millisecond); err != nil {
		t.Fatalf("client Ping() error = %v", err)
	}
}

func TestMuxPingPongWhileStreamIsActive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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
	defer clientConn.Close()
	serverConn := <-serverConnCh
	defer serverConn.Close()

	if _, err := clientConn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	got := make([]byte, len("ping\n"))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}
	if _, err := serverConn.Write([]byte("pong\n")); err != nil {
		t.Fatalf("server Write() error = %v", err)
	}
	reply := make([]byte, len("pong\n"))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}

	if err := serverMux.Ping(ctx, 200*time.Millisecond); err != nil {
		t.Fatalf("server Ping() error = %v", err)
	}
}

func TestMuxPingTimesOutWhenPeerDoesNotReply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	mux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer mux.Close()
	mux.ReplaceCarrier(newNoReplyCarrier())

	start := time.Now()
	err := mux.Ping(ctx, 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Ping() took %v, want prompt timeout", elapsed)
	}
}

func TestMuxPingTimesOutWhenPeerStopsReading(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientCarrier, serverCarrier := net.Pipe()
	defer clientCarrier.Close()

	mux := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer mux.Close()
	mux.ReplaceCarrier(serverCarrier)

	start := time.Now()
	if err := mux.Ping(ctx, 50*time.Millisecond); err == nil {
		t.Fatal("Ping() error = nil, want write timeout")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Ping() took %v, want prompt write timeout", elapsed)
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
	deadline := time.Now().Add(time.Second)
	for {
		if stream := serverMux.getStream(2); stream == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("stream still present after close frame")
		}
		time.Sleep(10 * time.Millisecond)
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

func TestMuxActivityAndStreamCounters(t *testing.T) {
	mux := NewMux(MuxConfig{Role: MuxRoleClient})
	if got := mux.LastPeerActivity(); !got.IsZero() {
		t.Fatalf("LastPeerActivity() = %v, want zero", got)
	}
	if got := mux.ActiveStreamCount(); got != 0 {
		t.Fatalf("ActiveStreamCount() = %d, want 0", got)
	}

	want := time.Unix(0, 1234)
	mux.lastPeerActivityUnixNano.Store(want.UnixNano())
	if got := mux.LastPeerActivity(); !got.Equal(want) {
		t.Fatalf("LastPeerActivity() = %v, want %v", got, want)
	}

	mux.mu.Lock()
	mux.streams[1] = &muxStream{}
	mux.streams[3] = &muxStream{}
	mux.mu.Unlock()
	if got := mux.ActiveStreamCount(); got != 2 {
		t.Fatalf("ActiveStreamCount() = %d, want 2", got)
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

func writeTestFrame(t *testing.T, w io.Writer, header frameHeader, payload []byte) {
	t.Helper()

	header.Length = len(payload)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal test frame header: %v", err)
	}

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(headerBytes)))
	if _, err := w.Write(prefix[:]); err != nil {
		t.Fatalf("write test frame prefix: %v", err)
	}
	if _, err := w.Write(headerBytes); err != nil {
		t.Fatalf("write test frame header: %v", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write test frame payload: %v", err)
		}
	}
}

type noReplyCarrier struct {
	closed chan struct{}
	once   sync.Once
}

func newNoReplyCarrier() *noReplyCarrier {
	return &noReplyCarrier{closed: make(chan struct{})}
}

func (c *noReplyCarrier) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *noReplyCarrier) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *noReplyCarrier) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}
