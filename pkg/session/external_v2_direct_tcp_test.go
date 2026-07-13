// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestExternalV2DirectTCPEightLaneBlockTransferPreservesPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("direct-tcp-files-v1:"), 1<<20)
	listener, err := openExternalV2DirectTCPListener("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := externalPeerControlAuth{EnvelopeKey: [32]byte{1, 2, 3}}
	acceptCh := make(chan struct {
		path *externalV2DirectTCPPath
		err  error
	}, 1)
	go func() {
		path, err := listener.accept(ctx, auth)
		acceptCh <- struct {
			path *externalV2DirectTCPPath
			err  error
		}{path: path, err: err}
	}()

	dialPath, err := dialExternalV2DirectTCP(ctx, listener.ad, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer dialPath.Close()
	accepted := <-acceptCh
	if accepted.err != nil {
		t.Fatal(accepted.err)
	}
	defer accepted.path.Close()

	sink := newMemoryBlockSink(int64(len(payload)))
	receiveCh := make(chan error, 1)
	go func() {
		_, err := receiveExternalV2BlockStreams(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)),
			ChunkSize:   externalV2DefaultBlockChunkSize,
		}, accepted.path.readers(), nil)
		receiveCh <- err
	}()
	err = copyExternalV2SendBlockStreams(ctx, &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
		ChunkSize:   externalV2DefaultBlockChunkSize,
	}, dialPath.writers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-receiveCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("direct TCP payload does not match")
	}
}

func TestExternalV2DirectTCPRejectsWrongFingerprint(t *testing.T) {
	listener, err := openExternalV2DirectTCPListener("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ad := listener.ad
	ad.FingerprintSHA256 = strings.Repeat("0", 64)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	auth := externalPeerControlAuth{EnvelopeKey: [32]byte{1, 2, 3}}
	go func() {
		_, _ = listener.accept(ctx, auth)
	}()
	if _, err := dialExternalV2DirectTCP(ctx, ad, auth); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("dial error = %v, want fingerprint failure", err)
	}
}

func TestExternalV2DirectTCPRejectsClientWithoutSessionAuthentication(t *testing.T) {
	listener, err := openExternalV2DirectTCPListener("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverAuth := externalPeerControlAuth{EnvelopeKey: [32]byte{1}}
	clientAuth := externalPeerControlAuth{EnvelopeKey: [32]byte{2}}
	acceptErr := make(chan error, 1)
	go func() {
		_, err := listener.accept(ctx, serverAuth)
		acceptErr <- err
	}()
	path, _ := dialExternalV2DirectTCP(ctx, listener.ad, clientAuth)
	if path != nil {
		path.Close()
	}
	serverErr := <-acceptErr
	if serverErr == nil || !strings.Contains(serverErr.Error(), "authentication") {
		t.Fatalf("server error = %v, want session authentication failure", serverErr)
	}
}

func TestExternalV2DirectTCPCandidatesReplacePortPreferPublicAndDeduplicate(t *testing.T) {
	got := externalV2DirectTCPCandidates([]string{
		"192.168.1.10:1000",
		"203.0.113.10:2000",
		"203.0.113.10:3000",
		"100.64.0.1:4000",
	}, 8123)
	want := []string{"203.0.113.10:8123", "192.168.1.10:8123", "100.64.0.1:8123"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

func TestReadExternalV2DirectTCPChunk(t *testing.T) {
	var frame bytes.Buffer
	var header [externalV2BlockFrameSize]byte
	binary.BigEndian.PutUint64(header[:8], 17)
	binary.BigEndian.PutUint32(header[8:], 4)
	frame.Write(header[:])
	frame.WriteString("data")

	chunk, done, err := readExternalV2DirectTCPChunk(&frame, make([]byte, 4))
	if err != nil || done || chunk.offset != 17 || !bytes.Equal(chunk.data, []byte("data")) {
		t.Fatalf("read chunk = (%+v, %t, %v)", chunk, done, err)
	}
	_, done, err = readExternalV2DirectTCPChunk(&frame, make([]byte, 4))
	if err != nil || !done {
		t.Fatalf("read EOF = (done %t, err %v)", done, err)
	}
}

func TestReadExternalV2DirectTCPChunkRejectsInvalidFrames(t *testing.T) {
	var oversized [externalV2BlockFrameSize]byte
	binary.BigEndian.PutUint32(oversized[8:], 5)
	if _, _, err := readExternalV2DirectTCPChunk(bytes.NewReader(oversized[:]), make([]byte, 4)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("oversized error = %v", err)
	}

	var truncated bytes.Buffer
	var header [externalV2BlockFrameSize]byte
	binary.BigEndian.PutUint32(header[8:], 4)
	truncated.Write(header[:])
	truncated.WriteString("no")
	if _, _, err := readExternalV2DirectTCPChunk(&truncated, make([]byte, 4)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated error = %v", err)
	}
}

func TestExternalV2DirectTCPSendCancellationUnblocksStalledLanes(t *testing.T) {
	path, writeStarted, cleanup := newStalledExternalV2DirectTCPPath(t, false)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2DirectTCPLaneCount*externalV2DirectTCPChunkSize)
	go func() {
		result <- sendExternalV2DirectTCPBlock(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
			ChunkSize:   externalV2DirectTCPChunkSize,
		}, path, nil)
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("direct TCP sender did not block on the stalled peer")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("send error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct TCP sender remained blocked after cancellation")
	}
}

func TestExternalV2DirectTCPReceiveCancellationUnblocksStalledLanes(t *testing.T) {
	path, readStarted, cleanup := newStalledExternalV2DirectTCPPath(t, true)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := receiveExternalV2DirectTCPBlock(ctx, newMemoryBlockSink(externalV2DirectTCPChunkSize), externalV2BlockReceiveConfig{
			PayloadSize: externalV2DirectTCPChunkSize,
			ChunkSize:   externalV2DirectTCPChunkSize,
		}, path, nil)
		result <- err
	}()
	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("direct TCP receiver did not block on the stalled peer")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("receive error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct TCP receiver remained blocked after cancellation")
	}
}

type stalledExternalV2DirectTCPConn struct {
	net.Conn
	armed      bool
	signalRead bool
	started    chan<- struct{}
}

func (c *stalledExternalV2DirectTCPConn) Read(p []byte) (int, error) {
	if c.armed && c.signalRead {
		select {
		case c.started <- struct{}{}:
		default:
		}
	}
	return c.Conn.Read(p)
}

func (c *stalledExternalV2DirectTCPConn) Write(p []byte) (int, error) {
	if c.armed && !c.signalRead {
		select {
		case c.started <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(p)
}

func newStalledExternalV2DirectTCPPath(t *testing.T, signalRead bool) (*externalV2DirectTCPPath, <-chan struct{}, func()) {
	t.Helper()
	certificate, fingerprint, err := newExternalV2DirectTCPCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := newExternalV2DirectTCPClientConfig(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		Certificates:                []tls.Certificate{certificate},
		MinVersion:                  tls.VersionTLS13,
		MaxVersion:                  tls.VersionTLS13,
		NextProtos:                  []string{externalV2DirectTCPProtocol},
		DynamicRecordSizingDisabled: true,
	}
	started := make(chan struct{}, 1)
	path := &externalV2DirectTCPPath{conns: make([]*tls.Conn, externalV2DirectTCPLaneCount)}
	peers := make([]*tls.Conn, externalV2DirectTCPLaneCount)
	for lane := range path.conns {
		clientRaw, serverRaw := net.Pipe()
		wrapped := &stalledExternalV2DirectTCPConn{Conn: clientRaw, signalRead: signalRead, started: started}
		client := tls.Client(wrapped, clientConfig)
		server := tls.Server(serverRaw, serverConfig)
		handshakes := make(chan error, 2)
		go func() { handshakes <- client.Handshake() }()
		go func() { handshakes <- server.Handshake() }()
		for range 2 {
			if err := <-handshakes; err != nil {
				_ = client.Close()
				_ = server.Close()
				t.Fatal(err)
			}
		}
		wrapped.armed = true
		path.conns[lane] = client
		peers[lane] = server
	}
	cleanup := func() {
		path.Close()
		closeExternalV2DirectTCPConns(peers)
	}
	return path, started, cleanup
}
