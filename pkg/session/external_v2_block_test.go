// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
)

func TestExternalV2BlockChunkSizeDefaultsToLargeBlocks(t *testing.T) {
	if got := externalV2BlockChunkSize(0); got != 256<<10 {
		t.Fatalf("externalV2BlockChunkSize(0) = %d, want 256 KiB", got)
	}
	if got := externalV2BlockChunkSize(4); got != 4 {
		t.Fatalf("externalV2BlockChunkSize(4) = %d, want 4", got)
	}
}

func TestWriteExternalV2BlockFrameUsesSingleWrite(t *testing.T) {
	var dst writeCountingBuffer
	if err := writeExternalV2BlockFrame(&dst, 7, []byte("payload")); err != nil {
		t.Fatalf("writeExternalV2BlockFrame() error = %v", err)
	}
	if dst.writes != 1 {
		t.Fatalf("write calls = %d, want 1", dst.writes)
	}
	chunk, err := readExternalV2BlockFrame(bytes.NewReader(dst.Bytes()), 16)
	if err != nil {
		t.Fatalf("readExternalV2BlockFrame() error = %v", err)
	}
	if chunk.offset != 7 || string(chunk.data) != "payload" {
		t.Fatalf("chunk = offset %d data %q, want offset 7 data payload", chunk.offset, string(chunk.data))
	}
}

func TestSendExternalV2BlockChunksBuildsFrameWithoutPayloadCopy(t *testing.T) {
	jobs := make(chan externalV2BlockChunk, 1)
	errCh := make(chan error, 1)
	err := sendExternalV2BlockChunks(context.Background(), &BlockSource{
		Payload:     bytes.NewReader([]byte("abcd")),
		PayloadSize: 4,
	}, 4, jobs, errCh)
	if err != nil {
		t.Fatalf("sendExternalV2BlockChunks() error = %v", err)
	}
	chunk := <-jobs
	if len(chunk.frame) != externalV2BlockFrameSize+len(chunk.data) {
		t.Fatalf("frame length = %d, want header plus data %d", len(chunk.frame), externalV2BlockFrameSize+len(chunk.data))
	}
	chunk.data[0] = 'z'
	if got := chunk.frame[externalV2BlockFrameSize]; got != 'z' {
		t.Fatalf("frame payload first byte = %q, want shared data byte z", got)
	}
	decoded, err := readExternalV2BlockFrame(bytes.NewReader(chunk.frame), 4)
	if err != nil {
		t.Fatalf("readExternalV2BlockFrame() error = %v", err)
	}
	if decoded.offset != 0 || string(decoded.data) != "zbcd" {
		t.Fatalf("decoded chunk = offset %d data %q, want offset 0 data zbcd", decoded.offset, string(decoded.data))
	}
}

func TestExternalV2BlockSourceAcceptSnapshotsHeaderFunc(t *testing.T) {
	header := []byte("initial")
	src := &BlockSource{
		HeaderFunc: func() []byte {
			return header
		},
		Payload:     bytes.NewReader([]byte("payload")),
		PayloadSize: 7,
	}
	var accept externalV2Accept
	externalV2BlockSourceAccept(src, &accept)
	header[0] = 'x'

	if string(accept.BlockHeader) != "initial" {
		t.Fatalf("accept block header = %q, want initial snapshot", string(accept.BlockHeader))
	}
	if accept.TransferMode != externalV2TransferModeBlocks {
		t.Fatalf("accept transfer mode = %q, want block mode", accept.TransferMode)
	}
}

func TestExternalV2BlockReceiveWritesOutOfOrderChunksByOffset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var later bytes.Buffer
	if err := writeExternalV2BlockFrame(&later, 4, []byte("bbbb")); err != nil {
		t.Fatalf("write later block frame: %v", err)
	}
	var earlier bytes.Buffer
	if err := writeExternalV2BlockFrame(&earlier, 0, []byte("aaaa")); err != nil {
		t.Fatalf("write earlier block frame: %v", err)
	}
	sink := newMemoryBlockSink(8)

	got, err := receiveExternalV2BlockStreams(ctx, sink, externalV2BlockReceiveConfig{
		PayloadSize: 8,
		ChunkSize:   4,
		HeaderBytes: 3,
	}, []io.ReadCloser{
		io.NopCloser(&later),
		io.NopCloser(&earlier),
	}, nil)
	if err != nil {
		t.Fatalf("receiveExternalV2BlockStreams() error = %v", err)
	}
	if got != 11 {
		t.Fatalf("bytes received = %d, want header plus payload bytes 11", got)
	}
	if string(sink.bytes()) != "aaaabbbb" {
		t.Fatalf("sink bytes = %q, want aaaabbbb", string(sink.bytes()))
	}
}

func TestExternalV2BlockReceiveRejectsInvalidInputs(t *testing.T) {
	ctx := context.Background()
	sink := newMemoryBlockSink(1)
	if _, err := receiveExternalV2BlockStreams(ctx, nil, externalV2BlockReceiveConfig{PayloadSize: 1, ChunkSize: 1}, []io.ReadCloser{io.NopCloser(bytes.NewReader(nil))}, nil); err == nil {
		t.Fatal("receiveExternalV2BlockStreams(nil sink) error = nil, want failure")
	}
	if _, err := receiveExternalV2BlockStreams(ctx, sink, externalV2BlockReceiveConfig{PayloadSize: 1, ChunkSize: 1}, nil, nil); err == nil {
		t.Fatal("receiveExternalV2BlockStreams(no streams) error = nil, want failure")
	}
	if _, err := receiveExternalV2BlockStreams(ctx, sink, externalV2BlockReceiveConfig{PayloadSize: -1, ChunkSize: 1}, []io.ReadCloser{io.NopCloser(bytes.NewReader(nil))}, nil); err == nil {
		t.Fatal("receiveExternalV2BlockStreams(negative payload) error = nil, want failure")
	}
}

func TestExternalV2BlockReceiveReturnsMalformedFrameError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var frame bytes.Buffer
	if err := writeExternalV2BlockFrame(&frame, 0, []byte("abcde")); err != nil {
		t.Fatalf("writeExternalV2BlockFrame() error = %v", err)
	}
	got, err := receiveExternalV2BlockStreams(ctx, newMemoryBlockSink(5), externalV2BlockReceiveConfig{
		PayloadSize: 5,
		ChunkSize:   4,
		HeaderBytes: 2,
	}, []io.ReadCloser{io.NopCloser(&frame)}, nil)
	if err == nil {
		t.Fatal("receiveExternalV2BlockStreams() error = nil, want malformed frame failure")
	}
	if got != 2 {
		t.Fatalf("bytes received = %d, want header bytes only 2", got)
	}
}

func TestExternalV2BlockReceiveReturnsSinkError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var frame bytes.Buffer
	if err := writeExternalV2BlockFrame(&frame, 0, []byte("aaaa")); err != nil {
		t.Fatalf("writeExternalV2BlockFrame() error = %v", err)
	}
	got, err := receiveExternalV2BlockStreams(ctx, errorBlockSink{}, externalV2BlockReceiveConfig{
		PayloadSize: 4,
		ChunkSize:   4,
		HeaderBytes: 3,
	}, []io.ReadCloser{io.NopCloser(&frame)}, nil)
	if err == nil {
		t.Fatal("receiveExternalV2BlockStreams() error = nil, want sink failure")
	}
	if got != 7 {
		t.Fatalf("bytes received = %d, want header plus marked payload bytes 7", got)
	}
}

func TestExternalV2BlockReceiveReportsIncompleteTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var frame bytes.Buffer
	if err := writeExternalV2BlockFrame(&frame, 0, []byte("aaaa")); err != nil {
		t.Fatalf("writeExternalV2BlockFrame() error = %v", err)
	}
	got, err := receiveExternalV2BlockStreams(ctx, newMemoryBlockSink(8), externalV2BlockReceiveConfig{
		PayloadSize: 8,
		ChunkSize:   4,
		HeaderBytes: 3,
	}, []io.ReadCloser{io.NopCloser(&frame)}, nil)
	if err == nil {
		t.Fatal("receiveExternalV2BlockStreams() error = nil, want incomplete transfer failure")
	}
	if got != 7 {
		t.Fatalf("bytes received = %d, want header plus one chunk bytes 7", got)
	}
}

func TestExternalV2BlockTransferRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	header := []byte("header")
	payload := []byte("0123456789abcdef")
	sink := newMemoryBlockSink(int64(len(payload)))
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			UsePublicDERP: true,
			ForceRelay:    true,
			BlockReceiver: func(_ context.Context, req BlockReceiveRequest) (BlockReceiveSink, error) {
				if !bytes.Equal(req.Header, header) {
					t.Errorf("block header = %q, want %q", string(req.Header), string(header))
				}
				if req.PayloadSize != int64(len(payload)) {
					t.Errorf("payload size = %d, want %d", req.PayloadSize, len(payload))
				}
				return sink, nil
			},
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

	if err := sendExternal(ctx, SendConfig{
		Token:         raw,
		UsePublicDERP: true,
		ForceRelay:    true,
		BlockSource: &BlockSource{
			Header:      header,
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
			ChunkSize:   4,
		},
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
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatalf("received payload = %q, want %q", string(sink.bytes()), string(payload))
	}
}

func TestExternalV2BlockTransferUsesBulkPacketsOnRawDirect(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{
				IP:   net.IPv4(127, 0, 0, 1),
				Mask: net.CIDRMask(8, 32),
			},
		}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	header := []byte("bulk-header")
	payload := bytes.Repeat([]byte("bulk-packets:"), 64<<10)
	sink := newMemoryBlockSink(int64(len(payload)))
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			UsePublicDERP: true,
			BlockReceiver: func(_ context.Context, req BlockReceiveRequest) (BlockReceiveSink, error) {
				if !bytes.Equal(req.Header, header) {
					t.Errorf("block header = %q, want %q", string(req.Header), string(header))
				}
				if req.PayloadSize != int64(len(payload)) {
					t.Errorf("payload size = %d, want %d", req.PayloadSize, len(payload))
				}
				return sink, nil
			},
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

	if err := sendExternal(ctx, SendConfig{
		Token:         raw,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		UsePublicDERP: true,
		BlockSource: &BlockSource{
			Header:      header,
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
	}); err != nil {
		t.Fatalf("sendExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	select {
	case err := <-listenErr:
		if err != nil {
			t.Fatalf("listenExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for listener: %v", ctx.Err())
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatalf("received payload length = %d, want %d", len(sink.bytes()), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "v2-block-transfer=bulk-packets") {
		t.Fatalf("sender status = %q, want bulk packet transfer marker", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "v2-block-transfer=bulk-packets") {
		t.Fatalf("listener status = %q, want bulk packet transfer marker", got)
	}
}

func TestExternalV2OfferBlockTransferRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	header := []byte("offer-header")
	payload := []byte("offer-block-payload")
	sink := newMemoryBlockSink(int64(len(payload)))
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink:     tokenSink,
			UsePublicDERP: true,
			ForceRelay:    true,
			BlockSource: &BlockSource{
				Header:      header,
				Payload:     bytes.NewReader(payload),
				PayloadSize: int64(len(payload)),
				ChunkSize:   4,
			},
		})
		offerErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-offerErr:
		t.Fatalf("Offer() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}

	if err := Receive(ctx, ReceiveConfig{
		Token:         raw,
		UsePublicDERP: true,
		ForceRelay:    true,
		BlockReceiver: func(_ context.Context, req BlockReceiveRequest) (BlockReceiveSink, error) {
			if !bytes.Equal(req.Header, header) {
				t.Errorf("block header = %q, want %q", string(req.Header), string(header))
			}
			if req.PayloadSize != int64(len(payload)) {
				t.Errorf("payload size = %d, want %d", req.PayloadSize, len(payload))
			}
			return sink, nil
		},
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	select {
	case err := <-offerErr:
		if err != nil {
			t.Fatalf("Offer() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offer: %v", ctx.Err())
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatalf("received payload = %q, want %q", string(sink.bytes()), string(payload))
	}
}

type memoryBlockSink struct {
	mu sync.Mutex
	b  []byte
}

type errorBlockSink struct{}

type writeCountingBuffer struct {
	bytes.Buffer
	writes int
}

func (b *writeCountingBuffer) Write(p []byte) (int, error) {
	b.writes++
	return b.Buffer.Write(p)
}

func newMemoryBlockSink(size int64) *memoryBlockSink {
	return &memoryBlockSink{b: make([]byte, size)}
}

func (s *memoryBlockSink) WriteAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copy(s.b[off:], p), nil
}

func (s *memoryBlockSink) Close() error {
	return nil
}

func (errorBlockSink) WriteAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

func (errorBlockSink) Close() error {
	return nil
}

func (s *memoryBlockSink) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b...)
}
