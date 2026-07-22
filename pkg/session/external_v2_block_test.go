// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
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

func TestExternalV2GroupedBulkRequiresBothPeerCapabilities(t *testing.T) {
	for _, tt := range []struct {
		name          string
		claim, accept bool
		want          bool
	}{
		{name: "both", claim: true, accept: true, want: true},
		{name: "old claimant", claim: false, accept: true},
		{name: "old acceptor", claim: true, accept: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalV2GroupedBulk(tt.claim, tt.accept); got != tt.want {
				t.Fatalf("externalV2GroupedBulk(%t, %t) = %t, want %t", tt.claim, tt.accept, got, tt.want)
			}
		})
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

func TestExternalV2BlockReceiveCountsOnlyCommittedQUICPayload(t *testing.T) {
	for _, tt := range []struct {
		name string
		sink BlockReceiveSink
		want int64
	}{
		{name: "exact write", sink: newMemoryBlockSink(4), want: 4},
		{name: "failed write", sink: errorBlockSink{}, want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var frame bytes.Buffer
			if err := writeExternalV2BlockFrame(&frame, 0, []byte("data")); err != nil {
				t.Fatal(err)
			}
			metrics := newExternalTransferMetricsWithTrace(time.Unix(190, 0), nil, transfertrace.RoleReceive)
			_, _ = receiveExternalV2BlockStreams(context.Background(), tt.sink, externalV2BlockReceiveConfig{
				PayloadSize: 4, ChunkSize: 4,
			}, []io.ReadCloser{io.NopCloser(&frame)}, metrics)
			metrics.mu.Lock()
			got := metrics.filePayloadBytesCommitted
			engine := metrics.filePayloadEngine
			bulk := metrics.filePayloadBytesBulk
			quic := metrics.filePayloadBytesQUIC
			metrics.mu.Unlock()
			if got != tt.want || engine != transfertrace.FilePayloadEngineQUIC || bulk != 0 || quic != tt.want {
				t.Fatalf("engine=%q committed=%d bulk=%d quic=%d, want committed/quic=%d", engine, got, bulk, quic, tt.want)
			}
		})
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

func TestExternalV2ListenSendDirectTCPFileRoundTripReceiverListens(t *testing.T) {
	testExternalV2ListenSendDirectTCPFileRoundTrip(t, false)
}

func TestExternalV2ListenSendDirectTCPFileRoundTripSenderListens(t *testing.T) {
	testExternalV2ListenSendDirectTCPFileRoundTrip(t, true)
}

func testExternalV2ListenSendDirectTCPFileRoundTrip(t *testing.T, senderListens bool) {
	disableExternalV2BulkPacketBatchCapability(t)
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		result := make([]net.Addr, 0, 5)
		for last := 1; last <= 5; last++ {
			result = append(result, &net.IPNet{IP: net.IPv4(127, 0, 0, byte(last)), Mask: net.CIDRMask(8, 32)})
		}
		return result, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(reserved.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	_ = reserved.Close()
	senderPort, receiverPort := 0, port
	if senderListens {
		senderPort, receiverPort = port, 0
	}

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte{0x6b}, externalV2DirectTCPMinFileSize)
	sink := newMemoryBlockSink(int64(len(payload)))
	var listenerStatus, senderStatus syncBuffer
	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := listenExternal(ctx, ListenConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			UsePublicDERP: true,
			DirectTCPPort: receiverPort,
			BlockReceiver: func(context.Context, BlockReceiveRequest) (BlockReceiveSink, error) {
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
		t.Fatal(ctx.Err())
	}
	err = sendExternal(ctx, SendConfig{
		Token:         raw,
		Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
		UsePublicDERP: true,
		DirectTCPPort: senderPort,
		BlockSource: &BlockSource{
			Header:      []byte("direct-tcp"),
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
			ChunkSize:   1 << 20,
		},
	})
	if err != nil {
		t.Fatalf("sendExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("listenExternal() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("direct TCP file payload mismatch")
	}
	for role, status := range map[string]string{"listener": listenerStatus.String(), "sender": senderStatus.String()} {
		if !strings.Contains(status, "v2-block-transfer=direct-tcp-files") || !strings.Contains(status, "v2-data-plane=direct-tcp-files") {
			t.Fatalf("%s status missing direct TCP markers: %q", role, status)
		}
	}
}

func TestExternalV2OfferReceiveRawDirectBulk(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	header := []byte("offer-header")
	payload := bytes.Repeat([]byte("offer-block-payload"), 256)
	sink := newGatedMemoryBlockSink(int64(len(payload)))
	t.Cleanup(sink.releaseWrites)
	var offerStatus syncBuffer
	var receiveStatus syncBuffer
	type progressSample struct {
		bytesReceived     int64
		transferElapsedMS int64
	}
	var progressMu sync.Mutex
	var progressSamples []progressSample
	progressCh := make(chan progressSample, 16)
	receiverComplete := make(chan struct{})
	releaseReceiver := make(chan struct{})
	var releaseReceiverOnce sync.Once
	releaseReceiverFn := func() { releaseReceiverOnce.Do(func() { close(releaseReceiver) }) }
	t.Cleanup(releaseReceiverFn)
	receiveEmitter := telemetry.WithStatusHook(
		telemetry.New(&receiveStatus, telemetry.LevelVerbose),
		func(status string) {
			if status != string(StateComplete) {
				return
			}
			close(receiverComplete)
			<-releaseReceiver
		},
	)
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&offerStatus, telemetry.LevelVerbose),
			UsePublicDERP: true,
			Progress: func(bytesReceived int64, transferElapsedMS int64) {
				sample := progressSample{bytesReceived: bytesReceived, transferElapsedMS: transferElapsedMS}
				progressMu.Lock()
				progressSamples = append(progressSamples, sample)
				progressMu.Unlock()
				progressCh <- sample
			},
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

	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(ctx, ReceiveConfig{
			Token:         raw,
			Emitter:       receiveEmitter,
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
	}()

	select {
	case <-sink.firstWrite:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for first receive write: %v", ctx.Err())
	}
	totalBytes := int64(len(header) + len(payload))
	var partial progressSample
	for partial.bytesReceived == 0 {
		select {
		case sample := <-progressCh:
			if sample.bytesReceived > int64(len(header)) && sample.bytesReceived < totalBytes && sample.transferElapsedMS > 0 {
				partial = sample
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for partial receiver-clock progress: %v", ctx.Err())
		}
	}
	sink.releaseWrites()

	select {
	case <-receiverComplete:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver completion status: %v", ctx.Err())
	}
	select {
	case err := <-offerErr:
		if err != nil {
			t.Fatalf("Offer() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for offer: %v", ctx.Err())
	}
	progressMu.Lock()
	progressAtOfferReturn := append([]progressSample(nil), progressSamples...)
	progressMu.Unlock()
	releaseReceiverFn()
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("Receive() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
	progressMu.Lock()
	progressAfterReceiverShutdown := append([]progressSample(nil), progressSamples...)
	progressMu.Unlock()
	if len(progressAtOfferReturn) == 0 {
		t.Fatal("Offer() returned without progress callbacks")
	}
	final := progressAtOfferReturn[len(progressAtOfferReturn)-1]
	if final.bytesReceived != totalBytes || final.transferElapsedMS <= 0 {
		t.Fatalf("final progress before Offer returned = (%d, %d), want (%d, >0); all progress = %#v",
			final.bytesReceived, final.transferElapsedMS, totalBytes, progressAtOfferReturn)
	}
	if len(progressAfterReceiverShutdown) != len(progressAtOfferReturn) {
		t.Fatalf("progress changed after Offer returned and receiver shut down: before=%#v after=%#v",
			progressAtOfferReturn, progressAfterReceiverShutdown)
	}
	for i := range progressAtOfferReturn {
		if progressAfterReceiverShutdown[i] != progressAtOfferReturn[i] {
			t.Fatalf("progress changed after Offer returned and receiver shut down: before=%#v after=%#v",
				progressAtOfferReturn, progressAfterReceiverShutdown)
		}
	}
	for i, sample := range progressAfterReceiverShutdown {
		if sample.transferElapsedMS <= 0 {
			t.Fatalf("non-positive elapsed progress at index %d: %#v", i, progressAfterReceiverShutdown)
		}
		if sample.bytesReceived > totalBytes || (i > 0 && sample.bytesReceived < progressAfterReceiverShutdown[i-1].bytesReceived) {
			t.Fatalf("out-of-order progress at index %d: %#v", i, progressAfterReceiverShutdown)
		}
		if sample.bytesReceived == totalBytes && i != len(progressAfterReceiverShutdown)-1 {
			t.Fatalf("completion progress was not terminal: %#v", progressAfterReceiverShutdown)
		}
	}
	if !strings.Contains(offerStatus.String(), "v2-block-policy=mode:bulk-packets-v1 receiver:claimant") {
		t.Fatalf("offer status = %q, want claimant receiver bulk policy", offerStatus.String())
	}
	if !strings.Contains(offerStatus.String(), "v2-block-transfer=bulk-packets") ||
		!strings.Contains(receiveStatus.String(), "v2-block-transfer=bulk-packets") {
		t.Fatalf("missing bulk packet marker: offer=%q receive=%q", offerStatus.String(), receiveStatus.String())
	}
	gotPayload := sink.bytes()
	if !bytes.Equal(gotPayload, payload) {
		t.Fatal("offer/receive block payload mismatch")
	}
}

func TestExternalV2ProbeFallbackCompletesThroughQUICBeforePayload(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	t.Setenv("DERPHOLE_TEST_BULK_PROBE_OUTCOME", "sender-reject")
	previousBarrierWait := externalV2BulkDecisionBarrierWait
	externalV2BulkDecisionBarrierWait = 2 * time.Second
	t.Cleanup(func() { externalV2BulkDecisionBarrierWait = previousBarrierWait })
	var offerStatus, receiveStatus syncBuffer

	previousInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = previousInterfaceAddrs })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	header := []byte("probe-fallback")
	payload := bytes.Repeat([]byte("quic-after-rejected-udp-probe"), 16<<10)
	sink := newGatedMemoryBlockSink(int64(len(payload)))
	t.Cleanup(sink.releaseWrites)
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink: tokenSink, Emitter: telemetry.New(&offerStatus, telemetry.LevelVerbose), UsePublicDERP: true,
			BlockSource: &BlockSource{Header: header, Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload))},
		})
		offerErr <- err
	}()

	var raw string
	select {
	case raw = <-tokenSink:
	case err := <-offerErr:
		t.Fatalf("Offer() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(ctx, ReceiveConfig{
			Token: raw, Emitter: telemetry.New(&receiveStatus, telemetry.LevelVerbose), UsePublicDERP: true,
			BlockReceiver: func(context.Context, BlockReceiveRequest) (BlockReceiveSink, error) { return sink, nil },
		})
	}()
	select {
	case <-sink.firstWrite:
	case err := <-receiveErr:
		t.Fatalf("Receive() returned before first payload write: %v offer=%q receive=%q", err, offerStatus.String(), receiveStatus.String())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	time.Sleep(externalV2BulkDecisionBarrierWait + 100*time.Millisecond)
	sink.releaseWrites()
	if err := <-receiveErr; err != nil {
		t.Fatalf("Receive() error after payload outlived decision barrier = %v offer=%q receive=%q", err, offerStatus.String(), receiveStatus.String())
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v offer=%q receive=%q", err, offerStatus.String(), receiveStatus.String())
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("QUIC fallback payload mismatch")
	}
	offerLog := offerStatus.String()
	receiveLog := receiveStatus.String()
	if readiness := strings.Index(offerLog, "v2-bulk-ready=mode:"); readiness >= 0 {
		decision := strings.Index(offerLog, "v2-bulk-decision=mode:quic")
		ack := strings.Index(offerLog, "v2-bulk-decision-ack=mode:quic")
		if !(decision < readiness && readiness < ack) {
			t.Fatalf("offer readiness ordering decision=%d readiness=%d ack=%d status=%q", decision, readiness, ack, offerLog)
		}
	}
	if readiness := strings.Index(receiveLog, "v2-bulk-ready=mode:"); readiness >= 0 {
		decision := strings.Index(receiveLog, "v2-bulk-decision=mode:quic")
		if readiness >= decision {
			t.Fatalf("receiver readiness ordering readiness=%d decision=%d status=%q", readiness, decision, receiveLog)
		}
	}
	for role, status := range map[string]string{"offer": offerLog, "receive": receiveLog} {
		markers := []string{
			"v2-bulk-decision=mode:quic",
			"v2-bulk-decision-ack=mode:quic",
			"v2-bulk-probe=fallback-before-payload",
		}
		previous := -1
		for _, marker := range markers {
			if !strings.Contains(status, marker) {
				t.Fatalf("%s status missing %q: %q", role, marker, status)
			}
			index := strings.Index(status, marker)
			if index <= previous {
				t.Fatalf("%s status marker %q out of order: %q", role, marker, status)
			}
			previous = index
		}
	}
	const forcedMarker = "v2-bulk-probe-test-outcome=sender-reject"
	if count := strings.Count(offerLog, forcedMarker); count != 1 {
		t.Fatalf("offer status marker count = %d, want 1 for %q: %q", count, forcedMarker, offerLog)
	}
	ack := strings.Index(offerLog, "v2-bulk-decision-ack=mode:quic")
	forced := strings.Index(offerLog, forcedMarker)
	fallback := strings.Index(offerLog, "v2-bulk-probe=fallback-before-payload")
	if !(ack < forced && forced < fallback) {
		t.Fatalf("offer controlled marker ordering ack=%d forced=%d fallback=%d: %q", ack, forced, fallback, offerLog)
	}
	if strings.Contains(receiveLog, forcedMarker) {
		t.Fatalf("receiver status unexpectedly contains %q: %q", forcedMarker, receiveLog)
	}
	offerStatusBefore := offerStatus.String()
	receiveStatusBefore := receiveStatus.String()
	time.Sleep(250 * time.Millisecond)
	if got := offerStatus.String(); got != offerStatusBefore {
		t.Fatalf("offer status grew after return: before=%q after=%q", offerStatusBefore, got)
	}
	if got := receiveStatus.String(); got != receiveStatusBefore {
		t.Fatalf("receive status grew after return: before=%q after=%q", receiveStatusBefore, got)
	}
}

func TestExternalV2NegotiatedBulkPacketFallbackAcceptsControlledSenderRejectionOnly(t *testing.T) {
	controlled := errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject)
	if !externalV2NegotiatedBulkPacketFallback(controlled) {
		t.Fatal("controlled sender rejection was not classified as negotiated fallback")
	}
	if externalV2NegotiatedBulkPacketFallback(errors.Join(controlled, errors.New("cleanup failed"))) {
		t.Fatal("controlled sender rejection with cleanup failure was classified as negotiated fallback")
	}
}

func TestExternalV2InvalidBulkPacketProbeTestOutcomeFailsSenderBeforeQUIC(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name: "explicit empty",
			want: `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "")`,
		},
		{
			name:  "unsupported",
			value: "receiver-reject",
			want:  `DERPHOLE_TEST_BULK_PROBE_OUTCOME must be unset or "sender-reject" (got "receiver-reject")`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testExternalV2InvalidBulkPacketProbeTestOutcomeFailsSenderBeforeQUIC(t, tt.value, tt.want)
		})
	}
}

func testExternalV2InvalidBulkPacketProbeTestOutcomeFailsSenderBeforeQUIC(t *testing.T, value, want string) {
	t.Helper()
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	t.Setenv(externalV2BulkPacketProbeTestOutcomeEnv, value)

	previousInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = previousInterfaceAddrs })

	var quicReceiveOpens atomic.Int32
	previousQUICOpenObserver := externalV2ObserveQUICBlockReceiveOpen
	externalV2ObserveQUICBlockReceiveOpen = func() { quicReceiveOpens.Add(1) }
	t.Cleanup(func() { externalV2ObserveQUICBlockReceiveOpen = previousQUICOpenObserver })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("invalid-probe-test-outcome"), 16<<10)
	sink := newMemoryBlockSink(int64(len(payload)))
	var offerStatus, receiveStatus syncBuffer
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink: tokenSink, Emitter: telemetry.New(&offerStatus, telemetry.LevelVerbose), UsePublicDERP: true,
			BlockSource: &BlockSource{Header: []byte("invalid-outcome"), Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload))},
		})
		offerErr <- err
	}()
	raw := waitExternalV2BlockTestToken(t, ctx, tokenSink, offerErr)
	receiveErr := make(chan error, 1)
	go func() {
		receiveErr <- Receive(ctx, ReceiveConfig{
			Token: raw, Emitter: telemetry.New(&receiveStatus, telemetry.LevelVerbose), UsePublicDERP: true,
			BlockReceiver: func(context.Context, BlockReceiveRequest) (BlockReceiveSink, error) { return sink, nil },
		})
	}()

	var senderErr error
	select {
	case senderErr = <-offerErr:
	case <-ctx.Done():
		t.Fatalf("sender did not return: %v offer=%q receive=%q", ctx.Err(), offerStatus.String(), receiveStatus.String())
	}
	if senderErr == nil || senderErr.Error() != want {
		t.Fatalf("sender error = %v, want %q; offer=%q receive=%q", senderErr, want, offerStatus.String(), receiveStatus.String())
	}
	for role, status := range map[string]string{"offer": offerStatus.String(), "receive": receiveStatus.String()} {
		for _, marker := range []string{"v2-bulk-decision=", "v2-bulk-decision-ack=", "v2-bulk-probe=fallback-before-payload"} {
			if strings.Contains(status, marker) {
				t.Fatalf("%s status unexpectedly contains %q: %q", role, marker, status)
			}
		}
	}
	if got := quicReceiveOpens.Load(); got != 0 {
		t.Fatalf("QUIC block receive open count = %d, want 0; offer=%q receive=%q", got, offerStatus.String(), receiveStatus.String())
	}
	if got := sink.bytes(); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("receiver committed payload bytes after invalid probe test outcome")
	}

	cancel()
	select {
	case <-receiveErr:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not stop after invalid probe test outcome")
	}
}

func TestExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC(t *testing.T) {
	for _, topology := range []string{"claimant-receiver", "offerer-receiver"} {
		for _, cleanup := range []string{"interrupt", "drain"} {
			t.Run(topology+"/"+cleanup, func(t *testing.T) {
				testExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC(t, topology, cleanup)
			})
		}
	}
}

func testExternalV2ReceiverProbeCleanupFailureDoesNotOpenQUIC(t *testing.T, topology, cleanup string) {
	t.Helper()
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	previousInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = previousInterfaceAddrs })

	fault := errors.New("injected receiver probe " + cleanup + " failure")
	previousInterrupt := externalV2BulkPacketProbeInterruptReads
	previousDrain := externalV2BulkPacketDrainForHandoff
	switch cleanup {
	case "interrupt":
		externalV2BulkPacketProbeInterruptReads = func(path externalV2BulkPacketPath, deadline time.Time) error {
			return errors.Join(interruptExternalV2BulkPacketReads(path, deadline), fault)
		}
	case "drain":
		externalV2BulkPacketDrainForHandoff = func(ctx context.Context, path externalV2BulkPacketPath) (externalV2BulkPacketHandoffDrainResult, error) {
			result, err := previousDrain(ctx, path)
			return result, errors.Join(err, fault)
		}
	default:
		t.Fatalf("unknown cleanup fault %q", cleanup)
	}
	t.Cleanup(func() {
		externalV2BulkPacketProbeInterruptReads = previousInterrupt
		externalV2BulkPacketDrainForHandoff = previousDrain
	})

	var quicReceiveOpens atomic.Int32
	previousQUICOpenObserver := externalV2ObserveQUICBlockReceiveOpen
	externalV2ObserveQUICBlockReceiveOpen = func() { quicReceiveOpens.Add(1) }
	t.Cleanup(func() { externalV2ObserveQUICBlockReceiveOpen = previousQUICOpenObserver })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("receiver-probe-cleanup"), 32<<10)
	sink := newMemoryBlockSink(int64(len(payload)))
	var receiverStatus syncBuffer
	var senderStatus syncBuffer
	receiverConfig := func() BlockReceiver {
		return func(context.Context, BlockReceiveRequest) (BlockReceiveSink, error) { return sink, nil }
	}

	var receiverErr error
	var senderErrCh <-chan error
	switch topology {
	case "claimant-receiver":
		tokenSink := make(chan string, 1)
		offerErr := make(chan error, 1)
		go func() {
			_, err := Offer(ctx, OfferConfig{
				TokenSink: tokenSink, Emitter: telemetry.New(&senderStatus, telemetry.LevelVerbose), UsePublicDERP: true,
				BlockSource: &BlockSource{Header: []byte("cleanup"), Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload))},
			})
			offerErr <- err
		}()
		raw := waitExternalV2BlockTestToken(t, ctx, tokenSink, offerErr)
		receiverErr = Receive(ctx, ReceiveConfig{
			Token: raw, Emitter: telemetry.New(&receiverStatus, telemetry.LevelVerbose), UsePublicDERP: true,
			BlockReceiver: receiverConfig(),
		})
		senderErrCh = offerErr
	case "offerer-receiver":
		tokenSink := make(chan string, 1)
		listenErr := make(chan error, 1)
		go func() {
			_, err := listenExternal(ctx, ListenConfig{
				TokenSink: tokenSink, Emitter: telemetry.New(&receiverStatus, telemetry.LevelVerbose), UsePublicDERP: true,
				BlockReceiver: receiverConfig(),
			})
			listenErr <- err
		}()
		raw := waitExternalV2BlockTestToken(t, ctx, tokenSink, listenErr)
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- sendExternal(ctx, SendConfig{
				Token: raw, Emitter: telemetry.New(&senderStatus, telemetry.LevelVerbose), UsePublicDERP: true,
				BlockSource: &BlockSource{Header: []byte("cleanup"), Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload))},
			})
		}()
		select {
		case receiverErr = <-listenErr:
		case <-ctx.Done():
			t.Fatalf("receiver did not return: %v", ctx.Err())
		}
		senderErrCh = sendErr
	default:
		t.Fatalf("unknown receiver topology %q", topology)
	}

	if !errors.Is(receiverErr, fault) {
		t.Fatalf("receiver error = %v, want cleanup fault %v; status=%q", receiverErr, fault, receiverStatus.String())
	}
	if got := quicReceiveOpens.Load(); got != 0 {
		t.Fatalf("QUIC block receive open count = %d, want 0; status=%q", got, receiverStatus.String())
	}
	if got := sink.bytes(); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("receiver committed payload bytes after probe cleanup failure")
	}
	for role, status := range map[string]string{"receiver": receiverStatus.String(), "sender": senderStatus.String()} {
		if strings.Contains(status, "v2-bulk-probe=fallback-before-payload") {
			t.Fatalf("%s emitted negotiated fallback after cleanup failure: %q", role, status)
		}
	}

	cancel()
	select {
	case <-senderErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not stop after receiver cleanup failure")
	}
}

func waitExternalV2BlockTestToken(t *testing.T, ctx context.Context, tokenSink <-chan string, earlyErr <-chan error) string {
	t.Helper()
	select {
	case raw := <-tokenSink:
		return raw
	case err := <-earlyErr:
		t.Fatalf("runtime returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}
	return ""
}

func TestExternalV2OfferReceiveDirectTCPFileRoundTripReceiverListens(t *testing.T) {
	testExternalV2OfferReceiveDirectTCPFileRoundTrip(t, false)
}

func TestExternalV2OfferReceiveDirectTCPFileRoundTripSenderListens(t *testing.T) {
	testExternalV2OfferReceiveDirectTCPFileRoundTrip(t, true)
}

func testExternalV2OfferReceiveDirectTCPFileRoundTrip(t *testing.T, senderListens bool) {
	disableExternalV2BulkPacketBatchCapability(t)
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) {
		result := make([]net.Addr, 0, 5)
		for last := 1; last <= 5; last++ {
			result = append(result, &net.IPNet{IP: net.IPv4(127, 0, 0, byte(last)), Mask: net.CIDRMask(8, 32)})
		}
		return result, nil
	}
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })

	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(reserved.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	_ = reserved.Close()
	senderPort, receiverPort := 0, port
	if senderListens {
		senderPort, receiverPort = port, 0
	}

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte{0x5a}, externalV2DirectTCPMinFileSize)
	sink := newMemoryBlockSink(int64(len(payload)))
	var offerStatus, receiveStatus syncBuffer
	tokenSink := make(chan string, 1)
	offerErr := make(chan error, 1)
	go func() {
		_, err := Offer(ctx, OfferConfig{
			TokenSink:     tokenSink,
			Emitter:       telemetry.New(&offerStatus, telemetry.LevelVerbose),
			UsePublicDERP: true,
			DirectTCPPort: senderPort,
			BlockSource: &BlockSource{
				Header:      []byte("direct-tcp"),
				Payload:     bytes.NewReader(payload),
				PayloadSize: int64(len(payload)),
				ChunkSize:   1 << 20,
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
		t.Fatal(ctx.Err())
	}
	err = Receive(ctx, ReceiveConfig{
		Token:         raw,
		Emitter:       telemetry.New(&receiveStatus, telemetry.LevelVerbose),
		UsePublicDERP: true,
		DirectTCPPort: receiverPort,
		BlockReceiver: func(context.Context, BlockReceiveRequest) (BlockReceiveSink, error) {
			return sink, nil
		},
	})
	if err != nil {
		t.Fatalf("Receive() error = %v offer=%q receive=%q", err, offerStatus.String(), receiveStatus.String())
	}
	if err := <-offerErr; err != nil {
		t.Fatalf("Offer() error = %v offer=%q receive=%q", err, offerStatus.String(), receiveStatus.String())
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("direct TCP file payload mismatch")
	}
	for role, status := range map[string]string{"offer": offerStatus.String(), "receive": receiveStatus.String()} {
		if !strings.Contains(status, "v2-block-transfer=direct-tcp-files") || !strings.Contains(status, "v2-data-plane=direct-tcp-files") {
			t.Fatalf("%s status missing direct TCP markers: %q", role, status)
		}
	}
}

func disableExternalV2BulkPacketBatchCapability(t *testing.T) {
	t.Helper()
	previous := externalV2BulkPacketBatchCapability
	externalV2BulkPacketBatchCapability = func() bool { return false }
	t.Cleanup(func() { externalV2BulkPacketBatchCapability = previous })
}

func TestExternalV2OfferReceiveRelayBlockRoundTrip(t *testing.T) {
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

type gatedMemoryBlockSink struct {
	*memoryBlockSink
	firstWrite  chan struct{}
	release     chan struct{}
	writeCount  int
	mu          sync.Mutex
	releaseOnce sync.Once
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

func newGatedMemoryBlockSink(size int64) *gatedMemoryBlockSink {
	return &gatedMemoryBlockSink{
		memoryBlockSink: newMemoryBlockSink(size),
		firstWrite:      make(chan struct{}),
		release:         make(chan struct{}),
	}
}

func (s *gatedMemoryBlockSink) WriteAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	s.writeCount++
	writeCount := s.writeCount
	s.mu.Unlock()
	if writeCount == 1 {
		n, err := s.memoryBlockSink.WriteAt(p, off)
		close(s.firstWrite)
		return n, err
	}
	<-s.release
	return s.memoryBlockSink.WriteAt(p, off)
}

func (s *gatedMemoryBlockSink) releaseWrites() {
	s.releaseOnce.Do(func() { close(s.release) })
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
