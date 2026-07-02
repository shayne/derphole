// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/quicpath"
)

const stripedTestStreamCount = 4

type delayedEOFReader struct {
	payload []byte
	split   int
	delay   time.Duration
	offset  int
	delayed bool
}

func (r *delayedEOFReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.payload) {
		return 0, io.EOF
	}
	if !r.delayed && r.offset >= r.split {
		r.delayed = true
		time.Sleep(r.delay)
	}
	n := copy(p, r.payload[r.offset:])
	if !r.delayed && r.offset+n > r.split {
		n = r.split - r.offset
	}
	r.offset += n
	return n, nil
}

type notifyingBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	want   int
	ready  chan struct{}
	closed bool
}

func newNotifyingBuffer(want int) *notifyingBuffer {
	return &notifyingBuffer{want: want, ready: make(chan struct{})}
}

func (b *notifyingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if !b.closed && b.buf.Len() >= b.want {
		b.closed = true
		close(b.ready)
	}
	return n, err
}

func (b *notifyingBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

type stripedRawQUICPair struct {
	server *dataplane.QUICServer
	client *dataplane.QUICClient
}

func newStripedRawQUICPair(t *testing.T, count int) stripedRawQUICPair {
	t.Helper()

	serverConns := make([]net.PacketConn, 0, count)
	clientConns := make([]net.PacketConn, 0, count)
	serverAddrs := make([]net.Addr, 0, count)
	for range count {
		serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket(server) error = %v", err)
		}
		t.Cleanup(func() { _ = serverConn.Close() })
		clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket(client) error = %v", err)
		}
		t.Cleanup(func() { _ = clientConn.Close() })
		serverConns = append(serverConns, serverConn)
		clientConns = append(clientConns, clientConn)
		serverAddrs = append(serverAddrs, serverConn.LocalAddr())
	}

	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}

	return stripedRawQUICPair{
		server: dataplane.NewQUICServerOnPacketConns(serverConns, serverIdentity, clientIdentity.Public),
		client: dataplane.NewQUICClientOnPacketConns(clientConns, serverAddrs, clientIdentity, serverIdentity.Public),
	}
}

type stripedPipeStreamPair struct {
	sender   *io.PipeWriter
	listener *io.PipeReader
}

func newStripedPipeStreamPairs(t *testing.T, n int) []stripedPipeStreamPair {
	t.Helper()

	pairs := make([]stripedPipeStreamPair, 0, n)
	for range n {
		listener, sender := io.Pipe()
		pairs = append(pairs, stripedPipeStreamPair{sender: sender, listener: listener})
	}
	return pairs
}

func closeStripedPipeStreamPairs(pairs []stripedPipeStreamPair) {
	for _, pair := range pairs {
		_ = pair.sender.Close()
		_ = pair.listener.Close()
	}
}

func TestExternalStripedCopyPreservesOrderAcrossInterleavedStripes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pairs := newStripedPipeStreamPairs(t, 4)
	defer closeStripedPipeStreamPairs(pairs)

	payload := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz"), 4096)
	var got bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		readers := make([]io.ReadCloser, 0, len(pairs))
		for _, pair := range pairs {
			readers = append(readers, pair.listener)
		}
		if err := receiveExternalStripedCopy(ctx, &got, readers, 1024); err != nil {
			t.Errorf("receiveExternalStripedCopy() error = %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		writers := make([]io.WriteCloser, 0, len(pairs))
		for _, pair := range pairs {
			writers = append(writers, pair.sender)
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 1024); err != nil {
			t.Errorf("sendExternalStripedCopy() error = %v", err)
		}
	}()

	wg.Wait()
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
}

func TestExternalStripedCopyHandlesShortFinalChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pairs := newStripedPipeStreamPairs(t, 3)
	defer closeStripedPipeStreamPairs(pairs)

	payload := []byte("short-final-chunk")
	var got bytes.Buffer
	errCh := make(chan error, 2)

	go func() {
		readers := []io.ReadCloser{pairs[0].listener, pairs[1].listener, pairs[2].listener}
		errCh <- receiveExternalStripedCopy(ctx, &got, readers, 8)
	}()
	go func() {
		writers := []io.WriteCloser{pairs[0].sender, pairs[1].sender, pairs[2].sender}
		errCh <- sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 8)
	}()

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if got.String() != string(payload) {
		t.Fatalf("reassembled payload = %q, want %q", got.String(), payload)
	}
}

func TestExternalStripedCopyFlushesPartialReadBeforeEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pairs := newStripedPipeStreamPairs(t, 2)
	defer closeStripedPipeStreamPairs(pairs)

	srcReader, srcWriter := io.Pipe()
	defer func() { _ = srcReader.Close() }()
	got := newNotifyingBuffer(len("early payload"))
	errCh := make(chan error, 2)

	go func() {
		readers := []io.ReadCloser{pairs[0].listener, pairs[1].listener}
		errCh <- receiveExternalStripedCopy(ctx, got, readers, 1024)
	}()
	go func() {
		writers := []io.WriteCloser{pairs[0].sender, pairs[1].sender}
		errCh <- sendExternalStripedCopy(ctx, srcReader, writers, 1024)
	}()

	if _, err := srcWriter.Write([]byte("early payload")); err != nil {
		t.Fatalf("source Write() error = %v", err)
	}
	select {
	case <-got.ready:
	case <-time.After(500 * time.Millisecond):
		_ = srcWriter.Close()
		t.Fatal("partial read was not delivered before source EOF")
	}
	if err := srcWriter.Close(); err != nil {
		t.Fatalf("source Close() error = %v", err)
	}

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if string(got.Bytes()) != "early payload" {
		t.Fatalf("reassembled payload = %q, want %q", string(got.Bytes()), "early payload")
	}
}

func TestExternalStripedCopyHandlesShortDelayedPayloadOverRawQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair := newStripedRawQUICPair(t, stripedTestStreamCount)
	payload := []byte("short delayed payload over raw direct quic")
	reader := &delayedEOFReader{
		payload: payload,
		split:   len(payload) / 2,
		delay:   200 * time.Millisecond,
	}

	var got bytes.Buffer
	errCh := make(chan error, 2)
	go func() {
		streams, err := pair.server.AcceptStreamsWithReady(ctx, stripedTestStreamCount, nil)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- receiveExternalStripedCopy(ctx, &got, streams, externalV2CopyBufferSize)
	}()
	go func() {
		streams, err := pair.client.OpenStreams(ctx, stripedTestStreamCount)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- sendExternalStripedCopy(ctx, reader, streams, externalV2CopyBufferSize)
	}()

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("reassembled payload = %q, want %q", got.String(), payload)
	}
}

func TestExternalStripedCopyWarmsParallelRawQUICStreamsBeforeSourceEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair := newStripedRawQUICPair(t, stripedTestStreamCount)
	payload := []byte("parallel raw quic should expose every stream before source eof")
	reader := &delayedEOFReader{
		payload: payload,
		split:   len(payload) / 2,
		delay:   1500 * time.Millisecond,
	}
	got := newNotifyingBuffer(len(payload) / 2)
	errCh := make(chan error, 2)

	go func() {
		streams, err := pair.server.AcceptStreamsWithReady(ctx, stripedTestStreamCount, nil)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- receiveExternalStripedCopy(ctx, got, streams, externalV2CopyBufferSize)
	}()
	go func() {
		streams, err := pair.client.OpenStreams(ctx, stripedTestStreamCount)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- sendExternalStripedCopy(ctx, reader, streams, externalV2CopyBufferSize)
	}()

	select {
	case <-got.ready:
	case err := <-errCh:
		t.Fatalf("striped raw QUIC copy exited before early payload: %v", err)
	case <-time.After(500 * time.Millisecond):
		cancel()
		t.Fatal("parallel raw QUIC streams were not warmed before source EOF")
	}

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("reassembled payload = %q, want %q", string(got.Bytes()), payload)
	}
}

func TestExternalStripedCopyKeepsFastStripeBusyWhenOneWriterBlocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slowRelease := make(chan struct{})
	slowWriter := &blockingWriteCloser{release: slowRelease}
	fastWriter := &countingWriteCloser{}
	done := make(chan error, 1)

	go func() {
		done <- sendExternalStripedCopy(ctx, bytes.NewReader([]byte("abcdefghijklmnopqrstuvwxyz")), []io.WriteCloser{slowWriter, fastWriter}, 1)
	}()

	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt64(&fastWriter.writes) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&fastWriter.writes); got == 0 {
		close(slowRelease)
		t.Fatal("fast stripe did not receive any chunk while slow stripe was blocked")
	}
	close(slowRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExternalStripedCopyObserverRecordsSenderBlockedDuration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	release := make(chan struct{})
	writers := []io.WriteCloser{
		newNotifyingBlockingWriteCloser(release),
		newNotifyingBlockingWriteCloser(release),
	}
	reader := newNotifyingChunkReader(bytes.Repeat([]byte("x"), 6), 5)
	blockedCh := make(chan time.Duration, 1)
	done := make(chan error, 1)
	observer := externalStripedCopyObserver{
		SendBlocked: func(d time.Duration) {
			select {
			case blockedCh <- d:
			default:
			}
		},
	}

	go func() {
		done <- sendExternalStripedCopyWithObserver(ctx, reader, writers, 1, observer)
	}()

	for _, writer := range writers {
		blockingWriter := writer.(*notifyingBlockingWriteCloser)
		select {
		case <-blockingWriter.entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("writer did not block before sender saturation")
		}
	}
	select {
	case <-reader.reached:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("sender did not fill the jobs channel")
	}
	time.Sleep(25 * time.Millisecond)
	close(release)

	select {
	case d := <-blockedCh:
		if d <= 0 {
			t.Fatalf("blocked duration = %s, want positive", d)
		}
	case err := <-done:
		if err != nil {
			t.Fatalf("sendExternalStripedCopyWithObserver() error = %v", err)
		}
		t.Fatal("sendExternalStripedCopyWithObserver() completed without recording blocked duration")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blocked duration")
	}
	if err := <-done; err != nil {
		t.Fatalf("sendExternalStripedCopyWithObserver() error = %v", err)
	}
}

func TestExternalStripedCopyObserverReportsReceiveBacklog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first := []byte("first")
	second := []byte("second")
	releaseFirst := make(chan struct{})
	var releaseFirstOnce sync.Once
	closeReleaseFirst := func() { releaseFirstOnce.Do(func() { close(releaseFirst) }) }
	readers := []io.ReadCloser{
		&gatedReadCloser{reader: bytes.NewReader(externalStripedTestFrame(t, 0, first)), release: releaseFirst, closeRelease: closeReleaseFirst},
		io.NopCloser(bytes.NewReader(externalStripedTestFrame(t, 1, second))),
	}
	var got bytes.Buffer
	var events []externalStripedBacklogEvent
	observer := externalStripedCopyObserver{
		ReceiveBacklog: func(chunks int, bytes int64) {
			events = append(events, externalStripedBacklogEvent{chunks: chunks, bytes: bytes})
			if chunks == 1 && bytes == int64(len(second)) {
				closeReleaseFirst()
			}
		},
	}

	if err := receiveExternalStripedCopyWithObserver(ctx, &got, readers, 8, observer); err != nil {
		closeReleaseFirst()
		t.Fatalf("receiveExternalStripedCopyWithObserver() error = %v", err)
	}
	if !bytes.Equal(got.Bytes(), append(first, second...)) {
		t.Fatalf("reassembled payload = %q, want %q", got.String(), string(append(first, second...)))
	}
	sawPending := false
	sawZeroAfterPending := false
	for _, event := range events {
		if !sawPending && event.chunks == 1 && event.bytes == int64(len(second)) {
			sawPending = true
			continue
		}
		if sawPending && event.chunks == 0 && event.bytes == 0 {
			sawZeroAfterPending = true
			break
		}
	}
	if !sawPending || !sawZeroAfterPending {
		t.Fatalf("receive backlog events = %#v, want pending second chunk then zero after flush", events)
	}
}

func BenchmarkExternalStripedCopy256MiB4Stripes(b *testing.B) {
	payload := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 32<<20)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pairs := make([]stripedPipeStreamPair, 0, 4)
		for range 4 {
			listener, sender := io.Pipe()
			pairs = append(pairs, stripedPipeStreamPair{sender: sender, listener: listener})
		}

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 2)

		b.StartTimer()
		go func() {
			readers := make([]io.ReadCloser, 0, len(pairs))
			for _, pair := range pairs {
				readers = append(readers, pair.listener)
			}
			errCh <- receiveExternalStripedCopy(ctx, io.Discard, readers, externalCopyBufferSize)
		}()
		go func() {
			writers := make([]io.WriteCloser, 0, len(pairs))
			for _, pair := range pairs {
				writers = append(writers, pair.sender)
			}
			errCh <- sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, externalCopyBufferSize)
		}()

		for range 2 {
			if err := <-errCh; err != nil {
				b.StopTimer()
				cancel()
				closeStripedPipeStreamPairs(pairs)
				b.Fatal(err)
			}
		}
		b.StopTimer()
		cancel()
		closeStripedPipeStreamPairs(pairs)
	}
}

type blockingWriteCloser struct {
	release chan struct{}
}

func (w *blockingWriteCloser) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

func (*blockingWriteCloser) Close() error {
	return nil
}

type countingWriteCloser struct {
	writes int64
}

func (w *countingWriteCloser) Write(p []byte) (int, error) {
	atomic.AddInt64(&w.writes, 1)
	return len(p), nil
}

func (*countingWriteCloser) Close() error {
	return nil
}

type notifyingBlockingWriteCloser struct {
	release <-chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newNotifyingBlockingWriteCloser(release <-chan struct{}) *notifyingBlockingWriteCloser {
	return &notifyingBlockingWriteCloser{
		release: release,
		entered: make(chan struct{}),
	}
}

func (w *notifyingBlockingWriteCloser) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func (*notifyingBlockingWriteCloser) Close() error {
	return nil
}

type notifyingChunkReader struct {
	reader  *bytes.Reader
	target  int64
	reads   int64
	reached chan struct{}
	once    sync.Once
}

func newNotifyingChunkReader(payload []byte, target int64) *notifyingChunkReader {
	return &notifyingChunkReader{
		reader:  bytes.NewReader(payload),
		target:  target,
		reached: make(chan struct{}),
	}
}

func (r *notifyingChunkReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && atomic.AddInt64(&r.reads, 1) == r.target {
		r.once.Do(func() { close(r.reached) })
	}
	return n, err
}

type gatedReadCloser struct {
	reader       *bytes.Reader
	release      <-chan struct{}
	closeRelease func()
	once         sync.Once
}

func (r *gatedReadCloser) Read(p []byte) (int, error) {
	r.once.Do(func() { <-r.release })
	return r.reader.Read(p)
}

func (r *gatedReadCloser) Close() error {
	if r.closeRelease != nil {
		r.closeRelease()
	}
	return nil
}

type externalStripedBacklogEvent struct {
	chunks int
	bytes  int64
}

func externalStripedTestFrame(t *testing.T, seq uint64, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := writeExternalStripedChunk(&buf, externalStripedChunk{seq: seq, data: payload}); err != nil {
		t.Fatalf("writeExternalStripedChunk() error = %v", err)
	}
	return buf.Bytes()
}
