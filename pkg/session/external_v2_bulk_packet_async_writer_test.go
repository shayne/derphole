// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExternalV2BulkPacketAsyncWriterCommitsQueuedExtents(t *testing.T) {
	sink := newMemoryBlockSink(12)
	writer := newExternalV2BulkPacketAsyncWriter(context.Background(), sink, 2, nil)
	for _, extent := range []externalV2BulkPacketWriteExtent{
		{Offset: 4, Data: []byte("efgh")},
		{Offset: 0, Data: []byte("abcd")},
		{Offset: 8, Data: []byte("ijkl")},
	} {
		if err := writer.enqueue(extent); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := writer.finish()
	if err != nil {
		t.Fatal(err)
	}
	if committed != 12 || !bytes.Equal(sink.bytes(), []byte("abcdefghijkl")) {
		t.Fatalf("committed = %d payload = %q", committed, sink.bytes())
	}
}

func TestExternalV2BulkPacketAsyncWriterReportsShortWrite(t *testing.T) {
	writer := newExternalV2BulkPacketAsyncWriter(context.Background(), shortAsyncBulkPacketSink{}, 1, nil)
	if err := writer.enqueue(externalV2BulkPacketWriteExtent{Data: []byte("payload")}); err != nil {
		t.Fatal(err)
	}
	_, err := writer.finish()
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

func TestExternalV2BulkPacketAsyncWriterQueueHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sink := &blockingAsyncBulkPacketSink{started: make(chan struct{}), release: make(chan struct{})}
	writer := newExternalV2BulkPacketAsyncWriter(ctx, sink, 1, nil)
	if err := writer.enqueue(externalV2BulkPacketWriteExtent{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	<-sink.started
	if err := writer.enqueue(externalV2BulkPacketWriteExtent{Data: []byte("second")}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- writer.enqueue(externalV2BulkPacketWriteExtent{Data: []byte("third")})
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("enqueue error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked enqueue did not stop after cancellation")
	}
	close(sink.release)
	_, _ = writer.finish()
}

func TestExternalV2BulkPacketAsyncWriterUsesConcurrentSafeSink(t *testing.T) {
	sink := &concurrentSafeAsyncBulkPacketSink{
		started: make(chan struct{}, 4),
		release: make(chan struct{}),
	}
	writer := newExternalV2BulkPacketAsyncWriter(context.Background(), sink, 4, nil)
	for index := range 4 {
		if err := writer.enqueue(externalV2BulkPacketWriteExtent{Offset: int64(index), Data: []byte{byte(index)}}); err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		select {
		case <-sink.started:
		case <-time.After(250 * time.Millisecond):
			close(sink.release)
			t.Fatal("concurrent-safe sink did not start four writes")
		}
	}
	close(sink.release)
	if _, err := writer.finish(); err != nil {
		t.Fatal(err)
	}
	if sink.maximum.Load() < 4 {
		t.Fatalf("maximum concurrent writes = %d, want 4", sink.maximum.Load())
	}
}

type shortAsyncBulkPacketSink struct{}

func (shortAsyncBulkPacketSink) WriteAt(payload []byte, _ int64) (int, error) {
	return max(0, len(payload)-1), nil
}

func (shortAsyncBulkPacketSink) Close() error { return nil }

type blockingAsyncBulkPacketSink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type concurrentSafeAsyncBulkPacketSink struct {
	started chan struct{}
	release chan struct{}
	active  atomic.Int32
	maximum atomic.Int32
}

func (*concurrentSafeAsyncBulkPacketSink) ConcurrentWriteAtSafe() bool { return true }

func (s *concurrentSafeAsyncBulkPacketSink) WriteAt(payload []byte, _ int64) (int, error) {
	active := s.active.Add(1)
	for current := s.maximum.Load(); active > current && !s.maximum.CompareAndSwap(current, active); current = s.maximum.Load() {
	}
	s.started <- struct{}{}
	<-s.release
	s.active.Add(-1)
	return len(payload), nil
}

func (*concurrentSafeAsyncBulkPacketSink) Close() error { return nil }

func (s *blockingAsyncBulkPacketSink) WriteAt(payload []byte, _ int64) (int, error) {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return len(payload), nil
}

func (*blockingAsyncBulkPacketSink) Close() error { return nil }
