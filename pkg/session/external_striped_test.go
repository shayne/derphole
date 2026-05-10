// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
