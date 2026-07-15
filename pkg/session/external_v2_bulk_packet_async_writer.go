// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

const (
	externalV2BulkPacketWriterQueue = 64
	externalV2BulkPacketWriteGroup  = 1 << 20
	externalV2BulkPacketWriters     = 4
)

type externalV2BulkPacketWriteExtent struct {
	Offset int64
	Data   []byte
}

type externalV2BulkPacketAsyncWriter struct {
	ctx       context.Context
	sink      BlockReceiveSink
	metrics   *externalTransferMetrics
	queue     chan externalV2BulkPacketWriteExtent
	done      chan struct{}
	closeOnce sync.Once
	workers   sync.WaitGroup
	committed atomic.Int64
	peak      atomic.Uint32
	errMu     sync.Mutex
	err       error
}

func newExternalV2BulkPacketAsyncWriter(ctx context.Context, sink BlockReceiveSink, depth int, metrics *externalTransferMetrics) *externalV2BulkPacketAsyncWriter {
	writer := &externalV2BulkPacketAsyncWriter{
		ctx:     ctx,
		sink:    sink,
		metrics: metrics,
		queue:   make(chan externalV2BulkPacketWriteExtent, max(1, depth)),
		done:    make(chan struct{}),
	}
	workerCount := 1
	if concurrent, ok := sink.(ConcurrentBlockReceiveSink); ok && concurrent.ConcurrentWriteAtSafe() {
		workerCount = externalV2BulkPacketWriters
	}
	writer.workers.Add(workerCount)
	for range workerCount {
		go writer.run()
	}
	go func() {
		writer.workers.Wait()
		close(writer.done)
	}()
	return writer
}

func (w *externalV2BulkPacketAsyncWriter) enqueue(extent externalV2BulkPacketWriteExtent) error {
	if err := w.loadError(); err != nil {
		return err
	}
	select {
	case w.queue <- extent:
		// The writer may dequeue before this goroutine resumes. Count the
		// accepted extent itself so a healthy fast writer still reports a
		// nonzero outstanding-write peak.
		externalV2BulkPacketAtomicMaxUint32(&w.peak, uint32(max(1, len(w.queue))))
		return nil
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}

func (w *externalV2BulkPacketAsyncWriter) finish() (int64, error) {
	w.closeOnce.Do(func() { close(w.queue) })
	<-w.done
	return w.committed.Load(), w.loadError()
}

func (w *externalV2BulkPacketAsyncWriter) run() {
	defer w.workers.Done()
	for extent := range w.queue {
		if w.loadError() != nil {
			continue
		}
		n, err := w.sink.WriteAt(extent.Data, extent.Offset)
		if err == nil && n != len(extent.Data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.setError(err)
			continue
		}
		w.committed.Add(int64(n))
		if w.metrics != nil {
			w.metrics.RecordDirectPacketReceive(int64(n), time.Now())
			w.metrics.RecordFilePayloadCommit(transfertrace.FilePayloadEngineBulk, int64(n), time.Now())
		}
	}
}

func (w *externalV2BulkPacketAsyncWriter) setError(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	w.err = errors.Join(w.err, err)
	w.errMu.Unlock()
}

func (w *externalV2BulkPacketAsyncWriter) loadError() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.err
}
