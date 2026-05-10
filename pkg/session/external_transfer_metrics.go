// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
)

type externalTransferMetrics struct {
	mu          sync.Mutex
	startedAt   time.Time
	completedAt time.Time
	firstByteAt time.Time
	relayBytes  int64
	directBytes int64
}

type externalTransferMetricsContextKey struct{}

func newExternalTransferMetrics(startedAt time.Time) *externalTransferMetrics {
	return &externalTransferMetrics{startedAt: startedAt}
}

func (m *externalTransferMetrics) RecordRelayWrite(n int64, at time.Time) {
	m.recordWrite(&m.relayBytes, n, at)
}

func (m *externalTransferMetrics) RecordDirectWrite(n int64, at time.Time) {
	m.recordWrite(&m.directBytes, n, at)
}

func (m *externalTransferMetrics) Complete(at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at.IsZero() {
		return
	}
	m.completedAt = at
}

func (m *externalTransferMetrics) TotalDurationMS() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.startedAt.IsZero() || m.completedAt.IsZero() || !m.completedAt.After(m.startedAt) {
		return 0
	}
	return m.completedAt.Sub(m.startedAt).Milliseconds()
}

func (m *externalTransferMetrics) FirstByteMS() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.startedAt.IsZero() || m.firstByteAt.IsZero() || m.firstByteAt.Before(m.startedAt) {
		return 0
	}
	return m.firstByteAt.Sub(m.startedAt).Milliseconds()
}

func (m *externalTransferMetrics) RelayBytes() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.relayBytes
}

func (m *externalTransferMetrics) DirectBytes() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.directBytes
}

func (m *externalTransferMetrics) Emit(emitter *telemetry.Emitter, prefix string, stats probe.TransferStats) {
	if emitter == nil {
		return
	}
	emitter.Debug(prefix + "-wall-duration-ms=" + strconv.FormatInt(m.TotalDurationMS(), 10))
	emitter.Debug(prefix + "-session-first-byte-ms=" + strconv.FormatInt(m.FirstByteMS(), 10))
	emitter.Debug(prefix + "-relay-bytes=" + strconv.FormatInt(m.RelayBytes(), 10))
	emitter.Debug(prefix + "-direct-bytes=" + strconv.FormatInt(m.DirectBytes(), 10))
	emitter.Debug(prefix + "-peak-goodput-mbps=" + strconv.FormatFloat(stats.PeakGoodputMbps, 'f', 2, 64))
}

func withExternalTransferMetrics(ctx context.Context, metrics *externalTransferMetrics) context.Context {
	if metrics == nil {
		return ctx
	}
	return context.WithValue(ctx, externalTransferMetricsContextKey{}, metrics)
}

func externalTransferMetricsFromContext(ctx context.Context) *externalTransferMetrics {
	if ctx == nil {
		return nil
	}
	metrics, _ := ctx.Value(externalTransferMetricsContextKey{}).(*externalTransferMetrics)
	return metrics
}

func emitExternalTransferMetricsComplete(metrics *externalTransferMetrics, emitter *telemetry.Emitter, prefix string, stats probe.TransferStats, at time.Time) {
	if metrics == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	metrics.Complete(at)
	metrics.Emit(emitter, prefix, stats)
}

type externalTransferMetricsWriter struct {
	w      io.Writer
	record func(int64, time.Time)
}

func (w externalTransferMetricsWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 && w.record != nil {
		w.record(int64(n), time.Now())
	}
	return n, err
}

func (m *externalTransferMetrics) recordWrite(totalBytes *int64, n int64, at time.Time) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	*totalBytes += n
	if at.IsZero() {
		return
	}
	if m.firstByteAt.IsZero() || at.Before(m.firstByteAt) {
		m.firstByteAt = at
	}
}
