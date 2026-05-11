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
	"github.com/shayne/derphole/pkg/transfertrace"
)

type externalTransferMetrics struct {
	mu                     sync.Mutex
	startedAt              time.Time
	completedAt            time.Time
	firstByteAt            time.Time
	relayBytes             int64
	directBytes            int64
	trace                  *transfertrace.Recorder
	role                   transfertrace.Role
	phase                  transfertrace.Phase
	lastState              string
	lastError              string
	directRateSelectedMbps int
	directRateActiveMbps   int
	directLanesActive      int
	directLanesAvailable   int
	directProbeState       string
	directProbeSummary     string
	replayWindowBytes      uint64
	repairQueueBytes       uint64
	retransmitCount        int64
	outOfOrderBytes        uint64
}

type externalTransferMetricsContextKey struct{}

func newExternalTransferMetrics(startedAt time.Time) *externalTransferMetrics {
	return &externalTransferMetrics{startedAt: startedAt}
}

func newExternalTransferMetricsWithTrace(startedAt time.Time, trace *transfertrace.Recorder, role transfertrace.Role) *externalTransferMetrics {
	metrics := newExternalTransferMetrics(startedAt)
	metrics.trace = trace
	metrics.role = role
	return metrics
}

func (m *externalTransferMetrics) RecordRelayWrite(n int64, at time.Time) {
	if m == nil {
		return
	}
	m.recordWrite(&m.relayBytes, n, at)
}

func (m *externalTransferMetrics) RecordDirectWrite(n int64, at time.Time) {
	if m == nil {
		return
	}
	m.recordWrite(&m.directBytes, n, at)
}

func (m *externalTransferMetrics) Complete(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if at.IsZero() {
		m.mu.Unlock()
		return
	}
	m.completedAt = at
	m.phase = transfertrace.PhaseComplete
	m.lastState = string(StateComplete)
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetPhase(phase transfertrace.Phase, state string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.phase = phase
	m.lastState = state
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetError(err error) {
	if m == nil || err == nil {
		return
	}
	m.mu.Lock()
	m.phase = transfertrace.PhaseError
	m.lastError = err.Error()
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetDirectPlan(selectedRate int, activeRate int, activeLanes int, availableLanes int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.directRateSelectedMbps = selectedRate
	m.directRateActiveMbps = activeRate
	m.directLanesActive = activeLanes
	m.directLanesAvailable = availableLanes
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetProbeSummary(state string, summary string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.directProbeState = state
	m.directProbeSummary = summary
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) Tick(at time.Time) {
	if m == nil || at.IsZero() {
		return
	}
	m.mu.Lock()
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
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
	*totalBytes += n
	if at.IsZero() {
		m.mu.Unlock()
		return
	}
	if m.firstByteAt.IsZero() || at.Before(m.firstByteAt) {
		m.firstByteAt = at
	}
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	observeExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) updateTraceLocked(at time.Time) (*transfertrace.Recorder, transfertrace.Snapshot, bool) {
	if m.trace == nil || at.IsZero() {
		return nil, transfertrace.Snapshot{}, false
	}
	return m.trace, transfertrace.Snapshot{
		At:                     at,
		Phase:                  m.phase,
		RelayBytes:             m.relayBytes,
		DirectBytes:            m.directBytes,
		AppBytes:               m.relayBytes + m.directBytes,
		DirectRateSelectedMbps: m.directRateSelectedMbps,
		DirectRateActiveMbps:   m.directRateActiveMbps,
		DirectLanesActive:      m.directLanesActive,
		DirectLanesAvailable:   m.directLanesAvailable,
		DirectProbeState:       m.directProbeState,
		DirectProbeSummary:     m.directProbeSummary,
		ReplayWindowBytes:      m.replayWindowBytes,
		RepairQueueBytes:       m.repairQueueBytes,
		RetransmitCount:        m.retransmitCount,
		OutOfOrderBytes:        m.outOfOrderBytes,
		LastState:              m.lastState,
		LastError:              m.lastError,
	}, true
}

func observeExternalTransferTrace(trace *transfertrace.Recorder, snap transfertrace.Snapshot, ok bool) {
	if !ok {
		return
	}
	trace.Observe(snap)
}
