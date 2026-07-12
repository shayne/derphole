// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
)

type externalTransferMetrics struct {
	mu                     sync.Mutex
	startedAt              time.Time
	completedAt            time.Time
	firstByteAt            time.Time
	relayBytes             int64
	directBytes            int64
	localSentBytes         int64
	peerReceivedBytes      int64
	peerProgressSet        bool
	transferStartedAt      time.Time
	receiverTransferMS     int64
	directValidated        bool
	fallbackReason         string
	transportPath          transport.Path
	transportSelectedAddr  string
	transportPreviousAddr  string
	transportReason        string
	transportSource        string
	transportRTTMS         int64
	directAppProgressBase  int64
	directAppProgressSet   bool
	trace                  *transfertrace.Recorder
	role                   transfertrace.Role
	phase                  transfertrace.Phase
	lastState              string
	lastError              string
	deferSendComplete      bool
	directRateSelectedMbps int
	directRateSelectedPlan bool
	directRateActiveMbps   int
	directLanesActive      int
	directLanesAvailable   int
	rateTargetMbps         int
	rateTargetFromDirect   bool
	rateCeilingMbps        int
	rateExplorationCeiling int
	laneMin                int
	laneCap                int
	controllerDecision     string
	controllerReason       string
	directProbeState       string
	directProbeSummary     string
	replayWindowBytes      uint64
	replayBytes            uint64
	repairQueueBytes       uint64
	retransmitCount        int64
	repairRequests         int64
	repairBytes            int64
	missingScanChecks      uint64
	pendingMissing         uint32
	pendingMissingPeak     uint32
	repairRequestedPackets uint64
	repairRequestBatches   uint64
	reorderTrailPackets    uint32
	receivePacketRatePPS   uint32

	localENOBUFSRetries        int64
	localENOBUFSWaitUS         int64
	localENOBUFSMaxConsecutive int64

	outOfOrderBytes       uint64
	directPacketBytes     int64
	directCommittedBytes  int64
	directTransport       string
	quicHandshakeMS       int64
	quicFirstByteMS       int64
	quicStreamBytesSent   int64
	quicStreamBytesRecv   int64
	quicStreamGoodputMbps string
	quicSmoothedRTTMS     string
	quicLossEvents        int64
	quicCloseReason       string
	transportManager      *transport.Manager

	stripedSendBlocked             time.Duration
	stripedReceivePendingChunks    int
	stripedReceivePendingChunksMax int
	stripedReceivePendingBytes     int64
	stripedReceivePendingBytesMax  int64
}

type externalDirectTransferStats struct {
	BytesSent       int64
	BytesReceived   int64
	Retransmits     int64
	MaxReplayBytes  uint64
	PeakGoodputMbps float64
	Diagnostics     externalDirectTransferDiagnostics
}

type externalDirectTransferDiagnostics struct {
	RateTargetMbps             int
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	RateSelectedMbps           int
	ActiveLanes                int
	AvailableLanes             int
	LaneMin                    int
	LaneCap                    int
	ControllerDecision         string
	ControllerReason           string
	ReplayBytes                uint64
	Retransmits                int64
	RepairRequests             int64
	RepairBytes                int64
	LocalENOBUFSRetries        int64
	LocalENOBUFSWaitUS         int64
	LocalENOBUFSMaxConsecutive int64
	DirectPacketBytes          int64
	DirectCommittedBytes       int64
	ReceiverCommittedBytes     uint64
	MissingScanChecks          uint64
	PendingMissing             uint32
	PendingMissingPeak         uint32
	RepairRequestedPackets     uint64
	RepairRequestBatches       uint64
	ReorderTrailPackets        uint32
	ReceivePacketRatePPS       uint32
}

type externalPeerProgressSnapshot struct {
	BytesReceived     int64
	TransferElapsedMS int64
	Set               bool
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

func (m *externalTransferMetrics) RecordLocalSent(n int64, at time.Time) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.localSentBytes += n
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordPeerProgress(bytesReceived int64, transferElapsedMS int64, at time.Time) {
	if m == nil || bytesReceived < 0 {
		return
	}
	at = nonZeroTime(at)
	m.mu.Lock()
	m.peerProgressSet = true
	if bytesReceived > m.peerReceivedBytes {
		m.peerReceivedBytes = bytesReceived
	}
	if transferElapsedMS > m.receiverTransferMS {
		m.receiverTransferMS = transferElapsedMS
	}
	if m.transferStartedAt.IsZero() && transferElapsedMS >= 0 {
		m.transferStartedAt = at.Add(-time.Duration(transferElapsedMS) * time.Millisecond)
	}
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) PeerProgressSnapshot() externalPeerProgressSnapshot {
	if m == nil {
		return externalPeerProgressSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return externalPeerProgressSnapshot{
		BytesReceived:     m.peerReceivedBytes,
		TransferElapsedMS: m.receiverTransferMS,
		Set:               m.peerProgressSet,
	}
}

func (m *externalTransferMetrics) MarkDirectValidated(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.markDirectValidatedLocked()
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordTransportPathSnapshot(snapshot transport.PathSnapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.transportPath = snapshot.Path
	m.transportSelectedAddr = addrString(snapshot.SelectedAddr)
	m.transportPreviousAddr = ""
	m.transportRTTMS = snapshot.SelectedRTT.Milliseconds()
	if snapshot.Path == transport.PathDirect {
		m.markDirectValidatedLocked()
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(snapshot.At))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordTransportPathEvent(event transport.PathEvent) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if event.Path != transport.PathUnknown {
		m.transportPath = event.Path
	} else if event.Snapshot.Path != transport.PathUnknown {
		m.transportPath = event.Snapshot.Path
	}
	m.transportSelectedAddr = addrString(event.SelectedAddr)
	m.transportPreviousAddr = addrString(event.PreviousAddr)
	m.transportReason = string(event.Reason)
	m.transportSource = string(event.Source)
	m.transportRTTMS = event.RTT.Milliseconds()
	if event.Type == transport.PathEventSelected && event.Path == transport.PathDirect {
		m.markDirectValidatedLocked()
	}
	if event.Type == transport.PathEventFallback && event.Reason != "" {
		m.fallbackReason = string(event.Reason)
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(event.At))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetFallbackReason(reason string, at time.Time) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.fallbackReason = reason
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetDirectAppProgressBase(offset int64) {
	if m == nil {
		return
	}
	if offset < 0 {
		offset = 0
	}
	m.mu.Lock()
	m.directAppProgressBase = offset
	m.directAppProgressSet = true
	m.mu.Unlock()
}

func (m *externalTransferMetrics) RecordDirectPathSend(n int64, at time.Time) {
	m.recordDirectPathBytes(n, at, true, "quic")
}

func (m *externalTransferMetrics) RecordDirectPathReceive(n int64, at time.Time) {
	m.recordDirectPathBytes(n, at, false, "quic")
}

func (m *externalTransferMetrics) RecordDirectPacketSend(n int64, at time.Time) {
	m.recordDirectPathBytes(n, at, true, "udp")
}

func (m *externalTransferMetrics) RecordDirectPacketReceive(n int64, at time.Time) {
	m.recordDirectPathBytes(n, at, false, "udp")
}

func (m *externalTransferMetrics) RecordStripedSendBlocked(d time.Duration, at time.Time) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	m.stripedSendBlocked += d
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordStripedReceiveBacklog(chunks int, bytes int64, at time.Time) {
	if m == nil {
		return
	}
	if chunks < 0 {
		chunks = 0
	}
	if bytes < 0 {
		bytes = 0
	}
	m.mu.Lock()
	m.stripedReceivePendingChunks = chunks
	m.stripedReceivePendingBytes = bytes
	if chunks > m.stripedReceivePendingChunksMax {
		m.stripedReceivePendingChunksMax = chunks
	}
	if bytes > m.stripedReceivePendingBytesMax {
		m.stripedReceivePendingBytesMax = bytes
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordPeerProgressFromFirstByte(bytesReceived int64, at time.Time) {
	if m == nil {
		return
	}
	at = nonZeroTime(at)
	m.mu.Lock()
	firstByteAt := m.firstByteAt
	m.mu.Unlock()
	transferElapsedMS := int64(0)
	if !firstByteAt.IsZero() && at.After(firstByteAt) {
		transferElapsedMS = at.Sub(firstByteAt).Milliseconds()
	}
	m.RecordPeerProgress(bytesReceived, transferElapsedMS, at)
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
	if m.deferSendComplete {
		trace, snap, ok := m.updateTraceLocked(at)
		m.mu.Unlock()
		sampleExternalTransferTrace(trace, snap, ok)
		return
	}
	m.phase = transfertrace.PhaseComplete
	m.lastState = string(StateComplete)
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	completeExternalTransferTrace(trace, snap, ok, at)
}

func (m *externalTransferMetrics) DeferSendCompleteUntilPeerAck() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.deferSendComplete = true
	m.mu.Unlock()
}

func (m *externalTransferMetrics) CompleteAfterPeerAck(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.deferSendComplete = false
	m.mu.Unlock()
	m.Complete(at)
}

func (m *externalTransferMetrics) SetTransportManager(manager *transport.Manager) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.transportManager = manager
	m.mu.Unlock()
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
	sampleExternalTransferTrace(trace, snap, ok)
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
	errorExternalTransferTrace(trace, snap, ok, err)
}

func (m *externalTransferMetrics) SetDirectPlan(selectedRate int, activeRate int, activeLanes int, availableLanes int) {
	m.SetDirectLimits(selectedRate, activeRate, 0, 0, activeLanes, availableLanes, 0, 0)
}

func (m *externalTransferMetrics) SetDirectLimits(selectedRate int, targetRate int, ceilingRate int, explorationCeiling int, activeLanes int, availableLanes int, laneMin int, laneCap int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.setDirectLimitsLocked(selectedRate, targetRate, ceilingRate, explorationCeiling, activeLanes, availableLanes, laneMin, laneCap)
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
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
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetDirectStats(stats externalDirectTransferStats) {
	m.setDirectStats(stats, true)
}

func (m *externalTransferMetrics) SetDirectStatsWithoutByteProgress(stats externalDirectTransferStats) {
	m.setDirectStats(stats, false)
}

func (m *externalTransferMetrics) SetDirectDiagnostics(
	diagnostics externalDirectTransferDiagnostics,
	at time.Time,
) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.setDirectDiagnosticsLocked(diagnostics)
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	recordExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) setDirectStats(stats externalDirectTransferStats, updateDirectBytes bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	diagnostics := m.diagnosticsForDirectStatsLocked(stats)
	if updateDirectBytes {
		if stats.BytesSent > m.directBytes {
			m.directBytes = stats.BytesSent
		}
		if stats.BytesReceived > m.directBytes {
			m.directBytes = stats.BytesReceived
		}
	}
	if m.directBytes > 0 && m.firstByteAt.IsZero() {
		m.firstByteAt = time.Now()
	}
	if stats.Retransmits > m.retransmitCount {
		m.retransmitCount = stats.Retransmits
	}
	m.replayWindowBytes = stats.MaxReplayBytes
	m.setDirectLocalSentLocked(stats, diagnostics)
	m.setDirectDiagnosticsLocked(diagnostics)
	trace, snap, ok := m.updateTraceLocked(time.Now())
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) Tick(at time.Time) {
	if m == nil || at.IsZero() {
		return
	}
	m.mu.Lock()
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	recordExternalTransferTrace(trace, snap, ok)
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

func withExternalTransferMetrics(ctx context.Context, metrics *externalTransferMetrics) context.Context {
	if metrics == nil {
		return ctx
	}
	return context.WithValue(ctx, externalTransferMetricsContextKey{}, metrics)
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
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) recordDirectPathBytes(n int64, at time.Time, send bool, transport string) {
	if m == nil || n <= 0 {
		return
	}
	at = nonZeroTime(at)
	m.mu.Lock()
	m.directTransport = transport
	if !m.directValidated {
		m.markDirectValidatedLocked()
	}
	m.directBytes += n
	m.directPacketBytes += n
	if send {
		m.localSentBytes += n
	} else {
		m.directCommittedBytes += n
	}
	if m.firstByteAt.IsZero() || at.Before(m.firstByteAt) {
		m.firstByteAt = at
	}
	trace, snap, ok := m.updateTraceLocked(at)
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) markDirectValidatedLocked() {
	m.directValidated = true
	if m.phase != transfertrace.PhaseComplete && m.phase != transfertrace.PhaseError {
		m.phase = transfertrace.PhaseDirectExecute
		m.lastState = string(StateDirect)
	}
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (m *externalTransferMetrics) updateTraceLocked(at time.Time) (*transfertrace.Recorder, transfertrace.Snapshot, bool) {
	if m.trace == nil || at.IsZero() {
		return nil, transfertrace.Snapshot{}, false
	}
	setupMS := int64(0)
	transferMS := m.receiverTransferMS
	if !m.transferStartedAt.IsZero() {
		setupMS = m.transferStartedAt.Sub(m.startedAt).Milliseconds()
		if setupMS < 0 {
			setupMS = 0
		}
		if transferMS == 0 && at.After(m.transferStartedAt) {
			transferMS = at.Sub(m.transferStartedAt).Milliseconds()
		}
	}
	peerRecvQueueDepth := 0
	peerRecvQueueDepthMax := 0
	if m.transportManager != nil {
		peerRecvQueueDepth = m.transportManager.CurrentPeerRecvQueueDepth()
		peerRecvQueueDepthMax = m.transportManager.MaxPeerRecvQueueDepth()
	}
	return m.trace, transfertrace.Snapshot{
		At:                         at,
		Phase:                      m.phase,
		RelayBytes:                 m.relayBytes,
		DirectBytes:                m.directBytes,
		AppBytes:                   m.appBytesLocked(),
		LocalSentBytes:             m.localSentBytes,
		PeerReceivedBytes:          m.peerReceivedBytes,
		SetupElapsedMS:             setupMS,
		TransferElapsedMS:          transferMS,
		DirectValidated:            m.directValidated,
		FallbackReason:             m.fallbackReason,
		DirectRateSelectedMbps:     m.directRateSelectedMbps,
		DirectRateActiveMbps:       m.directRateActiveMbps,
		DirectLanesActive:          m.directLanesActive,
		DirectLanesAvailable:       m.directLanesAvailable,
		RateTargetMbps:             m.rateTargetMbps,
		RateCeilingMbps:            m.rateCeilingMbps,
		RateExplorationCeilingMbps: m.rateExplorationCeiling,
		LaneMin:                    m.laneMin,
		LaneCap:                    m.laneCap,
		ControllerDecision:         m.controllerDecision,
		ControllerReason:           m.controllerReason,
		DirectProbeState:           m.directProbeState,
		DirectProbeSummary:         m.directProbeSummary,
		ReplayWindowBytes:          m.replayWindowBytes,
		ReplayBytes:                m.replayBytes,
		RepairQueueBytes:           m.repairQueueBytes,
		RetransmitCount:            m.retransmitCount,
		RepairRequests:             m.repairRequests,
		RepairBytes:                m.repairBytes,
		MissingScanChecks:          m.missingScanChecks,
		PendingMissing:             m.pendingMissing,
		PendingMissingPeak:         m.pendingMissingPeak,
		RepairRequestedPackets:     m.repairRequestedPackets,
		RepairRequestBatches:       m.repairRequestBatches,
		ReorderTrailPackets:        m.reorderTrailPackets,
		ReceivePacketRatePPS:       m.receivePacketRatePPS,
		LocalENOBUFSRetries:        m.localENOBUFSRetries,
		LocalENOBUFSWaitUS:         m.localENOBUFSWaitUS,
		LocalENOBUFSMaxConsecutive: m.localENOBUFSMaxConsecutive,
		OutOfOrderBytes:            m.outOfOrderBytes,

		StripedSendBlockedMS:           roundedUpMilliseconds(m.stripedSendBlocked),
		StripedReceivePendingChunks:    m.stripedReceivePendingChunks,
		StripedReceivePendingChunksMax: m.stripedReceivePendingChunksMax,
		StripedReceivePendingBytes:     m.stripedReceivePendingBytes,
		StripedReceivePendingBytesMax:  m.stripedReceivePendingBytesMax,

		DirectPacketBytes:       m.directPacketBytes,
		DirectCommittedBytes:    m.directCommittedBytes,
		DirectTransport:         m.directTransport,
		QUICHandshakeMS:         m.quicHandshakeMS,
		QUICFirstByteMS:         m.quicFirstByteMS,
		QUICStreamBytesSent:     m.quicStreamBytesSent,
		QUICStreamBytesReceived: m.quicStreamBytesRecv,
		QUICStreamGoodputMbps:   m.quicStreamGoodputMbps,
		QUICSmoothedRTTMS:       m.quicSmoothedRTTMS,
		QUICLossEvents:          m.quicLossEvents,
		QUICCloseReason:         m.quicCloseReason,
		PeerRecvQueueDepth:      peerRecvQueueDepth,
		PeerRecvQueueDepthMax:   peerRecvQueueDepthMax,
		LastState:               m.lastState,
		LastError:               m.lastError,
	}, true
}

func (m *externalTransferMetrics) setDirectLimitsLocked(selectedRate int, targetRate int, ceilingRate int, explorationCeiling int, activeLanes int, availableLanes int, laneMin int, laneCap int) {
	m.directRateSelectedMbps = selectedRate
	m.directRateSelectedPlan = selectedRate > 0
	m.directRateActiveMbps = targetRate
	m.directLanesActive = activeLanes
	m.directLanesAvailable = availableLanes
	if !m.rateTargetFromDirect {
		m.rateTargetMbps = targetRate
	}
	m.rateCeilingMbps = ceilingRate
	m.rateExplorationCeiling = explorationCeiling
	m.laneMin = laneMin
	m.laneCap = laneCap
}

func (m *externalTransferMetrics) diagnosticsForDirectStatsLocked(stats externalDirectTransferStats) externalDirectTransferDiagnostics {
	diagnostics := stats.Diagnostics
	if diagnostics.DirectPacketBytes <= 0 {
		diagnostics.DirectPacketBytes = stats.BytesSent
		if m.role == transfertrace.RoleReceive {
			diagnostics.DirectPacketBytes = stats.BytesReceived
		}
	}
	if m.role == transfertrace.RoleReceive && diagnostics.DirectCommittedBytes <= 0 {
		diagnostics.DirectCommittedBytes = stats.BytesReceived
	}
	return diagnostics
}

func (m *externalTransferMetrics) setDirectLocalSentLocked(stats externalDirectTransferStats, diagnostics externalDirectTransferDiagnostics) {
	if m.role != transfertrace.RoleSend {
		return
	}
	sent := stats.BytesSent
	if diagnostics.DirectPacketBytes > sent {
		sent = diagnostics.DirectPacketBytes
	}
	if sent > m.localSentBytes {
		m.localSentBytes = sent
	}
}

func (m *externalTransferMetrics) setDirectDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	m.setDirectRateDiagnosticsLocked(diagnostics)
	m.setDirectLaneDiagnosticsLocked(diagnostics)
	m.setDirectControllerDiagnosticsLocked(diagnostics)
	m.setDirectCounterDiagnosticsLocked(diagnostics)
}

func (m *externalTransferMetrics) setDirectRateDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.RateTargetMbps > 0 {
		m.rateTargetMbps = diagnostics.RateTargetMbps
		m.rateTargetFromDirect = true
		if m.directRateActiveMbps == 0 {
			m.directRateActiveMbps = diagnostics.RateTargetMbps
		}
	}
	if diagnostics.RateCeilingMbps > 0 {
		m.rateCeilingMbps = diagnostics.RateCeilingMbps
	}
	if diagnostics.RateExplorationCeilingMbps > 0 {
		m.rateExplorationCeiling = diagnostics.RateExplorationCeilingMbps
	}
	if diagnostics.RateSelectedMbps > 0 && !m.directRateSelectedPlan {
		m.directRateSelectedMbps = diagnostics.RateSelectedMbps
	}
}

func (m *externalTransferMetrics) setDirectLaneDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.ActiveLanes > 0 {
		m.directLanesActive = diagnostics.ActiveLanes
	}
	if diagnostics.AvailableLanes > m.directLanesAvailable {
		m.directLanesAvailable = diagnostics.AvailableLanes
	}
	if diagnostics.LaneMin > 0 {
		m.laneMin = diagnostics.LaneMin
	}
	if diagnostics.LaneCap > 0 {
		m.laneCap = diagnostics.LaneCap
	}
}

func (m *externalTransferMetrics) setDirectControllerDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.ControllerDecision != "" {
		m.controllerDecision = diagnostics.ControllerDecision
	}
	if diagnostics.ControllerReason != "" {
		m.controllerReason = diagnostics.ControllerReason
	}
}

func (m *externalTransferMetrics) setDirectCounterDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.ReplayBytes > m.replayBytes {
		m.replayBytes = diagnostics.ReplayBytes
	}
	if diagnostics.Retransmits > m.retransmitCount {
		m.retransmitCount = diagnostics.Retransmits
	}
	if diagnostics.RepairRequests > m.repairRequests {
		m.repairRequests = diagnostics.RepairRequests
	}
	if diagnostics.RepairBytes > m.repairBytes {
		m.repairBytes = diagnostics.RepairBytes
	}
	m.setRepairEfficiencyDiagnosticsLocked(diagnostics)
	m.setLocalENOBUFSDiagnosticsLocked(diagnostics)
	if diagnostics.DirectPacketBytes > m.directPacketBytes {
		m.directPacketBytes = diagnostics.DirectPacketBytes
	}
	if diagnostics.DirectCommittedBytes > m.directCommittedBytes {
		m.directCommittedBytes = diagnostics.DirectCommittedBytes
	}
	if diagnostics.ReceiverCommittedBytes > 0 &&
		uint64ToInt64Saturating(diagnostics.ReceiverCommittedBytes) > m.directCommittedBytes {
		m.directCommittedBytes = uint64ToInt64Saturating(diagnostics.ReceiverCommittedBytes)
	}
}

func (m *externalTransferMetrics) setRepairEfficiencyDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.MissingScanChecks > m.missingScanChecks {
		m.missingScanChecks = diagnostics.MissingScanChecks
	}
	m.pendingMissing = diagnostics.PendingMissing
	if diagnostics.PendingMissingPeak > m.pendingMissingPeak {
		m.pendingMissingPeak = diagnostics.PendingMissingPeak
	}
	if diagnostics.RepairRequestedPackets > m.repairRequestedPackets {
		m.repairRequestedPackets = diagnostics.RepairRequestedPackets
	}
	if diagnostics.RepairRequestBatches > m.repairRequestBatches {
		m.repairRequestBatches = diagnostics.RepairRequestBatches
	}
	if diagnostics.ReorderTrailPackets > m.reorderTrailPackets {
		m.reorderTrailPackets = diagnostics.ReorderTrailPackets
	}
	if diagnostics.ReceivePacketRatePPS > m.receivePacketRatePPS {
		m.receivePacketRatePPS = diagnostics.ReceivePacketRatePPS
	}
}

func (m *externalTransferMetrics) setLocalENOBUFSDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if diagnostics.LocalENOBUFSRetries > m.localENOBUFSRetries {
		m.localENOBUFSRetries = diagnostics.LocalENOBUFSRetries
	}
	if diagnostics.LocalENOBUFSWaitUS > m.localENOBUFSWaitUS {
		m.localENOBUFSWaitUS = diagnostics.LocalENOBUFSWaitUS
	}
	if diagnostics.LocalENOBUFSMaxConsecutive > m.localENOBUFSMaxConsecutive {
		m.localENOBUFSMaxConsecutive = diagnostics.LocalENOBUFSMaxConsecutive
	}
}

func uint64ToInt64Saturating(value uint64) int64 {
	const maxInt64AsUint64 = uint64(^uint64(0) >> 1)
	if value > maxInt64AsUint64 {
		return int64(maxInt64AsUint64)
	}
	return int64(value)
}

func (m *externalTransferMetrics) appBytesLocked() int64 {
	if m.role == transfertrace.RoleSend {
		if m.peerProgressSet {
			return m.peerReceivedBytes
		}
		if m.directTransport == "quic" {
			return m.localSentBytes
		}
		return 0
	}
	if !m.directAppProgressSet {
		return m.relayBytes + m.directBytes
	}
	directProgress := m.directBytes
	if m.directBytes > 0 || m.phase == transfertrace.PhaseComplete {
		directProgress += m.directAppProgressBase
	}
	if directProgress > m.relayBytes {
		return directProgress
	}
	return m.relayBytes
}

func nonZeroTime(at time.Time) time.Time {
	if at.IsZero() {
		return time.Now()
	}
	return at
}

func roundedUpMilliseconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	ms := d / time.Millisecond
	if d%time.Millisecond != 0 {
		ms++
	}
	return int64(ms)
}

func sampleExternalTransferTrace(trace *transfertrace.Recorder, snap transfertrace.Snapshot, ok bool) {
	if !ok {
		return
	}
	trace.Update(func(current *transfertrace.Snapshot) {
		*current = snap
	})
}

func recordExternalTransferTrace(trace *transfertrace.Recorder, snap transfertrace.Snapshot, ok bool) {
	if !ok {
		return
	}
	trace.Observe(snap)
}

func completeExternalTransferTrace(trace *transfertrace.Recorder, snap transfertrace.Snapshot, ok bool, at time.Time) {
	if !ok {
		return
	}
	sampleExternalTransferTrace(trace, snap, ok)
	trace.Complete(at)
}

func errorExternalTransferTrace(trace *transfertrace.Recorder, snap transfertrace.Snapshot, ok bool, err error) {
	if !ok {
		return
	}
	sampleExternalTransferTrace(trace, snap, ok)
	trace.Error(snap.At, err.Error())
}
