// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
)

type externalTransferMetrics struct {
	mu                             sync.Mutex
	startedAt                      time.Time
	completedAt                    time.Time
	firstByteAt                    time.Time
	relayBytes                     int64
	directBytes                    int64
	localSentBytes                 int64
	peerReceivedBytes              int64
	peerProgressSet                bool
	transferStartedAt              time.Time
	receiverTransferMS             int64
	directValidated                bool
	fallbackReason                 string
	transportPath                  transport.Path
	transportSelectedAddr          string
	transportPreviousAddr          string
	transportReason                string
	transportSource                string
	transportRTTMS                 int64
	directAppProgressBase          int64
	directAppProgressSet           bool
	trace                          *transfertrace.Recorder
	role                           transfertrace.Role
	phase                          transfertrace.Phase
	lastState                      string
	lastError                      string
	deferSendComplete              bool
	directRateSelectedMbps         int
	directRateSelectedPlan         bool
	directRateActiveMbps           int
	directLanesActive              int
	directLanesAvailable           int
	rateTargetMbps                 int
	rateTargetFromDirect           bool
	rateCeilingMbps                int
	rateExplorationCeiling         int
	laneMin                        int
	laneCap                        int
	controllerDecision             string
	controllerReason               string
	directProbeState               string
	directProbeSummary             string
	replayWindowBytes              uint64
	replayBytes                    uint64
	repairQueueBytes               uint64
	retransmitCount                int64
	repairRequests                 int64
	repairBytes                    int64
	missingScanChecks              uint64
	pendingMissing                 uint32
	pendingMissingPeak             uint32
	repairRequestedPackets         uint64
	repairRequestBatches           uint64
	reorderTrailPackets            uint32
	receivePacketRatePPS           uint32
	bulkBatchPresent               bool
	bulkBatchBackend               string
	bulkCandidateID                string
	bulkNativeSendAttempts         uint64
	bulkNativeSendSyscalls         uint64
	bulkNativeGSOMessages          uint64
	bulkLogicalDatagrams           uint64
	bulkNativeAcceptedPayloadBytes uint64
	bulkGSOSegmentsPerMessage      uint32
	bulkGSOAttempted               bool
	bulkGSOActive                  bool
	bulkGSOSegments                uint64
	bulkSendCalls                  uint64
	bulkSendDatagrams              uint64
	bulkReceiveCalls               uint64
	bulkReceiveDatagrams           uint64
	bulkMaxSendBatch               uint32
	bulkMaxReceiveBatch            uint32
	bulkCryptoQueuePeak            uint32
	bulkLaneQueuePeak              uint32
	bulkReceiveQueuePeak           uint32
	bulkWriterQueuePeak            uint32
	bulkDecryptBatches             uint64
	bulkDecryptDatagrams           uint64
	bulkProbeSelectedMbps          int
	bulkProbeDurationMS            int64
	bulkProbeTrains                uint32
	bulkProbeSentDatagrams         uint64
	bulkProbeReceivedDatagrams     uint64
	bulkProbeLossPPM               uint64
	bulkProbePressure              bool
	bulkProbeStopReason            string
	bulkProbeRejectStage           string
	bulkProbeRejectTrain           int
	bulkProbeRejectRateMbps        int
	bulkHandoffLanes               int
	bulkHandoffDrainedDatagrams    uint64
	bulkHandoffDrainDurationMS     int64
	bulkDecisionMode               string
	bulkDecisionReason             string
	bulkDecisionRunID              uint64
	filePayloadEngine              transfertrace.FilePayloadEngine
	filePayloadBytesCommitted      int64
	filePayloadBytesBulk           int64
	filePayloadBytesQUIC           int64
	filePayloadLaneAddresses       string
	fileSourceReadCalls            uint64
	fileSourceReadBytes            uint64

	localENOBUFSRetries        int64
	localENOBUFSWaitUS         int64
	localENOBUFSMaxConsecutive int64

	outOfOrderBytes          uint64
	directPacketBytes        int64
	directCommittedBytes     int64
	directTransport          string
	directStreamTransport    string
	quicTelemetryPresent     bool
	quicConnections          uint32
	quicStreams              uint32
	quicVersion              string
	quicRawSocketBackend     string
	quicNativeSendBackend    string
	quicNativeReceiveBackend string
	quicHandshakeMS          int64
	quicFirstByteMS          int64
	quicSmoothedRTTMS        string
	quicPacketsSent          uint64
	quicPacketsReceived      uint64
	quicPacketsLost          uint64
	quicWireBytesSent        uint64
	quicRecoveryWireBytes    uint64
	quicRecoveryRatio        string
	quicStreamBytesSent      int64
	quicStreamBytesRecv      int64
	quicStreamGoodputMbps    string
	quicCloseReason          string
	quicNativeGSO            string
	quicNativeReceiveBatch   string
	transportManager         *transport.Manager

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
	RateTargetMbps                 int
	RateCeilingMbps                int
	RateExplorationCeilingMbps     int
	RateSelectedMbps               int
	ActiveLanes                    int
	AvailableLanes                 int
	LaneMin                        int
	LaneCap                        int
	ControllerDecision             string
	ControllerReason               string
	ReplayBytes                    uint64
	Retransmits                    int64
	RepairRequests                 int64
	RepairBytes                    int64
	LocalENOBUFSRetries            int64
	LocalENOBUFSWaitUS             int64
	LocalENOBUFSMaxConsecutive     int64
	DirectPacketBytes              int64
	DirectCommittedBytes           int64
	ReceiverCommittedBytes         uint64
	MissingScanChecks              uint64
	PendingMissing                 uint32
	PendingMissingPeak             uint32
	RepairRequestedPackets         uint64
	RepairRequestBatches           uint64
	ReorderTrailPackets            uint32
	ReceivePacketRatePPS           uint32
	BulkBatchPresent               bool
	BulkBatchBackend               string
	BulkCandidateID                string
	BulkNativeSendAttempts         uint64
	BulkNativeSendSyscalls         uint64
	BulkNativeGSOMessages          uint64
	BulkLogicalDatagrams           uint64
	BulkNativeAcceptedPayloadBytes uint64
	BulkGSOSegmentsPerMessage      uint32
	BulkGSOAttempted               bool
	BulkGSOActive                  bool
	BulkGSOSegments                uint64
	BulkSendCalls                  uint64
	BulkSendDatagrams              uint64
	BulkReceiveCalls               uint64
	BulkReceiveDatagrams           uint64
	BulkMaxSendBatch               uint32
	BulkMaxReceiveBatch            uint32
	BulkCryptoQueuePeak            uint32
	BulkLaneQueuePeak              uint32
	BulkReceiveQueuePeak           uint32
	BulkWriterQueuePeak            uint32
	BulkDecryptBatches             uint64
	BulkDecryptDatagrams           uint64
	BulkProbeSelectedMbps          int
	BulkProbeDurationMS            int64
	BulkProbeTrains                uint32
	BulkProbeSentDatagrams         uint64
	BulkProbeReceivedDatagrams     uint64
	BulkProbeLossPPM               uint64
	BulkProbePressure              bool
	BulkProbeStopReason            string
	BulkProbeRejectStage           string
	BulkProbeRejectTrain           int
	BulkProbeRejectRateMbps        int
	BulkHandoffLanes               int
	BulkHandoffDrainedDatagrams    uint64
	BulkHandoffDrainDurationMS     int64
}

type externalV2BulkPacketFallbackDiagnostics struct {
	RejectStage      string
	RejectTrain      int
	RejectRateMbps   int
	HandoffLanes     int
	DrainedDatagrams uint64
	DrainDurationMS  int64
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

func (m *externalTransferMetrics) SelectFilePayloadEngine(engine transfertrace.FilePayloadEngine, at time.Time) {
	if m == nil || !engine.Valid() {
		return
	}
	m.mu.Lock()
	if m.filePayloadBytesCommitted == 0 || m.filePayloadEngine == engine {
		m.filePayloadEngine = engine
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetBulkDecision(decision externalV2BulkDecision, at time.Time) {
	if m == nil || decision.ProbeRunID == 0 {
		return
	}
	m.mu.Lock()
	if m.bulkDecisionRunID == 0 {
		m.bulkDecisionMode = decision.Mode
		m.bulkDecisionReason = decision.Reason
		m.bulkDecisionRunID = decision.ProbeRunID
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) SetFilePayloadLaneAddrs(addrs []net.Addr, at time.Time) error {
	if m == nil {
		return nil
	}
	if len(addrs) == 0 {
		return fmt.Errorf("file payload lane addresses are empty")
	}
	lanes := make([]string, 0, len(addrs))
	seen := make(map[netip.AddrPort]struct{}, len(addrs))
	for _, addr := range addrs {
		if addr == nil {
			return fmt.Errorf("file payload lane address is nil")
		}
		lane, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return fmt.Errorf("parse file payload lane address %q: %w", addr.String(), err)
		}
		lane = netip.AddrPortFrom(lane.Addr().Unmap(), lane.Port())
		if _, duplicate := seen[lane]; duplicate {
			return fmt.Errorf("duplicate file payload lane address %q", addr.String())
		}
		seen[lane] = struct{}{}
		lanes = append(lanes, lane.String())
	}
	encoded, err := json.Marshal(lanes)
	if err != nil {
		return fmt.Errorf("encode file payload lane addresses: %w", err)
	}
	m.mu.Lock()
	m.filePayloadLaneAddresses = string(encoded)
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
	return nil
}

func (m *externalTransferMetrics) RecordFilePayloadCommit(engine transfertrace.FilePayloadEngine, n int64, at time.Time) {
	if m == nil || m.role != transfertrace.RoleReceive || !engine.Valid() || n <= 0 {
		return
	}
	m.mu.Lock()
	if m.filePayloadEngine != engine {
		m.mu.Unlock()
		return
	}
	m.filePayloadBytesCommitted += n
	if engine == transfertrace.FilePayloadEngineBulk {
		m.filePayloadBytesBulk += n
	} else {
		m.filePayloadBytesQUIC += n
	}
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordFileSourceRead(n int, at time.Time) {
	if m == nil || n < 0 {
		return
	}
	m.mu.Lock()
	m.fileSourceReadCalls++
	m.fileSourceReadBytes += uint64(n)
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

func (m *externalTransferMetrics) RecordQUICEvidence(stats dataplane.Stats, _ int, _ bool, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.directTransport = "quic"
	if stats.TelemetryPresent {
		m.quicTelemetryPresent = true
	}
	m.quicConnections = max(m.quicConnections, stats.Connections)
	m.quicStreams = max(m.quicStreams, stats.Streams)
	setNonEmptyString(&m.quicVersion, stats.Version)
	setNonEmptyString(&m.quicRawSocketBackend, stats.RawSocketBackend)
	setNonEmptyString(&m.quicNativeSendBackend, stats.NativeSendBackend)
	setNonEmptyString(&m.quicNativeReceiveBackend, stats.NativeReceiveBackend)
	m.quicHandshakeMS = max(m.quicHandshakeMS, max(stats.HandshakeMS, formatQUICDurationMS(stats.HandshakeDuration)))
	m.quicFirstByteMS = max(m.quicFirstByteMS, max(stats.FirstByteMS, formatQUICDurationMS(stats.FirstByteDuration)))
	if stats.SmoothedRTT > 0 {
		m.quicSmoothedRTTMS = strings.TrimRight(strings.TrimRight(strconv.FormatFloat(float64(stats.SmoothedRTT)/float64(time.Millisecond), 'f', 3, 64), "0"), ".")
	}
	m.quicPacketsSent = max(m.quicPacketsSent, stats.PacketsSent)
	m.quicPacketsReceived = max(m.quicPacketsReceived, stats.PacketsReceived)
	m.quicPacketsLost = max(m.quicPacketsLost, stats.PacketsLost)
	m.quicWireBytesSent = max(m.quicWireBytesSent, stats.WireBytesSent)
	m.quicRecoveryWireBytes = max(m.quicRecoveryWireBytes, stats.RecoveryWireBytes)
	m.quicRecoveryRatio = formatQUICRecoveryRatio(m.quicRecoveryWireBytes, m.quicWireBytesSent)
	m.quicStreamBytesSent = max(m.quicStreamBytesSent, uint64ToInt64Saturating(stats.StreamBytesSent))
	m.quicStreamBytesRecv = max(m.quicStreamBytesRecv, uint64ToInt64Saturating(stats.StreamBytesReceived))
	setNonEmptyString(&m.quicCloseReason, stats.CloseReason)
	setNonEmptyString(&m.quicNativeGSO, stats.NativeGSO)
	setNonEmptyString(&m.quicNativeReceiveBatch, stats.NativeReceiveBatch)
	trace, snap, ok := m.updateTraceLocked(nonZeroTime(at))
	m.mu.Unlock()
	sampleExternalTransferTrace(trace, snap, ok)
}

type externalV2FileSourceReadMetrics struct {
	reader  io.ReaderAt
	metrics *externalTransferMetrics
}

func (r *externalV2FileSourceReadMetrics) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.reader.ReadAt(p, off)
	r.metrics.RecordFileSourceRead(n, time.Now())
	return n, err
}

func withExternalV2FileSourceReadMetrics(source *BlockSource, metrics *externalTransferMetrics) *BlockSource {
	if source == nil || source.Payload == nil || metrics == nil {
		return source
	}
	if wrapped, ok := source.Payload.(*externalV2FileSourceReadMetrics); ok && wrapped.metrics == metrics {
		return source
	}
	wrapped := *source
	wrapped.Payload = &externalV2FileSourceReadMetrics{reader: source.Payload, metrics: metrics}
	return &wrapped
}

func closeExternalV2QUICEndpoint(endpoint externalV2QUICEndpoint, metrics *externalTransferMetrics, streamCount int, rawDirect bool, code uint64, reason string) error {
	metrics.recordSelectedManagerFilePayloadLane(time.Now())
	stats := endpoint.Stats()
	if stats.CloseReason == "" {
		stats.CloseReason = reason
	}
	metrics.RecordQUICEvidence(stats, streamCount, rawDirect, time.Now())
	return endpoint.CloseWithError(code, reason)
}

func recordExternalV2OpenQUICPayloadLanes(endpoint externalV2QUICEndpoint, metrics *externalTransferMetrics, streamCount int, addrs []net.Addr, at time.Time) error {
	laneErr := metrics.SetFilePayloadLaneAddrs(addrs, at)
	if laneErr == nil {
		return nil
	}
	closeErr := closeExternalV2QUICEndpoint(endpoint, metrics, streamCount, true, 1, laneErr.Error())
	if closeErr == nil {
		return laneErr
	}
	return errors.Join(laneErr, fmt.Errorf("close QUIC endpoint after lane telemetry failure: %w", closeErr))
}

func (m *externalTransferMetrics) recordSelectedManagerFilePayloadLane(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	manager := m.transportManager
	hasLanes := m.filePayloadLaneAddresses != ""
	m.mu.Unlock()
	if hasLanes || manager == nil {
		return
	}
	if selected := manager.PathSnapshot().SelectedAddr; selected != nil {
		_ = m.SetFilePayloadLaneAddrs([]net.Addr{selected}, at)
	}
}

func formatQUICDurationMS(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	return max(int64(1), duration.Milliseconds())
}

func formatQUICRecoveryRatio(recoveryWireBytes, wireBytesSent uint64) string {
	if recoveryWireBytes == 0 {
		return "0"
	}
	originalWireBytes := wireBytesSent - min(wireBytesSent, recoveryWireBytes)
	ratio := float64(recoveryWireBytes) / float64(max(uint64(1), originalWireBytes))
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(ratio, 'f', 6, 64), "0"), ".")
}

func setNonEmptyString(dst *string, value string) {
	if value != "" {
		*dst = value
	}
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

func (m *externalTransferMetrics) SetDirectStreamTransport(transport string) {
	if m == nil || transport == "" {
		return
	}
	m.mu.Lock()
	m.directStreamTransport = transport
	m.mu.Unlock()
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

func (m *externalTransferMetrics) BulkPacketFallbackDiagnostics() externalV2BulkPacketFallbackDiagnostics {
	if m == nil {
		return externalV2BulkPacketFallbackDiagnostics{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return externalV2BulkPacketFallbackDiagnostics{
		RejectStage:      m.bulkProbeRejectStage,
		RejectTrain:      m.bulkProbeRejectTrain,
		RejectRateMbps:   m.bulkProbeRejectRateMbps,
		HandoffLanes:     m.bulkHandoffLanes,
		DrainedDatagrams: m.bulkHandoffDrainedDatagrams,
		DrainDurationMS:  m.bulkHandoffDrainDurationMS,
	}
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
	if transport == "quic" && m.directStreamTransport != "" {
		transport = m.directStreamTransport
	}
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
		At:                             at,
		Phase:                          m.phase,
		RelayBytes:                     m.relayBytes,
		DirectBytes:                    m.directBytes,
		AppBytes:                       m.appBytesLocked(),
		LocalSentBytes:                 m.localSentBytes,
		PeerReceivedBytes:              m.peerReceivedBytes,
		SetupElapsedMS:                 setupMS,
		TransferElapsedMS:              transferMS,
		DirectValidated:                m.directValidated,
		FallbackReason:                 m.fallbackReason,
		DirectRateSelectedMbps:         m.directRateSelectedMbps,
		DirectRateActiveMbps:           m.directRateActiveMbps,
		DirectLanesActive:              m.directLanesActive,
		DirectLanesAvailable:           m.directLanesAvailable,
		RateTargetMbps:                 m.rateTargetMbps,
		RateCeilingMbps:                m.rateCeilingMbps,
		RateExplorationCeilingMbps:     m.rateExplorationCeiling,
		LaneMin:                        m.laneMin,
		LaneCap:                        m.laneCap,
		ControllerDecision:             m.controllerDecision,
		ControllerReason:               m.controllerReason,
		DirectProbeState:               m.directProbeState,
		DirectProbeSummary:             m.directProbeSummary,
		ReplayWindowBytes:              m.replayWindowBytes,
		ReplayBytes:                    m.replayBytes,
		RepairQueueBytes:               m.repairQueueBytes,
		RetransmitCount:                m.retransmitCount,
		RepairRequests:                 m.repairRequests,
		RepairBytes:                    m.repairBytes,
		MissingScanChecks:              m.missingScanChecks,
		PendingMissing:                 m.pendingMissing,
		PendingMissingPeak:             m.pendingMissingPeak,
		RepairRequestedPackets:         m.repairRequestedPackets,
		RepairRequestBatches:           m.repairRequestBatches,
		ReorderTrailPackets:            m.reorderTrailPackets,
		ReceivePacketRatePPS:           m.receivePacketRatePPS,
		FilePayloadEngine:              m.filePayloadEngine,
		FilePayloadBytesCommitted:      m.filePayloadBytesCommitted,
		FilePayloadBytesBulk:           m.filePayloadBytesBulk,
		FilePayloadBytesQUIC:           m.filePayloadBytesQUIC,
		FilePayloadLaneAddresses:       m.filePayloadLaneAddresses,
		FileSourceReadCalls:            m.fileSourceReadCalls,
		FileSourceReadBytes:            m.fileSourceReadBytes,
		BulkBatchPresent:               m.bulkBatchPresent,
		BulkBatchBackend:               m.bulkBatchBackend,
		BulkCandidateID:                m.bulkCandidateID,
		BulkNativeSendAttempts:         m.bulkNativeSendAttempts,
		BulkNativeSendSyscalls:         m.bulkNativeSendSyscalls,
		BulkNativeGSOMessages:          m.bulkNativeGSOMessages,
		BulkLogicalDatagrams:           m.bulkLogicalDatagrams,
		BulkNativeAcceptedPayloadBytes: m.bulkNativeAcceptedPayloadBytes,
		BulkGSOSegmentsPerMessage:      m.bulkGSOSegmentsPerMessage,
		BulkGSOAttempted:               m.bulkGSOAttempted,
		BulkGSOActive:                  m.bulkGSOActive,
		BulkGSOSegments:                m.bulkGSOSegments,
		BulkSendCalls:                  m.bulkSendCalls,
		BulkSendDatagrams:              m.bulkSendDatagrams,
		BulkReceiveCalls:               m.bulkReceiveCalls,
		BulkReceiveDatagrams:           m.bulkReceiveDatagrams,
		BulkMaxSendBatch:               m.bulkMaxSendBatch,
		BulkMaxReceiveBatch:            m.bulkMaxReceiveBatch,
		BulkCryptoQueuePeak:            m.bulkCryptoQueuePeak,
		BulkLaneQueuePeak:              m.bulkLaneQueuePeak,
		BulkReceiveQueuePeak:           m.bulkReceiveQueuePeak,
		BulkWriterQueuePeak:            m.bulkWriterQueuePeak,
		BulkDecryptBatches:             m.bulkDecryptBatches,
		BulkDecryptDatagrams:           m.bulkDecryptDatagrams,
		BulkProbeSelectedMbps:          m.bulkProbeSelectedMbps,
		BulkProbeDurationMS:            m.bulkProbeDurationMS,
		BulkProbeTrains:                m.bulkProbeTrains,
		BulkProbeSentDatagrams:         m.bulkProbeSentDatagrams,
		BulkProbeReceivedDatagrams:     m.bulkProbeReceivedDatagrams,
		BulkProbeLossPPM:               m.bulkProbeLossPPM,
		BulkProbePressure:              m.bulkProbePressure,
		BulkProbeStopReason:            m.bulkProbeStopReason,
		BulkProbeRejectStage:           m.bulkProbeRejectStage,
		BulkHandoffDrainedDatagrams:    m.bulkHandoffDrainedDatagrams,
		BulkHandoffDrainDurationMS:     m.bulkHandoffDrainDurationMS,
		BulkDecisionMode:               m.bulkDecisionMode,
		BulkDecisionReason:             m.bulkDecisionReason,
		BulkDecisionRunID:              m.bulkDecisionRunID,
		LocalENOBUFSRetries:            m.localENOBUFSRetries,
		LocalENOBUFSWaitUS:             m.localENOBUFSWaitUS,
		LocalENOBUFSMaxConsecutive:     m.localENOBUFSMaxConsecutive,
		OutOfOrderBytes:                m.outOfOrderBytes,

		StripedSendBlockedMS:           roundedUpMilliseconds(m.stripedSendBlocked),
		StripedReceivePendingChunks:    m.stripedReceivePendingChunks,
		StripedReceivePendingChunksMax: m.stripedReceivePendingChunksMax,
		StripedReceivePendingBytes:     m.stripedReceivePendingBytes,
		StripedReceivePendingBytesMax:  m.stripedReceivePendingBytesMax,

		DirectPacketBytes:        m.directPacketBytes,
		DirectCommittedBytes:     m.directCommittedBytes,
		DirectTransport:          m.directTransport,
		QUICTelemetryPresent:     m.quicTelemetryPresent,
		QUICConnections:          m.quicConnections,
		QUICStreams:              m.quicStreams,
		QUICVersion:              m.quicVersion,
		QUICRawSocketBackend:     m.quicRawSocketBackend,
		QUICNativeSendBackend:    m.quicNativeSendBackend,
		QUICNativeReceiveBackend: m.quicNativeReceiveBackend,
		QUICHandshakeMS:          m.quicHandshakeMS,
		QUICFirstByteMS:          m.quicFirstByteMS,
		QUICSmoothedRTTMS:        m.quicSmoothedRTTMS,
		QUICPacketsSent:          m.quicPacketsSent,
		QUICPacketsReceived:      m.quicPacketsReceived,
		QUICPacketsLost:          m.quicPacketsLost,
		QUICWireBytesSent:        m.quicWireBytesSent,
		QUICRecoveryWireBytes:    m.quicRecoveryWireBytes,
		QUICRecoveryRatio:        m.quicRecoveryRatio,
		QUICStreamBytesSent:      m.quicStreamBytesSent,
		QUICStreamBytesReceived:  m.quicStreamBytesRecv,
		QUICStreamGoodputMbps:    m.quicStreamGoodputMbps,
		QUICCloseReason:          m.quicCloseReason,
		QUICNativeGSO:            m.quicNativeGSO,
		QUICNativeReceiveBatch:   m.quicNativeReceiveBatch,
		PeerRecvQueueDepth:       peerRecvQueueDepth,
		PeerRecvQueueDepthMax:    peerRecvQueueDepthMax,
		LastState:                m.lastState,
		LastError:                m.lastError,
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
	m.setBulkPacketFallbackDiagnosticsLocked(diagnostics)
	m.setBulkBatchDiagnosticsLocked(diagnostics)
}

func (m *externalTransferMetrics) setBulkPacketFallbackDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if m.bulkProbeRejectStage == "" && diagnostics.BulkProbeRejectStage != "" {
		m.bulkProbeRejectStage = diagnostics.BulkProbeRejectStage
		m.bulkProbeRejectTrain = diagnostics.BulkProbeRejectTrain
		m.bulkProbeRejectRateMbps = diagnostics.BulkProbeRejectRateMbps
	}
	m.bulkHandoffLanes = max(m.bulkHandoffLanes, diagnostics.BulkHandoffLanes)
	m.bulkHandoffDrainedDatagrams = max(m.bulkHandoffDrainedDatagrams, diagnostics.BulkHandoffDrainedDatagrams)
	m.bulkHandoffDrainDurationMS = max(m.bulkHandoffDrainDurationMS, diagnostics.BulkHandoffDrainDurationMS)
}

func (m *externalTransferMetrics) setBulkBatchDiagnosticsLocked(diagnostics externalDirectTransferDiagnostics) {
	if !diagnostics.BulkBatchPresent {
		return
	}
	m.bulkBatchPresent = true
	if diagnostics.BulkBatchBackend != "" {
		m.bulkBatchBackend = diagnostics.BulkBatchBackend
	}
	m.bulkCandidateID = diagnostics.BulkCandidateID
	m.bulkNativeSendAttempts = max(m.bulkNativeSendAttempts, diagnostics.BulkNativeSendAttempts)
	m.bulkNativeSendSyscalls = max(m.bulkNativeSendSyscalls, diagnostics.BulkNativeSendSyscalls)
	m.bulkNativeGSOMessages = max(m.bulkNativeGSOMessages, diagnostics.BulkNativeGSOMessages)
	m.bulkLogicalDatagrams = max(m.bulkLogicalDatagrams, diagnostics.BulkLogicalDatagrams)
	m.bulkNativeAcceptedPayloadBytes = max(m.bulkNativeAcceptedPayloadBytes, diagnostics.BulkNativeAcceptedPayloadBytes)
	m.bulkGSOSegmentsPerMessage = max(m.bulkGSOSegmentsPerMessage, diagnostics.BulkGSOSegmentsPerMessage)
	m.bulkGSOAttempted = m.bulkGSOAttempted || diagnostics.BulkGSOAttempted
	m.bulkGSOActive = m.bulkGSOActive || diagnostics.BulkGSOActive
	m.bulkGSOSegments = max(m.bulkGSOSegments, diagnostics.BulkGSOSegments)
	m.bulkSendCalls = max(m.bulkSendCalls, diagnostics.BulkSendCalls)
	m.bulkSendDatagrams = max(m.bulkSendDatagrams, diagnostics.BulkSendDatagrams)
	m.bulkReceiveCalls = max(m.bulkReceiveCalls, diagnostics.BulkReceiveCalls)
	m.bulkReceiveDatagrams = max(m.bulkReceiveDatagrams, diagnostics.BulkReceiveDatagrams)
	m.bulkMaxSendBatch = max(m.bulkMaxSendBatch, diagnostics.BulkMaxSendBatch)
	m.bulkMaxReceiveBatch = max(m.bulkMaxReceiveBatch, diagnostics.BulkMaxReceiveBatch)
	m.bulkCryptoQueuePeak = max(m.bulkCryptoQueuePeak, diagnostics.BulkCryptoQueuePeak)
	m.bulkLaneQueuePeak = max(m.bulkLaneQueuePeak, diagnostics.BulkLaneQueuePeak)
	m.bulkReceiveQueuePeak = max(m.bulkReceiveQueuePeak, diagnostics.BulkReceiveQueuePeak)
	m.bulkWriterQueuePeak = max(m.bulkWriterQueuePeak, diagnostics.BulkWriterQueuePeak)
	m.bulkDecryptBatches = max(m.bulkDecryptBatches, diagnostics.BulkDecryptBatches)
	m.bulkDecryptDatagrams = max(m.bulkDecryptDatagrams, diagnostics.BulkDecryptDatagrams)
	if diagnostics.BulkProbeSelectedMbps > 0 {
		m.bulkProbeSelectedMbps = diagnostics.BulkProbeSelectedMbps
	}
	if diagnostics.BulkProbeDurationMS > 0 {
		m.bulkProbeDurationMS = diagnostics.BulkProbeDurationMS
	}
	m.bulkProbeTrains = max(m.bulkProbeTrains, diagnostics.BulkProbeTrains)
	m.bulkProbeSentDatagrams = max(m.bulkProbeSentDatagrams, diagnostics.BulkProbeSentDatagrams)
	m.bulkProbeReceivedDatagrams = max(m.bulkProbeReceivedDatagrams, diagnostics.BulkProbeReceivedDatagrams)
	m.bulkProbeLossPPM = max(m.bulkProbeLossPPM, diagnostics.BulkProbeLossPPM)
	m.bulkProbePressure = m.bulkProbePressure || diagnostics.BulkProbePressure
	if m.bulkProbeStopReason == "" && diagnostics.BulkProbeStopReason != "" {
		m.bulkProbeStopReason = diagnostics.BulkProbeStopReason
	}
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
