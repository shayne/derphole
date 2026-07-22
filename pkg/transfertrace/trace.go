// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleSend    Role = "send"
	RoleReceive Role = "receive"
)

type FilePayloadEngine string

const (
	FilePayloadEngineBulk FilePayloadEngine = "bulk-packets-v1"
	FilePayloadEngineQUIC FilePayloadEngine = "quic-blocks-v1"
)

func (e FilePayloadEngine) Valid() bool {
	return e == FilePayloadEngineBulk || e == FilePayloadEngineQUIC
}

func ParseFilePayloadEngine(value string) (FilePayloadEngine, error) {
	engine := FilePayloadEngine(value)
	if !engine.Valid() {
		return "", fmt.Errorf("invalid file payload engine %q", value)
	}
	return engine, nil
}

type Phase string

const (
	PhaseClaim         Phase = "claim"
	PhaseRelay         Phase = "relay"
	PhaseDirectPrepare Phase = "direct_prepare"
	PhaseDirectProbe   Phase = "direct_probe"
	PhaseDirectExecute Phase = "direct_execute"
	PhaseOverlap       Phase = "overlap"
	PhaseComplete      Phase = "complete"
	PhaseError         Phase = "error"
)

var header = [...]string{
	"timestamp_unix_ms",
	"elapsed_ms",
	"role",
	"phase",
	"relay_bytes",
	"direct_bytes",
	"app_bytes",
	"delta_app_bytes",
	"app_mbps",
	"local_sent_bytes",
	"peer_received_bytes",
	"setup_elapsed_ms",
	"transfer_elapsed_ms",
	"direct_validated",
	"fallback_reason",
	"direct_rate_selected_mbps",
	"direct_rate_active_mbps",
	"direct_lanes_active",
	"direct_lanes_available",
	"direct_probe_state",
	"direct_probe_summary",
	"replay_window_bytes",
	"repair_queue_bytes",
	"retransmit_count",
	"out_of_order_bytes",
	"last_state",
	"last_error",
	"rate_target_mbps",
	"rate_ceiling_mbps",
	"rate_exploration_ceiling_mbps",
	"rate_selected_mbps",
	"active_lanes",
	"available_lanes",
	"lane_min",
	"lane_cap",
	"controller_decision",
	"controller_reason",
	"send_goodput_mbps",
	"receive_goodput_mbps",
	"receiver_committed_mbps",
	"replay_bytes",
	"retransmits",
	"repair_requests",
	"repair_bytes",
	"local_enobufs_retries",
	"local_enobufs_wait_us",
	"local_enobufs_max_consecutive",
	"peer_recv_queue_depth",
	"peer_recv_queue_depth_max",
	"striped_send_blocked_ms",
	"striped_receive_pending_chunks",
	"striped_receive_pending_chunks_max",
	"striped_receive_pending_bytes",
	"striped_receive_pending_bytes_max",
	"direct_packet_bytes",
	"direct_committed_bytes",
	"direct_transport",
	"quic_connections",
	"quic_streams",
	"quic_telemetry_present",
	"quic_version",
	"quic_raw_socket_backend",
	"quic_native_send_backend",
	"quic_native_receive_backend",
	"quic_handshake_ms",
	"quic_first_byte_ms",
	"quic_smoothed_rtt_ms",
	"quic_packets_sent",
	"quic_packets_received",
	"quic_packets_lost",
	"quic_wire_bytes_sent",
	"quic_recovery_wire_bytes",
	"quic_recovery_ratio",
	"quic_stream_bytes_sent",
	"quic_stream_bytes_received",
	"quic_stream_goodput_mbps",
	"quic_close_reason",
	"quic_native_gso",
	"quic_native_receive_batch",
	"file_source_read_calls",
	"file_source_read_bytes",
	"missing_scan_checks",
	"pending_missing",
	"pending_missing_peak",
	"repair_requested_packets",
	"repair_request_batches",
	"reorder_trail_packets",
	"receive_packet_rate_pps",
	"file_payload_engine",
	"file_payload_bytes_committed",
	"file_payload_bytes_bulk",
	"file_payload_bytes_quic",
	"file_payload_lane_addrs",
	"bulk_candidate_id",
	"bulk_native_send_attempts",
	"bulk_native_send_syscalls",
	"bulk_gso_messages",
	"bulk_logical_datagrams",
	"bulk_accepted_payload_bytes",
	"bulk_gso_segments_per_message",
	"bulk_batch_backend",
	"bulk_gso_attempted",
	"bulk_gso_active",
	"bulk_gso_segments",
	"bulk_send_calls",
	"bulk_send_datagrams",
	"bulk_receive_calls",
	"bulk_receive_datagrams",
	"bulk_max_send_batch",
	"bulk_max_receive_batch",
	"bulk_crypto_queue_peak",
	"bulk_writer_queue_peak",
	"bulk_lane_queue_peak",
	"bulk_receive_queue_peak",
	"bulk_decrypt_batches",
	"bulk_decrypt_datagrams",
	"bulk_probe_selected_mbps",
	"bulk_probe_duration_ms",
	"bulk_probe_trains",
	"bulk_probe_sent_datagrams",
	"bulk_probe_received_datagrams",
	"bulk_probe_loss_ppm",
	"bulk_probe_pressure",
	"bulk_probe_stop_reason",
	"bulk_decision_mode",
	"bulk_decision_reason",
	"bulk_decision_run_id",
	"bulk_probe_reject_stage",
	"bulk_handoff_drained_datagrams",
	"bulk_handoff_drain_duration_ms",
}

var Header = append([]string(nil), header[:]...)

var HeaderLine = strings.Join(header[:], ",")

type Snapshot struct {
	At                         time.Time
	Phase                      Phase
	RelayBytes                 int64
	DirectBytes                int64
	AppBytes                   int64
	LocalSentBytes             int64
	PeerReceivedBytes          int64
	SetupElapsedMS             int64
	TransferElapsedMS          int64
	DirectValidated            bool
	FallbackReason             string
	DirectRateSelectedMbps     int
	DirectRateActiveMbps       int
	DirectLanesActive          int
	DirectLanesAvailable       int
	RateTargetMbps             int
	RateCeilingMbps            int
	RateExplorationCeilingMbps int
	LaneMin                    int
	LaneCap                    int
	ControllerDecision         string
	ControllerReason           string
	DirectProbeState           string
	DirectProbeSummary         string
	ReplayWindowBytes          uint64
	ReplayBytes                uint64
	RepairQueueBytes           uint64
	RetransmitCount            int64
	RepairRequests             int64
	RepairBytes                int64
	LocalENOBUFSRetries        int64
	LocalENOBUFSWaitUS         int64
	LocalENOBUFSMaxConsecutive int64
	OutOfOrderBytes            uint64
	PeerRecvQueueDepth         int
	PeerRecvQueueDepthMax      int

	StripedSendBlockedMS           int64
	StripedReceivePendingChunks    int
	StripedReceivePendingChunksMax int
	StripedReceivePendingBytes     int64
	StripedReceivePendingBytesMax  int64

	DirectPacketBytes              int64
	DirectCommittedBytes           int64
	DirectTransport                string
	QUICTelemetryPresent           bool
	QUICConnections                uint32
	QUICStreams                    uint32
	QUICVersion                    string
	QUICRawSocketBackend           string
	QUICNativeSendBackend          string
	QUICNativeReceiveBackend       string
	QUICHandshakeMS                int64
	QUICFirstByteMS                int64
	QUICSmoothedRTTMS              string
	QUICPacketsSent                uint64
	QUICPacketsReceived            uint64
	QUICPacketsLost                uint64
	QUICWireBytesSent              uint64
	QUICRecoveryWireBytes          uint64
	QUICRecoveryRatio              string
	QUICStreamBytesSent            int64
	QUICStreamBytesReceived        int64
	QUICStreamGoodputMbps          string
	QUICCloseReason                string
	QUICNativeGSO                  string
	QUICNativeReceiveBatch         string
	FileSourceReadCalls            uint64
	FileSourceReadBytes            uint64
	MissingScanChecks              uint64
	PendingMissing                 uint32
	PendingMissingPeak             uint32
	RepairRequestedPackets         uint64
	RepairRequestBatches           uint64
	ReorderTrailPackets            uint32
	ReceivePacketRatePPS           uint32
	FilePayloadEngine              FilePayloadEngine
	FilePayloadBytesCommitted      int64
	FilePayloadBytesBulk           int64
	FilePayloadBytesQUIC           int64
	FilePayloadLaneAddresses       string
	BulkBatchPresent               bool
	BulkCandidateID                string
	BulkNativeSendAttempts         uint64
	BulkNativeSendSyscalls         uint64
	BulkNativeGSOMessages          uint64
	BulkLogicalDatagrams           uint64
	BulkNativeAcceptedPayloadBytes uint64
	BulkGSOSegmentsPerMessage      uint32
	BulkBatchBackend               string
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
	BulkWriterQueuePeak            uint32
	BulkLaneQueuePeak              uint32
	BulkReceiveQueuePeak           uint32
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
	BulkDecisionMode               string
	BulkDecisionReason             string
	BulkDecisionRunID              uint64
	BulkProbeRejectStage           string
	BulkHandoffDrainedDatagrams    uint64
	BulkHandoffDrainDurationMS     int64
	LastState                      string
	LastError                      string
}

type Recorder struct {
	mu                       sync.Mutex
	role                     Role
	start                    time.Time
	w                        *csv.Writer
	lastAt                   time.Time
	lastApp                  int64
	lastLocalSentBytes       int64
	lastDirectPacketBytes    int64
	lastDirectCommittedBytes int64
	lastPeerReceivedBytes    int64
	current                  Snapshot
	closed                   bool
	terminal                 bool
	err                      error
}

func NewRecorder(out io.Writer, role Role, start time.Time) (*Recorder, error) {
	if out == nil {
		return nil, errors.New("transfertrace: nil writer")
	}
	if start.IsZero() {
		start = time.Now()
	}
	w := csv.NewWriter(out)
	if err := w.Write(headerCopy()); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return &Recorder{
		role:  role,
		start: start,
		w:     w,
	}, nil
}

// Update copies the current snapshot, calls update while holding Recorder.mu,
// and stores the mutated snapshot without recording a CSV row. The callback
// must be fast, non-blocking, and must not call Recorder methods.
func (r *Recorder) Update(update func(*Snapshot)) {
	if update == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	update(&snap)
	r.current = snap
}

func (r *Recorder) Observe(snap Snapshot) {
	r.mu.Lock()
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Tick(at time.Time) {
	r.mu.Lock()
	snap := r.current
	snap.At = at
	r.observeLocked(snap)
	r.mu.Unlock()
}

func (r *Recorder) Error(at time.Time, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	snap.At = at
	snap.Phase = PhaseError
	snap.LastError = message
	r.observeLocked(snap)
	if r.err == nil {
		r.terminal = true
	}
}

func (r *Recorder) Complete(at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.terminal || r.err != nil {
		return
	}
	snap := r.current
	snap.At = at
	snap.Phase = PhaseComplete
	r.observeLocked(snap)
	if r.err == nil {
		r.terminal = true
	}
}

// Run records ticks until ctxDone is closed. Close flushes and prevents future
// writes, but it does not stop a running Run loop.
func (r *Recorder) Run(ctxDone <-chan struct{}, interval time.Duration, now func() time.Time) {
	ticker := time.NewTicker(runInterval(interval))
	defer ticker.Stop()
	runTicks(ctxDone, ticker.C, func() {
		r.Tick(runNow(now))
	})
}

func runTicks(done <-chan struct{}, ticks <-chan time.Time, tick func()) {
	for {
		select {
		case <-done:
			return
		case <-ticks:
			tick()
		}
	}
}

func runInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Second
	}
	return interval
}

func runNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now()
	}
	return now()
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	r.closed = true
	r.w.Flush()
	if err := r.w.Error(); err != nil && r.err == nil {
		r.err = err
	}
	return r.err
}

func (r *Recorder) observeLocked(snap Snapshot) {
	if r.closed || r.terminal || r.err != nil {
		return
	}
	if snap.At.IsZero() {
		snap.At = time.Now()
	}
	deltaBytes := nonNegativeDelta(snap.AppBytes, r.lastApp)
	localSentDelta := nonNegativeDelta(snap.LocalSentBytes, r.lastLocalSentBytes)
	directPacketDelta := nonNegativeDelta(snap.DirectPacketBytes, r.lastDirectPacketBytes)
	directCommittedDelta := nonNegativeDelta(snap.DirectCommittedBytes, r.lastDirectCommittedBytes)
	peerReceivedDelta := nonNegativeDelta(snap.PeerReceivedBytes, r.lastPeerReceivedBytes)
	deltaMS := int64(0)
	if !r.lastAt.IsZero() {
		deltaMS = snap.At.Sub(r.lastAt).Milliseconds()
	} else {
		deltaMS = snap.At.Sub(r.start).Milliseconds()
	}
	if deltaMS < 0 {
		deltaMS = 0
	}
	if err := r.w.Write(r.row(snap, deltaBytes, deltaMS, localSentDelta, directPacketDelta, directCommittedDelta, peerReceivedDelta)); err != nil {
		r.err = err
		return
	}
	r.w.Flush()
	if err := r.w.Error(); err != nil {
		r.err = err
		return
	}
	r.current = snap
	r.lastAt = snap.At
	r.lastApp = snap.AppBytes
	r.lastLocalSentBytes = snap.LocalSentBytes
	r.lastDirectPacketBytes = snap.DirectPacketBytes
	r.lastDirectCommittedBytes = snap.DirectCommittedBytes
	r.lastPeerReceivedBytes = snap.PeerReceivedBytes
}

func (r *Recorder) row(snap Snapshot, deltaBytes int64, deltaMS int64, localSentDelta int64, directPacketDelta int64, directCommittedDelta int64, peerReceivedDelta int64) []string {
	sendGoodput := ""
	if r.role == RoleSend && snap.LocalSentBytes > 0 {
		sendGoodput = formatMbps(localSentDelta, deltaMS)
	}
	receiveGoodput := ""
	if r.role == RoleReceive && snap.DirectPacketBytes > 0 {
		receiveGoodput = formatMbps(directPacketDelta, deltaMS)
	}
	receiverCommittedGoodput := ""
	if r.role == RoleReceive && snap.DirectCommittedBytes > 0 {
		receiverCommittedGoodput = formatMbps(directCommittedDelta, deltaMS)
	} else if r.role == RoleSend && snap.PeerReceivedBytes > 0 {
		receiverCommittedGoodput = formatMbps(peerReceivedDelta, deltaMS)
	}

	row := []string{
		strconv.FormatInt(snap.At.UnixMilli(), 10),
		strconv.FormatInt(snap.At.Sub(r.start).Milliseconds(), 10),
		string(r.role),
		string(snap.Phase),
		strconv.FormatInt(snap.RelayBytes, 10),
		strconv.FormatInt(snap.DirectBytes, 10),
		strconv.FormatInt(snap.AppBytes, 10),
		strconv.FormatInt(deltaBytes, 10),
		formatMbps(deltaBytes, deltaMS),
		strconv.FormatInt(snap.LocalSentBytes, 10),
		strconv.FormatInt(snap.PeerReceivedBytes, 10),
		formatOptionalInt64(snap.SetupElapsedMS),
		formatOptionalInt64(snap.TransferElapsedMS),
		strconv.FormatBool(snap.DirectValidated),
		snap.FallbackReason,
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectRateActiveMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		snap.DirectProbeState,
		snap.DirectProbeSummary,
		formatOptionalUint64(snap.ReplayWindowBytes),
		formatOptionalOrPresentUint64(snap.RepairQueueBytes, snap.BulkBatchPresent),
		formatOptionalInt64(snap.RetransmitCount),
		formatOptionalUint64(snap.OutOfOrderBytes),
		snap.LastState,
		snap.LastError,
		formatOptionalInt(snap.RateTargetMbps),
		formatOptionalInt(snap.RateCeilingMbps),
		formatOptionalInt(snap.RateExplorationCeilingMbps),
		formatOptionalInt(snap.DirectRateSelectedMbps),
		formatOptionalInt(snap.DirectLanesActive),
		formatOptionalInt(snap.DirectLanesAvailable),
		formatOptionalInt(snap.LaneMin),
		formatOptionalInt(snap.LaneCap),
		snap.ControllerDecision,
		snap.ControllerReason,
		sendGoodput,
		receiveGoodput,
		receiverCommittedGoodput,
		formatOptionalUint64(snap.ReplayBytes),
		formatOptionalOrPresentInt64(snap.RetransmitCount, snap.BulkBatchPresent),
		formatOptionalOrPresentInt64(snap.RepairRequests, snap.BulkBatchPresent),
		formatOptionalOrPresentInt64(snap.RepairBytes, snap.BulkBatchPresent),
		formatOptionalOrPresentInt64(snap.LocalENOBUFSRetries, snap.BulkBatchPresent),
		formatOptionalOrPresentInt64(snap.LocalENOBUFSWaitUS, snap.BulkBatchPresent),
		formatOptionalOrPresentInt64(snap.LocalENOBUFSMaxConsecutive, snap.BulkBatchPresent),
		formatOptionalOrPresentInt(snap.PeerRecvQueueDepth, snap.BulkBatchPresent),
		formatOptionalOrPresentInt(snap.PeerRecvQueueDepthMax, snap.BulkBatchPresent),
		strconv.FormatInt(snap.StripedSendBlockedMS, 10),
		strconv.Itoa(snap.StripedReceivePendingChunks),
		strconv.Itoa(snap.StripedReceivePendingChunksMax),
		strconv.FormatInt(snap.StripedReceivePendingBytes, 10),
		strconv.FormatInt(snap.StripedReceivePendingBytesMax, 10),
		formatOptionalInt64(snap.DirectPacketBytes),
		formatOptionalInt64(snap.DirectCommittedBytes),
		snap.DirectTransport,
	}
	row = append(row, quicTraceColumns(snap)...)
	row = append(row, fileSourceReadTraceColumns(snap)...)
	row = append(row,
		strconv.FormatUint(snap.MissingScanChecks, 10),
		strconv.FormatUint(uint64(snap.PendingMissing), 10),
		strconv.FormatUint(uint64(snap.PendingMissingPeak), 10),
		strconv.FormatUint(snap.RepairRequestedPackets, 10),
		strconv.FormatUint(snap.RepairRequestBatches, 10),
		strconv.FormatUint(uint64(snap.ReorderTrailPackets), 10),
		strconv.FormatUint(uint64(snap.ReceivePacketRatePPS), 10),
		string(snap.FilePayloadEngine),
		strconv.FormatInt(snap.FilePayloadBytesCommitted, 10),
		strconv.FormatInt(snap.FilePayloadBytesBulk, 10),
		strconv.FormatInt(snap.FilePayloadBytesQUIC, 10),
		snap.FilePayloadLaneAddresses,
	)
	row = append(row, bulkBatchTraceColumns(snap)...)
	return append(row,
		snap.BulkDecisionMode,
		snap.BulkDecisionReason,
		formatOptionalUint64(snap.BulkDecisionRunID),
		snap.BulkProbeRejectStage,
		strconv.FormatUint(snap.BulkHandoffDrainedDatagrams, 10),
		strconv.FormatUint(uint64(snap.BulkHandoffDrainDurationMS), 10),
	)
}

func quicTraceColumns(snap Snapshot) []string {
	if !snap.QUICTelemetryPresent {
		return make([]string, 22)
	}
	return []string{
		strconv.FormatUint(uint64(snap.QUICConnections), 10),
		strconv.FormatUint(uint64(snap.QUICStreams), 10),
		"true",
		snap.QUICVersion,
		snap.QUICRawSocketBackend,
		snap.QUICNativeSendBackend,
		snap.QUICNativeReceiveBackend,
		strconv.FormatInt(snap.QUICHandshakeMS, 10),
		strconv.FormatInt(snap.QUICFirstByteMS, 10),
		formatPresentDecimal(snap.QUICSmoothedRTTMS),
		strconv.FormatUint(snap.QUICPacketsSent, 10),
		strconv.FormatUint(snap.QUICPacketsReceived, 10),
		strconv.FormatUint(snap.QUICPacketsLost, 10),
		strconv.FormatUint(snap.QUICWireBytesSent, 10),
		strconv.FormatUint(snap.QUICRecoveryWireBytes, 10),
		formatPresentDecimal(snap.QUICRecoveryRatio),
		strconv.FormatInt(snap.QUICStreamBytesSent, 10),
		strconv.FormatInt(snap.QUICStreamBytesReceived, 10),
		formatPresentDecimal(snap.QUICStreamGoodputMbps),
		snap.QUICCloseReason,
		snap.QUICNativeGSO,
		snap.QUICNativeReceiveBatch,
	}
}

func fileSourceReadTraceColumns(snap Snapshot) []string {
	if !snap.FilePayloadEngine.Valid() && snap.FileSourceReadCalls == 0 && snap.FileSourceReadBytes == 0 {
		return []string{"", ""}
	}
	return []string{
		strconv.FormatUint(snap.FileSourceReadCalls, 10),
		strconv.FormatUint(snap.FileSourceReadBytes, 10),
	}
}

func formatPresentDecimal(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

func bulkBatchTraceColumns(snap Snapshot) []string {
	if !snap.BulkBatchPresent {
		return make([]string, 31)
	}
	return []string{
		snap.BulkCandidateID,
		strconv.FormatUint(snap.BulkNativeSendAttempts, 10),
		strconv.FormatUint(snap.BulkNativeSendSyscalls, 10),
		strconv.FormatUint(snap.BulkNativeGSOMessages, 10),
		strconv.FormatUint(snap.BulkLogicalDatagrams, 10),
		strconv.FormatUint(snap.BulkNativeAcceptedPayloadBytes, 10),
		strconv.FormatUint(uint64(snap.BulkGSOSegmentsPerMessage), 10),
		snap.BulkBatchBackend,
		strconv.FormatBool(snap.BulkGSOAttempted),
		strconv.FormatBool(snap.BulkGSOActive),
		strconv.FormatUint(snap.BulkGSOSegments, 10),
		strconv.FormatUint(snap.BulkSendCalls, 10),
		strconv.FormatUint(snap.BulkSendDatagrams, 10),
		strconv.FormatUint(snap.BulkReceiveCalls, 10),
		strconv.FormatUint(snap.BulkReceiveDatagrams, 10),
		strconv.FormatUint(uint64(snap.BulkMaxSendBatch), 10),
		strconv.FormatUint(uint64(snap.BulkMaxReceiveBatch), 10),
		strconv.FormatUint(uint64(snap.BulkCryptoQueuePeak), 10),
		strconv.FormatUint(uint64(snap.BulkWriterQueuePeak), 10),
		strconv.FormatUint(uint64(snap.BulkLaneQueuePeak), 10),
		strconv.FormatUint(uint64(snap.BulkReceiveQueuePeak), 10),
		strconv.FormatUint(snap.BulkDecryptBatches, 10),
		strconv.FormatUint(snap.BulkDecryptDatagrams, 10),
		strconv.Itoa(snap.BulkProbeSelectedMbps),
		strconv.FormatInt(snap.BulkProbeDurationMS, 10),
		strconv.FormatUint(uint64(snap.BulkProbeTrains), 10),
		strconv.FormatUint(snap.BulkProbeSentDatagrams, 10),
		strconv.FormatUint(snap.BulkProbeReceivedDatagrams, 10),
		strconv.FormatUint(snap.BulkProbeLossPPM, 10),
		strconv.FormatBool(snap.BulkProbePressure),
		snap.BulkProbeStopReason,
	}
}

func nonNegativeDelta(current int64, previous int64) int64 {
	delta := current - previous
	if delta < 0 {
		return 0
	}
	return delta
}

func formatMbps(deltaBytes int64, deltaMS int64) string {
	if deltaBytes == 0 || deltaMS <= 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", float64(deltaBytes*8)/float64(deltaMS*1000))
}

func formatOptionalInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func formatOptionalInt64(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func formatOptionalUint64(value uint64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatUint(value, 10)
}

func formatOptionalOrPresentInt(value int, present bool) string {
	if present {
		return strconv.Itoa(value)
	}
	return formatOptionalInt(value)
}

func formatOptionalOrPresentInt64(value int64, present bool) string {
	if present {
		return strconv.FormatInt(value, 10)
	}
	return formatOptionalInt64(value)
}

func formatOptionalOrPresentUint64(value uint64, present bool) string {
	if present {
		return strconv.FormatUint(value, 10)
	}
	return formatOptionalUint64(value)
}

func headerCopy() []string {
	return append([]string(nil), header[:]...)
}

func init() {
	if strings.Join(header[:], ",") != HeaderLine {
		panic("transfertrace: header mismatch")
	}
}
