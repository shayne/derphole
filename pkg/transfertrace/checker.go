// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

type Options struct {
	Role                       Role
	StallWindow                time.Duration
	ExpectedBytes              int64
	ExpectedBytesSet           bool
	ExpectedPayloadBytes       int64
	ExpectedPayloadBytesSet    bool
	RequireDirectTransport     string
	RequireFilePayloadEngine   FilePayloadEngine
	RequireEngineTelemetry     bool
	ExpectedSelectedPublicIPv4 string
	ForbidRelayPayload         bool
}

type Result struct {
	Rows                          int
	FinalAppBytes                 int64
	FinalFilePayloadBytes         int64
	FinalFilePayloadEngine        FilePayloadEngine
	FinalFilePayloadBytesBulk     int64
	FinalFilePayloadBytesQUIC     int64
	FinalFilePayloadLaneAddresses []string
	FinalPhase                    Phase
	MaxFlatline                   time.Duration
	Diagnostics                   DiagnosticsSummary
}

type DiagnosticsSummary struct {
	MaxRateTargetMbps              int
	MinRateTargetMbps              int
	FinalRateTargetMbps            int
	ControllerDecreases            int
	FinalRepairBytes               int64
	LocalENOBUFSRetries            int64
	LocalENOBUFSWaitUS             int64
	LocalENOBUFSMaxConsecutive     int64
	MaxReplayBytes                 uint64
	MaxRetransmits                 int64
	MaxPeerRecvQueueDepth          int
	MaxStripedSendBlockedMS        int64
	MaxStripedReceivePendingChunks int
	MaxStripedReceivePendingBytes  int64
	DirectTransport                string
	ReceiverCommittedMbpsMin       float64
	ReceiverCommittedMbpsMax       float64
	ReceiverCommittedMbpsObserved  bool
	ReceiverRateP10Mbps            float64
	ReceiverRateP50Mbps            float64
	ReceiverRateP90Mbps            float64
	ReceiverRateCV                 float64
	ReceiverWindowsBelow500Mbps    int
	ReceiverRateObserved           bool
	MissingScanChecks              uint64
	PendingMissing                 uint32
	PendingMissingPeak             uint32
	RepairRequestedPackets         uint64
	RepairRequestBatches           uint64
	ReorderTrailPackets            uint32
	ReceivePacketRatePPS           uint32
	ReceiverRepairObserved         bool
	SenderHealthObserved           bool
}

type PairOptions struct {
	Role                       Role
	PeerRole                   Role
	RateTolerance              float64
	ProgressLeadToleranceBytes int64
}

type PairResult struct {
	PrimaryRows          int
	PeerRows             int
	ProgressDeltaBytes   int64
	MaxProgressLeadBytes int64
	SenderRateMbps       float64
	ReceiverRateMbps     float64
}

type checkerIndexes struct {
	fields               int
	header               []string
	timestamp            int
	timestampName        string
	role                 int
	phase                int
	elapsedMS            int
	appBytes             int
	relayBytes           int
	appMbps              int
	peerReceivedBytes    int
	transferElapsedMS    int
	directValidated      int
	fallbackReason       int
	lastState            int
	lastError            int
	controllerDecision   int
	directTransport      int
	filePayloadEngine    int
	filePayloadCommitted int
	filePayloadBulk      int
	filePayloadQUIC      int
	filePayloadLaneAddrs int
	bulkDecisionMode     int
	bulkDecisionReason   int
	bulkDecisionRunID    int
	senderHealthSchema   bool
	receiverRepairSchema bool
	numericDiagnostics   []checkerNumericDiagnostic
	quicEvidence         map[string]int
	bulkEvidence         map[string]int
}

type checkerRow struct {
	rowNo              int
	role               Role
	timestamp          time.Time
	elapsedMS          int64
	phase              Phase
	appBytes           int64
	relayBytes         int64
	peerReceivedBytes  int64
	transferElapsedMS  int64
	directValidated    bool
	fallbackReason     string
	lastState          string
	lastError          string
	controllerDecision string
	filePayload        checkerRowFilePayload
	quicEvidence       checkerRowQUICEvidence
	bulkEvidence       checkerRowBulkEvidence
	bulkDecision       checkerRowBulkDecision
	diagnostics        checkerRowDiagnostics
}

type checkerRowBulkDecision struct {
	mode   string
	reason string
	runID  uint64
	set    bool
}

type checkerRowQUICEvidence struct {
	observed             map[string]bool
	telemetryPresent     bool
	connections          uint64
	streams              uint64
	version              string
	rawSocketBackend     string
	nativeSendBackend    string
	nativeReceiveBackend string
	handshakeMS          int64
	firstByteMS          int64
	smoothedRTTMS        float64
	packetsSent          uint64
	packetsReceived      uint64
	packetsLost          uint64
	wireBytesSent        uint64
	recoveryWireBytes    uint64
	recoveryRatio        float64
	streamBytesSent      int64
	streamBytesReceived  int64
	closeReason          string
	nativeGSO            string
	nativeReceiveBatch   string
	fileSourceReadCalls  uint64
	fileSourceReadBytes  uint64
}

type checkerRowFilePayload struct {
	engine        FilePayloadEngine
	committed     int64
	bulk          int64
	quic          int64
	laneAddresses []string
	observed      map[string]bool
}

type checkerRowBulkEvidence struct {
	observed map[string]bool
	strings  map[string]string
	uints    map[string]uint64
	bools    map[string]bool
}

type checkerRowDiagnostics struct {
	observed                       map[string]bool
	rateTargetMbps                 int
	appMbps                        float64
	appMbpsObserved                bool
	receiverCommittedMbps          float64
	receiverCommittedMbpsObserved  bool
	replayBytes                    uint64
	repairQueueBytes               uint64
	retransmits                    int64
	repairRequests                 int64
	repairBytes                    int64
	localENOBUFSRetries            int64
	localENOBUFSWaitUS             int64
	localENOBUFSMaxConsecutive     int64
	peerRecvQueueDepth             int
	peerRecvQueueDepthMax          int
	stripedSendBlockedMS           int64
	stripedReceivePendingChunks    int
	stripedReceivePendingChunksMax int
	stripedReceivePendingBytes     int64
	stripedReceivePendingBytesMax  int64
	missingScanChecks              uint64
	pendingMissing                 uint32
	pendingMissingPeak             uint32
	repairRequestedPackets         uint64
	repairRequestBatches           uint64
	reorderTrailPackets            uint32
	receivePacketRatePPS           uint32
	receiverRepairObserved         bool
	directTransport                string
}

var checkerRowDiagnosticRecorders = map[string]func(*checkerRowDiagnostics, checkerNumericDiagnosticValue){
	"rate_target_mbps": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.rateTargetMbps = value.intValue
	},
	"receiver_committed_mbps": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.receiverCommittedMbps = value.floatValue
		d.receiverCommittedMbpsObserved = true
	},
	"replay_bytes": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.replayBytes = value.uint64Value
	},
	"repair_queue_bytes": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.repairQueueBytes = value.uint64Value
	},
	"retransmits": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.retransmits = value.int64Value
	},
	"repair_requests": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.repairRequests = value.int64Value
	},
	"repair_bytes": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.repairBytes = value.int64Value
	},
	"local_enobufs_retries": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.localENOBUFSRetries = value.int64Value
	},
	"local_enobufs_wait_us": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.localENOBUFSWaitUS = value.int64Value
	},
	"local_enobufs_max_consecutive": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.localENOBUFSMaxConsecutive = value.int64Value
	},
	"peer_recv_queue_depth": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.peerRecvQueueDepth = value.intValue
	},
	"peer_recv_queue_depth_max": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.peerRecvQueueDepthMax = value.intValue
	},
	"striped_send_blocked_ms": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.stripedSendBlockedMS = value.int64Value
	},
	"striped_receive_pending_chunks": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.stripedReceivePendingChunks = value.intValue
	},
	"striped_receive_pending_chunks_max": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.stripedReceivePendingChunksMax = value.intValue
	},
	"striped_receive_pending_bytes": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.stripedReceivePendingBytes = value.int64Value
	},
	"striped_receive_pending_bytes_max": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.stripedReceivePendingBytesMax = value.int64Value
	},
	"missing_scan_checks": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.missingScanChecks = value.uint64Value
	},
	"pending_missing": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.pendingMissing = value.uint32Value
	},
	"pending_missing_peak": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.pendingMissingPeak = value.uint32Value
	},
	"repair_requested_packets": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.repairRequestedPackets = value.uint64Value
	},
	"repair_request_batches": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.repairRequestBatches = value.uint64Value
	},
	"reorder_trail_packets": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.reorderTrailPackets = value.uint32Value
	},
	"receive_packet_rate_pps": func(d *checkerRowDiagnostics, value checkerNumericDiagnosticValue) {
		d.receivePacketRatePPS = value.uint32Value
	},
}

type checkerNumericDiagnosticKind int

const (
	checkerNumericDiagnosticInt checkerNumericDiagnosticKind = iota
	checkerNumericDiagnosticInt64
	checkerNumericDiagnosticUint32
	checkerNumericDiagnosticUint64
	checkerNumericDiagnosticFloat
)

type checkerNumericDiagnosticColumn struct {
	name string
	kind checkerNumericDiagnosticKind
}

type checkerNumericDiagnostic struct {
	name  string
	index int
	kind  checkerNumericDiagnosticKind
}

type checkerNumericDiagnosticValue struct {
	intValue    int
	int64Value  int64
	uint32Value uint32
	uint64Value uint64
	floatValue  float64
}

var checkerNumericDiagnosticColumns = []checkerNumericDiagnosticColumn{
	{name: "rate_target_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_ceiling_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_exploration_ceiling_mbps", kind: checkerNumericDiagnosticInt},
	{name: "rate_selected_mbps", kind: checkerNumericDiagnosticInt},
	{name: "active_lanes", kind: checkerNumericDiagnosticInt},
	{name: "available_lanes", kind: checkerNumericDiagnosticInt},
	{name: "lane_min", kind: checkerNumericDiagnosticInt},
	{name: "lane_cap", kind: checkerNumericDiagnosticInt},
	{name: "send_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "receive_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "receiver_committed_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "replay_bytes", kind: checkerNumericDiagnosticUint64},
	{name: "repair_queue_bytes", kind: checkerNumericDiagnosticUint64},
	{name: "retransmits", kind: checkerNumericDiagnosticInt64},
	{name: "repair_requests", kind: checkerNumericDiagnosticInt64},
	{name: "repair_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "local_enobufs_retries", kind: checkerNumericDiagnosticInt64},
	{name: "local_enobufs_wait_us", kind: checkerNumericDiagnosticInt64},
	{name: "local_enobufs_max_consecutive", kind: checkerNumericDiagnosticInt64},
	{name: "peer_recv_queue_depth", kind: checkerNumericDiagnosticInt},
	{name: "peer_recv_queue_depth_max", kind: checkerNumericDiagnosticInt},
	{name: "striped_send_blocked_ms", kind: checkerNumericDiagnosticInt64},
	{name: "striped_receive_pending_chunks", kind: checkerNumericDiagnosticInt},
	{name: "striped_receive_pending_chunks_max", kind: checkerNumericDiagnosticInt},
	{name: "striped_receive_pending_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "striped_receive_pending_bytes_max", kind: checkerNumericDiagnosticInt64},
	{name: "direct_packet_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "direct_committed_bytes", kind: checkerNumericDiagnosticInt64},
	{name: "quic_handshake_ms", kind: checkerNumericDiagnosticInt64},
	{name: "quic_first_byte_ms", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_bytes_sent", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_bytes_received", kind: checkerNumericDiagnosticInt64},
	{name: "quic_stream_goodput_mbps", kind: checkerNumericDiagnosticFloat},
	{name: "quic_loss_events", kind: checkerNumericDiagnosticInt64},
	{name: "missing_scan_checks", kind: checkerNumericDiagnosticUint64},
	{name: "pending_missing", kind: checkerNumericDiagnosticUint32},
	{name: "pending_missing_peak", kind: checkerNumericDiagnosticUint32},
	{name: "repair_requested_packets", kind: checkerNumericDiagnosticUint64},
	{name: "repair_request_batches", kind: checkerNumericDiagnosticUint64},
	{name: "reorder_trail_packets", kind: checkerNumericDiagnosticUint32},
	{name: "receive_packet_rate_pps", kind: checkerNumericDiagnosticUint32},
}

var receiverRepairDiagnosticColumns = [...]string{
	"missing_scan_checks",
	"pending_missing",
	"pending_missing_peak",
	"repair_requested_packets",
	"repair_request_batches",
	"reorder_trail_packets",
	"receive_packet_rate_pps",
}

var checkerQUICEvidenceColumns = [...]string{
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
	"quic_close_reason",
	"quic_native_gso",
	"quic_native_receive_batch",
	"file_source_read_calls",
	"file_source_read_bytes",
}

var checkerBulkEvidenceColumns = [...]string{
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
	"bulk_probe_reject_stage",
	"bulk_handoff_drained_datagrams",
	"bulk_handoff_drain_duration_ms",
}

type checker struct {
	opts                Options
	result              Result
	lastAppBytes        int64
	lastRateTargetMbps  int
	receiverRates       []float64
	active              bool
	activeSince         time.Time
	lastPhase           Phase
	maxRelayBytes       int64
	filePayloadObserved map[string]bool
	finalQUICEvidence   checkerRowQUICEvidence
	finalBulkEvidence   checkerRowBulkEvidence
	finalBulkDecision   checkerRowBulkDecision
	bulkDecision        checkerRowBulkDecision
	finalRowDiagnostics checkerRowDiagnostics
}

func Check(r io.Reader, opts Options) (Result, error) {
	if opts.StallWindow <= 0 {
		opts.StallWindow = time.Second
	}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return Result{}, fmt.Errorf("read header: %w", err)
	}
	indexes, err := checkerHeaderIndexes(header)
	if err != nil {
		return Result{}, err
	}

	c := checker{opts: opts}
	if err := c.scanRows(cr, indexes); err != nil {
		return c.result, err
	}
	return c.finish()
}

func CheckPair(primary io.Reader, peer io.Reader, opts PairOptions) (PairResult, error) {
	if opts.Role != RoleSend && opts.Role != RoleReceive {
		return PairResult{}, fmt.Errorf("primary role must be send or receive")
	}
	if opts.PeerRole == "" {
		opts.PeerRole = oppositeRole(opts.Role)
	}
	primaryRows, err := readCheckerRows(primary, opts.Role)
	if err != nil {
		return PairResult{}, fmt.Errorf("read primary trace: %w", err)
	}
	peerRows, err := readCheckerRows(peer, opts.PeerRole)
	if err != nil {
		return PairResult{}, fmt.Errorf("read peer trace: %w", err)
	}
	if len(primaryRows) == 0 {
		return PairResult{}, fmt.Errorf("no rows matched primary role %q", opts.Role)
	}
	if len(peerRows) == 0 {
		return PairResult{}, fmt.Errorf("no rows matched peer role %q", opts.PeerRole)
	}
	return compareCheckerPair(primaryRows, peerRows, opts)
}

func (c *checker) scanRows(cr *csv.Reader, indexes checkerIndexes) error {
	rowNo := 1
	for {
		record, err := cr.Read()
		rowNo++
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("row %d: read row: %w", rowNo, err)
		}
		role := Role(field(record, indexes.role))
		if c.opts.Role != "" && role != c.opts.Role {
			continue
		}
		if role == RoleSend && indexes.senderHealthSchema {
			c.result.Diagnostics.SenderHealthObserved = true
		}
		row, err := parseCheckerRow(record, indexes, rowNo)
		if err != nil {
			return err
		}
		if err := c.consume(row); err != nil {
			return err
		}
	}
}

func (c *checker) consume(row checkerRow) error {
	c.recordRowSnapshot(row)
	if row.lastError != "" {
		return fmt.Errorf("row %d: terminal error: %s", row.rowNo, row.lastError)
	}
	if err := validateCheckerRowStatus(row); err != nil {
		return err
	}
	if err := c.consumeBulkDecision(row); err != nil {
		return err
	}
	return c.consumeProgress(row)
}

func (c *checker) recordRowSnapshot(row checkerRow) {
	c.result.Rows++
	c.result.FinalAppBytes = row.appBytes
	c.result.FinalFilePayloadBytes = row.filePayload.committed
	c.result.FinalFilePayloadEngine = row.filePayload.engine
	c.result.FinalFilePayloadBytesBulk = row.filePayload.bulk
	c.result.FinalFilePayloadBytesQUIC = row.filePayload.quic
	c.result.FinalFilePayloadLaneAddresses = append(c.result.FinalFilePayloadLaneAddresses[:0], row.filePayload.laneAddresses...)
	c.filePayloadObserved = row.filePayload.observed
	c.finalQUICEvidence = row.quicEvidence
	c.finalBulkEvidence = row.bulkEvidence
	c.finalBulkDecision = row.bulkDecision
	c.finalRowDiagnostics = row.diagnostics
	c.result.FinalPhase = row.phase
	c.maxRelayBytes = maxInt64(c.maxRelayBytes, row.relayBytes)
	c.recordDiagnostics(row)
}

func (c *checker) consumeBulkDecision(row checkerRow) error {
	if row.bulkDecision.set {
		if c.bulkDecision.set && row.bulkDecision != c.bulkDecision {
			return fmt.Errorf("row %d: bulk decision changed from mode=%q reason=%q run=%d to mode=%q reason=%q run=%d",
				row.rowNo, c.bulkDecision.mode, c.bulkDecision.reason, c.bulkDecision.runID,
				row.bulkDecision.mode, row.bulkDecision.reason, row.bulkDecision.runID)
		}
		c.bulkDecision = row.bulkDecision
	} else if c.bulkDecision.set {
		return fmt.Errorf("row %d: bulk decision evidence disappeared", row.rowNo)
	}
	return nil
}

func (c *checker) consumeProgress(row checkerRow) error {
	active := isActivePhase(row.phase)
	if c.result.Rows == 1 {
		c.recordFirstRow(row, active)
		return nil
	}
	if !active {
		c.recordInactive(row)
		return nil
	}
	if c.lastAppBytes == 0 && row.appBytes == 0 {
		c.recordPreProgressActive(row)
		return nil
	}
	if !c.active || row.appBytes > c.lastAppBytes {
		c.recordActiveProgress(row)
		return nil
	}
	if row.phase != c.lastPhase {
		c.recordActivePhaseChange(row)
		return nil
	}
	return c.checkFlatline(row)
}

func (c *checker) recordDiagnostics(row checkerRow) {
	diagnostics := &c.result.Diagnostics
	rowDiagnostics := row.diagnostics
	diagnostics.MaxRateTargetMbps = maxInt(diagnostics.MaxRateTargetMbps, rowDiagnostics.rateTargetMbps)
	diagnostics.MaxReplayBytes = maxUint64(diagnostics.MaxReplayBytes, rowDiagnostics.replayBytes)
	diagnostics.MaxRetransmits = maxInt64(diagnostics.MaxRetransmits, rowDiagnostics.retransmits)
	diagnostics.MaxPeerRecvQueueDepth = maxInt(diagnostics.MaxPeerRecvQueueDepth, maxInt(rowDiagnostics.peerRecvQueueDepth, rowDiagnostics.peerRecvQueueDepthMax))
	diagnostics.MaxStripedSendBlockedMS = maxInt64(diagnostics.MaxStripedSendBlockedMS, rowDiagnostics.stripedSendBlockedMS)
	diagnostics.MaxStripedReceivePendingChunks = maxInt(diagnostics.MaxStripedReceivePendingChunks, maxInt(rowDiagnostics.stripedReceivePendingChunks, rowDiagnostics.stripedReceivePendingChunksMax))
	diagnostics.MaxStripedReceivePendingBytes = maxInt64(diagnostics.MaxStripedReceivePendingBytes, maxInt64(rowDiagnostics.stripedReceivePendingBytes, rowDiagnostics.stripedReceivePendingBytesMax))
	if rowDiagnostics.directTransport != "" {
		diagnostics.DirectTransport = rowDiagnostics.directTransport
	}
	recordReceiverCommittedMbps(diagnostics, rowDiagnostics)
	if row.role == RoleReceive && rowDiagnostics.receiverRepairObserved {
		diagnostics.ReceiverRepairObserved = true
		diagnostics.MissingScanChecks = max(diagnostics.MissingScanChecks, rowDiagnostics.missingScanChecks)
		diagnostics.PendingMissing = rowDiagnostics.pendingMissing
		diagnostics.PendingMissingPeak = max(diagnostics.PendingMissingPeak, rowDiagnostics.pendingMissingPeak)
		diagnostics.RepairRequestedPackets = max(diagnostics.RepairRequestedPackets, rowDiagnostics.repairRequestedPackets)
		diagnostics.RepairRequestBatches = max(diagnostics.RepairRequestBatches, rowDiagnostics.repairRequestBatches)
		diagnostics.ReorderTrailPackets = max(diagnostics.ReorderTrailPackets, rowDiagnostics.reorderTrailPackets)
		diagnostics.ReceivePacketRatePPS = max(diagnostics.ReceivePacketRatePPS, rowDiagnostics.receivePacketRatePPS)
	}
	if row.role == RoleSend {
		c.recordSenderHealth(row)
	}
	if row.role == RoleReceive && row.phase == PhaseDirectExecute && row.appBytes > 0 && rowDiagnostics.appMbpsObserved {
		c.receiverRates = append(c.receiverRates, rowDiagnostics.appMbps)
	}
}

func (c *checker) recordSenderHealth(row checkerRow) {
	diagnostics := &c.result.Diagnostics
	target := row.diagnostics.rateTargetMbps
	if target > 0 {
		if diagnostics.MinRateTargetMbps == 0 || target < diagnostics.MinRateTargetMbps {
			diagnostics.MinRateTargetMbps = target
		}
		diagnostics.FinalRateTargetMbps = target
		if target != c.lastRateTargetMbps {
			if row.controllerDecision == "decrease" && c.lastRateTargetMbps > target {
				diagnostics.ControllerDecreases++
			}
			c.lastRateTargetMbps = target
		}
	}
	diagnostics.FinalRepairBytes = maxInt64(diagnostics.FinalRepairBytes, row.diagnostics.repairBytes)
	diagnostics.LocalENOBUFSRetries = maxInt64(diagnostics.LocalENOBUFSRetries, row.diagnostics.localENOBUFSRetries)
	diagnostics.LocalENOBUFSWaitUS = maxInt64(diagnostics.LocalENOBUFSWaitUS, row.diagnostics.localENOBUFSWaitUS)
	diagnostics.LocalENOBUFSMaxConsecutive = maxInt64(diagnostics.LocalENOBUFSMaxConsecutive, row.diagnostics.localENOBUFSMaxConsecutive)
}

func recordReceiverCommittedMbps(diagnostics *DiagnosticsSummary, row checkerRowDiagnostics) {
	if !row.receiverCommittedMbpsObserved {
		return
	}
	if !diagnostics.ReceiverCommittedMbpsObserved || row.receiverCommittedMbps < diagnostics.ReceiverCommittedMbpsMin {
		diagnostics.ReceiverCommittedMbpsMin = row.receiverCommittedMbps
	}
	if !diagnostics.ReceiverCommittedMbpsObserved || row.receiverCommittedMbps > diagnostics.ReceiverCommittedMbpsMax {
		diagnostics.ReceiverCommittedMbpsMax = row.receiverCommittedMbps
	}
	diagnostics.ReceiverCommittedMbpsObserved = true
}

func maxInt(a int, b int) int {
	if b > a {
		return b
	}
	return a
}

func maxInt64(a int64, b int64) int64 {
	if b > a {
		return b
	}
	return a
}

func maxUint64(a uint64, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func (c *checker) checkFlatline(row checkerRow) error {
	flatline := row.timestamp.Sub(c.activeSince)
	if flatline > c.result.MaxFlatline {
		c.result.MaxFlatline = flatline
	}
	if flatline > c.opts.StallWindow {
		return fmt.Errorf("row %d: app bytes stalled for %s in phase %s", row.rowNo, flatline, row.phase)
	}
	return nil
}

func (c *checker) recordFirstRow(row checkerRow, active bool) {
	c.lastAppBytes = row.appBytes
	c.active = active
	c.lastPhase = row.phase
	if active {
		c.activeSince = row.timestamp
	}
}

func (c *checker) recordInactive(row checkerRow) {
	if row.appBytes > c.lastAppBytes {
		c.lastAppBytes = row.appBytes
	}
	c.active = false
	c.lastPhase = row.phase
}

func (c *checker) recordPreProgressActive(row checkerRow) {
	c.active = false
	c.lastPhase = row.phase
}

func (c *checker) recordActiveProgress(row checkerRow) {
	c.lastAppBytes = row.appBytes
	c.active = true
	c.activeSince = row.timestamp
	c.lastPhase = row.phase
}

func (c *checker) recordActivePhaseChange(row checkerRow) {
	c.active = true
	c.activeSince = row.timestamp
	c.lastPhase = row.phase
}

func (c *checker) finish() (Result, error) {
	if c.result.Rows == 0 {
		return c.result, c.noRowsError()
	}
	if c.expectedBytesSet() && c.result.FinalAppBytes != c.opts.ExpectedBytes {
		return c.result, fmt.Errorf("final app bytes = %d, want %d", c.result.FinalAppBytes, c.opts.ExpectedBytes)
	}
	if c.result.FinalPhase != PhaseComplete {
		return c.result, fmt.Errorf("final phase = %s, want %s", c.result.FinalPhase, PhaseComplete)
	}
	if c.opts.ForbidRelayPayload && c.maxRelayBytes != 0 {
		return c.result, fmt.Errorf("relay payload bytes = %d, want 0", c.maxRelayBytes)
	}
	if c.opts.RequireDirectTransport != "" && c.result.Diagnostics.DirectTransport != c.opts.RequireDirectTransport {
		return c.result, fmt.Errorf("direct transport = %q, want %q", c.result.Diagnostics.DirectTransport, c.opts.RequireDirectTransport)
	}
	if err := c.validateFilePayloadEvidence(); err != nil {
		return c.result, err
	}
	c.recordReceiverRateSummary()
	return c.result, nil
}

func (c *checker) validateFilePayloadEvidence() error {
	requireEngine := c.opts.RequireEngineTelemetry || c.opts.RequireFilePayloadEngine != "" ||
		c.expectedPayloadBytesSet() || c.opts.ExpectedSelectedPublicIPv4 != ""
	if err := c.validateRequiredFilePayloadEngine(requireEngine); err != nil {
		return err
	}
	if c.opts.RequireEngineTelemetry {
		if err := c.validateSelectedEngineTelemetry(); err != nil {
			return err
		}
	}
	if requireEngine {
		if err := c.validateFilePayloadCounters(); err != nil {
			return err
		}
	}
	if err := c.validateSelectedPayloadLanes(); err != nil {
		return err
	}
	return c.validateFinalBulkDecision()
}

func (c *checker) validateFinalBulkDecision() error {
	decision := c.finalBulkDecision
	switch c.result.FinalFilePayloadEngine {
	case FilePayloadEngineBulk:
		if err := c.validateFinalBulkPacketDecision(decision); err != nil {
			return err
		}
	case FilePayloadEngineQUIC:
		if err := validateFinalQUICBulkDecision(decision); err != nil {
			return err
		}
		if decision.set && c.finalBulkEvidence.uints["bulk_handoff_drain_duration_ms"] == 0 {
			return errors.New("bulk handoff drain duration must be positive for final QUIC bulk decision")
		}
	}
	return nil
}

func (c *checker) validateFinalBulkPacketDecision(decision checkerRowBulkDecision) error {
	if !decision.set || decision.mode != "bulk-packets-v1" || decision.reason != "both-probes-accepted" {
		return fmt.Errorf("bulk decision mode=%q reason=%q, want bulk-packets-v1 and both-probes-accepted", decision.mode, decision.reason)
	}
	if c.finalBulkEvidence.uints["bulk_probe_selected_mbps"] == 0 {
		return errors.New("bulk probe selected rate must be non-zero")
	}
	return nil
}

func validateFinalQUICBulkDecision(decision checkerRowBulkDecision) error {
	if decision.set && decision.mode != "quic" {
		return fmt.Errorf("bulk decision mode=%q, want quic for final QUIC block engine", decision.mode)
	}
	return nil
}

func (c *checker) validateRequiredFilePayloadEngine(required bool) error {
	if required && (!c.filePayloadObserved["file_payload_engine"] || !c.result.FinalFilePayloadEngine.Valid()) {
		return fmt.Errorf("file payload engine = %q, want valid engine telemetry", c.result.FinalFilePayloadEngine)
	}
	if c.opts.RequireFilePayloadEngine == "" {
		return nil
	}
	if !c.opts.RequireFilePayloadEngine.Valid() {
		return fmt.Errorf("required file payload engine %q is invalid", c.opts.RequireFilePayloadEngine)
	}
	if c.result.FinalFilePayloadEngine != c.opts.RequireFilePayloadEngine {
		return fmt.Errorf("file payload engine = %q, want %q", c.result.FinalFilePayloadEngine, c.opts.RequireFilePayloadEngine)
	}
	return nil
}

func (c *checker) validateSelectedEngineTelemetry() error {
	if err := validateObservedTelemetry(c.filePayloadObserved, []string{
		"file_payload_engine", "file_payload_bytes_committed", "file_payload_bytes_bulk",
		"file_payload_bytes_quic", "file_payload_lane_addrs",
	}); err != nil {
		return err
	}
	if err := c.validateFileSourceReads(); err != nil {
		return err
	}
	switch c.result.FinalFilePayloadEngine {
	case FilePayloadEngineBulk:
		return c.validateBulkEngineTelemetry()
	case FilePayloadEngineQUIC:
		return c.validateQUICEngineTelemetry()
	default:
		return fmt.Errorf("file payload engine = %q, want selected engine telemetry", c.result.FinalFilePayloadEngine)
	}
}

func (c *checker) validateFilePayloadCounters() error {
	if err := validateObservedTelemetry(c.filePayloadObserved, []string{
		"file_payload_bytes_committed", "file_payload_bytes_bulk", "file_payload_bytes_quic",
	}); err != nil {
		return err
	}
	if c.opts.Role == RoleReceive {
		return c.validateReceiverFilePayloadCounters()
	}
	if c.opts.Role == RoleSend {
		return c.validateSenderFilePayloadCounters()
	}
	return nil
}

func (c *checker) validateReceiverFilePayloadCounters() error {
	if c.result.FinalFilePayloadBytesBulk+c.result.FinalFilePayloadBytesQUIC != c.result.FinalFilePayloadBytes {
		return fmt.Errorf("file payload engine bytes = %d, committed = %d", c.result.FinalFilePayloadBytesBulk+c.result.FinalFilePayloadBytesQUIC, c.result.FinalFilePayloadBytes)
	}
	if c.expectedPayloadBytesSet() && c.result.FinalFilePayloadBytes != c.opts.ExpectedPayloadBytes {
		return fmt.Errorf("final file payload bytes = %d, want %d", c.result.FinalFilePayloadBytes, c.opts.ExpectedPayloadBytes)
	}
	selected, other := c.selectedAndOtherFilePayloadBytes()
	if other != 0 {
		return fmt.Errorf("file payload engine %q other engine bytes = %d, want 0", c.result.FinalFilePayloadEngine, other)
	}
	if c.expectedPayloadBytesSet() && selected != c.opts.ExpectedPayloadBytes {
		return fmt.Errorf("file payload engine %q bytes = %d, other engine bytes = %d, want %d and 0", c.result.FinalFilePayloadEngine, selected, other, c.opts.ExpectedPayloadBytes)
	}
	return nil
}

func (c *checker) selectedAndOtherFilePayloadBytes() (int64, int64) {
	if c.result.FinalFilePayloadEngine == FilePayloadEngineQUIC {
		return c.result.FinalFilePayloadBytesQUIC, c.result.FinalFilePayloadBytesBulk
	}
	return c.result.FinalFilePayloadBytesBulk, c.result.FinalFilePayloadBytesQUIC
}

func (c *checker) validateSenderFilePayloadCounters() error {
	if c.result.FinalFilePayloadBytes == 0 && c.result.FinalFilePayloadBytesBulk == 0 && c.result.FinalFilePayloadBytesQUIC == 0 {
		return nil
	}
	return fmt.Errorf("sender file payload counters = committed:%d bulk:%d quic:%d, want receiver-owned zeroes", c.result.FinalFilePayloadBytes, c.result.FinalFilePayloadBytesBulk, c.result.FinalFilePayloadBytesQUIC)
}

func (c *checker) validateSelectedPayloadLanes() error {
	if !c.opts.RequireEngineTelemetry && c.opts.ExpectedSelectedPublicIPv4 == "" {
		return nil
	}
	return validateFilePayloadLanes(c.result.FinalFilePayloadLaneAddresses, c.opts.ExpectedSelectedPublicIPv4)
}

func validateObservedTelemetry(observed map[string]bool, columns []string) error {
	for _, column := range columns {
		if !observed[column] {
			return fmt.Errorf("missing observed %s telemetry", column)
		}
	}
	return nil
}

func (c *checker) validateFileSourceReads() error {
	evidence := c.finalQUICEvidence
	for _, name := range []string{"file_source_read_calls", "file_source_read_bytes"} {
		if !evidence.observed[name] {
			return fmt.Errorf("missing observed %s telemetry", name)
		}
	}
	if c.opts.Role == RoleSend {
		if evidence.fileSourceReadCalls == 0 {
			return fmt.Errorf("file_source_read_calls = 0, want positive sender source reads")
		}
		if c.expectedPayloadBytesSet() && evidence.fileSourceReadBytes < uint64(c.opts.ExpectedPayloadBytes) {
			return fmt.Errorf("file_source_read_bytes = %d, want at least %d", evidence.fileSourceReadBytes, c.opts.ExpectedPayloadBytes)
		}
	}
	return nil
}

var checkerBulkCommonRequiredColumns = []string{
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
	"bulk_probe_selected_mbps",
	"bulk_probe_duration_ms",
	"bulk_probe_trains",
	"bulk_probe_sent_datagrams",
	"bulk_probe_received_datagrams",
	"bulk_probe_loss_ppm",
	"bulk_probe_pressure",
	"bulk_probe_stop_reason",
}

var checkerBulkSenderRequiredColumns = []string{
	"bulk_send_calls",
	"bulk_send_datagrams",
	"bulk_max_send_batch",
	"bulk_crypto_queue_peak",
	"bulk_lane_queue_peak",
}

var checkerBulkSenderDiagnosticColumns = []string{
	"repair_queue_bytes",
	"local_enobufs_retries",
	"local_enobufs_wait_us",
	"local_enobufs_max_consecutive",
	"peer_recv_queue_depth",
	"peer_recv_queue_depth_max",
	"retransmits",
	"repair_requests",
	"repair_bytes",
}

var checkerBulkReceiverRequiredColumns = []string{
	"bulk_receive_calls",
	"bulk_receive_datagrams",
	"bulk_max_receive_batch",
	"bulk_crypto_queue_peak",
	"bulk_writer_queue_peak",
	"bulk_receive_queue_peak",
	"bulk_decrypt_batches",
	"bulk_decrypt_datagrams",
}

var checkerBulkReceiverDiagnosticColumns = []string{
	"repair_requests",
	"missing_scan_checks",
	"pending_missing",
	"pending_missing_peak",
	"repair_requested_packets",
	"repair_request_batches",
	"reorder_trail_packets",
	"receive_packet_rate_pps",
}

func (c *checker) validateBulkEngineTelemetry() error {
	evidence := c.finalBulkEvidence
	if err := validateObservedTelemetry(evidence.observed, checkerBulkCommonRequiredColumns); err != nil {
		return err
	}
	if evidence.strings["bulk_candidate_id"] == "" || evidence.strings["bulk_batch_backend"] == "" {
		return errors.New("bulk candidate and batch backend must be non-empty")
	}
	if err := validateBulkProbeRelations(evidence); err != nil {
		return err
	}
	switch c.opts.Role {
	case RoleSend:
		return c.validateBulkSenderTelemetry(evidence)
	case RoleReceive:
		return c.validateBulkReceiverTelemetry(evidence)
	default:
		return fmt.Errorf("bulk telemetry role = %q, want send or receive", c.opts.Role)
	}
}

func validateBulkProbeRelations(evidence checkerRowBulkEvidence) error {
	sent := evidence.uints["bulk_probe_sent_datagrams"]
	received := evidence.uints["bulk_probe_received_datagrams"]
	if received > sent {
		return fmt.Errorf("bulk_probe_received_datagrams = %d, exceeds bulk_probe_sent_datagrams = %d", received, sent)
	}
	if evidence.uints["bulk_probe_loss_ppm"] > 1_000_000 {
		return fmt.Errorf("bulk_probe_loss_ppm = %d, want at most 1000000", evidence.uints["bulk_probe_loss_ppm"])
	}
	return nil
}

func (c *checker) validateBulkSenderTelemetry(evidence checkerRowBulkEvidence) error {
	if err := validateObservedTelemetry(evidence.observed, checkerBulkSenderRequiredColumns); err != nil {
		return err
	}
	if err := validateObservedTelemetry(c.finalDiagnostics().observed, checkerBulkSenderDiagnosticColumns); err != nil {
		return err
	}
	if err := c.validateBulkNativeSenderRelations(evidence); err != nil {
		return err
	}
	return validateBulkSenderQueueAndRepairRelations(c.finalDiagnostics())
}

func (c *checker) validateBulkNativeSenderRelations(evidence checkerRowBulkEvidence) error {
	attempts := evidence.uints["bulk_native_send_attempts"]
	syscalls := evidence.uints["bulk_native_send_syscalls"]
	successfulCalls := evidence.uints["bulk_send_calls"]
	logicalDatagrams := evidence.uints["bulk_logical_datagrams"]
	acceptedPayload := evidence.uints["bulk_accepted_payload_bytes"]
	if attempts == 0 || attempts < syscalls {
		return fmt.Errorf("bulk_native_send_attempts = %d, want positive and at least bulk_native_send_syscalls = %d", attempts, syscalls)
	}
	if syscalls == 0 || syscalls < successfulCalls {
		return fmt.Errorf("bulk_native_send_syscalls = %d, want positive and at least bulk_send_calls = %d", syscalls, successfulCalls)
	}
	if successfulCalls == 0 || logicalDatagrams < successfulCalls {
		return fmt.Errorf("bulk_logical_datagrams = %d, want at least positive bulk_send_calls = %d", logicalDatagrams, successfulCalls)
	}
	if c.expectedPayloadBytesSet() && acceptedPayload < uint64(c.opts.ExpectedPayloadBytes) {
		return fmt.Errorf("bulk_accepted_payload_bytes = %d, want at least %d", acceptedPayload, c.opts.ExpectedPayloadBytes)
	}
	return validateBulkGSOActiveRelations(evidence)
}

func validateBulkGSOActiveRelations(evidence checkerRowBulkEvidence) error {
	if !evidence.bools["bulk_gso_active"] {
		return nil
	}
	if !evidence.bools["bulk_gso_attempted"] {
		return errors.New("bulk_gso_active = true, want bulk_gso_attempted = true")
	}
	if evidence.uints["bulk_gso_messages"] == 0 {
		return errors.New("bulk_gso_messages = 0, want positive while GSO is active")
	}
	if evidence.uints["bulk_gso_segments"] == 0 {
		return errors.New("bulk_gso_segments = 0, want positive while GSO is active")
	}
	if evidence.uints["bulk_gso_segments_per_message"] == 0 {
		return errors.New("bulk_gso_segments_per_message = 0, want positive while GSO is active")
	}
	return nil
}

func validateBulkSenderQueueAndRepairRelations(diagnostics checkerRowDiagnostics) error {
	if err := validateBulkPeerQueueRelations(diagnostics); err != nil {
		return err
	}
	if err := validateBulkENOBUFSRelations(diagnostics); err != nil {
		return err
	}
	return validateBulkRepairRelations(diagnostics)
}

func validateBulkPeerQueueRelations(diagnostics checkerRowDiagnostics) error {
	if diagnostics.peerRecvQueueDepth < 0 || diagnostics.peerRecvQueueDepthMax < 0 || diagnostics.peerRecvQueueDepth > diagnostics.peerRecvQueueDepthMax {
		return fmt.Errorf("peer_recv_queue_depth = %d, want non-negative and at most peer_recv_queue_depth_max = %d", diagnostics.peerRecvQueueDepth, diagnostics.peerRecvQueueDepthMax)
	}
	return nil
}

func validateBulkENOBUFSRelations(diagnostics checkerRowDiagnostics) error {
	if diagnostics.localENOBUFSRetries < 0 || diagnostics.localENOBUFSWaitUS < 0 || diagnostics.localENOBUFSMaxConsecutive < 0 {
		return errors.New("local ENOBUFS telemetry must be non-negative")
	}
	if diagnostics.localENOBUFSMaxConsecutive > diagnostics.localENOBUFSRetries {
		return fmt.Errorf("local_enobufs_max_consecutive = %d, exceeds local_enobufs_retries = %d", diagnostics.localENOBUFSMaxConsecutive, diagnostics.localENOBUFSRetries)
	}
	return nil
}

func validateBulkRepairRelations(diagnostics checkerRowDiagnostics) error {
	if diagnostics.retransmits < 0 || diagnostics.repairRequests < 0 || diagnostics.repairBytes < 0 {
		return errors.New("bulk repair telemetry must be non-negative")
	}
	return nil
}

func (c *checker) validateBulkReceiverTelemetry(evidence checkerRowBulkEvidence) error {
	if err := validateObservedTelemetry(evidence.observed, checkerBulkReceiverRequiredColumns); err != nil {
		return err
	}
	if err := validateObservedTelemetry(c.finalDiagnostics().observed, checkerBulkReceiverDiagnosticColumns); err != nil {
		return err
	}
	if err := validateBulkReceiverNativeZeroes(evidence); err != nil {
		return err
	}
	if err := validateBulkReceiverBatchRelations(evidence); err != nil {
		return err
	}
	return validateBulkReceiverRepairRelations(c.finalDiagnostics())
}

func validateBulkReceiverNativeZeroes(evidence checkerRowBulkEvidence) error {
	for _, name := range []string{
		"bulk_native_send_attempts", "bulk_native_send_syscalls", "bulk_gso_messages",
		"bulk_logical_datagrams", "bulk_accepted_payload_bytes", "bulk_gso_segments_per_message",
		"bulk_gso_segments", "bulk_send_calls", "bulk_send_datagrams", "bulk_max_send_batch",
	} {
		if evidence.uints[name] != 0 {
			return fmt.Errorf("receiver bulk native send counters must be zero: %s = %d", name, evidence.uints[name])
		}
	}
	if evidence.bools["bulk_gso_attempted"] || evidence.bools["bulk_gso_active"] {
		return errors.New("receiver bulk native send counters must be zero: GSO state is true")
	}
	return nil
}

func validateBulkReceiverBatchRelations(evidence checkerRowBulkEvidence) error {
	receiveCalls := evidence.uints["bulk_receive_calls"]
	receiveDatagrams := evidence.uints["bulk_receive_datagrams"]
	if receiveCalls == 0 || receiveDatagrams < receiveCalls {
		return fmt.Errorf("bulk_receive_datagrams = %d, want at least positive bulk_receive_calls = %d", receiveDatagrams, receiveCalls)
	}
	if evidence.uints["bulk_max_receive_batch"] == 0 {
		return errors.New("bulk_max_receive_batch = 0, want positive")
	}
	if evidence.uints["bulk_decrypt_datagrams"] < evidence.uints["bulk_decrypt_batches"] {
		return fmt.Errorf("bulk_decrypt_datagrams = %d, want at least bulk_decrypt_batches = %d", evidence.uints["bulk_decrypt_datagrams"], evidence.uints["bulk_decrypt_batches"])
	}
	return nil
}

func validateBulkReceiverRepairRelations(diagnostics checkerRowDiagnostics) error {
	if diagnostics.repairRequests < 0 {
		return errors.New("bulk repair telemetry must be non-negative")
	}
	if diagnostics.pendingMissing > diagnostics.pendingMissingPeak {
		return fmt.Errorf("pending_missing = %d, exceeds pending_missing_peak = %d", diagnostics.pendingMissing, diagnostics.pendingMissingPeak)
	}
	if diagnostics.repairRequestBatches > diagnostics.repairRequestedPackets {
		return fmt.Errorf("repair_request_batches = %d, exceeds repair_requested_packets = %d", diagnostics.repairRequestBatches, diagnostics.repairRequestedPackets)
	}
	return nil
}

func (c *checker) finalDiagnostics() checkerRowDiagnostics {
	return c.finalRowDiagnostics
}

func (c *checker) validateQUICEngineTelemetry() error {
	evidence := c.finalQUICEvidence
	if err := validateQUICObservedTelemetry(evidence); err != nil {
		return err
	}
	if err := validateQUICIdentityAndTiming(evidence); err != nil {
		return err
	}
	if err := validateQUICPacketRelations(evidence, c.opts.Role); err != nil {
		return err
	}
	if err := c.validateQUICPayloadAndClose(evidence); err != nil {
		return err
	}
	return validateQUICNativeStates(evidence)
}

func validateQUICObservedTelemetry(evidence checkerRowQUICEvidence) error {
	for _, name := range checkerQUICEvidenceColumns {
		if name != "file_source_read_calls" && name != "file_source_read_bytes" && !evidence.observed[name] {
			return fmt.Errorf("missing observed %s telemetry", name)
		}
	}
	return nil
}

func validateQUICIdentityAndTiming(evidence checkerRowQUICEvidence) error {
	if !evidence.telemetryPresent {
		return fmt.Errorf("quic_telemetry_present = false, want true")
	}
	if evidence.connections == 0 {
		return fmt.Errorf("quic_connections = 0, want positive")
	}
	if evidence.streams == 0 {
		return fmt.Errorf("quic_streams = 0, want positive")
	}
	if evidence.handshakeMS <= 0 {
		return fmt.Errorf("quic_handshake_ms = %d, want positive", evidence.handshakeMS)
	}
	if evidence.firstByteMS <= 0 {
		return fmt.Errorf("quic_first_byte_ms = %d, want positive", evidence.firstByteMS)
	}
	if evidence.smoothedRTTMS <= 0 {
		return fmt.Errorf("quic_smoothed_rtt_ms = %g, want positive", evidence.smoothedRTTMS)
	}
	return nil
}

func validateQUICPacketRelations(evidence checkerRowQUICEvidence, role Role) error {
	if role == RoleSend {
		if evidence.packetsSent == 0 {
			return fmt.Errorf("quic_packets_sent = 0, want positive sender packet evidence")
		}
		if evidence.wireBytesSent == 0 {
			return fmt.Errorf("quic_wire_bytes_sent = 0, want positive sender wire evidence")
		}
	}
	if role == RoleReceive && evidence.packetsReceived == 0 {
		return fmt.Errorf("quic_packets_received = 0, want positive receiver packet evidence")
	}
	if evidence.packetsLost > evidence.packetsSent {
		return fmt.Errorf("quic_packets_lost = %d, exceeds quic_packets_sent = %d", evidence.packetsLost, evidence.packetsSent)
	}
	if evidence.recoveryWireBytes > evidence.wireBytesSent {
		return fmt.Errorf("quic_recovery_wire_bytes = %d, exceeds quic_wire_bytes_sent = %d", evidence.recoveryWireBytes, evidence.wireBytesSent)
	}
	initialWireBytes := evidence.wireBytesSent - evidence.recoveryWireBytes
	wantRecoveryRatio := float64(evidence.recoveryWireBytes) / float64(max(uint64(1), initialWireBytes))
	if math.Abs(evidence.recoveryRatio-wantRecoveryRatio) > 0.000001 {
		return fmt.Errorf("quic_recovery_ratio = %g, want %g", evidence.recoveryRatio, wantRecoveryRatio)
	}
	return nil
}

func (c *checker) validateQUICPayloadAndClose(evidence checkerRowQUICEvidence) error {
	if c.expectedPayloadBytesSet() {
		if c.opts.Role == RoleSend && evidence.streamBytesSent < c.opts.ExpectedPayloadBytes {
			return fmt.Errorf("quic_stream_bytes_sent = %d, want at least %d", evidence.streamBytesSent, c.opts.ExpectedPayloadBytes)
		}
		if c.opts.Role == RoleReceive && evidence.streamBytesReceived < c.opts.ExpectedPayloadBytes {
			return fmt.Errorf("quic_stream_bytes_received = %d, want at least %d", evidence.streamBytesReceived, c.opts.ExpectedPayloadBytes)
		}
	}
	if evidence.closeReason != "complete" && evidence.closeReason != "normal" {
		return fmt.Errorf("quic_close_reason = %q, want normal completion", evidence.closeReason)
	}
	return nil
}

func validateQUICNativeStates(evidence checkerRowQUICEvidence) error {
	for name, state := range map[string]string{
		"quic_native_gso":           evidence.nativeGSO,
		"quic_native_receive_batch": evidence.nativeReceiveBatch,
	} {
		if state != "true" && state != "false" && state != "unsupported" {
			return fmt.Errorf("%s = %q, want true, false, or unsupported", name, state)
		}
	}
	return nil
}

func validateFilePayloadLanes(lanes []string, expectedIPv4 string) error {
	if len(lanes) == 0 {
		return errors.New("file payload lane addresses are empty")
	}
	expected, err := parseExpectedFilePayloadIPv4(expectedIPv4)
	if err != nil {
		return err
	}
	seen := make(map[netip.AddrPort]struct{}, len(lanes))
	for _, lane := range lanes {
		if err := validateFilePayloadLane(lane, expected, seen); err != nil {
			return err
		}
	}
	return nil
}

func parseExpectedFilePayloadIPv4(value string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	expected, err := netip.ParseAddr(value)
	if err != nil || !expected.Is4() || !publicFilePayloadAddr(expected) {
		return netip.Addr{}, fmt.Errorf("expected selected public IPv4 %q is invalid", value)
	}
	return expected, nil
}

func validateFilePayloadLane(lane string, expected netip.Addr, seen map[netip.AddrPort]struct{}) error {
	addrPort, err := netip.ParseAddrPort(lane)
	if err != nil {
		return fmt.Errorf("parse file payload lane address %q: %w", lane, err)
	}
	addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
	if _, duplicate := seen[addrPort]; duplicate {
		return fmt.Errorf("duplicate file payload lane address %q", lane)
	}
	seen[addrPort] = struct{}{}
	if !publicFilePayloadAddr(addrPort.Addr()) {
		return fmt.Errorf("file payload lane address %q is not public", lane)
	}
	if expected.IsValid() && addrPort.Addr() != expected {
		return fmt.Errorf("file payload lane IP = %s, want %s", addrPort.Addr(), expected)
	}
	return nil
}

func publicFilePayloadAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsMulticast() && !addr.IsUnspecified() && !cgnat.Contains(addr)
}

func (c *checker) recordReceiverRateSummary() {
	if len(c.receiverRates) == 0 {
		return
	}
	diagnostics := &c.result.Diagnostics
	diagnostics.ReceiverRateP10Mbps = checkerPercentile(c.receiverRates, 0.10)
	diagnostics.ReceiverRateP50Mbps = checkerPercentile(c.receiverRates, 0.50)
	diagnostics.ReceiverRateP90Mbps = checkerPercentile(c.receiverRates, 0.90)
	diagnostics.ReceiverRateCV = checkerCoefficientOfVariation(c.receiverRates)
	for _, rate := range c.receiverRates {
		if rate < 500 {
			diagnostics.ReceiverWindowsBelow500Mbps++
		}
	}
	diagnostics.ReceiverRateObserved = true
}

func checkerPercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	slices.Sort(values)
	position := float64(len(values)-1) * percentile
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	weight := position - float64(lower)
	return values[lower]*(1-weight) + values[upper]*weight
}

func checkerCoefficientOfVariation(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := 0.0
	for _, value := range values {
		mean += value
	}
	mean /= float64(len(values))
	if mean == 0 {
		return 0
	}
	variance := 0.0
	for _, value := range values {
		delta := value - mean
		variance += delta * delta
	}
	return math.Sqrt(variance/float64(len(values))) / mean
}

func readCheckerRows(r io.Reader, role Role) ([]checkerRow, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	indexes, err := checkerHeaderIndexes(header)
	if err != nil {
		return nil, err
	}
	if indexes.peerReceivedBytes < 0 {
		return nil, fmt.Errorf("missing required header %q for peer trace check", "peer_received_bytes")
	}
	rowNo := 1
	var rows []checkerRow
	for {
		record, err := cr.Read()
		rowNo++
		if err == io.EOF {
			return rows, nil
		}
		if err != nil {
			return nil, fmt.Errorf("row %d: read row: %w", rowNo, err)
		}
		if Role(field(record, indexes.role)) != role {
			continue
		}
		row, err := parseCheckerRow(record, indexes, rowNo)
		if err != nil {
			return nil, err
		}
		if err := validateReadCheckerRow(row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
}

func validateReadCheckerRow(row checkerRow) error {
	if row.lastError != "" {
		return fmt.Errorf("row %d: terminal error: %s", row.rowNo, row.lastError)
	}
	return validateCheckerRowStatus(row)
}

func compareCheckerPair(primaryRows []checkerRow, peerRows []checkerRow, opts PairOptions) (PairResult, error) {
	senderRows, receiverRows := senderReceiverRows(primaryRows, peerRows, opts.Role)
	senderFinal := senderRows[len(senderRows)-1]
	receiverFinal := receiverRows[len(receiverRows)-1]
	if !senderFinal.filePayload.engine.Valid() || !receiverFinal.filePayload.engine.Valid() {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("sender/receiver file payload engines must both be valid: sender=%q receiver=%q", senderFinal.filePayload.engine, receiverFinal.filePayload.engine)
	}
	if senderFinal.filePayload.engine != receiverFinal.filePayload.engine {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("sender file payload engine = %q, receiver = %q", senderFinal.filePayload.engine, receiverFinal.filePayload.engine)
	}
	if err := compareCheckerPairBulkDecision(senderFinal.bulkDecision, receiverFinal.bulkDecision); err != nil {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, err
	}
	if senderFinal.phase != PhaseComplete {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("sender final phase = %s, want %s", senderFinal.phase, PhaseComplete)
	}
	if receiverFinal.phase != PhaseComplete {
		return PairResult{PrimaryRows: len(primaryRows), PeerRows: len(peerRows)}, fmt.Errorf("receiver final phase = %s, want %s", receiverFinal.phase, PhaseComplete)
	}
	delta := absInt64(senderFinal.peerReceivedBytes - receiverFinal.appBytes)
	maxLead := maxSenderProgressLead(senderRows, receiverRows)
	result := PairResult{
		PrimaryRows:          len(primaryRows),
		PeerRows:             len(peerRows),
		ProgressDeltaBytes:   delta,
		MaxProgressLeadBytes: maxLead,
		SenderRateMbps:       mbps(senderFinal.peerReceivedBytes, senderFinal.transferElapsedMS),
		ReceiverRateMbps:     mbps(receiverFinal.appBytes, receiverFinal.transferElapsedMS),
	}
	if delta != 0 {
		return result, fmt.Errorf("sender peer_received_bytes = %d, receiver app_bytes = %d", senderFinal.peerReceivedBytes, receiverFinal.appBytes)
	}
	if maxLead > opts.ProgressLeadToleranceBytes {
		return result, fmt.Errorf("sender progress leads receiver by %d bytes, tolerance=%d", maxLead, opts.ProgressLeadToleranceBytes)
	}
	if rateDiverged(result.SenderRateMbps, result.ReceiverRateMbps, opts.RateTolerance) {
		return result, fmt.Errorf("transfer rate diverged: sender_peer_mbps=%.2f receiver_mbps=%.2f tolerance=%.2f", result.SenderRateMbps, result.ReceiverRateMbps, normalizedRateTolerance(opts.RateTolerance))
	}
	return result, nil
}

func compareCheckerPairBulkDecision(sender, receiver checkerRowBulkDecision) error {
	if sender.set != receiver.set {
		return fmt.Errorf("sender/receiver bulk decision presence differs: sender=%t receiver=%t", sender.set, receiver.set)
	}
	if !sender.set {
		return nil
	}
	if sender.mode != receiver.mode {
		return fmt.Errorf("sender bulk decision mode = %q, receiver = %q", sender.mode, receiver.mode)
	}
	if sender.reason != receiver.reason {
		return fmt.Errorf("sender bulk decision reason = %q, receiver = %q", sender.reason, receiver.reason)
	}
	if sender.runID != receiver.runID {
		return fmt.Errorf("sender bulk decision run ID = %d, receiver = %d", sender.runID, receiver.runID)
	}
	return nil
}

func senderReceiverRows(primaryRows []checkerRow, peerRows []checkerRow, role Role) ([]checkerRow, []checkerRow) {
	if role == RoleSend {
		return primaryRows, peerRows
	}
	return peerRows, primaryRows
}

func maxSenderProgressLead(senderRows []checkerRow, receiverRows []checkerRow) int64 {
	var maxLead int64
	receiverIndex := 0
	var receiverBytes int64
	useTransferElapsed := useTransferElapsedForProgressLead(senderRows, receiverRows)
	receiverBaseElapsed := firstReceiverAppElapsedMS(receiverRows)
	for _, sender := range senderRows {
		if sender.phase == PhaseComplete {
			continue
		}
		senderElapsed := comparableElapsed(sender, useTransferElapsed, 0)
		for receiverIndex < len(receiverRows) && comparableElapsed(receiverRows[receiverIndex], useTransferElapsed, receiverBaseElapsed) <= senderElapsed {
			if receiverRows[receiverIndex].appBytes > receiverBytes {
				receiverBytes = receiverRows[receiverIndex].appBytes
			}
			receiverIndex++
		}
		lead := sender.peerReceivedBytes - receiverBytes
		if lead > maxLead {
			maxLead = lead
		}
	}
	return maxLead
}

func useTransferElapsedForProgressLead(senderRows []checkerRow, receiverRows []checkerRow) bool {
	senderHasTransferElapsed := false
	for _, row := range senderRows {
		if row.peerReceivedBytes > 0 && row.transferElapsedMS > 0 {
			senderHasTransferElapsed = true
			break
		}
	}
	if !senderHasTransferElapsed {
		return false
	}
	for _, row := range receiverRows {
		if row.appBytes > 0 && (row.transferElapsedMS > 0 || row.elapsedMS > 0) {
			return true
		}
	}
	return false
}

func firstReceiverAppElapsedMS(rows []checkerRow) int64 {
	for _, row := range rows {
		if row.appBytes > 0 && row.elapsedMS > 0 {
			return row.elapsedMS
		}
	}
	return 0
}

func comparableElapsed(row checkerRow, useTransferElapsed bool, receiverBaseElapsed int64) int64 {
	if useTransferElapsed {
		if row.transferElapsedMS > 0 {
			return row.transferElapsedMS
		}
		if receiverBaseElapsed > 0 && row.elapsedMS > 0 {
			return row.elapsedMS - receiverBaseElapsed
		}
	}
	return row.timestamp.UnixMilli()
}

func oppositeRole(role Role) Role {
	if role == RoleSend {
		return RoleReceive
	}
	return RoleSend
}

func mbps(bytes int64, elapsedMS int64) float64 {
	if bytes <= 0 || elapsedMS <= 0 {
		return 0
	}
	return float64(bytes*8) / float64(elapsedMS*1000)
}

func rateDiverged(a float64, b float64, tolerance float64) bool {
	if a == 0 || b == 0 {
		return false
	}
	maxRate := math.Max(a, b)
	if maxRate == 0 {
		return false
	}
	return math.Abs(a-b)/maxRate > normalizedRateTolerance(tolerance)
}

func normalizedRateTolerance(tolerance float64) float64 {
	if tolerance <= 0 {
		return 0.10
	}
	return tolerance
}

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func (c *checker) expectedBytesSet() bool {
	return c.opts.ExpectedBytesSet || c.opts.ExpectedBytes > 0
}

func (c *checker) expectedPayloadBytesSet() bool {
	return c.opts.ExpectedPayloadBytesSet || c.opts.ExpectedPayloadBytes > 0
}

func (c *checker) noRowsError() error {
	if c.opts.Role != "" {
		return fmt.Errorf("no rows matched role %q", c.opts.Role)
	}
	return fmt.Errorf("no rows")
}

func checkerHeaderIndexes(header []string) (checkerIndexes, error) {
	positions := map[string]int{}
	for i, name := range header {
		positions[name] = i
	}
	lookup := func(name string) (int, error) {
		i, ok := positions[name]
		if !ok {
			return 0, fmt.Errorf("missing required header %q", name)
		}
		return i, nil
	}
	optional := func(name string) int {
		if i, ok := positions[name]; ok {
			return i
		}
		return -1
	}

	timestamp, timestampName, err := lookupTimestamp(positions)
	if err != nil {
		return checkerIndexes{}, err
	}
	role, err := lookup("role")
	if err != nil {
		return checkerIndexes{}, err
	}
	phase, err := lookup("phase")
	if err != nil {
		return checkerIndexes{}, err
	}
	appBytes, err := lookup("app_bytes")
	if err != nil {
		return checkerIndexes{}, err
	}
	lastError, err := lookup("last_error")
	if err != nil {
		return checkerIndexes{}, err
	}
	return checkerIndexes{
		fields:               len(header),
		header:               append([]string(nil), header...),
		timestamp:            timestamp,
		timestampName:        timestampName,
		role:                 role,
		phase:                phase,
		relayBytes:           optional("relay_bytes"),
		elapsedMS:            optional("elapsed_ms"),
		appBytes:             appBytes,
		appMbps:              optional("app_mbps"),
		peerReceivedBytes:    optional("peer_received_bytes"),
		transferElapsedMS:    optional("transfer_elapsed_ms"),
		directValidated:      optional("direct_validated"),
		fallbackReason:       optional("fallback_reason"),
		lastState:            optional("last_state"),
		lastError:            lastError,
		controllerDecision:   optional("controller_decision"),
		directTransport:      optional("direct_transport"),
		filePayloadEngine:    optional("file_payload_engine"),
		filePayloadCommitted: optional("file_payload_bytes_committed"),
		filePayloadBulk:      optional("file_payload_bytes_bulk"),
		filePayloadQUIC:      optional("file_payload_bytes_quic"),
		filePayloadLaneAddrs: optional("file_payload_lane_addrs"),
		bulkDecisionMode:     optional("bulk_decision_mode"),
		bulkDecisionReason:   optional("bulk_decision_reason"),
		bulkDecisionRunID:    optional("bulk_decision_run_id"),
		senderHealthSchema:   checkerSenderHealthSchema(positions),
		receiverRepairSchema: checkerReceiverRepairSchema(positions),
		numericDiagnostics:   checkerNumericDiagnostics(positions),
		quicEvidence:         checkerEvidenceIndexes(positions),
		bulkEvidence:         checkerBulkEvidenceIndexes(positions),
	}, nil
}

func checkerEvidenceIndexes(positions map[string]int) map[string]int {
	indexes := make(map[string]int, len(checkerQUICEvidenceColumns))
	for _, name := range checkerQUICEvidenceColumns {
		if index, ok := positions[name]; ok {
			indexes[name] = index
		} else {
			indexes[name] = -1
		}
	}
	return indexes
}

func checkerBulkEvidenceIndexes(positions map[string]int) map[string]int {
	indexes := make(map[string]int, len(checkerBulkEvidenceColumns))
	for _, name := range checkerBulkEvidenceColumns {
		if index, ok := positions[name]; ok {
			indexes[name] = index
		} else {
			indexes[name] = -1
		}
	}
	return indexes
}

func checkerReceiverRepairSchema(positions map[string]int) bool {
	for _, name := range receiverRepairDiagnosticColumns {
		if _, ok := positions[name]; !ok {
			return false
		}
	}
	return true
}

func checkerSenderHealthSchema(positions map[string]int) bool {
	for _, name := range []string{
		"rate_target_mbps",
		"controller_decision",
		"retransmits",
		"repair_bytes",
		"local_enobufs_retries",
		"local_enobufs_wait_us",
		"local_enobufs_max_consecutive",
	} {
		if _, ok := positions[name]; !ok {
			return false
		}
	}
	return true
}

func checkerNumericDiagnostics(positions map[string]int) []checkerNumericDiagnostic {
	diagnostics := make([]checkerNumericDiagnostic, 0, len(checkerNumericDiagnosticColumns))
	for _, column := range checkerNumericDiagnosticColumns {
		index, ok := positions[column.name]
		if !ok {
			continue
		}
		diagnostics = append(diagnostics, checkerNumericDiagnostic{
			name:  column.name,
			index: index,
			kind:  column.kind,
		})
	}
	return diagnostics
}

func lookupTimestamp(positions map[string]int) (int, string, error) {
	if i, ok := positions["timestamp_unix_ms"]; ok {
		return i, "timestamp_unix_ms", nil
	}
	if i, ok := positions["timestamp_ms"]; ok {
		return i, "timestamp_ms", nil
	}
	return 0, "", fmt.Errorf("missing required timestamp header %q or %q", "timestamp_unix_ms", "timestamp_ms")
}

func parseCheckerRow(record []string, indexes checkerIndexes, rowNo int) (checkerRow, error) {
	var err error
	record, err = normalizeCheckerRecord(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	if err := requireCheckerRowFields(record, indexes, rowNo); err != nil {
		return checkerRow{}, err
	}
	fields, err := parseCheckerRowFields(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	role := Role(field(record, indexes.role))
	phase := Phase(field(record, indexes.phase))
	diagnostics, err := parseCheckerRowDiagnostics(record, indexes, rowNo, role, phase)
	if err != nil {
		return checkerRow{}, err
	}
	filePayload, err := parseCheckerRowFilePayload(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	quicEvidence, err := parseCheckerRowQUICEvidence(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	bulkEvidence, err := parseCheckerRowBulkEvidence(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	bulkDecision, err := parseCheckerRowBulkDecision(record, indexes, rowNo)
	if err != nil {
		return checkerRow{}, err
	}
	return checkerRow{
		rowNo:              rowNo,
		role:               role,
		timestamp:          time.UnixMilli(fields.timestampMS),
		elapsedMS:          fields.elapsedMS,
		phase:              phase,
		appBytes:           fields.appBytes,
		relayBytes:         fields.relayBytes,
		peerReceivedBytes:  fields.peerReceivedBytes,
		transferElapsedMS:  fields.transferElapsedMS,
		directValidated:    fields.directValidated,
		fallbackReason:     field(record, indexes.fallbackReason),
		lastState:          field(record, indexes.lastState),
		lastError:          field(record, indexes.lastError),
		controllerDecision: field(record, indexes.controllerDecision),
		filePayload:        filePayload,
		quicEvidence:       quicEvidence,
		bulkEvidence:       bulkEvidence,
		bulkDecision:       bulkDecision,
		diagnostics:        diagnostics,
	}, nil
}

func parseCheckerRowBulkDecision(record []string, indexes checkerIndexes, rowNo int) (checkerRowBulkDecision, error) {
	decision := checkerRowBulkDecision{
		mode:   field(record, indexes.bulkDecisionMode),
		reason: field(record, indexes.bulkDecisionReason),
	}
	rawRunID := field(record, indexes.bulkDecisionRunID)
	set, err := checkerBulkDecisionFieldsSet(decision, rawRunID, rowNo)
	if err != nil {
		return checkerRowBulkDecision{}, err
	}
	if !set {
		return decision, nil
	}
	runID, err := strconv.ParseUint(rawRunID, 10, 64)
	if err != nil || runID == 0 {
		return checkerRowBulkDecision{}, fmt.Errorf("row %d: bulk decision run ID = %q, want non-zero decimal", rowNo, rawRunID)
	}
	decision.runID = runID
	decision.set = true
	if err := validateCheckerRowBulkDecisionReason(decision, rowNo); err != nil {
		return checkerRowBulkDecision{}, err
	}
	return decision, nil
}

func checkerBulkDecisionFieldsSet(decision checkerRowBulkDecision, rawRunID string, rowNo int) (bool, error) {
	fields := 0
	for _, value := range []string{decision.mode, decision.reason, rawRunID} {
		if value != "" {
			fields++
		}
	}
	switch fields {
	case 0:
		return false, nil
	case 3:
		return true, nil
	default:
		return false, fmt.Errorf("row %d: bulk decision mode, reason, and run ID must be set together", rowNo)
	}
}

func validateCheckerRowBulkDecisionReason(decision checkerRowBulkDecision, rowNo int) error {
	switch decision.mode {
	case "bulk-packets-v1":
		if decision.reason != "both-probes-accepted" {
			return fmt.Errorf("row %d: bulk decision reason %q is invalid for bulk-packets-v1", rowNo, decision.reason)
		}
	case "quic":
		switch decision.reason {
		case "sender-probe-rejected", "receiver-probe-rejected", "receiver-readiness-timeout":
		default:
			return fmt.Errorf("row %d: bulk decision reason %q is invalid for quic", rowNo, decision.reason)
		}
	default:
		return fmt.Errorf("row %d: bulk decision mode %q is invalid", rowNo, decision.mode)
	}
	return nil
}

func parseCheckerRowFilePayload(record []string, indexes checkerIndexes, rowNo int) (checkerRowFilePayload, error) {
	payload := checkerRowFilePayload{observed: make(map[string]bool)}
	engineValue := field(record, indexes.filePayloadEngine)
	if engineValue != "" {
		engine, err := ParseFilePayloadEngine(engineValue)
		if err != nil {
			return checkerRowFilePayload{}, fmt.Errorf("row %d: %w", rowNo, err)
		}
		payload.engine = engine
		payload.observed["file_payload_engine"] = true
	}
	for _, counter := range []struct {
		name  string
		index int
		value *int64
	}{
		{name: "file_payload_bytes_committed", index: indexes.filePayloadCommitted, value: &payload.committed},
		{name: "file_payload_bytes_bulk", index: indexes.filePayloadBulk, value: &payload.bulk},
		{name: "file_payload_bytes_quic", index: indexes.filePayloadQUIC, value: &payload.quic},
	} {
		value := field(record, counter.index)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 0 {
			return checkerRowFilePayload{}, fmt.Errorf("row %d: parse %s %q as non-negative decimal", rowNo, counter.name, value)
		}
		*counter.value = parsed
		payload.observed[counter.name] = true
	}
	laneValue := field(record, indexes.filePayloadLaneAddrs)
	if laneValue != "" {
		if err := json.Unmarshal([]byte(laneValue), &payload.laneAddresses); err != nil {
			return checkerRowFilePayload{}, fmt.Errorf("row %d: parse file_payload_lane_addrs as JSON array: %w", rowNo, err)
		}
		if payload.laneAddresses == nil {
			payload.laneAddresses = []string{}
		}
		payload.observed["file_payload_lane_addrs"] = true
	}
	return payload, nil
}

func parseCheckerRowQUICEvidence(record []string, indexes checkerIndexes, rowNo int) (checkerRowQUICEvidence, error) {
	evidence := checkerRowQUICEvidence{observed: make(map[string]bool)}
	parseCheckerQUICStrings(record, indexes, &evidence)
	if err := parseCheckerQUICTelemetryPresent(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowQUICEvidence{}, err
	}
	if err := parseCheckerQUICUintCounters(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowQUICEvidence{}, err
	}
	if err := parseCheckerQUICIntCounters(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowQUICEvidence{}, err
	}
	if err := parseCheckerQUICFloatCounters(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowQUICEvidence{}, err
	}
	return evidence, nil
}

func checkerEvidenceValue(record []string, indexes map[string]int, name string) string {
	index, ok := indexes[name]
	if !ok {
		return ""
	}
	return field(record, index)
}

func parseCheckerQUICStrings(record []string, indexes checkerIndexes, evidence *checkerRowQUICEvidence) {
	for _, item := range []struct {
		name string
		dst  *string
	}{
		{"quic_version", &evidence.version},
		{"quic_raw_socket_backend", &evidence.rawSocketBackend},
		{"quic_native_send_backend", &evidence.nativeSendBackend},
		{"quic_native_receive_backend", &evidence.nativeReceiveBackend},
		{"quic_close_reason", &evidence.closeReason},
		{"quic_native_gso", &evidence.nativeGSO},
		{"quic_native_receive_batch", &evidence.nativeReceiveBatch},
	} {
		if raw := checkerEvidenceValue(record, indexes.quicEvidence, item.name); raw != "" {
			*item.dst = raw
			evidence.observed[item.name] = true
		}
	}
}

func parseCheckerQUICTelemetryPresent(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowQUICEvidence) error {
	raw := checkerEvidenceValue(record, indexes.quicEvidence, "quic_telemetry_present")
	if raw == "" {
		return nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("row %d: parse quic_telemetry_present %q as boolean", rowNo, raw)
	}
	evidence.telemetryPresent = parsed
	evidence.observed["quic_telemetry_present"] = true
	return nil
}

func parseCheckerQUICUintCounters(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowQUICEvidence) error {
	for _, counter := range []struct {
		name string
		dst  *uint64
	}{
		{"quic_connections", &evidence.connections},
		{"quic_streams", &evidence.streams},
		{"quic_packets_sent", &evidence.packetsSent},
		{"quic_packets_received", &evidence.packetsReceived},
		{"quic_packets_lost", &evidence.packetsLost},
		{"quic_wire_bytes_sent", &evidence.wireBytesSent},
		{"quic_recovery_wire_bytes", &evidence.recoveryWireBytes},
		{"file_source_read_calls", &evidence.fileSourceReadCalls},
		{"file_source_read_bytes", &evidence.fileSourceReadBytes},
	} {
		raw := checkerEvidenceValue(record, indexes.quicEvidence, counter.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("row %d: parse %s %q as non-negative decimal", rowNo, counter.name, raw)
		}
		*counter.dst = parsed
		evidence.observed[counter.name] = true
	}
	return nil
}

func parseCheckerQUICIntCounters(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowQUICEvidence) error {
	for _, counter := range []struct {
		name string
		dst  *int64
	}{
		{"quic_handshake_ms", &evidence.handshakeMS},
		{"quic_first_byte_ms", &evidence.firstByteMS},
		{"quic_stream_bytes_sent", &evidence.streamBytesSent},
		{"quic_stream_bytes_received", &evidence.streamBytesReceived},
	} {
		raw := checkerEvidenceValue(record, indexes.quicEvidence, counter.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return fmt.Errorf("row %d: parse %s %q as non-negative decimal", rowNo, counter.name, raw)
		}
		*counter.dst = parsed
		evidence.observed[counter.name] = true
	}
	return nil
}

func parseCheckerQUICFloatCounters(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowQUICEvidence) error {
	for _, counter := range []struct {
		name string
		dst  *float64
	}{
		{"quic_smoothed_rtt_ms", &evidence.smoothedRTTMS},
		{"quic_recovery_ratio", &evidence.recoveryRatio},
	} {
		raw := checkerEvidenceValue(record, indexes.quicEvidence, counter.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return fmt.Errorf("row %d: parse %s %q as non-negative decimal", rowNo, counter.name, raw)
		}
		*counter.dst = parsed
		evidence.observed[counter.name] = true
	}
	return nil
}

func parseCheckerRowBulkEvidence(record []string, indexes checkerIndexes, rowNo int) (checkerRowBulkEvidence, error) {
	evidence := checkerRowBulkEvidence{
		observed: make(map[string]bool),
		strings:  make(map[string]string),
		uints:    make(map[string]uint64),
		bools:    make(map[string]bool),
	}
	if err := parseCheckerBulkStrings(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowBulkEvidence{}, err
	}
	if err := parseCheckerBulkBools(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowBulkEvidence{}, err
	}
	if err := parseCheckerBulkUints(record, indexes, rowNo, &evidence); err != nil {
		return checkerRowBulkEvidence{}, err
	}
	return evidence, nil
}

func parseCheckerBulkStrings(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowBulkEvidence) error {
	for _, name := range []string{"bulk_candidate_id", "bulk_batch_backend"} {
		if raw := checkerEvidenceValue(record, indexes.bulkEvidence, name); raw != "" {
			evidence.strings[name] = raw
			evidence.observed[name] = true
		}
	}
	if reason := checkerEvidenceValue(record, indexes.bulkEvidence, "bulk_probe_stop_reason"); reason != "" {
		if reason != "dirty" && reason != "pressure" && reason != "ladder-complete" {
			return fmt.Errorf("row %d: bulk probe stop reason %q is invalid", rowNo, reason)
		}
		evidence.strings["bulk_probe_stop_reason"] = reason
		evidence.observed["bulk_probe_stop_reason"] = true
	}
	stage := checkerEvidenceValue(record, indexes.bulkEvidence, "bulk_probe_reject_stage")
	if stage == "" {
		return nil
	}
	if stage != "ack-timeout" && stage != "selector" {
		return fmt.Errorf("row %d: bulk probe rejection stage %q is invalid", rowNo, stage)
	}
	evidence.strings["bulk_probe_reject_stage"] = stage
	evidence.observed["bulk_probe_reject_stage"] = true
	return nil
}

func parseCheckerBulkBools(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowBulkEvidence) error {
	for _, name := range []string{"bulk_gso_attempted", "bulk_gso_active", "bulk_probe_pressure"} {
		raw := checkerEvidenceValue(record, indexes.bulkEvidence, name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("row %d: parse %s %q as boolean", rowNo, name, raw)
		}
		evidence.bools[name] = parsed
		evidence.observed[name] = true
	}
	return nil
}

func parseCheckerBulkUints(record []string, indexes checkerIndexes, rowNo int, evidence *checkerRowBulkEvidence) error {
	for _, name := range checkerBulkEvidenceColumns {
		if evidence.observed[name] || name == "bulk_candidate_id" || name == "bulk_batch_backend" {
			continue
		}
		raw := checkerEvidenceValue(record, indexes.bulkEvidence, name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("row %d: parse %s %q as non-negative decimal", rowNo, name, raw)
		}
		evidence.uints[name] = parsed
		evidence.observed[name] = true
	}
	return nil
}

type checkerRowFields struct {
	timestampMS       int64
	elapsedMS         int64
	appBytes          int64
	relayBytes        int64
	peerReceivedBytes int64
	transferElapsedMS int64
	directValidated   bool
}

func parseCheckerRowFields(record []string, indexes checkerIndexes, rowNo int) (checkerRowFields, error) {
	var fields checkerRowFields
	parsers := []struct {
		value    *int64
		index    int
		name     string
		required bool
	}{
		{&fields.timestampMS, indexes.timestamp, indexes.timestampName, true},
		{&fields.elapsedMS, indexes.elapsedMS, "elapsed_ms", false},
		{&fields.appBytes, indexes.appBytes, "app_bytes", true},
		{&fields.relayBytes, indexes.relayBytes, "relay_bytes", false},
		{&fields.peerReceivedBytes, indexes.peerReceivedBytes, "peer_received_bytes", false},
		{&fields.transferElapsedMS, indexes.transferElapsedMS, "transfer_elapsed_ms", false},
	}
	for _, parser := range parsers {
		var err error
		if parser.required {
			*parser.value, err = parseIntField(record, parser.index, parser.name, rowNo)
		} else {
			*parser.value, err = parseOptionalIntField(record, parser.index, parser.name, rowNo)
		}
		if err != nil {
			return checkerRowFields{}, err
		}
	}
	directValidated, err := parseOptionalBoolField(record, indexes.directValidated, "direct_validated", rowNo)
	fields.directValidated = directValidated
	return fields, err
}

func parseReceiverAppMbps(record []string, indexes checkerIndexes, rowNo int, role Role, phase Phase) (float64, bool, error) {
	if role != RoleReceive || phase != PhaseDirectExecute {
		return 0, false, nil
	}
	value := field(record, indexes.appMbps)
	if value == "" {
		return 0, false, nil
	}
	appMbps, err := parseCheckerDiagnosticFloat(value)
	if err != nil {
		return 0, false, formatCheckerNumericDiagnosticError(err, rowNo, "app_mbps", value)
	}
	return appMbps, true, nil
}

func parseCheckerRowDiagnostics(record []string, indexes checkerIndexes, rowNo int, role Role, phase Phase) (checkerRowDiagnostics, error) {
	diagnostics := checkerRowDiagnostics{observed: make(map[string]bool)}
	diagnostics.receiverRepairObserved = checkerReceiverRepairObserved(record, indexes)
	for _, column := range indexes.numericDiagnostics {
		value, observed, err := parseCheckerNumericDiagnostic(record, column, rowNo)
		if err != nil {
			return checkerRowDiagnostics{}, err
		}
		if observed {
			diagnostics.observed[column.name] = true
			diagnostics.record(column.name, value)
		}
	}
	appMbps, appMbpsObserved, err := parseReceiverAppMbps(record, indexes, rowNo, role, phase)
	if err != nil {
		return checkerRowDiagnostics{}, err
	}
	diagnostics.appMbps = appMbps
	diagnostics.appMbpsObserved = appMbpsObserved
	diagnostics.directTransport = field(record, indexes.directTransport)
	return diagnostics, nil
}

func checkerReceiverRepairObserved(record []string, indexes checkerIndexes) bool {
	if !indexes.receiverRepairSchema {
		return false
	}
	observed := 0
	for _, column := range indexes.numericDiagnostics {
		if !isReceiverRepairDiagnosticColumn(column.name) {
			continue
		}
		if field(record, column.index) == "" {
			return false
		}
		observed++
	}
	return observed == len(receiverRepairDiagnosticColumns)
}

func isReceiverRepairDiagnosticColumn(name string) bool {
	for _, column := range receiverRepairDiagnosticColumns {
		if name == column {
			return true
		}
	}
	return false
}

func (d *checkerRowDiagnostics) record(name string, value checkerNumericDiagnosticValue) {
	if record, ok := checkerRowDiagnosticRecorders[name]; ok {
		record(d, value)
	}
}

func normalizeCheckerRecord(record []string, indexes checkerIndexes, rowNo int) ([]string, error) {
	if len(record) == indexes.fields {
		return record, nil
	}
	if len(record) > indexes.fields || !missingOnlyTrailingOptionalDiagnostics(indexes.header, len(record)) {
		return nil, fmt.Errorf("row %d: wrong number of fields: got %d, want %d", rowNo, len(record), indexes.fields)
	}
	padded := make([]string, indexes.fields)
	copy(padded, record)
	return padded, nil
}

func missingOnlyTrailingOptionalDiagnostics(header []string, missingStart int) bool {
	if missingStart >= len(header) {
		return false
	}
	for _, name := range header[missingStart:] {
		if !isOptionalTrailingDiagnosticColumn(name) {
			return false
		}
	}
	return true
}

func isOptionalTrailingDiagnosticColumn(name string) bool {
	switch name {
	case "rate_target_mbps",
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
		"bulk_decision_mode",
		"bulk_decision_reason",
		"bulk_decision_run_id",
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
		"quic_packets_sent",
		"quic_packets_received",
		"quic_packets_lost",
		"quic_wire_bytes_sent",
		"quic_recovery_wire_bytes",
		"quic_recovery_ratio",
		"quic_stream_bytes_sent",
		"quic_stream_bytes_received",
		"quic_stream_goodput_mbps",
		"quic_smoothed_rtt_ms",
		"quic_loss_events",
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
		"file_payload_lane_addrs":
		return true
	default:
		return false
	}
}

func requireCheckerRowFields(record []string, indexes checkerIndexes, rowNo int) error {
	required := []struct {
		index int
		name  string
	}{
		{indexes.timestamp, indexes.timestampName},
		{indexes.phase, "phase"},
		{indexes.appBytes, "app_bytes"},
	}
	for _, field := range required {
		if err := requireField(record, field.index, field.name, rowNo); err != nil {
			return err
		}
	}
	return nil
}

func validateCheckerRowStatus(row checkerRow) error {
	if row.lastState == "connected-direct" && !row.directValidated {
		return fmt.Errorf("row %d: connected-direct without direct validation", row.rowNo)
	}
	if row.lastState == "direct-fallback-relay" && row.fallbackReason == "" {
		return fmt.Errorf("row %d: direct-fallback-relay missing fallback reason", row.rowNo)
	}
	return nil
}

func requireField(record []string, index int, name string, rowNo int) error {
	if index < 0 || index >= len(record) {
		return fmt.Errorf("row %d: missing required field %q", rowNo, name)
	}
	return nil
}

func parseIntField(record []string, index int, name string, rowNo int) (int64, error) {
	value := field(record, index)
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return n, nil
}

func parseOptionalIntField(record []string, index int, name string, rowNo int) (int64, error) {
	if index < 0 {
		return 0, nil
	}
	value := field(record, index)
	if value == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return n, nil
}

func parseOptionalBoolField(record []string, index int, name string, rowNo int) (bool, error) {
	if index < 0 {
		return false, nil
	}
	value := field(record, index)
	if value == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
	}
	return b, nil
}

func parseCheckerNumericDiagnostic(record []string, column checkerNumericDiagnostic, rowNo int) (checkerNumericDiagnosticValue, bool, error) {
	value := field(record, column.index)
	if value == "" {
		return checkerNumericDiagnosticValue{}, false, nil
	}
	switch column.kind {
	case checkerNumericDiagnosticInt:
		n, err := strconv.Atoi(value)
		return checkerNumericDiagnosticValue{intValue: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticInt64:
		n, err := strconv.ParseInt(value, 10, 64)
		return checkerNumericDiagnosticValue{int64Value: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticUint32:
		n, err := strconv.ParseUint(value, 10, 32)
		return checkerNumericDiagnosticValue{uint32Value: uint32(n)}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticUint64:
		n, err := strconv.ParseUint(value, 10, 64)
		return checkerNumericDiagnosticValue{uint64Value: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	case checkerNumericDiagnosticFloat:
		n, err := parseCheckerDiagnosticFloat(value)
		return checkerNumericDiagnosticValue{floatValue: n}, err == nil, formatCheckerNumericDiagnosticError(err, rowNo, column.name, value)
	default:
		return checkerNumericDiagnosticValue{}, false, fmt.Errorf("row %d: unsupported numeric diagnostic %s", rowNo, column.name)
	}
}

func parseCheckerDiagnosticFloat(value string) (float64, error) {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, errors.New("non-finite value")
	}
	return n, nil
}

func formatCheckerNumericDiagnosticError(err error, rowNo int, name string, value string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("row %d: parse %s %q: %w", rowNo, name, value, err)
}

func field(record []string, index int) string {
	if index < 0 || index >= len(record) {
		return ""
	}
	return record[index]
}

func isActivePhase(phase Phase) bool {
	switch phase {
	case PhaseRelay, PhaseDirectPrepare, PhaseDirectProbe, PhaseDirectExecute, PhaseOverlap:
		return true
	default:
		return false
	}
}
