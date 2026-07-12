// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"bytes"
	"encoding/csv"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRecorderWritesHeaderAndEscapedRows(t *testing.T) {
	lastError := "quoted \" value, comma"
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                     time.Unix(100, int64(500*time.Millisecond)),
		Phase:                  PhaseDirectProbe,
		RelayBytes:             1024,
		DirectBytes:            2048,
		AppBytes:               3072,
		DirectRateSelectedMbps: 350,
		DirectRateActiveMbps:   100,
		DirectLanesActive:      2,
		DirectLanesAvailable:   8,
		DirectProbeState:       "running",
		DirectProbeSummary:     "8:rx=199296,350:rx=8749648",
		LastState:              "connected-direct",
		LastError:              lastError,
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	records, indexes := readTraceCSV(t, out.String())
	assertRecordCount(t, records, 2)
	assertHeaderLine(t, records[0])
	row := records[1]
	assertColumn(t, row, indexes, "role", "send")
	assertColumn(t, row, indexes, "phase", "direct_probe")
	assertColumn(t, row, indexes, "elapsed_ms", "500")
	assertColumn(t, row, indexes, "relay_bytes", "1024")
	assertColumn(t, row, indexes, "direct_bytes", "2048")
	assertColumn(t, row, indexes, "app_bytes", "3072")
	assertColumn(t, row, indexes, "direct_rate_selected_mbps", "350")
	assertColumn(t, row, indexes, "direct_rate_active_mbps", "100")
	assertColumn(t, row, indexes, "direct_lanes_active", "2")
	assertColumn(t, row, indexes, "direct_lanes_available", "8")
	assertColumn(t, row, indexes, "direct_probe_state", "running")
	assertColumn(t, row, indexes, "direct_probe_summary", "8:rx=199296,350:rx=8749648")
	assertColumn(t, row, indexes, "last_state", "connected-direct")
	assertColumn(t, row, indexes, "last_error", lastError)
}

func TestRecorderComputesDeltaAndMbps(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleReceive, time.Unix(200, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{At: time.Unix(200, 0), Phase: PhaseRelay, AppBytes: 1 << 20})
	rec.Observe(Snapshot{At: time.Unix(201, 0), Phase: PhaseRelay, AppBytes: 2 << 20})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	records, indexes := readTraceCSV(t, out.String())
	assertRecordCount(t, records, 3)
	row := records[2]
	assertColumn(t, row, indexes, "role", "receive")
	assertColumn(t, row, indexes, "phase", "relay")
	assertColumn(t, row, indexes, "app_bytes", "2097152")
	assertColumn(t, row, indexes, "delta_app_bytes", "1048576")
	assertColumn(t, row, indexes, "app_mbps", "8.39")
}

func TestRecorderWritesRepairEfficiencyDiagnostics(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleReceive, time.Unix(250, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                     time.Unix(251, 0),
		Phase:                  PhaseComplete,
		MissingScanChecks:      790_545,
		PendingMissing:         0,
		PendingMissingPeak:     1234,
		RepairRequestedPackets: 4567,
		RepairRequestBatches:   32,
		ReorderTrailPackets:    22_000,
		ReceivePacketRatePPS:   88_000,
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	assertHeaderSuffix(t, records[0], []string{
		"missing_scan_checks",
		"pending_missing",
		"pending_missing_peak",
		"repair_requested_packets",
		"repair_request_batches",
		"reorder_trail_packets",
		"receive_packet_rate_pps",
	})
	row := records[1]
	assertColumn(t, row, indexes, "missing_scan_checks", "790545")
	assertColumn(t, row, indexes, "pending_missing", "0")
	assertColumn(t, row, indexes, "pending_missing_peak", "1234")
	assertColumn(t, row, indexes, "repair_requested_packets", "4567")
	assertColumn(t, row, indexes, "repair_request_batches", "32")
	assertColumn(t, row, indexes, "reorder_trail_packets", "22000")
	assertColumn(t, row, indexes, "receive_packet_rate_pps", "88000")
}

func TestRecorderErrorRowIsTerminal(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(300, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Error(time.Unix(300, int64(250*time.Millisecond)), "write udp: message too long")
	rec.Complete(time.Unix(301, 0))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	records, indexes := readTraceCSV(t, out.String())
	assertRecordCount(t, records, 2)
	assertColumn(t, records[1], indexes, "phase", "error")
	assertColumn(t, records[1], indexes, "elapsed_ms", "250")
	assertColumn(t, records[1], indexes, "last_error", "write udp: message too long")
}

func TestRecorderTerminalRowsAreFinal(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(350, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Complete(time.Unix(351, 0))
	rec.Update(func(snap *Snapshot) {
		snap.At = time.Unix(351, int64(100*time.Millisecond))
		snap.Phase = PhaseDirectExecute
		snap.LastState = "connected-direct"
	})
	rec.Tick(time.Unix(351, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	assertRecordCount(t, records, 2)
	assertColumn(t, records[1], indexes, "phase", "complete")
	assertColumn(t, records[1], indexes, "elapsed_ms", "1000")
}

func TestRecorderHeaderUnaffectedByExportedHeaderMutation(t *testing.T) {
	original := Header[0]
	Header[0] = "mutated_header"
	defer func() {
		Header[0] = original
	}()

	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(400, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if got, want := lines[0], HeaderLine; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestRecorderWritesReceiverAnchoredProgressColumns(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(900, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                time.Unix(900, int64(500*time.Millisecond)),
		Phase:             PhaseRelay,
		AppBytes:          1024,
		LocalSentBytes:    4096,
		PeerReceivedBytes: 1024,
		SetupElapsedMS:    250,
		TransferElapsedMS: 250,
		DirectValidated:   false,
		FallbackReason:    "direct path probes received no packets",
		LastState:         "direct-fallback-relay",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	records, indexes := readTraceCSV(t, out.String())
	row := records[1]
	assertColumn(t, row, indexes, "local_sent_bytes", "4096")
	assertColumn(t, row, indexes, "peer_received_bytes", "1024")
	assertColumn(t, row, indexes, "setup_elapsed_ms", "250")
	assertColumn(t, row, indexes, "transfer_elapsed_ms", "250")
	assertColumn(t, row, indexes, "direct_validated", "false")
	assertColumn(t, row, indexes, "fallback_reason", "direct path probes received no packets")
}

func TestRecorderWritesDirectPathDiagnosticFields(t *testing.T) {
	start := time.UnixMilli(1_000)

	var sendOut bytes.Buffer
	sendRec, err := NewRecorder(&sendOut, RoleSend, start)
	if err != nil {
		t.Fatalf("NewRecorder(send) error = %v", err)
	}
	sendRec.Observe(Snapshot{
		At:                         start.Add(500 * time.Millisecond),
		Phase:                      PhaseDirectExecute,
		LocalSentBytes:             1_250_000,
		PeerReceivedBytes:          1_000_000,
		RateTargetMbps:             263,
		RateCeilingMbps:            700,
		RateExplorationCeilingMbps: 1200,
		DirectRateSelectedMbps:     263,
		DirectLanesActive:          4,
		DirectLanesAvailable:       7,
		LaneMin:                    4,
		LaneCap:                    4,
		ControllerDecision:         "hold",
		ControllerReason:           "initial-hold",
		ReplayBytes:                2_696_032,
		RetransmitCount:            3_600,
		RepairRequests:             12,
		RepairBytes:                98_304,
		LocalENOBUFSRetries:        7,
		LocalENOBUFSWaitUS:         913,
		LocalENOBUFSMaxConsecutive: 3,
		PeerRecvQueueDepth:         512,
		PeerRecvQueueDepthMax:      1_069,
		DirectPacketBytes:          1_250_000,
		DirectCommittedBytes:       1_000_000,
		LastState:                  "connected-direct",
	})
	sendRec.Observe(Snapshot{
		At:                         start.Add(time.Second),
		Phase:                      PhaseDirectExecute,
		LocalSentBytes:             2_000_000,
		PeerReceivedBytes:          1_250_000,
		RateTargetMbps:             263,
		RateCeilingMbps:            700,
		RateExplorationCeilingMbps: 1200,
		DirectRateSelectedMbps:     263,
		DirectLanesActive:          4,
		DirectLanesAvailable:       7,
		LaneMin:                    4,
		LaneCap:                    4,
		ControllerDecision:         "hold",
		ControllerReason:           "initial-hold",
		ReplayBytes:                2_696_032,
		RetransmitCount:            3_600,
		RepairRequests:             12,
		RepairBytes:                98_304,
		LocalENOBUFSRetries:        7,
		LocalENOBUFSWaitUS:         913,
		LocalENOBUFSMaxConsecutive: 3,
		PeerRecvQueueDepth:         512,
		PeerRecvQueueDepthMax:      1_069,

		StripedSendBlockedMS:           250,
		StripedReceivePendingChunks:    7,
		StripedReceivePendingChunksMax: 9,
		StripedReceivePendingBytes:     7_340_032,
		StripedReceivePendingBytesMax:  9_437_184,

		DirectPacketBytes:    2_000_000,
		DirectCommittedBytes: 1_250_000,
		LastState:            "connected-direct",
	})
	if err := sendRec.Close(); err != nil {
		t.Fatalf("Close(send) error = %v", err)
	}

	sendRecords, sendIndexes := readTraceCSV(t, sendOut.String())
	assertRecordCount(t, sendRecords, 3)
	assertHeaderSuffix(t, sendRecords[0], directPathDiagnosticHeader())
	sendRow := sendRecords[2]
	assertColumn(t, sendRow, sendIndexes, "rate_target_mbps", "263")
	assertColumn(t, sendRow, sendIndexes, "rate_ceiling_mbps", "700")
	assertColumn(t, sendRow, sendIndexes, "rate_exploration_ceiling_mbps", "1200")
	assertColumn(t, sendRow, sendIndexes, "rate_selected_mbps", "263")
	assertColumn(t, sendRow, sendIndexes, "active_lanes", "4")
	assertColumn(t, sendRow, sendIndexes, "available_lanes", "7")
	assertColumn(t, sendRow, sendIndexes, "lane_min", "4")
	assertColumn(t, sendRow, sendIndexes, "lane_cap", "4")
	assertColumn(t, sendRow, sendIndexes, "controller_decision", "hold")
	assertColumn(t, sendRow, sendIndexes, "controller_reason", "initial-hold")
	assertColumn(t, sendRow, sendIndexes, "send_goodput_mbps", "12.00")
	assertColumn(t, sendRow, sendIndexes, "receiver_committed_mbps", "4.00")
	assertColumn(t, sendRow, sendIndexes, "replay_bytes", "2696032")
	assertColumn(t, sendRow, sendIndexes, "retransmits", "3600")
	assertColumn(t, sendRow, sendIndexes, "repair_requests", "12")
	assertColumn(t, sendRow, sendIndexes, "repair_bytes", "98304")
	assertColumn(t, sendRow, sendIndexes, "local_enobufs_retries", "7")
	assertColumn(t, sendRow, sendIndexes, "local_enobufs_wait_us", "913")
	assertColumn(t, sendRow, sendIndexes, "local_enobufs_max_consecutive", "3")
	assertColumn(t, sendRow, sendIndexes, "peer_recv_queue_depth", "512")
	assertColumn(t, sendRow, sendIndexes, "peer_recv_queue_depth_max", "1069")
	assertColumn(t, sendRow, sendIndexes, "striped_send_blocked_ms", "250")
	assertColumn(t, sendRow, sendIndexes, "striped_receive_pending_chunks", "7")
	assertColumn(t, sendRow, sendIndexes, "striped_receive_pending_chunks_max", "9")
	assertColumn(t, sendRow, sendIndexes, "striped_receive_pending_bytes", "7340032")
	assertColumn(t, sendRow, sendIndexes, "striped_receive_pending_bytes_max", "9437184")
	assertColumn(t, sendRow, sendIndexes, "direct_packet_bytes", "2000000")
	assertColumn(t, sendRow, sendIndexes, "direct_committed_bytes", "1250000")

	var receiveOut bytes.Buffer
	receiveRec, err := NewRecorder(&receiveOut, RoleReceive, start)
	if err != nil {
		t.Fatalf("NewRecorder(receive) error = %v", err)
	}
	receiveRec.Observe(Snapshot{
		At:                   start.Add(500 * time.Millisecond),
		Phase:                PhaseDirectExecute,
		DirectBytes:          42,
		DirectPacketBytes:    1_250_000,
		DirectCommittedBytes: 1_000_000,
	})
	receiveRec.Observe(Snapshot{
		At:                   start.Add(time.Second),
		Phase:                PhaseDirectExecute,
		DirectBytes:          84,
		DirectPacketBytes:    2_000_000,
		DirectCommittedBytes: 1_250_000,
	})
	if err := receiveRec.Close(); err != nil {
		t.Fatalf("Close(receive) error = %v", err)
	}

	receiveRecords, receiveIndexes := readTraceCSV(t, receiveOut.String())
	assertRecordCount(t, receiveRecords, 3)
	assertHeaderSuffix(t, receiveRecords[0], directPathDiagnosticHeader())
	receiveRow := receiveRecords[2]
	assertColumn(t, receiveRow, receiveIndexes, "receive_goodput_mbps", "12.00")
	assertColumn(t, receiveRow, receiveIndexes, "receiver_committed_mbps", "4.00")
	assertColumn(t, receiveRow, receiveIndexes, "direct_packet_bytes", "2000000")
	assertColumn(t, receiveRow, receiveIndexes, "direct_committed_bytes", "1250000")
	assertColumn(t, receiveRow, receiveIndexes, "local_enobufs_retries", "")
	assertColumn(t, receiveRow, receiveIndexes, "local_enobufs_wait_us", "")
	assertColumn(t, receiveRow, receiveIndexes, "local_enobufs_max_consecutive", "")
}

func TestRecorderWritesQUICTransportFields(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:                      time.Unix(0, int64(time.Second)),
		Phase:                   PhaseDirectExecute,
		AppBytes:                1024,
		DirectTransport:         "quic",
		QUICHandshakeMS:         12,
		QUICFirstByteMS:         18,
		QUICStreamBytesSent:     1024,
		QUICStreamBytesReceived: 512,
		QUICStreamGoodputMbps:   "8.19",
		QUICSmoothedRTTMS:       "1.25",
		QUICLossEvents:          2,
		QUICCloseReason:         "normal",
		LastState:               "connected-direct",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	row := records[1]
	assertColumn(t, row, indexes, "direct_transport", "quic")
	assertColumn(t, row, indexes, "quic_handshake_ms", "12")
	assertColumn(t, row, indexes, "quic_first_byte_ms", "18")
	assertColumn(t, row, indexes, "quic_stream_bytes_sent", "1024")
	assertColumn(t, row, indexes, "quic_stream_bytes_received", "512")
	assertColumn(t, row, indexes, "quic_stream_goodput_mbps", "8.19")
	assertColumn(t, row, indexes, "quic_smoothed_rtt_ms", "1.25")
	assertColumn(t, row, indexes, "quic_loss_events", "2")
	assertColumn(t, row, indexes, "quic_close_reason", "normal")
}

func TestRecorderLeavesRoleSpecificDiagnosticFieldsEmpty(t *testing.T) {
	start := time.UnixMilli(2_000)

	var sendOut bytes.Buffer
	sendRec, err := NewRecorder(&sendOut, RoleSend, start)
	if err != nil {
		t.Fatalf("NewRecorder(send) error = %v", err)
	}
	sendRec.Observe(Snapshot{
		At:             start.Add(500 * time.Millisecond),
		Phase:          PhaseDirectExecute,
		LocalSentBytes: 1_250_000,
	})
	if err := sendRec.Close(); err != nil {
		t.Fatalf("Close(send) error = %v", err)
	}

	sendRecords, sendIndexes := readTraceCSV(t, sendOut.String())
	sendRow := sendRecords[1]
	assertColumn(t, sendRow, sendIndexes, "send_goodput_mbps", "20.00")
	assertColumn(t, sendRow, sendIndexes, "receive_goodput_mbps", "")
	assertColumn(t, sendRow, sendIndexes, "receiver_committed_mbps", "")
	assertColumn(t, sendRow, sendIndexes, "direct_packet_bytes", "")
	assertColumn(t, sendRow, sendIndexes, "direct_committed_bytes", "")

	var receiveOut bytes.Buffer
	receiveRec, err := NewRecorder(&receiveOut, RoleReceive, start)
	if err != nil {
		t.Fatalf("NewRecorder(receive) error = %v", err)
	}
	receiveRec.Observe(Snapshot{
		At:                   start.Add(500 * time.Millisecond),
		Phase:                PhaseDirectExecute,
		DirectPacketBytes:    1_250_000,
		DirectCommittedBytes: 1_000_000,
	})
	if err := receiveRec.Close(); err != nil {
		t.Fatalf("Close(receive) error = %v", err)
	}

	receiveRecords, receiveIndexes := readTraceCSV(t, receiveOut.String())
	receiveRow := receiveRecords[1]
	assertColumn(t, receiveRow, receiveIndexes, "send_goodput_mbps", "")
	assertColumn(t, receiveRow, receiveIndexes, "receive_goodput_mbps", "20.00")
	assertColumn(t, receiveRow, receiveIndexes, "receiver_committed_mbps", "16.00")
	assertColumn(t, receiveRow, receiveIndexes, "rate_target_mbps", "")
	assertColumn(t, receiveRow, receiveIndexes, "rate_ceiling_mbps", "")
	assertColumn(t, receiveRow, receiveIndexes, "rate_exploration_ceiling_mbps", "")
	assertColumn(t, receiveRow, receiveIndexes, "rate_selected_mbps", "")
	assertColumn(t, receiveRow, receiveIndexes, "active_lanes", "")
	assertColumn(t, receiveRow, receiveIndexes, "available_lanes", "")
	assertColumn(t, receiveRow, receiveIndexes, "lane_min", "")
	assertColumn(t, receiveRow, receiveIndexes, "lane_cap", "")
	assertColumn(t, receiveRow, receiveIndexes, "controller_decision", "")
	assertColumn(t, receiveRow, receiveIndexes, "controller_reason", "")
	assertColumn(t, receiveRow, receiveIndexes, "replay_bytes", "")
	assertColumn(t, receiveRow, receiveIndexes, "retransmits", "")
	assertColumn(t, receiveRow, receiveIndexes, "repair_requests", "")
	assertColumn(t, receiveRow, receiveIndexes, "repair_bytes", "")
	assertColumn(t, receiveRow, receiveIndexes, "peer_recv_queue_depth", "")
	assertColumn(t, receiveRow, receiveIndexes, "peer_recv_queue_depth_max", "")
	assertColumn(t, receiveRow, receiveIndexes, "striped_send_blocked_ms", "0")
	assertColumn(t, receiveRow, receiveIndexes, "striped_receive_pending_chunks", "0")
	assertColumn(t, receiveRow, receiveIndexes, "striped_receive_pending_chunks_max", "0")
	assertColumn(t, receiveRow, receiveIndexes, "striped_receive_pending_bytes", "0")
	assertColumn(t, receiveRow, receiveIndexes, "striped_receive_pending_bytes_max", "0")
}

func TestRecorderRowsParseByHeaderAndBlankZeroOptionalFields(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleReceive, time.Unix(500, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{
		At:          time.Unix(500, int64(750*time.Millisecond)),
		Phase:       PhaseRelay,
		RelayBytes:  11,
		DirectBytes: 22,
		AppBytes:    33,
		LastState:   "relay-only",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	row := records[1]
	assertColumn(t, row, indexes, "role", "receive")
	assertColumn(t, row, indexes, "phase", "relay")
	assertColumn(t, row, indexes, "relay_bytes", "11")
	assertColumn(t, row, indexes, "direct_bytes", "22")
	assertColumn(t, row, indexes, "app_bytes", "33")
	assertColumn(t, row, indexes, "elapsed_ms", "750")
	assertColumn(t, row, indexes, "last_state", "relay-only")
	assertColumn(t, row, indexes, "direct_rate_selected_mbps", "")
	assertColumn(t, row, indexes, "direct_rate_active_mbps", "")
	assertColumn(t, row, indexes, "direct_lanes_active", "")
	assertColumn(t, row, indexes, "direct_lanes_available", "")
	assertColumn(t, row, indexes, "replay_window_bytes", "")
	assertColumn(t, row, indexes, "repair_queue_bytes", "")
	assertColumn(t, row, indexes, "retransmit_count", "")
	assertColumn(t, row, indexes, "out_of_order_bytes", "")
}

func TestUpdateSkipsCallbackWhenClosedOrFailed(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(600, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rec.Update(func(*Snapshot) {
		t.Fatal("Update callback ran after Close")
	})

	writer := &failAfterWrites{remaining: 1}
	failed, err := NewRecorder(writer, RoleSend, time.Unix(700, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	failed.Observe(Snapshot{At: time.Unix(700, 0), Phase: PhaseRelay})
	failed.Update(func(*Snapshot) {
		t.Fatal("Update callback ran after writer failure")
	})
}

func TestUpdateMutatesCurrentSnapshotWithoutRecordingRow(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleSend, time.Unix(800, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	rec.Observe(Snapshot{At: time.Unix(800, 0), Phase: PhaseRelay, AppBytes: 1 << 20})
	rec.Update(func(snap *Snapshot) {
		snap.AppBytes = 2 << 20
		snap.DirectBytes = 99
		snap.LastState = "updated-only"
	})
	rec.Tick(time.Unix(801, 0))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	assertRecordCount(t, records, 3)
	row := records[2]
	assertColumn(t, row, indexes, "phase", "relay")
	assertColumn(t, row, indexes, "direct_bytes", "99")
	assertColumn(t, row, indexes, "app_bytes", "2097152")
	assertColumn(t, row, indexes, "delta_app_bytes", "1048576")
	assertColumn(t, row, indexes, "app_mbps", "8.39")
	assertColumn(t, row, indexes, "last_state", "updated-only")
}

func readTraceCSV(t *testing.T, body string) ([][]string, map[string]int) {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("records length = %d, want at least 2", len(records))
	}
	indexes := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		indexes[name] = i
	}
	return records, indexes
}

func assertHeaderLine(t *testing.T, header []string) {
	t.Helper()
	if got := strings.Join(header, ","); got != HeaderLine {
		t.Fatalf("header = %q, want %q", got, HeaderLine)
	}
}

func assertRecordCount(t *testing.T, records [][]string, want int) {
	t.Helper()
	if got := len(records); got != want {
		t.Fatalf("record count = %d, want %d; records = %#v", got, want, records)
	}
}

func assertHeaderSuffix(t *testing.T, header []string, suffix []string) {
	t.Helper()
	if len(header) < len(suffix) {
		t.Fatalf("header length = %d, want at least %d", len(header), len(suffix))
	}
	start := len(header) - len(suffix)
	for i, want := range suffix {
		if got := header[start+i]; got != want {
			t.Fatalf("header suffix[%d] = %q, want %q; header = %v", i, got, want, header)
		}
	}
}

func assertColumn(t *testing.T, row []string, indexes map[string]int, column string, want string) {
	t.Helper()
	index, ok := indexes[column]
	if !ok {
		t.Fatalf("missing header column %q", column)
	}
	if got := row[index]; got != want {
		t.Fatalf("%s = %q, want %q", column, got, want)
	}
}

func directPathDiagnosticHeader() []string {
	return []string{
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
		"quic_handshake_ms",
		"quic_first_byte_ms",
		"quic_stream_bytes_sent",
		"quic_stream_bytes_received",
		"quic_stream_goodput_mbps",
		"quic_smoothed_rtt_ms",
		"quic_loss_events",
		"quic_close_reason",
		"missing_scan_checks",
		"pending_missing",
		"pending_missing_peak",
		"repair_requested_packets",
		"repair_request_batches",
		"reorder_trail_packets",
		"receive_packet_rate_pps",
	}
}

type failAfterWrites struct {
	remaining int
}

func (w *failAfterWrites) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(p), nil
}
