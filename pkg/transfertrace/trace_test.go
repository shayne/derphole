// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"bytes"
	"encoding/csv"
	"io"
	"strconv"
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

func TestTraceRecordsFilePayloadEngineCounters(t *testing.T) {
	for _, tt := range []struct {
		name      string
		engine    FilePayloadEngine
		committed int64
		bulk      int64
		quic      int64
	}{
		{name: "bulk", engine: FilePayloadEngineBulk, committed: 3 << 30, bulk: 3 << 30},
		{name: "quic", engine: FilePayloadEngineQUIC, committed: 2 << 30, quic: 2 << 30},
		{name: "healthy zeroes", engine: FilePayloadEngineBulk},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			rec, err := NewRecorder(&out, RoleReceive, time.Unix(225, 0))
			if err != nil {
				t.Fatal(err)
			}
			rec.Observe(Snapshot{
				At:                        time.Unix(226, 0),
				Phase:                     PhaseComplete,
				FilePayloadEngine:         tt.engine,
				FilePayloadBytesCommitted: tt.committed,
				FilePayloadBytesBulk:      tt.bulk,
				FilePayloadBytesQUIC:      tt.quic,
				FilePayloadLaneAddresses:  `["203.0.113.10:41000"]`,
			})
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			records, indexes := readTraceCSV(t, out.String())
			row := records[1]
			assertHeaderContainsSequence(t, records[0], []string{
				"file_payload_engine",
				"file_payload_bytes_committed",
				"file_payload_bytes_bulk",
				"file_payload_bytes_quic",
				"file_payload_lane_addrs",
			})
			assertColumn(t, row, indexes, "file_payload_engine", string(tt.engine))
			assertColumn(t, row, indexes, "file_payload_bytes_committed", strconv.FormatInt(tt.committed, 10))
			assertColumn(t, row, indexes, "file_payload_bytes_bulk", strconv.FormatInt(tt.bulk, 10))
			assertColumn(t, row, indexes, "file_payload_bytes_quic", strconv.FormatInt(tt.quic, 10))
			assertColumn(t, row, indexes, "file_payload_lane_addrs", `["203.0.113.10:41000"]`)
		})
	}
}

func TestParseFilePayloadEngine(t *testing.T) {
	for _, value := range []string{string(FilePayloadEngineBulk), string(FilePayloadEngineQUIC)} {
		got, err := ParseFilePayloadEngine(value)
		if err != nil || string(got) != value {
			t.Fatalf("ParseFilePayloadEngine(%q) = %q, %v", value, got, err)
		}
	}
	if _, err := ParseFilePayloadEngine("tcp"); err == nil {
		t.Fatal("ParseFilePayloadEngine(tcp) error = nil")
	}
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
	assertHeaderContainsSequence(t, records[0], []string{
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

func TestRecorderWritesBulkBatchDiagnosticsIncludingHealthyZeroes(t *testing.T) {
	var out bytes.Buffer
	recorder, err := NewRecorder(&out, RoleSend, time.Unix(260, 0))
	if err != nil {
		t.Fatal(err)
	}
	recorder.Observe(Snapshot{
		At:                             time.Unix(261, 0),
		Phase:                          PhaseDirectExecute,
		BulkBatchPresent:               true,
		BulkCandidateID:                "combined-gso3",
		BulkNativeSendAttempts:         12,
		BulkNativeSendSyscalls:         11,
		BulkNativeGSOMessages:          200,
		BulkLogicalDatagrams:           640,
		BulkNativeAcceptedPayloadBytes: 896_000,
		BulkGSOSegmentsPerMessage:      3,
		BulkBatchBackend:               "linux-sendmmsg",
		BulkGSOAttempted:               true,
		BulkGSOActive:                  false,
		BulkGSOSegments:                0,
		BulkSendCalls:                  10,
		BulkSendDatagrams:              640,
		BulkReceiveCalls:               0,
		BulkReceiveDatagrams:           0,
		BulkMaxSendBatch:               64,
		BulkMaxReceiveBatch:            0,
		BulkCryptoQueuePeak:            4,
		BulkWriterQueuePeak:            0,
		BulkLaneQueuePeak:              2,
		BulkReceiveQueuePeak:           3,
		BulkDecryptBatches:             100,
		BulkDecryptDatagrams:           6400,
		BulkProbeSelectedMbps:          2160,
		BulkProbeDurationMS:            250,
		BulkProbeTrains:                5,
		BulkProbeSentDatagrams:         30000,
		BulkProbeReceivedDatagrams:     29800,
		BulkProbeLossPPM:               6666,
		BulkProbePressure:              false,
	})
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	records, indexes := readTraceCSV(t, out.String())
	assertHeaderSuffix(t, records[0], []string{
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
	})
	row := records[1]
	assertColumn(t, row, indexes, "bulk_candidate_id", "combined-gso3")
	assertColumn(t, row, indexes, "bulk_native_send_attempts", "12")
	assertColumn(t, row, indexes, "bulk_native_send_syscalls", "11")
	assertColumn(t, row, indexes, "bulk_gso_messages", "200")
	assertColumn(t, row, indexes, "bulk_logical_datagrams", "640")
	assertColumn(t, row, indexes, "bulk_accepted_payload_bytes", "896000")
	assertColumn(t, row, indexes, "bulk_gso_segments_per_message", "3")
	assertColumn(t, row, indexes, "bulk_batch_backend", "linux-sendmmsg")
	assertColumn(t, row, indexes, "bulk_gso_attempted", "true")
	assertColumn(t, row, indexes, "bulk_gso_active", "false")
	assertColumn(t, row, indexes, "bulk_gso_segments", "0")
	assertColumn(t, row, indexes, "bulk_send_datagrams", "640")
	assertColumn(t, row, indexes, "bulk_receive_calls", "0")
	assertColumn(t, row, indexes, "bulk_max_receive_batch", "0")
	assertColumn(t, row, indexes, "bulk_writer_queue_peak", "0")
	assertColumn(t, row, indexes, "bulk_lane_queue_peak", "2")
	assertColumn(t, row, indexes, "bulk_receive_queue_peak", "3")
	assertColumn(t, row, indexes, "bulk_decrypt_batches", "100")
	assertColumn(t, row, indexes, "bulk_decrypt_datagrams", "6400")
	assertColumn(t, row, indexes, "bulk_probe_selected_mbps", "2160")
	assertColumn(t, row, indexes, "bulk_probe_duration_ms", "250")
	assertColumn(t, row, indexes, "bulk_probe_trains", "5")
	assertColumn(t, row, indexes, "bulk_probe_sent_datagrams", "30000")
	assertColumn(t, row, indexes, "bulk_probe_received_datagrams", "29800")
	assertColumn(t, row, indexes, "bulk_probe_loss_ppm", "6666")
	assertColumn(t, row, indexes, "bulk_probe_pressure", "false")
}

func TestRecorderLeavesBulkBatchDiagnosticsEmptyWhenAbsent(t *testing.T) {
	var out bytes.Buffer
	recorder, err := NewRecorder(&out, RoleSend, time.Unix(270, 0))
	if err != nil {
		t.Fatal(err)
	}
	recorder.Observe(Snapshot{At: time.Unix(271, 0), Phase: PhaseDirectExecute})
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	records, indexes := readTraceCSV(t, out.String())
	for _, column := range []string{"bulk_candidate_id", "bulk_native_send_attempts", "bulk_native_send_syscalls", "bulk_gso_messages", "bulk_logical_datagrams", "bulk_accepted_payload_bytes", "bulk_gso_segments_per_message", "bulk_batch_backend", "bulk_gso_attempted", "bulk_send_calls", "bulk_writer_queue_peak", "bulk_lane_queue_peak", "bulk_decrypt_datagrams", "bulk_probe_selected_mbps", "bulk_probe_pressure"} {
		assertColumn(t, records[1], indexes, column, "")
	}
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
	assertHeaderContainsSequence(t, sendRecords[0], directPathDiagnosticHeader())
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
	assertHeaderContainsSequence(t, receiveRecords[0], directPathDiagnosticHeader())
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
		At:                       time.Unix(0, int64(time.Second)),
		Phase:                    PhaseDirectExecute,
		AppBytes:                 1024,
		DirectTransport:          "quic",
		QUICTelemetryPresent:     true,
		QUICConnections:          2,
		QUICStreams:              4,
		QUICVersion:              "v1",
		QUICRawSocketBackend:     "quic-go-oob",
		QUICNativeSendBackend:    "udp-gso-or-sendmsg",
		QUICNativeReceiveBackend: "udp-recvmmsg",
		QUICHandshakeMS:          12,
		QUICFirstByteMS:          18,
		QUICSmoothedRTTMS:        "1.25",
		QUICPacketsSent:          10,
		QUICPacketsReceived:      8,
		QUICPacketsLost:          2,
		QUICWireBytesSent:        12_000,
		QUICRecoveryWireBytes:    1_200,
		QUICRecoveryRatio:        "0.111111",
		QUICStreamBytesSent:      1024,
		QUICStreamBytesReceived:  512,
		QUICStreamGoodputMbps:    "8.19",
		QUICCloseReason:          "complete",
		QUICNativeGSO:            "true",
		QUICNativeReceiveBatch:   "true",
		FileSourceReadCalls:      1,
		FileSourceReadBytes:      1024,
		LastState:                "connected-direct",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	records, indexes := readTraceCSV(t, out.String())
	row := records[1]
	assertColumn(t, row, indexes, "direct_transport", "quic")
	assertColumn(t, row, indexes, "quic_connections", "2")
	assertColumn(t, row, indexes, "quic_streams", "4")
	assertColumn(t, row, indexes, "quic_telemetry_present", "true")
	assertColumn(t, row, indexes, "quic_version", "v1")
	assertColumn(t, row, indexes, "quic_raw_socket_backend", "quic-go-oob")
	assertColumn(t, row, indexes, "quic_native_send_backend", "udp-gso-or-sendmsg")
	assertColumn(t, row, indexes, "quic_native_receive_backend", "udp-recvmmsg")
	assertColumn(t, row, indexes, "quic_handshake_ms", "12")
	assertColumn(t, row, indexes, "quic_first_byte_ms", "18")
	assertColumn(t, row, indexes, "quic_smoothed_rtt_ms", "1.25")
	assertColumn(t, row, indexes, "quic_packets_sent", "10")
	assertColumn(t, row, indexes, "quic_packets_received", "8")
	assertColumn(t, row, indexes, "quic_packets_lost", "2")
	assertColumn(t, row, indexes, "quic_wire_bytes_sent", "12000")
	assertColumn(t, row, indexes, "quic_recovery_wire_bytes", "1200")
	assertColumn(t, row, indexes, "quic_recovery_ratio", "0.111111")
	assertColumn(t, row, indexes, "quic_stream_bytes_sent", "1024")
	assertColumn(t, row, indexes, "quic_stream_bytes_received", "512")
	assertColumn(t, row, indexes, "quic_stream_goodput_mbps", "8.19")
	assertColumn(t, row, indexes, "quic_close_reason", "complete")
	assertColumn(t, row, indexes, "quic_native_gso", "true")
	assertColumn(t, row, indexes, "quic_native_receive_batch", "true")
	assertColumn(t, row, indexes, "file_source_read_calls", "1")
	assertColumn(t, row, indexes, "file_source_read_bytes", "1024")
}

func TestRecorderWritesHealthyZeroQUICEvidenceOnlyWhenPresent(t *testing.T) {
	var out bytes.Buffer
	rec, err := NewRecorder(&out, RoleReceive, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	rec.Observe(Snapshot{At: time.Unix(1, 0), Phase: PhaseRelay})
	rec.Observe(Snapshot{
		At:                       time.Unix(2, 0),
		Phase:                    PhaseComplete,
		QUICTelemetryPresent:     true,
		QUICConnections:          1,
		QUICStreams:              1,
		QUICVersion:              "v1",
		QUICRawSocketBackend:     "packet-conn",
		QUICNativeSendBackend:    "packetconn-writeto",
		QUICNativeReceiveBackend: "packetconn-readfrom",
		QUICNativeGSO:            "false",
		QUICNativeReceiveBatch:   "false",
	})
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	records, indexes := readTraceCSV(t, out.String())
	assertColumn(t, records[1], indexes, "quic_telemetry_present", "")
	for _, column := range []string{
		"quic_handshake_ms", "quic_first_byte_ms", "quic_smoothed_rtt_ms",
		"quic_packets_sent", "quic_packets_received", "quic_packets_lost",
		"quic_wire_bytes_sent", "quic_recovery_wire_bytes", "quic_recovery_ratio",
		"quic_stream_bytes_sent", "quic_stream_bytes_received",
	} {
		assertColumn(t, records[2], indexes, column, "0")
	}
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

func assertHeaderContainsSequence(t *testing.T, header []string, sequence []string) {
	t.Helper()
	for start := 0; start+len(sequence) <= len(header); start++ {
		matches := true
		for index, want := range sequence {
			if header[start+index] != want {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("header does not contain sequence %v; header = %v", sequence, header)
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
