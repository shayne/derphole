// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"encoding/csv"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
)

func TestExternalTransferMetricsTrackRelayAndDirectBytes(t *testing.T) {
	start := time.Unix(0, 0)
	m := newExternalTransferMetrics(start)
	m.RecordRelayWrite(32<<10, start.Add(20*time.Millisecond))
	m.RecordDirectWrite(1<<20, start.Add(450*time.Millisecond))
	m.Complete(start.Add(1450 * time.Millisecond))

	if got := m.TotalDurationMS(); got != 1450 {
		t.Fatalf("TotalDurationMS() = %d, want 1450", got)
	}
	if got := m.FirstByteMS(); got != 20 {
		t.Fatalf("FirstByteMS() = %d, want 20", got)
	}
	if got := m.DirectBytes(); got != 1<<20 {
		t.Fatalf("DirectBytes() = %d, want %d", got, 1<<20)
	}
}

func TestExternalTransferMetricsNilReceiverWriteAndCompleteNoop(t *testing.T) {
	var m *externalTransferMetrics

	m.RecordRelayWrite(1024, time.Unix(1, 0))
	m.RecordDirectWrite(2048, time.Unix(2, 0))
	m.Complete(time.Unix(3, 0))
}

func TestExternalTransferMetricsUpdatesTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(10, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	metrics.RecordRelayWrite(1024, time.Unix(10, int64(500*time.Millisecond)))
	metrics.Tick(time.Unix(10, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	rows := readTransferTraceRows(t, body)
	row := rows[len(rows)-1]
	if row["role"] != string(transfertrace.RoleSend) ||
		row["phase"] != string(transfertrace.PhaseRelay) ||
		row["relay_bytes"] != "1024" ||
		row["direct_bytes"] != "0" ||
		row["app_bytes"] != "0" {
		t.Fatalf("trace row = %#v, want send relay bytes with receiver-anchored app_bytes=0", row)
	}
}

func TestExternalTransferMetricsSamplesTraceUntilTick(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(15, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(15, 0), rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-direct")
	metrics.RecordDirectWrite(64<<10, time.Unix(15, int64(100*time.Millisecond)))

	records, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error = %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("trace records before tick = %d, want header only\n%s", len(records), out.String())
	}

	metrics.Tick(time.Unix(15, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["phase"] != string(transfertrace.PhaseDirectExecute) ||
		row["direct_bytes"] != "65536" ||
		row["app_bytes"] != "65536" ||
		row["last_state"] != "connected-direct" {
		t.Fatalf("sampled trace row = %#v, want current metrics snapshot", row)
	}
}

func TestExternalTransferMetricsDirectValidationMovesTraceToDirect(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(16, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(16, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	metrics.MarkDirectValidated(time.Unix(16, int64(250*time.Millisecond)))
	metrics.RecordDirectWrite(128<<10, time.Unix(16, int64(300*time.Millisecond)))
	metrics.Tick(time.Unix(16, int64(500*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["direct_validated"] != "true" ||
		row["phase"] != string(transfertrace.PhaseDirectExecute) ||
		row["last_state"] != string(StateDirect) {
		t.Fatalf("trace row = %#v, want validated direct state", row)
	}
}

func TestExternalTransferMetricsRecordsTransportPathEvents(t *testing.T) {
	start := time.Unix(17, 0)
	metrics := newExternalTransferMetrics(start)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))

	selected := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 17), Port: 31717}
	previous := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 17), Port: 41717}
	metrics.RecordTransportPathEvent(transport.PathEvent{
		At:           start.Add(250 * time.Millisecond),
		Type:         transport.PathEventSelected,
		Path:         transport.PathDirect,
		PreviousPath: transport.PathRelay,
		SelectedAddr: selected,
		PreviousAddr: previous,
		Reason:       transport.PathEventReasonProbeAck,
		Source:       transport.PathEventSourceDirectProbe,
		RTT:          37 * time.Millisecond,
	})

	if !metrics.directValidated {
		t.Fatal("directValidated = false, want true after selected direct event")
	}
	if metrics.phase != transfertrace.PhaseDirectExecute {
		t.Fatalf("phase = %q, want %q", metrics.phase, transfertrace.PhaseDirectExecute)
	}
	if metrics.lastState != string(StateDirect) {
		t.Fatalf("lastState = %q, want %q", metrics.lastState, StateDirect)
	}
	if metrics.transportPath != transport.PathDirect {
		t.Fatalf("transportPath = %v, want %v", metrics.transportPath, transport.PathDirect)
	}
	if metrics.transportSelectedAddr != selected.String() {
		t.Fatalf("transportSelectedAddr = %q, want %q", metrics.transportSelectedAddr, selected.String())
	}
	if metrics.transportPreviousAddr != previous.String() {
		t.Fatalf("transportPreviousAddr = %q, want %q", metrics.transportPreviousAddr, previous.String())
	}
	if metrics.transportReason != string(transport.PathEventReasonProbeAck) {
		t.Fatalf("transportReason = %q, want %q", metrics.transportReason, transport.PathEventReasonProbeAck)
	}
	if metrics.transportSource != string(transport.PathEventSourceDirectProbe) {
		t.Fatalf("transportSource = %q, want %q", metrics.transportSource, transport.PathEventSourceDirectProbe)
	}
	if metrics.transportRTTMS != 37 {
		t.Fatalf("transportRTTMS = %d, want 37", metrics.transportRTTMS)
	}

	metrics.RecordTransportPathEvent(transport.PathEvent{
		At:           start.Add(500 * time.Millisecond),
		Type:         transport.PathEventFallback,
		Path:         transport.PathRelay,
		PreviousPath: transport.PathDirect,
		PreviousAddr: selected,
		Reason:       transport.PathEventReasonDirectBroken,
		Source:       transport.PathEventSourceManual,
	})

	if metrics.transportPath != transport.PathRelay {
		t.Fatalf("transportPath after fallback = %v, want %v", metrics.transportPath, transport.PathRelay)
	}
	if metrics.transportSelectedAddr != "" {
		t.Fatalf("transportSelectedAddr after fallback = %q, want empty", metrics.transportSelectedAddr)
	}
	if metrics.transportPreviousAddr != selected.String() {
		t.Fatalf("transportPreviousAddr after fallback = %q, want %q", metrics.transportPreviousAddr, selected.String())
	}
	if metrics.transportReason != string(transport.PathEventReasonDirectBroken) {
		t.Fatalf("transportReason after fallback = %q, want %q", metrics.transportReason, transport.PathEventReasonDirectBroken)
	}
	if metrics.transportSource != string(transport.PathEventSourceManual) {
		t.Fatalf("transportSource after fallback = %q, want %q", metrics.transportSource, transport.PathEventSourceManual)
	}
	if metrics.fallbackReason != string(transport.PathEventReasonDirectBroken) {
		t.Fatalf("fallbackReason = %q, want %q", metrics.fallbackReason, transport.PathEventReasonDirectBroken)
	}
}

func TestWatchExternalDirectPathRecordsInitialSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := transport.NewManager(transport.ManagerConfig{
		RelayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
	})
	metrics := newExternalTransferMetrics(time.Unix(18, 0))
	stop := watchExternalDirectPath(ctx, mgr, metrics)
	defer stop()

	deadline := time.Now().Add(time.Second)
	for {
		metrics.mu.Lock()
		path := metrics.transportPath
		directValidated := metrics.directValidated
		metrics.mu.Unlock()
		if path == transport.PathRelay {
			if directValidated {
				t.Fatal("directValidated = true after initial relay snapshot, want false")
			}
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("transportPath = %v, want initial %v snapshot", path, transport.PathRelay)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestExternalTransferMetricsSamplesPeerRecvQueueDepthFromTransportManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayPackets := make(chan []byte, 2)
	relayPackets <- []byte("first")
	relayPackets <- []byte("second")
	mgr := transport.NewManager(transport.ManagerConfig{
		RelayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
		ReceiveRelay: func(ctx context.Context) ([]byte, error) {
			select {
			case payload := <-relayPackets:
				return payload, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		mgr.Wait()
	})
	waitForPeerRecvQueueDepth(t, mgr, 2)

	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(16, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(16, 0), rec, transfertrace.RoleReceive)
	metrics.SetTransportManager(mgr)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.Tick(time.Unix(16, int64(100*time.Millisecond)))

	conn := mgr.PeerDatagramConn(ctx)
	payload, _, err := conn.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("RecvDatagram() error = %v", err)
	}
	conn.ReleaseDatagram(payload)
	waitForPeerRecvQueueDepth(t, mgr, 1)
	metrics.Tick(time.Unix(16, int64(200*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	first := rows[len(rows)-2]
	if first["peer_recv_queue_depth"] != "2" || first["peer_recv_queue_depth_max"] != "2" {
		t.Fatalf("first trace row queue depths = current %q max %q, want 2/2; row = %#v", first["peer_recv_queue_depth"], first["peer_recv_queue_depth_max"], first)
	}
	last := rows[len(rows)-1]
	if last["peer_recv_queue_depth"] != "1" || last["peer_recv_queue_depth_max"] != "2" {
		t.Fatalf("last trace row queue depths = current %q max %q, want 1/2; row = %#v", last["peer_recv_queue_depth"], last["peer_recv_queue_depth_max"], last)
	}
}

func TestTransferTraceIncludesStripedCopyDiagnostics(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(80, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(80, 0), rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.RecordStripedReceiveBacklog(7, 7340032, time.Unix(80, 1))
	metrics.RecordStripedSendBlocked(250*time.Millisecond, time.Unix(80, 2))
	metrics.RecordStripedReceiveBacklog(0, 0, time.Unix(80, 2).Add(500*time.Millisecond))
	metrics.Tick(time.Unix(80, 3))

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["striped_send_blocked_ms"] != "250" ||
		row["striped_receive_pending_chunks"] != "0" ||
		row["striped_receive_pending_bytes"] != "0" ||
		row["striped_receive_pending_chunks_max"] != "7" ||
		row["striped_receive_pending_bytes_max"] != "7340032" {
		t.Fatalf("trace row missing striped diagnostics: %#v", row)
	}
}

func TestTransferTraceRoundsAccumulatedSubMillisecondStripedSendBlocked(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(80, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(80, 0), rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.RecordStripedSendBlocked(400*time.Microsecond, time.Unix(80, 1))
	metrics.RecordStripedSendBlocked(400*time.Microsecond, time.Unix(80, 2))
	metrics.RecordStripedSendBlocked(400*time.Microsecond, time.Unix(80, 3))
	metrics.Tick(time.Unix(80, 4))

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["striped_send_blocked_ms"] != "2" {
		t.Fatalf("striped_send_blocked_ms = %q, want rounded-up accumulated duration of 2ms; row = %#v", row["striped_send_blocked_ms"], row)
	}
}

func TestExternalTransferMetricsPeerProgressSnapshot(t *testing.T) {
	t.Parallel()

	var nilMetrics *externalTransferMetrics
	if got := nilMetrics.PeerProgressSnapshot(); got.Set {
		t.Fatalf("nil snapshot = %#v, want unset", got)
	}

	metrics := newExternalTransferMetrics(time.Unix(100, 0))
	if got := metrics.PeerProgressSnapshot(); got.Set {
		t.Fatalf("initial snapshot = %#v, want unset", got)
	}

	metrics.RecordPeerProgress(64<<20, 750, time.Unix(101, 0))
	got := metrics.PeerProgressSnapshot()
	if !got.Set || got.BytesReceived != 64<<20 || got.TransferElapsedMS != 750 {
		t.Fatalf("snapshot = %#v, want bytes=%d elapsed=750 set", got, 64<<20)
	}
}

func TestExternalTransferMetricsRecordsControllerBeforeCompletion(t *testing.T) {
	t.Parallel()

	start := time.Unix(110, 0)
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateSelectedMbps:   1000,
		RateTargetMbps:     1000,
		RateCeilingMbps:    2400,
		ActiveLanes:        8,
		AvailableLanes:     8,
		ControllerDecision: "hold",
		ControllerReason:   "initial-target",
	}, start.Add(100*time.Millisecond))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		RateTargetMbps:     850,
		ControllerDecision: "decrease",
		ControllerReason:   "repair-pressure",
		Retransmits:        12,
		RepairRequests:     3,
		RepairBytes:        16_296,
	}, start.Add(600*time.Millisecond))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	if len(rows) != 2 {
		t.Fatalf("trace rows = %d, want 2\n%s", len(rows), out.String())
	}
	if rows[0]["rate_target_mbps"] != "1000" ||
		rows[0]["controller_decision"] != "hold" ||
		rows[0]["controller_reason"] != "initial-target" {
		t.Fatalf("initial controller row = %#v", rows[0])
	}
	if rows[1]["rate_target_mbps"] != "850" ||
		rows[1]["controller_decision"] != "decrease" ||
		rows[1]["controller_reason"] != "repair-pressure" ||
		rows[1]["retransmits"] != "12" ||
		rows[1]["repair_requests"] != "3" ||
		rows[1]["repair_bytes"] != "16296" {
		t.Fatalf("decrease controller row = %#v", rows[1])
	}
}

func TestExternalTransferMetricsDirectCountersNeverRegress(t *testing.T) {
	t.Parallel()

	metrics := newExternalTransferMetrics(time.Unix(120, 0))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		Retransmits:    12,
		RepairRequests: 3,
		RepairBytes:    16_296,
	}, time.Unix(120, 1))
	metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{
		Retransmits:    4,
		RepairRequests: 1,
		RepairBytes:    5432,
	}, time.Unix(120, 2))
	metrics.SetDirectStatsWithoutByteProgress(externalDirectTransferStats{
		Retransmits: 4,
		Diagnostics: externalDirectTransferDiagnostics{
			Retransmits:    4,
			RepairRequests: 1,
			RepairBytes:    5432,
		},
	})

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.retransmitCount != 12 ||
		metrics.repairRequests != 3 ||
		metrics.repairBytes != 16_296 {
		t.Fatalf("counters regressed: retransmits=%d requests=%d bytes=%d",
			metrics.retransmitCount,
			metrics.repairRequests,
			metrics.repairBytes,
		)
	}
}

func TestExternalTransferMetricsSetDirectStatsUpdatesTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(30, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(30, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.SetDirectStats(externalDirectTransferStats{
		BytesSent:      4096,
		Retransmits:    3,
		MaxReplayBytes: 8192,
		Diagnostics: externalDirectTransferDiagnostics{
			RateTargetMbps:             263,
			RateCeilingMbps:            700,
			RateExplorationCeilingMbps: 1200,
			RateSelectedMbps:           350,
			ActiveLanes:                3,
			AvailableLanes:             4,
			LaneMin:                    2,
			LaneCap:                    4,
			ControllerDecision:         "hold",
			ControllerReason:           "initial-hold",
			ReplayBytes:                4096,
			RepairRequests:             5,
			RepairBytes:                1024,
			DirectPacketBytes:          4096,
			DirectCommittedBytes:       3072,
		},
	})
	metrics.Tick(time.Unix(30, int64(100*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	rows := readTransferTraceRows(t, body)
	row := rows[len(rows)-1]
	if row["role"] != string(transfertrace.RoleSend) ||
		row["phase"] != string(transfertrace.PhaseDirectExecute) ||
		row["relay_bytes"] != "0" ||
		row["direct_bytes"] != "4096" ||
		row["app_bytes"] != "0" {
		t.Fatalf("trace row = %#v, want send direct bytes with receiver-anchored app_bytes=0", row)
	}
	if !strings.Contains(body, ",8192,,3,") {
		t.Fatalf("trace body missing direct counters:\n%s", body)
	}
	want := map[string]string{
		"direct_rate_selected_mbps":     "350",
		"direct_lanes_active":           "3",
		"direct_lanes_available":        "4",
		"local_sent_bytes":              "4096",
		"rate_target_mbps":              "263",
		"rate_ceiling_mbps":             "700",
		"rate_exploration_ceiling_mbps": "1200",
		"rate_selected_mbps":            "350",
		"active_lanes":                  "3",
		"available_lanes":               "4",
		"lane_min":                      "2",
		"lane_cap":                      "4",
		"controller_decision":           "hold",
		"controller_reason":             "initial-hold",
		"replay_bytes":                  "4096",
		"retransmits":                   "3",
		"repair_requests":               "5",
		"repair_bytes":                  "1024",
		"direct_packet_bytes":           "4096",
		"direct_committed_bytes":        "3072",
	}
	for column, value := range want {
		if row[column] != value {
			t.Fatalf("trace row[%q] = %q, want %q; row = %#v", column, row[column], value, row)
		}
	}
	if row["send_goodput_mbps"] == "" {
		t.Fatalf("trace row send_goodput_mbps is empty, want direct byte goodput; row = %#v", row)
	}
}

func TestExternalTransferMetricsDirectPathSendProgressUsesLocalBytesBeforeAck(t *testing.T) {
	var out bytes.Buffer
	start := time.Unix(81, 0)
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-direct")
	metrics.RecordDirectPathSend(2<<20, start.Add(100*time.Millisecond))
	metrics.Tick(start.Add(500 * time.Millisecond))
	metrics.RecordPeerProgressFromFirstByte(2<<20, start.Add(800*time.Millisecond))
	metrics.Tick(start.Add(900 * time.Millisecond))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	beforeAck := rows[len(rows)-2]
	if beforeAck["app_bytes"] != "2097152" ||
		beforeAck["local_sent_bytes"] != "2097152" ||
		beforeAck["peer_received_bytes"] != "0" ||
		beforeAck["direct_transport"] != "quic" ||
		beforeAck["direct_packet_bytes"] != "2097152" {
		t.Fatalf("pre-ACK trace row = %#v, want direct-path sender local progress", beforeAck)
	}
	afterAck := rows[len(rows)-1]
	if afterAck["app_bytes"] != "2097152" ||
		afterAck["peer_received_bytes"] != "2097152" ||
		afterAck["transfer_elapsed_ms"] != "700" {
		t.Fatalf("post-ACK trace row = %#v, want ACK-anchored peer progress", afterAck)
	}
}

func TestExternalTransferMetricsDirectPathReceiveProgressWritesCommittedBytes(t *testing.T) {
	var out bytes.Buffer
	start := time.Unix(82, 0)
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-direct")
	metrics.RecordDirectPathReceive(3<<20, start.Add(100*time.Millisecond))
	metrics.Tick(start.Add(500 * time.Millisecond))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["app_bytes"] != "3145728" ||
		row["direct_bytes"] != "3145728" ||
		row["direct_packet_bytes"] != "3145728" ||
		row["direct_committed_bytes"] != "3145728" ||
		row["direct_transport"] != "quic" {
		t.Fatalf("trace row = %#v, want direct-path receive progress", row)
	}
	if row["receive_goodput_mbps"] == "" {
		t.Fatalf("trace row receive_goodput_mbps is empty, want direct-path receive rate; row = %#v", row)
	}
}

func TestExternalTransferMetricsSetDirectStatsWithoutByteProgressWritesDiagnosticsOnly(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(35, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(35, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.SetDirectStatsWithoutByteProgress(externalDirectTransferStats{
		BytesSent:      8192,
		Retransmits:    7,
		MaxReplayBytes: 16384,
		Diagnostics: externalDirectTransferDiagnostics{
			RateTargetMbps:             300,
			RateCeilingMbps:            900,
			RateExplorationCeilingMbps: 1200,
			RateSelectedMbps:           700,
			ActiveLanes:                2,
			AvailableLanes:             4,
			LaneMin:                    1,
			LaneCap:                    4,
			ControllerDecision:         "increase",
			ControllerReason:           "clean-window",
			ReplayBytes:                2048,
			RepairRequests:             2,
			RepairBytes:                512,
			ReceiverCommittedBytes:     4096,
			DirectPacketBytes:          8192,
		},
	})
	metrics.Tick(time.Unix(35, int64(100*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if got := metrics.DirectBytes(); got != 0 {
		t.Fatalf("DirectBytes() = %d, want 0", got)
	}
	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	want := map[string]string{
		"direct_bytes":                  "0",
		"app_bytes":                     "0",
		"peer_received_bytes":           "0",
		"local_sent_bytes":              "8192",
		"direct_rate_selected_mbps":     "700",
		"direct_lanes_active":           "2",
		"direct_lanes_available":        "4",
		"rate_target_mbps":              "300",
		"rate_ceiling_mbps":             "900",
		"rate_exploration_ceiling_mbps": "1200",
		"active_lanes":                  "2",
		"available_lanes":               "4",
		"lane_min":                      "1",
		"lane_cap":                      "4",
		"controller_decision":           "increase",
		"controller_reason":             "clean-window",
		"replay_window_bytes":           "16384",
		"replay_bytes":                  "2048",
		"retransmits":                   "7",
		"repair_requests":               "2",
		"repair_bytes":                  "512",
		"direct_packet_bytes":           "8192",
		"direct_committed_bytes":        "4096",
	}
	for column, value := range want {
		if row[column] != value {
			t.Fatalf("trace row[%q] = %q, want %q; row = %#v", column, row[column], value, row)
		}
	}
	if row["send_goodput_mbps"] == "" {
		t.Fatalf("trace row send_goodput_mbps is empty, want direct byte goodput; row = %#v", row)
	}
}

func TestExternalTransferMetricsFinalLaneUpdatePreservesRuntimeRateTarget(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(37, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(37, 0), rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.SetDirectLimits(700, 350, 900, 1200, 4, 4, 1, 4)
	metrics.SetDirectStats(externalDirectTransferStats{
		BytesSent: 4096,
		Diagnostics: externalDirectTransferDiagnostics{
			RateTargetMbps:             512,
			RateCeilingMbps:            900,
			RateExplorationCeilingMbps: 1200,
			RateSelectedMbps:           700,
			ActiveLanes:                4,
			AvailableLanes:             4,
			DirectPacketBytes:          4096,
		},
	})
	metrics.SetDirectLimits(700, 350, 900, 1200, 2, 4, 1, 4)
	metrics.Complete(time.Unix(37, int64(time.Second)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	want := map[string]string{
		"phase":                     string(transfertrace.PhaseComplete),
		"rate_target_mbps":          "512",
		"direct_rate_active_mbps":   "350",
		"direct_lanes_active":       "2",
		"direct_lanes_available":    "4",
		"active_lanes":              "2",
		"available_lanes":           "4",
		"direct_rate_selected_mbps": "700",
	}
	for column, value := range want {
		if row[column] != value {
			t.Fatalf("trace row[%q] = %q, want %q; row = %#v", column, row[column], value, row)
		}
	}
}

func TestExternalTransferMetricsTraceUsesDirectStreamOffsetForOverlap(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(40, 0))
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(40, 0), rec, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct")
	metrics.RecordRelayWrite(10, time.Unix(40, int64(100*time.Millisecond)))
	metrics.SetDirectAppProgressBase(6)
	metrics.RecordDirectWrite(100, time.Unix(40, int64(200*time.Millisecond)))
	metrics.Tick(time.Unix(40, int64(300*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if strings.Contains(body, ",receive,direct_execute,10,100,110,") {
		t.Fatalf("trace body double-counted relay/direct overlap:\n%s", body)
	}
	if !strings.Contains(body, ",receive,direct_execute,10,100,106,106,") {
		t.Fatalf("trace body missing offset-based app progress:\n%s", body)
	}
}

func TestExternalTransferMetricsReceiverBlockHeaderDoesNotStartPayloadFlatline(t *testing.T) {
	const (
		headerBytes  = int64(105)
		payloadBytes = int64(4096)
	)

	t.Run("payload", func(t *testing.T) {
		start := time.Unix(45, 0)
		var out bytes.Buffer
		trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, start)
		if err != nil {
			t.Fatalf("NewRecorder() error = %v", err)
		}
		metrics := newExternalTransferMetricsWithTrace(start, trace, transfertrace.RoleReceive)
		metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
		metrics.SetDirectAppProgressBase(headerBytes)
		metrics.MarkDirectValidated(start.Add(250 * time.Millisecond))
		metrics.Tick(start.Add(500 * time.Millisecond))
		metrics.Tick(start.Add(time.Second))
		metrics.Tick(start.Add(1500 * time.Millisecond))
		metrics.RecordDirectPacketReceive(payloadBytes, start.Add(1600*time.Millisecond))
		metrics.Tick(start.Add(1600 * time.Millisecond))
		metrics.Complete(start.Add(1700 * time.Millisecond))
		if err := trace.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		result, err := transfertrace.Check(strings.NewReader(out.String()), transfertrace.Options{
			Role:             transfertrace.RoleReceive,
			StallWindow:      999 * time.Millisecond,
			ExpectedBytes:    headerBytes + payloadBytes,
			ExpectedBytesSet: true,
		})
		if err != nil {
			t.Fatalf("Check() error = %v\ntrace:\n%s", err, out.String())
		}
		if result.FinalAppBytes != headerBytes+payloadBytes {
			t.Fatalf("FinalAppBytes = %d, want %d", result.FinalAppBytes, headerBytes+payloadBytes)
		}

		rows := readTransferTraceRows(t, out.String())
		for i, row := range rows[:3] {
			if row["app_bytes"] != "0" {
				t.Fatalf("header-only row %d app_bytes = %q, want 0; row = %#v", i+1, row["app_bytes"], row)
			}
		}
		if got := rows[3]["app_bytes"]; got != "4201" {
			t.Fatalf("first payload row app_bytes = %q, want 4201; row = %#v", got, rows[3])
		}
	})

	t.Run("empty payload counts header at completion", func(t *testing.T) {
		start := time.Unix(46, 0)
		var out bytes.Buffer
		trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, start)
		if err != nil {
			t.Fatalf("NewRecorder() error = %v", err)
		}
		metrics := newExternalTransferMetricsWithTrace(start, trace, transfertrace.RoleReceive)
		metrics.SetDirectAppProgressBase(headerBytes)
		metrics.MarkDirectValidated(start.Add(250 * time.Millisecond))
		metrics.Tick(start.Add(500 * time.Millisecond))
		metrics.Tick(start.Add(1500 * time.Millisecond))
		metrics.Complete(start.Add(1600 * time.Millisecond))
		if err := trace.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		result, err := transfertrace.Check(strings.NewReader(out.String()), transfertrace.Options{
			Role:             transfertrace.RoleReceive,
			StallWindow:      999 * time.Millisecond,
			ExpectedBytes:    headerBytes,
			ExpectedBytesSet: true,
		})
		if err != nil {
			t.Fatalf("Check() error = %v\ntrace:\n%s", err, out.String())
		}
		if result.FinalAppBytes != headerBytes {
			t.Fatalf("FinalAppBytes = %d, want %d", result.FinalAppBytes, headerBytes)
		}

		rows := readTransferTraceRows(t, out.String())
		for i, row := range rows[:2] {
			if row["app_bytes"] != "0" {
				t.Fatalf("header-only row %d app_bytes = %q, want 0; row = %#v", i+1, row["app_bytes"], row)
			}
		}
		if got := rows[len(rows)-1]["app_bytes"]; got != "105" {
			t.Fatalf("terminal app_bytes = %q, want 105; row = %#v", got, rows[len(rows)-1])
		}
	})
}

func TestExternalTransferMetricsUsesPeerProgressForSenderAppBytes(t *testing.T) {
	var out bytes.Buffer
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(50, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(50, 0), trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	metrics.RecordLocalSent(10<<20, time.Unix(50, int64(100*time.Millisecond)))
	metrics.RecordPeerProgress(1<<20, 500, time.Unix(51, 0))
	metrics.Tick(time.Unix(51, int64(100*time.Millisecond)))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	want := map[string]string{
		"app_bytes":           "1048576",
		"local_sent_bytes":    "10485760",
		"peer_received_bytes": "1048576",
		"setup_elapsed_ms":    "500",
		"transfer_elapsed_ms": "500",
		"direct_validated":    "false",
	}
	for column, value := range want {
		if row[column] != value {
			t.Fatalf("trace row[%q] = %q, want %q; row = %#v", column, row[column], value, row)
		}
	}
}

func TestExternalTransferMetricsDefersSenderCompleteUntilPeerAck(t *testing.T) {
	var out bytes.Buffer
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(55, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(55, 0), trace, transfertrace.RoleSend)
	metrics.DeferSendCompleteUntilPeerAck()
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
	metrics.RecordLocalSent(16<<20, time.Unix(55, int64(100*time.Millisecond)))
	metrics.RecordPeerProgress(2<<20, 500, time.Unix(55, int64(500*time.Millisecond)))
	metrics.Complete(time.Unix(55, int64(600*time.Millisecond)))
	metrics.Tick(time.Unix(55, int64(700*time.Millisecond)))
	metrics.RecordPeerProgress(16<<20, 900, time.Unix(55, int64(900*time.Millisecond)))
	metrics.CompleteAfterPeerAck(time.Unix(56, 0))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	rows := readTransferTraceRows(t, out.String())
	if rows[len(rows)-2]["phase"] == string(transfertrace.PhaseComplete) {
		t.Fatalf("local send completion wrote terminal complete before ACK: %#v", rows)
	}
	row := rows[len(rows)-1]
	if row["phase"] != string(transfertrace.PhaseComplete) ||
		row["app_bytes"] != "16777216" ||
		row["peer_received_bytes"] != "16777216" ||
		row["transfer_elapsed_ms"] != "900" {
		t.Fatalf("final trace row = %#v, want ACK-anchored complete with peer bytes", row)
	}
}

func TestExternalTransferMetricsSenderAppBytesStayZeroBeforePeerProgress(t *testing.T) {
	var out bytes.Buffer
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(60, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(60, 0), trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	metrics.RecordRelayWrite(2<<20, time.Unix(60, int64(100*time.Millisecond)))
	metrics.RecordDirectWrite(3<<20, time.Unix(60, int64(200*time.Millisecond)))
	metrics.Tick(time.Unix(60, int64(300*time.Millisecond)))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["relay_bytes"] != "2097152" ||
		row["direct_bytes"] != "3145728" ||
		row["app_bytes"] != "0" ||
		row["peer_received_bytes"] != "0" {
		t.Fatalf("trace row = %#v, want local byte counters with sender app_bytes=0 before peer progress", row)
	}
}

func TestExternalTransferMetricsSenderZeroPeerProgressSetsReceiverAnchoredState(t *testing.T) {
	var out bytes.Buffer
	trace, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, time.Unix(70, 0))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(70, 0), trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	metrics.RecordRelayWrite(4<<20, time.Unix(70, int64(100*time.Millisecond)))
	metrics.RecordPeerProgress(0, 250, time.Unix(71, 0))
	metrics.Tick(time.Unix(71, int64(100*time.Millisecond)))
	if err := trace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	rows := readTransferTraceRows(t, out.String())
	row := rows[len(rows)-1]
	if row["relay_bytes"] != "4194304" ||
		row["app_bytes"] != "0" ||
		row["peer_received_bytes"] != "0" ||
		row["setup_elapsed_ms"] != "750" ||
		row["transfer_elapsed_ms"] != "250" {
		t.Fatalf("trace row = %#v, want zero peer progress ACK to anchor app_bytes and timing", row)
	}
}

func TestListenConfigTraceUpdatesReceiveRelayPrefixTrace(t *testing.T) {
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleReceive, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ListenConfig{Trace: rec}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(20, 0), cfg.Trace, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	metrics.RecordRelayWrite(2048, time.Unix(20, int64(250*time.Millisecond)))
	metrics.Tick(time.Unix(20, int64(250*time.Millisecond)))
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, ",receive,relay,2048,0,2048,2048,") {
		t.Fatalf("trace body missing receive relay progress:\n%s", body)
	}
}

func readTransferTraceRows(t *testing.T, body string) []map[string]string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error = %v\nbody:\n%s", err, body)
	}
	if len(records) < 2 {
		t.Fatalf("trace rows = %d, want header and at least one row\nbody:\n%s", len(records), body)
	}
	header := records[0]
	var rows []map[string]string
	for _, record := range records[1:] {
		if len(record) != len(header) {
			t.Fatalf("trace row has %d columns, want %d: %#v", len(record), len(header), record)
		}
		row := make(map[string]string, len(header))
		for i, name := range header {
			row[name] = record[i]
		}
		rows = append(rows, row)
	}
	return rows
}

func waitForPeerRecvQueueDepth(t *testing.T, mgr *transport.Manager, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if got := mgr.CurrentPeerRecvQueueDepth(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("CurrentPeerRecvQueueDepth() = %d, want %d", mgr.CurrentPeerRecvQueueDepth(), want)
		}
		time.Sleep(time.Millisecond)
	}
}
