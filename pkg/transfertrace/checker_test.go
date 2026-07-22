// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"bytes"
	"encoding/csv"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckPassesSmoothCompleteTransfer(t *testing.T) {
	csvText := HeaderLine + "\n" +
		padLegacyTraceRow("1000,0,receive,relay,1024,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,connected-relay,") +
		padLegacyTraceRow("1500,500,receive,overlap,2048,1024,2048,1024,16.38,0,0,,,true,,,,,,,,,,,,connected-direct,") +
		padLegacyTraceRow("2000,1000,receive,complete,2048,4096,4096,2048,32.77,0,0,,,false,,,,,,,,,,,,stream-complete,")
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 3 || result.FinalAppBytes != 4096 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckAcceptsTimestampMSAlias(t *testing.T) {
	csvText := "timestamp_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 4096 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckFiltersRoleWithMixedRows(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,error,0,send should be ignored\n" +
		"1500,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 4096 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckIgnoresMalformedNonMatchingRows(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"bad,send,error,bad,ignored send row\n" +
		"1500,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 4096 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckIgnoresShortNonMatchingRows(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,error,0\n" +
		"1500,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 4096 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckIgnoresExtraFieldNonMatchingRows(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,error,0,ignored,extra\n" +
		"1500,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 4096})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 4096 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckResetsFlatlineClockWhenEnteringActivePhase(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,claim,1024,\n" +
		"2501,receive,relay,1024,\n" +
		"2600,receive,complete,2048,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 2048})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 3 || result.FinalAppBytes != 2048 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckResetsFlatlineClockWhenActivePhaseChanges(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,direct_probe,1024,\n" +
		"2001,send,direct_execute,1024,\n" +
		"2500,send,direct_execute,2048,\n" +
		"2600,send,complete,2048,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second, ExpectedBytes: 2048})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 4 || result.FinalAppBytes != 2048 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckIgnoresInitialActiveSetupBeforeFirstAppByte(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,direct_execute,0,\n" +
		"2501,send,direct_execute,0,\n" +
		"3000,send,direct_execute,1024,\n" +
		"3500,send,complete,1024,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second, ExpectedBytes: 1024})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Rows != 4 || result.FinalAppBytes != 1024 || result.FinalPhase != PhaseComplete {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckFailsApplicationFlatline(t *testing.T) {
	csvText := HeaderLine + "\n" +
		padLegacyTraceRow("1000,0,receive,relay,1024,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,connected-relay,") +
		padLegacyTraceRow("1500,500,receive,direct_probe,1024,0,1024,0,0.00,0,0,,,true,,,,,,,,,,,,connected-direct,") +
		padLegacyTraceRow("2501,1501,receive,direct_probe,1024,0,1024,0,0.00,0,0,,,true,,,,,,,,,,,,connected-direct,")
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "app bytes stalled") || !strings.Contains(err.Error(), "row 4") {
		t.Fatalf("Check() error = %v, want app bytes stalled at row 4", err)
	}
}

func TestCheckFailsFinalPhaseMismatch(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,relay,1024,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "final phase") {
		t.Fatalf("Check() error = %v, want final phase mismatch", err)
	}
}

func TestCheckFailsNoMatchingRole(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,complete,1024,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), `no rows matched role "receive"`) {
		t.Fatalf("Check() error = %v, want no matching role", err)
	}
}

func TestCheckFailsMissingTimestampHeaderWithAliases(t *testing.T) {
	csvText := "role,phase,app_bytes,last_error\n" +
		"receive,complete,1024,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "timestamp_unix_ms") || !strings.Contains(err.Error(), "timestamp_ms") {
		t.Fatalf("Check() error = %v, want alias-aware timestamp header error", err)
	}
}

func TestCheckFailsTerminalError(t *testing.T) {
	csvText := HeaderLine + "\n" +
		padLegacyTraceRow("1000,0,send,error,0,0,0,0,0.00,0,0,,,false,,,,,,,,,,,,connected-direct,message too long")
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "message too long") || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("Check() error = %v, want terminal error at row 2", err)
	}
}

func TestCheckFailsConnectedDirectWithoutValidation(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:     1000,
			role:            RoleSend,
			phase:           PhaseComplete,
			appBytes:        1024,
			deltaAppBytes:   1024,
			directValidated: false,
			lastState:       "connected-direct",
		})
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, ExpectedBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "connected-direct without direct validation") {
		t.Fatalf("Check() error = %v, want direct validation failure", err)
	}
}

func TestCheckFailsDirectFallbackRelayWithoutReason(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:     1000,
			role:            RoleSend,
			phase:           PhaseComplete,
			appBytes:        1024,
			deltaAppBytes:   1024,
			directValidated: false,
			lastState:       "direct-fallback-relay",
		})
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, ExpectedBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "direct-fallback-relay missing fallback reason") {
		t.Fatalf("Check() error = %v, want fallback reason failure", err)
	}
}

func TestCheckAllowsDirectFallbackRelayReason(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:     1000,
			role:            RoleSend,
			phase:           PhaseComplete,
			appBytes:        1024,
			deltaAppBytes:   1024,
			directValidated: false,
			fallbackReason:  "direct path probes received no packets",
			lastState:       "stream-complete",
		})
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, ExpectedBytes: 1024})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckReportsDiagnosticsSummaryFromDirectPathFields(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:                    1000,
			role:                           RoleSend,
			phase:                          PhaseDirectExecute,
			appBytes:                       1024,
			deltaAppBytes:                  1024,
			localSentBytes:                 1024,
			peerReceivedBytes:              1024,
			transferElapsedMS:              500,
			directValidated:                true,
			lastState:                      "connected-direct",
			rateTargetMbps:                 263,
			receiverCommittedMbps:          "1.00",
			replayBytes:                    1048576,
			retransmits:                    7,
			peerRecvQueueDepth:             512,
			peerRecvQueueDepthMax:          700,
			stripedSendBlockedMS:           150,
			stripedReceivePendingChunks:    10,
			stripedReceivePendingChunksMax: 7,
			stripedReceivePendingBytes:     10485760,
			stripedReceivePendingBytesMax:  7340032,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:                    1500,
			elapsedMS:                      500,
			role:                           RoleSend,
			phase:                          PhaseComplete,
			appBytes:                       2048,
			deltaAppBytes:                  1024,
			localSentBytes:                 2048,
			peerReceivedBytes:              2048,
			transferElapsedMS:              1000,
			directValidated:                true,
			lastState:                      "stream-complete",
			rateTargetMbps:                 300,
			receiverCommittedMbps:          "16.38",
			replayBytes:                    2097152,
			retransmits:                    9,
			peerRecvQueueDepth:             900,
			peerRecvQueueDepthMax:          1069,
			stripedSendBlockedMS:           250,
			stripedReceivePendingChunksMax: 9,
			stripedReceivePendingBytesMax:  9437184,
		})
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second, ExpectedBytes: 2048, ExpectedBytesSet: true})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Diagnostics.MaxRateTargetMbps != 300 {
		t.Fatalf("MaxRateTargetMbps = %d, want 300", result.Diagnostics.MaxRateTargetMbps)
	}
	if result.Diagnostics.MaxReplayBytes != 2097152 {
		t.Fatalf("MaxReplayBytes = %d, want 2097152", result.Diagnostics.MaxReplayBytes)
	}
	if result.Diagnostics.MaxRetransmits != 9 {
		t.Fatalf("MaxRetransmits = %d, want 9", result.Diagnostics.MaxRetransmits)
	}
	if result.Diagnostics.MaxPeerRecvQueueDepth != 1069 {
		t.Fatalf("MaxPeerRecvQueueDepth = %d, want 1069", result.Diagnostics.MaxPeerRecvQueueDepth)
	}
	if result.Diagnostics.MaxStripedSendBlockedMS != 250 {
		t.Fatalf("MaxStripedSendBlockedMS = %d, want 250", result.Diagnostics.MaxStripedSendBlockedMS)
	}
	if result.Diagnostics.MaxStripedReceivePendingChunks != 10 {
		t.Fatalf("MaxStripedReceivePendingChunks = %d, want 10", result.Diagnostics.MaxStripedReceivePendingChunks)
	}
	if result.Diagnostics.MaxStripedReceivePendingBytes != 10485760 {
		t.Fatalf("MaxStripedReceivePendingBytes = %d, want 10485760", result.Diagnostics.MaxStripedReceivePendingBytes)
	}
	if !result.Diagnostics.ReceiverCommittedMbpsObserved {
		t.Fatal("ReceiverCommittedMbpsObserved = false, want true")
	}
	if result.Diagnostics.ReceiverCommittedMbpsMin != 1.00 {
		t.Fatalf("ReceiverCommittedMbpsMin = %.2f, want 1.00", result.Diagnostics.ReceiverCommittedMbpsMin)
	}
	if result.Diagnostics.ReceiverCommittedMbpsMax != 16.38 {
		t.Fatalf("ReceiverCommittedMbpsMax = %.2f, want 16.38", result.Diagnostics.ReceiverCommittedMbpsMax)
	}
}

func TestCheckReportsSenderHealthDiagnostics(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:        1000,
			role:               RoleSend,
			phase:              PhaseDirectExecute,
			appBytes:           1024,
			deltaAppBytes:      1024,
			directValidated:    true,
			lastState:          "connected-direct",
			rateTargetMbps:     1000,
			controllerDecision: "hold",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:        1500,
			elapsedMS:          500,
			role:               RoleSend,
			phase:              PhaseDirectExecute,
			appBytes:           1536,
			deltaAppBytes:      512,
			directValidated:    true,
			lastState:          "connected-direct",
			rateTargetMbps:     850,
			controllerDecision: "decrease",
			repairBytes:        256 << 20,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:        1750,
			elapsedMS:          750,
			role:               RoleSend,
			phase:              PhaseDirectExecute,
			appBytes:           1536,
			deltaAppBytes:      0,
			directValidated:    true,
			lastState:          "connected-direct",
			rateTargetMbps:     850,
			controllerDecision: "decrease",
			repairBytes:        256 << 20,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:                2000,
			elapsedMS:                  1000,
			role:                       RoleSend,
			phase:                      PhaseComplete,
			appBytes:                   2048,
			deltaAppBytes:              512,
			directValidated:            true,
			lastState:                  "stream-complete",
			rateTargetMbps:             722,
			controllerDecision:         "decrease",
			repairBytes:                512 << 20,
			localENOBUFSRetries:        9,
			localENOBUFSWaitUS:         1400,
			localENOBUFSMaxConsecutive: 4,
		})
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleSend, StallWindow: time.Second,
		ExpectedBytes: 2048, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Diagnostics.MinRateTargetMbps; got != 722 {
		t.Fatalf("MinRateTargetMbps = %d, want 722", got)
	}
	if got := result.Diagnostics.FinalRateTargetMbps; got != 722 {
		t.Fatalf("FinalRateTargetMbps = %d, want 722", got)
	}
	if got := result.Diagnostics.ControllerDecreases; got != 2 {
		t.Fatalf("ControllerDecreases = %d, want 2", got)
	}
	if got := result.Diagnostics.FinalRepairBytes; got != 512<<20 {
		t.Fatalf("FinalRepairBytes = %d, want %d", got, 512<<20)
	}
	if got := result.Diagnostics.LocalENOBUFSRetries; got != 9 {
		t.Fatalf("LocalENOBUFSRetries = %d, want 9", got)
	}
	if got := result.Diagnostics.LocalENOBUFSWaitUS; got != 1400 {
		t.Fatalf("LocalENOBUFSWaitUS = %d, want 1400", got)
	}
	if got := result.Diagnostics.LocalENOBUFSMaxConsecutive; got != 4 {
		t.Fatalf("LocalENOBUFSMaxConsecutive = %d, want 4", got)
	}

	var receiverTrace strings.Builder
	receiverTrace.WriteString(HeaderLine + "\n")
	for index, rate := range []string{"200", "400", "600", "800", "1000"} {
		receiverTrace.WriteString(testTraceRow(testTraceRowConfig{
			timestampMS:     1000 + int64(index)*500,
			elapsedMS:       int64(index) * 500,
			role:            RoleReceive,
			phase:           PhaseDirectExecute,
			appBytes:        int64(index+1) * 1024,
			deltaAppBytes:   1024,
			appMbps:         rate,
			directValidated: true,
			lastState:       "connected-direct",
		}))
	}
	receiverTrace.WriteString(testTraceRow(testTraceRowConfig{
		timestampMS:     3500,
		elapsedMS:       2500,
		role:            RoleReceive,
		phase:           PhaseComplete,
		appBytes:        5120,
		deltaAppBytes:   0,
		directValidated: true,
		lastState:       "stream-complete",
	}))
	result, err = Check(strings.NewReader(receiverTrace.String()), Options{
		Role: RoleReceive, StallWindow: time.Second,
		ExpectedBytes: 5120, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Diagnostics.ReceiverRateP10Mbps; got != 280 {
		t.Fatalf("ReceiverRateP10Mbps = %.2f, want 280", got)
	}
	if got := result.Diagnostics.ReceiverRateP50Mbps; got != 600 {
		t.Fatalf("ReceiverRateP50Mbps = %.2f, want 600", got)
	}
	if got := result.Diagnostics.ReceiverRateP90Mbps; got != 920 {
		t.Fatalf("ReceiverRateP90Mbps = %.2f, want 920", got)
	}
	if got := result.Diagnostics.ReceiverWindowsBelow500Mbps; got != 2 {
		t.Fatalf("ReceiverWindowsBelow500Mbps = %d, want 2", got)
	}
}

func TestCheckReceiverRatesIncludeZeroWindowsAfterProgress(t *testing.T) {
	var trace strings.Builder
	trace.WriteString(HeaderLine + "\n")
	for _, row := range []testTraceRowConfig{
		{
			timestampMS: 1000, role: RoleReceive, phase: PhaseDirectExecute,
			appBytes: 0, appMbps: "0.00", directValidated: true,
		},
		{
			timestampMS: 1500, role: RoleReceive, phase: PhaseDirectExecute,
			appBytes: 1024, deltaAppBytes: 1024, appMbps: "800.00", directValidated: true,
		},
		{
			timestampMS: 2000, role: RoleReceive, phase: PhaseDirectExecute,
			appBytes: 1024, appMbps: "0.00", directValidated: true,
		},
		{
			timestampMS: 2500, role: RoleReceive, phase: PhaseDirectExecute,
			appBytes: 2048, deltaAppBytes: 1024, appMbps: "800.00", directValidated: true,
		},
		{
			timestampMS: 3000, role: RoleReceive, phase: PhaseComplete,
			appBytes: 2048, directValidated: true,
		},
	} {
		trace.WriteString(testTraceRow(row))
	}

	result, err := Check(strings.NewReader(trace.String()), Options{
		Role: RoleReceive, StallWindow: time.Second,
		ExpectedBytes: 2048, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Diagnostics.ReceiverWindowsBelow500Mbps; got != 1 {
		t.Fatalf("ReceiverWindowsBelow500Mbps = %d, want one post-progress zero window", got)
	}
	if got := result.Diagnostics.ReceiverRateP10Mbps; got != 160 {
		t.Fatalf("ReceiverRateP10Mbps = %.2f, want 160", got)
	}
	if got := result.Diagnostics.ReceiverRateCV; got <= 0 {
		t.Fatalf("ReceiverRateCV = %.3f, want post-progress zero reflected in variation", got)
	}
}

func TestCheckReceiverRatesIgnoreLegacyRowsWithoutRateMetric(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,direct_execute,1024,\n" +
		"1500,receive,complete,1024,\n"
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleReceive, StallWindow: time.Second,
		ExpectedBytes: 1024, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.ReceiverRateObserved {
		t.Fatal("ReceiverRateObserved = true for legacy trace without app_mbps")
	}
}

func TestCheckReportsQUICDiagnosticsSummary(t *testing.T) {
	csvText := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:     1000,
			role:            RoleSend,
			phase:           PhaseDirectExecute,
			appBytes:        1024,
			deltaAppBytes:   1024,
			directValidated: true,
			lastState:       "connected-direct",
			directTransport: "quic",
			quicHandshakeMS: 12,
			quicFirstByteMS: 18,
			quicBytesSent:   1024,
			quicGoodputMbps: "8.19",
			quicCloseReason: "normal",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:     1500,
			elapsedMS:       500,
			role:            RoleSend,
			phase:           PhaseComplete,
			appBytes:        1024,
			deltaAppBytes:   0,
			directValidated: true,
			lastState:       "stream-complete",
			directTransport: "quic",
			quicHandshakeMS: 12,
			quicFirstByteMS: 18,
			quicBytesSent:   1024,
			quicGoodputMbps: "8.19",
			quicCloseReason: "normal",
		})
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second, ExpectedBytes: 1024, ExpectedBytesSet: true})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.Diagnostics.DirectTransport != "quic" {
		t.Fatalf("DirectTransport = %q, want quic", result.Diagnostics.DirectTransport)
	}
}

func TestCheckRequiresCompleteQUICEngineTelemetry(t *testing.T) {
	required := []string{
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
	for _, column := range required {
		t.Run(column, func(t *testing.T) {
			trace := testQUICEngineTrace(t, RoleSend, map[string]string{column: ""})
			_, err := Check(strings.NewReader(trace), Options{
				Role: RoleSend, ExpectedBytes: 1024, ExpectedBytesSet: true,
				ExpectedPayloadBytes: 1024, ExpectedPayloadBytesSet: true,
				RequireDirectTransport: "quic", RequireFilePayloadEngine: FilePayloadEngineQUIC,
				RequireEngineTelemetry: true,
			})
			if err == nil || !strings.Contains(err.Error(), column) {
				t.Fatalf("Check() error = %v, want missing %s", err, column)
			}
		})
	}
}

func TestCheckRejectsInvalidQUICEngineRelations(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		want      string
	}{
		{name: "lost exceeds sent", overrides: map[string]string{"quic_packets_sent": "4", "quic_packets_lost": "5"}, want: "quic_packets_lost"},
		{name: "recovery exceeds wire", overrides: map[string]string{"quic_wire_bytes_sent": "100", "quic_recovery_wire_bytes": "101"}, want: "quic_recovery_wire_bytes"},
		{name: "sender stream bytes short", overrides: map[string]string{"quic_stream_bytes_sent": "1023"}, want: "quic_stream_bytes_sent"},
		{name: "invalid GSO state", overrides: map[string]string{"quic_native_gso": "maybe"}, want: "quic_native_gso"},
		{name: "invalid receive batch state", overrides: map[string]string{"quic_native_receive_batch": "maybe"}, want: "quic_native_receive_batch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trace := testQUICEngineTrace(t, RoleSend, test.overrides)
			_, err := Check(strings.NewReader(trace), Options{
				Role: RoleSend, ExpectedBytes: 1024, ExpectedBytesSet: true,
				ExpectedPayloadBytes: 1024, ExpectedPayloadBytesSet: true,
				RequireDirectTransport: "quic", RequireFilePayloadEngine: FilePayloadEngineQUIC,
				RequireEngineTelemetry: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check() error = %v, want %s relation failure", err, test.want)
			}
		})
	}
}

func TestCheckAcceptsHealthyZeroLossQUICEngineTelemetry(t *testing.T) {
	trace := testQUICEngineTrace(t, RoleReceive, map[string]string{
		"file_source_read_calls":       "0",
		"file_source_read_bytes":       "0",
		"quic_stream_bytes_sent":       "0",
		"quic_stream_bytes_received":   "1024",
		"file_payload_bytes_committed": "1024",
		"file_payload_bytes_quic":      "1024",
	})
	_, err := Check(strings.NewReader(trace), Options{
		Role: RoleReceive, ExpectedBytes: 1024, ExpectedBytesSet: true,
		ExpectedPayloadBytes: 1024, ExpectedPayloadBytesSet: true,
		RequireDirectTransport: "quic", RequireFilePayloadEngine: FilePayloadEngineQUIC,
		RequireEngineTelemetry: true,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckRejectsQUICPayloadWithoutMechanismEvidence(t *testing.T) {
	trace := testQUICEngineTrace(t, RoleSend, map[string]string{
		"quic_handshake_ms":      "0",
		"quic_first_byte_ms":     "0",
		"quic_smoothed_rtt_ms":   "0",
		"quic_packets_sent":      "0",
		"quic_packets_received":  "0",
		"quic_wire_bytes_sent":   "0",
		"quic_stream_bytes_sent": "1024",
		"file_source_read_calls": "1",
		"file_source_read_bytes": "1024",
	})
	_, err := Check(strings.NewReader(trace), Options{
		Role: RoleSend, ExpectedBytes: 1024, ExpectedBytesSet: true,
		ExpectedPayloadBytes: 1024, ExpectedPayloadBytesSet: true,
		RequireDirectTransport: "quic", RequireFilePayloadEngine: FilePayloadEngineQUIC,
		RequireEngineTelemetry: true,
	})
	if err == nil {
		t.Fatal("QUIC payload with no timing, packet, or wire evidence accepted")
	}
}

func TestCheckRequiresCompleteBulkEngineTelemetry(t *testing.T) {
	common := []string{
		"file_source_read_calls", "file_source_read_bytes",
		"bulk_candidate_id", "bulk_native_send_attempts", "bulk_native_send_syscalls",
		"bulk_gso_messages", "bulk_logical_datagrams", "bulk_accepted_payload_bytes",
		"bulk_gso_segments_per_message", "bulk_batch_backend", "bulk_gso_attempted",
		"bulk_gso_active", "bulk_gso_segments", "bulk_probe_selected_mbps",
		"bulk_probe_duration_ms", "bulk_probe_trains", "bulk_probe_sent_datagrams",
		"bulk_probe_received_datagrams", "bulk_probe_loss_ppm", "bulk_probe_pressure", "bulk_probe_stop_reason",
	}
	required := map[Role][]string{
		RoleSend: append(append([]string{}, common...),
			"bulk_send_calls", "bulk_send_datagrams", "bulk_max_send_batch", "bulk_crypto_queue_peak",
			"bulk_lane_queue_peak", "local_enobufs_retries", "local_enobufs_wait_us",
			"local_enobufs_max_consecutive", "repair_queue_bytes", "peer_recv_queue_depth",
			"peer_recv_queue_depth_max", "retransmits", "repair_requests", "repair_bytes"),
		RoleReceive: append(append([]string{}, common...),
			"bulk_receive_calls", "bulk_receive_datagrams", "bulk_max_receive_batch", "bulk_crypto_queue_peak",
			"bulk_writer_queue_peak", "bulk_receive_queue_peak", "bulk_decrypt_batches", "bulk_decrypt_datagrams",
			"repair_requests", "missing_scan_checks", "pending_missing", "pending_missing_peak",
			"repair_requested_packets", "repair_request_batches", "reorder_trail_packets", "receive_packet_rate_pps"),
	}
	for role, columns := range required {
		for _, column := range columns {
			t.Run(string(role)+"/"+column, func(t *testing.T) {
				trace := testBulkEngineTrace(t, role, map[string]string{column: ""})
				_, err := Check(strings.NewReader(trace), testBulkEngineOptions(role))
				if err == nil || !strings.Contains(err.Error(), column) {
					t.Fatalf("Check() error = %v, want missing %s", err, column)
				}
			})
		}
	}
}

func TestCheckAcceptsHealthyZeroBulkReceiverTelemetry(t *testing.T) {
	trace := testBulkEngineTrace(t, RoleReceive, nil)
	if _, err := Check(strings.NewReader(trace), testBulkEngineOptions(RoleReceive)); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckRejectsInvalidBulkEngineRelations(t *testing.T) {
	tests := []struct {
		name      string
		role      Role
		overrides map[string]string
		want      string
	}{
		{name: "attempts below syscalls", role: RoleSend, overrides: map[string]string{"bulk_native_send_attempts": "1", "bulk_native_send_syscalls": "2"}, want: "bulk_native_send_attempts"},
		{name: "syscalls below successful calls", role: RoleSend, overrides: map[string]string{"bulk_native_send_syscalls": "1", "bulk_send_calls": "2"}, want: "bulk_native_send_syscalls"},
		{name: "accepted payload short", role: RoleSend, overrides: map[string]string{"bulk_accepted_payload_bytes": "1023"}, want: "bulk_accepted_payload_bytes"},
		{name: "logical datagrams below calls", role: RoleSend, overrides: map[string]string{"bulk_logical_datagrams": "1", "bulk_send_calls": "2"}, want: "bulk_logical_datagrams"},
		{name: "active GSO without messages", role: RoleSend, overrides: map[string]string{"bulk_gso_messages": "0"}, want: "bulk_gso_messages"},
		{name: "active GSO without accepted segments", role: RoleSend, overrides: map[string]string{"bulk_gso_segments": "0"}, want: "bulk_gso_segments"},
		{name: "active GSO without segments", role: RoleSend, overrides: map[string]string{"bulk_gso_segments_per_message": "0"}, want: "bulk_gso_segments_per_message"},
		{name: "probe receives more than sent", role: RoleSend, overrides: map[string]string{"bulk_probe_sent_datagrams": "9", "bulk_probe_received_datagrams": "10"}, want: "bulk_probe_received_datagrams"},
		{name: "unknown probe stop reason", role: RoleSend, overrides: map[string]string{"bulk_probe_stop_reason": "timeout"}, want: "bulk probe stop reason"},
		{name: "sender repair requests negative", role: RoleSend, overrides: map[string]string{"repair_requests": "-1"}, want: "repair"},
		{name: "receiver repair requests negative", role: RoleReceive, overrides: map[string]string{"repair_requests": "-1"}, want: "repair"},
		{name: "pending missing exceeds peak", role: RoleReceive, overrides: map[string]string{"pending_missing": "2", "pending_missing_peak": "1"}, want: "pending_missing"},
		{name: "receiver invents attempts", role: RoleReceive, overrides: map[string]string{"bulk_native_send_attempts": "1"}, want: "receiver bulk native send counters"},
		{name: "receiver invents accepted payload", role: RoleReceive, overrides: map[string]string{"bulk_accepted_payload_bytes": "1"}, want: "receiver bulk native send counters"},
		{name: "receiver invents GSO segments", role: RoleReceive, overrides: map[string]string{"bulk_gso_segments": "1"}, want: "receiver bulk native send counters"},
		{name: "receiver invents successful sends", role: RoleReceive, overrides: map[string]string{"bulk_send_calls": "1"}, want: "receiver bulk native send counters"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trace := testBulkEngineTrace(t, test.role, test.overrides)
			_, err := Check(strings.NewReader(trace), testBulkEngineOptions(test.role))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check() error = %v, want %s relation failure", err, test.want)
			}
		})
	}
}

func TestCheckRejectsInvalidBulkDecisionRelations(t *testing.T) {
	tests := []struct {
		name  string
		trace func(*testing.T) string
		want  string
	}{
		{
			name: "bulk engine with quic decision",
			trace: func(t *testing.T) string {
				return testBulkEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected",
				})
			},
			want: "bulk decision mode",
		},
		{
			name: "quic engine with bulk decision",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "bulk-packets-v1", "bulk_decision_reason": "both-probes-accepted", "bulk_decision_run_id": "77",
				})
			},
			want: "bulk decision mode",
		},
		{
			name: "decision with zero run id",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "0",
				})
			},
			want: "bulk decision run ID",
		},
		{
			name: "bulk decision with zero selected rate",
			trace: func(t *testing.T) string {
				return testBulkEngineTrace(t, RoleSend, map[string]string{"bulk_probe_selected_mbps": "0"})
			},
			want: "bulk probe selected rate",
		},
		{
			name: "unstable reason",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "peer-said-no", "bulk_decision_run_id": "77",
				})
			},
			want: "bulk decision reason",
		},
		{
			name: "non-decimal handoff datagrams",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "77",
					"bulk_probe_reject_stage": "ack-timeout", "bulk_handoff_drained_datagrams": "9.5", "bulk_handoff_drain_duration_ms": "17",
				})
			},
			want: "bulk_handoff_drained_datagrams",
		},
		{
			name: "non-decimal handoff duration",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "77",
					"bulk_probe_reject_stage": "ack-timeout", "bulk_handoff_drained_datagrams": "0", "bulk_handoff_drain_duration_ms": "17ms",
				})
			},
			want: "bulk_handoff_drain_duration_ms",
		},
		{
			name: "unknown rejection stage",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "77",
					"bulk_probe_reject_stage": "capacity", "bulk_handoff_drained_datagrams": "0", "bulk_handoff_drain_duration_ms": "17",
				})
			},
			want: "bulk probe rejection stage",
		},
		{
			name: "quic fallback without positive handoff duration",
			trace: func(t *testing.T) string {
				return testQUICEngineTrace(t, RoleSend, map[string]string{
					"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "77",
					"bulk_probe_reject_stage": "selector", "bulk_handoff_drained_datagrams": "0", "bulk_handoff_drain_duration_ms": "0",
				})
			},
			want: "bulk handoff drain duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Check(strings.NewReader(test.trace(t)), Options{Role: RoleSend})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check() error = %v, want %s failure", err, test.want)
			}
		})
	}
}

func TestCheckAcceptsQUICBulkFallbackWithQuietHandoff(t *testing.T) {
	trace := testQUICEngineTrace(t, RoleSend, map[string]string{
		"bulk_decision_mode": "quic", "bulk_decision_reason": "sender-probe-rejected", "bulk_decision_run_id": "77",
		"bulk_probe_reject_stage": "ack-timeout", "bulk_handoff_drained_datagrams": "0", "bulk_handoff_drain_duration_ms": "17",
	})
	if _, err := Check(strings.NewReader(trace), Options{Role: RoleSend}); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckRejectsChangingBulkDecisionAcrossRows(t *testing.T) {
	trace := "timestamp_unix_ms,role,phase,app_bytes,last_error,bulk_decision_mode,bulk_decision_reason,bulk_decision_run_id\n" +
		"1000,send,direct_prepare,0,,bulk-packets-v1,both-probes-accepted,77\n" +
		"1100,send,complete,0,,quic,sender-probe-rejected,77\n"
	_, err := Check(strings.NewReader(trace), Options{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "bulk decision changed") {
		t.Fatalf("Check() error = %v, want immutable decision failure", err)
	}
}

func TestCheckRejectsDisappearingBulkDecisionAcrossRows(t *testing.T) {
	trace := "timestamp_unix_ms,role,phase,app_bytes,last_error,bulk_decision_mode,bulk_decision_reason,bulk_decision_run_id\n" +
		"1000,send,direct_prepare,0,,bulk-packets-v1,both-probes-accepted,77\n" +
		"1100,send,complete,0,,,,\n"
	_, err := Check(strings.NewReader(trace), Options{Role: RoleSend})
	if err == nil || err.Error() != "row 3: bulk decision evidence disappeared" {
		t.Fatalf("Check() error = %v, want exact disappearing evidence failure", err)
	}
}

func TestCheckRejectsMalformedBulkDecisionTuple(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		reason string
		runID  string
		want   string
	}{
		{name: "incomplete", mode: "quic", reason: "sender-probe-rejected", want: "row 2: bulk decision mode, reason, and run ID must be set together"},
		{name: "unknown mode", mode: "udp", reason: "both-probes-accepted", runID: "77", want: `row 2: bulk decision mode "udp" is invalid`},
		{name: "bulk reason", mode: "bulk-packets-v1", reason: "sender-probe-rejected", runID: "77", want: `row 2: bulk decision reason "sender-probe-rejected" is invalid for bulk-packets-v1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := "timestamp_unix_ms,role,phase,app_bytes,last_error,bulk_decision_mode,bulk_decision_reason,bulk_decision_run_id\n" +
				"1000,send,complete,0,," + tt.mode + "," + tt.reason + "," + tt.runID + "\n"
			_, err := Check(strings.NewReader(trace), Options{Role: RoleSend})
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Check() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func testBulkEngineOptions(role Role) Options {
	return Options{
		Role: role, ExpectedBytes: 1024, ExpectedBytesSet: true,
		ExpectedPayloadBytes: 1024, ExpectedPayloadBytesSet: true,
		RequireDirectTransport: "udp", RequireFilePayloadEngine: FilePayloadEngineBulk,
		RequireEngineTelemetry: true,
	}
}

func testBulkEngineTrace(t *testing.T, role Role, overrides map[string]string) string {
	t.Helper()
	values := map[string]string{
		"timestamp_unix_ms": "1000", "role": string(role), "phase": "complete", "app_bytes": "1024",
		"last_error": "", "direct_validated": "true", "last_state": "stream-complete", "direct_transport": "udp",
		"file_payload_engine": string(FilePayloadEngineBulk), "file_payload_bytes_committed": "0",
		"file_payload_bytes_bulk": "0", "file_payload_bytes_quic": "0", "file_payload_lane_addrs": `["203.0.113.10:41000"]`,
		"file_source_read_calls": "1", "file_source_read_bytes": "1024", "bulk_candidate_id": "combined-gso3",
		"bulk_native_send_attempts": "2", "bulk_native_send_syscalls": "2", "bulk_gso_messages": "1",
		"bulk_logical_datagrams": "8", "bulk_accepted_payload_bytes": "1024", "bulk_gso_segments_per_message": "3",
		"bulk_batch_backend": "linux-gso", "bulk_gso_attempted": "true", "bulk_gso_active": "true",
		"bulk_gso_segments": "8", "bulk_send_calls": "2", "bulk_send_datagrams": "8", "bulk_receive_calls": "0",
		"bulk_receive_datagrams": "0", "bulk_max_send_batch": "8", "bulk_max_receive_batch": "0",
		"bulk_crypto_queue_peak": "0", "bulk_writer_queue_peak": "0", "bulk_lane_queue_peak": "0",
		"bulk_receive_queue_peak": "0", "bulk_decrypt_batches": "0", "bulk_decrypt_datagrams": "0",
		"bulk_probe_selected_mbps": "2160", "bulk_probe_duration_ms": "250", "bulk_probe_trains": "5",
		"bulk_probe_sent_datagrams": "100", "bulk_probe_received_datagrams": "99", "bulk_probe_loss_ppm": "10000",
		"bulk_probe_pressure": "false", "bulk_probe_stop_reason": "ladder-complete",
		"local_enobufs_retries": "0", "local_enobufs_wait_us": "0",
		"local_enobufs_max_consecutive": "0", "repair_queue_bytes": "0", "peer_recv_queue_depth": "0",
		"peer_recv_queue_depth_max": "0", "retransmits": "0", "repair_requests": "0", "repair_bytes": "0",
		"missing_scan_checks": "0", "pending_missing": "0", "pending_missing_peak": "0",
		"repair_requested_packets": "0", "repair_request_batches": "0", "reorder_trail_packets": "0",
		"receive_packet_rate_pps": "100",
		"bulk_decision_mode":      "bulk-packets-v1", "bulk_decision_reason": "both-probes-accepted",
		"bulk_decision_run_id": "77",
	}
	if role == RoleReceive {
		values["file_payload_bytes_committed"] = "1024"
		values["file_payload_bytes_bulk"] = "1024"
		values["file_source_read_calls"] = "0"
		values["file_source_read_bytes"] = "0"
		values["bulk_native_send_attempts"] = "0"
		values["bulk_native_send_syscalls"] = "0"
		values["bulk_gso_messages"] = "0"
		values["bulk_logical_datagrams"] = "0"
		values["bulk_accepted_payload_bytes"] = "0"
		values["bulk_gso_segments_per_message"] = "0"
		values["bulk_batch_backend"] = "linux-recvmmsg"
		values["bulk_gso_attempted"] = "false"
		values["bulk_gso_active"] = "false"
		values["bulk_gso_segments"] = "0"
		values["bulk_send_calls"] = "0"
		values["bulk_send_datagrams"] = "0"
		values["bulk_max_send_batch"] = "0"
		values["bulk_receive_calls"] = "2"
		values["bulk_receive_datagrams"] = "8"
		values["bulk_max_receive_batch"] = "4"
		values["bulk_decrypt_batches"] = "2"
		values["bulk_decrypt_datagrams"] = "8"
	}
	for name, value := range overrides {
		values[name] = value
	}
	var body bytes.Buffer
	w := csv.NewWriter(&body)
	columns := append([]string(nil), Header...)
	if err := w.Write(columns); err != nil {
		t.Fatal(err)
	}
	row := make([]string, len(columns))
	for index, column := range columns {
		row[index] = values[column]
	}
	if err := w.Write(row); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

func testQUICEngineTrace(t *testing.T, role Role, overrides map[string]string) string {
	t.Helper()
	columns := []string{
		"timestamp_unix_ms", "role", "phase", "app_bytes", "last_error", "direct_validated", "last_state", "direct_transport",
		"file_payload_engine", "file_payload_bytes_committed", "file_payload_bytes_bulk", "file_payload_bytes_quic", "file_payload_lane_addrs",
		"quic_connections", "quic_streams", "quic_telemetry_present", "quic_version", "quic_raw_socket_backend", "quic_native_send_backend", "quic_native_receive_backend",
		"quic_handshake_ms", "quic_first_byte_ms", "quic_smoothed_rtt_ms", "quic_packets_sent", "quic_packets_received", "quic_packets_lost",
		"quic_wire_bytes_sent", "quic_recovery_wire_bytes", "quic_recovery_ratio", "quic_stream_bytes_sent", "quic_stream_bytes_received", "quic_close_reason",
		"quic_native_gso", "quic_native_receive_batch", "file_source_read_calls", "file_source_read_bytes",
		"bulk_decision_mode", "bulk_decision_reason", "bulk_decision_run_id",
		"bulk_probe_reject_stage", "bulk_handoff_drained_datagrams", "bulk_handoff_drain_duration_ms",
	}
	values := map[string]string{
		"timestamp_unix_ms": "1000", "role": string(role), "phase": "complete", "app_bytes": "1024", "last_error": "",
		"direct_validated": "true", "last_state": "stream-complete", "direct_transport": "quic",
		"file_payload_engine": string(FilePayloadEngineQUIC), "file_payload_bytes_committed": "0", "file_payload_bytes_bulk": "0", "file_payload_bytes_quic": "0",
		"file_payload_lane_addrs": `["203.0.113.10:41000"]`, "quic_connections": "1", "quic_streams": "1", "quic_telemetry_present": "true", "quic_version": "v1",
		"quic_raw_socket_backend": "quic-go-oob", "quic_native_send_backend": "udp-gso-or-sendmsg", "quic_native_receive_backend": "udp-recvmmsg",
		"quic_handshake_ms": "1", "quic_first_byte_ms": "2", "quic_smoothed_rtt_ms": "3", "quic_packets_sent": "10", "quic_packets_received": "8", "quic_packets_lost": "0",
		"quic_wire_bytes_sent": "12000", "quic_recovery_wire_bytes": "0", "quic_recovery_ratio": "0", "quic_stream_bytes_sent": "1024", "quic_stream_bytes_received": "0",
		"quic_close_reason": "complete", "quic_native_gso": "false", "quic_native_receive_batch": "true", "file_source_read_calls": "1", "file_source_read_bytes": "1024",
	}
	for name, value := range overrides {
		values[name] = value
	}
	var body bytes.Buffer
	w := csv.NewWriter(&body)
	if err := w.Write(columns); err != nil {
		t.Fatal(err)
	}
	row := make([]string, len(columns))
	for i, column := range columns {
		row[i] = values[column]
	}
	if err := w.Write(row); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

func TestCheckRequiresUDPDirectTransport(t *testing.T) {
	csvText := HeaderLine + "\n" + testTraceRow(testTraceRowConfig{
		timestampMS:     1000,
		role:            RoleSend,
		phase:           PhaseComplete,
		appBytes:        1024,
		deltaAppBytes:   1024,
		directValidated: true,
		directTransport: "tcp",
	})
	_, err := Check(strings.NewReader(csvText), Options{
		Role: RoleSend, ExpectedBytes: 1024, ExpectedBytesSet: true,
		RequireDirectTransport: "udp",
	})
	if err == nil || !strings.Contains(err.Error(), `direct transport = "tcp", want "udp"`) {
		t.Fatalf("Check() error = %v, want UDP transport mismatch", err)
	}
}

func TestCheckForbidsRelayPayload(t *testing.T) {
	csvText := HeaderLine + "\n" + testTraceRow(testTraceRowConfig{
		timestampMS:     1000,
		role:            RoleReceive,
		phase:           PhaseComplete,
		relayBytes:      1,
		appBytes:        1024,
		deltaAppBytes:   1024,
		directValidated: true,
		directTransport: "udp",
	})
	_, err := Check(strings.NewReader(csvText), Options{
		Role: RoleReceive, ExpectedBytes: 1024, ExpectedBytesSet: true,
		RequireDirectTransport: "udp", ForbidRelayPayload: true,
	})
	if err == nil || !strings.Contains(err.Error(), "relay payload bytes = 1, want 0") {
		t.Fatalf("Check() error = %v, want relay payload rejection", err)
	}
}

func TestCheckRequiresExactReceiverFilePayloadAccounting(t *testing.T) {
	wantBytes := strconv.FormatInt(3<<30, 10)
	trace := testBulkEngineTrace(t, RoleReceive, map[string]string{
		"app_bytes":                    wantBytes,
		"file_payload_bytes_committed": wantBytes,
		"file_payload_bytes_bulk":      wantBytes,
	})
	result, err := Check(strings.NewReader(trace), Options{
		Role:                       RoleReceive,
		ExpectedPayloadBytes:       3 << 30,
		ExpectedPayloadBytesSet:    true,
		RequireFilePayloadEngine:   FilePayloadEngineBulk,
		RequireEngineTelemetry:     true,
		ExpectedSelectedPublicIPv4: "203.0.113.10",
	})
	if err != nil || result.FinalFilePayloadBytes != 3<<30 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if result.FinalFilePayloadEngine != FilePayloadEngineBulk || result.FinalFilePayloadBytesBulk != 3<<30 || result.FinalFilePayloadBytesQUIC != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestCheckRejectsWrongFilePayloadEngineCounter(t *testing.T) {
	for _, tt := range []struct {
		name      string
		committed int64
		bulk      int64
		quic      int64
	}{
		{name: "committed mismatch", committed: 4095, bulk: 4096},
		{name: "sum mismatch", committed: 4096, bulk: 4095},
		{name: "other engine nonzero", committed: 4096, bulk: 4095, quic: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trace := testTraceWithFilePayload(RoleReceive, FilePayloadEngineBulk, 4096, tt.committed, tt.bulk, tt.quic, `["203.0.113.10:41000"]`)
			_, err := Check(strings.NewReader(trace), Options{
				Role: RoleReceive, ExpectedPayloadBytes: 4096, ExpectedPayloadBytesSet: true,
				RequireFilePayloadEngine: FilePayloadEngineBulk,
			})
			if err == nil {
				t.Fatal("invalid file payload accounting accepted")
			}
		})
	}
}

func TestCheckRejectsSenderOwnedFilePayloadCounters(t *testing.T) {
	trace := testTraceWithFilePayload(RoleSend, FilePayloadEngineBulk, 4096, 1, 1, 0, `["203.0.113.10:41000"]`)
	_, err := Check(strings.NewReader(trace), Options{
		Role: RoleSend, ExpectedPayloadBytes: 4096, ExpectedPayloadBytesSet: true,
		RequireFilePayloadEngine: FilePayloadEngineBulk,
	})
	if err == nil {
		t.Fatal("sender-owned committed payload accepted")
	}
}

func TestCheckRejectsSenderOwnedFilePayloadCountersWithoutExpectedSize(t *testing.T) {
	trace := testTraceWithFilePayload(RoleSend, FilePayloadEngineBulk, 4096, 1, 1, 0, `["203.0.113.10:41000"]`)
	_, err := Check(strings.NewReader(trace), Options{Role: RoleSend, RequireFilePayloadEngine: FilePayloadEngineBulk})
	if err == nil {
		t.Fatal("sender-owned committed payload accepted without expected size")
	}
}

func TestCheckRequiresObservedFilePayloadZeroCounters(t *testing.T) {
	trace := "timestamp_unix_ms,role,phase,app_bytes,last_error,file_payload_engine,bulk_probe_selected_mbps,bulk_decision_mode,bulk_decision_reason,bulk_decision_run_id\n" +
		"1000,send,complete,0,,bulk-packets-v1,1,bulk-packets-v1,both-probes-accepted,77\n"
	_, err := Check(strings.NewReader(trace), Options{Role: RoleSend, RequireFilePayloadEngine: FilePayloadEngineBulk})
	if err == nil || !strings.Contains(err.Error(), "missing observed") {
		t.Fatalf("Check() error = %v, want missing observed zero counter", err)
	}
}

func TestCheckRejectsUnexpectedOrNonPublicLane(t *testing.T) {
	for _, tt := range []struct {
		name  string
		lanes string
	}{
		{name: "unexpected", lanes: `["198.51.100.20:42000"]`},
		{name: "private", lanes: `["10.0.0.8:42000"]`},
		{name: "link local", lanes: `["169.254.1.8:42000"]`},
		{name: "cgnat", lanes: `["100.100.1.8:42000"]`},
		{name: "ula", lanes: `["[fd00::8]:42000"]`},
		{name: "multicast", lanes: `["224.0.0.8:42000"]`},
		{name: "duplicate", lanes: `["203.0.113.10:41000","203.0.113.10:41000"]`},
		{name: "malformed json", lanes: `203.0.113.10:41000`},
		{name: "malformed address", lanes: `["not-an-address"]`},
		{name: "empty", lanes: `[]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trace := testTraceWithFilePayload(RoleReceive, FilePayloadEngineBulk, 4096, 4096, 4096, 0, tt.lanes)
			_, err := Check(strings.NewReader(trace), Options{
				Role: RoleReceive, ExpectedPayloadBytes: 4096, ExpectedPayloadBytesSet: true,
				RequireFilePayloadEngine: FilePayloadEngineBulk, ExpectedSelectedPublicIPv4: "203.0.113.10",
			})
			if err == nil {
				t.Fatal("invalid selected lane accepted")
			}
		})
	}
}

func TestCheckPairRejectsEngineDisagreement(t *testing.T) {
	send := testTraceWithFilePayload(RoleSend, FilePayloadEngineQUIC, 4096, 0, 0, 0, `["203.0.113.10:41000"]`)
	receive := testTraceWithFilePayload(RoleReceive, FilePayloadEngineBulk, 4096, 4096, 4096, 0, `["198.51.100.20:42000"]`)
	if _, err := CheckPair(strings.NewReader(send), strings.NewReader(receive), PairOptions{Role: RoleSend}); err == nil {
		t.Fatal("engine disagreement accepted")
	}
}

func TestCheckPairRejectsBulkDecisionDisagreement(t *testing.T) {
	quicSenderRejected := checkerRowBulkDecision{set: true, mode: "quic", reason: "sender-probe-rejected", runID: 77}
	quicReceiverRejected := checkerRowBulkDecision{set: true, mode: "quic", reason: "receiver-probe-rejected", runID: 77}
	quicDifferentRun := checkerRowBulkDecision{set: true, mode: "quic", reason: "sender-probe-rejected", runID: 88}
	bulkAccepted := checkerRowBulkDecision{set: true, mode: "bulk-packets-v1", reason: "both-probes-accepted", runID: 77}
	tests := []struct {
		name             string
		senderDecision   checkerRowBulkDecision
		receiverDecision checkerRowBulkDecision
		want             string
	}{
		{
			name:             "presence",
			senderDecision:   quicSenderRejected,
			receiverDecision: checkerRowBulkDecision{},
			want:             "sender/receiver bulk decision presence differs: sender=true receiver=false",
		},
		{
			name:             "mode",
			senderDecision:   quicSenderRejected,
			receiverDecision: bulkAccepted,
			want:             `sender bulk decision mode = "quic", receiver = "bulk-packets-v1"`,
		},
		{
			name:             "reason",
			senderDecision:   quicSenderRejected,
			receiverDecision: quicReceiverRejected,
			want:             `sender bulk decision reason = "sender-probe-rejected", receiver = "receiver-probe-rejected"`,
		},
		{
			name:             "run ID",
			senderDecision:   quicSenderRejected,
			receiverDecision: quicDifferentRun,
			want:             "sender bulk decision run ID = 77, receiver = 88",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			send := testTraceWithFilePayload(RoleSend, FilePayloadEngineQUIC, 4096, 0, 0, 0, `["203.0.113.10:41000"]`)
			receive := testTraceWithFilePayload(RoleReceive, FilePayloadEngineQUIC, 4096, 4096, 0, 4096, `["198.51.100.20:42000"]`)
			send = testTraceWithFinalBulkDecision(t, send, tt.senderDecision)
			receive = testTraceWithFinalBulkDecision(t, receive, tt.receiverDecision)

			_, err := CheckPair(strings.NewReader(send), strings.NewReader(receive), PairOptions{Role: RoleSend})
			if err == nil || err.Error() != tt.want {
				t.Fatalf("CheckPair() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckReportsRepairEfficiencyDiagnostics(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error,missing_scan_checks,pending_missing,pending_missing_peak,repair_requested_packets,repair_request_batches,reorder_trail_packets,receive_packet_rate_pps\n" +
		"1000,receive,direct_execute,1024,,790545,1234,1234,4567,32,22000,88000\n" +
		"1500,receive,complete,2048,,790000,0,1200,4500,30,21000,87000\n"
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleReceive, ExpectedBytes: 2048, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	diagnostics := result.Diagnostics
	if !diagnostics.ReceiverRepairObserved {
		t.Fatal("ReceiverRepairObserved = false, want true")
	}
	if diagnostics.MissingScanChecks != 790_545 ||
		diagnostics.PendingMissing != 0 ||
		diagnostics.PendingMissingPeak != 1234 ||
		diagnostics.RepairRequestedPackets != 4567 ||
		diagnostics.RepairRequestBatches != 32 ||
		diagnostics.ReorderTrailPackets != 22_000 ||
		diagnostics.ReceivePacketRatePPS != 88_000 {
		t.Fatalf("repair efficiency diagnostics = %#v", diagnostics)
	}
}

func TestCheckTreatsZeroRepairEfficiencyDiagnosticsAsObserved(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error,missing_scan_checks,pending_missing,pending_missing_peak,repair_requested_packets,repair_request_batches,reorder_trail_packets,receive_packet_rate_pps\n" +
		"1000,receive,complete,0,,0,0,0,0,0,0,0\n"
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleReceive, ExpectedBytes: 0, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Diagnostics.ReceiverRepairObserved {
		t.Fatalf("Diagnostics = %#v, want zero repair values observed", result.Diagnostics)
	}
}

func TestCheckAcceptsLegacyRowWithoutRepairEfficiencyDiagnostics(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error,missing_scan_checks,pending_missing,pending_missing_peak,repair_requested_packets,repair_request_batches,reorder_trail_packets,receive_packet_rate_pps\n" +
		"1000,receive,complete,4096,\n"
	result, err := Check(strings.NewReader(csvText), Options{
		Role: RoleReceive, ExpectedBytes: 4096, ExpectedBytesSet: true,
	})
	if err != nil {
		t.Fatalf("Check() legacy row error = %v", err)
	}
	if result.Diagnostics.ReceiverRepairObserved {
		t.Fatalf("Diagnostics = %#v, want repair diagnostics absent", result.Diagnostics)
	}
}

func TestCheckKeepsDiagnosticsAbsentForMinimalAndEmptyTrace(t *testing.T) {
	tests := []struct {
		name string
		csv  string
	}{
		{
			name: "minimal header",
			csv: "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
				"1000,receive,complete,4096,\n",
		},
		{
			name: "empty diagnostic cells",
			csv: HeaderLine + "\n" +
				testTraceRow(testTraceRowConfig{
					timestampMS:     1000,
					role:            RoleReceive,
					phase:           PhaseComplete,
					appBytes:        4096,
					deltaAppBytes:   4096,
					directValidated: true,
					lastState:       "stream-complete",
				}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Check(strings.NewReader(tt.csv), Options{Role: RoleReceive, ExpectedBytes: 4096, ExpectedBytesSet: true})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if result.Diagnostics != (DiagnosticsSummary{}) {
				t.Fatalf("Diagnostics = %#v, want absent zero summary", result.Diagnostics)
			}
		})
	}
}

func TestCheckFailsMalformedNonEmptyDiagnosticField(t *testing.T) {
	for _, column := range []string{"rate_target_mbps", "rate_ceiling_mbps"} {
		t.Run(column, func(t *testing.T) {
			csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error," + column + "\n" +
				"1000,send,complete,1024,,fast\n"
			_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, ExpectedBytes: 1024, ExpectedBytesSet: true})
			if err == nil || !strings.Contains(err.Error(), "row 2") || !strings.Contains(err.Error(), "parse "+column) || !strings.Contains(err.Error(), "fast") {
				t.Fatalf("Check() error = %v, want malformed %s at row 2", err, column)
			}
		})
	}
}

func TestCheckPairAllowsSynchronizedSenderReceiverProgress(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          1024,
			deltaAppBytes:     1024,
			peerReceivedBytes: 1024,
			transferElapsedMS: 500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "stream-complete",
		})
	result, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err != nil {
		t.Fatalf("CheckPair() error = %v", err)
	}
	if result.PrimaryRows != 1 || result.PeerRows != 1 || result.ProgressDeltaBytes != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckPairUsesTransferElapsedForPeerProgressLead(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			elapsedMS:         2000,
			role:              RoleSend,
			phase:             PhaseRelay,
			appBytes:          1024,
			deltaAppBytes:     1024,
			peerReceivedBytes: 1024,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			elapsedMS:         3000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          2048,
			deltaAppBytes:     1024,
			peerReceivedBytes: 2048,
			transferElapsedMS: 1000,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:   1008,
			elapsedMS:     1500,
			role:          RoleReceive,
			phase:         PhaseRelay,
			appBytes:      1024,
			deltaAppBytes: 1024,
			lastState:     "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:   2008,
			elapsedMS:     2500,
			role:          RoleReceive,
			phase:         PhaseComplete,
			appBytes:      2048,
			deltaAppBytes: 1024,
			lastState:     "stream-complete",
		})
	result, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err != nil {
		t.Fatalf("CheckPair() error = %v", err)
	}
	if result.MaxProgressLeadBytes != 0 {
		t.Fatalf("MaxProgressLeadBytes = %d, want 0", result.MaxProgressLeadBytes)
	}
}

func TestCheckPairFailsSenderPeerProgressDivergence(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          2048,
			deltaAppBytes:     2048,
			peerReceivedBytes: 2048,
			transferElapsedMS: 500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "sender peer_received_bytes") {
		t.Fatalf("CheckPair() error = %v, want peer progress divergence", err)
	}
}

func TestCheckPairSkipsRateDivergenceWithoutReceiverTransferClock(t *testing.T) {
	const transferredBytes = int64(67108967)
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       4438,
			elapsedMS:         4438,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          transferredBytes,
			deltaAppBytes:     transferredBytes,
			peerReceivedBytes: transferredBytes,
			transferElapsedMS: 908,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:     4001,
			elapsedMS:       4001,
			role:            RoleReceive,
			phase:           PhaseDirectExecute,
			appBytes:        51951751,
			deltaAppBytes:   51951751,
			lastState:       "connected-direct",
			directValidated: true,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:     4438,
			elapsedMS:       4438,
			role:            RoleReceive,
			phase:           PhaseComplete,
			appBytes:        transferredBytes,
			deltaAppBytes:   transferredBytes - 51951751,
			lastState:       "stream-complete",
			directValidated: true,
		})

	result, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err != nil {
		t.Fatalf("CheckPair() error = %v", err)
	}
	if result.ProgressDeltaBytes != 0 {
		t.Fatalf("ProgressDeltaBytes = %d, want 0", result.ProgressDeltaBytes)
	}
	if result.MaxProgressLeadBytes != 0 {
		t.Fatalf("MaxProgressLeadBytes = %d, want 0", result.MaxProgressLeadBytes)
	}
	if math.Abs(result.SenderRateMbps-591.27) > 0.01 {
		t.Fatalf("SenderRateMbps = %.2f, want about 591.27", result.SenderRateMbps)
	}
	if result.ReceiverRateMbps != 0 {
		t.Fatalf("ReceiverRateMbps = %.2f, want 0 without an explicit transfer clock", result.ReceiverRateMbps)
	}
}

func TestCheckPairFailsTransferRateDivergence(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          1024,
			deltaAppBytes:     1024,
			peerReceivedBytes: 1024,
			transferElapsedMS: 500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 1000,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend, RateTolerance: 0.10})
	if err == nil || !strings.Contains(err.Error(), "transfer rate diverged") {
		t.Fatalf("CheckPair() error = %v, want rate divergence", err)
	}
}

func TestCheckPairFailsSenderProgressLeadDuringRun(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseRelay,
			appBytes:          8192,
			deltaAppBytes:     8192,
			peerReceivedBytes: 8192,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     0,
			peerReceivedBytes: 8192,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseRelay,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     7168,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "sender progress leads receiver") {
		t.Fatalf("CheckPair() error = %v, want sender progress lead", err)
	}
}

func TestCheckPairAllowsConfiguredProgressLeadTolerance(t *testing.T) {
	sendTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleSend,
			phase:             PhaseRelay,
			appBytes:          4096,
			deltaAppBytes:     4096,
			peerReceivedBytes: 4096,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleSend,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     4096,
			peerReceivedBytes: 8192,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	receiveTrace := HeaderLine + "\n" +
		testTraceRow(testTraceRowConfig{
			timestampMS:       1000,
			role:              RoleReceive,
			phase:             PhaseRelay,
			appBytes:          1024,
			deltaAppBytes:     1024,
			transferElapsedMS: 500,
			lastState:         "connected-relay",
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:       2000,
			role:              RoleReceive,
			phase:             PhaseComplete,
			appBytes:          8192,
			deltaAppBytes:     7168,
			transferElapsedMS: 1500,
			lastState:         "stream-complete",
		})
	_, err := CheckPair(strings.NewReader(sendTrace), strings.NewReader(receiveTrace), PairOptions{
		Role:                       RoleSend,
		ProgressLeadToleranceBytes: 4096,
	})
	if err != nil {
		t.Fatalf("CheckPair() error = %v", err)
	}
}

func TestCheckReturnsTerminalErrorResultMetadata(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,error,2048,message too long\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleSend})
	if err == nil || !strings.Contains(err.Error(), "message too long") {
		t.Fatalf("Check() error = %v, want terminal error", err)
	}
	if result.Rows != 1 || result.FinalAppBytes != 2048 || result.FinalPhase != PhaseError {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckFailsMalformedMatchingRowWithRowNumber(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"bad,receive,complete,4096,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "parse timestamp_unix_ms") || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("Check() error = %v, want malformed row 2", err)
	}
}

func TestCheckFailsShortMatchingRowWithRowNumber(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "row 2") || !strings.Contains(err.Error(), "wrong number of fields") {
		t.Fatalf("Check() error = %v, want short matching row 2", err)
	}
}

func TestCheckFailsTargetRowMissingTrailingLastError(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete,4096\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "row 2") || !strings.Contains(err.Error(), "wrong number of fields") {
		t.Fatalf("Check() error = %v, want missing trailing last_error row 2", err)
	}
}

func TestCheckFailsTargetRowWithExtraFields(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete,4096,,extra\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err == nil || !strings.Contains(err.Error(), "row 2") || !strings.Contains(err.Error(), "wrong number of fields") {
		t.Fatalf("Check() error = %v, want extra field row 2", err)
	}
}

func TestCheckFailsExpectedByteMismatch(t *testing.T) {
	csvText := HeaderLine + "\n" +
		padLegacyTraceRow("1000,0,receive,complete,0,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,stream-complete,")
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 2048})
	if err == nil || !strings.Contains(err.Error(), "final app bytes") {
		t.Fatalf("Check() error = %v, want byte mismatch", err)
	}
}

func TestCheckValidatesExplicitExpectedZeroBytes(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete,1024,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, ExpectedBytes: 0, ExpectedBytesSet: true})
	if err == nil || !strings.Contains(err.Error(), "final app bytes") {
		t.Fatalf("Check() error = %v, want zero-byte mismatch", err)
	}
}

func TestCheckAllowsOmittedExpectedZeroBytes(t *testing.T) {
	csvText := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,receive,complete,1024,\n"
	result, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.FinalAppBytes != 1024 {
		t.Fatalf("result = %#v", result)
	}
}

type testTraceRowConfig struct {
	timestampMS                    int64
	elapsedMS                      int64
	role                           Role
	phase                          Phase
	relayBytes                     int64
	directBytes                    int64
	appBytes                       int64
	deltaAppBytes                  int64
	appMbps                        string
	localSentBytes                 int64
	peerReceivedBytes              int64
	transferElapsedMS              int64
	directValidated                bool
	fallbackReason                 string
	lastState                      string
	lastError                      string
	rateTargetMbps                 int
	controllerDecision             string
	receiverCommittedMbps          string
	replayBytes                    uint64
	retransmits                    int64
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
	directTransport                string
	quicHandshakeMS                int64
	quicFirstByteMS                int64
	quicBytesSent                  int64
	quicGoodputMbps                string
	quicCloseReason                string
	filePayloadEngine              FilePayloadEngine
	filePayloadBytesCommitted      int64
	filePayloadBytesBulk           int64
	filePayloadBytesQUIC           int64
	filePayloadLaneAddresses       string
	fileSourceTelemetry            bool
	fileSourceReadCalls            uint64
	fileSourceReadBytes            uint64
}

func padLegacyTraceRow(row string) string {
	fields := strings.Split(row, ",")
	if len(fields) > len(Header) {
		panic("legacy trace row has more fields than current header")
	}
	fields = append(fields, make([]string, len(Header)-len(fields))...)
	return strings.Join(fields, ",") + "\n"
}

func testTraceRow(cfg testTraceRowConfig) string {
	fields := make([]string, len(Header))
	positions := make(map[string]int, len(Header))
	for i, name := range Header {
		positions[name] = i
	}
	set := func(name string, value string) {
		fields[positions[name]] = value
	}
	set("timestamp_unix_ms", strconv.FormatInt(cfg.timestampMS, 10))
	set("elapsed_ms", strconv.FormatInt(cfg.elapsedMS, 10))
	set("role", string(cfg.role))
	set("phase", string(cfg.phase))
	set("relay_bytes", strconv.FormatInt(cfg.relayBytes, 10))
	set("direct_bytes", strconv.FormatInt(cfg.directBytes, 10))
	set("app_bytes", strconv.FormatInt(cfg.appBytes, 10))
	set("delta_app_bytes", strconv.FormatInt(cfg.deltaAppBytes, 10))
	appMbps := cfg.appMbps
	if appMbps == "" {
		appMbps = "0.00"
	}
	set("app_mbps", appMbps)
	set("local_sent_bytes", strconv.FormatInt(cfg.localSentBytes, 10))
	set("peer_received_bytes", strconv.FormatInt(cfg.peerReceivedBytes, 10))
	set("transfer_elapsed_ms", formatTestOptionalInt64(cfg.transferElapsedMS))
	set("direct_validated", strconv.FormatBool(cfg.directValidated))
	set("fallback_reason", cfg.fallbackReason)
	set("last_state", cfg.lastState)
	set("last_error", cfg.lastError)
	set("rate_target_mbps", formatTestOptionalInt(cfg.rateTargetMbps))
	set("controller_decision", cfg.controllerDecision)
	set("receiver_committed_mbps", cfg.receiverCommittedMbps)
	set("replay_bytes", formatTestOptionalUint64(cfg.replayBytes))
	set("retransmits", formatTestOptionalInt64(cfg.retransmits))
	set("repair_bytes", formatTestOptionalInt64(cfg.repairBytes))
	set("local_enobufs_retries", formatTestOptionalInt64(cfg.localENOBUFSRetries))
	set("local_enobufs_wait_us", formatTestOptionalInt64(cfg.localENOBUFSWaitUS))
	set("local_enobufs_max_consecutive", formatTestOptionalInt64(cfg.localENOBUFSMaxConsecutive))
	set("peer_recv_queue_depth", formatTestOptionalInt(cfg.peerRecvQueueDepth))
	set("peer_recv_queue_depth_max", formatTestOptionalInt(cfg.peerRecvQueueDepthMax))
	set("striped_send_blocked_ms", formatTestOptionalInt64(cfg.stripedSendBlockedMS))
	set("striped_receive_pending_chunks", formatTestOptionalInt(cfg.stripedReceivePendingChunks))
	set("striped_receive_pending_chunks_max", formatTestOptionalInt(cfg.stripedReceivePendingChunksMax))
	set("striped_receive_pending_bytes", formatTestOptionalInt64(cfg.stripedReceivePendingBytes))
	set("striped_receive_pending_bytes_max", formatTestOptionalInt64(cfg.stripedReceivePendingBytesMax))
	set("direct_transport", cfg.directTransport)
	set("quic_handshake_ms", formatTestOptionalInt64(cfg.quicHandshakeMS))
	set("quic_first_byte_ms", formatTestOptionalInt64(cfg.quicFirstByteMS))
	set("quic_stream_bytes_sent", formatTestOptionalInt64(cfg.quicBytesSent))
	set("quic_stream_goodput_mbps", cfg.quicGoodputMbps)
	set("quic_close_reason", cfg.quicCloseReason)
	engine := cfg.filePayloadEngine
	if engine == "" {
		engine = FilePayloadEngineBulk
	}
	set("file_payload_engine", string(engine))
	if engine == FilePayloadEngineBulk {
		set("bulk_probe_selected_mbps", "1")
		set("bulk_decision_mode", "bulk-packets-v1")
		set("bulk_decision_reason", "both-probes-accepted")
		set("bulk_decision_run_id", "77")
	}
	set("file_payload_bytes_committed", strconv.FormatInt(cfg.filePayloadBytesCommitted, 10))
	set("file_payload_bytes_bulk", strconv.FormatInt(cfg.filePayloadBytesBulk, 10))
	set("file_payload_bytes_quic", strconv.FormatInt(cfg.filePayloadBytesQUIC, 10))
	lanes := cfg.filePayloadLaneAddresses
	if lanes == "" {
		lanes = "[]"
	}
	set("file_payload_lane_addrs", lanes)
	if cfg.fileSourceTelemetry {
		set("file_source_read_calls", strconv.FormatUint(cfg.fileSourceReadCalls, 10))
		set("file_source_read_bytes", strconv.FormatUint(cfg.fileSourceReadBytes, 10))
	}
	var row bytes.Buffer
	w := csv.NewWriter(&row)
	if err := w.Write(fields); err != nil {
		panic(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		panic(err)
	}
	return row.String()
}

func testTraceWithFilePayload(role Role, engine FilePayloadEngine, appBytes, committed, bulk, quic int64, lanes string) string {
	peerReceived := int64(0)
	if role == RoleSend {
		peerReceived = appBytes
	}
	readCalls, readBytes := uint64(0), uint64(0)
	if role == RoleSend {
		readCalls, readBytes = 1, uint64(appBytes)
	}
	return HeaderLine + "\n" + testTraceRow(testTraceRowConfig{
		timestampMS: 1000, role: role, phase: PhaseComplete, appBytes: appBytes, deltaAppBytes: appBytes,
		peerReceivedBytes: peerReceived, transferElapsedMS: 500, directValidated: true, lastState: "stream-complete",
		filePayloadEngine: engine, filePayloadBytesCommitted: committed, filePayloadBytesBulk: bulk,
		filePayloadBytesQUIC: quic, filePayloadLaneAddresses: lanes,
		fileSourceTelemetry: true, fileSourceReadCalls: readCalls, fileSourceReadBytes: readBytes,
	})
}

func testTraceWithFinalBulkDecision(t *testing.T, trace string, decision checkerRowBulkDecision) string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(trace)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	positions := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		positions[name] = i
	}
	final := records[len(records)-1]
	final[positions["bulk_decision_mode"]] = decision.mode
	final[positions["bulk_decision_reason"]] = decision.reason
	if decision.set {
		final[positions["bulk_decision_run_id"]] = strconv.FormatUint(decision.runID, 10)
	} else {
		final[positions["bulk_decision_run_id"]] = ""
	}
	var output bytes.Buffer
	w := csv.NewWriter(&output)
	if err := w.WriteAll(records); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func formatTestOptionalInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func formatTestOptionalInt64(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func formatTestOptionalUint64(value uint64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatUint(value, 10)
}
