// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
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
	return strings.Join(fields, ",") + "\n"
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
