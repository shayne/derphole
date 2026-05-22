// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckPassesSmoothCompleteTransfer(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,overlap,2048,1024,2048,1024,16.38,0,0,,,true,,,,,,,,,,,,connected-direct,\n" +
		"2000,1000,receive,complete,2048,4096,4096,2048,32.77,0,0,,,false,,,,,,,,,,,,stream-complete,\n"
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

func TestCheckFailsApplicationFlatline(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,direct_probe,1024,0,1024,0,0.00,0,0,,,true,,,,,,,,,,,,connected-direct,\n" +
		"2501,1501,receive,direct_probe,1024,0,1024,0,0.00,0,0,,,true,,,,,,,,,,,,connected-direct,\n"
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
		"1000,0,send,error,0,0,0,0,0.00,0,0,,,false,,,,,,,,,,,,connected-direct,message too long\n"
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
			timestampMS:           1000,
			role:                  RoleSend,
			phase:                 PhaseDirectExecute,
			appBytes:              1024,
			deltaAppBytes:         1024,
			localSentBytes:        1024,
			peerReceivedBytes:     1024,
			transferElapsedMS:     500,
			directValidated:       true,
			lastState:             "connected-direct",
			rateTargetMbps:        263,
			receiverCommittedMbps: "1.00",
			replayBytes:           1048576,
			retransmits:           7,
			peerRecvQueueDepth:    512,
			peerRecvQueueDepthMax: 700,
		}) +
		testTraceRow(testTraceRowConfig{
			timestampMS:           1500,
			elapsedMS:             500,
			role:                  RoleSend,
			phase:                 PhaseComplete,
			appBytes:              2048,
			deltaAppBytes:         1024,
			localSentBytes:        2048,
			peerReceivedBytes:     2048,
			transferElapsedMS:     1000,
			directValidated:       true,
			lastState:             "stream-complete",
			rateTargetMbps:        300,
			receiverCommittedMbps: "16.38",
			replayBytes:           2097152,
			retransmits:           9,
			peerRecvQueueDepth:    900,
			peerRecvQueueDepthMax: 1069,
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
		"1000,0,receive,complete,0,0,1024,1024,0.00,0,0,,,false,,,,,,,,,,,,stream-complete,\n"
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
	timestampMS           int64
	elapsedMS             int64
	role                  Role
	phase                 Phase
	relayBytes            int64
	directBytes           int64
	appBytes              int64
	deltaAppBytes         int64
	localSentBytes        int64
	peerReceivedBytes     int64
	transferElapsedMS     int64
	directValidated       bool
	fallbackReason        string
	lastState             string
	lastError             string
	rateTargetMbps        int
	receiverCommittedMbps string
	replayBytes           uint64
	retransmits           int64
	peerRecvQueueDepth    int
	peerRecvQueueDepthMax int
	directTransport       string
	quicHandshakeMS       int64
	quicFirstByteMS       int64
	quicBytesSent         int64
	quicGoodputMbps       string
	quicCloseReason       string
}

func testTraceRow(cfg testTraceRowConfig) string {
	fields := make([]string, len(Header))
	fields[0] = strconv.FormatInt(cfg.timestampMS, 10)
	fields[1] = strconv.FormatInt(cfg.elapsedMS, 10)
	fields[2] = string(cfg.role)
	fields[3] = string(cfg.phase)
	fields[4] = strconv.FormatInt(cfg.relayBytes, 10)
	fields[5] = strconv.FormatInt(cfg.directBytes, 10)
	fields[6] = strconv.FormatInt(cfg.appBytes, 10)
	fields[7] = strconv.FormatInt(cfg.deltaAppBytes, 10)
	fields[8] = "0.00"
	fields[9] = strconv.FormatInt(cfg.localSentBytes, 10)
	fields[10] = strconv.FormatInt(cfg.peerReceivedBytes, 10)
	fields[12] = formatTestOptionalInt64(cfg.transferElapsedMS)
	fields[13] = strconv.FormatBool(cfg.directValidated)
	fields[14] = cfg.fallbackReason
	fields[25] = cfg.lastState
	fields[26] = cfg.lastError
	fields[27] = formatTestOptionalInt(cfg.rateTargetMbps)
	fields[39] = cfg.receiverCommittedMbps
	fields[40] = formatTestOptionalUint64(cfg.replayBytes)
	fields[41] = formatTestOptionalInt64(cfg.retransmits)
	fields[44] = formatTestOptionalInt(cfg.peerRecvQueueDepth)
	fields[45] = formatTestOptionalInt(cfg.peerRecvQueueDepthMax)
	fields[48] = cfg.directTransport
	fields[49] = formatTestOptionalInt64(cfg.quicHandshakeMS)
	fields[50] = formatTestOptionalInt64(cfg.quicFirstByteMS)
	fields[51] = formatTestOptionalInt64(cfg.quicBytesSent)
	fields[53] = cfg.quicGoodputMbps
	fields[56] = cfg.quicCloseReason
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
