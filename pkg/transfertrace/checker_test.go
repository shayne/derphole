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
			fallbackReason:  "direct UDP rate probes received no packets",
			lastState:       "stream-complete",
		})
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, ExpectedBytes: 1024})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
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
	timestampMS       int64
	elapsedMS         int64
	role              Role
	phase             Phase
	relayBytes        int64
	directBytes       int64
	appBytes          int64
	deltaAppBytes     int64
	localSentBytes    int64
	peerReceivedBytes int64
	transferElapsedMS int64
	directValidated   bool
	fallbackReason    string
	lastState         string
	lastError         string
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
	return strings.Join(fields, ",") + "\n"
}

func formatTestOptionalInt64(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}
