// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"strings"
	"testing"
	"time"
)

func TestCheckPassesSmoothCompleteTransfer(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,overlap,2048,1024,2048,1024,16.38,,,,,,,,,,,connected-direct,\n" +
		"2000,1000,receive,complete,2048,4096,4096,2048,32.77,,,,,,,,,,,stream-complete,\n"
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

func TestCheckFailsApplicationFlatline(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n" +
		"2501,1501,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n"
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
		"1000,0,send,error,0,0,0,0,0.00,,,,,,,,,,,connected-direct,message too long\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "message too long") || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("Check() error = %v, want terminal error at row 2", err)
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
		"1000,0,receive,complete,0,0,1024,1024,0.00,,,,,,,,,,,stream-complete,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second, ExpectedBytes: 2048})
	if err == nil || !strings.Contains(err.Error(), "final app bytes") {
		t.Fatalf("Check() error = %v, want byte mismatch", err)
	}
}
