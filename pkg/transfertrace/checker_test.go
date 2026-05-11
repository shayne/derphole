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

func TestCheckFailsApplicationFlatline(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,receive,relay,1024,0,1024,1024,0.00,,,,,,,,,,,connected-relay,\n" +
		"1500,500,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n" +
		"2501,1501,receive,direct_probe,1024,0,1024,0,0.00,,,,,,,,,,,connected-direct,\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleReceive, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "app bytes stalled") {
		t.Fatalf("Check() error = %v, want app bytes stalled", err)
	}
}

func TestCheckFailsTerminalError(t *testing.T) {
	csvText := HeaderLine + "\n" +
		"1000,0,send,error,0,0,0,0,0.00,,,,,,,,,,,connected-direct,message too long\n"
	_, err := Check(strings.NewReader(csvText), Options{Role: RoleSend, StallWindow: time.Second})
	if err == nil || !strings.Contains(err.Error(), "message too long") {
		t.Fatalf("Check() error = %v, want terminal error", err)
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
