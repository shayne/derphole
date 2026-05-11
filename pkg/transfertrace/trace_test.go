// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transfertrace

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRecorderWritesHeaderAndEscapedRows(t *testing.T) {
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
		LastError:              "quoted \" value, comma",
	})
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if got, want := lines[0], HeaderLine; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	if !strings.Contains(lines[1], `"quoted "" value, comma"`) {
		t.Fatalf("row did not CSV-escape quoted error: %q", lines[1])
	}
	if !strings.Contains(lines[1], ",send,direct_probe,") {
		t.Fatalf("row missing role/phase: %q", lines[1])
	}
	if !strings.Contains(lines[1], ",500,") {
		t.Fatalf("row missing elapsed ms: %q", lines[1])
	}
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
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.Contains(rows[2], ",1048576,8.39,") {
		t.Fatalf("second row missing delta/rate: %q", rows[2])
	}
}

func TestRecorderErrorAndCompleteRows(t *testing.T) {
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
	body := out.String()
	if !strings.Contains(body, ",error,") || !strings.Contains(body, "message too long") {
		t.Fatalf("missing terminal error row:\n%s", body)
	}
	if !strings.Contains(body, ",complete,") {
		t.Fatalf("missing complete row:\n%s", body)
	}
}
