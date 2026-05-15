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
		FallbackReason:    "direct UDP rate probes received no packets",
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
	assertColumn(t, row, indexes, "fallback_reason", "direct UDP rate probes received no packets")
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
