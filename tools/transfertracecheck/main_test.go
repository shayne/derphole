// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestRunPrintsUsageForBadArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage: transfertracecheck") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunPrintsSuccess(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,4096,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "4096", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "trace-ok rows=1 final_app_bytes=4096") {
		t.Fatalf("stdout = %q, want trace-ok", stdout.String())
	}
	if strings.Contains(stdout.String(), "max_rate_target_mbps") || strings.Contains(stdout.String(), "receiver_committed_mbps") {
		t.Fatalf("stdout = %q, want minimal output without diagnostics", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunPrintsDiagnosticSummary(t *testing.T) {
	path := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms":                  "1000",
			"elapsed_ms":                         "0",
			"role":                               "send",
			"phase":                              "direct_execute",
			"direct_bytes":                       "1024",
			"app_bytes":                          "1024",
			"delta_app_bytes":                    "1024",
			"app_mbps":                           "0.00",
			"local_sent_bytes":                   "1024",
			"peer_received_bytes":                "1024",
			"transfer_elapsed_ms":                "500",
			"direct_validated":                   "true",
			"last_state":                         "connected-direct",
			"rate_target_mbps":                   "263",
			"receiver_committed_mbps":            "1.00",
			"replay_bytes":                       "1048576",
			"retransmits":                        "7",
			"peer_recv_queue_depth":              "512",
			"peer_recv_queue_depth_max":          "700",
			"striped_send_blocked_ms":            "150",
			"striped_receive_pending_chunks_max": "7",
			"striped_receive_pending_bytes_max":  "7340032",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms":                  "1500",
			"elapsed_ms":                         "500",
			"role":                               "send",
			"phase":                              "complete",
			"direct_bytes":                       "2048",
			"app_bytes":                          "2048",
			"delta_app_bytes":                    "1024",
			"app_mbps":                           "16.38",
			"local_sent_bytes":                   "2048",
			"peer_received_bytes":                "2048",
			"transfer_elapsed_ms":                "1000",
			"direct_validated":                   "true",
			"last_state":                         "stream-complete",
			"rate_target_mbps":                   "300",
			"receiver_committed_mbps":            "16.38",
			"replay_bytes":                       "2097152",
			"retransmits":                        "9",
			"peer_recv_queue_depth":              "900",
			"peer_recv_queue_depth_max":          "1069",
			"striped_send_blocked_ms":            "250",
			"striped_receive_pending_chunks_max": "9",
			"striped_receive_pending_bytes_max":  "9437184",
			"direct_transport":                   "quic",
		}))
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "2048", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"max_rate_target_mbps=300",
		"max_replay_bytes=2097152",
		"max_retransmits=9",
		"max_peer_recv_queue_depth=1069",
		"max_striped_send_blocked_ms=250",
		"max_striped_receive_pending_chunks=9",
		"max_striped_receive_pending_bytes=9437184",
		"direct_transport=quic",
		"receiver_committed_mbps_min=1.00",
		"receiver_committed_mbps_max=16.38",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout = %q, want %q", out, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestFormatDiagnosticsSummaryPrintsCurrentSenderZeroHealth(t *testing.T) {
	got := formatDiagnosticsSummary(transfertrace.DiagnosticsSummary{SenderHealthObserved: true})
	want := " min_rate_target_mbps=0 final_rate_target_mbps=0 controller_decreases=0 final_repair_bytes=0 max_retransmits=0 local_enobufs_retries=0 local_enobufs_wait_us=0 local_enobufs_max_consecutive=0"
	if got != want {
		t.Fatalf("formatDiagnosticsSummary() = %q, want %q", got, want)
	}
}

func TestRunChecksPeerTraceSuccess(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,send,complete,1024,0,1024,1024,0.00,1024,1024,,500,false,,,,,,,,,,,,stream-complete,\n")
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,complete,1024,0,1024,1024,0.00,0,0,,500,false,,,,,,,,,,,,stream-complete,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "1024", "-progress-lead-tolerance", "0", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "peer_delta_bytes=0") {
		t.Fatalf("stdout = %q, want peer pair summary", stdout.String())
	}
}

func TestRunChecksPeerTraceFailure(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,send,complete,2048,0,2048,2048,0.00,2048,2048,,500,false,,,,,,,,,,,,stream-complete,\n")
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,complete,1024,0,1024,1024,0.00,0,0,,500,false,,,,,,,,,,,,stream-complete,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "2048", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "sender peer_received_bytes") {
		t.Fatalf("stderr = %q, want peer progress error", stderr.String())
	}
}

func TestRunPairedSenderUsesReceiverForPayloadFlatline(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "elapsed_ms": "0", "role": "send", "phase": "direct_execute",
			"direct_bytes": "1000", "app_bytes": "1000", "delta_app_bytes": "1000", "local_sent_bytes": "1000",
			"peer_received_bytes": "1000", "transfer_elapsed_ms": "0", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1500", "elapsed_ms": "500", "role": "send", "phase": "direct_execute",
			"direct_bytes": "2000", "app_bytes": "1000", "delta_app_bytes": "0", "local_sent_bytes": "2000",
			"peer_received_bytes": "1000", "transfer_elapsed_ms": "500", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2000", "elapsed_ms": "1000", "role": "send", "phase": "direct_execute",
			"direct_bytes": "3000", "app_bytes": "1000", "delta_app_bytes": "0", "local_sent_bytes": "3000",
			"peer_received_bytes": "1000", "transfer_elapsed_ms": "1000", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2500", "elapsed_ms": "1500", "role": "send", "phase": "direct_execute",
			"direct_bytes": "4000", "app_bytes": "1000", "delta_app_bytes": "0", "local_sent_bytes": "4000",
			"peer_received_bytes": "1000", "transfer_elapsed_ms": "1500", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "3000", "elapsed_ms": "2000", "role": "send", "phase": "complete",
			"direct_bytes": "5000", "app_bytes": "5000", "delta_app_bytes": "4000", "local_sent_bytes": "5000",
			"peer_received_bytes": "5000", "transfer_elapsed_ms": "2000", "direct_validated": "true", "last_state": "stream-complete",
		}))
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "elapsed_ms": "0", "role": "receive", "phase": "direct_execute",
			"direct_bytes": "1000", "app_bytes": "1000", "delta_app_bytes": "1000", "transfer_elapsed_ms": "0",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1500", "elapsed_ms": "500", "role": "receive", "phase": "direct_execute",
			"direct_bytes": "2000", "app_bytes": "2000", "delta_app_bytes": "1000", "transfer_elapsed_ms": "500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2000", "elapsed_ms": "1000", "role": "receive", "phase": "direct_execute",
			"direct_bytes": "3000", "app_bytes": "2000", "delta_app_bytes": "0", "transfer_elapsed_ms": "1000",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2500", "elapsed_ms": "1500", "role": "receive", "phase": "direct_execute",
			"direct_bytes": "4000", "app_bytes": "4000", "delta_app_bytes": "2000", "transfer_elapsed_ms": "1500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "3000", "elapsed_ms": "2000", "role": "receive", "phase": "complete",
			"direct_bytes": "5000", "app_bytes": "5000", "delta_app_bytes": "1000", "transfer_elapsed_ms": "2000",
			"direct_validated": "true", "last_state": "stream-complete",
		}))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-stall-window", "999ms", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"max_flatline=500ms", "sender_ack_max_flatline=1.5s"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunPairedSenderRejectsReceiverPayloadFlatline(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "elapsed_ms": "0", "role": "send", "phase": "direct_execute",
			"app_bytes": "1000", "delta_app_bytes": "1000", "peer_received_bytes": "1000", "transfer_elapsed_ms": "0",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1500", "elapsed_ms": "500", "role": "send", "phase": "direct_execute",
			"app_bytes": "2000", "delta_app_bytes": "1000", "peer_received_bytes": "2000", "transfer_elapsed_ms": "500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2000", "elapsed_ms": "1000", "role": "send", "phase": "direct_execute",
			"app_bytes": "3000", "delta_app_bytes": "1000", "peer_received_bytes": "3000", "transfer_elapsed_ms": "1000",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2500", "elapsed_ms": "1500", "role": "send", "phase": "direct_execute",
			"app_bytes": "4000", "delta_app_bytes": "1000", "peer_received_bytes": "4000", "transfer_elapsed_ms": "1500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "3000", "elapsed_ms": "2000", "role": "send", "phase": "complete",
			"app_bytes": "5000", "delta_app_bytes": "1000", "peer_received_bytes": "5000", "transfer_elapsed_ms": "2000",
			"direct_validated": "true", "last_state": "stream-complete",
		}))
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "elapsed_ms": "0", "role": "receive", "phase": "direct_execute",
			"app_bytes": "1000", "delta_app_bytes": "1000", "transfer_elapsed_ms": "0",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1500", "elapsed_ms": "500", "role": "receive", "phase": "direct_execute",
			"app_bytes": "2000", "delta_app_bytes": "1000", "transfer_elapsed_ms": "500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2000", "elapsed_ms": "1000", "role": "receive", "phase": "direct_execute",
			"app_bytes": "2000", "delta_app_bytes": "0", "transfer_elapsed_ms": "1000",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2500", "elapsed_ms": "1500", "role": "receive", "phase": "direct_execute",
			"app_bytes": "2000", "delta_app_bytes": "0", "transfer_elapsed_ms": "1500",
			"direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "3000", "elapsed_ms": "2000", "role": "receive", "phase": "complete",
			"app_bytes": "5000", "delta_app_bytes": "3000", "transfer_elapsed_ms": "2000",
			"direct_validated": "true", "last_state": "stream-complete",
		}))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-stall-window", "999ms", "-progress-lead-tolerance", "2000", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1; stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "max_flatline=1s") {
		t.Fatalf("stderr = %q, want receiver max_flatline=1s", stderr.String())
	}
}

func TestRunPairedSenderKeepsSenderFailuresFatal(t *testing.T) {
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "role": "receive", "phase": "complete", "app_bytes": "1024",
			"delta_app_bytes": "1024", "transfer_elapsed_ms": "500", "last_state": "stream-complete",
		}))
	tests := []struct {
		name        string
		senderTrace string
		extraArgs   []string
		wantError   string
	}{
		{
			name: "terminal error",
			senderTrace: transfertrace.HeaderLine + "\n" +
				traceCSVRow(t, map[string]string{
					"timestamp_unix_ms": "1000", "role": "send", "phase": "direct_execute", "app_bytes": "1024",
					"delta_app_bytes": "1024", "peer_received_bytes": "1024", "direct_validated": "true",
					"last_state": "connected-direct", "last_error": "sender exploded",
				}),
			wantError: "terminal error: sender exploded",
		},
		{
			name: "expected byte mismatch",
			senderTrace: transfertrace.HeaderLine + "\n" +
				traceCSVRow(t, map[string]string{
					"timestamp_unix_ms": "1000", "role": "send", "phase": "complete", "app_bytes": "1024",
					"delta_app_bytes": "1024", "peer_received_bytes": "1024", "transfer_elapsed_ms": "500",
					"last_state": "stream-complete",
				}),
			extraArgs: []string{"-expected-bytes", "2048"},
			wantError: "final app bytes = 1024, want 2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sendPath := writeTrace(t, tt.senderTrace)
			args := []string{"-role", "send", "-peer-trace", receivePath}
			args = append(args, tt.extraArgs...)
			args = append(args, sendPath)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("run() exit = %d, want 1; stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantError) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tt.wantError)
			}
		})
	}
}

func TestRunStandaloneFailureReportsObservedFlatline(t *testing.T) {
	path := writeTrace(t, transfertrace.HeaderLine+"\n"+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1000", "role": "receive", "phase": "direct_execute", "app_bytes": "1000",
			"delta_app_bytes": "1000", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "1500", "role": "receive", "phase": "direct_execute", "app_bytes": "1000",
			"delta_app_bytes": "0", "direct_validated": "true", "last_state": "connected-direct",
		})+
		traceCSVRow(t, map[string]string{
			"timestamp_unix_ms": "2000", "role": "receive", "phase": "direct_execute", "app_bytes": "1000",
			"delta_app_bytes": "0", "direct_validated": "true", "last_state": "connected-direct",
		}))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-stall-window", "999ms", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "max_flatline=1s") {
		t.Fatalf("stderr = %q, want max_flatline=1s", stderr.String())
	}
}

func TestRunReturnsFailureForCheckError(t *testing.T) {
	path := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,error,0,0,0,0,0.00,0,0,,,false,,,,,,,,,,,,connected-direct,message too long\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "message too long") {
		t.Fatalf("stderr = %q, want check error", stderr.String())
	}
}

func TestRunValidatesExplicitExpectedZeroBytes(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,1024,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "0", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "final app bytes") {
		t.Fatalf("stderr = %q, want byte mismatch", stderr.String())
	}
}

func TestRunRejectsNegativeExpectedBytes(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,0,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "-1", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "expected-bytes must be non-negative") {
		t.Fatalf("stderr = %q, want expected-bytes validation", stderr.String())
	}
}

func TestRunRejectsNegativeProgressLeadTolerance(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,0,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-progress-lead-tolerance", "-1", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "progress-lead-tolerance must be non-negative") {
		t.Fatalf("stderr = %q, want progress-lead-tolerance validation", stderr.String())
	}
}

func TestRunRejectsInvalidRole(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,4096,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "both", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "role must be send or receive") {
		t.Fatalf("stderr = %q, want role validation", stderr.String())
	}
}

func writeTrace(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trace.csv")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatalf("write trace: %v", err)
	}
	return path
}

func traceCSVRow(t *testing.T, values map[string]string) string {
	t.Helper()
	fields := make([]string, len(transfertrace.Header))
	positions := make(map[string]int, len(transfertrace.Header))
	for i, name := range transfertrace.Header {
		positions[name] = i
	}
	for name, value := range values {
		index, ok := positions[name]
		if !ok {
			t.Fatalf("unknown trace header %q", name)
		}
		fields[index] = value
	}
	return strings.Join(fields, ",") + "\n"
}
