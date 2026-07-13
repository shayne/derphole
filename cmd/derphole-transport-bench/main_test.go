// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/transportbench"
)

func TestRunCLIRequiresSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunCLITLSSendRejectsBadFingerprint(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input")
	if err := os.WriteFile(inputPath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{
		"tls-send",
		"--peer", "127.0.0.1:1",
		"--fingerprint", "bad",
		"--transfer-id", strings.Repeat("0", 32),
		"--in", inputPath,
		"--trace", filepath.Join(tempDir, "trace.csv"),
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "fingerprint") {
		t.Fatalf("stderr = %q, want fingerprint", stderr.String())
	}
}

func TestRunCLITLSReceiveConnectRejectsBadFingerprint(t *testing.T) {
	tempDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{
		"tls-receive-connect",
		"--peer", "127.0.0.1:1",
		"--fingerprint", "bad",
		"--transfer-id", strings.Repeat("0", 32),
		"--out", filepath.Join(tempDir, "output"),
		"--trace", filepath.Join(tempDir, "trace.csv"),
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "fingerprint") {
		t.Fatalf("stderr = %q, want fingerprint", stderr.String())
	}
}

func TestRunCLIDecideSelectsPassingCandidate(t *testing.T) {
	tempDir := t.TempDir()
	resultsPath := filepath.Join(tempDir, "results.jsonl")
	outPath := filepath.Join(tempDir, "decision.json")
	results := append(completeCLICandidate(transportbench.EngineBulkUDP), completeCLICandidate(transportbench.EngineTLS8)...)
	for index := range results {
		if results[index].Engine == transportbench.EngineBulkUDP {
			results[index].Sender.CPUSecondsPerGiB = cliFloat64Pointer(1.1)
			results[index].Receiver.CPUSecondsPerGiB = cliFloat64Pointer(1.1)
		} else {
			results[index].Sender.CPUSecondsPerGiB = cliFloat64Pointer(0.9)
			results[index].Receiver.CPUSecondsPerGiB = cliFloat64Pointer(0.9)
		}
	}
	writeJSONLines(t, resultsPath, results)

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"decide", "--results", resultsPath, "--out", outPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var decision transportbench.Decision
	decodeJSONFile(t, outPath, &decision)
	if decision.Selected != transportbench.EngineTLS8 {
		t.Fatalf("selected = %q, want %q", decision.Selected, transportbench.EngineTLS8)
	}
	if strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
		t.Fatalf("stdout contains more than one JSON value: %q", stdout.String())
	}
}

func TestRunCLIDecideRejectsIncompleteEvidence(t *testing.T) {
	tempDir := t.TempDir()
	resultsPath := filepath.Join(tempDir, "results.jsonl")
	writeJSONLines(t, resultsPath, completeCLICandidate(transportbench.EngineTLS8)[:1])

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"decide", "--results", resultsPath, "--out", filepath.Join(tempDir, "decision.json")}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "incomplete") {
		t.Fatalf("stderr = %q, want incomplete", stderr.String())
	}
}

func TestRunCLIIngestBulkProducesEvaluatedResult(t *testing.T) {
	tempDir := t.TempDir()
	summaryPath := filepath.Join(tempDir, "summary.csv")
	outPath := filepath.Join(tempDir, "result.json")
	writeBulkSummaryFixture(t, summaryPath)

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{
		"ingest-bulk",
		"--summary-csv", summaryPath,
		"--direction", string(transportbench.DirectionLocalToRemote),
		"--run", "1",
		"--out", outPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var result transportbench.RunResult
	decodeJSONFile(t, outPath, &result)
	if result.Disposition != transportbench.DispositionPass {
		t.Fatalf("disposition = %q: %s", result.Disposition, result.DispositionReason)
	}
	if result.Engine != transportbench.EngineBulkUDP || result.Direction != transportbench.DirectionLocalToRemote || result.Run != 1 {
		t.Fatalf("identity = %q/%q/%d", result.Engine, result.Direction, result.Run)
	}
}

func TestIngestBulkSummaryRejectsMismatchedRows(t *testing.T) {
	tests := []struct {
		name      string
		direction transportbench.Direction
		mutate    func([][]string)
		want      string
	}{
		{name: "missing transfer", direction: transportbench.DirectionLocalToRemote, mutate: func(rows [][]string) { rows[2][2] = "other" }, want: "requires iperf3 and derphole"},
		{name: "non-file workload", direction: transportbench.DirectionLocalToRemote, mutate: func(rows [][]string) { rows[2][4] = "pipe" }, want: "workload must be file"},
		{name: "non-bulk mode", direction: transportbench.DirectionLocalToRemote, mutate: func(rows [][]string) { rows[2][5] = "quic" }, want: "does not identify bulk"},
		{name: "wrong direction", direction: transportbench.DirectionRemoteToLocal, mutate: func(_ [][]string) {}, want: "want \"reverse\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "summary.csv")
			rows := bulkSummaryFixtureRows()
			tt.mutate(rows)
			writeCSVFixture(t, path, rows)
			_, err := ingestBulkSummary(path, tt.direction, 1)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func completeCLICandidate(engine transportbench.Engine) []transportbench.RunResult {
	runs := make([]transportbench.RunResult, 0, 6)
	for _, direction := range []transportbench.Direction{transportbench.DirectionLocalToRemote, transportbench.DirectionRemoteToLocal} {
		for run := 1; run <= 3; run++ {
			runs = append(runs, completeCLIResult(engine, direction, run))
		}
	}
	return runs
}

func completeCLIResult(engine transportbench.Engine, direction transportbench.Direction, run int) transportbench.RunResult {
	transport := cliTLSEvidence()
	if engine == transportbench.EngineBulkUDP {
		transport = cliBulkEvidence()
	}
	return transportbench.RunResult{
		SchemaVersion:        transportbench.ResultSchemaVersion,
		Revision:             "0123456789abcdef",
		Engine:               engine,
		Direction:            direction,
		Run:                  run,
		SizeBytes:            transportbench.RequiredFileSizeBytes,
		ExpectedSHA256:       strings.Repeat("a", 64),
		ActualSHA256:         strings.Repeat("a", 64),
		CanonicalGoodputMbps: cliFloat64Pointer(2100),
		WallGoodputMbps:      cliFloat64Pointer(2050),
		CapacityMbps:         cliFloat64Pointer(2300),
		MaxFlatlineMS:        cliInt64Pointer(100),
		TraceComplete:        cliBoolPointer(true),
		PublicRouteProven:    cliBoolPointer(true),
		TailscaleCandidates:  cliIntPointer(0),
		Sender: transportbench.EndpointResources{
			UserCPUSeconds:   cliFloat64Pointer(1),
			SystemCPUSeconds: cliFloat64Pointer(0.1),
			CPUSecondsPerGiB: cliFloat64Pointer(0.4),
			PeakRSSBytes:     cliInt64Pointer(64 << 20),
		},
		Receiver: transportbench.EndpointResources{
			UserCPUSeconds:   cliFloat64Pointer(1),
			SystemCPUSeconds: cliFloat64Pointer(0.1),
			CPUSecondsPerGiB: cliFloat64Pointer(0.4),
			PeakRSSBytes:     cliInt64Pointer(64 << 20),
		},
		Transport: transport,
	}
}

func cliTLSEvidence() map[string]any {
	base := transportbench.RequiredFileSizeBytes / transportbench.TLSLaneCount
	laneBytes := make([]int64, transportbench.TLSLaneCount)
	for index := range laneBytes {
		laneBytes[index] = base
	}
	return map[string]any{
		"tls_version": "TLS1.3", "tls_cipher": "TLS_AES_128_GCM_SHA256", "alpn": transportbench.TLSProtocol,
		"connections": 8, "pin_verified": true, "lane_bytes": laneBytes,
		"read_calls": 8, "write_calls": 8, "bytes_per_read_call": 1, "bytes_per_write_call": 1,
		"tcp_info_supported": false, "tcp_retransmits": 0, "tcp_cwnd_segments": 0,
	}
}

func cliBulkEvidence() map[string]any {
	return map[string]any{
		"batch_backend": "linux-sendmmsg", "gso_attempted": true, "gso_active": false,
		"gso_segments": 0, "send_calls": 1, "send_datagrams": 1, "receive_calls": 1, "receive_datagrams": 1,
		"max_send_batch": 1, "max_receive_batch": 1, "crypto_queue_peak": 0, "writer_queue_peak": 0,
		"local_enobufs_retries": 0, "repair_bytes": 0, "repair_ratio": 0, "retransmits": 0,
		"primary_packet_count": 1, "received_packet_count": 1,
	}
}

func writeBulkSummaryFixture(t *testing.T, path string) {
	t.Helper()
	writeCSVFixture(t, path, bulkSummaryFixtureRows())
}

func bulkSummaryFixtureRows() [][]string {
	header := []string{
		"host", "run", "tool", "direction", "workload", "transfer_mode", "mbps", "wall_mbps", "trace_ok", "max_flatline",
		"benchmark_size_bytes", "revision_label", "sender_user_cpu_seconds", "sender_system_cpu_seconds", "sender_cpu_seconds_per_gib", "sender_max_rss_bytes",
		"receiver_user_cpu_seconds", "receiver_system_cpu_seconds", "receiver_cpu_seconds_per_gib", "receiver_max_rss_bytes", "expected_sha256", "actual_sha256",
		"public_route_proven", "tailscale_candidates", "batch_backend", "gso_attempted", "gso_active", "gso_segments", "send_calls", "send_datagrams",
		"receive_calls", "receive_datagrams", "max_send_batch", "max_receive_batch", "crypto_queue_peak", "writer_queue_peak", "local_enobufs_retries",
		"repair_bytes", "repair_ratio", "retransmits", "primary_packet_count", "received_packet_count",
	}
	return [][]string{
		header,
		{"remote", "1", "iperf3", "forward", "stream", "tcp", "2300"},
		{
			"remote", "1", "derphole", "forward", "file", "bulk-packets", "2100", "2050", "true", "100ms",
			"3221225472", "0123456789abcdef", "1", "0.1", "0.366", "67108864", "1", "0.1", "0.366", "67108864",
			strings.Repeat("a", 64), strings.Repeat("a", 64), "true", "0", "linux-sendmmsg", "true", "false", "0", "1", "1", "1", "1", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1",
		},
	}
}

func writeCSVFixture(t *testing.T, path string, rows [][]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w := csv.NewWriter(file)
	header := rows[0]
	for _, row := range rows {
		padded := make([]string, len(header))
		copy(padded, row)
		if err := w.Write(padded); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
}

func writeJSONLines(t *testing.T, path string, results []transportbench.RunResult) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			t.Fatal(err)
		}
	}
}

func decodeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(value); err != nil {
		t.Fatal(err)
	}
}

func cliFloat64Pointer(value float64) *float64 { return &value }
func cliInt64Pointer(value int64) *int64       { return &value }
func cliIntPointer(value int) *int             { return &value }
func cliBoolPointer(value bool) *bool          { return &value }
