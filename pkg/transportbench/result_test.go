// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestEvaluateRunRejectsMissingEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RunResult)
		want   string
	}{
		{name: "revision", mutate: func(r *RunResult) { r.Revision = "" }, want: "revision"},
		{name: "canonical goodput", mutate: func(r *RunResult) { r.CanonicalGoodputMbps = nil }, want: "canonical_goodput_mbps"},
		{name: "wall goodput", mutate: func(r *RunResult) { r.WallGoodputMbps = nil }, want: "wall_goodput_mbps"},
		{name: "capacity", mutate: func(r *RunResult) { r.CapacityMbps = nil }, want: "capacity_mbps"},
		{name: "flatline", mutate: func(r *RunResult) { r.MaxFlatlineMS = nil }, want: "max_flatline_ms"},
		{name: "trace", mutate: func(r *RunResult) { r.TraceComplete = nil }, want: "trace_complete"},
		{name: "route", mutate: func(r *RunResult) { r.PublicRouteProven = nil }, want: "public_route_proven"},
		{name: "tailscale count", mutate: func(r *RunResult) { r.TailscaleCandidates = nil }, want: "tailscale_candidates"},
		{name: "sender user cpu", mutate: func(r *RunResult) { r.Sender.UserCPUSeconds = nil }, want: "sender.user_cpu_seconds"},
		{name: "receiver rss", mutate: func(r *RunResult) { r.Receiver.PeakRSSBytes = nil }, want: "receiver.peak_rss_bytes"},
		{name: "transport", mutate: func(r *RunResult) { r.Transport = nil }, want: "transport"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := completeRun(EngineTLS8, DirectionLocalToRemote, 1)
			tt.mutate(&result)

			got := EvaluateRun(result)

			if got.Disposition != DispositionFail {
				t.Fatalf("disposition = %q, want %q (%s)", got.Disposition, DispositionFail, got.DispositionReason)
			}
			if !strings.Contains(got.DispositionReason, tt.want) {
				t.Fatalf("reason = %q, want substring %q", got.DispositionReason, tt.want)
			}
		})
	}
}

func TestEvaluateRunInvalidatesLowCapacity(t *testing.T) {
	result := completeRun(EngineTLS8, DirectionLocalToRemote, 1)
	result.CapacityMbps = float64Pointer(2049.99)

	got := EvaluateRun(result)

	if got.Disposition != DispositionInvalid {
		t.Fatalf("disposition = %q, want %q", got.Disposition, DispositionInvalid)
	}
	if !strings.Contains(got.DispositionReason, "capacity") {
		t.Fatalf("reason = %q, want capacity", got.DispositionReason)
	}
}

func TestEvaluateRunRequiresStrictlyGreaterThanTwoGbps(t *testing.T) {
	result := completeRun(EngineTLS8, DirectionLocalToRemote, 1)
	result.CanonicalGoodputMbps = float64Pointer(2000)

	got := EvaluateRun(result)

	if got.Disposition != DispositionFail {
		t.Fatalf("disposition = %q, want %q", got.Disposition, DispositionFail)
	}
	if !strings.Contains(got.DispositionReason, "greater than 2000") {
		t.Fatalf("reason = %q, want strict threshold", got.DispositionReason)
	}
}

func TestEvaluateRunAcceptsHealthyZeroes(t *testing.T) {
	result := completeRun(EngineTLS8, DirectionLocalToRemote, 1)
	result.Sender.SystemCPUSeconds = float64Pointer(0)
	result.Receiver.SystemCPUSeconds = float64Pointer(0)
	result.TailscaleCandidates = intPointer(0)
	result.MaxFlatlineMS = int64Pointer(0)

	got := EvaluateRun(result)

	if got.Disposition != DispositionPass {
		t.Fatalf("disposition = %q, want %q: %s", got.Disposition, DispositionPass, got.DispositionReason)
	}
}

func TestEvaluateRunRequiresEngineSpecificEvidence(t *testing.T) {
	tests := []struct {
		name   string
		engine Engine
		key    string
	}{
		{name: "tls pin", engine: EngineTLS8, key: "pin_verified"},
		{name: "tls lane bytes", engine: EngineTLS8, key: "lane_bytes"},
		{name: "bulk backend", engine: EngineBulkUDP, key: "batch_backend"},
		{name: "bulk repair ratio", engine: EngineBulkUDP, key: "repair_ratio"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := completeRun(tt.engine, DirectionLocalToRemote, 1)
			delete(result.Transport, tt.key)

			got := EvaluateRun(result)

			if got.Disposition != DispositionFail {
				t.Fatalf("disposition = %q, want %q", got.Disposition, DispositionFail)
			}
			if !strings.Contains(got.DispositionReason, "transport."+tt.key) {
				t.Fatalf("reason = %q, want missing key %q", got.DispositionReason, tt.key)
			}
		})
	}
}

func TestEvaluateRunRejectsMalformedIdentityAndCompletionEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RunResult)
		want   string
	}{
		{name: "schema", mutate: func(r *RunResult) { r.SchemaVersion = 0 }, want: "schema_version"},
		{name: "engine", mutate: func(r *RunResult) { r.Engine = "other" }, want: "engine is invalid"},
		{name: "direction", mutate: func(r *RunResult) { r.Direction = "sideways" }, want: "direction is invalid"},
		{name: "run", mutate: func(r *RunResult) { r.Run = 4 }, want: "run must be"},
		{name: "size", mutate: func(r *RunResult) { r.SizeBytes-- }, want: "size_bytes"},
		{name: "expected hash", mutate: func(r *RunResult) { r.ExpectedSHA256 = "BAD" }, want: "expected_sha256"},
		{name: "actual hash", mutate: func(r *RunResult) { r.ActualSHA256 = "BAD" }, want: "actual_sha256"},
		{name: "hash mismatch", mutate: func(r *RunResult) { r.ActualSHA256 = strings.Repeat("b", 64) }, want: "does not match"},
		{name: "flatline negative", mutate: func(r *RunResult) { r.MaxFlatlineMS = int64Pointer(-1) }, want: "max_flatline_ms"},
		{name: "trace false", mutate: func(r *RunResult) { r.TraceComplete = boolPointer(false) }, want: "trace_complete must be true"},
		{name: "route false", mutate: func(r *RunResult) { r.PublicRouteProven = boolPointer(false) }, want: "public_route_proven must be true"},
		{name: "tailscale", mutate: func(r *RunResult) { r.TailscaleCandidates = intPointer(1) }, want: "tailscale_candidates must be zero"},
		{name: "failure", mutate: func(r *RunResult) { r.Failure = "boom" }, want: "transfer failure: boom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := completeRun(EngineTLS8, DirectionLocalToRemote, 1)
			tt.mutate(&result)
			got := EvaluateRun(result)
			if got.Disposition != DispositionFail || !strings.Contains(got.DispositionReason, tt.want) {
				t.Fatalf("result = %#v, want failure containing %q", got, tt.want)
			}
		})
	}
}

func TestNumberValueSupportsJSONNumericRepresentations(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  float64
		ok    bool
	}{
		{name: "float64", value: float64(1), want: 1, ok: true},
		{name: "float32", value: float32(2), want: 2, ok: true},
		{name: "int", value: int(3), want: 3, ok: true},
		{name: "int8", value: int8(4), want: 4, ok: true},
		{name: "int16", value: int16(5), want: 5, ok: true},
		{name: "int32", value: int32(6), want: 6, ok: true},
		{name: "int64", value: int64(7), want: 7, ok: true},
		{name: "uint", value: uint(8), want: 8, ok: true},
		{name: "uint8", value: uint8(9), want: 9, ok: true},
		{name: "uint16", value: uint16(10), want: 10, ok: true},
		{name: "uint32", value: uint32(11), want: 11, ok: true},
		{name: "uint64", value: uint64(12), want: 12, ok: true},
		{name: "json number", value: json.Number("13.5"), want: 13.5, ok: true},
		{name: "bad json number", value: json.Number("nope"), ok: false},
		{name: "unsupported", value: "14", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := numberValue(tt.value)
			if ok != tt.ok || (ok && math.Abs(got-tt.want) > 1e-9) {
				t.Fatalf("numberValue(%T(%v)) = %v, %t; want %v, %t", tt.value, tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEvaluateCandidateRequiresSixPassingRuns(t *testing.T) {
	runs := completeCandidateRuns(EngineTLS8)
	verdict := EvaluateCandidate(EngineTLS8, runs[:5])
	if verdict.Pass {
		t.Fatal("five-run verdict passed")
	}
	if !containsReason(verdict.Reasons, "exactly six") {
		t.Fatalf("reasons = %q, want exactly six", verdict.Reasons)
	}

	runs[5].CanonicalGoodputMbps = float64Pointer(1999)
	verdict = EvaluateCandidate(EngineTLS8, runs)
	if verdict.Pass {
		t.Fatal("failed-run verdict passed")
	}
	if !containsReason(verdict.Reasons, "remote-to-local run 3") {
		t.Fatalf("reasons = %q, want failed run identity", verdict.Reasons)
	}

	verdict = EvaluateCandidate(EngineTLS8, completeCandidateRuns(EngineTLS8))
	if !verdict.Pass {
		t.Fatalf("complete verdict failed: %q", verdict.Reasons)
	}
}

func TestEvaluateCandidateRejectsDuplicateRunIdentity(t *testing.T) {
	runs := completeCandidateRuns(EngineTLS8)
	runs[5] = runs[4]

	verdict := EvaluateCandidate(EngineTLS8, runs)

	if verdict.Pass {
		t.Fatal("duplicate-run verdict passed")
	}
	if !containsReason(verdict.Reasons, "duplicate") {
		t.Fatalf("reasons = %q, want duplicate", verdict.Reasons)
	}
}

func TestSelectWinnerUsesCPUThenWallGoodputThenRSS(t *testing.T) {
	bulk := EvaluateCandidate(EngineBulkUDP, completeCandidateRuns(EngineBulkUDP))
	tls := EvaluateCandidate(EngineTLS8, completeCandidateRuns(EngineTLS8))

	bulk.MaxEndpointCPUPerGiB = 1.2
	tls.MaxEndpointCPUPerGiB = 1.1
	decision := SelectWinner(bulk, tls)
	if decision.Selected != EngineTLS8 {
		t.Fatalf("CPU winner = %q, want %q", decision.Selected, EngineTLS8)
	}

	bulk.MaxEndpointCPUPerGiB = 1.1
	bulk.MedianWallGoodput = 2100
	tls.MedianWallGoodput = 2099
	decision = SelectWinner(bulk, tls)
	if decision.Selected != EngineBulkUDP {
		t.Fatalf("wall-goodput winner = %q, want %q", decision.Selected, EngineBulkUDP)
	}

	bulk.MedianWallGoodput = 2099
	bulk.MaxPeakRSSBytes = 101
	tls.MaxPeakRSSBytes = 100
	decision = SelectWinner(bulk, tls)
	if decision.Selected != EngineTLS8 {
		t.Fatalf("RSS winner = %q, want %q", decision.Selected, EngineTLS8)
	}

	bulk.MaxPeakRSSBytes = 100
	decision = SelectWinner(tls, bulk)
	if decision.Selected != EngineBulkUDP {
		t.Fatalf("exact-tie winner = %q, want %q", decision.Selected, EngineBulkUDP)
	}
}

func TestSelectWinnerHandlesOneOrNoPassingCandidate(t *testing.T) {
	bulk := EvaluateCandidate(EngineBulkUDP, completeCandidateRuns(EngineBulkUDP))
	tls := EvaluateCandidate(EngineTLS8, completeCandidateRuns(EngineTLS8))
	tls.Pass = false
	tls.Reasons = []string{"throughput"}

	decision := SelectWinner(bulk, tls)
	if decision.Selected != EngineBulkUDP {
		t.Fatalf("single winner = %q, want %q", decision.Selected, EngineBulkUDP)
	}

	bulk.Pass = false
	bulk.Reasons = []string{"throughput"}
	decision = SelectWinner(bulk, tls)
	if decision.Selected != "" {
		t.Fatalf("no-pass winner = %q, want empty", decision.Selected)
	}
	if !strings.Contains(decision.Reason, "neither") {
		t.Fatalf("reason = %q, want neither", decision.Reason)
	}
}

func completeCandidateRuns(engine Engine) []RunResult {
	runs := make([]RunResult, 0, 6)
	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		for run := 1; run <= 3; run++ {
			runs = append(runs, completeRun(engine, direction, run))
		}
	}
	return runs
}

func completeRun(engine Engine, direction Direction, run int) RunResult {
	transport := completeTLSTransportEvidence()
	if engine == EngineBulkUDP {
		transport = completeBulkTransportEvidence()
	}
	return RunResult{
		SchemaVersion:        ResultSchemaVersion,
		Revision:             "0123456789abcdef",
		Engine:               engine,
		Direction:            direction,
		Run:                  run,
		SizeBytes:            RequiredFileSizeBytes,
		ExpectedSHA256:       strings.Repeat("a", 64),
		ActualSHA256:         strings.Repeat("a", 64),
		CanonicalGoodputMbps: float64Pointer(2100),
		WallGoodputMbps:      float64Pointer(2050),
		CapacityMbps:         float64Pointer(2300),
		MaxFlatlineMS:        int64Pointer(100),
		TraceComplete:        boolPointer(true),
		PublicRouteProven:    boolPointer(true),
		TailscaleCandidates:  intPointer(0),
		Sender: EndpointResources{
			UserCPUSeconds:   float64Pointer(1.2),
			SystemCPUSeconds: float64Pointer(0.3),
			CPUSecondsPerGiB: float64Pointer(0.5),
			PeakRSSBytes:     int64Pointer(64 << 20),
		},
		Receiver: EndpointResources{
			UserCPUSeconds:   float64Pointer(1.5),
			SystemCPUSeconds: float64Pointer(0.5),
			CPUSecondsPerGiB: float64Pointer(2.0 / 3.0),
			PeakRSSBytes:     int64Pointer(80 << 20),
		},
		Transport: transport,
	}
}

func completeTLSTransportEvidence() map[string]any {
	base := RequiredFileSizeBytes / 8
	rem := RequiredFileSizeBytes % 8
	laneBytes := make([]int64, 8)
	for lane := range laneBytes {
		laneBytes[lane] = base
		if int64(lane) < rem {
			laneBytes[lane]++
		}
	}
	return map[string]any{
		"tls_version":          "TLS1.3",
		"tls_cipher":           "TLS_AES_128_GCM_SHA256",
		"alpn":                 TLSProtocol,
		"connections":          8,
		"pin_verified":         true,
		"lane_bytes":           laneBytes,
		"read_calls":           uint64(8),
		"write_calls":          uint64(8),
		"bytes_per_read_call":  1.0,
		"bytes_per_write_call": 1.0,
		"tcp_info_supported":   false,
		"tcp_retransmits":      uint64(0),
		"tcp_cwnd_segments":    uint32(0),
	}
}

func completeBulkTransportEvidence() map[string]any {
	return map[string]any{
		"batch_backend":         "linux-sendmmsg",
		"gso_attempted":         true,
		"gso_active":            false,
		"gso_segments":          uint64(0),
		"send_calls":            uint64(1),
		"send_datagrams":        uint64(1),
		"receive_calls":         uint64(1),
		"receive_datagrams":     uint64(1),
		"max_send_batch":        uint32(1),
		"max_receive_batch":     uint32(1),
		"crypto_queue_peak":     uint32(0),
		"writer_queue_peak":     uint32(0),
		"local_enobufs_retries": int64(0),
		"repair_bytes":          int64(0),
		"repair_ratio":          0.0,
		"retransmits":           int64(0),
		"primary_packet_count":  uint64(1),
		"received_packet_count": uint64(1),
	}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, want) {
			return true
		}
	}
	return false
}

func float64Pointer(value float64) *float64 { return &value }
func int64Pointer(value int64) *int64       { return &value }
func intPointer(value int) *int             { return &value }
func boolPointer(value bool) *bool          { return &value }
