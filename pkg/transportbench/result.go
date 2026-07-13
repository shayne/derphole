// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	ResultSchemaVersion   = 1
	RequiredFileSizeBytes = int64(3 * 1024 * 1024 * 1024)
	RequiredCapacityMbps  = 2050.0
	RequiredGoodputMbps   = 2000.0
	MaximumFlatlineMS     = int64(1000)
	TLSProtocol           = "derphole-transport-bench-v1"
)

type Engine string

const (
	EngineBulkUDP Engine = "bulk-udp-batched-v1"
	EngineTLS8    Engine = "tls-stream-8-v1"
)

type Direction string

const (
	DirectionLocalToRemote Direction = "local-to-remote"
	DirectionRemoteToLocal Direction = "remote-to-local"
)

type RunDisposition string

const (
	DispositionPass    RunDisposition = "pass"
	DispositionFail    RunDisposition = "fail"
	DispositionInvalid RunDisposition = "invalid"
)

type EndpointResources struct {
	UserCPUSeconds   *float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds *float64 `json:"system_cpu_seconds"`
	CPUSecondsPerGiB *float64 `json:"cpu_seconds_per_gib"`
	PeakRSSBytes     *int64   `json:"peak_rss_bytes"`
}

type RunResult struct {
	SchemaVersion        int               `json:"schema_version"`
	Revision             string            `json:"revision"`
	Engine               Engine            `json:"engine"`
	Direction            Direction         `json:"direction"`
	Run                  int               `json:"run"`
	SizeBytes            int64             `json:"size_bytes"`
	ExpectedSHA256       string            `json:"expected_sha256"`
	ActualSHA256         string            `json:"actual_sha256"`
	CanonicalGoodputMbps *float64          `json:"canonical_goodput_mbps"`
	WallGoodputMbps      *float64          `json:"wall_goodput_mbps"`
	CapacityMbps         *float64          `json:"capacity_mbps"`
	MaxFlatlineMS        *int64            `json:"max_flatline_ms"`
	TraceComplete        *bool             `json:"trace_complete"`
	PublicRouteProven    *bool             `json:"public_route_proven"`
	TailscaleCandidates  *int              `json:"tailscale_candidates"`
	Sender               EndpointResources `json:"sender"`
	Receiver             EndpointResources `json:"receiver"`
	Transport            map[string]any    `json:"transport"`
	Failure              string            `json:"failure,omitempty"`
	Disposition          RunDisposition    `json:"disposition"`
	DispositionReason    string            `json:"disposition_reason"`
}

type CandidateVerdict struct {
	Engine                 Engine      `json:"engine"`
	Pass                   bool        `json:"pass"`
	Runs                   []RunResult `json:"runs"`
	MaxEndpointCPUPerGiB   float64     `json:"max_endpoint_cpu_seconds_per_gib"`
	MedianCanonicalGoodput float64     `json:"median_canonical_goodput_mbps"`
	MedianWallGoodput      float64     `json:"median_wall_goodput_mbps"`
	MaxPeakRSSBytes        int64       `json:"max_peak_rss_bytes"`
	Reasons                []string    `json:"reasons,omitempty"`
}

type Decision struct {
	SchemaVersion int                `json:"schema_version"`
	Selected      Engine             `json:"selected,omitempty"`
	Reason        string             `json:"reason"`
	Candidates    []CandidateVerdict `json:"candidates"`
}

func EvaluateRun(result RunResult) RunResult {
	result.Disposition = ""
	result.DispositionReason = ""

	if lowCapacity(result.CapacityMbps) {
		result.Disposition = DispositionInvalid
		result.DispositionReason = fmt.Sprintf("capacity %.2f Mbps is below required %.2f Mbps", *result.CapacityMbps, RequiredCapacityMbps)
		return result
	}

	var reasons []string
	reasons = append(reasons, validateRunIdentity(result)...)
	reasons = append(reasons, validateRunPayload(result)...)
	reasons = append(reasons, validateRunMeasurements(result)...)
	reasons = append(reasons, validateRunAssertions(result)...)
	reasons = append(reasons, validateEndpointResources("sender", result.Sender)...)
	reasons = append(reasons, validateEndpointResources("receiver", result.Receiver)...)
	reasons = append(reasons, validateTransportEvidence(result.Engine, result.SizeBytes, result.Transport)...)
	if failure := strings.TrimSpace(result.Failure); failure != "" {
		reasons = append(reasons, "transfer failure: "+failure)
	}

	if len(reasons) > 0 {
		result.Disposition = DispositionFail
		result.DispositionReason = strings.Join(reasons, "; ")
		return result
	}
	result.Disposition = DispositionPass
	result.DispositionReason = "all required evidence and thresholds passed"
	return result
}

func lowCapacity(capacity *float64) bool {
	return capacity != nil && finiteNonNegative(*capacity) && *capacity < RequiredCapacityMbps
}

func validateRunIdentity(result RunResult) []string {
	var reasons []string
	if result.SchemaVersion != ResultSchemaVersion {
		reasons = append(reasons, fmt.Sprintf("schema_version must be %d", ResultSchemaVersion))
	}
	if strings.TrimSpace(result.Revision) == "" {
		reasons = append(reasons, "revision is required")
	}
	if result.Engine != EngineBulkUDP && result.Engine != EngineTLS8 {
		reasons = append(reasons, "engine is invalid")
	}
	if result.Direction != DirectionLocalToRemote && result.Direction != DirectionRemoteToLocal {
		reasons = append(reasons, "direction is invalid")
	}
	if result.Run < 1 || result.Run > 3 {
		reasons = append(reasons, "run must be between 1 and 3")
	}
	return reasons
}

func validateRunPayload(result RunResult) []string {
	var reasons []string
	if result.SizeBytes != RequiredFileSizeBytes {
		reasons = append(reasons, fmt.Sprintf("size_bytes must be %d", RequiredFileSizeBytes))
	}
	if !validSHA256(result.ExpectedSHA256) {
		reasons = append(reasons, "expected_sha256 must be 64 lowercase hexadecimal characters")
	}
	if !validSHA256(result.ActualSHA256) {
		reasons = append(reasons, "actual_sha256 must be 64 lowercase hexadecimal characters")
	}
	if result.ExpectedSHA256 != result.ActualSHA256 {
		reasons = append(reasons, "actual_sha256 does not match expected_sha256")
	}
	return reasons
}

func validateRunMeasurements(result RunResult) []string {
	var reasons []string
	reasons = append(reasons, validateFloatPointer("canonical_goodput_mbps", result.CanonicalGoodputMbps)...)
	if result.CanonicalGoodputMbps != nil && finiteNonNegative(*result.CanonicalGoodputMbps) && *result.CanonicalGoodputMbps <= RequiredGoodputMbps {
		reasons = append(reasons, fmt.Sprintf("canonical_goodput_mbps must be greater than %.0f", RequiredGoodputMbps))
	}
	reasons = append(reasons, validateFloatPointer("wall_goodput_mbps", result.WallGoodputMbps)...)
	reasons = append(reasons, validateFloatPointer("capacity_mbps", result.CapacityMbps)...)
	if result.MaxFlatlineMS == nil {
		reasons = append(reasons, "max_flatline_ms is required")
	} else if *result.MaxFlatlineMS < 0 || *result.MaxFlatlineMS >= MaximumFlatlineMS {
		reasons = append(reasons, fmt.Sprintf("max_flatline_ms must be between 0 and %d", MaximumFlatlineMS-1))
	}
	return reasons
}

func validateRunAssertions(result RunResult) []string {
	var reasons []string
	if result.TraceComplete == nil {
		reasons = append(reasons, "trace_complete is required")
	} else if !*result.TraceComplete {
		reasons = append(reasons, "trace_complete must be true")
	}
	if result.PublicRouteProven == nil {
		reasons = append(reasons, "public_route_proven is required")
	} else if !*result.PublicRouteProven {
		reasons = append(reasons, "public_route_proven must be true")
	}
	if result.TailscaleCandidates == nil {
		reasons = append(reasons, "tailscale_candidates is required")
	} else if *result.TailscaleCandidates != 0 {
		reasons = append(reasons, "tailscale_candidates must be zero")
	}
	return reasons
}

func EvaluateCandidate(engine Engine, runs []RunResult) CandidateVerdict {
	verdict := CandidateVerdict{
		Engine: engine,
		Runs:   make([]RunResult, len(runs)),
	}
	if len(runs) != 6 {
		verdict.Reasons = append(verdict.Reasons, fmt.Sprintf("candidate requires exactly six runs, got %d", len(runs)))
	}

	seen := make(map[string]struct{}, len(runs))
	canonical := make([]float64, 0, len(runs))
	wall := make([]float64, 0, len(runs))
	for index, raw := range runs {
		run := EvaluateRun(raw)
		verdict.Runs[index] = run
		identity := fmt.Sprintf("%s run %d", run.Direction, run.Run)
		if run.Engine != engine {
			verdict.Reasons = append(verdict.Reasons, fmt.Sprintf("%s uses engine %q, want %q", identity, run.Engine, engine))
		}
		if _, ok := seen[identity]; ok {
			verdict.Reasons = append(verdict.Reasons, "duplicate "+identity)
		}
		seen[identity] = struct{}{}
		if run.Disposition != DispositionPass {
			verdict.Reasons = append(verdict.Reasons, fmt.Sprintf("%s: %s", identity, run.DispositionReason))
			continue
		}
		canonical = append(canonical, *run.CanonicalGoodputMbps)
		wall = append(wall, *run.WallGoodputMbps)
		verdict.MaxEndpointCPUPerGiB = max(verdict.MaxEndpointCPUPerGiB, *run.Sender.CPUSecondsPerGiB, *run.Receiver.CPUSecondsPerGiB)
		verdict.MaxPeakRSSBytes = max(verdict.MaxPeakRSSBytes, *run.Sender.PeakRSSBytes, *run.Receiver.PeakRSSBytes)
	}

	for _, direction := range []Direction{DirectionLocalToRemote, DirectionRemoteToLocal} {
		for run := 1; run <= 3; run++ {
			identity := fmt.Sprintf("%s run %d", direction, run)
			if _, ok := seen[identity]; !ok {
				verdict.Reasons = append(verdict.Reasons, "missing "+identity)
			}
		}
	}
	verdict.Reasons = compactSorted(verdict.Reasons)
	if len(canonical) > 0 {
		verdict.MedianCanonicalGoodput = median(canonical)
		verdict.MedianWallGoodput = median(wall)
	}
	verdict.Pass = len(verdict.Reasons) == 0
	return verdict
}

func SelectWinner(candidates ...CandidateVerdict) Decision {
	decision := Decision{
		SchemaVersion: ResultSchemaVersion,
		Candidates:    slices.Clone(candidates),
	}
	sort.Slice(decision.Candidates, func(i, j int) bool {
		return decision.Candidates[i].Engine < decision.Candidates[j].Engine
	})
	passing := make([]CandidateVerdict, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Pass {
			passing = append(passing, candidate)
		}
	}
	switch len(passing) {
	case 0:
		decision.Reason = "neither feasibility candidate passed all six required runs"
		return decision
	case 1:
		decision.Selected = passing[0].Engine
		decision.Reason = fmt.Sprintf("%s is the only candidate that passed all six required runs", passing[0].Engine)
		return decision
	}

	sort.SliceStable(passing, func(i, j int) bool {
		left, right := passing[i], passing[j]
		if left.MaxEndpointCPUPerGiB != right.MaxEndpointCPUPerGiB {
			return left.MaxEndpointCPUPerGiB < right.MaxEndpointCPUPerGiB
		}
		if left.MedianWallGoodput != right.MedianWallGoodput {
			return left.MedianWallGoodput > right.MedianWallGoodput
		}
		if left.MaxPeakRSSBytes != right.MaxPeakRSSBytes {
			return left.MaxPeakRSSBytes < right.MaxPeakRSSBytes
		}
		if left.Engine == EngineBulkUDP {
			return true
		}
		if right.Engine == EngineBulkUDP {
			return false
		}
		return left.Engine < right.Engine
	})
	decision.Selected = passing[0].Engine
	decision.Reason = fmt.Sprintf("%s won the CPU, wall-goodput, RSS, then existing-transport preference order", passing[0].Engine)
	return decision
}

func validateEndpointResources(prefix string, resources EndpointResources) []string {
	var reasons []string
	reasons = append(reasons, validateFloatPointer(prefix+".user_cpu_seconds", resources.UserCPUSeconds)...)
	reasons = append(reasons, validateFloatPointer(prefix+".system_cpu_seconds", resources.SystemCPUSeconds)...)
	reasons = append(reasons, validateFloatPointer(prefix+".cpu_seconds_per_gib", resources.CPUSecondsPerGiB)...)
	if resources.PeakRSSBytes == nil {
		reasons = append(reasons, prefix+".peak_rss_bytes is required")
	} else if *resources.PeakRSSBytes < 0 {
		reasons = append(reasons, prefix+".peak_rss_bytes must be non-negative")
	}
	return reasons
}

func validateFloatPointer(name string, value *float64) []string {
	if value == nil {
		return []string{name + " is required"}
	}
	if !finiteNonNegative(*value) {
		return []string{name + " must be finite and non-negative"}
	}
	return nil
}

func validateTransportEvidence(engine Engine, size int64, evidence map[string]any) []string {
	if evidence == nil {
		return []string{"transport evidence is required"}
	}
	switch engine {
	case EngineTLS8:
		return validateTLSTransportEvidence(size, evidence)
	case EngineBulkUDP:
		return validateBulkTransportEvidence(evidence)
	default:
		return nil
	}
}

func validateTLSTransportEvidence(size int64, evidence map[string]any) []string {
	var reasons []string
	reasons = append(reasons, requireStringValue(evidence, "tls_version", "TLS1.3")...)
	reasons = append(reasons, requireNonEmptyString(evidence, "tls_cipher")...)
	reasons = append(reasons, requireStringValue(evidence, "alpn", TLSProtocol)...)
	reasons = append(reasons, requireIntegerValue(evidence, "connections", 8)...)
	reasons = append(reasons, requireBoolValue(evidence, "pin_verified", true)...)
	laneBytes, ok := integerSlice(evidence["lane_bytes"])
	if !ok || len(laneBytes) != 8 {
		reasons = append(reasons, "transport.lane_bytes must contain eight integer values")
	} else {
		var total int64
		for _, value := range laneBytes {
			if value < 0 {
				reasons = append(reasons, "transport.lane_bytes must be non-negative")
				break
			}
			total += value
		}
		if total != size {
			reasons = append(reasons, fmt.Sprintf("transport.lane_bytes total must be %d", size))
		}
	}
	for _, key := range []string{"read_calls", "write_calls", "bytes_per_read_call", "bytes_per_write_call", "tcp_retransmits", "tcp_cwnd_segments"} {
		reasons = append(reasons, requireNonNegativeNumber(evidence, key)...)
	}
	if _, ok := boolValue(evidence["tcp_info_supported"]); !ok {
		reasons = append(reasons, "transport.tcp_info_supported is required and must be boolean")
	}
	return reasons
}

func validateBulkTransportEvidence(evidence map[string]any) []string {
	var reasons []string
	reasons = append(reasons, requireNonEmptyString(evidence, "batch_backend")...)
	for _, key := range []string{"gso_attempted", "gso_active"} {
		if _, ok := boolValue(evidence[key]); !ok {
			reasons = append(reasons, "transport."+key+" is required and must be boolean")
		}
	}
	for _, key := range []string{
		"gso_segments",
		"send_calls",
		"send_datagrams",
		"receive_calls",
		"receive_datagrams",
		"max_send_batch",
		"max_receive_batch",
		"crypto_queue_peak",
		"writer_queue_peak",
		"local_enobufs_retries",
		"repair_bytes",
		"repair_ratio",
		"retransmits",
		"primary_packet_count",
		"received_packet_count",
	} {
		reasons = append(reasons, requireNonNegativeNumber(evidence, key)...)
	}
	return reasons
}

func requireNonEmptyString(evidence map[string]any, key string) []string {
	value, ok := evidence[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return []string{"transport." + key + " is required and must be a non-empty string"}
	}
	return nil
}

func requireStringValue(evidence map[string]any, key, want string) []string {
	value, ok := evidence[key].(string)
	if !ok || value != want {
		return []string{fmt.Sprintf("transport.%s must be %q", key, want)}
	}
	return nil
}

func requireIntegerValue(evidence map[string]any, key string, want int64) []string {
	value, ok := integerValue(evidence[key])
	if !ok || value != want {
		return []string{fmt.Sprintf("transport.%s must be %d", key, want)}
	}
	return nil
}

func requireBoolValue(evidence map[string]any, key string, want bool) []string {
	value, ok := boolValue(evidence[key])
	if !ok || value != want {
		return []string{fmt.Sprintf("transport.%s must be %t", key, want)}
	}
	return nil
}

func requireNonNegativeNumber(evidence map[string]any, key string) []string {
	value, ok := numberValue(evidence[key])
	if !ok || !finiteNonNegative(value) {
		return []string{"transport." + key + " is required and must be a finite non-negative number"}
	}
	return nil
}

func numberValue(value any) (float64, bool) {
	switch value := value.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case json.Number:
		number, err := value.Float64()
		return number, err == nil
	}
	if number, ok := signedNumberValue(value); ok {
		return number, true
	}
	return unsignedNumberValue(value)
}

func signedNumberValue(value any) (float64, bool) {
	switch value := value.(type) {
	case int:
		return float64(value), true
	case int8:
		return float64(value), true
	case int16:
		return float64(value), true
	case int32:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}

func unsignedNumberValue(value any) (float64, bool) {
	switch value := value.(type) {
	case uint:
		return float64(value), true
	case uint8:
		return float64(value), true
	case uint16:
		return float64(value), true
	case uint32:
		return float64(value), true
	case uint64:
		return float64(value), true
	default:
		return 0, false
	}
}

func integerValue(value any) (int64, bool) {
	number, ok := numberValue(value)
	if !ok || math.Trunc(number) != number || number < math.MinInt64 || number > math.MaxInt64 {
		return 0, false
	}
	return int64(number), true
}

func integerSlice(value any) ([]int64, bool) {
	switch values := value.(type) {
	case []int64:
		return slices.Clone(values), true
	case []any:
		result := make([]int64, len(values))
		for index, value := range values {
			parsed, ok := integerValue(value)
			if !ok {
				return nil, false
			}
			result[index] = parsed
		}
		return result, true
	default:
		return nil, false
	}
}

func boolValue(value any) (bool, bool) {
	result, ok := value.(bool)
	return result, ok
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := strconv.ParseUint(value[:16], 16, 64)
	if err != nil {
		return false
	}
	_, err = strconv.ParseUint(value[16:32], 16, 64)
	if err != nil {
		return false
	}
	_, err = strconv.ParseUint(value[32:48], 16, 64)
	if err != nil {
		return false
	}
	_, err = strconv.ParseUint(value[48:], 16, 64)
	return err == nil
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func median(values []float64) float64 {
	values = slices.Clone(values)
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

func compactSorted(values []string) []string {
	sort.Strings(values)
	return slices.Compact(values)
}
