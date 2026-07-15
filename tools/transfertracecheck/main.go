// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/transfertrace"
)

var errUsage = errors.New("usage")

type options struct {
	Role                           string
	ExpectedBytes                  int64
	ExpectedBytesSet               bool
	ExpectedPayloadBytes           int64
	ExpectedPayloadBytesSet        bool
	StallWindow                    time.Duration
	PeerTrace                      string
	RateTolerance                  float64
	ProgressLeadToleranceBytes     int64
	RequireDirectTransport         string
	RequireFilePayloadEngine       transfertrace.FilePayloadEngine
	RequireEngineTelemetry         bool
	ExpectedSelectedPublicIPv4     string
	PeerExpectedSelectedPublicIPv4 string
	ForbidRelayPayload             bool
	Path                           string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, errUsage) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "transfertracecheck: %v\n", err)
		return 1
	}

	result, senderACKSummary, err := checkPayloadPaths(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "transfertracecheck: %v max_flatline=%s\n", err, result.MaxFlatline)
		return 1
	}

	pairSummary := ""
	if opts.PeerTrace != "" {
		pairResult, err := checkPairPaths(opts)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "transfertracecheck: %v\n", err)
			return 1
		}
		pairSummary = fmt.Sprintf(" peer_delta_bytes=%d sender_mbps=%.2f receiver_mbps=%.2f", pairResult.ProgressDeltaBytes, pairResult.SenderRateMbps, pairResult.ReceiverRateMbps)
	}

	diagnosticSummary := formatDiagnosticsSummary(result.Diagnostics)
	_, _ = fmt.Fprintf(stdout, "trace-ok rows=%d final_app_bytes=%d final_file_payload_bytes=%d max_flatline=%s%s%s%s\n", result.Rows, result.FinalAppBytes, result.FinalFilePayloadBytes, result.MaxFlatline, pairSummary, senderACKSummary, diagnosticSummary)
	return 0
}

func formatDiagnosticsSummary(diagnostics transfertrace.DiagnosticsSummary) string {
	summary := ""
	if diagnostics.MaxRateTargetMbps > 0 {
		summary += fmt.Sprintf(" max_rate_target_mbps=%d", diagnostics.MaxRateTargetMbps)
	}
	if diagnostics.MaxReplayBytes > 0 {
		summary += fmt.Sprintf(" max_replay_bytes=%d", diagnostics.MaxReplayBytes)
	}
	if diagnostics.MaxPeerRecvQueueDepth > 0 {
		summary += fmt.Sprintf(" max_peer_recv_queue_depth=%d", diagnostics.MaxPeerRecvQueueDepth)
	}
	if diagnostics.MaxStripedSendBlockedMS > 0 {
		summary += fmt.Sprintf(" max_striped_send_blocked_ms=%d", diagnostics.MaxStripedSendBlockedMS)
	}
	if diagnostics.MaxStripedReceivePendingChunks > 0 {
		summary += fmt.Sprintf(" max_striped_receive_pending_chunks=%d", diagnostics.MaxStripedReceivePendingChunks)
	}
	if diagnostics.MaxStripedReceivePendingBytes > 0 {
		summary += fmt.Sprintf(" max_striped_receive_pending_bytes=%d", diagnostics.MaxStripedReceivePendingBytes)
	}
	if diagnostics.DirectTransport != "" {
		summary += fmt.Sprintf(" direct_transport=%s", diagnostics.DirectTransport)
	}
	if diagnostics.ReceiverCommittedMbpsObserved {
		summary += fmt.Sprintf(" receiver_committed_mbps_min=%.2f receiver_committed_mbps_max=%.2f", diagnostics.ReceiverCommittedMbpsMin, diagnostics.ReceiverCommittedMbpsMax)
	}
	summary += formatSenderHealthSummary(diagnostics)
	summary += formatReceiverRateSummary(diagnostics)
	summary += formatReceiverRepairSummary(diagnostics)
	return summary
}

func formatSenderHealthSummary(diagnostics transfertrace.DiagnosticsSummary) string {
	if diagnostics.SenderHealthObserved {
		return fmt.Sprintf(" min_rate_target_mbps=%d final_rate_target_mbps=%d controller_decreases=%d final_repair_bytes=%d max_retransmits=%d local_enobufs_retries=%d local_enobufs_wait_us=%d local_enobufs_max_consecutive=%d",
			diagnostics.MinRateTargetMbps,
			diagnostics.FinalRateTargetMbps,
			diagnostics.ControllerDecreases,
			diagnostics.FinalRepairBytes,
			diagnostics.MaxRetransmits,
			diagnostics.LocalENOBUFSRetries,
			diagnostics.LocalENOBUFSWaitUS,
			diagnostics.LocalENOBUFSMaxConsecutive,
		)
	}
	return ""
}

func formatReceiverRateSummary(diagnostics transfertrace.DiagnosticsSummary) string {
	if diagnostics.ReceiverRateObserved {
		return fmt.Sprintf(" receiver_rate_p10_mbps=%.2f receiver_rate_p50_mbps=%.2f receiver_rate_p90_mbps=%.2f receiver_rate_cv=%.3f receiver_windows_below_500_mbps=%d",
			diagnostics.ReceiverRateP10Mbps,
			diagnostics.ReceiverRateP50Mbps,
			diagnostics.ReceiverRateP90Mbps,
			diagnostics.ReceiverRateCV,
			diagnostics.ReceiverWindowsBelow500Mbps,
		)
	}
	return ""
}

func formatReceiverRepairSummary(d transfertrace.DiagnosticsSummary) string {
	if !d.ReceiverRepairObserved {
		return ""
	}
	return fmt.Sprintf(" missing_scan_checks=%d pending_missing=%d pending_missing_peak=%d repair_requested_packets=%d repair_request_batches=%d reorder_trail_packets=%d receive_packet_rate_pps=%d",
		d.MissingScanChecks,
		d.PendingMissing,
		d.PendingMissingPeak,
		d.RepairRequestedPackets,
		d.RepairRequestBatches,
		d.ReorderTrailPackets,
		d.ReceivePacketRatePPS,
	)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var role string
	var expectedBytes int64
	var expectedPayloadBytes int64
	var stallWindow time.Duration
	var peerTrace string
	var rateTolerance float64
	var progressLeadToleranceBytes int64
	var requireDirectTransport string
	var requireFilePayloadEngine string
	var requireEngineTelemetry bool
	var expectedSelectedPublicIPv4 string
	var peerExpectedSelectedPublicIPv4 string
	var forbidRelayPayload bool
	flags := flag.NewFlagSet("transfertracecheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&role, "role", "", "trace role to check")
	flags.Int64Var(&expectedBytes, "expected-bytes", 0, "expected final app byte count")
	flags.Int64Var(&expectedPayloadBytes, "expected-payload-bytes", 0, "expected receiver-committed file payload byte count")
	flags.DurationVar(&stallWindow, "stall-window", time.Second, "maximum active-phase app byte stall")
	flags.StringVar(&peerTrace, "peer-trace", "", "optional peer trace CSV for sender peer_received_bytes to receiver app_bytes comparison")
	flags.Float64Var(&rateTolerance, "rate-tolerance", 0.10, "allowed sender/receiver transfer rate divergence")
	flags.Int64Var(&progressLeadToleranceBytes, "progress-lead-tolerance", 0, "allowed sender peer progress lead over receiver app bytes")
	flags.StringVar(&requireDirectTransport, "require-direct-transport", "", "require the final direct transport (for example, udp)")
	flags.StringVar(&requireFilePayloadEngine, "require-file-payload-engine", "", "require file payload engine (bulk-packets-v1 or quic-blocks-v1)")
	flags.BoolVar(&requireEngineTelemetry, "require-engine-telemetry", false, "require observed file payload engine telemetry")
	flags.StringVar(&expectedSelectedPublicIPv4, "expected-selected-public-ipv4", "", "require every selected file payload lane to use this public IPv4")
	flags.StringVar(&peerExpectedSelectedPublicIPv4, "peer-expected-selected-public-ipv4", "", "require every peer selected file payload lane to use this public IPv4")
	flags.BoolVar(&forbidRelayPayload, "forbid-relay-payload", false, "reject any payload bytes carried by relay")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: transfertracecheck -role receive [-expected-bytes N] [-peer-trace peer.csv] trace.csv")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return options{}, errUsage
	}
	if err := validateRoleOption(role, flags, stderr); err != nil {
		return options{}, err
	}
	expectedBytesSet := flagProvided(flags, "expected-bytes")
	expectedPayloadBytesSet := flagProvided(flags, "expected-payload-bytes")
	if err := validateExpectedByteOptions(expectedBytes, expectedPayloadBytes, flags, stderr); err != nil {
		return options{}, err
	}
	filePayloadEngine, err := parseRequiredFilePayloadEngine(requireFilePayloadEngine, flags, stderr)
	if err != nil {
		return options{}, err
	}
	if err := validateToleranceOptions(rateTolerance, progressLeadToleranceBytes, flags, stderr); err != nil {
		return options{}, err
	}
	return options{
		Role:                           role,
		ExpectedBytes:                  expectedBytes,
		ExpectedBytesSet:               expectedBytesSet,
		ExpectedPayloadBytes:           expectedPayloadBytes,
		ExpectedPayloadBytesSet:        expectedPayloadBytesSet,
		StallWindow:                    stallWindow,
		PeerTrace:                      peerTrace,
		RateTolerance:                  rateTolerance,
		ProgressLeadToleranceBytes:     progressLeadToleranceBytes,
		RequireDirectTransport:         requireDirectTransport,
		RequireFilePayloadEngine:       filePayloadEngine,
		RequireEngineTelemetry:         requireEngineTelemetry,
		ExpectedSelectedPublicIPv4:     expectedSelectedPublicIPv4,
		PeerExpectedSelectedPublicIPv4: peerExpectedSelectedPublicIPv4,
		ForbidRelayPayload:             forbidRelayPayload,
		Path:                           flags.Arg(0),
	}, nil
}

func validateRoleOption(role string, flags *flag.FlagSet, stderr io.Writer) error {
	if role == "" || flags.NArg() != 1 {
		flags.Usage()
		return errUsage
	}
	if role != string(transfertrace.RoleSend) && role != string(transfertrace.RoleReceive) {
		return optionUsageError(stderr, flags, "role must be send or receive")
	}
	return nil
}

func validateExpectedByteOptions(expectedBytes, expectedPayloadBytes int64, flags *flag.FlagSet, stderr io.Writer) error {
	if expectedBytes < 0 {
		return optionUsageError(stderr, flags, "expected-bytes must be non-negative")
	}
	if expectedPayloadBytes < 0 {
		return optionUsageError(stderr, flags, "expected-payload-bytes must be non-negative")
	}
	return nil
}

func parseRequiredFilePayloadEngine(value string, flags *flag.FlagSet, stderr io.Writer) (transfertrace.FilePayloadEngine, error) {
	if value == "" {
		return "", nil
	}
	engine, err := transfertrace.ParseFilePayloadEngine(value)
	if err != nil {
		return "", optionUsageError(stderr, flags, err)
	}
	return engine, nil
}

func validateToleranceOptions(rateTolerance float64, progressLeadToleranceBytes int64, flags *flag.FlagSet, stderr io.Writer) error {
	if rateTolerance < 0 {
		return optionUsageError(stderr, flags, "rate-tolerance must be non-negative")
	}
	if progressLeadToleranceBytes < 0 {
		return optionUsageError(stderr, flags, "progress-lead-tolerance must be non-negative")
	}
	return nil
}

func optionUsageError(stderr io.Writer, flags *flag.FlagSet, message any) error {
	_, _ = fmt.Fprintln(stderr, message)
	flags.Usage()
	return errUsage
}

func flagProvided(flags *flag.FlagSet, name string) bool {
	provided := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func checkPayloadPaths(opts options) (transfertrace.Result, string, error) {
	checkOpts := transfertrace.Options{
		Role:                       transfertrace.Role(opts.Role),
		ExpectedBytes:              opts.ExpectedBytes,
		ExpectedBytesSet:           opts.ExpectedBytesSet,
		ExpectedPayloadBytes:       opts.ExpectedPayloadBytes,
		ExpectedPayloadBytesSet:    opts.ExpectedPayloadBytesSet,
		StallWindow:                opts.StallWindow,
		RequireDirectTransport:     opts.RequireDirectTransport,
		RequireFilePayloadEngine:   opts.RequireFilePayloadEngine,
		RequireEngineTelemetry:     opts.RequireEngineTelemetry,
		ExpectedSelectedPublicIPv4: opts.ExpectedSelectedPublicIPv4,
		ForbidRelayPayload:         opts.ForbidRelayPayload,
	}
	pairedSender := opts.Role == string(transfertrace.RoleSend) && opts.PeerTrace != ""
	if pairedSender {
		checkOpts.StallWindow = time.Duration(math.MaxInt64)
	}
	result, err := checkTracePath(opts.Path, checkOpts)
	if err != nil || !pairedSender {
		return result, "", err
	}

	peerResult, err := checkTracePath(opts.PeerTrace, transfertrace.Options{
		Role:                       transfertrace.RoleReceive,
		StallWindow:                opts.StallWindow,
		ExpectedPayloadBytes:       opts.ExpectedPayloadBytes,
		ExpectedPayloadBytesSet:    opts.ExpectedPayloadBytesSet,
		RequireDirectTransport:     opts.RequireDirectTransport,
		RequireFilePayloadEngine:   opts.RequireFilePayloadEngine,
		RequireEngineTelemetry:     opts.RequireEngineTelemetry,
		ExpectedSelectedPublicIPv4: opts.PeerExpectedSelectedPublicIPv4,
		ForbidRelayPayload:         opts.ForbidRelayPayload,
	})
	if err != nil {
		return peerResult, "", err
	}
	senderACKSummary := fmt.Sprintf(" sender_ack_max_flatline=%s", result.MaxFlatline)
	result.MaxFlatline = peerResult.MaxFlatline
	result.FinalFilePayloadBytes = peerResult.FinalFilePayloadBytes
	result.FinalFilePayloadEngine = peerResult.FinalFilePayloadEngine
	result.FinalFilePayloadBytesBulk = peerResult.FinalFilePayloadBytesBulk
	result.FinalFilePayloadBytesQUIC = peerResult.FinalFilePayloadBytesQUIC
	result.FinalFilePayloadLaneAddresses = append([]string(nil), peerResult.FinalFilePayloadLaneAddresses...)
	return result, senderACKSummary, nil
}

func checkTracePath(path string, opts transfertrace.Options) (transfertrace.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return transfertrace.Result{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	return transfertrace.Check(f, opts)
}

func checkPairPaths(opts options) (transfertrace.PairResult, error) {
	primary, err := os.Open(opts.Path)
	if err != nil {
		return transfertrace.PairResult{}, fmt.Errorf("open %s: %w", opts.Path, err)
	}
	defer func() {
		_ = primary.Close()
	}()
	peer, err := os.Open(opts.PeerTrace)
	if err != nil {
		return transfertrace.PairResult{}, fmt.Errorf("open %s: %w", opts.PeerTrace, err)
	}
	defer func() {
		_ = peer.Close()
	}()
	return transfertrace.CheckPair(primary, peer, transfertrace.PairOptions{
		Role:                       transfertrace.Role(opts.Role),
		RateTolerance:              opts.RateTolerance,
		ProgressLeadToleranceBytes: opts.ProgressLeadToleranceBytes,
	})
}
