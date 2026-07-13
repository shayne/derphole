// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/transportbench"
)

const defaultTransferTimeout = 5 * time.Minute

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

type incompleteEvidenceError struct{ err error }

func (e incompleteEvidenceError) Error() string { return e.err.Error() }
func (e incompleteEvidenceError) Unwrap() error { return e.err }

type noWinnerError struct{ err error }

func (e noWinnerError) Error() string { return e.err.Error() }
func (e noWinnerError) Unwrap() error { return e.err }

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}
	err, known := runCLICommand(args[0], args[1:], stdout, stderr)
	if !known {
		writeUsage(stderr)
		return 2
	}
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "derphole-transport-bench: %v\n", err)
	var usage usageError
	var incomplete incompleteEvidenceError
	if errors.As(err, &usage) || errors.As(err, &incomplete) {
		return 2
	}
	return 1
}

func runCLICommand(command string, args []string, stdout, stderr io.Writer) (error, bool) {
	switch command {
	case "tls-receive":
		return runTLSReceive(args, stdout, stderr), true
	case "tls-send":
		return runTLSSend(args, stdout, stderr), true
	case "tls-send-listen":
		return runTLSSendListen(args, stdout, stderr), true
	case "tls-receive-connect":
		return runTLSReceiveConnect(args, stdout, stderr), true
	case "ingest-bulk":
		return runIngestBulk(args, stdout, stderr), true
	case "decide":
		return runDecide(args, stdout, stderr), true
	default:
		return nil, false
	}
}

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "usage:")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench tls-receive --listen ADDR --out FILE --ready-file FILE --trace FILE [--timeout 5m]")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench tls-send --peer ADDR --fingerprint HEX --transfer-id HEX --in FILE --trace FILE [--timeout 5m]")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench tls-send-listen --listen ADDR --in FILE --ready-file FILE --trace FILE [--timeout 5m]")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench tls-receive-connect --peer ADDR --fingerprint HEX --transfer-id HEX --out FILE --trace FILE [--timeout 5m]")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench ingest-bulk --summary-csv FILE --direction local-to-remote --run 1 --out FILE")
	_, _ = fmt.Fprintln(writer, "  derphole-transport-bench decide --results FILE --out FILE")
}

func runTLSReceive(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls-receive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddr := flags.String("listen", "", "TCP listen address")
	outputPath := flags.String("out", "", "output file")
	readyFile := flags.String("ready-file", "", "atomic ready descriptor")
	tracePath := flags.String("trace", "", "100ms CSV trace")
	timeout := flags.Duration("timeout", defaultTransferTimeout, "transfer timeout")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() != 0 {
		return usageError{errors.New("tls-receive does not accept positional arguments")}
	}
	summary, err := transportbench.ReceiveTLS(context.Background(), transportbench.TLSReceiveConfig{
		ListenAddr: *listenAddr,
		OutputPath: *outputPath,
		ReadyFile:  *readyFile,
		TracePath:  *tracePath,
		Timeout:    *timeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func runTLSSend(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls-send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	peerAddr := flags.String("peer", "", "receiver address")
	fingerprint := flags.String("fingerprint", "", "pinned SHA-256 SPKI fingerprint")
	transferIDHex := flags.String("transfer-id", "", "16-byte transfer ID in hexadecimal")
	inputPath := flags.String("in", "", "input file")
	tracePath := flags.String("trace", "", "100ms CSV trace")
	timeout := flags.Duration("timeout", defaultTransferTimeout, "transfer timeout")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() != 0 {
		return usageError{errors.New("tls-send does not accept positional arguments")}
	}
	transferID, err := parseTransferID(*transferIDHex)
	if err != nil {
		return usageError{err}
	}
	summary, err := transportbench.SendTLS(context.Background(), transportbench.TLSSendConfig{
		PeerAddr:          *peerAddr,
		FingerprintSHA256: *fingerprint,
		TransferID:        transferID,
		InputPath:         *inputPath,
		TracePath:         *tracePath,
		Timeout:           *timeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func runTLSSendListen(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls-send-listen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddr := flags.String("listen", "", "TCP listen address")
	inputPath := flags.String("in", "", "input file")
	readyFile := flags.String("ready-file", "", "atomic ready descriptor")
	tracePath := flags.String("trace", "", "100ms CSV trace")
	timeout := flags.Duration("timeout", defaultTransferTimeout, "transfer timeout")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() != 0 {
		return usageError{errors.New("tls-send-listen does not accept positional arguments")}
	}
	summary, err := transportbench.SendTLSListening(context.Background(), transportbench.TLSSendListenConfig{
		ListenAddr: *listenAddr,
		InputPath:  *inputPath,
		ReadyFile:  *readyFile,
		TracePath:  *tracePath,
		Timeout:    *timeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func runTLSReceiveConnect(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls-receive-connect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	peerAddr := flags.String("peer", "", "sender address")
	fingerprint := flags.String("fingerprint", "", "pinned SHA-256 SPKI fingerprint")
	transferIDHex := flags.String("transfer-id", "", "16-byte transfer ID in hexadecimal")
	outputPath := flags.String("out", "", "output file")
	tracePath := flags.String("trace", "", "100ms CSV trace")
	timeout := flags.Duration("timeout", defaultTransferTimeout, "transfer timeout")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() != 0 {
		return usageError{errors.New("tls-receive-connect does not accept positional arguments")}
	}
	transferID, err := parseTransferID(*transferIDHex)
	if err != nil {
		return usageError{err}
	}
	summary, err := transportbench.ReceiveTLSConnecting(context.Background(), transportbench.TLSReceiveConnectConfig{
		PeerAddr:          *peerAddr,
		FingerprintSHA256: *fingerprint,
		TransferID:        transferID,
		OutputPath:        *outputPath,
		TracePath:         *tracePath,
		Timeout:           *timeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func parseTransferID(value string) ([16]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		return [16]byte{}, errors.New("transfer ID must be 32 hexadecimal characters")
	}
	var transferID [16]byte
	copy(transferID[:], raw)
	return transferID, nil
}

func runDecide(args []string, stdout, stderr io.Writer) error {
	resultsPath, outputPath, err := parseDecideArgs(args, stderr)
	if err != nil {
		return err
	}
	runs, err := readRunResults(resultsPath)
	if err != nil {
		return incompleteEvidenceError{err}
	}
	byEngine := groupRunsByEngine(runs)
	if err := validateDecisionEvidence(byEngine); err != nil {
		return incompleteEvidenceError{err}
	}
	decision := transportbench.SelectWinner(
		transportbench.EvaluateCandidate(transportbench.EngineBulkUDP, byEngine[transportbench.EngineBulkUDP]),
		transportbench.EvaluateCandidate(transportbench.EngineTLS8, byEngine[transportbench.EngineTLS8]),
	)
	if err := writeJSONAtomic(outputPath, decision); err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(decision); err != nil {
		return err
	}
	if decision.Selected == "" {
		return noWinnerError{errors.New(decision.Reason)}
	}
	return nil
}

func parseDecideArgs(args []string, stderr io.Writer) (string, string, error) {
	flags := flag.NewFlagSet("decide", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resultsPath := flags.String("results", "", "JSON Lines run results")
	outputPath := flags.String("out", "", "decision JSON")
	if err := flags.Parse(args); err != nil {
		return "", "", usageError{err}
	}
	if flags.NArg() != 0 || *resultsPath == "" || *outputPath == "" {
		return "", "", usageError{errors.New("decide requires --results and --out")}
	}
	return *resultsPath, *outputPath, nil
}

func groupRunsByEngine(runs []transportbench.RunResult) map[transportbench.Engine][]transportbench.RunResult {
	byEngine := map[transportbench.Engine][]transportbench.RunResult{}
	for _, run := range runs {
		byEngine[run.Engine] = append(byEngine[run.Engine], run)
	}
	return byEngine
}

func validateDecisionEvidence(byEngine map[transportbench.Engine][]transportbench.RunResult) error {
	for _, engine := range []transportbench.Engine{transportbench.EngineBulkUDP, transportbench.EngineTLS8} {
		if len(byEngine[engine]) != 6 {
			return fmt.Errorf("incomplete evidence: %s has %d runs, want 6", engine, len(byEngine[engine]))
		}
		for _, run := range byEngine[engine] {
			if transportbench.EvaluateRun(run).Disposition == transportbench.DispositionInvalid {
				return fmt.Errorf("incomplete evidence: %s %s run %d has invalid capacity", engine, run.Direction, run.Run)
			}
		}
	}
	return nil
}

func readRunResults(path string) ([]transportbench.RunResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var results []transportbench.RunResult
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var result transportbench.RunResult
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil, fmt.Errorf("decode result line %d: %w", line, err)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("results file is empty")
	}
	return results, nil
}

func runIngestBulk(args []string, stdout, stderr io.Writer) error {
	summaryPath, direction, runNumber, outputPath, err := parseIngestBulkArgs(args, stderr)
	if err != nil {
		return err
	}
	result, err := ingestBulkSummary(summaryPath, direction, runNumber)
	if err != nil {
		return incompleteEvidenceError{err}
	}
	result = transportbench.EvaluateRun(result)
	if err := writeJSONAtomic(outputPath, result); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}

func parseIngestBulkArgs(args []string, stderr io.Writer) (string, transportbench.Direction, int, string, error) {
	flags := flag.NewFlagSet("ingest-bulk", flag.ContinueOnError)
	flags.SetOutput(stderr)
	summaryPath := flags.String("summary-csv", "", "public path summary CSV")
	directionRaw := flags.String("direction", "", "local-to-remote or remote-to-local")
	runNumber := flags.Int("run", 0, "run number")
	outputPath := flags.String("out", "", "normalized result JSON")
	if err := flags.Parse(args); err != nil {
		return "", "", 0, "", usageError{err}
	}
	direction := transportbench.Direction(*directionRaw)
	if flags.NArg() != 0 || *summaryPath == "" || *outputPath == "" || *runNumber < 1 || *runNumber > 3 ||
		(direction != transportbench.DirectionLocalToRemote && direction != transportbench.DirectionRemoteToLocal) {
		return "", "", 0, "", usageError{errors.New("ingest-bulk requires --summary-csv, a valid --direction, --run 1..3, and --out")}
	}
	return *summaryPath, direction, *runNumber, *outputPath, nil
}

func ingestBulkSummary(path string, direction transportbench.Direction, run int) (transportbench.RunResult, error) {
	records, err := readSummaryCSV(path)
	if err != nil {
		return transportbench.RunResult{}, err
	}
	header := csvHeader(records[0])
	iperfRow, transferRow, err := findBulkSummaryRows(records[1:], header, run)
	if err != nil {
		return transportbench.RunResult{}, err
	}
	if err := validateBulkSummaryIdentity(transferRow, header, direction); err != nil {
		return transportbench.RunResult{}, err
	}
	return parseBulkSummaryResult(iperfRow, transferRow, header, direction, run)
}

func readSummaryCSV(path string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, errors.New("summary CSV has no data rows")
	}
	return records, nil
}

func csvHeader(row []string) map[string]int {
	header := make(map[string]int, len(row))
	for index, name := range row {
		header[name] = index
	}
	return header
}

func findBulkSummaryRows(records [][]string, header map[string]int, run int) ([]string, []string, error) {
	var iperfRow, transferRow []string
	for _, row := range records {
		if csvField(row, header, "run") != strconv.Itoa(run) {
			continue
		}
		switch csvField(row, header, "tool") {
		case "iperf3":
			iperfRow = row
		case "derphole":
			transferRow = row
		}
	}
	if iperfRow == nil || transferRow == nil {
		return nil, nil, fmt.Errorf("summary CSV run %d requires iperf3 and derphole rows", run)
	}
	return iperfRow, transferRow, nil
}

func validateBulkSummaryIdentity(transferRow []string, header map[string]int, direction transportbench.Direction) error {
	if csvField(transferRow, header, "workload") != "file" {
		return errors.New("bulk result workload must be file")
	}
	if !strings.Contains(csvField(transferRow, header, "transfer_mode"), "bulk") {
		return errors.New("bulk result transfer_mode does not identify bulk")
	}
	expectedDirection := "forward"
	if direction == transportbench.DirectionRemoteToLocal {
		expectedDirection = "reverse"
	}
	if got := csvField(transferRow, header, "direction"); got != expectedDirection {
		return fmt.Errorf("summary direction %q, want %q", got, expectedDirection)
	}
	return nil
}

func parseBulkSummaryResult(iperfRow, transferRow []string, header map[string]int, direction transportbench.Direction, run int) (transportbench.RunResult, error) {
	measurements, err := parseBulkSummaryMeasurements(iperfRow, transferRow, header)
	if err != nil {
		return transportbench.RunResult{}, err
	}
	sender, err := csvEndpointResources(transferRow, header, "sender")
	if err != nil {
		return transportbench.RunResult{}, err
	}
	receiver, err := csvEndpointResources(transferRow, header, "receiver")
	if err != nil {
		return transportbench.RunResult{}, err
	}
	transport, err := csvBulkTransport(transferRow, header)
	if err != nil {
		return transportbench.RunResult{}, err
	}
	return transportbench.RunResult{
		SchemaVersion:        transportbench.ResultSchemaVersion,
		Revision:             requiredCSVString(transferRow, header, "revision_label"),
		Engine:               transportbench.EngineBulkUDP,
		Direction:            direction,
		Run:                  run,
		SizeBytes:            measurements.size,
		ExpectedSHA256:       requiredCSVString(transferRow, header, "expected_sha256"),
		ActualSHA256:         requiredCSVString(transferRow, header, "actual_sha256"),
		CanonicalGoodputMbps: &measurements.canonical,
		WallGoodputMbps:      &measurements.wall,
		CapacityMbps:         &measurements.capacity,
		MaxFlatlineMS:        &measurements.flatline,
		TraceComplete:        &measurements.traceOK,
		PublicRouteProven:    &measurements.publicRoute,
		TailscaleCandidates:  &measurements.tailscale,
		Sender:               sender,
		Receiver:             receiver,
		Transport:            transport,
	}, nil
}

type bulkSummaryMeasurements struct {
	canonical   float64
	wall        float64
	capacity    float64
	flatline    int64
	size        int64
	traceOK     bool
	publicRoute bool
	tailscale   int
}

func parseBulkSummaryMeasurements(iperfRow, transferRow []string, header map[string]int) (bulkSummaryMeasurements, error) {
	var result bulkSummaryMeasurements
	canonical, err := requiredCSVFloat(transferRow, header, "mbps")
	if err != nil {
		return result, err
	}
	result.canonical = canonical
	wall, err := requiredCSVFloat(transferRow, header, "wall_mbps")
	if err != nil {
		return result, err
	}
	result.wall = wall
	capacity, err := requiredCSVFloat(iperfRow, header, "mbps")
	if err != nil {
		return result, err
	}
	result.capacity = capacity
	flatline, err := requiredCSVDurationMS(transferRow, header, "max_flatline")
	if err != nil {
		return result, err
	}
	result.flatline = flatline
	size, err := requiredCSVInt64(transferRow, header, "benchmark_size_bytes")
	if err != nil {
		return result, err
	}
	result.size = size
	traceOK, err := requiredCSVBool(transferRow, header, "trace_ok")
	if err != nil {
		return result, err
	}
	result.traceOK = traceOK
	publicRoute, err := requiredCSVBool(transferRow, header, "public_route_proven")
	if err != nil {
		return result, err
	}
	result.publicRoute = publicRoute
	tailscale, err := requiredCSVInt(transferRow, header, "tailscale_candidates")
	if err != nil {
		return result, err
	}
	result.tailscale = tailscale
	return result, nil
}

func csvEndpointResources(row []string, header map[string]int, prefix string) (transportbench.EndpointResources, error) {
	user, err := requiredCSVFloat(row, header, prefix+"_user_cpu_seconds")
	if err != nil {
		return transportbench.EndpointResources{}, err
	}
	system, err := requiredCSVFloat(row, header, prefix+"_system_cpu_seconds")
	if err != nil {
		return transportbench.EndpointResources{}, err
	}
	perGiB, err := requiredCSVFloat(row, header, prefix+"_cpu_seconds_per_gib")
	if err != nil {
		return transportbench.EndpointResources{}, err
	}
	rss, err := requiredCSVInt64(row, header, prefix+"_max_rss_bytes")
	if err != nil {
		return transportbench.EndpointResources{}, err
	}
	return transportbench.EndpointResources{
		UserCPUSeconds:   &user,
		SystemCPUSeconds: &system,
		CPUSecondsPerGiB: &perGiB,
		PeakRSSBytes:     &rss,
	}, nil
}

func csvBulkTransport(row []string, header map[string]int) (map[string]any, error) {
	result := make(map[string]any)
	result["batch_backend"] = requiredCSVString(row, header, "batch_backend")
	for _, key := range []string{"gso_attempted", "gso_active"} {
		value, err := requiredCSVBool(row, header, key)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	integerKeys := []string{
		"gso_segments", "send_calls", "send_datagrams", "receive_calls", "receive_datagrams", "max_send_batch", "max_receive_batch",
		"crypto_queue_peak", "writer_queue_peak", "local_enobufs_retries", "repair_bytes", "retransmits", "primary_packet_count", "received_packet_count",
	}
	for _, key := range integerKeys {
		value, err := requiredCSVInt64(row, header, key)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	repairRatio, err := requiredCSVFloat(row, header, "repair_ratio")
	if err != nil {
		return nil, err
	}
	result["repair_ratio"] = repairRatio
	return result, nil
}

func csvField(row []string, header map[string]int, name string) string {
	index, ok := header[name]
	if !ok || index >= len(row) {
		return ""
	}
	return row[index]
}

func requiredCSVString(row []string, header map[string]int, name string) string {
	return strings.TrimSpace(csvField(row, header, name))
}

func requiredCSVFloat(row []string, header map[string]int, name string) (float64, error) {
	raw := requiredCSVString(row, header, name)
	if raw == "" {
		return 0, fmt.Errorf("summary CSV field %s is required", name)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("parse summary CSV field %s: %w", name, err)
	}
	return value, nil
}

func requiredCSVInt64(row []string, header map[string]int, name string) (int64, error) {
	raw := requiredCSVString(row, header, name)
	if raw == "" {
		return 0, fmt.Errorf("summary CSV field %s is required", name)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse summary CSV field %s: %w", name, err)
	}
	return value, nil
}

func requiredCSVInt(row []string, header map[string]int, name string) (int, error) {
	value, err := requiredCSVInt64(row, header, name)
	return int(value), err
}

func requiredCSVBool(row []string, header map[string]int, name string) (bool, error) {
	raw := requiredCSVString(row, header, name)
	if raw == "" {
		return false, fmt.Errorf("summary CSV field %s is required", name)
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse summary CSV field %s: %w", name, err)
	}
	return value, nil
}

func requiredCSVDurationMS(row []string, header map[string]int, name string) (int64, error) {
	raw := requiredCSVString(row, header, name)
	if raw == "" {
		return 0, fmt.Errorf("summary CSV field %s is required", name)
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse summary CSV field %s: %w", name, err)
	}
	return duration.Milliseconds(), nil
}

func writeJSONAtomic(path string, value any) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(temp).Encode(value); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}
