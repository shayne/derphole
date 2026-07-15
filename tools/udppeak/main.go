// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/udpbenchproof"
)

const maximumManifestBytes = 16 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "udppeak: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing command")
	}
	handler, ok := commandHandlers()[args[0]]
	if !ok {
		return fmt.Errorf("unknown command %q", args[0])
	}
	return handler(args[1:], stdout, stderr)
}

type commandHandler func([]string, io.Writer, io.Writer) error

func commandHandlers() map[string]commandHandler {
	return map[string]commandHandler{
		"manifest-create":     runManifestCreate,
		"artifact-verify":     runArtifactVerify,
		"validate":            runManifestValidate,
		"schedule":            runSchedule,
		"sample-validate":     runSampleValidate,
		"evaluate":            runEvaluate,
		"prerequisite-decide": runPrerequisiteDecide,
		"verify-prerequisite": runVerifyPrerequisite,
		"fleet-decide":        runFleetDecide,
		"acceptance-decide":   runAcceptanceDecide,
		"ceiling-decide":      runCeilingDecide,
		"health-snapshot":     runHealthSnapshot,
		"health-watch":        runHealthWatch,
		"health-compare":      runHealthCompare,
		"capacity-check":      runCapacityCheck,
		"process-identify":    runProcessIdentify,
	}
}

type processIdentifyFunc func(context.Context, string, int, time.Duration) (udpbenchproof.ProcessRef, error)

func runProcessIdentify(args []string, stdout, stderr io.Writer) error {
	return runProcessIdentifyWithIdentify(args, stdout, stderr, udpbenchproof.IdentifyProcess)
}

func runProcessIdentifyWithIdentify(args []string, stdout, stderr io.Writer, identify processIdentifyFunc) error {
	flags := newFlagSet("process-identify", stderr)
	name := flags.String("name", "", "exact process name")
	pid := flags.Int("pid", 0, "exact process ID")
	timeout := flags.Duration("timeout", 5*time.Second, "total identity deadline")
	outputPath := flags.String("out", "", "immutable process identity output")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *name == "" || *pid <= 0 || *timeout <= 0 || *outputPath == "" || identify == nil {
		return fmt.Errorf("process-identify requires -name, positive -pid, valid -timeout, and -out")
	}
	process, err := identify(context.Background(), *name, *pid, *timeout)
	if err != nil {
		return err
	}
	return writeImmutableResult(*outputPath, process, stdout, "process identity")
}

type healthCaptureFunc func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error)

type healthCaptureFlags struct {
	workDir        *string
	interfaceName  *string
	scopePath      *string
	captureTimeout *time.Duration
	commandTimeout *time.Duration
}

func registerHealthCaptureFlags(flags *flag.FlagSet) *healthCaptureFlags {
	options := &healthCaptureFlags{
		workDir:        flags.String("workdir", "", "work directory to measure"),
		interfaceName:  flags.String("interface", "", "network interface to measure"),
		scopePath:      flags.String("scope", "", "canonical declared cleanup scope"),
		captureTimeout: flags.Duration("capture-timeout", 30*time.Second, "total capture deadline"),
		commandTimeout: flags.Duration("command-timeout", 5*time.Second, "per-command deadline"),
	}
	return options
}

func (options *healthCaptureFlags) value() (udpbenchproof.HealthCaptureOptions, error) {
	if healthCaptureFlagPointersMissing(options) || healthCaptureFlagValuesInvalid(options) {
		return udpbenchproof.HealthCaptureOptions{}, fmt.Errorf("health capture requires -workdir, -interface, -scope, and valid deadlines")
	}
	var scope udpbenchproof.CleanupScope
	if _, err := loadCanonicalJSON(*options.scopePath, &scope); err != nil {
		return udpbenchproof.HealthCaptureOptions{}, fmt.Errorf("load cleanup scope: %w", err)
	}
	if err := udpbenchproof.ValidateCleanupScope(scope); err != nil {
		return udpbenchproof.HealthCaptureOptions{}, err
	}
	return udpbenchproof.HealthCaptureOptions{
		WorkDir: *options.workDir, Interface: *options.interfaceName,
		CleanupScope: scope, CaptureTimeout: *options.captureTimeout, CommandTimeout: *options.commandTimeout,
	}, nil
}

func healthCaptureFlagPointersMissing(options *healthCaptureFlags) bool {
	return options == nil || options.workDir == nil || options.interfaceName == nil || options.scopePath == nil ||
		options.captureTimeout == nil || options.commandTimeout == nil
}

func healthCaptureFlagValuesInvalid(options *healthCaptureFlags) bool {
	return *options.workDir == "" || *options.interfaceName == "" || *options.scopePath == "" ||
		*options.captureTimeout <= 0 || *options.commandTimeout <= 0 || *options.commandTimeout > *options.captureTimeout
}

func runHealthSnapshot(args []string, stdout, stderr io.Writer) error {
	return runHealthSnapshotWithCapture(args, stdout, stderr, udpbenchproof.CaptureHealth)
}

func runHealthSnapshotWithCapture(args []string, stdout, stderr io.Writer, capture healthCaptureFunc) error {
	flags := newFlagSet("health-snapshot", stderr)
	captureFlags := registerHealthCaptureFlags(flags)
	outputPath := flags.String("out", "", "immutable health snapshot output")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	options, err := captureFlags.value()
	if err != nil {
		return err
	}
	if *outputPath == "" {
		return fmt.Errorf("health-snapshot requires -out")
	}
	snapshot, err := capture(context.Background(), options)
	if err != nil {
		return err
	}
	return writeImmutableResult(*outputPath, snapshot, stdout, "health snapshot")
}

func runHealthWatch(args []string, stdout, stderr io.Writer) error {
	return runHealthWatchWithCapture(args, stdout, stderr, udpbenchproof.CaptureHealth)
}

func runHealthWatchWithCapture(args []string, stdout, stderr io.Writer, capture healthCaptureFunc) error {
	options, err := parseHealthWatchOptions(args, stderr)
	if err != nil {
		return err
	}
	if err := requireAbsentHealthStopFile(options.stopPath); err != nil {
		return err
	}
	if err := rejectHealthWatchPathAlias(options.stopPath, options.outputPath); err != nil {
		return err
	}
	file, err := os.OpenFile(options.outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable health watch output: %w", err)
	}
	if err := syncCLIArtifactDirectory(filepath.Dir(options.outputPath)); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := writeHealthWatch(file, options, capture); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close health watch output: %w", err)
	}
	return printCLIFileDigest(options.outputPath, stdout, "health watch")
}

type healthWatchOptions struct {
	capture    udpbenchproof.HealthCaptureOptions
	interval   time.Duration
	stopPath   string
	outputPath string
}

func parseHealthWatchOptions(args []string, stderr io.Writer) (healthWatchOptions, error) {
	flags := newFlagSet("health-watch", stderr)
	captureFlags := registerHealthCaptureFlags(flags)
	interval := flags.Duration("interval", 0, "capture cadence from 1s through 2s")
	stopPath := flags.String("stop-file", "", "exact stop-file path")
	outputPath := flags.String("out", "", "immutable health JSONL output")
	if err := parseExactFlags(flags, args); err != nil {
		return healthWatchOptions{}, err
	}
	captureOptions, err := captureFlags.value()
	if err != nil {
		return healthWatchOptions{}, err
	}
	if *interval < time.Second || *interval > 2*time.Second || *stopPath == "" || *outputPath == "" {
		return healthWatchOptions{}, fmt.Errorf("health-watch requires a 1s-2s -interval, -stop-file, and -out")
	}
	return healthWatchOptions{capture: captureOptions, interval: *interval, stopPath: *stopPath, outputPath: *outputPath}, nil
}

func requireAbsentHealthStopFile(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("health-watch stop file already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect health-watch stop file: %w", err)
	}
	return nil
}

func rejectHealthWatchPathAlias(stopPath, outputPath string) error {
	stopAbsolute, err := filepath.Abs(stopPath)
	if err != nil {
		return fmt.Errorf("resolve health-watch stop path: %w", err)
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve health-watch output path: %w", err)
	}
	stopAbsolute = filepath.Clean(stopAbsolute)
	outputAbsolute = filepath.Clean(outputAbsolute)
	if stopAbsolute == outputAbsolute {
		return fmt.Errorf("health-watch stop and output paths alias")
	}
	stopParent, err := filepath.EvalSymlinks(filepath.Dir(stopAbsolute))
	if err != nil {
		return fmt.Errorf("resolve health-watch stop parent: %w", err)
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(outputAbsolute))
	if err != nil {
		return fmt.Errorf("resolve health-watch output parent: %w", err)
	}
	resolvedStop := filepath.Join(stopParent, filepath.Base(stopAbsolute))
	resolvedOutput := filepath.Join(outputParent, filepath.Base(outputAbsolute))
	if resolvedStop == resolvedOutput {
		return fmt.Errorf("health-watch stop and output paths alias")
	}
	return nil
}

func writeHealthWatch(file *os.File, options healthWatchOptions, capture healthCaptureFunc) error {
	if options.interval <= 0 {
		return fmt.Errorf("health watch interval is invalid")
	}
	ctx := context.Background()
	nextStart := time.Now()
	completeSamples := 0
	for {
		stopped, err := waitForScheduledHealthCapture(ctx, nextStart, options.stopPath)
		if err != nil {
			return err
		}
		if stopped {
			if completeSamples == 0 {
				return fmt.Errorf("health watch stopped before first complete sample")
			}
			return nil
		}
		started, err := captureHealthWatchSnapshot(ctx, file, options, capture)
		if err != nil {
			return err
		}
		completeSamples++
		nextStart = started.Add(options.interval)
		if !time.Now().Before(nextStart) {
			return fmt.Errorf("health watch cadence overrun before next capture")
		}
	}
}

func waitForScheduledHealthCapture(ctx context.Context, nextStart time.Time, stopPath string) (bool, error) {
	stopped, err := healthWatchStopped(stopPath)
	if err != nil || stopped {
		return stopped, err
	}
	wait := time.Until(nextStart)
	if wait <= 0 {
		return false, nil
	}
	return waitForHealthWatchStart(ctx, wait, stopPath)
}

func captureHealthWatchSnapshot(ctx context.Context, file *os.File, options healthWatchOptions, capture healthCaptureFunc) (time.Time, error) {
	started := time.Now()
	captureContext, cancel := context.WithTimeout(ctx, options.interval)
	snapshot, captureErr := capture(captureContext, options.capture)
	captureContextErr := captureContext.Err()
	cancel()
	elapsed := time.Since(started)
	if captureErr != nil {
		return started, captureErr
	}
	if err := appendHealthWatchSnapshot(file, snapshot); err != nil {
		return started, err
	}
	if captureContextErr != nil || elapsed >= options.interval {
		return started, fmt.Errorf("health watch capture overrun after %s", elapsed)
	}
	return started, nil
}

func appendHealthWatchSnapshot(file *os.File, snapshot udpbenchproof.HealthSnapshot) error {
	line, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if err := writeCLIBytes(file, line); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync health watch output: %w", err)
	}
	return nil
}

func waitForHealthWatchStart(ctx context.Context, wait time.Duration, stopPath string) (bool, error) {
	if wait <= 0 {
		return healthWatchStopped(stopPath)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	pollEvery := 10 * time.Millisecond
	if wait < pollEvery {
		pollEvery = wait
	}
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return healthWatchStopped(stopPath)
		case <-ticker.C:
			stopped, err := healthWatchStopped(stopPath)
			if err != nil || stopped {
				return stopped, err
			}
		}
	}
}

func healthWatchStopped(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect health-watch stop file: %w", err)
}

func printCLIFileDigest(path string, stdout io.Writer, label string) error {
	digest, err := udpbenchproof.FileDigest(path)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, digest); err != nil {
		return fmt.Errorf("write %s digest result: %w", label, err)
	}
	return nil
}

func runHealthCompare(args []string, stdout, stderr io.Writer) error {
	options, err := parseHealthCompareOptions(args, stderr)
	if err != nil {
		return err
	}
	before, err := loadHealthSnapshot(options.beforePath, "before")
	if err != nil {
		return err
	}
	after, err := loadHealthSnapshot(options.afterPath, "after")
	if err != nil {
		return err
	}
	verdict := udpbenchproof.CompareHealth(before, after, options.policy)
	digest, err := udpbenchproof.WriteImmutableJSON(options.outputPath, verdict)
	if err != nil {
		return err
	}
	if !verdict.Healthy {
		return fmt.Errorf("health comparison failed (verdict %s): %s", digest, strings.Join(verdict.Reasons, "; "))
	}
	if _, err := fmt.Fprintln(stdout, digest); err != nil {
		return fmt.Errorf("write health verdict digest result: %w", err)
	}
	return nil
}

type healthCompareOptions struct {
	beforePath string
	afterPath  string
	outputPath string
	policy     udpbenchproof.HealthPolicy
}

func parseHealthCompareOptions(args []string, stderr io.Writer) (healthCompareOptions, error) {
	flags := newFlagSet("health-compare", stderr)
	beforePath := flags.String("before", "", "canonical before snapshot")
	afterPath := flags.String("after", "", "canonical after snapshot")
	expectedCPUs := flags.Int("expected-online-cpus", 0, "required online CPU count")
	minMemory := flags.Int64("min-available-memory-bytes", -1, "minimum available memory")
	minDisk := flags.Int64("min-disk-available-bytes", -1, "minimum available disk")
	maxSwap := flags.Int64("max-swap-used-bytes", -1, "maximum swap used after capture")
	maxSwapIncrease := flags.Int64("max-swap-increase-bytes", -1, "maximum swap increase")
	scopePath := flags.String("scope", "", "canonical expected cleanup scope")
	outputPath := flags.String("out", "", "immutable health verdict output")
	if err := parseExactFlags(flags, args); err != nil {
		return healthCompareOptions{}, err
	}
	if invalidHealthCompareFlags(*beforePath, *afterPath, *scopePath, *outputPath, *expectedCPUs, *minMemory, *minDisk, *maxSwap, *maxSwapIncrease) {
		return healthCompareOptions{}, fmt.Errorf("health-compare requires snapshots, exact scope, positive expected CPUs, nonnegative thresholds, and -out")
	}
	var scope udpbenchproof.CleanupScope
	if _, err := loadCanonicalJSON(*scopePath, &scope); err != nil {
		return healthCompareOptions{}, fmt.Errorf("load expected cleanup scope: %w", err)
	}
	if err := udpbenchproof.ValidateCleanupScope(scope); err != nil {
		return healthCompareOptions{}, err
	}
	return healthCompareOptions{
		beforePath: *beforePath, afterPath: *afterPath, outputPath: *outputPath,
		policy: udpbenchproof.HealthPolicy{
			ExpectedOnlineCPUs: *expectedCPUs, MinAvailableMemoryBytes: *minMemory, MinDiskAvailableBytes: *minDisk,
			MaxSwapUsedBytes: *maxSwap, MaxSwapIncreaseBytes: *maxSwapIncrease, ExpectedCleanupScope: scope,
		},
	}, nil
}

func invalidHealthCompareFlags(before, after, scope, output string, cpus int, minMemory, minDisk, maxSwap, maxSwapIncrease int64) bool {
	return before == "" || after == "" || scope == "" || output == "" || cpus <= 0 || minMemory < 0 || minDisk < 0 || maxSwap < 0 || maxSwapIncrease < 0
}

func loadHealthSnapshot(path, role string) (udpbenchproof.HealthSnapshot, error) {
	var snapshot udpbenchproof.HealthSnapshot
	if _, err := loadCanonicalJSON(path, &snapshot); err != nil {
		return udpbenchproof.HealthSnapshot{}, fmt.Errorf("load %s health snapshot: %w", role, err)
	}
	return snapshot, nil
}

type capacityCheckRecord struct {
	SchemaVersion     int                           `json:"schema_version"`
	Kind              string                        `json:"kind"`
	FreeBytes         int64                         `json:"free_bytes"`
	Requirement       udpbenchproof.DiskRequirement `json:"requirement"`
	RequiredFreeBytes int64                         `json:"required_free_bytes"`
	Sufficient        bool                          `json:"sufficient"`
}

func runCapacityCheck(args []string, stdout, stderr io.Writer) error {
	options, err := parseCapacityCheckOptions(args, stderr)
	if err != nil {
		return err
	}
	required, err := udpbenchproof.RequiredFreeBytes(options.requirement)
	if err != nil {
		return err
	}
	checkErr := udpbenchproof.CheckDiskCapacity(options.freeBytes, options.requirement)
	record := capacityCheckRecord{
		SchemaVersion: 1, Kind: "disk-capacity", FreeBytes: options.freeBytes, Requirement: options.requirement,
		RequiredFreeBytes: required, Sufficient: checkErr == nil,
	}
	digest, err := udpbenchproof.WriteImmutableJSON(options.outputPath, record)
	if err != nil {
		return err
	}
	if checkErr != nil {
		return fmt.Errorf("capacity check failed (verdict %s): %w", digest, checkErr)
	}
	if _, err := fmt.Fprintln(stdout, digest); err != nil {
		return fmt.Errorf("write capacity verdict digest result: %w", err)
	}
	return nil
}

type capacityCheckOptions struct {
	freeBytes   int64
	requirement udpbenchproof.DiskRequirement
	outputPath  string
}

func parseCapacityCheckOptions(args []string, stderr io.Writer) (capacityCheckOptions, error) {
	flags := newFlagSet("capacity-check", stderr)
	freeBytes := flags.Int64("free-bytes", -1, "measured free bytes")
	payloadBytes := flags.Int64("payload-bytes", -1, "one payload size")
	binaryBytes := flags.Int64("binary-bytes", -1, "concurrent binary bytes")
	evidenceBytes := flags.Int64("evidence-reserve-bytes", -1, "evidence reserve bytes")
	additionalCopies := flags.Int("additional-payload-copies", -1, "additional concurrent payload copies")
	outputPath := flags.String("out", "", "immutable capacity verdict output")
	if err := parseExactFlags(flags, args); err != nil {
		return capacityCheckOptions{}, err
	}
	for _, value := range []int64{*freeBytes, *payloadBytes, *binaryBytes, *evidenceBytes, int64(*additionalCopies)} {
		if value < 0 {
			return capacityCheckOptions{}, fmt.Errorf("capacity-check requires nonnegative byte/copy values and -out")
		}
	}
	if *outputPath == "" {
		return capacityCheckOptions{}, fmt.Errorf("capacity-check requires nonnegative byte/copy values and -out")
	}
	return capacityCheckOptions{
		freeBytes: *freeBytes, outputPath: *outputPath,
		requirement: udpbenchproof.DiskRequirement{
			PayloadBytes: *payloadBytes, BinaryBytes: *binaryBytes, EvidenceReserveBytes: *evidenceBytes,
			AdditionalPayloadCopies: *additionalCopies,
		},
	}, nil
}

func syncCLIArtifactDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open health artifact directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync health artifact directory: %w", err), directory.Close())
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close health artifact directory: %w", err)
	}
	return nil
}

func writeCLIBytes(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return fmt.Errorf("invalid health output write count %d", written)
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type scheduleOptions struct {
	stage            udpbenchproof.Stage
	manifestPath     string
	manifestDigest   udpbenchproof.SHA256Digest
	priorPath        string
	prerequisitePath string
	fleetPath        string
	outputPath       string
}

func runSchedule(args []string, stdout, stderr io.Writer) error {
	options, err := parseScheduleOptions(args, stderr)
	if err != nil {
		return err
	}
	if err := udpbenchproof.VerifyArtifact(options.manifestPath, options.manifestDigest); err != nil {
		return err
	}
	manifest, got, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	if got != options.manifestDigest {
		return fmt.Errorf("manifest changed during schedule load")
	}
	authorization, err := loadScheduleAuthorization(manifest, options)
	if err != nil {
		return err
	}
	schedule, err := udpbenchproof.BuildSchedule(manifest, options.stage, authorization)
	if err != nil {
		return err
	}
	return writeImmutableResult(options.outputPath, schedule, stdout, "schedule")
}

func parseScheduleOptions(args []string, stderr io.Writer) (scheduleOptions, error) {
	flags := newFlagSet("schedule", stderr)
	stageValue := flags.String("stage", "", "schedule stage")
	manifestPath := flags.String("manifest", "", "manifest path")
	manifestDigest := flags.String("manifest-sha256", "", "manifest SHA-256")
	priorPath := flags.String("prior", "", "prior peak decision path")
	prerequisitePath := flags.String("prerequisite", "", "prerequisite decision path")
	fleetPath := flags.String("fleet", "", "fleet decision path")
	outputPath := flags.String("out", "", "immutable schedule output")
	if err := parseExactFlags(flags, args); err != nil {
		return scheduleOptions{}, err
	}
	if *stageValue == "" || *manifestPath == "" || *manifestDigest == "" || *outputPath == "" {
		return scheduleOptions{}, fmt.Errorf("schedule requires -stage, -manifest, -manifest-sha256, and -out")
	}
	stage, err := parseStage(*stageValue)
	if err != nil {
		return scheduleOptions{}, err
	}
	options := scheduleOptions{
		stage: stage, manifestPath: *manifestPath, manifestDigest: udpbenchproof.SHA256Digest(*manifestDigest),
		priorPath: *priorPath, prerequisitePath: *prerequisitePath, fleetPath: *fleetPath, outputPath: *outputPath,
	}
	if err := validateScheduleProofPaths(options); err != nil {
		return scheduleOptions{}, err
	}
	return options, nil
}

func validateScheduleProofPaths(options scheduleOptions) error {
	got := scheduleProofSet{prior: options.priorPath != "", prerequisite: options.prerequisitePath != "", fleet: options.fleetPath != ""}
	want, message := requiredScheduleProofSet(options.stage)
	if got != want {
		return fmt.Errorf("%s", message)
	}
	return nil
}

type scheduleProofSet struct {
	prior        bool
	prerequisite bool
	fleet        bool
}

func requiredScheduleProofSet(stage udpbenchproof.Stage) (scheduleProofSet, string) {
	switch stage {
	case udpbenchproof.StageScreening:
		return scheduleProofSet{}, "screening schedule must omit authorization decisions"
	case udpbenchproof.StagePreliminary, udpbenchproof.StageFinalist, udpbenchproof.StageFinalistRerun, udpbenchproof.StageProduction:
		return scheduleProofSet{prior: true}, fmt.Sprintf("%s schedule requires only -prior", stage)
	case udpbenchproof.StageFleet:
		return scheduleProofSet{prerequisite: true}, "fleet schedule requires only -prerequisite"
	case udpbenchproof.StageAcceptance:
		return scheduleProofSet{prerequisite: true, fleet: true}, "acceptance schedule requires -prerequisite and -fleet"
	case udpbenchproof.StageCeiling:
		return scheduleProofSet{prior: true, prerequisite: true, fleet: true}, "ceiling schedule requires -prior, -prerequisite, and -fleet"
	}
	return scheduleProofSet{}, "unsupported schedule stage"
}

func loadScheduleAuthorization(manifest udpbenchproof.Manifest, options scheduleOptions) (udpbenchproof.ScheduleAuthorization, error) {
	root := manifest.EvidenceRoot
	switch options.stage {
	case udpbenchproof.StageScreening:
		return udpbenchproof.ScheduleAuthorization{}, nil
	case udpbenchproof.StagePreliminary, udpbenchproof.StageFinalist, udpbenchproof.StageFinalistRerun, udpbenchproof.StageProduction:
		peak, err := loadPriorDecision(options.stage, options.priorPath, root)
		return udpbenchproof.ScheduleAuthorization{Peak: peak}, err
	case udpbenchproof.StageFleet:
		prerequisite, err := loadSchedulePrerequisite(options.prerequisitePath, root)
		return udpbenchproof.ScheduleAuthorization{Prerequisite: prerequisite}, err
	case udpbenchproof.StageAcceptance, udpbenchproof.StageCeiling:
		return loadChildScheduleAuthorization(manifest, options)
	default:
		return udpbenchproof.ScheduleAuthorization{}, fmt.Errorf("unsupported schedule stage %q", options.stage)
	}
}

func loadSchedulePrerequisite(path, root string) (udpbenchproof.PrerequisiteDecision, error) {
	var prerequisite udpbenchproof.PrerequisiteDecision
	digest, err := loadCanonicalJSON(path, &prerequisite)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	ref, err := rootedArtifactRef(root, path, "prerequisite", digest)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	prerequisite.Artifact = ref
	prerequisite.EvidenceRoot = root
	return prerequisite, nil
}

func loadChildScheduleAuthorization(manifest udpbenchproof.Manifest, options scheduleOptions) (udpbenchproof.ScheduleAuthorization, error) {
	prerequisiteRef, hasPrerequisiteRef := manifestDecisionRef(manifest, "prerequisite")
	fleetRef, hasFleetRef := manifestDecisionRef(manifest, "fleet")
	if !hasFleetRef {
		return udpbenchproof.ScheduleAuthorization{}, fmt.Errorf("%s manifest lacks fleet reference", options.stage)
	}
	var prerequisite udpbenchproof.PrerequisiteDecision
	var err error
	if hasPrerequisiteRef {
		prerequisite, err = loadAcceptancePrerequisite(options.prerequisitePath, prerequisiteRef, manifest.EvidenceRoot)
	} else {
		prerequisite, err = loadSchedulePrerequisite(options.prerequisitePath, manifest.EvidenceRoot)
	}
	if err != nil {
		return udpbenchproof.ScheduleAuthorization{}, err
	}
	fleet, err := loadAcceptanceFleet(options.fleetPath, fleetRef, manifest.EvidenceRoot)
	if err != nil {
		return udpbenchproof.ScheduleAuthorization{}, err
	}
	authorization := udpbenchproof.ScheduleAuthorization{Prerequisite: prerequisite, Fleet: fleet}
	if options.stage == udpbenchproof.StageCeiling {
		peakRef, ok := manifestDecisionRef(manifest, "peak")
		if !ok {
			return udpbenchproof.ScheduleAuthorization{}, fmt.Errorf("ceiling manifest lacks peak reference")
		}
		authorization.Peak, err = loadAcceptanceFleet(options.priorPath, peakRef, manifest.EvidenceRoot)
		if err != nil {
			return udpbenchproof.ScheduleAuthorization{}, err
		}
	}
	return authorization, nil
}

func loadPriorDecision(stage udpbenchproof.Stage, path, evidenceRoot string) (udpbenchproof.Decision, error) {
	if err := validatePriorPath(stage, path); err != nil {
		return udpbenchproof.Decision{}, err
	}
	if stage == udpbenchproof.StageScreening {
		return udpbenchproof.Decision{}, nil
	}
	var prior udpbenchproof.Decision
	digest, err := loadCanonicalJSON(path, &prior)
	if err != nil {
		return udpbenchproof.Decision{}, fmt.Errorf("load prior decision: %w", err)
	}
	relative, err := filepath.Rel(evidenceRoot, path)
	if err != nil {
		return udpbenchproof.Decision{}, fmt.Errorf("bind prior decision to evidence root: %w", err)
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") || filepath.IsAbs(relative) {
		return udpbenchproof.Decision{}, fmt.Errorf("prior decision is outside campaign evidence root")
	}
	role := string(prior.Stage)
	if stage == udpbenchproof.StageProduction {
		role = "finalist"
	}
	prior.Artifact = udpbenchproof.ArtifactRef{
		Role:   role,
		Path:   relative,
		SHA256: digest,
	}
	prior.EvidenceRoot = evidenceRoot
	return prior, nil
}

func validatePriorPath(stage udpbenchproof.Stage, path string) error {
	if stage == udpbenchproof.StageScreening {
		if path != "" {
			return fmt.Errorf("screening schedule must omit -prior")
		}
		return nil
	}
	if path == "" {
		return fmt.Errorf("%s requires -prior", stage)
	}
	return nil
}

func runSampleValidate(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("sample-validate", stderr)
	manifestPath := flags.String("manifest", "", "manifest path")
	samplePath := flags.String("sample", "", "sample path")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *manifestPath == "" || *samplePath == "" {
		return fmt.Errorf("sample-validate requires -manifest and -sample")
	}
	manifest, _, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}
	var sample udpbenchproof.Sample
	if _, err := loadCanonicalJSON(*samplePath, &sample); err != nil {
		return fmt.Errorf("load sample: %w", err)
	}
	sample.EvidenceRoot = manifest.EvidenceRoot
	verdict := udpbenchproof.ValidateSample(manifest, sample)
	if verdict.Status != "valid" {
		return fmt.Errorf("sample %s: %v", verdict.Status, verdict.Reasons)
	}
	if _, err := fmt.Fprintln(stdout, "valid"); err != nil {
		return fmt.Errorf("write sample validation result: %w", err)
	}
	return nil
}

func runEvaluate(args []string, stdout, stderr io.Writer) error {
	options, err := parseEvaluateOptions(args, stderr)
	if err != nil {
		return err
	}
	stage, err := parseStage(options.stage)
	if err != nil {
		return err
	}
	if err := validatePriorPath(stage, options.priorPath); err != nil {
		return err
	}
	manifest, _, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	prior, err := loadPriorDecision(stage, options.priorPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	samples, err := loadSampleJSONL(options.resultsPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	decision, err := udpbenchproof.Evaluate(manifest, samples, stage, prior)
	if err != nil {
		return err
	}
	return writeImmutableResult(options.outputPath, decision, stdout, "decision")
}

type evaluateOptions struct {
	stage        string
	manifestPath string
	resultsPath  string
	priorPath    string
	outputPath   string
}

func parseEvaluateOptions(args []string, stderr io.Writer) (evaluateOptions, error) {
	flags := newFlagSet("evaluate", stderr)
	stageValue := flags.String("stage", "", "decision stage")
	manifestPath := flags.String("manifest", "", "manifest path")
	resultsPath := flags.String("results", "", "sample JSONL path")
	priorPath := flags.String("prior", "", "prior decision path")
	outputPath := flags.String("out", "", "immutable decision output")
	if err := parseExactFlags(flags, args); err != nil {
		return evaluateOptions{}, err
	}
	if *stageValue == "" || *manifestPath == "" || *resultsPath == "" || *outputPath == "" {
		return evaluateOptions{}, fmt.Errorf("evaluate requires -stage, -manifest, -results, and -out")
	}
	return evaluateOptions{*stageValue, *manifestPath, *resultsPath, *priorPath, *outputPath}, nil
}

func runPrerequisiteDecide(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("prerequisite-decide", stderr)
	manifestPath := flags.String("manifest", "", "production manifest path")
	resultsPath := flags.String("results", "", "production sample JSONL path")
	outputPath := flags.String("out", "", "immutable prerequisite output")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *manifestPath == "" || *resultsPath == "" || *outputPath == "" {
		return fmt.Errorf("prerequisite-decide requires -manifest, -results, and -out")
	}
	manifest, _, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}
	samples, err := loadSampleJSONL(*resultsPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	decision := udpbenchproof.DecidePrerequisite(manifest, samples)
	return writeImmutableResult(*outputPath, decision, stdout, "prerequisite decision")
}

func runVerifyPrerequisite(args []string, stdout, stderr io.Writer) error {
	options, err := parseVerifyPrerequisiteOptions(args, stderr)
	if err != nil {
		return err
	}
	if err := udpbenchproof.VerifyArtifact(options.manifestPath, options.manifestDigest); err != nil {
		return err
	}
	if err := udpbenchproof.VerifyArtifact(options.decisionPath, options.decisionDigest); err != nil {
		return err
	}
	manifest, gotManifest, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	if gotManifest != options.manifestDigest {
		return fmt.Errorf("manifest changed during prerequisite verification")
	}
	decision, err := loadPrerequisiteDecision(options)
	if err != nil {
		return err
	}
	binaries, err := loadVerifiedBinaries(options, decision.BinarySet)
	if err != nil {
		return err
	}
	if err := udpbenchproof.VerifyPrerequisite(manifest, options.manifestDigest, decision, options.decisionDigest, binaries); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, options.decisionDigest); err != nil {
		return fmt.Errorf("write prerequisite verification result: %w", err)
	}
	return nil
}

type verifyPrerequisiteOptions struct {
	manifestPath   string
	manifestDigest udpbenchproof.SHA256Digest
	decisionPath   string
	decisionDigest udpbenchproof.SHA256Digest
	localBin       string
	linuxBin       string
}

func parseVerifyPrerequisiteOptions(args []string, stderr io.Writer) (verifyPrerequisiteOptions, error) {
	flags := newFlagSet("verify-prerequisite", stderr)
	manifestPath := flags.String("manifest", "", "production manifest path")
	manifestDigest := flags.String("manifest-sha256", "", "production manifest SHA-256")
	decisionPath := flags.String("decision", "", "prerequisite decision path")
	decisionDigest := flags.String("decision-sha256", "", "prerequisite decision SHA-256")
	localBin := flags.String("local-bin", "", "Darwin binary path")
	linuxBin := flags.String("linux-bin", "", "Linux binary path")
	if err := parseExactFlags(flags, args); err != nil {
		return verifyPrerequisiteOptions{}, err
	}
	if *manifestPath == "" || *manifestDigest == "" || *decisionPath == "" || *decisionDigest == "" || *localBin == "" || *linuxBin == "" {
		return verifyPrerequisiteOptions{}, fmt.Errorf("verify-prerequisite requires manifest, decision, and binary paths with exact digests")
	}
	return verifyPrerequisiteOptions{
		manifestPath: *manifestPath, manifestDigest: udpbenchproof.SHA256Digest(*manifestDigest),
		decisionPath: *decisionPath, decisionDigest: udpbenchproof.SHA256Digest(*decisionDigest),
		localBin: *localBin, linuxBin: *linuxBin,
	}, nil
}

func loadPrerequisiteDecision(options verifyPrerequisiteOptions) (udpbenchproof.PrerequisiteDecision, error) {
	var decision udpbenchproof.PrerequisiteDecision
	gotDecision, err := loadCanonicalJSON(options.decisionPath, &decision)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	if gotDecision != options.decisionDigest {
		return udpbenchproof.PrerequisiteDecision{}, fmt.Errorf("decision changed during prerequisite verification")
	}
	evidenceRoot := filepath.Dir(filepath.Clean(options.manifestPath))
	ref, err := rootedArtifactRef(evidenceRoot, options.decisionPath, "prerequisite", gotDecision)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	decision.Artifact = ref
	decision.EvidenceRoot = evidenceRoot
	return decision, nil
}

func loadVerifiedBinaries(options verifyPrerequisiteOptions, binaries udpbenchproof.BinarySet) (udpbenchproof.BinarySet, error) {
	var err error
	binaries.Darwin.SHA256, err = udpbenchproof.FileDigest(options.localBin)
	if err != nil {
		return udpbenchproof.BinarySet{}, err
	}
	binaries.Linux.SHA256, err = udpbenchproof.FileDigest(options.linuxBin)
	if err != nil {
		return udpbenchproof.BinarySet{}, err
	}
	return binaries, nil
}

func runFleetDecide(args []string, stdout, stderr io.Writer) error {
	options, err := parseFleetOptions(args, stderr)
	if err != nil {
		return err
	}
	manifest, manifestDigest, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	var prerequisite udpbenchproof.PrerequisiteDecision
	prerequisiteDigest, err := loadCanonicalJSON(options.prerequisitePath, &prerequisite)
	if err != nil {
		return err
	}
	root := manifest.EvidenceRoot
	prerequisiteRef, err := rootedArtifactRef(root, options.prerequisitePath, "prerequisite", prerequisiteDigest)
	if err != nil {
		return err
	}
	prerequisite.Artifact = prerequisiteRef
	prerequisite.EvidenceRoot = root
	probeRefs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](options.probesPath)
	if err != nil {
		return err
	}
	samples, err := loadSampleJSONL(options.resultsPath, root)
	if err != nil {
		return err
	}
	decision := udpbenchproof.DecideFleet(udpbenchproof.FleetInputs{
		Manifest: manifest, ManifestRef: udpbenchproof.ArtifactRef{Role: "manifest", Path: filepath.ToSlash(filepath.Base(options.manifestPath)), SHA256: manifestDigest},
		Prerequisite: prerequisite, PrerequisiteRef: prerequisiteRef, ProbeRefs: probeRefs,
		Samples: samples, EvidenceRoot: root,
	})
	return writeImmutableResult(options.outputPath, decision, stdout, "fleet decision")
}

type fleetOptions struct {
	manifestPath     string
	prerequisitePath string
	probesPath       string
	resultsPath      string
	outputPath       string
}

func parseFleetOptions(args []string, stderr io.Writer) (fleetOptions, error) {
	flags := newFlagSet("fleet-decide", stderr)
	manifestPath := flags.String("manifest", "", "production manifest path")
	prerequisitePath := flags.String("prerequisite", "", "verified prerequisite decision path")
	probesPath := flags.String("probes", "", "fleet probe artifact reference JSONL path")
	resultsPath := flags.String("results", "", "fleet sample artifact reference JSONL path")
	outputPath := flags.String("out", "", "immutable fleet decision output")
	if err := parseExactFlags(flags, args); err != nil {
		return fleetOptions{}, err
	}
	if *manifestPath == "" || *prerequisitePath == "" || *probesPath == "" || *resultsPath == "" || *outputPath == "" {
		return fleetOptions{}, fmt.Errorf("fleet-decide requires manifest, prerequisite, probes, results, and output paths")
	}
	return fleetOptions{*manifestPath, *prerequisitePath, *probesPath, *resultsPath, *outputPath}, nil
}

func rootedArtifactRef(root, artifactPath, role string, digest udpbenchproof.SHA256Digest) (udpbenchproof.ArtifactRef, error) {
	relative, err := filepath.Rel(root, artifactPath)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return udpbenchproof.ArtifactRef{}, fmt.Errorf("%s artifact is outside evidence root", role)
	}
	return udpbenchproof.ArtifactRef{Role: role, Path: filepath.ToSlash(relative), SHA256: digest}, nil
}

func runAcceptanceDecide(args []string, stdout, stderr io.Writer) error {
	options, err := parseAcceptanceOptions(args, stderr)
	if err != nil {
		return err
	}
	manifest, manifestDigest, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	prerequisite, prerequisiteRef, fleet, fleetRef, err := loadAcceptanceParents(manifest, options)
	if err != nil {
		return err
	}
	samples, err := loadSampleJSONL(options.resultsPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	decision := udpbenchproof.DecideAcceptance(udpbenchproof.AcceptanceInputs{
		Manifest:        manifest,
		ManifestRef:     udpbenchproof.ArtifactRef{Role: "manifest", Path: filepath.Base(options.manifestPath), SHA256: manifestDigest},
		Prerequisite:    prerequisite,
		PrerequisiteRef: prerequisiteRef,
		Fleet:           fleet,
		FleetRef:        fleetRef,
		Samples:         samples,
	})
	return writeImmutableResult(options.outputPath, decision, stdout, "acceptance decision")
}

func loadAcceptanceParents(manifest udpbenchproof.Manifest, options acceptanceOptions) (udpbenchproof.PrerequisiteDecision, udpbenchproof.ArtifactRef, udpbenchproof.Decision, udpbenchproof.ArtifactRef, error) {
	prerequisiteRef, ok := manifestDecisionRef(manifest, "prerequisite")
	if !ok {
		return udpbenchproof.PrerequisiteDecision{}, udpbenchproof.ArtifactRef{}, udpbenchproof.Decision{}, udpbenchproof.ArtifactRef{}, fmt.Errorf("acceptance manifest lacks prerequisite reference")
	}
	fleetRef, ok := manifestDecisionRef(manifest, "fleet")
	if !ok {
		return udpbenchproof.PrerequisiteDecision{}, udpbenchproof.ArtifactRef{}, udpbenchproof.Decision{}, udpbenchproof.ArtifactRef{}, fmt.Errorf("acceptance manifest lacks fleet reference")
	}
	prerequisite, err := loadAcceptancePrerequisite(options.prerequisitePath, prerequisiteRef, manifest.EvidenceRoot)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, udpbenchproof.ArtifactRef{}, udpbenchproof.Decision{}, udpbenchproof.ArtifactRef{}, err
	}
	fleet, err := loadAcceptanceFleet(options.fleetPath, fleetRef, manifest.EvidenceRoot)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, udpbenchproof.ArtifactRef{}, udpbenchproof.Decision{}, udpbenchproof.ArtifactRef{}, err
	}
	return prerequisite, prerequisiteRef, fleet, fleetRef, nil
}

func loadAcceptancePrerequisite(path string, ref udpbenchproof.ArtifactRef, root string) (udpbenchproof.PrerequisiteDecision, error) {
	if err := udpbenchproof.VerifyArtifact(path, ref.SHA256); err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	var decision udpbenchproof.PrerequisiteDecision
	if _, err := loadCanonicalJSON(path, &decision); err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	bound, err := rootedArtifactRef(root, path, ref.Role, ref.SHA256)
	if err != nil {
		return udpbenchproof.PrerequisiteDecision{}, err
	}
	if bound != ref {
		return udpbenchproof.PrerequisiteDecision{}, fmt.Errorf("prerequisite path does not match exact manifest reference")
	}
	decision.Artifact = ref
	decision.EvidenceRoot = root
	return decision, nil
}

func loadAcceptanceFleet(path string, ref udpbenchproof.ArtifactRef, root string) (udpbenchproof.Decision, error) {
	if err := udpbenchproof.VerifyArtifact(path, ref.SHA256); err != nil {
		return udpbenchproof.Decision{}, err
	}
	var decision udpbenchproof.Decision
	if _, err := loadCanonicalJSON(path, &decision); err != nil {
		return udpbenchproof.Decision{}, err
	}
	bound, err := rootedArtifactRef(root, path, ref.Role, ref.SHA256)
	if err != nil {
		return udpbenchproof.Decision{}, err
	}
	if bound != ref {
		return udpbenchproof.Decision{}, fmt.Errorf("decision path does not match exact manifest reference")
	}
	decision.Artifact = ref
	decision.EvidenceRoot = root
	return decision, nil
}

type acceptanceOptions struct {
	manifestPath     string
	prerequisitePath string
	fleetPath        string
	resultsPath      string
	outputPath       string
}

func parseAcceptanceOptions(args []string, stderr io.Writer) (acceptanceOptions, error) {
	flags := newFlagSet("acceptance-decide", stderr)
	manifestPath := flags.String("manifest", "", "acceptance manifest path")
	prerequisitePath := flags.String("prerequisite", "", "prerequisite decision path")
	fleetPath := flags.String("fleet", "", "fleet decision path")
	resultsPath := flags.String("results", "", "acceptance sample JSONL path")
	outputPath := flags.String("out", "", "immutable acceptance decision output")
	if err := parseExactFlags(flags, args); err != nil {
		return acceptanceOptions{}, err
	}
	if *manifestPath == "" || *prerequisitePath == "" || *fleetPath == "" || *resultsPath == "" || *outputPath == "" {
		return acceptanceOptions{}, fmt.Errorf("acceptance-decide requires manifest, prerequisite, fleet, results, and output paths")
	}
	return acceptanceOptions{manifestPath: *manifestPath, prerequisitePath: *prerequisitePath, fleetPath: *fleetPath, resultsPath: *resultsPath, outputPath: *outputPath}, nil
}

func runCeilingDecide(args []string, stdout, stderr io.Writer) error {
	options, err := parseCeilingOptions(args, stderr)
	if err != nil {
		return err
	}
	manifest, _, err := loadManifest(options.manifestPath)
	if err != nil {
		return err
	}
	sweeps, err := loadCeilingSweepJSONL(options.sweepsPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	profiles, err := loadCeilingProfileJSONL(options.profilesPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	samples, err := loadSampleJSONL(options.winnerPath, manifest.EvidenceRoot)
	if err != nil {
		return err
	}
	decision := udpbenchproof.DecideCeiling(manifest, sweeps, profiles, samples)
	return writeImmutableResult(options.outputPath, decision, stdout, "ceiling decision")
}

func loadCeilingSweepJSONL(path, root string) ([]udpbenchproof.CeilingSweepPoint, error) {
	refs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](path)
	if err != nil {
		return nil, err
	}
	points := make([]udpbenchproof.CeilingSweepPoint, 0, len(refs))
	for index, ref := range refs {
		point, openErr := udpbenchproof.LoadCeilingSweepArtifact(root, ref)
		if openErr != nil {
			return nil, fmt.Errorf("ceiling sweep ref line %d: %w", index+1, openErr)
		}
		points = append(points, point)
	}
	return points, nil
}

func loadCeilingProfileJSONL(path, root string) ([]udpbenchproof.CeilingProfile, error) {
	refs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](path)
	if err != nil {
		return nil, err
	}
	profiles := make([]udpbenchproof.CeilingProfile, 0, len(refs))
	for index, ref := range refs {
		profile, openErr := udpbenchproof.LoadCeilingProfileArtifact(root, ref)
		if openErr != nil {
			return nil, fmt.Errorf("ceiling profile ref line %d: %w", index+1, openErr)
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

type ceilingOptions struct {
	manifestPath string
	sweepsPath   string
	profilesPath string
	winnerPath   string
	outputPath   string
}

func parseCeilingOptions(args []string, stderr io.Writer) (ceilingOptions, error) {
	flags := newFlagSet("ceiling-decide", stderr)
	manifestPath := flags.String("manifest", "", "ceiling manifest path")
	sweepsPath := flags.String("sweeps", "", "ceiling sweep JSONL path")
	profilesPath := flags.String("profiles", "", "ceiling profile JSONL path")
	winnerPath := flags.String("winner-samples", "", "winner sample JSONL path")
	outputPath := flags.String("out", "", "immutable ceiling decision output")
	if err := parseExactFlags(flags, args); err != nil {
		return ceilingOptions{}, err
	}
	if *manifestPath == "" || *sweepsPath == "" || *profilesPath == "" || *winnerPath == "" || *outputPath == "" {
		return ceilingOptions{}, fmt.Errorf("ceiling-decide requires manifest, sweeps, profiles, winner samples, and output paths")
	}
	return ceilingOptions{manifestPath: *manifestPath, sweepsPath: *sweepsPath, profilesPath: *profilesPath, winnerPath: *winnerPath, outputPath: *outputPath}, nil
}

func runManifestCreate(args []string, stdout, stderr io.Writer) error {
	return runManifestCreateWithWriter(args, stdout, stderr, udpbenchproof.WriteImmutableJSON)
}

type immutableJSONWriter func(string, any) (udpbenchproof.SHA256Digest, error)

func runManifestCreateWithWriter(args []string, stdout, stderr io.Writer, writer immutableJSONWriter) error {
	flags := newFlagSet("manifest-create", stderr)
	inputPath := flags.String("input", "", "manifest input JSON")
	outputPath := flags.String("out", "", "immutable manifest output")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *inputPath == "" || *outputPath == "" {
		return fmt.Errorf("manifest-create requires -input and -out")
	}
	data, err := readBoundedFile(*inputPath)
	if err != nil {
		return err
	}
	var input udpbenchproof.ManifestInput
	if err := decodeStrictJSON(data, &input); err != nil {
		return fmt.Errorf("decode manifest input: %w", err)
	}
	manifest, err := udpbenchproof.NewManifest(input)
	if err != nil {
		return err
	}
	digest, err := writer(*outputPath, manifest)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, digest); err != nil {
		return fmt.Errorf("write manifest digest result: %w", err)
	}
	return nil
}

func runArtifactVerify(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("artifact-verify", stderr)
	path := flags.String("path", "", "artifact path")
	digest := flags.String("sha256", "", "expected SHA-256")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *path == "" || *digest == "" {
		return fmt.Errorf("artifact-verify requires -path and -sha256")
	}
	want := udpbenchproof.SHA256Digest(*digest)
	if err := udpbenchproof.VerifyArtifact(*path, want); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, want); err != nil {
		return fmt.Errorf("write artifact verification result: %w", err)
	}
	return nil
}

func runManifestValidate(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("validate", stderr)
	manifestPath := flags.String("manifest", "", "manifest path")
	digest := flags.String("sha256", "", "expected SHA-256")
	if err := parseExactFlags(flags, args); err != nil {
		return err
	}
	if *manifestPath == "" || *digest == "" {
		return fmt.Errorf("validate requires -manifest and -sha256")
	}
	want := udpbenchproof.SHA256Digest(*digest)
	if err := validateManifestArtifact(*manifestPath, want); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, want); err != nil {
		return fmt.Errorf("write manifest validation result: %w", err)
	}
	return nil
}

func validateManifestArtifact(path string, want udpbenchproof.SHA256Digest) error {
	if err := udpbenchproof.VerifyArtifact(path, want); err != nil {
		return err
	}
	data, err := readBoundedFile(path)
	if err != nil {
		return err
	}
	if got := udpbenchproof.DigestBytes(data); got != want {
		return fmt.Errorf("manifest changed during verification: got %s, want %s", got, want)
	}
	var manifest udpbenchproof.Manifest
	if err := decodeStrictJSON(data, &manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if err := udpbenchproof.ValidateManifest(manifest); err != nil {
		return err
	}
	return requireCanonicalManifestBytes(data, manifest)
}

func requireCanonicalManifestBytes(data []byte, manifest udpbenchproof.Manifest) error {
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal canonical manifest: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("manifest bytes are not canonical compact JSON with one final newline")
	}
	return nil
}

func parseStage(value string) (udpbenchproof.Stage, error) {
	stage := udpbenchproof.Stage(value)
	switch stage {
	case udpbenchproof.StageScreening, udpbenchproof.StagePreliminary, udpbenchproof.StageFinalist,
		udpbenchproof.StageFinalistRerun, udpbenchproof.StageProduction, udpbenchproof.StageFleet,
		udpbenchproof.StageCeiling, udpbenchproof.StageAcceptance:
		return stage, nil
	default:
		return "", fmt.Errorf("invalid stage %q", value)
	}
}

func loadManifest(path string) (udpbenchproof.Manifest, udpbenchproof.SHA256Digest, error) {
	var manifest udpbenchproof.Manifest
	digest, err := loadCanonicalJSON(path, &manifest)
	if err != nil {
		return udpbenchproof.Manifest{}, "", fmt.Errorf("load manifest: %w", err)
	}
	if err := udpbenchproof.ValidateManifest(manifest); err != nil {
		return udpbenchproof.Manifest{}, "", err
	}
	manifest.EvidenceRoot = filepath.Dir(path)
	return manifest, digest, nil
}

func loadCanonicalJSON(path string, target any) (udpbenchproof.SHA256Digest, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return "", err
	}
	if err := decodeStrictJSON(data, target); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return "", fmt.Errorf("JSON input is not canonical compact JSON with one final newline")
	}
	return udpbenchproof.DigestBytes(data), nil
}

func loadSampleJSONL(path, root string) ([]udpbenchproof.Sample, error) {
	refs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](path)
	if err != nil {
		return nil, err
	}
	samples := make([]udpbenchproof.Sample, 0, len(refs))
	for index, ref := range refs {
		sample, openErr := udpbenchproof.LoadSampleArtifact(root, ref)
		if openErr != nil {
			return nil, fmt.Errorf("sample ref line %d: %w", index+1, openErr)
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

func loadCanonicalJSONL[T any](path string) ([]T, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("JSONL input must end with exactly one newline")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	if len(lines) == 0 {
		return nil, fmt.Errorf("JSONL input is empty")
	}
	values := make([]T, 0, len(lines))
	for index, line := range lines {
		if len(line) == 0 {
			return nil, fmt.Errorf("JSONL line %d is empty", index+1)
		}
		var value T
		if err := decodeStrictJSON(line, &value); err != nil {
			return nil, fmt.Errorf("JSONL line %d: %w", index+1, err)
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(line, canonical) {
			return nil, fmt.Errorf("JSONL line %d is not canonical compact JSON", index+1)
		}
		values = append(values, value)
	}
	return values, nil
}

func writeImmutableResult(path string, value any, stdout io.Writer, label string) error {
	digest, err := udpbenchproof.WriteImmutableJSON(path, value)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, digest); err != nil {
		return fmt.Errorf("write %s digest result: %w", label, err)
	}
	return nil
}

func manifestDecisionRef(manifest udpbenchproof.Manifest, role string) (udpbenchproof.ArtifactRef, bool) {
	for _, ref := range manifest.ManifestInput.ParentDecisionRefs {
		if ref.Role == role {
			return ref, true
		}
	}
	return udpbenchproof.ArtifactRef{}, false
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parseExactFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected trailing arguments: %v", flags.Args())
	}
	return nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open JSON input: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > maximumManifestBytes {
		return nil, fmt.Errorf("JSON input exceeds %d bytes", maximumManifestBytes)
	}
	return data, nil
}

func decodeStrictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkUniqueJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func walkUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		return walkUniqueJSONObject(decoder)
	case '[':
		return walkUniqueJSONArray(decoder)
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func walkUniqueJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		key, err := readUniqueJSONObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		seen[key] = struct{}{}
		if err := walkUniqueJSONValue(decoder); err != nil {
			return err
		}
	}
	return requireClosingJSONDelimiter(decoder, '}')
}

func readUniqueJSONObjectKey(decoder *json.Decoder, seen map[string]struct{}) (string, error) {
	keyToken, err := decoder.Token()
	if err != nil {
		return "", err
	}
	key, ok := keyToken.(string)
	if !ok {
		return "", fmt.Errorf("JSON object key is not a string")
	}
	if _, duplicate := seen[key]; duplicate {
		return "", fmt.Errorf("duplicate JSON object member %q", key)
	}
	return key, nil
}

func walkUniqueJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := walkUniqueJSONValue(decoder); err != nil {
			return err
		}
	}
	return requireClosingJSONDelimiter(decoder, ']')
}

func requireClosingJSONDelimiter(decoder *json.Decoder, want json.Delim) error {
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != want {
		return fmt.Errorf("invalid JSON closing token %v, want %q", closing, want)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected extra JSON value beginning with %v", token)
	}
	return nil
}
