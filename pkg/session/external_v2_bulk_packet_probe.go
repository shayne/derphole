// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"golang.org/x/time/rate"
)

var (
	errExternalV2BulkPacketProbeRejected           = errors.New("bulk packet capacity probe rejected")
	errExternalV2BulkPacketProbeForcedSenderReject = errors.New("bulk packet sender probe rejected by test outcome")
)

var externalV2BulkPacketProbeRatesMbps = []int{128, 512, 1000, 1600, 2000, 2200, 2400}

var externalV2BulkPacketSenderProbeSelector = selectExternalV2BulkPacketProbe
var externalV2BulkPacketReceiverProbeSelector = selectExternalV2BulkPacketProbe

const (
	externalV2BulkPacketProbeTestOutcomeEnv          = "DERPHOLE_TEST_BULK_PROBE_OUTCOME"
	externalV2BulkPacketProbeTestOutcomeSenderReject = "sender-reject"
	externalV2BulkPacketProbeDirtyRateEnv            = "DERPHOLE_TEST_BULK_PROBE_DIRTY_RATE_MBPS"

	externalV2BulkPacketProbeDuration    = 50 * time.Millisecond
	externalV2BulkPacketProbeMaxBytes    = 16 << 20
	externalV2BulkPacketProbeSettle      = 10 * time.Millisecond
	externalV2BulkPacketProbePrefixSize  = 16
	externalV2BulkPacketProbeTagSize     = 16
	externalV2BulkPacketProbeSeedPercent = 90

	externalV2BulkPacketProbeStopDirty          = "dirty"
	externalV2BulkPacketProbeStopPressure       = "pressure"
	externalV2BulkPacketProbeStopLadderComplete = "ladder-complete"
)

type externalV2BulkPacketProbeTrainResult struct {
	RateMbps int
	Sent     uint32
	Received uint32
	Pressure bool
}

type externalV2BulkPacketProbeResult struct {
	RunID          uint64
	SelectedMbps   int
	Duration       time.Duration
	Trains         []externalV2BulkPacketProbeTrainResult
	StopReason     string
	RejectStage    string
	RejectTrain    int
	RejectRateMbps int
	HandoffDrain   externalV2BulkPacketHandoffDrainResult
}

type externalV2BulkPacketProbeRejection struct {
	Stage    string
	Train    int
	RateMbps int
	cause    error
}

func (e *externalV2BulkPacketProbeRejection) Error() string {
	return fmt.Sprintf("bulk packet capacity probe rejected at %s train %d rate %d Mbps: %v", e.Stage, e.Train, e.RateMbps, e.cause)
}

func (e *externalV2BulkPacketProbeRejection) Unwrap() error { return e.cause }

func (e *externalV2BulkPacketProbeRejection) Is(target error) bool {
	return target == errExternalV2BulkPacketProbeRejected
}

func externalV2BulkPacketProbeOrdinaryRejection(err error) bool {
	if err == errExternalV2BulkPacketProbeRejected {
		return true
	}
	if _, ok := err.(*externalV2BulkPacketProbeRejection); ok {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	errs := joined.Unwrap()
	return len(errs) == 2 &&
		externalV2BulkPacketProbeOrdinaryRejection(errs[0]) &&
		errs[1] == errExternalV2BulkPacketProbeForcedSenderReject
}

type externalV2BulkPacketProbeTestOutcomeError struct {
	value string
}

func (e *externalV2BulkPacketProbeTestOutcomeError) Error() string {
	return fmt.Sprintf(
		"%s must be unset or %q (got %q)",
		externalV2BulkPacketProbeTestOutcomeEnv,
		externalV2BulkPacketProbeTestOutcomeSenderReject,
		e.value,
	)
}

type externalV2BulkPacketProbeRole string

const (
	externalV2BulkPacketProbeSender   externalV2BulkPacketProbeRole = "sender"
	externalV2BulkPacketProbeReceiver externalV2BulkPacketProbeRole = "receiver"
)

type externalV2BulkPacketProbeDirtyRateError struct {
	value string
	role  externalV2BulkPacketProbeRole
}

func (e *externalV2BulkPacketProbeDirtyRateError) Error() string {
	if e.role != externalV2BulkPacketProbeReceiver {
		return fmt.Sprintf("%s is receiver-only (got role %q)", externalV2BulkPacketProbeDirtyRateEnv, e.role)
	}
	return fmt.Sprintf("%s must be unset or one configured probe rate (got %q)", externalV2BulkPacketProbeDirtyRateEnv, e.value)
}

func parseExternalV2BulkPacketProbeDirtyRate(
	value string,
	configured bool,
	role externalV2BulkPacketProbeRole,
) (int, bool, error) {
	if !configured {
		return 0, false, nil
	}
	if role != externalV2BulkPacketProbeReceiver {
		return 0, false, &externalV2BulkPacketProbeDirtyRateError{value: value, role: role}
	}
	rateMbps, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(rateMbps) != value {
		return 0, false, &externalV2BulkPacketProbeDirtyRateError{value: value, role: role}
	}
	for _, configuredRate := range externalV2BulkPacketProbeRatesMbps {
		if rateMbps == configuredRate {
			return rateMbps, true, nil
		}
	}
	return 0, false, &externalV2BulkPacketProbeDirtyRateError{value: value, role: role}
}

func externalV2BulkPacketProbeDirtyRate(role externalV2BulkPacketProbeRole) (int, bool, error) {
	value, configured := os.LookupEnv(externalV2BulkPacketProbeDirtyRateEnv)
	return parseExternalV2BulkPacketProbeDirtyRate(value, configured, role)
}

type externalV2BulkPacketProbePrefix struct {
	Train    uint16
	Flags    uint16
	Sequence uint32
	Expected uint32
	RateMbps uint32
}

func encodeExternalV2BulkPacketProbePrefix(prefix externalV2BulkPacketProbePrefix) [externalV2BulkPacketProbePrefixSize]byte {
	var encoded [externalV2BulkPacketProbePrefixSize]byte
	binary.BigEndian.PutUint16(encoded[0:2], prefix.Train)
	binary.BigEndian.PutUint16(encoded[2:4], prefix.Flags)
	binary.BigEndian.PutUint32(encoded[4:8], prefix.Sequence)
	binary.BigEndian.PutUint32(encoded[8:12], prefix.Expected)
	binary.BigEndian.PutUint32(encoded[12:16], prefix.RateMbps)
	return encoded
}

func decodeExternalV2BulkPacketProbePrefix(payload []byte) (externalV2BulkPacketProbePrefix, bool) {
	if len(payload) < externalV2BulkPacketProbePrefixSize {
		return externalV2BulkPacketProbePrefix{}, false
	}
	return externalV2BulkPacketProbePrefix{
		Train:    binary.BigEndian.Uint16(payload[0:2]),
		Flags:    binary.BigEndian.Uint16(payload[2:4]),
		Sequence: binary.BigEndian.Uint32(payload[4:8]),
		Expected: binary.BigEndian.Uint32(payload[8:12]),
		RateMbps: binary.BigEndian.Uint32(payload[12:16]),
	}, true
}

func externalV2BulkPacketProbeDatagramCount(rateMbps int) uint32 {
	if rateMbps <= 0 {
		return 0
	}
	wireBytes := int64(externalV2BulkPacketIPv4WireBytes(externalV2BulkPacketMaxSize))
	targetBytes := int64(rateMbps) * 1_000_000 * int64(externalV2BulkPacketProbeDuration) / int64(8*time.Second)
	targetBytes = min(targetBytes, int64(externalV2BulkPacketProbeMaxBytes))
	return uint32(max(int64(1), targetBytes/wireBytes))
}

func selectExternalV2BulkPacketProbe(trains []externalV2BulkPacketProbeTrainResult) (externalV2BulkPacketProbeResult, error) {
	result := externalV2BulkPacketProbeResult{
		Trains:     append([]externalV2BulkPacketProbeTrainResult(nil), trains...),
		StopReason: externalV2BulkPacketProbeStopReason(trains),
	}
	highestClean := 0
	for _, train := range trains {
		clean := !train.Pressure && train.Sent > 0 && uint64(train.Received)*100 >= uint64(train.Sent)*95
		if clean {
			highestClean = max(highestClean, train.RateMbps)
		}
		if !clean {
			break
		}
	}
	if highestClean == 0 {
		return result, errExternalV2BulkPacketProbeRejected
	}
	result.SelectedMbps = min(
		externalV2BulkPacketCeilingWireMbps,
		max(externalV2BulkPacketMinimumWireMbps, highestClean*externalV2BulkPacketProbeSeedPercent/100),
	)
	return result, nil
}

func externalV2BulkPacketProbeStopReason(trains []externalV2BulkPacketProbeTrainResult) string {
	if len(trains) == 0 {
		return ""
	}
	last := trains[len(trains)-1]
	switch {
	case last.Pressure:
		return externalV2BulkPacketProbeStopPressure
	case last.Sent == 0 || uint64(last.Received)*100 < uint64(last.Sent)*95:
		return externalV2BulkPacketProbeStopDirty
	case len(trains) == len(externalV2BulkPacketProbeRatesMbps):
		return externalV2BulkPacketProbeStopLadderComplete
	default:
		return ""
	}
}

func externalV2BulkPacketProbeHighestCleanMbps(trains []externalV2BulkPacketProbeTrainResult) int {
	highestClean := 0
	for _, train := range trains {
		if train.Pressure || train.Sent == 0 || uint64(train.Received)*100 < uint64(train.Sent)*95 {
			break
		}
		highestClean = max(highestClean, train.RateMbps)
	}
	return highestClean
}

func emitExternalV2BulkPacketProbeDiagnostics(emitter *telemetry.Emitter, result externalV2BulkPacketProbeResult) {
	for trainIndex, train := range result.Trains {
		final := result.StopReason != "" && trainIndex == len(result.Trains)-1
		emitExternalV2Debug(emitter, fmt.Sprintf(
			"v2-bulk-probe-result=train:%d rate_mbps:%d sent:%d received:%d pressure:%t final:%t",
			trainIndex, train.RateMbps, train.Sent, train.Received, train.Pressure, final,
		))
	}
	emitExternalV2Debug(emitter, fmt.Sprintf(
		"v2-bulk-probe-selected=selected_mbps:%d highest_clean_mbps:%d trains:%d",
		result.SelectedMbps, externalV2BulkPacketProbeHighestCleanMbps(result.Trains), len(result.Trains),
	))
}

func selectExternalV2BulkPacketSenderProbe(trains []externalV2BulkPacketProbeTrainResult) (externalV2BulkPacketProbeResult, error) {
	result, err := externalV2BulkPacketSenderProbeSelector(trains)
	if err == errExternalV2BulkPacketProbeRejected {
		rejectTrain := len(result.Trains) - 1
		rejectRateMbps := 0
		if rejectTrain >= 0 {
			rejectRateMbps = result.Trains[rejectTrain].RateMbps
		}
		result.RejectStage = "selector"
		result.RejectTrain = rejectTrain
		result.RejectRateMbps = rejectRateMbps
		err = &externalV2BulkPacketProbeRejection{
			Stage: "selector", Train: rejectTrain, RateMbps: rejectRateMbps, cause: err,
		}
	}
	return finalizeExternalV2BulkPacketSenderProbe(result, err)
}

func finalizeExternalV2BulkPacketSenderProbe(
	result externalV2BulkPacketProbeResult,
	selectionErr error,
) (externalV2BulkPacketProbeResult, error) {
	if selectionErr != nil && !externalV2BulkPacketProbeOrdinaryRejection(selectionErr) {
		return result, selectionErr
	}
	value, configured := os.LookupEnv(externalV2BulkPacketProbeTestOutcomeEnv)
	return applyExternalV2BulkPacketSenderProbeTestOutcome(result, selectionErr, value, configured)
}

func applyExternalV2BulkPacketSenderProbeTestOutcome(
	result externalV2BulkPacketProbeResult,
	selectionErr error,
	value string,
	configured bool,
) (externalV2BulkPacketProbeResult, error) {
	if !configured {
		return result, selectionErr
	}
	if selectionErr != nil && !externalV2BulkPacketProbeOrdinaryRejection(selectionErr) {
		return result, selectionErr
	}
	if value != externalV2BulkPacketProbeTestOutcomeSenderReject {
		return result, &externalV2BulkPacketProbeTestOutcomeError{value: value}
	}
	result.SelectedMbps = 0
	return result, errors.Join(errExternalV2BulkPacketProbeRejected, errExternalV2BulkPacketProbeForcedSenderReject)
}

func externalV2BulkPacketProbeTestOutcomeInvalid(err error) bool {
	var outcomeErr *externalV2BulkPacketProbeTestOutcomeError
	return errors.As(err, &outcomeErr)
}

func externalV2BulkPacketProbeTestOutcome(err error) string {
	if errors.Is(err, errExternalV2BulkPacketProbeForcedSenderReject) {
		return externalV2BulkPacketProbeTestOutcomeSenderReject
	}
	return ""
}

type externalV2BulkPacketProbeEvent struct {
	header externalV2BulkPacketHeader
	prefix externalV2BulkPacketProbePrefix
}

func (s *externalV2BulkPacketSender) setInitialPaceMbps(mbps int) {
	mbps = min(externalV2BulkPacketCeilingWireMbps, max(externalV2BulkPacketMinimumWireMbps, mbps))
	s.initialPaceMbps = mbps
	s.currentPaceMbps.Store(int64(mbps))
	s.pacer.SetLimitAt(time.Now(), externalV2BulkPacketRateLimit(mbps))
	s.controller = newExternalV2BulkPacketController(mbps)
}

func externalV2BulkPacketProbeLossPPM(sent, received uint64) uint64 {
	if sent == 0 || received >= sent {
		return 0
	}
	return (sent - received) * 1_000_000 / sent
}

func setExternalV2BulkPacketProbeDiagnostics(diagnostics *externalDirectTransferDiagnostics, result externalV2BulkPacketProbeResult) {
	if diagnostics == nil {
		return
	}
	diagnostics.BulkProbeRejectStage = result.RejectStage
	diagnostics.BulkProbeRejectTrain = result.RejectTrain
	diagnostics.BulkProbeRejectRateMbps = result.RejectRateMbps
	diagnostics.BulkProbeStopReason = result.StopReason
	diagnostics.BulkHandoffLanes = result.HandoffDrain.Lanes
	diagnostics.BulkHandoffDrainedDatagrams = result.HandoffDrain.Datagrams
	if result.HandoffDrain.Duration > 0 {
		diagnostics.BulkHandoffDrainDurationMS = max(int64(1), result.HandoffDrain.Duration.Milliseconds())
	}
	diagnostics.BulkProbeSelectedMbps = result.SelectedMbps
	diagnostics.BulkProbeDurationMS = result.Duration.Milliseconds()
	diagnostics.BulkProbeTrains = uint32(len(result.Trains))
	for _, train := range result.Trains {
		diagnostics.BulkProbeSentDatagrams += uint64(train.Sent)
		diagnostics.BulkProbeReceivedDatagrams += uint64(train.Received)
		diagnostics.BulkProbePressure = diagnostics.BulkProbePressure || train.Pressure
	}
	diagnostics.BulkProbeLossPPM = externalV2BulkPacketProbeLossPPM(diagnostics.BulkProbeSentDatagrams, diagnostics.BulkProbeReceivedDatagrams)
}

func sendExternalV2BulkPacketProbe(
	ctx context.Context,
	sender *externalV2BulkPacketSender,
	coordinator *externalV2BulkDecisionCoordinator,
) (externalV2BulkPacketProbeResult, error) {
	started := time.Now()
	result := externalV2BulkPacketProbeResult{RunID: sender.runID}
	if _, _, err := externalV2BulkPacketProbeDirtyRate(externalV2BulkPacketProbeSender); err != nil {
		result.Duration = time.Since(started)
		return result, err
	}
	trains := make([]externalV2BulkPacketProbeTrainResult, 0, len(externalV2BulkPacketProbeRatesMbps))
	nextPacketIndex := uint32(1)
	for trainIndex, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		expected := externalV2BulkPacketProbeDatagramCount(rateMbps)
		train, nextIndex, err := sender.sendExternalV2BulkPacketProbeTrain(ctx, uint16(trainIndex), rateMbps, expected, nextPacketIndex)
		nextPacketIndex = nextIndex
		if err != nil {
			result.Duration = time.Since(started)
			result.Trains = append(result.Trains, trains...)
			return result, err
		}
		end := externalV2BulkControl{
			Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeEnd,
			ProbeRunID: sender.runID, Mode: externalV2BulkModeBulk,
			Probe: &externalV2BulkProbeControl{
				Train: trainIndex, RateMbps: rateMbps, Sent: train.Sent,
				Pressure: train.Pressure,
				Final:    train.Pressure || trainIndex == len(externalV2BulkPacketProbeRatesMbps)-1,
			},
		}
		measured, err := coordinator.sendProbeEndAndWaitResult(ctx, end)
		if err != nil {
			result.Duration = time.Since(started)
			result.Trains = append(result.Trains, trains...)
			return result, err
		}
		train.Received = measured.Probe.Received
		train.Pressure = measured.Probe.Pressure
		trains = append(trains, train)
		if measured.Probe.Final {
			break
		}
	}
	selected, err := selectExternalV2BulkPacketSenderProbe(trains)
	result = selected
	result.RunID = sender.runID
	result.Duration = time.Since(started)
	emitExternalV2BulkPacketProbeDiagnostics(coordinator.emitter, result)
	if err == nil {
		sender.setInitialPaceMbps(result.SelectedMbps)
	}
	return result, err
}

func (s *externalV2BulkPacketSender) sendExternalV2BulkPacketProbeTrain(
	ctx context.Context,
	train uint16,
	rateMbps int,
	expected uint32,
	nextIndex uint32,
) (externalV2BulkPacketProbeTrainResult, uint32, error) {
	result := externalV2BulkPacketProbeTrainResult{RateMbps: rateMbps, Sent: expected}
	pacer := rate.NewLimiter(externalV2BulkPacketRateLimit(rateMbps), externalV2BulkPacketPaceBurstBytes)
	payload := make([]byte, externalV2BulkPacketPayloadSize)
	batchSize := externalV2BulkPacketDataBatchSize
	for sequence := uint32(0); sequence < expected; {
		count := min(uint32(batchSize), expected-sequence)
		lane := int(sequence/uint32(batchSize)) % s.laneCount
		messages := make([]externalV2BulkPacketBatchMessage, 0, count)
		wireBytes := 0
		for range count {
			prefix := encodeExternalV2BulkPacketProbePrefix(externalV2BulkPacketProbePrefix{
				Train: train, Sequence: sequence, Expected: expected, RateMbps: uint32(rateMbps),
			})
			copy(payload[:externalV2BulkPacketProbePrefixSize], prefix[:])
			header := externalV2BulkPacketHeader{
				kind: externalV2BulkPacketProbeData, runID: s.runID, index: nextIndex, total: s.totalPackets,
			}
			var packet []byte
			var err error
			if s.auth.probe != nil {
				header.kind = externalV2BulkPacketProbeTaggedData
				packet, err = encodeExternalV2BulkPacketTaggedProbeData(s.auth, header, externalV2BulkPacketProbePrefix{
					Train: train, Sequence: sequence - 1, Expected: expected, RateMbps: uint32(rateMbps),
				})
			} else {
				packet, err = sealExternalV2BulkPacket(s.auth.control, header, payload)
			}
			if err != nil {
				return result, nextIndex, err
			}
			messages = append(messages, externalV2BulkPacketBatchMessage{Buffers: [][]byte{packet}, Addr: s.path.Addrs[lane]})
			wireBytes += externalV2BulkPacketIPv4WireBytes(len(packet))
			sequence++
			nextIndex++
		}
		if err := pacer.WaitN(ctx, wireBytes); err != nil {
			return result, nextIndex, err
		}
		if err := writeExternalV2BulkPacketProbeBatch(ctx, s.batchConns[lane], messages); err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				result.Pressure = true
				result.Sent = sequence - count
				break
			}
			return result, nextIndex, err
		}
	}
	return result, nextIndex, nil
}

func writeExternalV2BulkPacketProbeBatch(ctx context.Context, conn externalV2BulkPacketBatchConn, messages []externalV2BulkPacketBatchMessage) error {
	for len(messages) > 0 {
		written, err := conn.WriteBatch(ctx, messages)
		if written < 0 || written > len(messages) {
			return fmt.Errorf("probe batch wrote %d of %d datagrams", written, len(messages))
		}
		messages = messages[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func receiveExternalV2BulkPacketProbe(
	ctx context.Context,
	path externalV2BulkPacketPath,
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
	coordinator *externalV2BulkDecisionCoordinator,
) (externalV2BulkPacketProbeResult, error) {
	return receiveExternalV2BulkPacketProbeWithRunObserver(ctx, path, auth, totalPackets, coordinator, nil)
}

func receiveExternalV2BulkPacketProbeWithRunObserver(
	ctx context.Context,
	path externalV2BulkPacketPath,
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
	coordinator *externalV2BulkDecisionCoordinator,
	observeRunID func(uint64),
) (externalV2BulkPacketProbeResult, error) {
	started := time.Now()
	dirtyRateMbps, dirtyRateConfigured, err := externalV2BulkPacketProbeDirtyRate(externalV2BulkPacketProbeReceiver)
	if err != nil {
		return externalV2BulkPacketProbeResult{Duration: time.Since(started)}, err
	}
	if dirtyRateConfigured {
		emitExternalV2Debug(coordinator.emitter, fmt.Sprintf("v2-bulk-probe-test-dirty-rate-mbps=%d", dirtyRateMbps))
	}
	probeCtx, cancel := context.WithCancel(ctx)
	events := make(chan externalV2BulkPacketProbeEvent, externalV2BulkPacketDataQueue)
	errCh := make(chan error, len(path.Conns))
	done := startExternalV2BulkPacketProbeReaders(probeCtx, path, auth, totalPackets, events, errCh)
	trains, probeRunID, probeErr := receiveExternalV2BulkPacketProbeTrains(
		probeCtx, events, errCh, coordinator, dirtyRateMbps, observeRunID,
	)
	drain, cleanupErr := finishExternalV2BulkPacketReceiverProbe(ctx, path, cancel, done)
	if probeErr != nil {
		return externalV2BulkPacketProbeResult{
			RunID: probeRunID, Duration: time.Since(started), Trains: trains, HandoffDrain: drain,
		}, joinExternalV2BulkPacketProbeCleanup(probeErr, cleanupErr)
	}
	result, selectionErr := externalV2BulkPacketReceiverProbeSelector(trains)
	result.RunID = probeRunID
	result.Duration = time.Since(started)
	result.HandoffDrain = drain
	emitExternalV2BulkPacketProbeDiagnostics(coordinator.emitter, result)
	if cleanupErr == nil {
		return result, selectionErr
	}
	return result, errors.Join(selectionErr, cleanupErr)
}

func receiveExternalV2BulkPacketProbeTrains(
	ctx context.Context,
	events <-chan externalV2BulkPacketProbeEvent,
	errCh <-chan error,
	coordinator *externalV2BulkDecisionCoordinator,
	dirtyRateMbps int,
	observeRunID func(uint64),
) ([]externalV2BulkPacketProbeTrainResult, uint64, error) {
	trains := make([]externalV2BulkPacketProbeTrainResult, 0, len(externalV2BulkPacketProbeRatesMbps))
	var probeRunID uint64
	var previousEnd externalV2BulkControl
	var previousResult externalV2BulkControl
	for trainIndex, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		train, end, runID, err := receiveExternalV2BulkPacketReliableProbeTrain(
			ctx, events, errCh, coordinator, trainIndex, rateMbps, dirtyRateMbps, probeRunID,
			previousEnd, previousResult, observeRunID,
		)
		if runID != 0 {
			probeRunID = runID
		}
		if err != nil {
			return trains, probeRunID, err
		}
		trains = append(trains, train)
		resultControl := externalV2BulkPacketProbeResultControl(probeRunID, trainIndex, train)
		if err := coordinator.sendProbeResult(ctx, resultControl); err != nil {
			return trains, probeRunID, err
		}
		previousEnd, previousResult = end, resultControl
		if resultControl.Probe.Final {
			coordinator.respondToDuplicateProbeEnds(end, resultControl)
			break
		}
	}
	return trains, probeRunID, nil
}

func externalV2BulkPacketProbeResultControl(
	probeRunID uint64,
	trainIndex int,
	train externalV2BulkPacketProbeTrainResult,
) externalV2BulkControl {
	return externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseProbeResult,
		ProbeRunID: probeRunID, Mode: externalV2BulkModeBulk,
		Probe: &externalV2BulkProbeControl{
			Train: trainIndex, RateMbps: train.RateMbps, Sent: train.Sent, Received: train.Received,
			Pressure: train.Pressure,
			Final: train.Pressure || train.Sent == 0 ||
				uint64(train.Received)*100 < uint64(train.Sent)*95 ||
				trainIndex == len(externalV2BulkPacketProbeRatesMbps)-1,
		},
	}
}

func joinExternalV2BulkPacketProbeCleanup(err, cleanupErr error) error {
	if cleanupErr == nil {
		return err
	}
	return errors.Join(err, cleanupErr)
}

func receiveExternalV2BulkPacketReliableProbeTrain(
	ctx context.Context,
	events <-chan externalV2BulkPacketProbeEvent,
	errCh <-chan error,
	coordinator *externalV2BulkDecisionCoordinator,
	train int,
	rateMbps int,
	dirtyRateMbps int,
	runID uint64,
	previousEnd externalV2BulkControl,
	previousResult externalV2BulkControl,
	observeRunID func(uint64),
) (externalV2BulkPacketProbeTrainResult, externalV2BulkControl, uint64, error) {
	result := externalV2BulkPacketProbeTrainResult{RateMbps: rateMbps}
	seen := make(map[uint32]struct{}, externalV2BulkPacketProbeDatagramCount(rateMbps))
	end, runID, err := waitForExternalV2BulkPacketProbeBoundary(
		ctx, events, errCh, coordinator, train, rateMbps, dirtyRateMbps, runID,
		previousEnd, previousResult, observeRunID, seen,
	)
	if err != nil {
		return result, end, runID, err
	}
	result, runID, err = settleExternalV2BulkPacketProbeTrain(
		ctx, events, errCh, coordinator, train, rateMbps, dirtyRateMbps, runID,
		end, observeRunID, seen,
	)
	return result, end, runID, err
}

func waitForExternalV2BulkPacketProbeBoundary(
	ctx context.Context,
	events <-chan externalV2BulkPacketProbeEvent,
	errCh <-chan error,
	coordinator *externalV2BulkDecisionCoordinator,
	train int,
	rateMbps int,
	dirtyRateMbps int,
	runID uint64,
	previousEnd externalV2BulkControl,
	previousResult externalV2BulkControl,
	observeRunID func(uint64),
	seen map[uint32]struct{},
) (externalV2BulkControl, uint64, error) {
	retryCh, stopRetry := externalV2BulkPacketProbeRetry(previousResult, coordinator.retry)
	defer stopRetry()
	var end externalV2BulkControl
	for {
		select {
		case event := <-events:
			collectExternalV2BulkPacketProbeData(event, train, rateMbps, dirtyRateMbps, &runID, observeRunID, seen)
		case err := <-errCh:
			return end, runID, err
		case event, ok := <-coordinator.probeControlEvents():
			message, accepted, err := acceptExternalV2BulkPacketProbeBoundaryControl(
				ctx, coordinator, event, ok, train, rateMbps, previousEnd, previousResult, &runID, observeRunID,
			)
			if err != nil {
				return end, runID, err
			}
			if accepted {
				return message, runID, nil
			}
		case <-retryCh:
			if err := coordinator.sendProbeResult(ctx, previousResult); err != nil {
				return end, runID, err
			}
		case <-ctx.Done():
			return end, runID, externalV2BulkContextError(ctx)
		}
	}
}

func externalV2BulkPacketProbeRetry(
	previousResult externalV2BulkControl,
	retryInterval time.Duration,
) (<-chan time.Time, func()) {
	if previousResult.Probe == nil {
		return nil, func() {}
	}
	retry := time.NewTicker(retryInterval)
	return retry.C, retry.Stop
}

func acceptExternalV2BulkPacketProbeBoundaryControl(
	ctx context.Context,
	coordinator *externalV2BulkDecisionCoordinator,
	event externalV2BulkControlEvent,
	ok bool,
	train int,
	rateMbps int,
	previousEnd externalV2BulkControl,
	previousResult externalV2BulkControl,
	runID *uint64,
	observeRunID func(uint64),
) (externalV2BulkControl, bool, error) {
	message, err := externalV2BulkControlFromEvent(event, ok)
	if err != nil {
		return externalV2BulkControl{}, false, err
	}
	if previousEnd.Probe != nil && message.Probe != nil && message.Probe.Train == previousEnd.Probe.Train {
		if !externalV2BulkControlsEqual(message, previousEnd) {
			return externalV2BulkControl{}, false, fmt.Errorf("%w: contradictory probe boundary for train %d", errExternalV2BulkDecisionProtocol, message.Probe.Train)
		}
		return externalV2BulkControl{}, false, coordinator.sendProbeResult(ctx, previousResult)
	}
	if err := validateExternalV2BulkPacketProbeBoundary(message, train, rateMbps, runID, observeRunID); err != nil {
		return externalV2BulkControl{}, false, err
	}
	return message, true, nil
}

func settleExternalV2BulkPacketProbeTrain(
	ctx context.Context,
	events <-chan externalV2BulkPacketProbeEvent,
	errCh <-chan error,
	coordinator *externalV2BulkDecisionCoordinator,
	train int,
	rateMbps int,
	dirtyRateMbps int,
	runID uint64,
	end externalV2BulkControl,
	observeRunID func(uint64),
	seen map[uint32]struct{},
) (externalV2BulkPacketProbeTrainResult, uint64, error) {
	result := externalV2BulkPacketProbeTrainResult{RateMbps: rateMbps}
	settle := time.NewTimer(externalV2BulkPacketProbeSettle)
	defer settle.Stop()
	for {
		select {
		case event := <-events:
			collectExternalV2BulkPacketProbeData(event, train, rateMbps, dirtyRateMbps, &runID, observeRunID, seen)
		case err := <-errCh:
			return result, runID, err
		case event, ok := <-coordinator.probeControlEvents():
			message, err := externalV2BulkControlFromEvent(event, ok)
			if err != nil {
				return result, runID, err
			}
			if !externalV2BulkControlsEqual(message, end) {
				return result, runID, fmt.Errorf("%w: contradictory probe boundary for train %d", errExternalV2BulkDecisionProtocol, train)
			}
		case <-settle.C:
			result.Sent = end.Probe.Sent
			result.Received = uint32(len(seen))
			result.Pressure = end.Probe.Pressure
			if result.Received > result.Sent {
				return result, runID, fmt.Errorf("%w: received %d probe datagrams after %d sent", errExternalV2BulkDecisionProtocol, result.Received, result.Sent)
			}
			return result, runID, nil
		case <-ctx.Done():
			return result, runID, externalV2BulkContextError(ctx)
		}
	}
}

func validateExternalV2BulkPacketProbeBoundary(
	message externalV2BulkControl,
	train int,
	rateMbps int,
	runID *uint64,
	observeRunID func(uint64),
) error {
	if message.Phase != externalV2BulkPhaseProbeEnd || message.Probe == nil ||
		message.Probe.Train != train || message.Probe.RateMbps != rateMbps {
		return fmt.Errorf("%w: unexpected probe boundary", errExternalV2BulkDecisionProtocol)
	}
	if *runID == 0 {
		*runID = message.ProbeRunID
		if observeRunID != nil {
			observeRunID(*runID)
		}
	}
	if message.ProbeRunID != *runID {
		return fmt.Errorf("%w: probe boundary run ID %d does not match %d", errExternalV2BulkDecisionProtocol, message.ProbeRunID, *runID)
	}
	return nil
}

func collectExternalV2BulkPacketProbeData(
	event externalV2BulkPacketProbeEvent,
	train int,
	rateMbps int,
	dirtyRateMbps int,
	runID *uint64,
	observeRunID func(uint64),
	seen map[uint32]struct{},
) {
	if event.header.kind != externalV2BulkPacketProbeData && event.header.kind != externalV2BulkPacketProbeTaggedData ||
		int(event.prefix.Train) != train || event.prefix.RateMbps != uint32(rateMbps) {
		return
	}
	if *runID == 0 {
		*runID = event.header.runID
		if observeRunID != nil {
			observeRunID(*runID)
		}
	}
	if event.header.runID == *runID && (rateMbps != dirtyRateMbps || event.prefix.Sequence%10 != 0) {
		seen[event.prefix.Sequence] = struct{}{}
	}
}

func finishExternalV2BulkPacketReceiverProbe(
	ctx context.Context,
	path externalV2BulkPacketPath,
	cancel context.CancelFunc,
	done <-chan struct{},
) (externalV2BulkPacketHandoffDrainResult, error) {
	cancel()
	interruptErr := externalV2BulkPacketProbeInterruptReads(path, time.Now())
	<-done
	drain, drainErr := externalV2BulkPacketDrainForHandoff(ctx, path)
	return drain, newExternalV2BulkPacketProbeCleanupError(interruptErr, drainErr)
}

type externalV2BulkPacketProbeCleanupError struct {
	err error
}

func newExternalV2BulkPacketProbeCleanupError(errs ...error) error {
	err := errors.Join(errs...)
	if err == nil {
		return nil
	}
	return &externalV2BulkPacketProbeCleanupError{err: err}
}

func (e *externalV2BulkPacketProbeCleanupError) Error() string {
	return fmt.Sprintf("bulk packet probe cleanup: %v", e.err)
}

func (e *externalV2BulkPacketProbeCleanupError) Unwrap() error {
	return e.err
}

func externalV2BulkPacketProbeCleanupFailure(err error) error {
	var cleanup *externalV2BulkPacketProbeCleanupError
	if !errors.As(err, &cleanup) {
		return nil
	}
	return cleanup.err
}

func startExternalV2BulkPacketProbeReaders(
	ctx context.Context,
	path externalV2BulkPacketPath,
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
	events chan<- externalV2BulkPacketProbeEvent,
	errCh chan<- error,
) <-chan struct{} {
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(len(path.Conns))
	for _, conn := range path.Conns {
		go func(conn net.PacketConn) {
			defer readers.Done()
			readExternalV2BulkPacketProbeEvents(ctx, conn, auth, totalPackets, events, errCh)
		}(conn)
	}
	go func() {
		readers.Wait()
		close(done)
	}()
	return done
}

func readExternalV2BulkPacketProbeEvents(
	ctx context.Context,
	conn net.PacketConn,
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
	events chan<- externalV2BulkPacketProbeEvent,
	errCh chan<- error,
) {
	batch := newExternalV2BulkPacketBatchConn(conn)
	messages := newExternalV2BulkPacketReadMessages()
	for {
		count, err := batch.ReadBatch(ctx, messages)
		if err != nil {
			if ctx.Err() == nil {
				offerExternalV2BulkPacketRepairError(errCh, err)
			}
			return
		}
		for _, message := range messages[:count] {
			event, ok := decodeExternalV2BulkPacketProbeEvent(auth, totalPackets, message)
			if !ok {
				continue
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func decodeExternalV2BulkPacketProbeEvent(auth externalV2BulkPacketAuth, totalPackets uint32, message externalV2BulkPacketBatchMessage) (externalV2BulkPacketProbeEvent, bool) {
	if auth.probe != nil {
		if event, ok := decodeExternalV2BulkPacketTaggedProbeData(auth, totalPackets, message); ok {
			return event, true
		}
	}
	header, payload, ok := openExternalV2BulkPacket(auth.control, message.Buffers[0][:message.N])
	if !ok || header.total != totalPackets || header.kind != externalV2BulkPacketProbeData {
		return externalV2BulkPacketProbeEvent{}, false
	}
	prefix, ok := decodeExternalV2BulkPacketProbePrefix(payload)
	return externalV2BulkPacketProbeEvent{header: header, prefix: prefix}, ok
}

func encodeExternalV2BulkPacketTaggedProbeData(
	auth externalV2BulkPacketAuth,
	header externalV2BulkPacketHeader,
	prefix externalV2BulkPacketProbePrefix,
) ([]byte, error) {
	if auth.probe == nil {
		return nil, errors.New("bulk packet tagged probe auth is not configured")
	}
	if header.kind != externalV2BulkPacketProbeTaggedData || header.runID == 0 ||
		prefix.Flags != 0 || prefix.RateMbps > uint32(^uint16(0)) ||
		prefix.Expected != externalV2BulkPacketProbeDatagramCount(int(prefix.RateMbps)) {
		return nil, errors.New("bulk packet tagged probe fields are invalid")
	}
	packet := make([]byte, externalV2BulkPacketMaxSize)
	header.length = uint16(externalV2BulkPacketMaxSize - externalV2BulkPacketHeaderSize)
	fillExternalV2BulkPacketHeader(packet, header)
	payload := packet[externalV2BulkPacketHeaderSize:]
	input := externalV2BulkPacketProbeTagInput(header.runID, prefix)
	auth.probe.Encrypt(payload[:externalV2BulkPacketProbeTagSize], input[:])
	encoded := encodeExternalV2BulkPacketProbePrefix(prefix)
	copy(payload[externalV2BulkPacketProbeTagSize:], encoded[:])
	return packet, nil
}

func decodeExternalV2BulkPacketTaggedProbeData(
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
	message externalV2BulkPacketBatchMessage,
) (externalV2BulkPacketProbeEvent, bool) {
	if auth.probe == nil || message.N != externalV2BulkPacketMaxSize || len(message.Buffers) != 1 || len(message.Buffers[0]) < message.N {
		return externalV2BulkPacketProbeEvent{}, false
	}
	packet := message.Buffers[0][:message.N]
	header, ok := parseExternalV2BulkPacketHeader(packet)
	wantPayload := externalV2BulkPacketMaxSize - externalV2BulkPacketHeaderSize
	if !ok || header.kind != externalV2BulkPacketProbeTaggedData || header.runID == 0 || header.total != totalPackets ||
		int(header.length) != wantPayload || len(header.payload) != wantPayload {
		return externalV2BulkPacketProbeEvent{}, false
	}
	prefix, ok := decodeExternalV2BulkPacketProbePrefix(header.payload[externalV2BulkPacketProbeTagSize:])
	if !ok || prefix.Flags != 0 || prefix.RateMbps > uint32(^uint16(0)) ||
		prefix.Expected != externalV2BulkPacketProbeDatagramCount(int(prefix.RateMbps)) {
		return externalV2BulkPacketProbeEvent{}, false
	}
	input := externalV2BulkPacketProbeTagInput(header.runID, prefix)
	var tag [externalV2BulkPacketProbeTagSize]byte
	auth.probe.Encrypt(tag[:], input[:])
	if subtle.ConstantTimeCompare(tag[:], header.payload[:externalV2BulkPacketProbeTagSize]) != 1 {
		return externalV2BulkPacketProbeEvent{}, false
	}
	return externalV2BulkPacketProbeEvent{header: header, prefix: prefix}, true
}

func externalV2BulkPacketProbeTagInput(runID uint64, prefix externalV2BulkPacketProbePrefix) [externalV2BulkPacketProbeTagSize]byte {
	var input [externalV2BulkPacketProbeTagSize]byte
	binary.BigEndian.PutUint64(input[0:8], runID)
	binary.BigEndian.PutUint16(input[8:10], prefix.Train)
	binary.BigEndian.PutUint16(input[10:12], uint16(prefix.RateMbps))
	binary.BigEndian.PutUint32(input[12:16], prefix.Sequence)
	return input
}

func interruptExternalV2BulkPacketReads(path externalV2BulkPacketPath, deadline time.Time) error {
	var errs []error
	for lane, conn := range path.Conns {
		if err := conn.SetReadDeadline(deadline); err != nil {
			errs = append(errs, fmt.Errorf("bulk packet lane %d could not interrupt reads: %w", lane, err))
		}
	}
	return errors.Join(errs...)
}

var externalV2BulkPacketProbeInterruptReads = interruptExternalV2BulkPacketReads
