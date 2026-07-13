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
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

var errExternalV2BulkPacketProbeRejected = errors.New("bulk packet capacity probe rejected")

var externalV2BulkPacketProbeRatesMbps = [...]int{128, 512, 1000, 1600, 2000, 2200, 2400}

var externalV2BulkPacketProbeSelector = selectExternalV2BulkPacketProbe

const (
	externalV2BulkPacketProbeDuration    = 50 * time.Millisecond
	externalV2BulkPacketProbeMaxBytes    = 16 << 20
	externalV2BulkPacketProbeAckTimeout  = 250 * time.Millisecond
	externalV2BulkPacketProbeSettle      = 10 * time.Millisecond
	externalV2BulkPacketProbeEndRepeats  = 3
	externalV2BulkPacketProbeAckRepeats  = 3
	externalV2BulkPacketProbePrefixSize  = 16
	externalV2BulkPacketProbePressure    = uint16(1)
	externalV2BulkPacketProbeTagSize     = 16
	externalV2BulkPacketProbeSeedPercent = 90
)

type externalV2BulkPacketProbeTrainResult struct {
	RateMbps int
	Sent     uint32
	Received uint32
	Pressure bool
}

type externalV2BulkPacketProbeResult struct {
	RunID        uint64
	SelectedMbps int
	Duration     time.Duration
	Trains       []externalV2BulkPacketProbeTrainResult
}

type externalV2BulkPacketProbePrefix struct {
	Train    uint16
	Flags    uint16
	Sequence uint32
	Expected uint32
	RateMbps uint32
}

func (p externalV2BulkPacketProbePrefix) pressure() bool {
	return p.Flags&externalV2BulkPacketProbePressure != 0
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
	result := externalV2BulkPacketProbeResult{Trains: append([]externalV2BulkPacketProbeTrainResult(nil), trains...)}
	highestClean := 0
	for _, train := range trains {
		if !train.Pressure && train.Sent > 0 && uint64(train.Received)*100 >= uint64(train.Sent)*95 {
			highestClean = max(highestClean, train.RateMbps)
		}
		if train.Pressure {
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

type externalV2BulkPacketProbeAckFrame struct {
	header externalV2BulkPacketHeader
	prefix externalV2BulkPacketProbePrefix
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
	ackCh <-chan externalV2BulkPacketProbeAckFrame,
) (externalV2BulkPacketProbeResult, error) {
	started := time.Now()
	trains := make([]externalV2BulkPacketProbeTrainResult, 0, len(externalV2BulkPacketProbeRatesMbps))
	nextPacketIndex := uint32(1)
	for trainIndex, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		expected := externalV2BulkPacketProbeDatagramCount(rateMbps)
		train, nextIndex, err := sender.sendExternalV2BulkPacketProbeTrain(ctx, uint16(trainIndex), rateMbps, expected, nextPacketIndex)
		nextPacketIndex = nextIndex
		if err != nil {
			return externalV2BulkPacketProbeResult{Duration: time.Since(started), Trains: trains}, errors.Join(errExternalV2BulkPacketProbeRejected, err)
		}
		ack, err := waitExternalV2BulkPacketProbeAck(ctx, ackCh, sender.runID, uint16(trainIndex), rateMbps)
		if err != nil {
			return externalV2BulkPacketProbeResult{Duration: time.Since(started), Trains: trains}, errors.Join(errExternalV2BulkPacketProbeRejected, err)
		}
		train.Received = ack.prefix.Sequence
		train.Pressure = train.Pressure || ack.prefix.pressure()
		trains = append(trains, train)
		if train.Pressure {
			break
		}
	}
	result, err := externalV2BulkPacketProbeSelector(trains)
	result.RunID = sender.runID
	result.Duration = time.Since(started)
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
	flags := uint16(0)
	if result.Pressure {
		flags = externalV2BulkPacketProbePressure
	}
	for repeat := range externalV2BulkPacketProbeEndRepeats {
		prefix := encodeExternalV2BulkPacketProbePrefix(externalV2BulkPacketProbePrefix{
			Train: train, Flags: flags, Sequence: uint32(repeat), Expected: result.Sent, RateMbps: uint32(rateMbps),
		})
		if err := writeExternalV2BulkPacketControl(s.path, s.auth, externalV2BulkPacketHeader{
			kind: externalV2BulkPacketProbeEnd, runID: s.runID, index: nextIndex, total: s.totalPackets,
		}, prefix[:]); err != nil {
			return result, nextIndex, err
		}
		nextIndex++
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

func waitExternalV2BulkPacketProbeAck(ctx context.Context, ackCh <-chan externalV2BulkPacketProbeAckFrame, runID uint64, train uint16, rateMbps int) (externalV2BulkPacketProbeAckFrame, error) {
	timer := time.NewTimer(externalV2BulkPacketProbeAckTimeout)
	defer timer.Stop()
	for {
		select {
		case ack := <-ackCh:
			if ack.header.runID == runID && ack.prefix.Train == train && ack.prefix.RateMbps == uint32(rateMbps) {
				return ack, nil
			}
		case <-timer.C:
			return externalV2BulkPacketProbeAckFrame{}, errors.New("bulk packet capacity probe acknowledgement timed out")
		case <-ctx.Done():
			return externalV2BulkPacketProbeAckFrame{}, ctx.Err()
		}
	}
}

func receiveExternalV2BulkPacketProbe(
	ctx context.Context,
	path externalV2BulkPacketPath,
	auth externalV2BulkPacketAuth,
	totalPackets uint32,
) (externalV2BulkPacketProbeResult, error) {
	started := time.Now()
	probeCtx, cancel := context.WithCancel(ctx)
	events := make(chan externalV2BulkPacketProbeEvent, externalV2BulkPacketDataQueue)
	errCh := make(chan error, len(path.Conns))
	done := startExternalV2BulkPacketProbeReaders(probeCtx, path, auth, totalPackets, events, errCh)
	trains := make([]externalV2BulkPacketProbeTrainResult, 0, len(externalV2BulkPacketProbeRatesMbps))
	var probeRunID uint64
	var ackIndex uint32 = 1
	var finalPrefix externalV2BulkPacketProbePrefix
	for trainIndex, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		train, runID, err := receiveExternalV2BulkPacketProbeTrain(probeCtx, events, errCh, uint16(trainIndex), rateMbps, probeRunID)
		if err != nil {
			cancel()
			_ = interruptExternalV2BulkPacketReads(path, time.Now())
			<-done
			_ = clearExternalV2BulkPacketDeadlines(path)
			return externalV2BulkPacketProbeResult{Duration: time.Since(started), Trains: trains}, errors.Join(errExternalV2BulkPacketProbeRejected, err)
		}
		probeRunID = runID
		trains = append(trains, train)
		finalPrefix = externalV2BulkPacketProbePrefix{
			Train: uint16(trainIndex), Sequence: train.Received, Expected: train.Sent, RateMbps: uint32(rateMbps),
		}
		if train.Pressure {
			finalPrefix.Flags = externalV2BulkPacketProbePressure
		}
		final := train.Pressure || trainIndex == len(externalV2BulkPacketProbeRatesMbps)-1
		if !final {
			if err := sendExternalV2BulkPacketProbeAck(path, auth, probeRunID, totalPackets, &ackIndex, finalPrefix); err != nil {
				cancel()
				_ = interruptExternalV2BulkPacketReads(path, time.Now())
				<-done
				_ = clearExternalV2BulkPacketDeadlines(path)
				return externalV2BulkPacketProbeResult{Duration: time.Since(started), Trains: trains}, err
			}
			continue
		}
		break
	}
	cancel()
	interruptErr := interruptExternalV2BulkPacketReads(path, time.Now())
	<-done
	cleanupErr := clearExternalV2BulkPacketDeadlines(path)
	ackErr := sendExternalV2BulkPacketProbeAck(path, auth, probeRunID, totalPackets, &ackIndex, finalPrefix)
	result, selectionErr := externalV2BulkPacketProbeSelector(trains)
	result.RunID = probeRunID
	result.Duration = time.Since(started)
	return result, errors.Join(selectionErr, interruptErr, cleanupErr, ackErr)
}

func receiveExternalV2BulkPacketProbeTrain(
	ctx context.Context,
	events <-chan externalV2BulkPacketProbeEvent,
	errCh <-chan error,
	train uint16,
	rateMbps int,
	runID uint64,
) (externalV2BulkPacketProbeTrainResult, uint64, error) {
	result := externalV2BulkPacketProbeTrainResult{RateMbps: rateMbps}
	seen := make(map[uint32]struct{}, externalV2BulkPacketProbeDatagramCount(rateMbps))
	var settle *time.Timer
	var settleCh <-chan time.Time
	defer func() {
		if settle != nil {
			settle.Stop()
		}
	}()
	for {
		select {
		case event := <-events:
			if externalV2BulkPacketProbeEventMatchesTrain(event, train, rateMbps, &runID) {
				end := applyExternalV2BulkPacketProbeEvent(event, seen, &result)
				if end && settle == nil {
					settle = time.NewTimer(externalV2BulkPacketProbeSettle)
					settleCh = settle.C
				}
			}
		case err := <-errCh:
			return result, runID, err
		case <-settleCh:
			result.Received = uint32(len(seen))
			return result, runID, nil
		case <-ctx.Done():
			return result, runID, ctx.Err()
		}
	}
}

func externalV2BulkPacketProbeEventMatchesTrain(event externalV2BulkPacketProbeEvent, train uint16, rateMbps int, runID *uint64) bool {
	if event.prefix.Train != train || event.prefix.RateMbps != uint32(rateMbps) {
		return false
	}
	if *runID == 0 {
		*runID = event.header.runID
	}
	return event.header.runID == *runID
}

func applyExternalV2BulkPacketProbeEvent(event externalV2BulkPacketProbeEvent, seen map[uint32]struct{}, result *externalV2BulkPacketProbeTrainResult) bool {
	switch event.header.kind {
	case externalV2BulkPacketProbeData, externalV2BulkPacketProbeTaggedData:
		seen[event.prefix.Sequence] = struct{}{}
		return false
	case externalV2BulkPacketProbeEnd:
		result.Sent = event.prefix.Expected
		result.Pressure = event.prefix.pressure()
		return true
	default:
		return false
	}
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
	if !ok || header.total != totalPackets || (header.kind != externalV2BulkPacketProbeData && header.kind != externalV2BulkPacketProbeEnd) {
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

func sendExternalV2BulkPacketProbeAck(
	path externalV2BulkPacketPath,
	auth externalV2BulkPacketAuth,
	runID uint64,
	totalPackets uint32,
	ackIndex *uint32,
	prefix externalV2BulkPacketProbePrefix,
) error {
	encoded := encodeExternalV2BulkPacketProbePrefix(prefix)
	for range externalV2BulkPacketProbeAckRepeats {
		if err := writeExternalV2BulkPacketControl(path, auth, externalV2BulkPacketHeader{
			kind: externalV2BulkPacketProbeAck, runID: runID, index: *ackIndex, total: totalPackets,
		}, encoded[:]); err != nil {
			return err
		}
		*ackIndex = *ackIndex + 1
	}
	return nil
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
