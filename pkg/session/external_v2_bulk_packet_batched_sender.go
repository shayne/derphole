// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const (
	externalV2BulkPacketSlabPackets     = 768
	externalV2BulkPacketPreparedBatches = 4
	externalV2BulkPacketMaximumWorkers  = 2
	// Forty-five full packets fit both the IPv4 UDP payload ceiling and the
	// 64 KiB pacer burst, so Linux can emit every full batch with one GSO send.
	externalV2BulkPacketDataBatchSize = 45
)

type externalV2BulkPacketSlab struct {
	input  []byte
	sealed []byte
}

type externalV2BulkPacketPrepareJob struct {
	sequence int
	start    uint32
	count    uint32
}

type externalV2BulkPacketPreparedSlab struct {
	sequence int
	byLane   [][]externalV2BulkPacketBatchMessage
	slab     *externalV2BulkPacketSlab
	err      error
}

func externalV2BulkPacketWorkerCount(cpus int) int {
	return max(1, min(externalV2BulkPacketMaximumWorkers, cpus))
}

func (s *externalV2BulkPacketSender) sendInitialPacketsBatched() error {
	if len(s.batchConns) != s.laneCount || s.laneCount == 0 {
		return errors.New("bulk packet batch connections are not configured")
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	slabPool := &sync.Pool{New: func() any {
		return &externalV2BulkPacketSlab{
			input:  make([]byte, externalV2BulkPacketSlabPackets*externalV2BulkPacketPayloadSize),
			sealed: make([]byte, externalV2BulkPacketSlabPackets*externalV2BulkPacketMaxSize),
		}
	}}
	jobs := make(chan externalV2BulkPacketPrepareJob, externalV2BulkPacketMaximumWorkers)
	prepared := make(chan externalV2BulkPacketPreparedSlab, externalV2BulkPacketPreparedBatches)
	startExternalV2BulkPacketPrepareJobs(ctx, s.totalPackets, jobs)
	startExternalV2BulkPacketPrepareWorkers(ctx, s, jobs, prepared, slabPool)
	return s.consumeExternalV2BulkPacketPreparedSlabs(ctx, cancel, prepared, slabPool)
}

func startExternalV2BulkPacketPrepareJobs(ctx context.Context, totalPackets uint32, jobs chan<- externalV2BulkPacketPrepareJob) {
	go func() {
		defer close(jobs)
		sequence := 0
		for start := uint32(0); start < totalPackets; start += externalV2BulkPacketSlabPackets {
			job := externalV2BulkPacketPrepareJob{
				sequence: sequence,
				start:    start,
				count:    min(uint32(externalV2BulkPacketSlabPackets), totalPackets-start),
			}
			select {
			case jobs <- job:
				sequence++
			case <-ctx.Done():
				return
			}
		}
	}()
}

func startExternalV2BulkPacketPrepareWorkers(
	ctx context.Context,
	s *externalV2BulkPacketSender,
	jobs <-chan externalV2BulkPacketPrepareJob,
	prepared chan<- externalV2BulkPacketPreparedSlab,
	slabPool *sync.Pool,
) {
	workerCount := externalV2BulkPacketWorkerCount(runtime.GOMAXPROCS(0))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				if !s.prepareAndOfferExternalV2BulkPacketSlab(ctx, job, prepared, slabPool) {
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(prepared)
	}()
}

func (s *externalV2BulkPacketSender) prepareAndOfferExternalV2BulkPacketSlab(
	ctx context.Context,
	job externalV2BulkPacketPrepareJob,
	prepared chan<- externalV2BulkPacketPreparedSlab,
	slabPool *sync.Pool,
) bool {
	slab := slabPool.Get().(*externalV2BulkPacketSlab)
	result := s.preparePacketSlab(job, slab)
	select {
	case prepared <- result:
		externalV2BulkPacketAtomicMaxUint32(&s.batchCryptoQueuePeak, uint32(len(prepared)))
		return result.err == nil
	case <-ctx.Done():
		slabPool.Put(slab)
		return false
	}
}

func (s *externalV2BulkPacketSender) consumeExternalV2BulkPacketPreparedSlabs(
	ctx context.Context,
	cancel context.CancelFunc,
	prepared <-chan externalV2BulkPacketPreparedSlab,
	slabPool *sync.Pool,
) error {
	nextSequence := 0
	pending := make(map[int]externalV2BulkPacketPreparedSlab, externalV2BulkPacketPreparedBatches)
	var firstErr error
	for result := range prepared {
		nextSequence, firstErr = s.consumeExternalV2BulkPacketPreparedSlab(result, nextSequence, firstErr, pending, cancel, slabPool)
	}
	releaseExternalV2BulkPacketPendingSlabs(pending, slabPool)
	return errors.Join(firstErr, ctx.Err())
}

func (s *externalV2BulkPacketSender) consumeExternalV2BulkPacketPreparedSlab(
	result externalV2BulkPacketPreparedSlab,
	nextSequence int,
	firstErr error,
	pending map[int]externalV2BulkPacketPreparedSlab,
	cancel context.CancelFunc,
	slabPool *sync.Pool,
) (int, error) {
	if result.err != nil {
		cancel()
		slabPool.Put(result.slab)
		return nextSequence, errors.Join(firstErr, result.err)
	}
	if firstErr != nil {
		slabPool.Put(result.slab)
		return nextSequence, firstErr
	}
	pending[result.sequence] = result
	return s.sendExternalV2BulkPacketReadySlabs(nextSequence, firstErr, pending, cancel, slabPool)
}

func (s *externalV2BulkPacketSender) sendExternalV2BulkPacketReadySlabs(
	nextSequence int,
	firstErr error,
	pending map[int]externalV2BulkPacketPreparedSlab,
	cancel context.CancelFunc,
	slabPool *sync.Pool,
) (int, error) {
	for {
		current, ok := pending[nextSequence]
		if !ok {
			return nextSequence, firstErr
		}
		delete(pending, nextSequence)
		if err := s.sendPreparedPacketSlab(current); err != nil {
			firstErr = errors.Join(firstErr, err)
			cancel()
		}
		slabPool.Put(current.slab)
		nextSequence++
		if firstErr != nil {
			return nextSequence, firstErr
		}
	}
}

func releaseExternalV2BulkPacketPendingSlabs(pending map[int]externalV2BulkPacketPreparedSlab, slabPool *sync.Pool) {
	for _, result := range pending {
		slabPool.Put(result.slab)
	}
}

func (s *externalV2BulkPacketSender) preparePacketSlab(job externalV2BulkPacketPrepareJob, slab *externalV2BulkPacketSlab) externalV2BulkPacketPreparedSlab {
	result := externalV2BulkPacketPreparedSlab{
		sequence: job.sequence,
		byLane:   make([][]externalV2BulkPacketBatchMessage, s.laneCount),
		slab:     slab,
	}
	offset := int64(job.start) * externalV2BulkPacketPayloadSize
	want := min(int64(job.count)*externalV2BulkPacketPayloadSize, s.src.PayloadSize-offset)
	input := slab.input[:want]
	n, readErr := s.src.Payload.ReadAt(input, offset)
	if err := externalV2BlockReadError(readErr, n, int(want), offset+int64(n), s.src.PayloadSize); err != nil {
		result.err = err
		return result
	}
	input = input[:n]
	for localIndex := uint32(0); localIndex < job.count; localIndex++ {
		if err := s.ctx.Err(); err != nil {
			result.err = err
			return result
		}
		index := job.start + localIndex
		payloadStart := int(localIndex) * externalV2BulkPacketPayloadSize
		payloadEnd := min(len(input), payloadStart+externalV2BulkPacketPayloadSize)
		packetStart := int(localIndex) * externalV2BulkPacketMaxSize
		packet, err := sealExternalV2BulkPacketInto(s.auth.data, slab.sealed[packetStart:packetStart:packetStart+externalV2BulkPacketMaxSize], externalV2BulkPacketHeader{
			kind:  externalV2BulkPacketData,
			runID: s.runID,
			index: index,
			total: s.totalPackets,
		}, input[payloadStart:payloadEnd])
		if err != nil {
			result.err = err
			return result
		}
		lane := externalV2BulkPacketPrimaryLane(index, s.laneCount)
		result.byLane[lane] = append(result.byLane[lane], externalV2BulkPacketBatchMessage{
			Buffers: [][]byte{packet},
			Addr:    s.path.Addrs[lane],
		})
	}
	return result
}

func (s *externalV2BulkPacketSender) sendPreparedPacketSlab(prepared externalV2BulkPacketPreparedSlab) error {
	for lane, messages := range prepared.byLane {
		for len(messages) > 0 {
			batchSize := min(externalV2BulkPacketDataBatchSize, len(messages))
			batch := messages[:batchSize]
			wireBytes := 0
			payloadBytes := 0
			for _, message := range batch {
				packetBytes := externalV2BulkPacketMessageLength(message.Buffers)
				wireBytes += externalV2BulkPacketIPv4WireBytes(packetBytes)
				payloadBytes += packetBytes - externalV2BulkPacketHeaderSize - s.auth.data.Overhead()
			}
			if err := s.waitForBatchPacing(wireBytes); err != nil {
				return err
			}
			if err := s.writeDataBatch(lane, batch); err != nil {
				return err
			}
			s.sentPackets.Add(uint64(len(batch)))
			s.sentPayload.Add(int64(payloadBytes))
			s.primaryWireBytes.Add(int64(wireBytes))
			s.primaryPayloadBytes.Add(int64(payloadBytes))
			if s.metrics != nil {
				s.metrics.RecordDirectPacketSend(int64(payloadBytes), time.Now())
			}
			messages = messages[batchSize:]
		}
	}
	return nil
}

func (s *externalV2BulkPacketSender) waitForBatchPacing(wireBytes int) error {
	for wireBytes > 0 {
		charge := min(wireBytes, externalV2BulkPacketPaceBurstBytes)
		if err := s.pacer.WaitN(s.ctx, charge); err != nil {
			return err
		}
		wireBytes -= charge
	}
	return nil
}

func (s *externalV2BulkPacketSender) writeDataBatch(lane int, messages []externalV2BulkPacketBatchMessage) error {
	consecutive := int64(0)
	for len(messages) > 0 {
		written, err := s.batchConns[lane].WriteBatch(s.ctx, messages)
		if written < 0 || written > len(messages) {
			return fmt.Errorf("bulk packet batch wrote %d of %d messages", written, len(messages))
		}
		messages = messages[written:]
		if !errors.Is(err, syscall.ENOBUFS) {
			if err != nil {
				return err
			}
			if written == 0 && len(messages) > 0 {
				return errExternalV2BulkPacketBatchNoProgress
			}
			consecutive = 0
			continue
		}

		consecutive++
		s.localENOBUFSRetries.Add(1)
		updateExternalV2BulkPacketAtomicMax(&s.localENOBUFSMaxConsecutive, consecutive)
		waitStarted := time.Now()
		timer := time.NewTimer(externalV2BulkPacketWriteRetryDelay)
		select {
		case <-timer.C:
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
		case <-s.ctx.Done():
			timer.Stop()
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
			return s.ctx.Err()
		}
	}
	return nil
}
