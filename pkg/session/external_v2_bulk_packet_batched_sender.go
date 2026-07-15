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
	"sync/atomic"
	"syscall"
	"time"
)

const (
	externalV2BulkPacketSlabPackets           = 768
	externalV2BulkPacketPreparedBatches       = 4
	externalV2BulkPacketMaximumWorkers        = 2
	externalV2BulkPacketMaximumDataLanes      = 4
	externalV2BulkPacketLaneQueueDepth        = 2
	externalV2BulkPacketBufferedReceiveWindow = 32 << 20
	externalV2BulkPacketDirectReceiveWindow   = 32 << 20
	externalV2BulkPacketFallbackReceiveWindow = 192 << 20
	externalV2BulkPacketAckNegotiationWait    = 100 * time.Millisecond
	externalV2BulkPacketPeerWindowPoll        = 2 * time.Millisecond
	// Forty-five full packets fit both the IPv4 UDP payload ceiling and the
	// 64 KiB pacer burst, so Linux can emit every full batch with one GSO send.
	externalV2BulkPacketDataBatchSize = 45
)

func externalV2BulkPacketDataLaneCount(conns, addrs int) int {
	return min(externalV2BulkPacketMaximumDataLanes, conns, addrs)
}

type externalV2BulkPacketSlab struct {
	input      []byte
	ciphertext []byte
	sealed     []byte
}

func newExternalV2BulkPacketSlab() *externalV2BulkPacketSlab {
	return &externalV2BulkPacketSlab{
		input:      make([]byte, externalV2BulkPacketSlabPackets*externalV2BulkPacketPayloadSize),
		ciphertext: make([]byte, externalV2BulkPacketGroupedGroupsPerSlab*(externalV2BulkPacketGroupedPlaintextBytes+16)),
		sealed:     make([]byte, externalV2BulkPacketSlabPackets*externalV2BulkPacketMaxSize),
	}
}

type externalV2BulkPacketSlabPool interface {
	Get() any
	Put(any)
}

type externalV2BulkPacketSlabLease struct {
	slab      *externalV2BulkPacketSlab
	pool      externalV2BulkPacketSlabPool
	remaining atomic.Int32
}

func (l *externalV2BulkPacketSlabLease) release() {
	if l != nil && l.remaining.Add(-1) == 0 {
		l.pool.Put(l.slab)
	}
}

type externalV2BulkPacketLaneJob struct {
	sequence int
	messages []externalV2BulkPacketBatchMessage
	lease    *externalV2BulkPacketSlabLease
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

type externalV2BulkPacketRepair struct {
	index uint32
	lane  int
}

func externalV2BulkPacketWorkerCount(cpus int) int {
	return max(1, min(externalV2BulkPacketMaximumWorkers, cpus))
}

func (s *externalV2BulkPacketSender) sendInitialPacketsBatched() error {
	if len(s.batchConns) != s.laneCount || s.laneCount == 0 {
		return errors.New("bulk packet batch connections are not configured")
	}
	if s.grouped {
		return s.sendGroupedInitialPacketsBatched()
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	slabPool := s.slabPool
	if slabPool == nil {
		slabPool = &sync.Pool{New: func() any { return newExternalV2BulkPacketSlab() }}
	}
	jobs := make(chan externalV2BulkPacketPrepareJob, externalV2BulkPacketMaximumWorkers)
	prepared := make(chan externalV2BulkPacketPreparedSlab, externalV2BulkPacketPreparedBatches)
	startExternalV2BulkPacketPrepareJobs(ctx, s.totalPackets, jobs)
	startExternalV2BulkPacketPrepareWorkers(ctx, s, jobs, prepared, slabPool)
	laneQueues, writerErrs, writersDone := startExternalV2BulkPacketLaneWriters(ctx, cancel, s)
	return s.consumeExternalV2BulkPacketPreparedSlabs(ctx, cancel, prepared, slabPool, laneQueues, writerErrs, writersDone)
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
	slabPool externalV2BulkPacketSlabPool,
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
	slabPool externalV2BulkPacketSlabPool,
) bool {
	slab := slabPool.Get().(*externalV2BulkPacketSlab)
	result := s.preparePacketSlab(ctx, job, slab)
	select {
	case prepared <- result:
		externalV2BulkPacketAtomicMaxUint32(&s.batchCryptoQueuePeak, uint32(len(prepared)))
		return result.err == nil
	case <-ctx.Done():
		slabPool.Put(slab)
		return false
	}
}

func startExternalV2BulkPacketLaneWriters(
	ctx context.Context,
	cancel context.CancelFunc,
	s *externalV2BulkPacketSender,
) ([]chan externalV2BulkPacketLaneJob, <-chan error, <-chan struct{}) {
	queues := make([]chan externalV2BulkPacketLaneJob, s.laneCount)
	errCh := make(chan error, 1)
	done := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(s.laneCount)
	for lane := range s.laneCount {
		queues[lane] = make(chan externalV2BulkPacketLaneJob, externalV2BulkPacketLaneQueueDepth)
		go func(lane int, jobs <-chan externalV2BulkPacketLaneJob) {
			defer writers.Done()
			for job := range jobs {
				var err error
				if ctx.Err() == nil {
					err = s.sendPreparedPacketLane(ctx, lane, job.messages)
				}
				job.lease.release()
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel()
				}
			}
		}(lane, queues[lane])
	}
	go func() {
		writers.Wait()
		close(errCh)
		close(done)
	}()
	return queues, errCh, done
}

func (s *externalV2BulkPacketSender) consumeExternalV2BulkPacketPreparedSlabs(
	ctx context.Context,
	cancel context.CancelFunc,
	prepared <-chan externalV2BulkPacketPreparedSlab,
	slabPool externalV2BulkPacketSlabPool,
	laneQueues []chan externalV2BulkPacketLaneJob,
	writerErrs <-chan error,
	writersDone <-chan struct{},
) error {
	nextSequence := 0
	pending := make(map[int]externalV2BulkPacketPreparedSlab, externalV2BulkPacketPreparedBatches)
	var firstErr error
	for result := range prepared {
		nextSequence, firstErr = s.consumeExternalV2BulkPacketPreparedSlab(ctx, result, nextSequence, firstErr, pending, cancel, slabPool, laneQueues)
	}
	releaseExternalV2BulkPacketPendingSlabs(pending, slabPool)
	for _, queue := range laneQueues {
		close(queue)
	}
	<-writersDone
	for err := range writerErrs {
		firstErr = errors.Join(firstErr, err)
	}
	return errors.Join(firstErr, ctx.Err())
}

func (s *externalV2BulkPacketSender) consumeExternalV2BulkPacketPreparedSlab(
	ctx context.Context,
	result externalV2BulkPacketPreparedSlab,
	nextSequence int,
	firstErr error,
	pending map[int]externalV2BulkPacketPreparedSlab,
	cancel context.CancelFunc,
	slabPool externalV2BulkPacketSlabPool,
	laneQueues []chan externalV2BulkPacketLaneJob,
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
	return s.sendExternalV2BulkPacketReadySlabs(ctx, nextSequence, firstErr, pending, cancel, slabPool, laneQueues)
}

func (s *externalV2BulkPacketSender) sendExternalV2BulkPacketReadySlabs(
	ctx context.Context,
	nextSequence int,
	firstErr error,
	pending map[int]externalV2BulkPacketPreparedSlab,
	cancel context.CancelFunc,
	slabPool externalV2BulkPacketSlabPool,
	laneQueues []chan externalV2BulkPacketLaneJob,
) (int, error) {
	for {
		current, ok := pending[nextSequence]
		if !ok {
			return nextSequence, firstErr
		}
		delete(pending, nextSequence)
		if err := s.dispatchPreparedPacketSlab(ctx, current, laneQueues, slabPool); err != nil {
			firstErr = errors.Join(firstErr, err)
			cancel()
		}
		nextSequence++
		if firstErr != nil {
			return nextSequence, firstErr
		}
	}
}

func releaseExternalV2BulkPacketPendingSlabs(pending map[int]externalV2BulkPacketPreparedSlab, slabPool externalV2BulkPacketSlabPool) {
	for _, result := range pending {
		slabPool.Put(result.slab)
	}
}

func (s *externalV2BulkPacketSender) dispatchPreparedPacketSlab(
	ctx context.Context,
	prepared externalV2BulkPacketPreparedSlab,
	laneQueues []chan externalV2BulkPacketLaneJob,
	slabPool externalV2BulkPacketSlabPool,
) error {
	jobCount := 0
	for _, messages := range prepared.byLane {
		if len(messages) > 0 {
			jobCount++
		}
	}
	if jobCount == 0 {
		slabPool.Put(prepared.slab)
		return nil
	}
	lease := &externalV2BulkPacketSlabLease{slab: prepared.slab, pool: slabPool}
	lease.remaining.Store(int32(jobCount))
	dispatched := 0
	for lane, messages := range prepared.byLane {
		if len(messages) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			releaseExternalV2BulkPacketUndispatchedJobs(lease, jobCount-dispatched)
			return err
		}
		job := externalV2BulkPacketLaneJob{sequence: prepared.sequence, messages: messages, lease: lease}
		if err := s.dispatchExternalV2BulkPacketLaneJob(ctx, laneQueues[lane], job); err != nil {
			releaseExternalV2BulkPacketUndispatchedJobs(lease, jobCount-dispatched)
			return ctx.Err()
		}
		dispatched++
	}
	return nil
}

func releaseExternalV2BulkPacketUndispatchedJobs(lease *externalV2BulkPacketSlabLease, count int) {
	for range count {
		lease.release()
	}
}

func (s *externalV2BulkPacketSender) dispatchExternalV2BulkPacketLaneJob(ctx context.Context, queue chan<- externalV2BulkPacketLaneJob, job externalV2BulkPacketLaneJob) error {
	select {
	case queue <- job:
		queueDepth := max(1, len(queue))
		externalV2BulkPacketAtomicMaxUint32(&s.batchLaneQueuePeak, uint32(queueDepth))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *externalV2BulkPacketSender) preparePacketSlab(ctx context.Context, job externalV2BulkPacketPrepareJob, slab *externalV2BulkPacketSlab) externalV2BulkPacketPreparedSlab {
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
		if err := ctx.Err(); err != nil {
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
			Buffers:      [][]byte{packet},
			Addr:         s.path.Addrs[lane],
			PayloadBytes: payloadEnd - payloadStart,
		})
	}
	return result
}

func (s *externalV2BulkPacketSender) sendRepairPacketsBatched(repairs []externalV2BulkPacketRepair) error {
	if len(repairs) == 0 {
		return nil
	}
	if len(s.batchConns) != s.laneCount || s.laneCount == 0 {
		return errors.New("bulk packet batch connections are not configured")
	}
	slabPool := s.slabPool
	if slabPool == nil {
		slabPool = &sync.Pool{New: func() any { return newExternalV2BulkPacketSlab() }}
	}
	slab := slabPool.Get().(*externalV2BulkPacketSlab)
	defer slabPool.Put(slab)

	byLane, err := s.prepareRepairPacketSlab(s.ctx, repairs, slab)
	if err != nil {
		return err
	}
	for lane, messages := range byLane {
		if err := s.sendPreparedRepairLane(s.ctx, lane, messages); err != nil {
			return err
		}
	}
	return nil
}

func (s *externalV2BulkPacketSender) prepareRepairPacketSlab(
	ctx context.Context,
	repairs []externalV2BulkPacketRepair,
	slab *externalV2BulkPacketSlab,
) ([][]externalV2BulkPacketBatchMessage, error) {
	if s.grouped {
		return s.prepareGroupedRepairPacketSlab(ctx, repairs, slab)
	}
	if len(repairs) > externalV2BulkPacketSlabPackets {
		return nil, fmt.Errorf("bulk packet repair batch contains %d packets, maximum %d", len(repairs), externalV2BulkPacketSlabPackets)
	}
	byLane := make([][]externalV2BulkPacketBatchMessage, s.laneCount)
	for slot, repair := range repairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		payloadLength := externalV2BulkPacketPayloadLength(repair.index, s.src.PayloadSize)
		payloadStart := slot * externalV2BulkPacketPayloadSize
		payload := slab.input[payloadStart : payloadStart+payloadLength]
		offset := int64(repair.index) * externalV2BulkPacketPayloadSize
		n, readErr := s.src.Payload.ReadAt(payload, offset)
		if err := externalV2BlockReadError(readErr, n, payloadLength, offset+int64(n), s.src.PayloadSize); err != nil {
			return nil, err
		}
		packetStart := slot * externalV2BulkPacketMaxSize
		packet, err := sealExternalV2BulkPacketInto(s.auth.data, slab.sealed[packetStart:packetStart:packetStart+externalV2BulkPacketMaxSize], externalV2BulkPacketHeader{
			kind:  externalV2BulkPacketData,
			runID: s.runID,
			index: repair.index,
			total: s.totalPackets,
		}, payload[:n])
		if err != nil {
			return nil, err
		}
		byLane[repair.lane] = append(byLane[repair.lane], externalV2BulkPacketBatchMessage{
			Buffers:      [][]byte{packet},
			Addr:         s.path.Addrs[repair.lane],
			PayloadBytes: n,
		})
	}
	return byLane, nil
}

func (s *externalV2BulkPacketSender) sendPreparedRepairLane(ctx context.Context, lane int, messages []externalV2BulkPacketBatchMessage) error {
	for len(messages) > 0 {
		batchSize := min(externalV2BulkPacketDataBatchSize, len(messages))
		batch := messages[:batchSize]
		wireBytes := 0
		payloadBytes := 0
		for _, message := range batch {
			packetBytes := externalV2BulkPacketMessageLength(message.Buffers)
			wireBytes += externalV2BulkPacketIPv4WireBytes(packetBytes)
			payloadBytes += externalV2BulkPacketMessagePayloadBytes(message, s.auth.data.Overhead())
		}
		if err := s.waitForBatchPacingContext(ctx, wireBytes); err != nil {
			return err
		}
		if err := s.writeDataBatchContext(ctx, lane, batch); err != nil {
			return err
		}
		s.sentPackets.Add(uint64(len(batch)))
		s.sentPayload.Add(int64(payloadBytes))
		s.repairWireBytes.Add(int64(wireBytes))
		s.repairPackets.Add(int64(len(batch)))
		s.repairPayloadBytes.Add(int64(payloadBytes))
		if s.metrics != nil {
			s.metrics.RecordDirectPacketSend(int64(payloadBytes), time.Now())
		}
		messages = messages[batchSize:]
	}
	return nil
}

func (s *externalV2BulkPacketSender) sendPreparedPacketLane(ctx context.Context, lane int, messages []externalV2BulkPacketBatchMessage) error {
	for len(messages) > 0 {
		batchSize := min(externalV2BulkPacketDataBatchSize, len(messages))
		batch := messages[:batchSize]
		wireBytes := 0
		payloadBytes := 0
		for _, message := range batch {
			packetBytes := externalV2BulkPacketMessageLength(message.Buffers)
			wireBytes += externalV2BulkPacketIPv4WireBytes(packetBytes)
			payloadBytes += externalV2BulkPacketMessagePayloadBytes(message, s.auth.data.Overhead())
		}
		if err := s.waitForPeerReceiveWindow(ctx, int64(payloadBytes)); err != nil {
			return err
		}
		if err := s.waitForBatchPacingContext(ctx, wireBytes); err != nil {
			return err
		}
		if err := s.writeDataBatchContext(ctx, lane, batch); err != nil {
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
	return nil
}

func externalV2BulkPacketMessagePayloadBytes(message externalV2BulkPacketBatchMessage, overhead int) int {
	if message.PayloadBytes > 0 {
		return message.PayloadBytes
	}
	return externalV2BulkPacketMessageLength(message.Buffers) - externalV2BulkPacketHeaderSize - overhead
}

func (s *externalV2BulkPacketSender) waitForPeerReceiveWindow(ctx context.Context, nextPayloadBytes int64) error {
	if s.metrics == nil {
		return nil
	}
	for {
		peerBytes, window := s.peerReceiveWindow(time.Now())
		if s.primaryPayloadBytes.Load()+nextPayloadBytes <= peerBytes+window {
			return nil
		}
		s.receiveWindowBlocked.Store(true)
		timer := time.NewTimer(externalV2BulkPacketPeerWindowPoll)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (s *externalV2BulkPacketSender) peerReceiveWindow(now time.Time) (int64, int64) {
	if bytes, window, ok := s.receiveAck.snapshot(); ok {
		return bytes, window
	}
	peer := s.metrics.PeerProgressSnapshot()
	if !s.ackNegotiationUntil.IsZero() && now.Before(s.ackNegotiationUntil) {
		return peer.BytesReceived, externalV2BulkPacketBufferedReceiveWindow
	}
	return peer.BytesReceived, externalV2BulkPacketFallbackReceiveWindow
}

func (s *externalV2BulkPacketSender) waitForBatchPacingContext(ctx context.Context, wireBytes int) error {
	for wireBytes > 0 {
		charge := min(wireBytes, externalV2BulkPacketPaceBurstBytes)
		if err := s.pacer.WaitN(ctx, charge); err != nil {
			return err
		}
		wireBytes -= charge
	}
	return nil
}

func (s *externalV2BulkPacketSender) writeDataBatch(lane int, messages []externalV2BulkPacketBatchMessage) error {
	return s.writeDataBatchContext(s.ctx, lane, messages)
}

func (s *externalV2BulkPacketSender) writeDataBatchContext(ctx context.Context, lane int, messages []externalV2BulkPacketBatchMessage) error {
	consecutive := int64(0)
	for len(messages) > 0 {
		written, err := s.batchConns[lane].WriteBatch(ctx, messages)
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
		case <-ctx.Done():
			timer.Stop()
			s.localENOBUFSWaitNanos.Add(time.Since(waitStarted).Nanoseconds())
			return ctx.Err()
		}
	}
	return nil
}
