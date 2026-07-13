// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	externalV2BulkPacketGroupedDecryptQueue = 544
	externalV2BulkPacketGroupedResultBatch  = 32
)

func startExternalV2BulkPacketGroupedBatchedDataReaders(
	ctx context.Context,
	conns []externalV2BulkPacketBatchConn,
	auth externalV2BulkPacketAuth,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	assembler *externalV2BulkPacketGroupAssembler,
	cryptoQueuePeak *atomic.Uint32,
	receiveQueuePeak *atomic.Uint32,
) <-chan struct{} {
	done := make(chan struct{})
	completed := make(chan *externalV2BulkPacketCiphertextGroup, externalV2BulkPacketGroupedDecryptQueue)
	resultPool := &sync.Pool{New: func() any {
		results := make([]externalV2BulkPacketReceiveResult, 0, externalV2BulkPacketGroupedResultBatch)
		return &results
	}}

	var readers sync.WaitGroup
	readers.Add(len(conns))
	for _, conn := range conns {
		go func(conn externalV2BulkPacketBatchConn) {
			defer readers.Done()
			readExternalV2BulkPacketGroupedBatches(
				ctx, conn, auth, dataCh, errCh, assembler, completed, cryptoQueuePeak, receiveQueuePeak,
			)
		}(conn)
	}
	go func() {
		readers.Wait()
		close(completed)
	}()

	workerCount := externalV2BulkPacketWorkerCount(runtime.GOMAXPROCS(0))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			openExternalV2BulkPacketGroupedBatches(
				ctx, completed, dataCh, errCh, assembler, resultPool, receiveQueuePeak,
			)
		}()
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}

func readExternalV2BulkPacketGroupedBatches(
	ctx context.Context,
	conn externalV2BulkPacketBatchConn,
	auth externalV2BulkPacketAuth,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	assembler *externalV2BulkPacketGroupAssembler,
	completed chan<- *externalV2BulkPacketCiphertextGroup,
	cryptoQueuePeak *atomic.Uint32,
	receiveQueuePeak *atomic.Uint32,
) {
	slab := newExternalV2BulkPacketDirectReadSlab()
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	for {
		count, err := conn.ReadBatch(ctx, slab.messages[:])
		if err != nil {
			reportExternalV2BulkPacketReadError(ctx, errCh, err)
			return
		}
		activityObserved := false
		for index := range count {
			message := &slab.messages[index]
			if !validExternalV2BulkPacketReadLength(message.N) {
				continue
			}
			packet := message.Buffers[0][:message.N]
			header, parsed := parseExternalV2BulkPacketHeader(packet)
			if !parsed {
				continue
			}
			if header.kind == externalV2BulkPacketPrimaryComplete {
				opened, ok := openExternalV2BulkPacketPrimaryComplete(auth.data, packet, &nonce)
				if ok && !sendExternalV2BulkPacketGroupedResult(
					ctx, dataCh, externalV2BulkPacketReceiveResult{header: opened, primaryComplete: true}, receiveQueuePeak,
				) {
					return
				}
				continue
			}
			if header.kind != externalV2BulkPacketGroupedData {
				continue
			}
			group, accepted, err := assembler.addEncrypted(packet)
			if err != nil {
				offerExternalV2BulkPacketRepairError(errCh, err)
				return
			}
			if accepted && !activityObserved {
				assembler.arrivals.observeActivity(time.Now())
				activityObserved = true
			}
			if group == nil {
				continue
			}
			select {
			case completed <- group:
				if cryptoQueuePeak != nil {
					externalV2BulkPacketAtomicMaxUint32(cryptoQueuePeak, uint32(max(1, len(completed))))
				}
			case <-ctx.Done():
				assembler.releaseGroup(group)
				return
			}
		}
	}
}

func openExternalV2BulkPacketGroupedBatches(
	ctx context.Context,
	completed <-chan *externalV2BulkPacketCiphertextGroup,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	assembler *externalV2BulkPacketGroupAssembler,
	resultPool *sync.Pool,
	receiveQueuePeak *atomic.Uint32,
) {
	failed := false
	for group := range completed {
		if failed || ctx.Err() != nil {
			assembler.releaseGroup(group)
			continue
		}
		poolResults := resultPool.Get().(*[]externalV2BulkPacketReceiveResult)
		results := (*poolResults)[:0]
		for {
			result, err := assembler.openGroup(group)
			if err != nil {
				offerExternalV2BulkPacketRepairError(errCh, err)
				failed = true
				break
			}
			results = append(results, result)
			if len(results) == externalV2BulkPacketGroupedResultBatch {
				break
			}
			select {
			case group = <-completed:
			default:
				group = nil
			}
			if group == nil {
				break
			}
		}
		if failed {
			for index := range results {
				results[index].release()
			}
			*poolResults = results[:0]
			resultPool.Put(poolResults)
			continue
		}
		batch := externalV2BulkPacketReceiveBatch{results: results, poolResults: poolResults, pool: resultPool}
		select {
		case dataCh <- batch:
			if receiveQueuePeak != nil {
				externalV2BulkPacketAtomicMaxUint32(receiveQueuePeak, uint32(max(1, len(dataCh))))
			}
		case <-ctx.Done():
			batch.release()
		}
	}
}

func sendExternalV2BulkPacketGroupedResult(
	ctx context.Context,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	result externalV2BulkPacketReceiveResult,
	receiveQueuePeak *atomic.Uint32,
) bool {
	batch := externalV2BulkPacketReceiveBatch{results: []externalV2BulkPacketReceiveResult{result}}
	select {
	case dataCh <- batch:
		if receiveQueuePeak != nil {
			externalV2BulkPacketAtomicMaxUint32(receiveQueuePeak, uint32(max(1, len(dataCh))))
		}
		return true
	case <-ctx.Done():
		batch.release()
		return false
	}
}
