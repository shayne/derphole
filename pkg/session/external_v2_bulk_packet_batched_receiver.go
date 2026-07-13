// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const externalV2BulkPacketDecryptQueue = 256

type externalV2BulkPacketSealedBuffer struct {
	data [externalV2BulkPacketMaxSize]byte
}

type externalV2BulkPacketDecryptJob struct {
	buffer *externalV2BulkPacketSealedBuffer
	length int
}

func startExternalV2BulkPacketBatchedDataReaders(
	ctx context.Context,
	conns []externalV2BulkPacketBatchConn,
	auth externalV2BulkPacketAuth,
	dataCh chan<- externalV2BulkPacketReceiveResult,
	errCh chan<- error,
	queuePeaks ...*atomic.Uint32,
) <-chan struct{} {
	done := make(chan struct{})
	jobs := make(chan externalV2BulkPacketDecryptJob, externalV2BulkPacketDecryptQueue)
	sealedPool := &sync.Pool{New: func() any { return &externalV2BulkPacketSealedBuffer{} }}

	var readers sync.WaitGroup
	readers.Add(len(conns))
	for _, conn := range conns {
		go func(conn externalV2BulkPacketBatchConn) {
			defer readers.Done()
			readExternalV2BulkPacketBatches(ctx, conn, jobs, errCh, sealedPool, queuePeaks...)
		}(conn)
	}
	go func() {
		readers.Wait()
		close(jobs)
	}()

	workerCount := externalV2BulkPacketWorkerCount(runtime.GOMAXPROCS(0))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			decryptExternalV2BulkPacketJobs(ctx, auth, jobs, dataCh, sealedPool)
		}()
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}

func readExternalV2BulkPacketBatches(
	ctx context.Context,
	conn externalV2BulkPacketBatchConn,
	jobs chan<- externalV2BulkPacketDecryptJob,
	errCh chan<- error,
	sealedPool *sync.Pool,
	queuePeaks ...*atomic.Uint32,
) {
	messages := newExternalV2BulkPacketReadMessages()
	for {
		count, err := conn.ReadBatch(ctx, messages)
		if err != nil {
			reportExternalV2BulkPacketReadError(ctx, errCh, err)
			return
		}
		if !enqueueExternalV2BulkPacketDecryptJobs(ctx, messages[:count], jobs, sealedPool, queuePeaks) {
			return
		}
	}
}

func newExternalV2BulkPacketReadMessages() []externalV2BulkPacketBatchMessage {
	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
	}
	return messages
}

func reportExternalV2BulkPacketReadError(ctx context.Context, errCh chan<- error, err error) {
	if ctx.Err() == nil {
		offerExternalV2BulkPacketRepairError(errCh, err)
	}
}

func enqueueExternalV2BulkPacketDecryptJobs(
	ctx context.Context,
	messages []externalV2BulkPacketBatchMessage,
	jobs chan<- externalV2BulkPacketDecryptJob,
	sealedPool *sync.Pool,
	queuePeaks []*atomic.Uint32,
) bool {
	for _, message := range messages {
		if !validExternalV2BulkPacketReadLength(message.N) {
			continue
		}
		buffer := sealedPool.Get().(*externalV2BulkPacketSealedBuffer)
		copy(buffer.data[:], message.Buffers[0][:message.N])
		if !offerExternalV2BulkPacketDecryptJob(ctx, jobs, externalV2BulkPacketDecryptJob{buffer: buffer, length: message.N}, sealedPool) {
			return false
		}
		observeExternalV2BulkPacketQueuePeaks(queuePeaks, len(jobs))
	}
	return true
}

func validExternalV2BulkPacketReadLength(length int) bool {
	return length > 0 && length <= externalV2BulkPacketMaxSize
}

func offerExternalV2BulkPacketDecryptJob(ctx context.Context, jobs chan<- externalV2BulkPacketDecryptJob, job externalV2BulkPacketDecryptJob, sealedPool *sync.Pool) bool {
	select {
	case jobs <- job:
		return true
	case <-ctx.Done():
		sealedPool.Put(job.buffer)
		return false
	}
}

func observeExternalV2BulkPacketQueuePeaks(peaks []*atomic.Uint32, depth int) {
	for _, peak := range peaks {
		if peak != nil {
			externalV2BulkPacketAtomicMaxUint32(peak, uint32(depth))
		}
	}
}

func decryptExternalV2BulkPacketJobs(
	ctx context.Context,
	auth externalV2BulkPacketAuth,
	jobs <-chan externalV2BulkPacketDecryptJob,
	dataCh chan<- externalV2BulkPacketReceiveResult,
	sealedPool *sync.Pool,
) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	for job := range jobs {
		if ctx.Err() != nil {
			sealedPool.Put(job.buffer)
			continue
		}
		payloadBuffer := externalV2BulkPacketPayloadPool.get()
		header, payload, opened := openExternalV2BulkPacketIntoWithNonce(
			auth.data,
			job.buffer.data[:job.length],
			payloadBuffer.data,
			&nonce,
		)
		sealedPool.Put(job.buffer)
		if !opened || header.kind != externalV2BulkPacketData {
			externalV2BulkPacketPayloadPool.put(payloadBuffer)
			continue
		}
		payloadBuffer.data = payload
		result := externalV2BulkPacketReceiveResult{
			header:        header,
			data:          payload,
			payloadBuffer: payloadBuffer,
			payloadPool:   externalV2BulkPacketPayloadPool,
		}
		select {
		case dataCh <- result:
		case <-ctx.Done():
			result.release()
		}
	}
}
