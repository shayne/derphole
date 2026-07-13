// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/cipher"
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	externalV2BulkPacketDecryptQueue             = 32
	externalV2BulkPacketDirectDecryptQueue       = 128
	externalV2BulkPacketReceiveSocketBufferBytes = 8 << 20
)

type externalV2BulkPacketSealedBuffer struct {
	data [externalV2BulkPacketMaxSize]byte
}

type externalV2BulkPacketDecryptBatchJob struct {
	buffers []*externalV2BulkPacketSealedBuffer
	lengths []int
}

type externalV2BulkPacketDirectReadSlab struct {
	data     [externalV2BulkPacketMaxBatch * externalV2BulkPacketMaxSize]byte
	messages [externalV2BulkPacketMaxBatch]externalV2BulkPacketBatchMessage
	count    int
}

func newExternalV2BulkPacketDirectReadSlab() *externalV2BulkPacketDirectReadSlab {
	slab := &externalV2BulkPacketDirectReadSlab{}
	for index := range slab.messages {
		start := index * externalV2BulkPacketMaxSize
		slab.messages[index].Buffers = [][]byte{slab.data[start : start+externalV2BulkPacketMaxSize]}
	}
	return slab
}

type externalV2BulkPacketReceiveBatch struct {
	results     []externalV2BulkPacketReceiveResult
	poolResults *[]externalV2BulkPacketReceiveResult
	pool        *sync.Pool
}

func (b *externalV2BulkPacketReceiveBatch) release() {
	if b == nil {
		return
	}
	for index := range b.results {
		b.results[index].release()
	}
	results := b.results[:0]
	b.results = nil
	if b.pool != nil && b.poolResults != nil {
		*b.poolResults = results
		b.pool.Put(b.poolResults)
		b.poolResults = nil
	}
}

func startExternalV2BulkPacketBatchedDataReaders(
	ctx context.Context,
	conns []externalV2BulkPacketBatchConn,
	auth externalV2BulkPacketAuth,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	arrivals *externalV2BulkPacketArrivalTracker,
	directBuffer []byte,
	groupAssembler *externalV2BulkPacketGroupAssembler,
	queuePeaks ...*atomic.Uint32,
) <-chan struct{} {
	if groupAssembler != nil {
		return startExternalV2BulkPacketGroupedBatchedDataReaders(
			ctx,
			conns,
			auth,
			dataCh,
			errCh,
			groupAssembler,
			firstExternalV2BulkPacketQueuePeak(queuePeaks),
			secondExternalV2BulkPacketQueuePeak(queuePeaks),
		)
	}
	if len(directBuffer) > 0 {
		return startExternalV2BulkPacketDirectBatchedDataReaders(
			ctx,
			conns,
			auth,
			dataCh,
			errCh,
			arrivals,
			directBuffer,
			groupAssembler,
			firstExternalV2BulkPacketQueuePeak(queuePeaks),
			secondExternalV2BulkPacketQueuePeak(queuePeaks),
		)
	}
	done := make(chan struct{})
	jobs := make(chan *externalV2BulkPacketDecryptBatchJob, externalV2BulkPacketDecryptQueue)
	sealedPool := &sync.Pool{New: func() any { return &externalV2BulkPacketSealedBuffer{} }}
	jobPool := &sync.Pool{New: func() any {
		return &externalV2BulkPacketDecryptBatchJob{
			buffers: make([]*externalV2BulkPacketSealedBuffer, 0, externalV2BulkPacketMaxBatch),
			lengths: make([]int, 0, externalV2BulkPacketMaxBatch),
		}
	}}
	resultPool := &sync.Pool{New: func() any {
		results := make([]externalV2BulkPacketReceiveResult, 0, externalV2BulkPacketMaxBatch)
		return &results
	}}

	var readers sync.WaitGroup
	readers.Add(len(conns))
	for _, conn := range conns {
		go func(conn externalV2BulkPacketBatchConn) {
			defer readers.Done()
			readExternalV2BulkPacketBatches(ctx, conn, jobs, errCh, sealedPool, jobPool, firstExternalV2BulkPacketQueuePeak(queuePeaks))
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
			decryptExternalV2BulkPacketBatchJobs(ctx, auth, jobs, dataCh, sealedPool, jobPool, resultPool, arrivals, directBuffer, secondExternalV2BulkPacketQueuePeak(queuePeaks))
		}()
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}

func startExternalV2BulkPacketDirectBatchedDataReaders(
	ctx context.Context,
	conns []externalV2BulkPacketBatchConn,
	auth externalV2BulkPacketAuth,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	arrivals *externalV2BulkPacketArrivalTracker,
	directBuffer []byte,
	groupAssembler *externalV2BulkPacketGroupAssembler,
	cryptoQueuePeak *atomic.Uint32,
	receiveQueuePeak *atomic.Uint32,
) <-chan struct{} {
	done := make(chan struct{})
	jobs := make(chan *externalV2BulkPacketDirectReadSlab, externalV2BulkPacketDirectDecryptQueue)
	slabPool := &sync.Pool{New: func() any { return newExternalV2BulkPacketDirectReadSlab() }}
	resultPool := &sync.Pool{New: func() any {
		results := make([]externalV2BulkPacketReceiveResult, 0, externalV2BulkPacketMaxBatch)
		return &results
	}}

	var readers sync.WaitGroup
	readers.Add(len(conns))
	for _, conn := range conns {
		go func(conn externalV2BulkPacketBatchConn) {
			defer readers.Done()
			readExternalV2BulkPacketDirectSlabs(ctx, conn, jobs, errCh, slabPool, cryptoQueuePeak)
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
			decryptExternalV2BulkPacketDirectSlabs(ctx, auth, jobs, dataCh, errCh, slabPool, resultPool, arrivals, directBuffer, groupAssembler, receiveQueuePeak)
		}()
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}

func readExternalV2BulkPacketDirectSlabs(
	ctx context.Context,
	conn externalV2BulkPacketBatchConn,
	jobs chan<- *externalV2BulkPacketDirectReadSlab,
	errCh chan<- error,
	slabPool *sync.Pool,
	queuePeak *atomic.Uint32,
) {
	slab := slabPool.Get().(*externalV2BulkPacketDirectReadSlab)
	defer slabPool.Put(slab)
	for {
		count, err := conn.ReadBatch(ctx, slab.messages[:])
		if err != nil {
			reportExternalV2BulkPacketReadError(ctx, errCh, err)
			return
		}
		slab.count = count
		select {
		case jobs <- slab:
			if queuePeak != nil {
				externalV2BulkPacketAtomicMaxUint32(queuePeak, uint32(max(1, len(jobs))))
			}
			slab = slabPool.Get().(*externalV2BulkPacketDirectReadSlab)
		case <-ctx.Done():
			return
		}
	}
}

func decryptExternalV2BulkPacketDirectSlabs(
	ctx context.Context,
	auth externalV2BulkPacketAuth,
	jobs <-chan *externalV2BulkPacketDirectReadSlab,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	errCh chan<- error,
	slabPool *sync.Pool,
	resultPool *sync.Pool,
	arrivals *externalV2BulkPacketArrivalTracker,
	directBuffer []byte,
	groupAssembler *externalV2BulkPacketGroupAssembler,
	receiveQueuePeak *atomic.Uint32,
) {
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	for slab := range jobs {
		if ctx.Err() != nil {
			slabPool.Put(slab)
			continue
		}
		poolResults := resultPool.Get().(*[]externalV2BulkPacketReceiveResult)
		results := (*poolResults)[:0]
		for index := range slab.count {
			result, accepted, err := decryptExternalV2BulkPacketDirectMessage(
				auth, &slab.messages[index], directBuffer, arrivals, groupAssembler, &nonce,
			)
			if err != nil {
				offerExternalV2BulkPacketRepairError(errCh, err)
				*poolResults = results[:0]
				resultPool.Put(poolResults)
				slabPool.Put(slab)
				return
			}
			if !accepted {
				continue
			}
			results = append(results, result)
		}
		slabPool.Put(slab)
		if len(results) == 0 {
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

func decryptExternalV2BulkPacketDirectMessage(
	auth externalV2BulkPacketAuth,
	message *externalV2BulkPacketBatchMessage,
	directBuffer []byte,
	arrivals *externalV2BulkPacketArrivalTracker,
	groupAssembler *externalV2BulkPacketGroupAssembler,
	nonce *[externalV2BulkPacketMaximumNonceSize]byte,
) (externalV2BulkPacketReceiveResult, bool, error) {
	if !validExternalV2BulkPacketReadLength(message.N) {
		return externalV2BulkPacketReceiveResult{}, false, nil
	}
	packet := message.Buffers[0][:message.N]
	parsed, parsedOK := parseExternalV2BulkPacketHeader(packet)
	if parsedOK && parsed.kind == externalV2BulkPacketPrimaryComplete {
		header, opened := openExternalV2BulkPacketPrimaryComplete(auth.data, packet, nonce)
		return externalV2BulkPacketReceiveResult{header: header, primaryComplete: opened}, opened, nil
	}
	if parsedOK && parsed.kind == externalV2BulkPacketGroupedData && groupAssembler != nil {
		return groupAssembler.add(packet)
	}
	header, opened := openExternalV2BulkPacketDirectInto(auth.data, packet, directBuffer, arrivals, nonce)
	return externalV2BulkPacketReceiveResult{header: header, direct: opened}, opened, nil
}

func openExternalV2BulkPacketDirectInto(
	aead cipher.AEAD,
	packet []byte,
	directBuffer []byte,
	arrivals *externalV2BulkPacketArrivalTracker,
	nonce *[externalV2BulkPacketMaximumNonceSize]byte,
) (externalV2BulkPacketHeader, bool) {
	header, ok := parseExternalV2BulkPacketHeader(packet)
	if !ok || aead == nil || header.kind != externalV2BulkPacketData || arrivals == nil ||
		header.total != arrivals.total || header.index >= header.total {
		return externalV2BulkPacketHeader{}, false
	}
	want := externalV2BulkPacketPayloadLength(header.index, int64(len(directBuffer)))
	offset := int64(header.index) * externalV2BulkPacketPayloadSize
	if int(header.length) != want || offset < 0 || offset+int64(want) > int64(len(directBuffer)) ||
		len(packet)-externalV2BulkPacketHeaderSize != want+aead.Overhead() || !arrivals.tryClaim(header.index) {
		return externalV2BulkPacketHeader{}, false
	}
	nonceSize := aead.NonceSize()
	if nonceSize < 12 || nonceSize > len(nonce) {
		arrivals.finishClaim(header, false)
		return externalV2BulkPacketHeader{}, false
	}
	fillExternalV2BulkPacketNonce(nonce[:nonceSize], header)
	start := int(offset)
	dst := directBuffer[start : start : start+want]
	payload, err := aead.Open(dst, nonce[:nonceSize], header.payload, packet[:externalV2BulkPacketHeaderSize])
	authenticated := err == nil && len(payload) == want
	arrivals.finishClaim(header, authenticated)
	if !authenticated {
		return externalV2BulkPacketHeader{}, false
	}
	header.payload = nil
	return header, true
}

func firstExternalV2BulkPacketQueuePeak(peaks []*atomic.Uint32) *atomic.Uint32 {
	if len(peaks) > 0 {
		return peaks[0]
	}
	return nil
}

func secondExternalV2BulkPacketQueuePeak(peaks []*atomic.Uint32) *atomic.Uint32 {
	if len(peaks) > 1 {
		return peaks[1]
	}
	return nil
}

func readExternalV2BulkPacketBatches(
	ctx context.Context,
	conn externalV2BulkPacketBatchConn,
	jobs chan<- *externalV2BulkPacketDecryptBatchJob,
	errCh chan<- error,
	sealedPool *sync.Pool,
	jobPool *sync.Pool,
	queuePeak *atomic.Uint32,
) {
	messages, readBuffers := newExternalV2BulkPacketPooledReadMessages(sealedPool)
	defer releaseExternalV2BulkPacketReadBuffers(readBuffers, sealedPool)
	for {
		count, err := conn.ReadBatch(ctx, messages)
		if err != nil {
			reportExternalV2BulkPacketReadError(ctx, errCh, err)
			return
		}
		if !enqueueExternalV2BulkPacketDecryptBatch(ctx, messages[:count], readBuffers[:count], jobs, sealedPool, jobPool, queuePeak) {
			return
		}
	}
}

func newExternalV2BulkPacketPooledReadMessages(
	sealedPool *sync.Pool,
) ([]externalV2BulkPacketBatchMessage, []*externalV2BulkPacketSealedBuffer) {
	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	buffers := make([]*externalV2BulkPacketSealedBuffer, externalV2BulkPacketMaxBatch)
	for index := range messages {
		buffer := sealedPool.Get().(*externalV2BulkPacketSealedBuffer)
		buffers[index] = buffer
		messages[index].Buffers = [][]byte{buffer.data[:]}
	}
	return messages, buffers
}

func releaseExternalV2BulkPacketReadBuffers(
	buffers []*externalV2BulkPacketSealedBuffer,
	sealedPool *sync.Pool,
) {
	for _, buffer := range buffers {
		sealedPool.Put(buffer)
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

func enqueueExternalV2BulkPacketDecryptBatch(
	ctx context.Context,
	messages []externalV2BulkPacketBatchMessage,
	readBuffers []*externalV2BulkPacketSealedBuffer,
	jobs chan<- *externalV2BulkPacketDecryptBatchJob,
	sealedPool *sync.Pool,
	jobPool *sync.Pool,
	queuePeak *atomic.Uint32,
) bool {
	job := jobPool.Get().(*externalV2BulkPacketDecryptBatchJob)
	job.buffers = job.buffers[:0]
	job.lengths = job.lengths[:0]
	for index, message := range messages {
		buffer := readBuffers[index]
		replacement := sealedPool.Get().(*externalV2BulkPacketSealedBuffer)
		readBuffers[index] = replacement
		messages[index].Buffers[0] = replacement.data[:]
		if !validExternalV2BulkPacketReadLength(message.N) {
			sealedPool.Put(buffer)
			continue
		}
		job.buffers = append(job.buffers, buffer)
		job.lengths = append(job.lengths, message.N)
	}
	if len(job.buffers) == 0 {
		jobPool.Put(job)
		return true
	}
	select {
	case jobs <- job:
		if queuePeak != nil {
			externalV2BulkPacketAtomicMaxUint32(queuePeak, uint32(max(1, len(jobs))))
		}
		return true
	case <-ctx.Done():
		releaseExternalV2BulkPacketDecryptBatchJob(job, sealedPool)
		job.buffers = job.buffers[:0]
		job.lengths = job.lengths[:0]
		jobPool.Put(job)
		return false
	}
}

func validExternalV2BulkPacketReadLength(length int) bool {
	return length > 0 && length <= externalV2BulkPacketMaxSize
}

func releaseExternalV2BulkPacketDecryptBatchJob(job *externalV2BulkPacketDecryptBatchJob, sealedPool *sync.Pool) {
	if job == nil {
		return
	}
	for _, buffer := range job.buffers {
		sealedPool.Put(buffer)
	}
}

func decryptExternalV2BulkPacketBatchJobs(
	ctx context.Context,
	auth externalV2BulkPacketAuth,
	jobs <-chan *externalV2BulkPacketDecryptBatchJob,
	dataCh chan<- externalV2BulkPacketReceiveBatch,
	sealedPool *sync.Pool,
	jobPool *sync.Pool,
	resultPool *sync.Pool,
	arrivals *externalV2BulkPacketArrivalTracker,
	directBuffer []byte,
	receiveQueuePeak *atomic.Uint32,
) {
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	for job := range jobs {
		if ctx.Err() != nil {
			releaseExternalV2BulkPacketDecryptBatchJob(job, sealedPool)
			job.buffers = job.buffers[:0]
			job.lengths = job.lengths[:0]
			jobPool.Put(job)
			continue
		}
		poolResults := resultPool.Get().(*[]externalV2BulkPacketReceiveResult)
		results := (*poolResults)[:0]
		for index, buffer := range job.buffers {
			header, payload, opened := openExternalV2BulkPacketIntoWithNonce(
				auth.data,
				buffer.data[:job.lengths[index]],
				buffer.data[externalV2BulkPacketHeaderSize:externalV2BulkPacketHeaderSize],
				&nonce,
			)
			if !opened || (header.kind != externalV2BulkPacketData && header.kind != externalV2BulkPacketPrimaryComplete) {
				sealedPool.Put(buffer)
				continue
			}
			if header.kind == externalV2BulkPacketPrimaryComplete {
				sealedPool.Put(buffer)
				if len(payload) == 0 {
					results = append(results, externalV2BulkPacketReceiveResult{header: header, primaryComplete: true})
				}
				continue
			}
			if len(directBuffer) > 0 {
				if !copyExternalV2BulkPacketDirectPayload(directBuffer, header, payload) {
					sealedPool.Put(buffer)
					continue
				}
				arrivals.markData(header)
				sealedPool.Put(buffer)
				results = append(results, externalV2BulkPacketReceiveResult{
					header: header,
					direct: true,
				})
				continue
			}
			arrivals.markData(header)
			results = append(results, externalV2BulkPacketReceiveResult{
				header:       header,
				data:         payload,
				sealedBuffer: buffer,
				sealedPool:   sealedPool,
			})
		}
		job.buffers = job.buffers[:0]
		job.lengths = job.lengths[:0]
		jobPool.Put(job)
		if len(results) == 0 {
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

func copyExternalV2BulkPacketDirectPayload(directBuffer []byte, header externalV2BulkPacketHeader, payload []byte) bool {
	if header.total != externalV2BulkPacketCount(int64(len(directBuffer))) || header.index >= header.total {
		return false
	}
	offset := int64(header.index) * externalV2BulkPacketPayloadSize
	want := externalV2BulkPacketPayloadLength(header.index, int64(len(directBuffer)))
	if len(payload) != want || offset < 0 || offset+int64(want) > int64(len(directBuffer)) {
		return false
	}
	copy(directBuffer[int(offset):int(offset)+want], payload)
	return true
}
