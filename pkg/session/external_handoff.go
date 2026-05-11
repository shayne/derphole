// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 Retired public QUIC handoff helpers pending deletion after the WG cutover settles.
package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var errExternalHandoffWindowOverflow = errors.New("external handoff receive window overflow")
var errExternalHandoffUnackedWindowFull = errors.New("external handoff unacked window full")
var errExternalHandoffSourcePending = errors.New("external handoff source data pending")
var errExternalHandoffCarrierHandoff = errors.New("external handoff carrier switching to another transport")

const externalHandoffMaxUnackedBytes = 64 << 20
const externalHandoffTransferIDHandoff = ^uint64(0)

var externalTransferTraceStart = time.Now()

func externalTransferTracef(format string, args ...any) {
	if os.Getenv("DERPHOLE_TRACE_HANDOFF") != "1" {
		return
	}
	allArgs := append([]any{time.Since(externalTransferTraceStart).Truncate(time.Microsecond)}, args...)
	log.Printf("handoff-trace elapsed=%s "+format, allArgs...)
}

type externalHandoffChunk struct {
	TransferID uint64
	Offset     int64
	Payload    []byte
}

type externalHandoffReceiver struct {
	mu        sync.Mutex
	out       io.Writer
	maxWindow int64
	watermark int64
	pending   map[int64]externalHandoffPendingChunk
	buffered  int64
}

func newExternalHandoffReceiver(out io.Writer, maxWindow int64) *externalHandoffReceiver {
	return &externalHandoffReceiver{
		out:       out,
		maxWindow: maxWindow,
		pending:   make(map[int64]externalHandoffPendingChunk),
	}
}

type externalHandoffChunkSource uint8

const (
	externalHandoffChunkSourceUnknown externalHandoffChunkSource = iota
	externalHandoffChunkSourceRelay
	externalHandoffChunkSourceDirect
)

type externalHandoffDelivery struct {
	Relay   int64
	Direct  int64
	Unknown int64
}

func (d *externalHandoffDelivery) add(source externalHandoffChunkSource, n int64) {
	if n <= 0 {
		return
	}
	switch source {
	case externalHandoffChunkSourceRelay:
		d.Relay += n
	case externalHandoffChunkSourceDirect:
		d.Direct += n
	default:
		d.Unknown += n
	}
}

type externalHandoffPendingChunk struct {
	payload []byte
	source  externalHandoffChunkSource
}

type externalHandoffBufferSegment struct {
	offset  int64
	payload []byte
	source  externalHandoffChunkSource
}

func (r *externalHandoffReceiver) Watermark() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.watermark
}

func (r *externalHandoffReceiver) AcceptChunk(chunk externalHandoffChunk) error {
	_, err := r.AcceptChunkFrom(chunk, externalHandoffChunkSourceUnknown)
	return err
}

func (r *externalHandoffReceiver) AcceptChunkFrom(chunk externalHandoffChunk, source externalHandoffChunkSource) (externalHandoffDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	offset, payload, ignored, err := normalizeExternalHandoffChunk(r.watermark, chunk)
	if err != nil || ignored {
		return externalHandoffDelivery{}, err
	}
	if err := r.bufferChunkLocked(offset, payload, source); err != nil {
		return externalHandoffDelivery{}, err
	}
	return r.flushBufferedChunksLocked()
}

func normalizeExternalHandoffChunk(watermark int64, chunk externalHandoffChunk) (int64, []byte, bool, error) {
	if chunk.Offset < 0 {
		return 0, nil, false, fmt.Errorf("external handoff chunk offset %d is negative", chunk.Offset)
	}
	if len(chunk.Payload) == 0 {
		return 0, nil, true, nil
	}
	offset := chunk.Offset
	payload := chunk.Payload
	end := offset + int64(len(payload))
	if end <= watermark {
		return 0, nil, true, nil
	}
	if offset < watermark {
		payload = payload[watermark-offset:]
		offset = watermark
	}
	return offset, payload, false, nil
}

func (r *externalHandoffReceiver) bufferChunkLocked(offset int64, payload []byte, source externalHandoffChunkSource) error {
	if offset > r.watermark+r.maxWindow {
		return errExternalHandoffWindowOverflow
	}
	segments, err := r.newExternalHandoffBufferSegmentsLocked(offset, payload, source)
	if err != nil {
		return err
	}
	newBytes := externalHandoffBufferSegmentBytes(segments)
	if r.buffered+newBytes > r.maxWindow {
		return errExternalHandoffWindowOverflow
	}

	for _, segment := range segments {
		if len(segment.payload) == 0 {
			continue
		}
		copied := append([]byte(nil), segment.payload...)
		r.pending[segment.offset] = externalHandoffPendingChunk{payload: copied, source: segment.source}
		r.buffered += int64(len(copied))
	}
	return nil
}

func (r *externalHandoffReceiver) newExternalHandoffBufferSegmentsLocked(offset int64, payload []byte, source externalHandoffChunkSource) ([]externalHandoffBufferSegment, error) {
	segments := []externalHandoffBufferSegment{{
		offset:  offset,
		payload: payload,
		source:  source,
	}}
	for _, pendingOffset := range r.pendingOffsetsLocked() {
		pending := r.pending[pendingOffset]
		next := segments[:0]
		for _, segment := range segments {
			split, err := splitExternalHandoffSegmentAroundPending(segment, pendingOffset, pending)
			if err != nil {
				return nil, err
			}
			next = append(next, split...)
		}
		segments = next
		if len(segments) == 0 {
			return nil, nil
		}
	}
	return segments, nil
}

func (r *externalHandoffReceiver) pendingOffsetsLocked() []int64 {
	offsets := make([]int64, 0, len(r.pending))
	for offset := range r.pending {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	return offsets
}

func splitExternalHandoffSegmentAroundPending(segment externalHandoffBufferSegment, pendingOffset int64, pending externalHandoffPendingChunk) ([]externalHandoffBufferSegment, error) {
	segmentEnd := segment.offset + int64(len(segment.payload))
	pendingEnd := pendingOffset + int64(len(pending.payload))
	if segmentEnd <= pendingOffset || pendingEnd <= segment.offset {
		return []externalHandoffBufferSegment{segment}, nil
	}

	overlapStart := maxInt64(segment.offset, pendingOffset)
	overlapEnd := minInt64(segmentEnd, pendingEnd)
	segmentOverlapStart := overlapStart - segment.offset
	pendingOverlapStart := overlapStart - pendingOffset
	overlapLen := overlapEnd - overlapStart
	segmentOverlap := segment.payload[segmentOverlapStart : segmentOverlapStart+overlapLen]
	pendingOverlap := pending.payload[pendingOverlapStart : pendingOverlapStart+overlapLen]
	if !bytes.Equal(segmentOverlap, pendingOverlap) {
		return nil, fmt.Errorf("external handoff duplicate chunk at offset %d does not match buffered payload", overlapStart)
	}

	split := make([]externalHandoffBufferSegment, 0, 2)
	if segment.offset < overlapStart {
		split = append(split, externalHandoffBufferSegment{
			offset:  segment.offset,
			payload: segment.payload[:segmentOverlapStart],
			source:  segment.source,
		})
	}
	if overlapEnd < segmentEnd {
		rightStart := segmentOverlapStart + overlapLen
		split = append(split, externalHandoffBufferSegment{
			offset:  overlapEnd,
			payload: segment.payload[rightStart:],
			source:  segment.source,
		})
	}
	return split, nil
}

func externalHandoffBufferSegmentBytes(segments []externalHandoffBufferSegment) int64 {
	var total int64
	for _, segment := range segments {
		total += int64(len(segment.payload))
	}
	return total
}

func (r *externalHandoffReceiver) flushBufferedChunksLocked() (externalHandoffDelivery, error) {
	var delivery externalHandoffDelivery
	for {
		next, ok := r.pending[r.watermark]
		if !ok {
			return delivery, nil
		}
		if _, err := r.out.Write(next.payload); err != nil {
			return delivery, err
		}
		delete(r.pending, r.watermark)
		delivered := int64(len(next.payload))
		r.buffered -= delivered
		r.watermark += delivered
		delivery.add(next.source, delivered)
	}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type externalHandoffSpool struct {
	mu              sync.Mutex
	cond            *sync.Cond
	src             io.Reader
	srcCloser       io.Closer
	file            *os.File
	filePath        string
	chunkSize       int
	maxUnacked      int64
	maxBuffered     int64
	readOffset      int64
	sourceOffset    int64
	ackedWatermark  int64
	eof             bool
	readErr         error
	readInterrupted bool
	closed          bool
	pumpDone        chan struct{}
}

type externalHandoffSpoolSnapshot struct {
	ReadOffset     int64
	SourceOffset   int64
	AckedWatermark int64
	EOF            bool
}

func newExternalHandoffSpool(src io.Reader, chunkSize int, maxUnackedBytes int64) (*externalHandoffSpool, error) {
	if src == nil {
		return nil, errors.New("external handoff spool source is nil")
	}
	if chunkSize <= 0 {
		return nil, fmt.Errorf("external handoff chunk size %d must be positive", chunkSize)
	}
	if maxUnackedBytes <= 0 {
		return nil, fmt.Errorf("external handoff unacked window %d must be positive", maxUnackedBytes)
	}
	file, err := os.CreateTemp("", "derphole-external-handoff-*.spool")
	if err != nil {
		return nil, err
	}
	spool := &externalHandoffSpool{
		src:         src,
		srcCloser:   externalHandoffSourceCloser(src),
		file:        file,
		filePath:    file.Name(),
		chunkSize:   chunkSize,
		maxUnacked:  maxUnackedBytes,
		maxBuffered: maxUnackedBytes,
		pumpDone:    make(chan struct{}),
	}
	spool.cond = sync.NewCond(&spool.mu)
	go spool.pumpSource()
	return spool, nil
}

func (s *externalHandoffSpool) NextChunk() (externalHandoffChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	chunkLen, err := s.nextChunkLenLocked()
	if err != nil {
		return externalHandoffChunk{}, err
	}

	for {
		if s.readOffset < s.sourceOffset {
			return s.readNextAvailableChunkLocked(chunkLen)
		}

		if err, done := s.nextBlockedChunkErrLocked(); done {
			return externalHandoffChunk{}, err
		}
		s.cond.Wait()
	}
}

func (s *externalHandoffSpool) nextChunkLenLocked() (int64, error) {
	if s.readOffset-s.ackedWatermark >= s.maxUnacked {
		return 0, errExternalHandoffUnackedWindowFull
	}
	chunkLen := int64(s.chunkSize)
	if remaining := s.maxUnacked - (s.readOffset - s.ackedWatermark); remaining < chunkLen {
		chunkLen = remaining
	}
	if chunkLen <= 0 {
		return 0, errExternalHandoffUnackedWindowFull
	}
	return chunkLen, nil
}

func (s *externalHandoffSpool) readNextAvailableChunkLocked(chunkLen int64) (externalHandoffChunk, error) {
	available := s.sourceOffset - s.readOffset
	if available < chunkLen {
		chunkLen = available
	}
	payload := make([]byte, chunkLen)
	n, err := s.file.ReadAt(payload, s.readOffset)
	if err != nil && !errors.Is(err, io.EOF) {
		return externalHandoffChunk{}, err
	}
	payload = payload[:n]
	chunk := externalHandoffChunk{Offset: s.readOffset, Payload: payload}
	s.readOffset += int64(n)
	return chunk, nil
}

func (s *externalHandoffSpool) nextBlockedChunkErrLocked() (error, bool) {
	switch {
	case s.readInterrupted:
		s.readInterrupted = false
		return errExternalHandoffSourcePending, true
	case s.readErr != nil:
		return s.readErr, true
	case s.eof:
		return io.EOF, true
	case s.closed:
		return net.ErrClosed, true
	default:
		return nil, false
	}
}

func (s *externalHandoffSpool) AckTo(watermark int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if watermark < s.ackedWatermark {
		return nil
	}
	if watermark > s.sourceOffset {
		return fmt.Errorf("external handoff ack watermark %d exceeds source offset %d", watermark, s.sourceOffset)
	}
	s.ackedWatermark = watermark
	s.cond.Broadcast()
	return nil
}

func (s *externalHandoffSpool) AckedWatermark() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ackedWatermark
}

func (s *externalHandoffSpool) WaitForUnackedAtMost(ctx context.Context, maxUnacked int64) error {
	if maxUnacked < 0 {
		maxUnacked = 0
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		case <-done:
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.readOffset-s.ackedWatermark <= maxUnacked {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.closed {
			return net.ErrClosed
		}
		s.cond.Wait()
	}
}

func (s *externalHandoffSpool) SetMaxUnacked(maxUnacked int64) {
	if maxUnacked <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxUnacked = maxUnacked
	if s.maxBuffered < maxUnacked {
		s.maxBuffered = maxUnacked
	}
	s.cond.Broadcast()
}

func (s *externalHandoffSpool) SetMaxBuffered(maxBuffered int64) {
	if maxBuffered <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxBuffered = maxBuffered
	s.cond.Broadcast()
}

func (s *externalHandoffSpool) Snapshot() externalHandoffSpoolSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	return externalHandoffSpoolSnapshot{
		ReadOffset:     s.readOffset,
		SourceOffset:   s.sourceOffset,
		AckedWatermark: s.ackedWatermark,
		EOF:            s.eof,
	}
}

func (s *externalHandoffSpool) Done() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.eof && s.ackedWatermark >= s.sourceOffset
}

func (s *externalHandoffSpool) AllSourceBytesSent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.eof && s.readOffset >= s.sourceOffset
}

func (s *externalHandoffSpool) RewindTo(offset int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if offset < s.ackedWatermark {
		return fmt.Errorf("external handoff rewind offset %d precedes ack watermark %d", offset, s.ackedWatermark)
	}
	if offset > s.sourceOffset {
		return fmt.Errorf("external handoff rewind offset %d exceeds source offset %d", offset, s.sourceOffset)
	}
	s.readOffset = offset
	s.readInterrupted = false
	s.cond.Broadcast()
	return nil
}

type externalHandoffSpoolCursor struct {
	ctx    context.Context
	spool  *externalHandoffSpool
	offset int64
}

func newExternalHandoffSpoolCursor(ctx context.Context, spool *externalHandoffSpool, offset int64) io.Reader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &externalHandoffSpoolCursor{
		ctx:    ctx,
		spool:  spool,
		offset: offset,
	}
}

func (c *externalHandoffSpoolCursor) Read(p []byte) (int, error) {
	if c == nil || c.spool == nil {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.offset < 0 {
		return 0, fmt.Errorf("external handoff cursor offset %d is negative", c.offset)
	}
	for {
		if err := c.ctx.Err(); err != nil {
			return 0, err
		}

		n, err, wait := c.readAvailable(p)
		if !wait {
			return n, err
		}
		if err := c.waitForData(); err != nil {
			return 0, err
		}
	}
}

func (c *externalHandoffSpoolCursor) waitForData() error {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *externalHandoffSpoolCursor) readAvailable(p []byte) (int, error, bool) {
	s := c.spool
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.file == nil {
		return 0, net.ErrClosed, false
	}
	if c.offset < s.sourceOffset {
		return c.readAvailablePayloadLocked(s, p)
	}
	return externalHandoffSpoolCursorBlockedRead(s)
}

func (c *externalHandoffSpoolCursor) readAvailablePayloadLocked(s *externalHandoffSpool, p []byte) (int, error, bool) {
	readLen := s.sourceOffset - c.offset
	if readLen > int64(len(p)) {
		readLen = int64(len(p))
	}
	n, err := s.file.ReadAt(p[:readLen], c.offset)
	if err != nil && errors.Is(err, io.EOF) {
		err = nil
	}
	c.offset += int64(n)
	return n, err, false
}

func externalHandoffSpoolCursorBlockedRead(s *externalHandoffSpool) (int, error, bool) {
	switch {
	case s.readErr != nil:
		return 0, s.readErr, false
	case s.eof:
		return 0, io.EOF, false
	default:
		return 0, nil, true
	}
}

func (s *externalHandoffSpool) InterruptPendingRead() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.readInterrupted = true
	s.cond.Broadcast()
}

func (s *externalHandoffSpool) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if s.file == nil {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cond.Broadcast()
	srcCloser := s.srcCloser
	s.mu.Unlock()

	if srcCloser != nil {
		_ = srcCloser.Close()
	}
	<-s.pumpDone

	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.file.Close()
	removeErr := os.Remove(s.filePath)
	s.file = nil
	if err != nil {
		return err
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return nil
}

func (s *externalHandoffSpool) pumpSource() {
	defer close(s.pumpDone)

	for {
		readSize, done := s.nextPumpReadSize()
		if done {
			return
		}
		if readSize <= 0 {
			continue
		}
		if s.readAndStorePumpPayload(readSize) {
			return
		}
	}
}

func (s *externalHandoffSpool) nextPumpReadSize() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for !s.closed && s.readErr == nil && !s.eof && s.sourceOffset-s.ackedWatermark >= s.maxBuffered {
		s.cond.Wait()
	}
	if s.closed || s.readErr != nil || s.eof {
		return 0, true
	}
	headroom := s.maxBuffered - (s.sourceOffset - s.ackedWatermark)
	readSize := s.chunkSize
	if headroom < int64(readSize) {
		readSize = int(headroom)
	}
	return readSize, false
}

func (s *externalHandoffSpool) readAndStorePumpPayload(readSize int) bool {
	payload := make([]byte, readSize)
	n, err := s.src.Read(payload)
	payload = payload[:n]

	s.mu.Lock()
	defer s.mu.Unlock()

	s.storePumpPayloadLocked(payload)
	s.storePumpReadErrLocked(err)
	done := s.eof || s.readErr != nil || s.closed
	s.cond.Broadcast()
	return done
}

func (s *externalHandoffSpool) storePumpPayloadLocked(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if _, writeErr := s.file.WriteAt(payload, s.sourceOffset); writeErr != nil && s.readErr == nil {
		s.readErr = writeErr
		return
	}
	s.sourceOffset += int64(len(payload))
}

func (s *externalHandoffSpool) storePumpReadErrLocked(err error) {
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		s.eof = true
	default:
		if s.readErr == nil {
			s.readErr = err
		}
	}
}

func externalHandoffSourceCloser(src io.Reader) io.Closer {
	if closer, ok := src.(io.Closer); ok {
		return closer
	}
	return nil
}

func sendExternalHandoffCarrier(ctx context.Context, carrier io.ReadWriteCloser, spool *externalHandoffSpool, stop <-chan struct{}) error {
	externalTransferTracef("sender-carrier-start carrier=%T stop=%v", carrier, stop != nil)
	stopWatchDone := startExternalHandoffStopWatcher(stop, spool)
	if stopWatchDone != nil {
		defer close(stopWatchDone)
	}
	ackErrCh := startExternalHandoffAckReader(carrier, spool)
	firstChunk := true
	for {
		if err, done := pollExternalHandoffSenderControl(carrier, spool, stop, ackErrCh); done {
			return err
		}
		nextFirstChunk, done, err := sendExternalHandoffNextChunk(ctx, carrier, spool, stop, ackErrCh, firstChunk)
		firstChunk = nextFirstChunk
		if done || err != nil {
			return err
		}
	}
}

func startExternalHandoffStopWatcher(stop <-chan struct{}, spool *externalHandoffSpool) chan struct{} {
	if stop != nil {
		stopWatchDone := make(chan struct{})
		go func() {
			select {
			case <-stop:
				select {
				case <-stopWatchDone:
					return
				default:
				}
				spool.InterruptPendingRead()
			case <-stopWatchDone:
			}
		}()
		return stopWatchDone
	}
	return nil
}

func startExternalHandoffAckReader(carrier io.ReadWriteCloser, spool *externalHandoffSpool) <-chan error {
	ackErrCh := make(chan error, 1)
	go func() {
		for {
			watermark, err := readExternalHandoffWatermarkFrame(carrier)
			if err != nil {
				externalTransferTracef("sender-carrier-ack-stop carrier=%T err=%v", carrier, err)
				if externalHandoffCarrierClosed(err) {
					ackErrCh <- nil
					return
				}
				ackErrCh <- err
				return
			}
			if err := spool.AckTo(watermark); err != nil {
				ackErrCh <- err
				return
			}
			externalTransferTracef("sender-carrier-ack carrier=%T watermark=%d", carrier, watermark)
		}
	}()
	return ackErrCh
}

func pollExternalHandoffSenderControl(carrier io.ReadWriteCloser, spool *externalHandoffSpool, stop <-chan struct{}, ackErrCh <-chan error) (error, bool) {
	select {
	case err := <-ackErrCh:
		return err, true
	case <-stop:
		return stopExternalHandoffSender(carrier, spool, ackErrCh), true
	default:
		return nil, false
	}
}

func stopExternalHandoffSender(carrier io.ReadWriteCloser, spool *externalHandoffSpool, ackErrCh <-chan error) error {
	if !spool.Done() {
		externalTransferTracef("sender-carrier-handoff carrier=%T acked=%d", carrier, spool.AckedWatermark())
		if err := writeExternalHandoffHandoffFrame(carrier, spool.AckedWatermark()); err != nil {
			return err
		}
	}
	if err := closeExternalHandoffWrite(carrier); err != nil {
		return err
	}
	return <-ackErrCh
}

func sendExternalHandoffNextChunk(ctx context.Context, carrier io.ReadWriteCloser, spool *externalHandoffSpool, stop <-chan struct{}, ackErrCh <-chan error, firstChunk bool) (bool, bool, error) {
	chunk, err := spool.NextChunk()
	switch {
	case err == nil:
		if firstChunk {
			firstChunk = false
			externalTransferTracef("sender-first-chunk offset=%d bytes=%d carrier=%T", chunk.Offset, len(chunk.Payload), carrier)
		}
		return firstChunk, false, writeExternalHandoffChunkFrame(carrier, chunk)
	case errors.Is(err, io.EOF):
		return firstChunk, true, finishExternalHandoffSenderEOF(carrier, ackErrCh)
	case errors.Is(err, errExternalHandoffUnackedWindowFull), errors.Is(err, errExternalHandoffSourcePending):
		waitErr, done := waitExternalHandoffSenderBackpressure(ctx, carrier, spool, stop, ackErrCh)
		return firstChunk, done, waitErr
	default:
		return firstChunk, true, err
	}
}

func finishExternalHandoffSenderEOF(carrier io.ReadWriteCloser, ackErrCh <-chan error) error {
	externalTransferTracef("sender-carrier-eof carrier=%T", carrier)
	if err := closeExternalHandoffWrite(carrier); err != nil {
		return err
	}
	return <-ackErrCh
}

func waitExternalHandoffSenderBackpressure(ctx context.Context, carrier io.ReadWriteCloser, spool *externalHandoffSpool, stop <-chan struct{}, ackErrCh <-chan error) (error, bool) {
	select {
	case ackErr := <-ackErrCh:
		return ackErr, true
	case <-stop:
		return stopExternalHandoffSender(carrier, spool, ackErrCh), true
	case <-ctx.Done():
		return ctx.Err(), true
	case <-time.After(time.Millisecond):
		return nil, false
	}
}

func receiveExternalHandoffCarrier(ctx context.Context, carrier io.ReadWriteCloser, rx *externalHandoffReceiver, maxPayload int) error {
	externalTransferTracef("listener-carrier-start carrier=%T", carrier)
	firstChunk := true
	for {
		done, nextFirstChunk, err := receiveExternalHandoffChunk(carrier, rx, maxPayload, firstChunk)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		firstChunk = nextFirstChunk
		if err := externalHandoffReceiveContext(ctx); err != nil {
			return err
		}
	}
}

func receiveExternalHandoffChunk(carrier io.ReadWriteCloser, rx *externalHandoffReceiver, maxPayload int, firstChunk bool) (bool, bool, error) {
	chunk, err := readExternalHandoffChunkFrame(carrier, maxPayload)
	if err != nil {
		return false, firstChunk, finishExternalHandoffReceiverOnReadError(carrier, rx, err)
	}
	if chunk.TransferID == externalHandoffTransferIDHandoff {
		return true, firstChunk, finishExternalHandoffReceiverOnHandoff(carrier, rx)
	}
	nextFirstChunk := traceExternalHandoffReceiverChunk(carrier, chunk, firstChunk)
	if err := rx.AcceptChunk(chunk); err != nil {
		return false, nextFirstChunk, err
	}
	return false, nextFirstChunk, writeExternalHandoffWatermarkFrame(carrier, rx.Watermark())
}

func externalHandoffReceiveContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func finishExternalHandoffReceiverOnReadError(carrier io.ReadWriteCloser, rx *externalHandoffReceiver, err error) error {
	if !externalHandoffCarrierClosed(err) {
		return err
	}
	externalTransferTracef("listener-carrier-eof carrier=%T watermark=%d", carrier, rx.Watermark())
	if writeErr := writeExternalHandoffWatermarkFrame(carrier, rx.Watermark()); writeErr != nil {
		return writeErr
	}
	externalTransferTracef("listener-carrier-final-ack carrier=%T watermark=%d", carrier, rx.Watermark())
	return closeExternalHandoffWrite(carrier)
}

func finishExternalHandoffReceiverOnHandoff(carrier io.ReadWriteCloser, rx *externalHandoffReceiver) error {
	externalTransferTracef("listener-carrier-handoff carrier=%T watermark=%d", carrier, rx.Watermark())
	if writeErr := writeExternalHandoffWatermarkFrame(carrier, rx.Watermark()); writeErr != nil {
		return writeErr
	}
	if closeErr := closeExternalHandoffWrite(carrier); closeErr != nil {
		return closeErr
	}
	return errExternalHandoffCarrierHandoff
}

func traceExternalHandoffReceiverChunk(carrier io.ReadWriteCloser, chunk externalHandoffChunk, firstChunk bool) bool {
	if firstChunk {
		externalTransferTracef("listener-first-chunk offset=%d bytes=%d carrier=%T", chunk.Offset, len(chunk.Payload), carrier)
		return false
	}
	return firstChunk
}

type externalHandoffOffsetWriter struct {
	rx      *externalHandoffReceiver
	offset  int64
	deliver func(externalHandoffDelivery)
}

func newExternalHandoffOffsetWriter(rx *externalHandoffReceiver, offset int64, deliver func(externalHandoffDelivery)) io.Writer {
	return &externalHandoffOffsetWriter{rx: rx, offset: offset, deliver: deliver}
}

func (w *externalHandoffOffsetWriter) Write(p []byte) (int, error) {
	if w == nil || w.rx == nil {
		return 0, errors.New("nil external handoff offset writer")
	}
	if w.offset < 0 {
		return 0, fmt.Errorf("external handoff offset writer offset %d is negative", w.offset)
	}
	delivery, err := w.rx.AcceptChunkFrom(externalHandoffChunk{Offset: w.offset, Payload: p}, externalHandoffChunkSourceDirect)
	if err != nil {
		return 0, err
	}
	w.offset += int64(len(p))
	if w.deliver != nil {
		w.deliver(delivery)
	}
	return len(p), nil
}

type externalHandoffSpoolReader struct {
	spool         *externalHandoffSpool
	pending       []byte
	pendingOffset int64
}

func newExternalHandoffSpoolReader(spool *externalHandoffSpool) *externalHandoffSpoolReader {
	return &externalHandoffSpoolReader{spool: spool}
}

func (r *externalHandoffSpoolReader) Read(p []byte) (int, error) {
	if r == nil || r.spool == nil {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		chunk, err := r.spool.NextChunk()
		switch {
		case err == nil:
			r.pending = chunk.Payload
			r.pendingOffset = chunk.Offset
		case errors.Is(err, errExternalHandoffUnackedWindowFull), errors.Is(err, errExternalHandoffSourcePending):
			time.Sleep(time.Millisecond)
			continue
		default:
			return 0, err
		}
	}

	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	r.pendingOffset += int64(n)
	if err := r.spool.AckTo(r.pendingOffset); err != nil {
		return n, err
	}
	return n, nil
}

func externalHandoffCarrierClosed(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr) && appErr.ErrorCode == 0
}

func closeExternalHandoffWrite(carrier io.ReadWriteCloser) error {
	if closer, ok := carrier.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return carrier.Close()
}

func writeExternalHandoffChunkFrame(w io.Writer, chunk externalHandoffChunk) error {
	if chunk.Offset < 0 {
		return fmt.Errorf("external handoff chunk offset %d is negative", chunk.Offset)
	}
	if len(chunk.Payload) > int(^uint32(0)) {
		return fmt.Errorf("external handoff chunk payload length %d exceeds uint32", len(chunk.Payload))
	}
	if err := binary.Write(w, binary.BigEndian, chunk.TransferID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, chunk.Offset); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(chunk.Payload))); err != nil {
		return err
	}
	_, err := w.Write(chunk.Payload)
	return err
}

func readExternalHandoffChunkFrame(r io.Reader, maxPayload int) (externalHandoffChunk, error) {
	var chunk externalHandoffChunk
	if err := binary.Read(r, binary.BigEndian, &chunk.TransferID); err != nil {
		return externalHandoffChunk{}, err
	}
	if err := binary.Read(r, binary.BigEndian, &chunk.Offset); err != nil {
		return externalHandoffChunk{}, err
	}
	if chunk.Offset < 0 {
		return externalHandoffChunk{}, fmt.Errorf("external handoff chunk offset %d is negative", chunk.Offset)
	}
	var payloadLen uint32
	if err := binary.Read(r, binary.BigEndian, &payloadLen); err != nil {
		return externalHandoffChunk{}, err
	}
	if chunk.TransferID == externalHandoffTransferIDHandoff {
		if payloadLen != 0 {
			return externalHandoffChunk{}, fmt.Errorf("external handoff marker payload length %d must be zero", payloadLen)
		}
		return chunk, nil
	}
	if maxPayload < 0 || int64(payloadLen) > int64(maxPayload) {
		return externalHandoffChunk{}, fmt.Errorf("external handoff chunk payload length %d exceeds max %d", payloadLen, maxPayload)
	}
	chunk.Payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, chunk.Payload); err != nil {
		return externalHandoffChunk{}, err
	}
	return chunk, nil
}

func writeExternalHandoffWatermarkFrame(w io.Writer, watermark int64) error {
	if watermark < 0 {
		return fmt.Errorf("external handoff watermark %d is negative", watermark)
	}
	return binary.Write(w, binary.BigEndian, watermark)
}

func writeExternalHandoffHandoffFrame(w io.Writer, watermark int64) error {
	if watermark < 0 {
		return fmt.Errorf("external handoff marker watermark %d is negative", watermark)
	}
	if err := binary.Write(w, binary.BigEndian, externalHandoffTransferIDHandoff); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, watermark); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, uint32(0))
}

func readExternalHandoffWatermarkFrame(r io.Reader) (int64, error) {
	var watermark int64
	if err := binary.Read(r, binary.BigEndian, &watermark); err != nil {
		return 0, err
	}
	if watermark < 0 {
		return 0, fmt.Errorf("external handoff watermark %d is negative", watermark)
	}
	return watermark, nil
}
