// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type tlsChunkSchedule struct {
	total int64
	next  atomic.Int64
}

func newTLSChunkSchedule(total int64) *tlsChunkSchedule {
	return &tlsChunkSchedule{total: total}
}

func (s *tlsChunkSchedule) claim() (ByteRange, bool) {
	offset := s.next.Add(int64(TLSChunkSize)) - int64(TLSChunkSize)
	if offset >= s.total {
		return ByteRange{}, false
	}
	return ByteRange{Offset: offset, Length: min(int64(TLSChunkSize), s.total-offset)}, true
}

type tlsChunkTracker struct {
	total     int64
	seen      []atomic.Bool
	completed atomic.Int64
}

func newTLSChunkTracker(total int64) *tlsChunkTracker {
	count := int((total + int64(TLSChunkSize) - 1) / int64(TLSChunkSize))
	return &tlsChunkTracker{total: total, seen: make([]atomic.Bool, count)}
}

func (t *tlsChunkTracker) claim(header TLSChunkHeader) error {
	if header.Length == 0 {
		return errors.New("zero-length data chunk")
	}
	if header.Offset >= uint64(t.total) || header.Offset%uint64(TLSChunkSize) != 0 {
		return fmt.Errorf("chunk offset %d is outside the aligned file range", header.Offset)
	}
	want := min(uint64(TLSChunkSize), uint64(t.total)-header.Offset)
	if uint64(header.Length) != want {
		return fmt.Errorf("chunk at offset %d has length %d, want %d", header.Offset, header.Length, want)
	}
	index := int(header.Offset / uint64(TLSChunkSize))
	if !t.seen[index].CompareAndSwap(false, true) {
		return fmt.Errorf("duplicate chunk at offset %d", header.Offset)
	}
	t.completed.Add(1)
	return nil
}

func (t *tlsChunkTracker) validateComplete() error {
	if got, want := t.completed.Load(), int64(len(t.seen)); got != want {
		return fmt.Errorf("received %d chunks, want %d", got, want)
	}
	return nil
}

func sendTLSFramedRanges(ctx context.Context, conn io.Writer, input io.ReaderAt, lane int, schedule *tlsChunkSchedule, counters *tlsTransferCounters) error {
	buffer := make([]byte, int(TLSChunkSize))
	for {
		byteRange, ok := schedule.claim()
		if !ok {
			end := EncodeTLSChunkHeader(TLSChunkHeader{})
			return writeFull(conn, end[:])
		}
		frame := EncodeTLSChunkHeader(TLSChunkHeader{Offset: uint64(byteRange.Offset), Length: uint32(byteRange.Length)})
		if err := writeFull(conn, frame[:]); err != nil {
			return err
		}
		if err := sendTLSChunk(ctx, conn, input, lane, byteRange, buffer, counters); err != nil {
			return err
		}
	}
}

func sendTLSChunk(ctx context.Context, conn io.Writer, input io.ReaderAt, lane int, byteRange ByteRange, buffer []byte, counters *tlsTransferCounters) error {
	remaining := byteRange.Length
	offset := byteRange.Offset
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := min(int64(len(buffer)), remaining)
		n, readErr := input.ReadAt(buffer[:want], offset)
		if n > 0 {
			counters.readCalls.Add(1)
			counters.readBytes.Add(int64(n))
			written, err := writeTLSChunkPayload(conn, buffer[:n], lane, counters)
			if err != nil {
				return err
			}
			offset += int64(written)
			remaining -= int64(written)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeTLSChunkPayload(conn io.Writer, payload []byte, lane int, counters *tlsTransferCounters) (int, error) {
	written := 0
	for written < len(payload) {
		count, err := conn.Write(payload[written:])
		if count > 0 {
			counters.writeCalls.Add(1)
			counters.writeBytes.Add(int64(count))
			counters.recordCommitted(lane, count, time.Now())
			written += count
		}
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func receiveTLSFramedPayloads(ctx context.Context, lanes []tlsAcceptedLane, output io.WriterAt, total int64, counters *tlsTransferCounters) error {
	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tracker := newTLSChunkTracker(total)
	errCh := make(chan error, len(lanes))
	var workers sync.WaitGroup
	workers.Add(len(lanes))
	for _, accepted := range lanes {
		go func(accepted tlsAcceptedLane) {
			defer workers.Done()
			if err := receiveTLSFramedLane(receiveCtx, accepted, output, tracker, counters); err != nil {
				offerTLSError(errCh, fmt.Errorf("lane %d payload: %w", accepted.header.Lane, err))
				cancel()
				for _, lane := range lanes {
					_ = lane.conn.SetDeadline(time.Now())
				}
			}
		}(accepted)
	}
	workers.Wait()
	close(errCh)
	if err := joinTLSErrors(errCh); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return tracker.validateComplete()
}

func receiveTLSFramedLane(ctx context.Context, accepted tlsAcceptedLane, output io.WriterAt, tracker *tlsChunkTracker, counters *tlsTransferCounters) error {
	buffer := make([]byte, int(TLSChunkSize))
	for {
		var rawHeader [TLSChunkHeaderSize]byte
		if _, err := io.ReadFull(accepted.conn, rawHeader[:]); err != nil {
			return err
		}
		header, err := DecodeTLSChunkHeader(rawHeader[:])
		if err != nil {
			return err
		}
		if header.Length == 0 {
			if header.Offset != 0 {
				return errors.New("end frame offset must be zero")
			}
			return nil
		}
		if err := tracker.claim(header); err != nil {
			return err
		}
		if err := receiveTLSChunk(ctx, accepted.conn, output, int(accepted.header.Lane), header, buffer, counters); err != nil {
			return err
		}
	}
}

func receiveTLSChunk(ctx context.Context, conn io.Reader, output io.WriterAt, lane int, header TLSChunkHeader, buffer []byte, counters *tlsTransferCounters) error {
	offset := int64(header.Offset)
	remaining := int64(header.Length)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := min(int64(len(buffer)), remaining)
		n, readErr := conn.Read(buffer[:want])
		if n > 0 {
			counters.readCalls.Add(1)
			counters.readBytes.Add(int64(n))
			written, writeErr := output.WriteAt(buffer[:n], offset)
			if written > 0 {
				counters.writeCalls.Add(1)
				counters.writeBytes.Add(int64(written))
				counters.recordCommitted(lane, written, time.Now())
				offset += int64(written)
				remaining -= int64(written)
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
