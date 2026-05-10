// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var errExternalStripedDuplicateChunk = errors.New("duplicate striped chunk sequence")

const externalStripedFrameHeaderSize = 12

type externalStripedChunk struct {
	seq  uint64
	data []byte
}

type externalStripedReadResult struct {
	chunk externalStripedChunk
	done  bool
	err   error
}

func sendExternalStripedCopy(ctx context.Context, src io.Reader, writers []io.WriteCloser, chunkSize int) error {
	if err := validateExternalStripedArgs(len(writers), chunkSize, "writers"); err != nil {
		return err
	}
	defer closeExternalStripedWriters(writers)

	chunkPool := newExternalStripedChunkPool(chunkSize)
	jobs, errCh, wait := startExternalStripedWriters(writers, chunkPool)
	readErr := sendExternalStripedChunks(ctx, src, jobs, errCh, wait, chunkPool)
	if readErr != nil {
		return readErr
	}
	select {
	case writeErr := <-errCh:
		return writeErr
	default:
	}
	return nil
}

func validateExternalStripedArgs(count int, chunkSize int, name string) error {
	if count == 0 {
		return fmt.Errorf("no striped %s", name)
	}
	if chunkSize < 1 {
		return errors.New("striped chunk size must be positive")
	}
	return nil
}

func newExternalStripedChunkPool(chunkSize int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			buf := make([]byte, chunkSize)
			return &buf
		},
	}
}

func startExternalStripedWriters(writers []io.WriteCloser, chunkPool *sync.Pool) (chan externalStripedChunk, chan error, func()) {
	jobs := make(chan externalStripedChunk, len(writers)*2)
	errCh := make(chan error, len(writers))
	var wg sync.WaitGroup
	for _, writer := range writers {
		wg.Add(1)
		go func(dst io.Writer) {
			defer wg.Done()
			for chunk := range jobs {
				if err := writeExternalStripedChunk(dst, chunk); err != nil {
					putExternalStripedBuffer(chunkPool, chunk.data)
					errCh <- err
					return
				}
				putExternalStripedBuffer(chunkPool, chunk.data)
			}
		}(writer)
	}
	return jobs, errCh, wg.Wait
}

func sendExternalStripedChunks(ctx context.Context, src io.Reader, jobs chan externalStripedChunk, errCh <-chan error, wait func(), chunkPool *sync.Pool) error {
	var seq uint64
	var readErr error
	for {
		if err := ctx.Err(); err != nil {
			readErr = err
			break
		}
		buf := getExternalStripedBuffer(chunkPool)
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			nextSeq, err := sendExternalStripedChunkJob(ctx, jobs, errCh, chunkPool, seq, buf[:n], buf)
			if err != nil {
				close(jobs)
				wait()
				return err
			}
			seq = nextSeq
		} else {
			putExternalStripedBuffer(chunkPool, buf)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		readErr = err
		break
	}

	close(jobs)
	wait()
	return readErr
}

func sendExternalStripedChunkJob(ctx context.Context, jobs chan<- externalStripedChunk, errCh <-chan error, chunkPool *sync.Pool, seq uint64, data []byte, buf []byte) (uint64, error) {
	select {
	case jobs <- externalStripedChunk{seq: seq, data: data}:
		return seq + 1, nil
	case writeErr := <-errCh:
		putExternalStripedBuffer(chunkPool, buf)
		return seq, writeErr
	case <-ctx.Done():
		putExternalStripedBuffer(chunkPool, buf)
		return seq, ctx.Err()
	}
}

func receiveExternalStripedCopy(ctx context.Context, dst io.Writer, readers []io.ReadCloser, chunkSize int) error {
	if err := validateExternalStripedArgs(len(readers), chunkSize, "readers"); err != nil {
		return err
	}
	defer closeExternalStripedReaders(readers)

	chunkPool := newExternalStripedChunkPool(chunkSize)
	results := startExternalStripedReaders(ctx, readers, chunkSize, chunkPool)
	return receiveExternalStripedResults(ctx, dst, len(readers), results, chunkPool)
}

func startExternalStripedReaders(ctx context.Context, readers []io.ReadCloser, chunkSize int, chunkPool *sync.Pool) <-chan externalStripedReadResult {
	results := make(chan externalStripedReadResult, len(readers)*2)
	var wg sync.WaitGroup
	for _, reader := range readers {
		wg.Add(1)
		go func(src io.Reader) {
			defer wg.Done()
			for {
				chunk, err := readExternalStripedChunk(src, chunkSize, chunkPool)
				if errors.Is(err, io.EOF) {
					select {
					case results <- externalStripedReadResult{done: true}:
					case <-ctx.Done():
					}
					return
				}
				select {
				case results <- externalStripedReadResult{chunk: chunk, err: err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}(reader)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func receiveExternalStripedResults(ctx context.Context, dst io.Writer, liveReaders int, results <-chan externalStripedReadResult, chunkPool *sync.Pool) error {
	nextSeq := uint64(0)
	pending := make(map[uint64][]byte)
	for liveReaders > 0 || len(pending) > 0 {
		next, flushed, err := flushExternalStripedPending(dst, pending, nextSeq, chunkPool)
		if err != nil {
			return err
		}
		if flushed {
			nextSeq = next
			continue
		}
		select {
		case result, ok := <-results:
			state, err := handleExternalStripedReadResult(dst, pending, result, ok, nextSeq, liveReaders, chunkPool)
			if err != nil {
				return err
			}
			liveReaders = state.liveReaders
			nextSeq = state.nextSeq
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type externalStripedReceiveState struct {
	liveReaders int
	nextSeq     uint64
}

func flushExternalStripedPending(dst io.Writer, pending map[uint64][]byte, nextSeq uint64, chunkPool *sync.Pool) (uint64, bool, error) {
	chunk, ok := pending[nextSeq]
	if !ok {
		return nextSeq, false, nil
	}
	if _, err := dst.Write(chunk); err != nil {
		putExternalStripedBuffer(chunkPool, chunk)
		return nextSeq, false, err
	}
	putExternalStripedBuffer(chunkPool, chunk)
	delete(pending, nextSeq)
	return nextSeq + 1, true, nil
}

func handleExternalStripedReadResult(dst io.Writer, pending map[uint64][]byte, result externalStripedReadResult, ok bool, nextSeq uint64, liveReaders int, chunkPool *sync.Pool) (externalStripedReceiveState, error) {
	state := externalStripedReceiveState{liveReaders: liveReaders, nextSeq: nextSeq}
	if !ok {
		return state, externalStripedResultsClosedErr(liveReaders)
	}
	if result.done {
		state.liveReaders--
		return state, nil
	}
	if result.err != nil {
		putExternalStripedChunkBuffer(chunkPool, result.chunk)
		return state, result.err
	}
	if result.chunk.seq == nextSeq {
		next, err := writeExternalStripedImmediateChunk(dst, result.chunk, chunkPool, nextSeq)
		state.nextSeq = next
		return state, err
	}
	return state, bufferExternalStripedOutOfOrderChunk(pending, result.chunk, chunkPool)
}

func externalStripedResultsClosedErr(liveReaders int) error {
	if liveReaders > 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func writeExternalStripedImmediateChunk(dst io.Writer, chunk externalStripedChunk, chunkPool *sync.Pool, nextSeq uint64) (uint64, error) {
	if _, err := dst.Write(chunk.data); err != nil {
		putExternalStripedBuffer(chunkPool, chunk.data)
		return nextSeq, err
	}
	putExternalStripedBuffer(chunkPool, chunk.data)
	return nextSeq + 1, nil
}

func bufferExternalStripedOutOfOrderChunk(pending map[uint64][]byte, chunk externalStripedChunk, chunkPool *sync.Pool) error {
	if _, ok := pending[chunk.seq]; ok {
		putExternalStripedBuffer(chunkPool, chunk.data)
		return errExternalStripedDuplicateChunk
	}
	pending[chunk.seq] = chunk.data
	return nil
}

func putExternalStripedChunkBuffer(chunkPool *sync.Pool, chunk externalStripedChunk) {
	if len(chunk.data) > 0 {
		putExternalStripedBuffer(chunkPool, chunk.data)
	}
}

func writeExternalStripedChunk(dst io.Writer, chunk externalStripedChunk) error {
	var header [externalStripedFrameHeaderSize]byte
	binary.BigEndian.PutUint64(header[:8], chunk.seq)
	binary.BigEndian.PutUint32(header[8:], uint32(len(chunk.data)))
	if _, err := dst.Write(header[:]); err != nil {
		return err
	}
	_, err := dst.Write(chunk.data)
	return err
}

func readExternalStripedChunk(src io.Reader, chunkSize int, chunkPool *sync.Pool) (externalStripedChunk, error) {
	var header [externalStripedFrameHeaderSize]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return externalStripedChunk{}, err
	}
	n := int(binary.BigEndian.Uint32(header[8:]))
	if n < 0 || n > chunkSize {
		return externalStripedChunk{}, io.ErrUnexpectedEOF
	}
	buf := getExternalStripedBuffer(chunkPool)
	chunk := externalStripedChunk{
		seq:  binary.BigEndian.Uint64(header[:8]),
		data: buf[:n],
	}
	if _, err := io.ReadFull(src, chunk.data); err != nil {
		putExternalStripedBuffer(chunkPool, buf)
		return externalStripedChunk{}, err
	}
	return chunk, nil
}

func getExternalStripedBuffer(chunkPool *sync.Pool) []byte {
	return *chunkPool.Get().(*[]byte)
}

func putExternalStripedBuffer(chunkPool *sync.Pool, buf []byte) {
	if buf == nil {
		return
	}
	buf = buf[:cap(buf)]
	chunkPool.Put(&buf)
}

func closeExternalStripedWriters(writers []io.WriteCloser) {
	for _, writer := range writers {
		_ = writer.Close()
	}
}

func closeExternalStripedReaders(readers []io.ReadCloser) {
	for _, reader := range readers {
		_ = reader.Close()
	}
}

func newExternalStripedBufferedWriteClosers(conns []net.Conn, chunkSize int) []io.WriteCloser {
	writers := make([]io.WriteCloser, 0, len(conns))
	bufSize := chunkSize + externalStripedFrameHeaderSize
	for _, conn := range conns {
		writers = append(writers, externalStripedBufferedWriteCloser{
			conn: conn,
			buf:  bufio.NewWriterSize(conn, bufSize),
		})
	}
	return writers
}

func newExternalStripedBufferedReadClosers(conns []net.Conn, chunkSize int) []io.ReadCloser {
	readers := make([]io.ReadCloser, 0, len(conns))
	bufSize := chunkSize + externalStripedFrameHeaderSize
	for _, conn := range conns {
		readers = append(readers, externalStripedBufferedReadCloser{
			conn: conn,
			buf:  bufio.NewReaderSize(conn, bufSize),
		})
	}
	return readers
}

type externalStripedBufferedWriteCloser struct {
	conn io.Closer
	buf  *bufio.Writer
}

func (w externalStripedBufferedWriteCloser) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w externalStripedBufferedWriteCloser) Close() error {
	if err := w.buf.Flush(); err != nil {
		_ = w.conn.Close()
		return err
	}
	return w.conn.Close()
}

type externalStripedBufferedReadCloser struct {
	conn io.Closer
	buf  *bufio.Reader
}

func (r externalStripedBufferedReadCloser) Read(p []byte) (int, error) {
	return r.buf.Read(p)
}

func (r externalStripedBufferedReadCloser) Close() error {
	return r.conn.Close()
}
