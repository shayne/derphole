// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
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
	if len(writers) == 0 {
		return errors.New("no striped writers")
	}
	if chunkSize < 1 {
		return errors.New("striped chunk size must be positive")
	}
	defer closeExternalStripedWriters(writers)

	jobs := make(chan externalStripedChunk, len(writers)*2)
	errCh := make(chan error, len(writers))
	chunkPool := &sync.Pool{
		New: func() any {
			buf := make([]byte, chunkSize)
			return &buf
		},
	}
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
			select {
			case jobs <- externalStripedChunk{seq: seq, data: buf[:n]}:
				seq++
			case writeErr := <-errCh:
				putExternalStripedBuffer(chunkPool, buf)
				close(jobs)
				wg.Wait()
				return writeErr
			case <-ctx.Done():
				putExternalStripedBuffer(chunkPool, buf)
				close(jobs)
				wg.Wait()
				return ctx.Err()
			}
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
	wg.Wait()
	select {
	case writeErr := <-errCh:
		return writeErr
	default:
	}
	return readErr
}

func receiveExternalStripedCopy(ctx context.Context, dst io.Writer, readers []io.ReadCloser, chunkSize int) error {
	if len(readers) == 0 {
		return errors.New("no striped readers")
	}
	if chunkSize < 1 {
		return errors.New("striped chunk size must be positive")
	}
	defer closeExternalStripedReaders(readers)

	results := make(chan externalStripedReadResult, len(readers)*2)
	chunkPool := &sync.Pool{
		New: func() any {
			buf := make([]byte, chunkSize)
			return &buf
		},
	}
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

	nextSeq := uint64(0)
	pending := make(map[uint64][]byte)
	liveReaders := len(readers)
	for liveReaders > 0 || len(pending) > 0 {
		if chunk, ok := pending[nextSeq]; ok {
			if _, err := dst.Write(chunk); err != nil {
				putExternalStripedBuffer(chunkPool, chunk)
				return err
			}
			putExternalStripedBuffer(chunkPool, chunk)
			delete(pending, nextSeq)
			nextSeq++
			continue
		}
		select {
		case result, ok := <-results:
			if !ok {
				if liveReaders > 0 {
					return io.ErrUnexpectedEOF
				}
				continue
			}
			if result.done {
				liveReaders--
				continue
			}
			if result.err != nil {
				if len(result.chunk.data) > 0 {
					putExternalStripedBuffer(chunkPool, result.chunk.data)
				}
				return result.err
			}
			if result.chunk.seq == nextSeq {
				if _, err := dst.Write(result.chunk.data); err != nil {
					putExternalStripedBuffer(chunkPool, result.chunk.data)
					return err
				}
				putExternalStripedBuffer(chunkPool, result.chunk.data)
				nextSeq++
				continue
			}
			if _, ok := pending[result.chunk.seq]; ok {
				putExternalStripedBuffer(chunkPool, result.chunk.data)
				return errExternalStripedDuplicateChunk
			}
			pending[result.chunk.seq] = result.chunk.data
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
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
