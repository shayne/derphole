// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"io"
	"sync/atomic"
)

type byteCountingReadCloser struct {
	src io.ReadCloser
	n   atomic.Int64
}

func newByteCountingReadCloser(src io.ReadCloser) *byteCountingReadCloser {
	return &byteCountingReadCloser{src: src}
}

func (r *byteCountingReadCloser) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.n.Add(int64(n))
	}
	return n, err
}

func (r *byteCountingReadCloser) Close() error {
	return r.src.Close()
}

func (r *byteCountingReadCloser) Count() int64 {
	if r == nil {
		return 0
	}
	return r.n.Load()
}

type byteCountingWriteCloser struct {
	dst io.WriteCloser
	n   atomic.Int64
}

func newByteCountingWriteCloser(dst io.WriteCloser) *byteCountingWriteCloser {
	return &byteCountingWriteCloser{dst: dst}
}

func (w *byteCountingWriteCloser) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.n.Add(int64(n))
	}
	return n, err
}

func (w *byteCountingWriteCloser) Close() error {
	return w.dst.Close()
}

func (w *byteCountingWriteCloser) Count() int64 {
	if w == nil {
		return 0
	}
	return w.n.Load()
}
