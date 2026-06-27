// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"sync"
)

const terminalReplayLimit = 128 * 1024

type terminalFanout struct {
	src   io.Reader
	local io.Writer
	limit int

	mu     sync.Mutex
	replay []byte
	subs   map[*terminalFanoutSubscriber]struct{}
	closed bool
}

type terminalFanoutSubscriber struct {
	reader *terminalFanoutReader
}

func newTerminalFanout(src io.Reader, local io.Writer) *terminalFanout {
	return &terminalFanout{
		src:   src,
		local: local,
		limit: terminalReplayLimit,
		subs:  make(map[*terminalFanoutSubscriber]struct{}),
	}
}

func (f *terminalFanout) Run(ctx context.Context) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := f.src.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if f.local != nil {
				if _, writeErr := f.local.Write(data); writeErr != nil {
					f.closeSubscribers()
					return writeErr
				}
			}
			f.broadcast(data)
		}
		if err != nil {
			f.closeSubscribers()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (f *terminalFanout) Reader() io.ReadCloser {
	reader := newTerminalFanoutReader(f)
	sub := &terminalFanoutSubscriber{reader: reader}
	reader.sub = sub

	f.mu.Lock()
	reader.appendLocked(f.replay)
	if f.closed {
		reader.closeLocked()
	} else {
		f.subs[sub] = struct{}{}
	}
	f.mu.Unlock()

	return reader
}

func (f *terminalFanout) LazyReader() io.ReadCloser {
	return &lazyTerminalFanoutReader{fanout: f}
}

type lazyTerminalFanoutReader struct {
	fanout *terminalFanout
	once   sync.Once
	r      io.ReadCloser
}

func (r *lazyTerminalFanoutReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		r.r = r.fanout.Reader()
	})
	return r.r.Read(p)
}

func (r *lazyTerminalFanoutReader) Close() error {
	if r.r == nil {
		return nil
	}
	return r.r.Close()
}

func (f *terminalFanout) broadcast(data []byte) {
	f.mu.Lock()
	f.appendReplayLocked(data)
	subs := make([]*terminalFanoutSubscriber, 0, len(f.subs))
	for sub := range f.subs {
		subs = append(subs, sub)
	}
	f.mu.Unlock()

	for _, sub := range subs {
		sub.reader.append(data)
	}
}

func (f *terminalFanout) appendReplayLocked(data []byte) {
	if f.limit <= 0 {
		f.replay = nil
		return
	}
	f.replay = append(f.replay, data...)
	if len(f.replay) <= f.limit {
		return
	}
	tail := f.replay[len(f.replay)-f.limit:]
	f.replay = append([]byte(nil), tail...)
}

func (f *terminalFanout) closeSubscribers() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	subs := make([]*terminalFanoutSubscriber, 0, len(f.subs))
	for sub := range f.subs {
		subs = append(subs, sub)
		delete(f.subs, sub)
	}
	f.mu.Unlock()

	for _, sub := range subs {
		sub.reader.closeFromFanout()
	}
}

func (f *terminalFanout) removeSubscriber(sub *terminalFanoutSubscriber) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.subs, sub)
}

type terminalFanoutReader struct {
	fanout *terminalFanout
	sub    *terminalFanoutSubscriber
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newTerminalFanoutReader(fanout *terminalFanout) *terminalFanoutReader {
	r := &terminalFanoutReader{fanout: fanout}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *terminalFanoutReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.buf) == 0 && !r.closed {
		r.cond.Wait()
	}
	if len(r.buf) == 0 && r.closed {
		return 0, io.EOF
	}
	n := copy(p, r.buf)
	copy(r.buf, r.buf[n:])
	r.buf = r.buf[:len(r.buf)-n]
	return n, nil
}

func (r *terminalFanoutReader) Close() error {
	if r.fanout != nil && r.sub != nil {
		r.fanout.removeSubscriber(r.sub)
	}
	r.mu.Lock()
	r.closeLocked()
	r.mu.Unlock()
	return nil
}

func (r *terminalFanoutReader) append(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appendLocked(data)
}

func (r *terminalFanoutReader) appendLocked(data []byte) {
	if len(data) == 0 || r.closed {
		return
	}
	r.buf = append(r.buf, data...)
	r.cond.Signal()
}

func (r *terminalFanoutReader) closeFromFanout() {
	r.mu.Lock()
	r.closeLocked()
	r.mu.Unlock()
}

func (r *terminalFanoutReader) closeLocked() {
	r.closed = true
	r.cond.Broadcast()
}
