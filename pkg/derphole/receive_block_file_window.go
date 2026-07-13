// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"runtime"
	"sync"
	"sync/atomic"
)

const receiveBlockFileAdviceChunk = int64(4 << 20)

type receiveBlockFileWindow struct {
	size      int64
	prepare   func(start, end int64) error
	release   func(start, end int64) error
	requested atomic.Int64
	notify    chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	mu        sync.Mutex
	prepared  int64
	released  int64
	processed int64
	failure   error
}

func newReceiveBlockFileWindow(
	size int64,
	prepared int64,
	prepare func(start, end int64) error,
	release func(start, end int64) error,
) *receiveBlockFileWindow {
	w := &receiveBlockFileWindow{
		size:     size,
		prepare:  prepare,
		release:  release,
		notify:   make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		prepared: prepared,
	}
	go w.run()
	return w
}

func (w *receiveBlockFileWindow) request(highestEnd int64) {
	if w == nil || highestEnd <= 0 {
		return
	}
	highestEnd = min(highestEnd, w.size)
	for {
		current := w.requested.Load()
		if highestEnd <= current || w.requested.CompareAndSwap(current, highestEnd) {
			break
		}
	}
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

func (w *receiveBlockFileWindow) run() {
	defer close(w.done)
	for {
		select {
		case <-w.notify:
			if err := w.advanceRequested(); err != nil {
				w.setError(err)
				return
			}
		case <-w.stop:
			return
		}
	}
}

func (w *receiveBlockFileWindow) advanceRequested() error {
	for {
		highestEnd := w.requested.Load()
		w.mu.Lock()
		processed := w.processed
		w.mu.Unlock()
		if highestEnd <= processed {
			return nil
		}
		if err := w.advance(highestEnd); err != nil {
			return err
		}
		w.mu.Lock()
		w.processed = highestEnd
		w.mu.Unlock()
		if w.requested.Load() <= highestEnd {
			return nil
		}
	}
}

func (w *receiveBlockFileWindow) advance(highestEnd int64) error {
	w.mu.Lock()
	prepared := w.prepared
	released := w.released
	w.mu.Unlock()

	if highestEnd > receiveBlockFileReleaseBehind {
		target := receiveBlockFileAlignDownTo(highestEnd-receiveBlockFileReleaseBehind, receiveBlockFileReleaseStep)
		if target > released {
			if err := applyReceiveBlockFileAdvice(w.release, released, target); err != nil {
				return err
			}
			w.mu.Lock()
			w.released = target
			w.mu.Unlock()
		}
	}
	if highestEnd+receiveBlockFilePrepareThreshold >= prepared && prepared < w.size {
		target := min(w.size, receiveBlockFileAlignUp(highestEnd+receiveBlockFilePrepareAhead))
		if target > prepared {
			if err := applyReceiveBlockFileAdvice(w.prepare, prepared, target); err != nil {
				return err
			}
			prepared = target
			w.mu.Lock()
			w.prepared = prepared
			w.mu.Unlock()
		}
	}
	return nil
}

func applyReceiveBlockFileAdvice(advice func(start, end int64) error, start, end int64) error {
	for start < end {
		chunkEnd := min(end, start+receiveBlockFileAdviceChunk)
		if err := advice(start, chunkEnd); err != nil {
			return err
		}
		start = chunkEnd
		runtime.Gosched()
	}
	return nil
}

func (w *receiveBlockFileWindow) setError(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.failure == nil {
		w.failure = err
	}
	w.mu.Unlock()
}

func (w *receiveBlockFileWindow) err() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failure
}

func (w *receiveBlockFileWindow) state() (prepared, released int64) {
	if w == nil {
		return 0, 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prepared, w.released
}

func (w *receiveBlockFileWindow) close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() { close(w.stop) })
	<-w.done
	return w.err()
}
