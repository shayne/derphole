// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
)

const terminalReplayLimit = 128 * 1024
const terminalPrimaryDeviceAttributesResponse = "\x1b[?1;2c"
const terminalSecondaryDeviceAttributesResponse = "\x1b[>0;0;0c"

var terminalQueryPattern = regexp.MustCompile("\x1b\\[(>?)(0?)c")

type terminalFanout struct {
	src            io.Reader
	local          io.Writer
	responseWriter io.Writer
	responseTail   string
	limit          int

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

func (f *terminalFanout) setTerminalResponseWriter(w io.Writer) {
	f.mu.Lock()
	f.responseWriter = w
	f.responseTail = ""
	f.mu.Unlock()
}

func (f *terminalFanout) Run(ctx context.Context) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := f.src.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			// The host shell talks to derpssh's internal terminal surface, so
			// answer terminal identity queries before rendering or broadcasting.
			f.respondToTerminalQueries(data)
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

func (f *terminalFanout) respondToTerminalQueries(data []byte) {
	f.mu.Lock()
	writer := f.responseWriter
	input := f.responseTail + string(data)
	responses := terminalQueryResponses(input)
	f.responseTail = incompleteTerminalQueryTail(input)
	f.mu.Unlock()

	if writer == nil {
		return
	}
	for _, response := range responses {
		_, _ = io.WriteString(writer, response)
	}
}

func terminalQueryResponses(output string) []string {
	matches := terminalQueryPattern.FindAllStringSubmatch(output, -1)
	var responses []string
	for _, match := range matches {
		if len(match) > 1 && match[1] == ">" {
			responses = append(responses, terminalSecondaryDeviceAttributesResponse)
		} else {
			responses = append(responses, terminalPrimaryDeviceAttributesResponse)
		}
	}
	return responses
}

func incompleteTerminalQueryTail(output string) string {
	if strings.HasSuffix(output, "\x1b") {
		return "\x1b"
	}
	idx := strings.LastIndex(output, "\x1b[")
	if idx == -1 {
		return ""
	}
	tail := output[idx:]
	switch tail {
	case "\x1b[", "\x1b[0", "\x1b[>", "\x1b[>0":
		return tail
	default:
		return ""
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
