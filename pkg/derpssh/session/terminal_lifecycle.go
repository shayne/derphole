// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"io"
	"sync"
)

type CloseReason struct {
	Code    string
	Message string
}

type terminalLifecycleOptions struct {
	Output  io.Writer
	Program teaProgram
	Restore []byte
	IsTTY   bool
}

type TerminalLifecycle struct {
	output  io.Writer
	program teaProgram
	restore []byte
	isTTY   bool

	mu          sync.Mutex
	reason      CloseReason
	ended       bool
	restoreOnce sync.Once
}

func newTerminalLifecycle(opts terminalLifecycleOptions) *TerminalLifecycle {
	return &TerminalLifecycle{
		output:  opts.Output,
		program: opts.Program,
		restore: append([]byte(nil), opts.Restore...),
		isTTY:   opts.IsTTY,
	}
}

func (l *TerminalLifecycle) End(reason CloseReason) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.ended {
		l.reason = reason
		l.ended = true
	}
	l.mu.Unlock()

	l.restoreOnce.Do(func() {
		if l.output != nil && len(l.restore) > 0 {
			_, _ = l.output.Write(l.restore)
		}
		if l.program != nil {
			l.program.Quit()
		}
	})
}

func (l *TerminalLifecycle) WriteFinalReason() {
	if l == nil {
		return
	}
	l.mu.Lock()
	reason := l.reason
	l.mu.Unlock()
	if l.output != nil && reason.Message != "" {
		_, _ = fmt.Fprintf(l.output, "\r\nderpssh: %s\r\n", reason.Message)
	}
}
