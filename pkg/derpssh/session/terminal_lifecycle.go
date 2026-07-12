// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/brand"
)

type CloseReason struct {
	Code    string
	Message string
}

type terminalLifecycleOptions struct {
	Output  io.Writer
	Restore []byte
	IsTTY   bool
}

type TerminalLifecycle struct {
	output  io.Writer
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
	})
}

func (l *TerminalLifecycle) WriteFinalReason() {
	if l == nil {
		return
	}
	l.mu.Lock()
	reason := l.reason
	l.mu.Unlock()
	writeCleanExitMessage(l.output, reason.Message, l.isTTY)
}

func reportSessionCloseReason(w io.Writer, reason string) {
	reason = strings.TrimSpace(reason)
	if w == nil || reason == "" {
		return
	}
	writeCleanExitMessage(w, "session ended: "+reason, writerIsTerminal(w))
}

func writeCleanExitMessage(w io.Writer, message string, tty bool) {
	message = strings.TrimSpace(message)
	if w == nil || message == "" {
		return
	}
	if !tty {
		_, _ = fmt.Fprintf(w, "derpssh: %s\n", message)
		return
	}
	writeTerminalRestore(w)
	for _, line := range brand.WordmarkLines() {
		_, _ = io.WriteString(w, line+"\r\n")
	}
	_, _ = io.WriteString(w, "\r\n")
	_, _ = fmt.Fprintf(w, "derpssh: %s\r\n", message)
}

func writerIsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok || file == nil {
		return false
	}
	return isTerminalFD(file.Fd())
}
