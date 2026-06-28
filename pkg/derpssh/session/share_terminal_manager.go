// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"io"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/pty"
)

type shareTerminalEventKind string

const (
	shareTerminalShellExited shareTerminalEventKind = "shell-exited"
)

type shareTerminalEvent struct {
	Kind shareTerminalEventKind
	Err  error
}

type shareTerminalStarter func(pty.Size) (*shareTerminal, error)

type restartableShareTerminal struct {
	Input  io.Writer
	Output io.Reader

	start shareTerminalStarter

	mu      sync.Mutex
	cond    *sync.Cond
	current *shareTerminal
	closed  bool
	events  chan shareTerminalEvent
}

func newRestartableShareTerminal(size pty.Size, start shareTerminalStarter) (*restartableShareTerminal, error) {
	if start == nil {
		start = startShareTerminal
	}
	m := &restartableShareTerminal{
		start:  start,
		events: make(chan shareTerminalEvent, 8),
	}
	m.cond = sync.NewCond(&m.mu)
	m.Input = restartableTerminalInput{manager: m}
	m.Output = restartableTerminalOutput{manager: m}
	if err := m.Restart(size); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *restartableShareTerminal) Restart(size pty.Size) error {
	next, err := m.start(size)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = next.Close()
		go func() { _ = next.Wait() }()
		return io.ErrClosedPipe
	}
	old := m.current
	m.current = next
	m.cond.Broadcast()
	m.mu.Unlock()
	closeShareTerminalAsync(old)
	return nil
}

func (m *restartableShareTerminal) Resize(size pty.Size) error {
	m.mu.Lock()
	current := m.current
	m.mu.Unlock()
	if current == nil {
		return nil
	}
	return current.Resize(size)
}

func (m *restartableShareTerminal) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	current := m.current
	m.current = nil
	m.cond.Broadcast()
	m.mu.Unlock()
	if current == nil {
		return nil
	}
	return current.Close()
}

func (m *restartableShareTerminal) Wait() error {
	m.mu.Lock()
	current := m.current
	m.mu.Unlock()
	if current == nil {
		return nil
	}
	return current.Wait()
}

func (m *restartableShareTerminal) Events() <-chan shareTerminalEvent {
	return m.events
}

func (m *restartableShareTerminal) active() (*shareTerminal, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for m.current == nil && !m.closed {
		m.cond.Wait()
	}
	return m.current, m.closed
}

func (m *restartableShareTerminal) markExited(term *shareTerminal, err error) {
	if term == nil {
		return
	}
	m.mu.Lock()
	if m.current != term {
		m.mu.Unlock()
		return
	}
	m.current = nil
	m.cond.Broadcast()
	m.mu.Unlock()
	go func() { _ = term.Wait() }()
	select {
	case m.events <- shareTerminalEvent{Kind: shareTerminalShellExited, Err: err}:
	default:
	}
}

type restartableTerminalInput struct {
	manager *restartableShareTerminal
}

func (w restartableTerminalInput) Write(p []byte) (int, error) {
	w.manager.mu.Lock()
	current := w.manager.current
	closed := w.manager.closed
	w.manager.mu.Unlock()
	if closed || current == nil || current.Input == nil {
		return 0, io.ErrClosedPipe
	}
	return current.Input.Write(p)
}

type restartableTerminalOutput struct {
	manager *restartableShareTerminal
}

func (r restartableTerminalOutput) Read(p []byte) (int, error) {
	for {
		current, closed := r.manager.active()
		if closed {
			return 0, io.EOF
		}
		if current == nil || current.Output == nil {
			r.manager.markExited(current, io.ErrClosedPipe)
			continue
		}
		n, err := current.Output.Read(p)
		if err == nil {
			return n, nil
		}
		if n > 0 {
			r.manager.markExited(current, err)
			return n, nil
		}
		r.manager.markExited(current, err)
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			continue
		}
	}
}

func closeShareTerminalAsync(term *shareTerminal) {
	if term == nil {
		return
	}
	_ = term.Close()
	go func() { _ = term.Wait() }()
}
