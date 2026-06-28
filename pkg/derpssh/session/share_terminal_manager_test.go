// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derpssh/tui"
)

func TestRestartableShareTerminalEOFBlocksUntilRestart(t *testing.T) {
	firstOutR, firstOutW := io.Pipe()
	secondOutR, secondOutW := io.Pipe()
	firstIn := &recordingWriter{}
	secondIn := &recordingWriter{}
	starts := 0
	start := func(size pty.Size) (*shareTerminal, error) {
		starts++
		switch starts {
		case 1:
			return &shareTerminal{
				Input:  firstIn,
				Output: firstOutR,
				close:  func() error { return nil },
				wait:   func() error { return nil },
				resize: func(pty.Size) error { return nil },
			}, nil
		case 2:
			if size != (pty.Size{Cols: 100, Rows: 30}) {
				t.Fatalf("restart size = %+v, want 100x30", size)
			}
			return &shareTerminal{
				Input:  secondIn,
				Output: secondOutR,
				close:  func() error { return nil },
				wait:   func() error { return nil },
				resize: func(pty.Size) error { return nil },
			}, nil
		default:
			t.Fatalf("unexpected start %d", starts)
			return nil, nil
		}
	}

	mgr, err := newRestartableShareTerminal(pty.Size{Cols: 80, Rows: 24}, start)
	if err != nil {
		t.Fatalf("newRestartableShareTerminal error = %v", err)
	}
	defer mgr.Close()

	firstWrite := writePipeAsync(firstOutW, "one")
	buf := make([]byte, 8)
	n, err := mgr.Output.Read(buf)
	<-firstWrite
	if err != nil || string(buf[:n]) != "one" {
		t.Fatalf("first read = %q, %v; want one, nil", string(buf[:n]), err)
	}

	readAfterRestart := make(chan terminalReadResult, 1)
	go func() {
		n, err := mgr.Output.Read(buf)
		readAfterRestart <- terminalReadResult{Data: string(buf[:n]), Err: err}
	}()
	_ = firstOutW.Close()
	event := <-mgr.Events()
	if event.Kind != shareTerminalShellExited {
		t.Fatalf("event kind = %v, want shell exited", event.Kind)
	}
	select {
	case result := <-readAfterRestart:
		t.Fatalf("read returned before restart: %+v", result)
	case <-time.After(20 * time.Millisecond):
	}

	if err := mgr.Restart(pty.Size{Cols: 100, Rows: 30}); err != nil {
		t.Fatalf("Restart error = %v", err)
	}
	secondWrite := writePipeAsync(secondOutW, "two")
	result := <-readAfterRestart
	<-secondWrite
	if result.Err != nil || result.Data != "two" {
		t.Fatalf("second read = %q, %v; want two, nil", result.Data, result.Err)
	}
}

func TestRestartableShareTerminalWriteUsesActiveGeneration(t *testing.T) {
	firstOutR, firstOutW := io.Pipe()
	secondOutR, _ := io.Pipe()
	firstIn := &recordingWriter{}
	secondIn := &recordingWriter{}
	starts := 0
	start := func(pty.Size) (*shareTerminal, error) {
		starts++
		if starts == 1 {
			return &shareTerminal{Input: firstIn, Output: firstOutR, close: func() error { return nil }, wait: func() error { return nil }}, nil
		}
		return &shareTerminal{Input: secondIn, Output: secondOutR, close: func() error { return nil }, wait: func() error { return nil }}, nil
	}

	mgr, err := newRestartableShareTerminal(pty.Size{Cols: 80, Rows: 24}, start)
	if err != nil {
		t.Fatalf("newRestartableShareTerminal error = %v", err)
	}
	defer mgr.Close()

	if _, err := mgr.Input.Write([]byte("before")); err != nil {
		t.Fatalf("first write error = %v", err)
	}
	if got := firstIn.String(); got != "before" {
		t.Fatalf("first input = %q, want before", got)
	}

	go func() {
		_, _ = mgr.Output.Read(make([]byte, 1))
	}()
	_ = firstOutW.Close()
	<-mgr.Events()
	if _, err := mgr.Input.Write([]byte("between")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write while exited error = %v, want ErrClosedPipe", err)
	}
	if err := mgr.Restart(pty.Size{Cols: 80, Rows: 24}); err != nil {
		t.Fatalf("Restart error = %v", err)
	}
	if _, err := mgr.Input.Write([]byte("after")); err != nil {
		t.Fatalf("second write error = %v", err)
	}
	if got := secondIn.String(); got != "after" {
		t.Fatalf("second input = %q, want after", got)
	}
}

func TestShareRestartShellCallbackRestartsWithConsoleSize(t *testing.T) {
	var starts []pty.Size
	start := func(size pty.Size) (*shareTerminal, error) {
		starts = append(starts, size)
		outR, _ := io.Pipe()
		return &shareTerminal{
			Input:  &recordingWriter{},
			Output: outR,
			close:  func() error { return outR.Close() },
			wait:   func() error { return nil },
			resize: func(pty.Size) error { return nil },
		}, nil
	}
	manager, err := newRestartableShareTerminal(pty.Size{Cols: 80, Rows: 24}, start)
	if err != nil {
		t.Fatalf("newRestartableShareTerminal error = %v", err)
	}
	defer manager.Close()
	console := newHeadlessTUIConsole(tui.ModeHost, 120, 40, tui.NewVTTerminalPane(120, 40))

	restart := newShareRestartShellCallback(console, manager, nil)
	if err := restart(context.Background()); err != nil {
		t.Fatalf("restart callback error = %v", err)
	}

	want := console.TerminalSize()
	if len(starts) != 2 {
		t.Fatalf("starts = %d, want initial plus restart", len(starts))
	}
	if starts[1] != want {
		t.Fatalf("restart size = %+v, want console terminal size %+v", starts[1], want)
	}
	view := console.View()
	if !strings.Contains(view, "shell restarted") {
		t.Fatalf("console view missing restart status:\n%s", view)
	}
}

type recordingWriter struct {
	data []byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *recordingWriter) String() string {
	return string(w.data)
}

type terminalReadResult struct {
	Data string
	Err  error
}

func writePipeAsync(w *io.PipeWriter, body string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte(body))
		close(done)
	}()
	return done
}
