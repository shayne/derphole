// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestTerminalLifecycleRestoresExactlyOnce(t *testing.T) {
	var out bytes.Buffer
	program := &recordingTeaProgram{}
	lifecycle := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Program: program,
		Restore: []byte("RESTORE"),
	})

	lifecycle.End(CloseReason{Code: "host_quit", Message: "host quit"})
	lifecycle.End(CloseReason{Code: "stop", Message: "stop called"})
	lifecycle.End(CloseReason{Code: "run_done", Message: "program returned"})

	if got := strings.Count(out.String(), "RESTORE"); got != 1 {
		t.Fatalf("restore writes = %d, want 1; output %q", got, out.String())
	}
	if got := program.quitCalls; got != 1 {
		t.Fatalf("program Quit calls = %d, want 1", got)
	}
}

func TestTerminalLifecycleWritesRestoreBeforeFinalReason(t *testing.T) {
	var out bytes.Buffer
	lifecycle := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Restore: []byte("\x1b[?1006l\x1b[?25h\x1b[0m"),
	})

	lifecycle.End(CloseReason{Code: "guest_quit", Message: "session ended: guest quit"})
	lifecycle.WriteFinalReason()

	got := out.String()
	restoreAt := strings.Index(got, "\x1b[?1006l")
	reasonAt := strings.Index(got, "session ended: guest quit")
	if restoreAt < 0 || reasonAt < 0 || restoreAt > reasonAt {
		t.Fatalf("restore must precede final reason, output %q", got)
	}
}

type recordingTeaProgram struct {
	quitCalls int
}

func (p *recordingTeaProgram) Send(tea.Msg) {}

func (p *recordingTeaProgram) Run() (tea.Model, error) {
	return nil, nil
}

func (p *recordingTeaProgram) Quit() {
	p.quitCalls++
}

func (p *recordingTeaProgram) Wait() {}
