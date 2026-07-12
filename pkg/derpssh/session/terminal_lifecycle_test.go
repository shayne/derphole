// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/brand"
)

func TestTerminalLifecycleRestoresExactlyOnce(t *testing.T) {
	var out bytes.Buffer
	lifecycle := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Restore: []byte("RESTORE"),
	})

	lifecycle.End(CloseReason{Code: "host_quit", Message: "host quit"})
	lifecycle.End(CloseReason{Code: "stop", Message: "stop called"})
	lifecycle.End(CloseReason{Code: "run_done", Message: "program returned"})

	if got := strings.Count(out.String(), "RESTORE"); got != 1 {
		t.Fatalf("restore writes = %d, want 1; output %q", got, out.String())
	}
}

func TestTerminalLifecycleWritesRestoreBeforeFinalReason(t *testing.T) {
	var out bytes.Buffer
	lifecycle := newTerminalLifecycle(terminalLifecycleOptions{
		Output:  &out,
		Restore: []byte("\x1b[?1006l\x1b[?25h\x1b[0m"),
		IsTTY:   true,
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

func TestCleanExitTTYOutputClearsBeforeWordmarkAndReason(t *testing.T) {
	var out bytes.Buffer

	writeCleanExitMessage(&out, "session ended: host quit", true)

	got := out.String()
	normalized := strings.ReplaceAll(got, "\r\n", "\n")
	restoreAt := strings.Index(normalized, "\x1b[?1049l")
	wordmarkAt := strings.Index(normalized, brand.Wordmark())
	reasonAt := strings.Index(normalized, "derpssh: session ended: host quit")
	if restoreAt < 0 {
		t.Fatalf("clean exit output missing terminal restore: %q", got)
	}
	if wordmarkAt < 0 {
		t.Fatalf("clean exit output missing derpssh wordmark: %q", got)
	}
	if reasonAt < 0 {
		t.Fatalf("clean exit output missing final reason: %q", got)
	}
	if !(restoreAt < wordmarkAt && wordmarkAt < reasonAt) {
		t.Fatalf("clean exit output order = restore %d, wordmark %d, reason %d in %q", restoreAt, wordmarkAt, reasonAt, got)
	}
}

func TestCleanExitNonTTYOutputKeepsPlainReason(t *testing.T) {
	var out bytes.Buffer

	writeCleanExitMessage(&out, "session ended: host quit", false)

	if got, want := out.String(), "derpssh: session ended: host quit\n"; got != want {
		t.Fatalf("clean non-tty output = %q, want %q", got, want)
	}
}
