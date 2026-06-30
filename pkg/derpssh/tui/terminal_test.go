// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

func TestVTTerminalPanePreservesANSIStyleOutput(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("plain \x1b[31mred\x1b[0m\x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	stripped := ansiPattern.ReplaceAllString(view, "")
	if !strings.Contains(stripped, "plain red") {
		t.Fatalf("View() = %q, want rendered ANSI text", view)
	}
	if !strings.Contains(view, "\x1b[31mred\x1b[0m") {
		t.Fatalf("View() stripped terminal color styling: %q", view)
	}
	if width := visibleWidth(strings.Split(view, "\n")[0]); width != len("plain red") {
		t.Fatalf("first line visible width = %d, want %d: %q", width, len("plain red"), view)
	}
}

func TestVTTerminalPanePreservesStyledSpaces(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("load \x1b[48;5;34m  \x1b[0m done")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	if !strings.Contains(view, "\x1b[48;5;34m  \x1b[0m") {
		t.Fatalf("View() stripped styled spaces used by rich TUIs: %q", view)
	}
	if !strings.Contains(view, "load ") || !strings.Contains(view, " done") {
		t.Fatalf("View() missing plain text around styled cells: %q", view)
	}
}

func TestVTTerminalPaneSuppressesUnderlineOnlyBlankCells(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("vim\x1b[4m          \x1b[0m\x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	firstLine := strings.Split(view, "\n")[0]
	if strings.Contains(firstLine, "\x1b[4m") {
		t.Fatalf("View() rendered underline-only blank cells as visible rules: %q", view)
	}
	if width := visibleWidth(firstLine); width != len("vim") {
		t.Fatalf("first line visible width = %d, want %d: %q", width, len("vim"), view)
	}
}

func TestVTTerminalPaneHandlesCursorMovement(t *testing.T) {
	pane := NewVTTerminalPane(10, 3)

	if _, err := pane.Write([]byte("abc\x1b[2DZ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	stripped := ansiPattern.ReplaceAllString(view, "")
	if !strings.Contains(stripped, "aZc") {
		t.Fatalf("View() = %q, want cursor movement to overwrite middle cell", view)
	}
}

func TestTrackMouseModeSGREnableDisable(t *testing.T) {
	mode := TrackMouseMode(MouseMode{}, []byte("\x1b[?1000h\x1b[?1006h"))
	if !mode.Enabled || !mode.SGR {
		t.Fatalf("enable mode = %+v, want enabled SGR", mode)
	}

	mode = TrackMouseMode(mode, []byte("\x1b[?1006l"))
	if !mode.Enabled || mode.SGR {
		t.Fatalf("disable SGR mode = %+v, want enabled non-SGR", mode)
	}

	mode = TrackMouseMode(mode, []byte("\x1b[?1000l"))
	if mode.Enabled || mode.SGR {
		t.Fatalf("disable mouse mode = %+v, want disabled", mode)
	}
}

func TestVTTerminalPaneTracksSplitSGRMouseMode(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("\x1b[?100")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if mode := pane.MouseMode(); mode.Enabled || mode.SGR {
		t.Fatalf("MouseMode after partial sequence = %+v, want disabled", mode)
	}

	if _, err := pane.Write([]byte("6h")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}

	if mode := pane.MouseMode(); !mode.Enabled || !mode.SGR {
		t.Fatalf("MouseMode after split SGR enable = %+v, want enabled SGR", mode)
	}
}

func TestVTTerminalPaneTracksApplicationCursorMode(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("\x1b[?1h")); err != nil {
		t.Fatalf("enable Write() error = %v", err)
	}
	if mode := pane.InputMode(); !mode.ApplicationCursor {
		t.Fatalf("InputMode after application cursor enable = %+v, want enabled", mode)
	}

	if _, err := pane.Write([]byte("\x1b[?1l")); err != nil {
		t.Fatalf("disable Write() error = %v", err)
	}
	if mode := pane.InputMode(); mode.ApplicationCursor {
		t.Fatalf("InputMode after application cursor disable = %+v, want disabled", mode)
	}
}

func TestTrackInputModeApplicationCursorEnableDisable(t *testing.T) {
	mode := TrackInputMode(TerminalInputMode{}, []byte("\x1b[?1h"))
	if !mode.ApplicationCursor {
		t.Fatalf("TrackInputMode enable = %+v, want application cursor enabled", mode)
	}

	mode = TrackInputMode(mode, []byte("\x1b[?25l\x1b[?1l"))
	if mode.ApplicationCursor {
		t.Fatalf("TrackInputMode disable = %+v, want application cursor disabled", mode)
	}
}

func TestTrackInputModePreservesStateForUnrelatedPrivateModes(t *testing.T) {
	mode := TrackInputMode(TerminalInputMode{ApplicationCursor: true}, []byte("\x1b[?25l\x1b[?1006h\x1b[?bad?h"))
	if !mode.ApplicationCursor {
		t.Fatalf("TrackInputMode unrelated modes = %+v, want application cursor unchanged", mode)
	}
}

func TestIncompletePrivateModeTail(t *testing.T) {
	longTail := "\x1b[?" + strings.Repeat("1", 33)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "none", in: "plain output", want: ""},
		{name: "partial tail", in: "prefix \x1b[?100", want: "\x1b[?100"},
		{name: "complete sequence", in: "\x1b[?1006h", want: ""},
		{name: "invalid tail", in: "\x1b[?100x", want: ""},
		{name: "too long", in: longTail, want: ""},
		{name: "last partial wins", in: "first \x1b[?1006h second \x1b[?1", want: "\x1b[?1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := incompletePrivateModeTail(tt.in); got != tt.want {
				t.Fatalf("incompletePrivateModeTail(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestVTTerminalPaneRendersVisibleCursorOnBlankCell(t *testing.T) {
	pane := NewVTTerminalPane(10, 3)

	if _, err := pane.Write([]byte("$ ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	if !strings.Contains(view, "\x1b[7m \x1b[0m") {
		t.Fatalf("View() = %q, want visible reverse-video cursor cell", view)
	}
	if width := visibleWidth(strings.Split(view, "\n")[0]); width != len("$  ") {
		t.Fatalf("first line visible width = %d, want cursor cell included: %q", width, view)
	}
}

func TestVTTerminalPaneViewClampsReadsToBufferSize(t *testing.T) {
	pane := NewVTTerminalPane(101, 30)

	if _, err := pane.Write([]byte("root@host:~# ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(131, 33)
	lines := strings.Split(view, "\n")
	if len(lines) != 33 {
		t.Fatalf("View line count = %d, want 33", len(lines))
	}
	if !strings.Contains(ansiPattern.ReplaceAllString(lines[0], ""), "root@host") {
		t.Fatalf("View() lost terminal content:\n%s", view)
	}
}

func TestVTTerminalPaneHidesCursorWhenDECTCEMDisabled(t *testing.T) {
	pane := NewVTTerminalPane(10, 3)

	if _, err := pane.Write([]byte("$ \x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	if strings.Contains(view, "\x1b[7m") {
		t.Fatalf("View() = %q, want hidden cursor to omit reverse-video overlay", view)
	}
}
