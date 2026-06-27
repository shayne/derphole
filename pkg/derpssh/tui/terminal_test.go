// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

func TestVTTerminalPaneRendersANSIOutput(t *testing.T) {
	pane := NewVTTerminalPane(20, 4)

	if _, err := pane.Write([]byte("plain \x1b[31mred\x1b[0m")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	if !strings.Contains(view, "plain red") {
		t.Fatalf("View() = %q, want rendered ANSI text without escape bytes", view)
	}
	if strings.Contains(view, "\x1b[31m") {
		t.Fatalf("View() exposes raw ANSI sequence: %q", view)
	}
}

func TestVTTerminalPaneHandlesCursorMovement(t *testing.T) {
	pane := NewVTTerminalPane(10, 3)

	if _, err := pane.Write([]byte("abc\x1b[2DZ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	if !strings.Contains(view, "aZc") {
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
