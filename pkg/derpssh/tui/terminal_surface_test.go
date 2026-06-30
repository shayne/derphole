// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func TestVTTerminalSurfaceClampsCellReads(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 30, Rows: 10})

	cell := surface.Cell(130, 0)
	if cell.Rune != ' ' {
		t.Fatalf("out-of-range cell rune = %q, want space", cell.Rune)
	}
	if !cell.Style.equal(defaultTerminalCellStyle()) {
		t.Fatalf("out-of-range cell style = %#v, want default", cell.Style)
	}
}

func TestTerminalCellVisibleOnBlankDocumentsTerminalSemantics(t *testing.T) {
	underlineOnly := terminalCellStyle{mode: vtAttrUnderline, fg: defaultTerminalCellStyle().fg, bg: defaultTerminalCellStyle().bg}
	if terminalCellVisibleOnBlank(underlineOnly) {
		t.Fatalf("underline-only blank cell should not be visible")
	}

	withBackground := terminalCellStyle{fg: defaultTerminalCellStyle().fg, bg: 4}
	if !terminalCellVisibleOnBlank(withBackground) {
		t.Fatalf("background-styled blank cell should be visible")
	}

	reverse := defaultTerminalCellStyle()
	reverse.reverse = true
	if !terminalCellVisibleOnBlank(reverse) {
		t.Fatalf("reverse-video blank cell should be visible")
	}
}
