// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"
)

var _ TerminalSurface = (*vtTerminalSurface)(nil)

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

func TestTerminalSurfaceDoesNotRenderUnderlineOnlyBlankCells(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 40, Rows: 5})
	surface.Write([]byte("\x1b[4m                                        \x1b[0m"))

	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{
		Width:   40,
		Height:  5,
		Focused: false,
	})
	if strings.Contains(view, "________________________________________") {
		t.Fatalf("underline-only blank row rendered as visible rule: %q", view)
	}
	if strings.Contains(view, "\x1b[4m") {
		t.Fatalf("underline-only blank row emitted underline styling: %q", view)
	}
}

func TestTerminalSurfaceVimAlternateScreenFixture(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 40, Rows: 6})
	surface.Write([]byte("\x1b[?1049h\x1b[H\x1b[4m                                        \x1b[0m\x1b[2;1H\"scratch\" [No Name]\x1b[6;1H:"))

	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{
		Width:   40,
		Height:  6,
		Focused: true,
	})
	if strings.Contains(view, "________________________________________") {
		t.Fatalf("vim fixture rendered underline-only blanks as rule: %q", view)
	}
	if !strings.Contains(view, `"scratch" [No Name]`) {
		t.Fatalf("vim fixture missing status text: %q", view)
	}
	cursor := surface.Cursor().cursor
	if cursor.X < 0 || cursor.X >= 40 || cursor.Y < 0 || cursor.Y >= 6 {
		t.Fatalf("cursor = %+v, want within 40x6", cursor)
	}
}
