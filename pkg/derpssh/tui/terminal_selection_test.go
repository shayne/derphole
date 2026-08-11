// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func newSelectionTestSurface(t *testing.T) *vtTerminalSurface {
	t.Helper()
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("alpha\r\nbeta"))
	return surface
}

func TestTerminalSelectionCopiesForwardAndReverseRanges(t *testing.T) {
	for _, test := range []struct {
		name    string
		anchorX int
		anchorY int
		cursorX int
		cursorY int
	}{
		{name: "forward", anchorX: 0, anchorY: 0, cursorX: 3, cursorY: 1},
		{name: "reverse", anchorX: 3, anchorY: 1, cursorX: 0, cursorY: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			surface := newSelectionTestSurface(t)
			if !surface.BeginSelection(test.anchorX, test.anchorY) {
				t.Fatal("BeginSelection() = false")
			}
			if !surface.UpdateSelection(test.cursorX, test.cursorY) {
				t.Fatal("UpdateSelection() = false")
			}
			if got, ok := surface.FinishSelection(); !ok || got != "alpha\nbeta" {
				t.Fatalf("FinishSelection() = (%q, %v), want (alpha\\nbeta, true)", got, ok)
			}
		})
	}
}

func TestTerminalSelectionClickWithoutMovementIsEmpty(t *testing.T) {
	surface := newSelectionTestSurface(t)
	if !surface.BeginSelection(2, 0) {
		t.Fatal("BeginSelection() = false")
	}
	if got, ok := surface.FinishSelection(); ok || got != "" {
		t.Fatalf("FinishSelection() = (%q, %v), want (empty, false)", got, ok)
	}
}

func TestTerminalSelectionEmptyDragClearsSelection(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 8, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("    "))
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(3, 0) {
		t.Fatal("could not select whitespace")
	}

	if got, ok := surface.FinishSelection(); ok || got != "" {
		t.Fatalf("FinishSelection() = (%q, %v), want (empty, false)", got, ok)
	}
	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after empty drag completed")
	}
	if surface.Cell(0, 0).Selected {
		t.Fatal("empty drag left persistent selection highlighting")
	}
}

func TestTerminalSelectionExtractsDisplayCells(t *testing.T) {
	tests := []struct {
		name             string
		cols, rows       int
		contents         string
		scroll           int
		anchorX, anchorY int
		cursorX, cursorY int
		want             string
	}{
		{
			name: "partial first and last lines with full middle", cols: 12, rows: 3,
			contents: "first\r\nmiddle\r\nlast", anchorX: 1, anchorY: 0, cursorX: 2, cursorY: 2,
			want: "irst\nmiddle\nlas",
		},
		{
			name: "trims trailing blanks but preserves interior blanks", cols: 12, rows: 2,
			contents: "a b  ", anchorX: 0, anchorY: 0, cursorX: 4, cursorY: 0,
			want: "a b",
		},
		{
			name: "reverse range", cols: 12, rows: 2,
			contents: "alpha\r\nbeta", anchorX: 3, anchorY: 1, cursorX: 0, cursorY: 0,
			want: "alpha\nbeta",
		},
		{
			name: "empty retained row", cols: 12, rows: 3,
			contents: "alpha\r\n\r\nbeta\r\ntail", scroll: 1, anchorX: 0, anchorY: 0, cursorX: 3, cursorY: 2,
			want: "alpha\n\nbeta",
		},
		{
			name: "wide grapheme lead", cols: 12, rows: 2,
			contents: "A界B", anchorX: 0, anchorY: 0, cursorX: 1, cursorY: 0,
			want: "A界",
		},
		{
			name: "wide grapheme continuation", cols: 12, rows: 2,
			contents: "A界B", anchorX: 0, anchorY: 0, cursorX: 2, cursorY: 0,
			want: "A界",
		},
		{
			name: "combining grapheme", cols: 12, rows: 2,
			contents: "e\u0301x", anchorX: 0, anchorY: 0, cursorX: 1, cursorY: 0,
			want: "e\u0301x",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			surface := newVTTerminalSurface(terminalSize{Cols: test.cols, Rows: test.rows})
			t.Cleanup(func() { _ = surface.Close() })
			surface.Write([]byte(test.contents))
			surface.ScrollLines(test.scroll)
			if !surface.BeginSelection(test.anchorX, test.anchorY) {
				t.Fatal("BeginSelection() = false")
			}
			if !surface.UpdateSelection(test.cursorX, test.cursorY) {
				t.Fatal("UpdateSelection() = false")
			}
			got, ok := surface.FinishSelection()
			if test.want == "" {
				if ok || got != "" {
					t.Fatalf("FinishSelection() = (%q, %v), want (empty, false)", got, ok)
				}
				return
			}
			if !ok || got != test.want {
				t.Fatalf("FinishSelection() = (%q, %v), want (%q, true)", got, ok, test.want)
			}
		})
	}
}

func TestTerminalSelectionSelectsWords(t *testing.T) {
	tests := []struct {
		line string
		col  int
		want string
	}{
		{"alpha_beta!", 4, "alpha_beta"},
		{"café κόσμος", 6, "κόσμος"},
		{"one.two", 3, ""},
		{"word  next", 4, ""},
		{"界界!", 2, "界界"},
	}

	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
			t.Cleanup(func() { _ = surface.Close() })
			surface.Write([]byte(test.line))
			got, ok := surface.SelectWord(test.col, 0)
			if test.want == "" {
				if ok || got != "" {
					t.Fatalf("SelectWord() = (%q, %v), want (empty, false)", got, ok)
				}
				return
			}
			if !ok || got != test.want {
				t.Fatalf("SelectWord() = (%q, %v), want (%q, true)", got, ok, test.want)
			}
		})
	}
}

func newScrollbackSelectionSurface(t *testing.T) *vtTerminalSurface {
	t.Helper()
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("zero\r\none\r\ntwo\r\nthree"))
	return surface
}

func TestTerminalSelectionAnchorUsesCombinedRowAcrossScrolling(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	if !surface.BeginSelection(0, 0) {
		t.Fatal("BeginSelection() = false")
	}
	anchor := surface.selection.anchor
	if !surface.ScrollLines(1) {
		t.Fatal("ScrollLines() = false")
	}
	if got := surface.selection.anchor; got != anchor {
		t.Fatalf("anchor after scroll = %+v, want %+v", got, anchor)
	}
}

func TestTerminalSelectionUpdatesDragAgainstScrolledViewport(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(0, 1) {
		t.Fatal("could not begin drag")
	}
	if !surface.ScrollLines(1) {
		t.Fatal("ScrollLines() = false")
	}
	if !surface.UpdateSelection(0, 0) {
		t.Fatal("UpdateSelection() = false")
	}
	if got, want := surface.selection.cursor.Row, surface.term.ScrollbackLen()-1; got != want {
		t.Fatalf("cursor row after scroll = %d, want %d", got, want)
	}
}

func TestTerminalSelectionResizeClearsAndClampsViewport(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	surface.ScrollLines(999)
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(1, 0) {
		t.Fatal("could not create selection")
	}
	surface.Resize(terminalSize{Cols: 12, Rows: 1})
	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after Resize()")
	}
	if got := surface.ViewportState(); got.OffsetFromBottom < 0 || got.OffsetFromBottom > got.ScrollbackLines {
		t.Fatalf("viewport after Resize() = %+v, want clamped offset", got)
	}
}

func TestTerminalSelectionAlternateScreenClears(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(1, 0) {
		t.Fatal("could not create selection")
	}
	surface.Write([]byte("\x1b[?1049h"))
	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after alternate-screen entry")
	}
}

func TestTerminalSelectionWriteAtFullScrollbackClears(t *testing.T) {
	surface := newVTTerminalSurfaceWithScrollbackLimit(terminalSize{Cols: 12, Rows: 2}, 2)
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("zero\r\none\r\ntwo\r\nthree"))
	if got := surface.ViewportState().ScrollbackLines; got != 2 {
		t.Fatalf("scrollback = %d, want full limit 2", got)
	}
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(1, 0) {
		t.Fatal("could not create selection")
	}
	surface.Write([]byte("\r\nfour"))
	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after write at full scrollback")
	}
}

func TestTerminalSelectionScrollbackClearInvalidatesHistoricalRows(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	if !surface.ScrollLines(999) {
		t.Fatal("ScrollLines() = false")
	}
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(2, 0) {
		t.Fatal("could not select a retained historical row")
	}

	surface.Write([]byte("\x1b[3J"))

	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after retained row identities were discarded")
	}
	if surface.Cell(0, 0).Selected {
		t.Fatal("live-grid cell inherited selection from discarded historical coordinates")
	}
	if got, ok := surface.FinishSelection(); ok || got != "" {
		t.Fatalf("FinishSelection() = (%q, %v), want (empty, false)", got, ok)
	}
}

func TestTerminalSelectionScrollbackClearAndRepopulateInvalidatesHistoricalRows(t *testing.T) {
	surface := newScrollbackSelectionSurface(t)
	if got := surface.ViewportState().ScrollbackLines; got != 2 {
		t.Fatalf("initial scrollback = %d, want 2", got)
	}
	if !surface.ScrollLines(999) {
		t.Fatal("ScrollLines() = false")
	}
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(2, 0) {
		t.Fatal("could not select a retained historical row")
	}

	surface.Write([]byte("\x1b[3J\r\nfour\r\nfive"))

	if got := surface.ViewportState().ScrollbackLines; got != 2 {
		t.Fatalf("repopulated scrollback = %d, want net-zero length 2", got)
	}
	if surface.SelectionActive() {
		t.Fatal("SelectionActive() = true after scrollback was cleared and repopulated in one write")
	}
	if surface.Cell(0, 0).Selected {
		t.Fatal("replacement row inherited selection from discarded historical coordinates")
	}
	if got, ok := surface.FinishSelection(); ok || got != "" {
		t.Fatalf("FinishSelection() = (%q, %v), want (empty, false)", got, ok)
	}
}
