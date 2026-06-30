// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"sync"

	"github.com/hinshun/vt10x"
)

type terminalMouseMode = MouseMode
type terminalInputMode = TerminalInputMode

type TerminalSurface interface {
	Write([]byte)
	Resize(terminalSize)
	Size() terminalSize
	Cell(x int, y int) terminalCell
	Cursor() terminalCursorView
	MouseMode() terminalMouseMode
	InputMode() terminalInputMode
	Scroll(delta int)
}

type terminalSize struct {
	Cols int
	Rows int
}

type terminalCell struct {
	Rune  rune
	Style terminalCellStyle
}

type terminalRenderOptions struct {
	Width   int
	Height  int
	Focused bool
}

type vtTerminalSurface struct {
	mu           sync.Mutex
	term         vt10x.Terminal
	mouse        MouseMode
	inputMode    TerminalInputMode
	modeTail     string
	cursorActive bool
}

func newVTTerminalSurface(size terminalSize) *vtTerminalSurface {
	cols := size.Cols
	rows := size.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return &vtTerminalSurface{term: vt10x.New(vt10x.WithSize(cols, rows)), cursorActive: true}
}

func (s *vtTerminalSurface) Write(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	modeInput := s.modeTail + string(b)
	s.mouse = TrackMouseMode(s.mouse, []byte(modeInput))
	s.inputMode = TrackInputMode(s.inputMode, []byte(modeInput))
	s.modeTail = incompletePrivateModeTail(modeInput)
	_, _ = s.term.Write(b)
}

func (s *vtTerminalSurface) Resize(size terminalSize) {
	if size.Cols <= 0 || size.Rows <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.term.Resize(size.Cols, size.Rows)
}

func (s *vtTerminalSurface) Size() terminalSize {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.term.Lock()
	defer s.term.Unlock()
	cols, rows := s.term.Size()
	return terminalSize{Cols: cols, Rows: rows}
}

func (s *vtTerminalSurface) Cell(x int, y int) terminalCell {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.term.Lock()
	defer s.term.Unlock()
	cols, rows := s.term.Size()
	if x < 0 || y < 0 || x >= cols || y >= rows {
		return terminalCell{Rune: ' ', Style: defaultTerminalCellStyle()}
	}
	glyph := s.term.Cell(x, y)
	return terminalCell{Rune: terminalCellRune(glyph), Style: terminalStyleFromGlyph(glyph)}
}

func (s *vtTerminalSurface) Cursor() terminalCursorView {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.term.Lock()
	defer s.term.Unlock()
	return terminalCursorView{cursor: s.term.Cursor(), visible: s.term.CursorVisible() && s.cursorActive}
}

func (s *vtTerminalSurface) MouseMode() terminalMouseMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mouse
}

func (s *vtTerminalSurface) InputMode() terminalInputMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inputMode
}

func (s *vtTerminalSurface) Scroll(int) {}

func (s *vtTerminalSurface) SetCursorActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursorActive = active
}

func renderTerminalSurfaceRows(surface TerminalSurface, opts terminalRenderOptions) string {
	if surface == nil || opts.Width <= 0 || opts.Height <= 0 {
		return ""
	}
	lines := make([]string, 0, opts.Height)
	size := surface.Size()
	cursor := surface.Cursor()
	renderWidth := minInt(opts.Width, size.Cols)
	for y := 0; y < opts.Height; y++ {
		if y >= size.Rows || renderWidth <= 0 {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, renderTerminalSurfaceRow(surface, renderWidth, y, cursor))
	}
	return strings.Join(lines, "\n")
}

func renderTerminalSurfaceRow(surface TerminalSurface, width int, y int, cursor terminalCursorView) string {
	var b strings.Builder
	activeStyle := defaultTerminalCellStyle()
	styleActive := false
	last := cursor.lastColumn(surface, width, y)
	for x := 0; x <= last; x++ {
		cell := surface.Cell(x, y)
		style := cursor.styleCell(cell, x, y)
		writeTerminalCell(&b, cell.Rune, style, &activeStyle, &styleActive)
	}
	if styleActive {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

func terminalCellRune(glyph vt10x.Glyph) rune {
	if glyph.Char == 0 {
		return ' '
	}
	return glyph.Char
}
