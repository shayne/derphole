// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/hinshun/vt10x"

type terminalSize struct {
	Cols int
	Rows int
}

type terminalCell struct {
	Rune  rune
	Style terminalCellStyle
}

func newVTTerminalSurface(size terminalSize) *vtTerminalPane {
	cols := size.Cols
	rows := size.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return &vtTerminalPane{term: vt10x.New(vt10x.WithSize(cols, rows)), cursorActive: true}
}

func (p *vtTerminalPane) Size() terminalSize {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.term.Lock()
	defer p.term.Unlock()
	cols, rows := p.term.Size()
	return terminalSize{Cols: cols, Rows: rows}
}

func (p *vtTerminalPane) Cell(x int, y int) terminalCell {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.term.Lock()
	defer p.term.Unlock()
	cols, rows := p.term.Size()
	if x < 0 || y < 0 || x >= cols || y >= rows {
		return terminalCell{Rune: ' ', Style: defaultTerminalCellStyle()}
	}
	glyph := p.term.Cell(x, y)
	return terminalCell{Rune: terminalCellRune(glyph), Style: terminalStyleFromGlyph(glyph)}
}

func terminalCellRune(glyph vt10x.Glyph) rune {
	if glyph.Char == 0 {
		return ' '
	}
	return glyph.Char
}
