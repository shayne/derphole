// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

type Point struct {
	X int
	Y int
}

type Cell struct {
	Rune  rune
	Style lipgloss.Style
	Raw   string
	Skip  bool
}

type FrameCanvas struct {
	width  int
	height int
	cells  []Cell
}

func NewFrameCanvas(width int, height int, base lipgloss.Style) *FrameCanvas {
	if width < 0 {
		width = 0
	}
	if height < 0 {
		height = 0
	}
	canvas := &FrameCanvas{
		width:  width,
		height: height,
		cells:  make([]Cell, width*height),
	}
	canvas.Fill(Rect{W: width, H: height}, Cell{Rune: ' ', Style: base})
	return canvas
}

func (c *FrameCanvas) Fill(rect Rect, cell Cell) {
	if c == nil {
		return
	}
	if cell.Rune == 0 {
		cell.Rune = ' '
	}
	x0 := clampInt(rect.X, 0, c.width)
	y0 := clampInt(rect.Y, 0, c.height)
	x1 := clampInt(rect.X+rect.W, 0, c.width)
	y1 := clampInt(rect.Y+rect.H, 0, c.height)
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			c.cells[c.index(x, y)] = cell
		}
	}
}

func (c *FrameCanvas) DrawText(x int, y int, text string, style lipgloss.Style) {
	if c == nil || y < 0 || y >= c.height || x >= c.width {
		return
	}
	col := x
	for _, r := range text {
		if col >= c.width {
			return
		}
		cellWidth := maxInt(displayWidth(string(r)), 1)
		if col+cellWidth > c.width {
			return
		}
		if col >= 0 {
			c.cells[c.index(col, y)] = Cell{Rune: r, Style: style}
			c.markContinuationCells(col, y, cellWidth)
		}
		col += cellWidth
	}
}

func (c *FrameCanvas) DrawANSIText(x int, y int, text string, style lipgloss.Style) {
	if c == nil || y < 0 || y >= c.height || x >= c.width {
		return
	}
	col := x
	pending := ""
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == '\x1b' {
			seq, n := readANSISequence(text[i:])
			pending += seq
			i += n
			continue
		}
		nextCol, ok := c.drawANSIRune(col, y, r, pending, style)
		if !ok {
			return
		}
		pending = ""
		col = nextCol
		i += size
	}
	c.appendPendingANSI(x, col, y, pending)
}

func (c *FrameCanvas) Overlay(src *FrameCanvas, at Point) {
	if c == nil || src == nil {
		return
	}
	for y := 0; y < src.height; y++ {
		dstY := at.Y + y
		if dstY < 0 || dstY >= c.height {
			continue
		}
		for x := 0; x < src.width; x++ {
			dstX := at.X + x
			if dstX < 0 || dstX >= c.width {
				continue
			}
			c.cells[c.index(dstX, dstY)] = src.cells[src.index(x, y)]
		}
	}
}

func (c *FrameCanvas) Cell(x int, y int) Cell {
	if c == nil || x < 0 || y < 0 || x >= c.width || y >= c.height {
		return Cell{Rune: ' '}
	}
	return c.cells[c.index(x, y)]
}

func (c *FrameCanvas) Render() string {
	if c == nil || c.width <= 0 || c.height <= 0 {
		return ""
	}
	lines := make([]string, c.height)
	for y := 0; y < c.height; y++ {
		var b strings.Builder
		for x := 0; x < c.width; x++ {
			cell := c.Cell(x, y)
			if cell.Skip {
				continue
			}
			if cell.Rune == 0 {
				cell.Rune = ' '
			}
			if cell.Raw != "" {
				b.WriteString(cell.Raw)
				continue
			}
			b.WriteString(cell.Style.Render(string(cell.Rune)))
		}
		lines[y] = b.String()
	}
	return strings.Join(lines, "\n")
}

func (c *FrameCanvas) index(x int, y int) int {
	return y*c.width + x
}

func (c *FrameCanvas) drawANSIRune(col int, y int, r rune, pending string, style lipgloss.Style) (int, bool) {
	cellWidth := maxInt(displayWidth(string(r)), 1)
	if col+cellWidth > c.width {
		return col, false
	}
	if col >= 0 {
		c.cells[c.index(col, y)] = Cell{Rune: r, Style: style, Raw: pending + string(r)}
		c.markContinuationCells(col, y, cellWidth)
	}
	return col + cellWidth, true
}

func (c *FrameCanvas) appendPendingANSI(startX int, col int, y int, pending string) {
	if pending == "" || col <= startX {
		return
	}
	last := clampInt(col-1, 0, c.width-1)
	cell := c.cells[c.index(last, y)]
	cell.Raw += pending
	c.cells[c.index(last, y)] = cell
}

func (c *FrameCanvas) markContinuationCells(x int, y int, width int) {
	for offset := 1; offset < width && x+offset < c.width; offset++ {
		c.cells[c.index(x+offset, y)] = Cell{Skip: true}
	}
}

func readANSISequence(s string) (string, int) {
	if len(s) == 0 || s[0] != '\x1b' {
		return "", 0
	}
	if len(s) == 1 {
		return s, 1
	}
	switch s[1] {
	case '[':
		return readCSISequence(s)
	case ']':
		return readOSCSequence(s)
	}
	return readShortEscapeSequence(s)
}

func readCSISequence(s string) (string, int) {
	for i := 2; i < len(s); i++ {
		if isANSIFinalByte(s[i]) {
			return s[:i+1], i + 1
		}
	}
	return s, len(s)
}

func readOSCSequence(s string) (string, int) {
	for i := 2; i < len(s); i++ {
		if s[i] == '\a' {
			return s[:i+1], i + 1
		}
		if isStringTerminator(s, i) {
			return s[:i+2], i + 2
		}
	}
	return s, len(s)
}

func readShortEscapeSequence(s string) (string, int) {
	return s[:2], 2
}

func isANSIFinalByte(b byte) bool {
	return b >= 0x40 && b <= 0x7e
}

func isStringTerminator(s string, i int) bool {
	return s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\'
}
