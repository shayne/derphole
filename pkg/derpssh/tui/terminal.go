// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hinshun/vt10x"
)

type TerminalPane interface {
	Write(p []byte) (int, error)
	Resize(cols int, rows int)
	View(width int, height int) string
	MouseMode() MouseMode
	InputMode() TerminalInputMode
}

type MouseMode struct {
	Enabled bool
	SGR     bool
}

type TerminalInputMode struct {
	ApplicationCursor bool
}

type vtTerminalPane struct {
	surface *vtTerminalSurface
}

func NewVTTerminalPane(cols int, rows int) TerminalPane {
	return &vtTerminalPane{surface: newVTTerminalSurface(terminalSize{Cols: cols, Rows: rows})}
}

func (p *vtTerminalPane) Write(b []byte) (int, error) {
	p.surface.Write(b)
	return len(b), nil
}

func (p *vtTerminalPane) Resize(cols int, rows int) {
	p.surface.Resize(terminalSize{Cols: cols, Rows: rows})
}

func (p *vtTerminalPane) View(width int, height int) string {
	return renderTerminalSurfaceRows(p.surface, terminalRenderOptions{Width: width, Height: height, Focused: true})
}

func (p *vtTerminalPane) MouseMode() MouseMode {
	return p.surface.MouseMode()
}

func (p *vtTerminalPane) InputMode() TerminalInputMode {
	return p.surface.InputMode()
}

func (p *vtTerminalPane) SetCursorActive(active bool) {
	p.surface.SetCursorActive(active)
}

const (
	_ int16 = 1 << iota
	vtAttrUnderline
	vtAttrBold
	_
	vtAttrItalic
	vtAttrBlink
)

const vtRenderedAttrMask = vtAttrUnderline | vtAttrBold | vtAttrItalic | vtAttrBlink

type terminalCellStyle struct {
	mode    int16
	fg      vt10x.Color
	bg      vt10x.Color
	reverse bool
}

type terminalCursorView struct {
	cursor  vt10x.Cursor
	visible bool
}

func writeTerminalCell(b *strings.Builder, r rune, style terminalCellStyle, activeStyle *terminalCellStyle, styleActive *bool) {
	if terminalBlankCellShouldUseDefaultStyle(r, style) {
		style = defaultTerminalCellStyle()
	}
	if !style.equal(*activeStyle) {
		resetTerminalStyle(b, styleActive)
		if style.active() {
			b.WriteString(style.sgr())
			*styleActive = true
		}
		*activeStyle = style
	}
	b.WriteRune(r)
}

func resetTerminalStyle(b *strings.Builder, styleActive *bool) {
	if !*styleActive {
		return
	}
	b.WriteString("\x1b[0m")
	*styleActive = false
}

func (c terminalCursorView) lastColumn(surface TerminalSurface, width int, y int) int {
	last := terminalLastRenderableColumn(surface, width, y)
	if c.visibleAt(y, width) && c.cursor.X > last {
		return c.cursor.X
	}
	return last
}

func (c terminalCursorView) styleCell(cell terminalCell, x int, y int) terminalCellStyle {
	if c.visible && c.cursor.Y == y && c.cursor.X == x {
		style := cell.Style
		style.reverse = true
		return style
	}
	return cell.Style
}

func (c terminalCursorView) visibleAt(y int, width int) bool {
	return c.visible && c.cursor.Y == y && c.cursor.X >= 0 && c.cursor.X < width
}

func terminalLastRenderableColumn(surface TerminalSurface, width int, y int) int {
	for x := width - 1; x >= 0; x-- {
		cell := surface.Cell(x, y)
		if cell.Rune != ' ' {
			return x
		}
		if terminalBlankCellHasVisibleStyle(cell) {
			return x
		}
	}
	return -1
}

func terminalBlankCellShouldUseDefaultStyle(r rune, style terminalCellStyle) bool {
	return r == ' ' && !terminalCellVisibleOnBlank(style)
}

func terminalBlankCellHasVisibleStyle(cell terminalCell) bool {
	return cell.Rune == ' ' && terminalCellVisibleOnBlank(cell.Style)
}

func terminalStyleFromGlyph(glyph vt10x.Glyph) terminalCellStyle {
	if glyph.Char == 0 {
		return defaultTerminalCellStyle()
	}
	return terminalStyleFromAttr(glyph)
}

func terminalStyleFromAttr(glyph vt10x.Glyph) terminalCellStyle {
	return terminalCellStyle{
		mode: glyph.Mode & vtRenderedAttrMask,
		fg:   glyph.FG,
		bg:   glyph.BG,
	}
}

func defaultTerminalCellStyle() terminalCellStyle {
	return terminalCellStyle{fg: vt10x.DefaultFG, bg: vt10x.DefaultBG}
}

func (s terminalCellStyle) equal(other terminalCellStyle) bool {
	return s.mode == other.mode && s.fg == other.fg && s.bg == other.bg && s.reverse == other.reverse
}

func (s terminalCellStyle) active() bool {
	return s.mode != 0 || s.fg != vt10x.DefaultFG || s.bg != vt10x.DefaultBG || s.reverse
}

func terminalCellVisibleOnBlank(style terminalCellStyle) bool {
	return style.reverse || style.bg != vt10x.DefaultBG
}

func (s terminalCellStyle) sgr() string {
	codes := make([]string, 0, 7)
	if s.mode&vtAttrBold != 0 {
		codes = append(codes, "1")
	}
	if s.reverse {
		codes = append(codes, "7")
	}
	if s.mode&vtAttrItalic != 0 {
		codes = append(codes, "3")
	}
	if s.mode&vtAttrUnderline != 0 {
		codes = append(codes, "4")
	}
	if s.mode&vtAttrBlink != 0 {
		codes = append(codes, "5")
	}
	appendTerminalColorCodes(&codes, s.fg, true)
	appendTerminalColorCodes(&codes, s.bg, false)
	if len(codes) == 0 {
		return ""
	}
	return "\x1b[" + strings.Join(codes, ";") + "m"
}

func appendTerminalColorCodes(codes *[]string, color vt10x.Color, foreground bool) {
	if color == vt10x.DefaultFG || color == vt10x.DefaultBG || color > 0xFFFFFF {
		return
	}
	n := int(color)
	if color < 16 {
		base := 30
		brightBase := 90
		if !foreground {
			base = 40
			brightBase = 100
		}
		if n < 8 {
			*codes = append(*codes, strconv.Itoa(base+n))
		} else {
			*codes = append(*codes, strconv.Itoa(brightBase+n-8))
		}
		return
	}
	if color < 256 {
		target := 38
		if !foreground {
			target = 48
		}
		*codes = append(*codes, fmt.Sprintf("%d;5;%d", target, n))
		return
	}

	target := 38
	if !foreground {
		target = 48
	}
	r := int((color >> 16) & 0xff)
	g := int((color >> 8) & 0xff)
	b := int(color & 0xff)
	*codes = append(*codes, fmt.Sprintf("%d;2;%d;%d;%d", target, r, g, b))
}

type staticTerminalPane struct {
	text string
}

func (p *staticTerminalPane) Write(b []byte) (int, error) {
	p.text += string(b)
	return len(b), nil
}

func (p *staticTerminalPane) Resize(cols int, rows int) {}

func (p *staticTerminalPane) View(width int, height int) string {
	return p.text
}

func (p *staticTerminalPane) MouseMode() MouseMode {
	return MouseMode{}
}

func (p *staticTerminalPane) InputMode() TerminalInputMode {
	return TerminalInputMode{}
}

var privateModePattern = regexp.MustCompile(`\x1b\[\?([0-9;]+)([hl])`)

func TrackMouseMode(current MouseMode, output []byte) MouseMode {
	next := current
	for _, match := range privateModePattern.FindAllSubmatch(output, -1) {
		enable := len(match[2]) == 1 && match[2][0] == 'h'
		for _, raw := range strings.Split(string(match[1]), ";") {
			param, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			switch param {
			case 1000, 1002, 1003:
				next.Enabled = enable
				if !enable {
					next.SGR = false
				}
			case 1006:
				if enable {
					next.Enabled = true
				}
				next.SGR = enable
			}
		}
	}
	if !next.Enabled {
		next.SGR = false
	}
	return next
}

func TrackInputMode(current TerminalInputMode, output []byte) TerminalInputMode {
	next := current
	for _, match := range privateModePattern.FindAllSubmatch(output, -1) {
		enable := len(match[2]) == 1 && match[2][0] == 'h'
		for _, raw := range strings.Split(string(match[1]), ";") {
			param, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			if param == 1 {
				next.ApplicationCursor = enable
			}
		}
	}
	return next
}

func incompletePrivateModeTail(s string) string {
	idx := strings.LastIndex(s, "\x1b[?")
	if idx == -1 {
		return ""
	}
	tail := s[idx:]
	if privateModePattern.MatchString(tail) {
		return ""
	}
	if len(tail) > 32 {
		return ""
	}
	for _, r := range tail[len("\x1b[?"):] {
		if (r < '0' || r > '9') && r != ';' {
			return ""
		}
	}
	return tail
}
