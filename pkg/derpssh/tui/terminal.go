// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/hinshun/vt10x"
)

type TerminalPane interface {
	Write(p []byte) (int, error)
	Resize(cols int, rows int)
	View(width int, height int) string
	MouseMode() MouseMode
}

type MouseMode struct {
	Enabled bool
	SGR     bool
}

type vtTerminalPane struct {
	mu        sync.Mutex
	term      vt10x.Terminal
	mouse     MouseMode
	mouseTail string
}

func NewVTTerminalPane(cols int, rows int) TerminalPane {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return &vtTerminalPane{term: vt10x.New(vt10x.WithSize(cols, rows))}
}

func (p *vtTerminalPane) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mouseInput := p.mouseTail + string(b)
	p.mouse = TrackMouseMode(p.mouse, []byte(mouseInput))
	p.mouseTail = incompleteMouseModeTail(mouseInput)
	return p.term.Write(b)
}

func (p *vtTerminalPane) Resize(cols int, rows int) {
	if cols <= 0 || rows <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.term.Resize(cols, rows)
}

func (p *vtTerminalPane) View(width int, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.term.Lock()
	defer p.term.Unlock()

	lines := make([]string, 0, height)
	for y := 0; y < height; y++ {
		var b strings.Builder
		activeStyle := defaultTerminalCellStyle()
		styleActive := false
		last := terminalLastRenderableColumn(p.term, width, y)
		for x := 0; x <= last; x++ {
			glyph := p.term.Cell(x, y)
			style := terminalStyleFromGlyph(glyph)
			if !style.equal(activeStyle) {
				if styleActive {
					b.WriteString("\x1b[0m")
					styleActive = false
				}
				if style.active() {
					b.WriteString(style.sgr())
					styleActive = true
				}
				activeStyle = style
			}
			if glyph.Char == 0 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(glyph.Char)
			}
		}
		if styleActive {
			b.WriteString("\x1b[0m")
		}
		lines = append(lines, b.String())
	}
	return strings.Join(lines, "\n")
}

func (p *vtTerminalPane) MouseMode() MouseMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mouse
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
	mode int16
	fg   vt10x.Color
	bg   vt10x.Color
}

func terminalLastRenderableColumn(term vt10x.Terminal, width int, y int) int {
	for x := width - 1; x >= 0; x-- {
		glyph := term.Cell(x, y)
		if glyph.Char != 0 && glyph.Char != ' ' {
			return x
		}
		if glyph.Char != 0 && terminalStyleFromGlyph(glyph).active() {
			return x
		}
	}
	return -1
}

func terminalStyleFromGlyph(glyph vt10x.Glyph) terminalCellStyle {
	if glyph.Char == 0 {
		return defaultTerminalCellStyle()
	}
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
	return s.mode == other.mode && s.fg == other.fg && s.bg == other.bg
}

func (s terminalCellStyle) active() bool {
	return s.mode != 0 || s.fg != vt10x.DefaultFG || s.bg != vt10x.DefaultBG
}

func (s terminalCellStyle) sgr() string {
	codes := make([]string, 0, 6)
	if s.mode&vtAttrBold != 0 {
		codes = append(codes, "1")
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

var mouseModePattern = regexp.MustCompile(`\x1b\[\?([0-9;]+)([hl])`)

func TrackMouseMode(current MouseMode, output []byte) MouseMode {
	next := current
	for _, match := range mouseModePattern.FindAllSubmatch(output, -1) {
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

func incompleteMouseModeTail(s string) string {
	idx := strings.LastIndex(s, "\x1b[?")
	if idx == -1 {
		return ""
	}
	tail := s[idx:]
	if mouseModePattern.MatchString(tail) {
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
