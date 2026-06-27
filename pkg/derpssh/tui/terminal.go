// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
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
		for x := 0; x < width; x++ {
			glyph := p.term.Cell(x, y)
			if glyph.Char == 0 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(glyph.Char)
			}
		}
		lines = append(lines, strings.TrimRight(b.String(), " "))
	}
	return strings.Join(lines, "\n")
}

func (p *vtTerminalPane) MouseMode() MouseMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mouse
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
