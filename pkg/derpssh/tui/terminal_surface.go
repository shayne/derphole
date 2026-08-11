// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"io"
	"strings"
	"sync"
	"unicode"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	ansiparser "github.com/charmbracelet/x/ansi/parser"
	"github.com/charmbracelet/x/vt"
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
}

type terminalSize struct {
	Cols int
	Rows int
}

type terminalPoint struct {
	X int
	Y int
}

type terminalCell struct {
	Content  string
	Width    int
	Style    uv.Style
	Selected bool
}

type terminalRenderOptions struct {
	Width   int
	Height  int
	Focused bool
}

type terminalViewportState struct {
	OffsetFromBottom int
	ScrollbackLines  int
	Rows             int
	AlternateScreen  bool
}

type vtTerminalSurface struct {
	mu               sync.Mutex
	term             *vt.Emulator
	graphemes        terminalGraphemeAdapter
	privateModes     map[int]bool
	mouse            MouseMode
	inputMode        TerminalInputMode
	offsetFromBottom int
	scrollbackLimit  int
	selection        terminalSelection
	cursorVisible    bool
	cursorActive     bool
	closed           bool
	drainDone        chan struct{}
}

const terminalScrollbackLimit = 10_000

func newVTTerminalSurface(size terminalSize) *vtTerminalSurface {
	return newVTTerminalSurfaceWithScrollbackLimit(size, terminalScrollbackLimit)
}

func newVTTerminalSurfaceWithScrollbackLimit(size terminalSize, scrollbackLimit int) *vtTerminalSurface {
	cols := size.Cols
	rows := size.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	surface := &vtTerminalSurface{
		term:            vt.NewEmulator(cols, rows),
		privateModes:    make(map[int]bool),
		cursorVisible:   true,
		cursorActive:    true,
		scrollbackLimit: scrollbackLimit,
	}
	surface.term.SetScrollbackSize(scrollbackLimit)
	surface.term.SetCallbacks(vt.Callbacks{
		CursorVisibility: func(visible bool) {
			surface.cursorVisible = visible
		},
		EnableMode: func(mode ansi.Mode) {
			surface.setPrivateMode(mode, true)
		},
		DisableMode: func(mode ansi.Mode) {
			surface.setPrivateMode(mode, false)
		},
		AltScreen: func(bool) {
			surface.offsetFromBottom = 0
			surface.selection = terminalSelection{}
		},
	})
	surface.drainDone = make(chan struct{})
	go func() {
		defer close(surface.drainDone)
		_, _ = io.Copy(io.Discard, surface.term)
	}()
	return surface
}

func (s *vtTerminalSurface) Write(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	before := s.term.ScrollbackLen()
	scrollbackErased := s.graphemes.Write(s.term, b)
	scrollbackLen := s.term.ScrollbackLen()
	if scrollbackErased || scrollbackLen < before || len(b) > 0 && before == s.scrollbackLimit && scrollbackLen == s.scrollbackLimit {
		s.selection = terminalSelection{}
	}
	if growth := scrollbackLen - before; growth > 0 && s.offsetFromBottom > 0 {
		s.offsetFromBottom += growth
	}
	s.offsetFromBottom = minInt(maxInt(s.offsetFromBottom, 0), scrollbackLen)
}

func (s *vtTerminalSurface) Resize(size terminalSize) {
	if size.Cols <= 0 || size.Rows <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.graphemes.ResetCell()
	s.term.Resize(size.Cols, size.Rows)
	s.offsetFromBottom = minInt(maxInt(s.offsetFromBottom, 0), s.term.ScrollbackLen())
	s.selection = terminalSelection{}
}

type terminalGraphemeAdapter struct {
	parser           *ansi.Parser
	incomplete       []byte
	previousCell     *uv.Cell
	scrollbackErased bool
}

type terminalGraphemeEvent struct {
	raw       []byte
	printable bool
	rune      rune
}

func (a *terminalGraphemeAdapter) Write(term *vt.Emulator, b []byte) bool {
	events := a.scan(b)
	var passthrough []byte
	for i, event := range events {
		if a.canAppendCombiningMark(event) {
			passthrough = flushTerminalGraphemeBytes(term, passthrough)
			a.previousCell.Content += string(event.raw)
			continue
		}

		a.previousCell = nil
		if terminalGraphemeEventStartsBase(events, i) {
			passthrough = flushTerminalGraphemeBytes(term, passthrough)
			a.previousCell = writeTerminalGraphemeBase(term, event.raw)
			continue
		}
		passthrough = append(passthrough, event.raw...)
	}
	flushTerminalGraphemeBytes(term, passthrough)
	return a.scrollbackErased
}

func (a *terminalGraphemeAdapter) canAppendCombiningMark(event terminalGraphemeEvent) bool {
	return event.printable && terminalRuneIsCombiningMark(event.rune) && a.previousCell != nil
}

func terminalGraphemeEventStartsBase(events []terminalGraphemeEvent, i int) bool {
	event := events[i]
	if !event.printable || terminalRuneIsCombiningMark(event.rune) {
		return false
	}
	return i == len(events)-1 || events[i+1].printable && terminalRuneIsCombiningMark(events[i+1].rune)
}

func flushTerminalGraphemeBytes(term *vt.Emulator, b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	_, _ = term.Write(b)
	return b[:0]
}

func (a *terminalGraphemeAdapter) ResetCell() {
	a.previousCell = nil
}

func (a *terminalGraphemeAdapter) scan(b []byte) []terminalGraphemeEvent {
	a.scrollbackErased = false
	if a.parser == nil {
		a.parser = ansi.NewParser()
		a.parser.SetHandler(ansi.Handler{
			HandleCsi: func(cmd ansi.Cmd, params ansi.Params) {
				param, _, _ := params.Param(0, 0)
				if cmd.Prefix() == 0 && cmd.Intermediate() == 0 && cmd.Final() == 'J' && param == 3 {
					a.scrollbackErased = true
				}
			},
		})
	}
	events := make([]terminalGraphemeEvent, 0, len(b))
	for i := range b {
		action := a.parser.Advance(b[i])
		if len(a.incomplete) > 0 || a.parser.State() == ansiparser.Utf8State {
			a.incomplete = append(a.incomplete, b[i])
			if action == ansiparser.PrintAction {
				events = append(events, terminalGraphemeEvent{
					raw:       append([]byte(nil), a.incomplete...),
					printable: true,
					rune:      a.parser.Rune(),
				})
				a.incomplete = a.incomplete[:0]
			}
			continue
		}
		events = append(events, terminalGraphemeEvent{
			raw:       b[i : i+1],
			printable: action == ansiparser.PrintAction,
			rune:      rune(b[i]),
		})
	}
	return events
}

func writeTerminalGraphemeBase(term *vt.Emulator, raw []byte) *uv.Cell {
	before := term.CursorPosition()
	_, _ = term.Write(raw)
	after := term.CursorPosition()
	x := after.X - 1
	if term.Width() == 1 || before == after {
		x = after.X
	}
	cell := term.CellAt(x, after.Y)
	for x > 0 && cell != nil && cell.Width == 0 {
		x--
		cell = term.CellAt(x, after.Y)
	}
	return cell
}

func terminalRuneIsCombiningMark(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Me)
}

func (s *vtTerminalSurface) Size() terminalSize {
	s.mu.Lock()
	defer s.mu.Unlock()
	return terminalSize{Cols: s.term.Width(), Rows: s.term.Height()}
}

func (s *vtTerminalSurface) Cell(x int, y int) terminalCell {
	s.mu.Lock()
	defer s.mu.Unlock()
	cols, rows := s.term.Width(), s.term.Height()
	if x < 0 || y < 0 || x >= cols || y >= rows {
		return terminalCellFromUV(uv.EmptyCell)
	}
	row := y
	if !s.term.IsAltScreen() {
		row = s.term.ScrollbackLen() - s.offsetFromBottom + y
	}
	cell, ownerCol := s.cellAtCombinedLocked(row, x)
	if cell == nil {
		return terminalCellFromUV(uv.EmptyCell)
	}
	result := terminalCellFromUV(*cell.Clone())
	result.Selected = s.selection.contains(terminalBufferPosition{Row: row, Col: ownerCol})
	return result
}

func (s *vtTerminalSurface) cellAtCombinedLocked(row, col int) (*uv.Cell, int) {
	if row < 0 || col < 0 || col >= s.term.Width() {
		return nil, col
	}
	cell := s.cellAtBufferLocked(row, col)
	for col > 0 && cell != nil && cell.Width == 0 {
		col--
		cell = s.cellAtBufferLocked(row, col)
	}
	if cell == nil {
		empty := uv.EmptyCell
		return &empty, col
	}
	return cell, col
}

func (s *vtTerminalSurface) cellAtBufferLocked(row, col int) *uv.Cell {
	if s.term.IsAltScreen() {
		if row >= s.term.Height() {
			return nil
		}
		return s.term.CellAt(col, row)
	}
	scrollbackLen := s.term.ScrollbackLen()
	if row < scrollbackLen {
		return s.term.ScrollbackCellAt(col, row)
	}
	if row < scrollbackLen+s.term.Height() {
		return s.term.CellAt(col, row-scrollbackLen)
	}
	return nil
}

func (s *vtTerminalSurface) Cursor() terminalCursorView {
	s.mu.Lock()
	defer s.mu.Unlock()
	cursor := s.term.CursorPosition()
	return terminalCursorView{
		cursor:  terminalPoint{X: cursor.X, Y: cursor.Y},
		visible: s.cursorVisible && s.cursorActive && s.offsetFromBottom == 0,
	}
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

func (s *vtTerminalSurface) ScrollLines(delta int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.term.IsAltScreen() {
		return false
	}
	previous := s.offsetFromBottom
	s.offsetFromBottom = minInt(maxInt(s.offsetFromBottom+delta, 0), s.term.ScrollbackLen())
	return s.offsetFromBottom != previous
}

func (s *vtTerminalSurface) ResetViewport() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offsetFromBottom == 0 {
		return false
	}
	s.offsetFromBottom = 0
	return true
}

func (s *vtTerminalSurface) ViewportState() terminalViewportState {
	s.mu.Lock()
	defer s.mu.Unlock()
	alternateScreen := s.term.IsAltScreen()
	scrollbackLines := s.term.ScrollbackLen()
	if alternateScreen {
		scrollbackLines = 0
	}
	return terminalViewportState{
		OffsetFromBottom: s.offsetFromBottom,
		ScrollbackLines:  scrollbackLines,
		Rows:             s.term.Height(),
		AlternateScreen:  alternateScreen,
	}
}

func (s *vtTerminalSurface) SetCursorActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursorActive = active
}

func (s *vtTerminalSurface) IsAltScreen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.term.IsAltScreen()
}

func (s *vtTerminalSurface) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.drainDone
		return nil
	}
	s.closed = true
	input := s.term.InputPipe()
	s.mu.Unlock()
	var err error
	if closer, ok := input.(io.Closer); ok {
		err = closer.Close()
	}
	<-s.drainDone
	s.mu.Lock()
	closeErr := s.term.Close()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return closeErr
}

func (s *vtTerminalSurface) setPrivateMode(mode ansi.Mode, enabled bool) {
	if _, ok := mode.(ansi.DECMode); !ok {
		return
	}
	s.privateModes[mode.Mode()] = enabled
	s.mouse = MouseMode{
		Enabled: s.privateModes[ansi.ModeMouseNormal.Mode()] ||
			s.privateModes[ansi.ModeMouseButtonEvent.Mode()] ||
			s.privateModes[ansi.ModeMouseAnyEvent.Mode()],
		SGR: s.privateModes[ansi.ModeMouseExtSgr.Mode()],
	}
	s.inputMode = TerminalInputMode{
		ApplicationCursor: s.privateModes[ansi.ModeCursorKeys.Mode()],
		BracketedPaste:    s.privateModes[ansi.ModeBracketedPaste.Mode()],
		AlternateScroll:   s.privateModes[ansi.DECMode(1007).Mode()],
	}
}

func terminalCellFromUV(cell uv.Cell) terminalCell {
	return terminalCell{Content: cell.Content, Width: cell.Width, Style: cell.Style}
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
	activeStyle := uv.Style{}
	last := cursor.lastColumn(surface, width, y)
	for x := 0; x <= last; {
		cell := surface.Cell(x, y)
		if cell.Width == 0 {
			x++
			continue
		}
		cell = normalizeTerminalCell(cell)
		style := cursor.styleCell(cell, x, y)
		writeTerminalCell(&b, cell.Content, style, &activeStyle)
		x += maxInt(cell.Width, 1)
	}
	if !activeStyle.IsZero() {
		b.WriteString(ansi.ResetStyle)
	}
	return b.String()
}
