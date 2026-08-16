// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"
	"io"
	"strings"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
)

type TerminalPane interface {
	Write(p []byte) (int, error)
	Resize(cols int, rows int)
	View(width int, height int) string
	MouseMode() MouseMode
	InputMode() TerminalInputMode
}

type terminalViewportInteraction interface {
	ScrollLines(delta int) bool
	ResetViewport() bool
	ViewportState() terminalViewportState
}

type terminalInteraction interface {
	terminalViewportInteraction
	BeginSelection(x, y int) bool
	UpdateSelection(x, y int) bool
	FinishSelection() (string, bool)
	SelectWord(x, y int) (string, bool)
	ClearSelection()
	SelectionActive() bool
}

type terminalCursorProvider interface {
	TerminalCursor() terminalCursorView
}

type MouseMode struct {
	Enabled bool
	SGR     bool
}

type TerminalInputMode struct {
	ApplicationCursor bool
	BracketedPaste    bool
	AlternateScroll   bool
	FocusEvents       bool
}

type vtTerminalPane struct {
	surface *vtTerminalSurface
}

var (
	_ TerminalPane                = (*vtTerminalPane)(nil)
	_ terminalViewportInteraction = (*vtTerminalPane)(nil)
	_ terminalInteraction         = (*vtTerminalPane)(nil)
	_ io.Closer                   = (*vtTerminalPane)(nil)
)

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
	return renderTerminalSurfaceRows(p.surface, terminalRenderOptions{Width: width, Height: height})
}

func (p *vtTerminalPane) MouseMode() MouseMode {
	return p.surface.MouseMode()
}

func (p *vtTerminalPane) InputMode() TerminalInputMode {
	return p.surface.InputMode()
}

func (p *vtTerminalPane) TerminalCursor() terminalCursorView {
	return p.surface.Cursor()
}

func (p *vtTerminalPane) SetCursorActive(active bool) {
	p.surface.SetCursorActive(active)
}

func (p *vtTerminalPane) ScrollLines(delta int) bool {
	return p.surface.ScrollLines(delta)
}

func (p *vtTerminalPane) ResetViewport() bool {
	return p.surface.ResetViewport()
}

func (p *vtTerminalPane) ViewportState() terminalViewportState {
	return p.surface.ViewportState()
}

func (p *vtTerminalPane) BeginSelection(x, y int) bool { return p.surface.BeginSelection(x, y) }

func (p *vtTerminalPane) UpdateSelection(x, y int) bool { return p.surface.UpdateSelection(x, y) }

func (p *vtTerminalPane) FinishSelection() (string, bool) { return p.surface.FinishSelection() }

func (p *vtTerminalPane) SelectWord(x, y int) (string, bool) { return p.surface.SelectWord(x, y) }

func (p *vtTerminalPane) ClearSelection() { p.surface.ClearSelection() }

func (p *vtTerminalPane) SelectionActive() bool { return p.surface.SelectionActive() }

func (p *vtTerminalPane) Close() error {
	return p.surface.Close()
}

type terminalCursorView struct {
	cursor  terminalPoint
	visible bool
	style   vt.CursorStyle
	steady  bool
	color   color.Color
}

func writeTerminalCell(
	b *strings.Builder,
	content string,
	style uv.Style,
	link uv.Link,
	activeStyle *uv.Style,
	activeLink *uv.Link,
) {
	if terminalBlankCellShouldUseDefaultStyle(content, style) {
		style = uv.Style{}
	}
	if !style.Equal(activeStyle) {
		b.WriteString(style.Diff(activeStyle))
		*activeStyle = style
	}
	if link != *activeLink && !activeLink.IsZero() {
		b.WriteString(ansi.ResetHyperlink())
		*activeLink = uv.Link{}
	}
	if link != *activeLink && !link.IsZero() {
		b.WriteString(ansi.SetHyperlink(link.URL, link.Params))
		*activeLink = link
	}
	b.WriteString(content)
}

func (c terminalCursorView) lastColumn(surface TerminalSurface, width int, y int) int {
	last := terminalLastRenderableColumn(surface, width, y)
	if c.visibleAt(y, width) && c.cursor.X > last {
		return c.cursor.X
	}
	return last
}

func (c terminalCursorView) styleCell(cell terminalCell, x int, y int) uv.Style {
	style := cell.Style
	if cell.Selected {
		style.Attrs ^= uv.AttrReverse
	}
	if c.visible && c.cursor.Y == y && c.cursor.X == x {
		style.Attrs |= uv.AttrReverse
		return style
	}
	return style
}

func (c terminalCursorView) visibleAt(y int, width int) bool {
	return c.visible && c.cursor.Y == y && c.cursor.X >= 0 && c.cursor.X < width
}

func terminalLastRenderableColumn(surface TerminalSurface, width int, y int) int {
	for x := width - 1; x >= 0; x-- {
		cell := surface.Cell(x, y)
		if cell.Selected {
			return x
		}
		if cell.Width == 0 {
			continue
		}
		if cell.Content != "" && cell.Content != " " {
			return x
		}
		if terminalBlankCellHasVisibleStyle(cell) {
			return x
		}
	}
	return -1
}

func normalizeTerminalCell(cell terminalCell) terminalCell {
	if cell.Content == "" {
		cell.Content = " "
		cell.Width = 1
	}
	return cell
}

func terminalBlankCellShouldUseDefaultStyle(content string, style uv.Style) bool {
	return content == " " && !terminalCellVisibleOnBlank(style)
}

func terminalBlankCellHasVisibleStyle(cell terminalCell) bool {
	return cell.Content == " " && terminalCellVisibleOnBlank(cell.Style)
}

func terminalCellVisibleOnBlank(style uv.Style) bool {
	return style.Attrs&uv.AttrReverse != 0 || style.Bg != nil
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
