// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"
	"strings"
	"testing"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
)

var _ TerminalSurface = (*vtTerminalSurface)(nil)

func TestVTTerminalSurfaceScrollsRetainedRows(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 5})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07"))

	if got := surface.ViewportState().ScrollbackLines; got != 2 {
		t.Fatalf("scrollback = %d, want 2", got)
	}
	surface.ScrollLines(2)
	if got := plainSurfaceRows(surface, 12, 5); !strings.HasPrefix(got, "01\n02\n03") {
		t.Fatalf("historical view = %q", got)
	}
	surface.ScrollLines(999)
	if got := surface.ViewportState().OffsetFromBottom; got != 2 {
		t.Fatalf("offset = %d, want 2", got)
	}
	surface.ScrollLines(-999)
	if got := surface.ViewportState().OffsetFromBottom; got != 0 {
		t.Fatalf("offset = %d, want 0", got)
	}
}

func TestVTTerminalSurfacePreservesScrolledViewportOnWrite(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 5})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07"))
	surface.ScrollLines(2)
	before := plainSurfaceRows(surface, 12, 5)

	surface.Write([]byte("\r\n08\r\n09"))
	if got := plainSurfaceRows(surface, 12, 5); got != before {
		t.Fatalf("viewport after output = %q, want preserved %q", got, before)
	}
}

func TestVTTerminalSurfaceClampsViewportWhenScrollbackClears(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 5})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07"))
	surface.ScrollLines(2)

	surface.Write([]byte("\x1b[3J"))
	if got := surface.ViewportState(); got.ScrollbackLines != 0 || got.OffsetFromBottom != 0 {
		t.Fatalf("viewport after clearing scrollback = %+v, want zero history and offset", got)
	}
}

func TestVTTerminalSurfaceResetsViewportForAlternateScreen(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 5})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07"))

	if got := surface.ViewportState().OffsetFromBottom; got != 0 {
		t.Fatalf("live bottom offset = %d, want 0", got)
	}
	surface.Write([]byte("\r\n08"))
	if got := surface.ViewportState().OffsetFromBottom; got != 0 {
		t.Fatalf("live bottom offset after output = %d, want 0", got)
	}

	surface.ScrollLines(1)
	surface.Write([]byte("\x1b[?1049h"))
	if got := surface.ViewportState(); !got.AlternateScreen || got.OffsetFromBottom != 0 || got.ScrollbackLines != 0 {
		t.Fatalf("alternate-screen state = %+v, want zero offset and scrollback", got)
	}

	surface.ScrollLines(1)
	surface.Write([]byte("\x1b[?1049l"))
	if got := surface.ViewportState(); got.AlternateScreen || got.OffsetFromBottom != 0 {
		t.Fatalf("main-screen state = %+v, want zero offset", got)
	}
}

func TestTerminalSurfaceRendersGraphemesAndStyledBlanks(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	surface.Write([]byte("界e\u0301\x1b[7m \x1b[0m\x1b[48;5;34m \x1b[0m\x1b[4m \x1b[0m"))

	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 20, Height: 2})
	plain := ansiPattern.ReplaceAllString(view, "")
	if strings.Count(plain, "界") != 1 {
		t.Fatalf("wide grapheme count = %d, want 1: %q", strings.Count(plain, "界"), view)
	}
	if strings.Count(plain, "e\u0301") != 1 {
		t.Fatalf("combining grapheme count = %d, want 1: %q", strings.Count(plain, "e\u0301"), view)
	}
	if width := visibleWidth(strings.Split(view, "\n")[0]); width != 5 {
		t.Fatalf("visible width = %d, want 5 with reverse and background blanks only: %q", width, view)
	}
	if strings.Contains(view, "\x1b[4m") {
		t.Fatalf("underline-only trailing blank rendered visibly: %q", view)
	}
}

func TestVTTerminalSurfacePreservesASCIICombiningGraphemeAcrossWriteChunks(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)

	surface.Write([]byte("e"))
	surface.Write([]byte{0xcc})
	surface.Write([]byte{0x81})
	surface.Write([]byte("\x1b[7m \x1b[0m"))

	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 20, Height: 2})
	plain := ansiPattern.ReplaceAllString(view, "")
	if strings.Count(plain, "e\u0301") != 1 {
		t.Fatalf("combining grapheme count = %d, want 1 across split UTF-8 writes: %q", strings.Count(plain, "e\u0301"), view)
	}
}

func TestVTTerminalSurfacePreservesNonASCIICombiningGraphemeAcrossWriteChunks(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)

	for _, chunk := range [][]byte{{0xce}, {0xb1}, {0xcc}, {0x81}} {
		surface.Write(chunk)
	}
	surface.Write([]byte("\x1b[1mX\x1b[0m"))

	if got, want := surface.Cell(0, 0).Content, "α\u0301"; got != want {
		t.Fatalf("split non-ASCII grapheme bytes = % x, want decomposed % x", []byte(got), []byte(want))
	}
	if cell := surface.Cell(1, 0); cell.Content != "X" || cell.Style.Attrs&uv.AttrBold == 0 {
		t.Fatalf("styled cell after split grapheme = %+v, want bold X", cell)
	}
	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 20, Height: 2})
	if plain := ansiPattern.ReplaceAllString(view, ""); strings.Count(plain, "α\u0301") != 1 {
		t.Fatalf("split non-ASCII grapheme rendered incorrectly: %q", view)
	}
}

func TestVTTerminalSurfaceDoesNotRepairGraphemeAcrossStyleBoundary(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)

	surface.Write([]byte("α"))
	surface.Write([]byte("\x1b[1m"))
	surface.Write([]byte("\u0301"))
	surface.Write([]byte("X\x1b[0m"))

	if got := surface.Cell(0, 0).Content; got != "α" {
		t.Fatalf("style boundary mutated preceding cell to %q, want alpha only", got)
	}
	if cell := surface.Cell(1, 0); cell.Content != "X" || cell.Style.Attrs&uv.AttrBold == 0 {
		t.Fatalf("cell after styled combining mark = %+v, want bold X", cell)
	}
}

func TestVTTerminalSurfacePreservesCombiningTextInSplitOSCPayload(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	payload := "title e\u0301"
	var title string
	surface.term.SetCallbacks(vt.Callbacks{Title: func(value string) { title = value }})

	surface.Write([]byte("\x1b]2;title e"))
	surface.Write([]byte{0xcc})
	surface.Write([]byte{0x81})
	surface.Write([]byte("\x07ok"))
	if title != payload {
		t.Fatalf("title payload bytes = % x, want % x", []byte(title), []byte(payload))
	}

	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 20, Height: 2})
	if plain := ansiPattern.ReplaceAllString(view, ""); plain != "ok\n" {
		t.Fatalf("OSC payload changed rendered content: %q", view)
	}
}

func TestRenderTerminalSurfaceRowSkipsWidthZeroContinuationCells(t *testing.T) {
	surface := terminalCellSurface{cells: [][]terminalCell{{
		{Content: "界", Width: 2},
		{Content: "duplicate", Width: 0},
	}}}

	if got := renderTerminalSurfaceRow(&surface, 2, 0, terminalCursorView{}); got != "界" {
		t.Fatalf("rendered continuation = %q, want only leading grapheme", got)
	}
}

func TestRenderTerminalSurfaceRowUsesStyleDiff(t *testing.T) {
	surface := terminalCellSurface{cells: [][]terminalCell{{
		{Content: "A", Width: 1, Style: uv.Style{Attrs: uv.AttrBold}},
		{Content: "B", Width: 1, Style: uv.Style{Attrs: uv.AttrReverse}},
	}}}

	view := renderTerminalSurfaceRow(&surface, 2, 0, terminalCursorView{})
	if strings.Contains(view, "\x1b[0m\x1b[7m") {
		t.Fatalf("style transition resets before applying next style: %q", view)
	}
}

func TestVTTerminalSurfaceRendersOnlySelectedCellsInReverseVideo(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	surface.Write([]byte("abc"))
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(1, 0) {
		t.Fatal("could not create selection")
	}

	if !surface.Cell(0, 0).Selected || !surface.Cell(1, 0).Selected || surface.Cell(2, 0).Selected {
		t.Fatalf("selected cells = (%v, %v, %v), want (true, true, false)", surface.Cell(0, 0).Selected, surface.Cell(1, 0).Selected, surface.Cell(2, 0).Selected)
	}
	if got := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 12, Height: 2}); !strings.Contains(got, "\x1b[7mab\x1b[mc") {
		t.Fatalf("rendered selection = %q, want only selected span reversed", got)
	}
}

func TestVTTerminalSurfaceSelectionXORsExistingReverseVideo(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 12, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	surface.Write([]byte("x\x1b[7ma\x1b[0m"))
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(1, 0) {
		t.Fatal("could not create selection")
	}

	if got := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: 12, Height: 2}); !strings.Contains(got, "\x1b[7mx\x1b[ma") {
		t.Fatalf("rendered pre-reversed selection = %q, want reverse attribute toggled off for a", got)
	}
}

func TestVTTerminalSurfaceRendersSelectedDefaultStyleTrailingBlanks(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 6, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	surface.Write([]byte("a"))
	if !surface.BeginSelection(0, 0) || !surface.UpdateSelection(4, 0) {
		t.Fatal("could not select trailing blanks")
	}

	view := renderTerminalSurfaceRow(surface, 6, 0, surface.Cursor())
	if plain := ansiPattern.ReplaceAllString(view, ""); plain != "a    " {
		t.Fatalf("selected trailing blanks rendered as %q, want five selected columns", plain)
	}
	if !strings.Contains(view, "\x1b[7ma    "+ansi.ResetStyle) {
		t.Fatalf("selected trailing blanks are not visibly highlighted: %q", view)
	}
}

func TestVTTerminalSurfaceRendersSelectionOnEmptyRowThroughSelectedColumn(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 6, Rows: 2})
	t.Cleanup(func() { _ = surface.Close() })
	surface.SetCursorActive(false)
	if !surface.BeginSelection(1, 0) || !surface.UpdateSelection(4, 0) {
		t.Fatal("could not select empty row")
	}

	view := renderTerminalSurfaceRow(surface, 6, 0, surface.Cursor())
	if plain := ansiPattern.ReplaceAllString(view, ""); plain != "     " {
		t.Fatalf("selected empty row rendered as %q, want columns through selected endpoint", plain)
	}
	if !strings.Contains(view, " \x1b[7m    "+ansi.ResetStyle) {
		t.Fatalf("empty-row selection is not visibly highlighted: %q", view)
	}
}

func plainSurfaceRows(surface TerminalSurface, width, height int) string {
	view := renderTerminalSurfaceRows(surface, terminalRenderOptions{Width: width, Height: height})
	return ansiPattern.ReplaceAllString(view, "")
}

type terminalCellSurface struct {
	cells [][]terminalCell
}

func (s *terminalCellSurface) Write([]byte) {}

func (s *terminalCellSurface) Resize(terminalSize) {}

func (s *terminalCellSurface) Size() terminalSize {
	rows := len(s.cells)
	cols := 0
	if rows > 0 {
		cols = len(s.cells[0])
	}
	return terminalSize{Cols: cols, Rows: rows}
}

func (s *terminalCellSurface) Cell(x int, y int) terminalCell {
	if y < 0 || y >= len(s.cells) || x < 0 || x >= len(s.cells[y]) {
		return terminalCell{Content: " ", Width: 1}
	}
	return s.cells[y][x]
}

func (s *terminalCellSurface) Cursor() terminalCursorView { return terminalCursorView{} }

func (s *terminalCellSurface) MouseMode() terminalMouseMode { return terminalMouseMode{} }

func (s *terminalCellSurface) InputMode() terminalInputMode { return terminalInputMode{} }

func TestVTTerminalSurfaceClampsCellReads(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 30, Rows: 10})
	t.Cleanup(func() { _ = surface.Close() })

	cell := surface.Cell(130, 0)
	if cell.Content != " " || cell.Width != 1 {
		t.Fatalf("out-of-range cell = %+v, want empty terminal cell", cell)
	}
	if !cell.Style.IsZero() {
		t.Fatalf("out-of-range cell style = %#v, want default", cell.Style)
	}
}

func TestVTTerminalSurfaceTracksModesThroughEmulatorCallbacks(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
	t.Cleanup(func() { _ = surface.Close() })

	surface.Write([]byte("\x1b[?10"))
	surface.Write([]byte("00;1006h\x1b[?1;2004;1007h"))

	if got := surface.MouseMode(); got != (MouseMode{Enabled: true, SGR: true}) {
		t.Fatalf("MouseMode() = %+v", got)
	}
	if got := surface.InputMode(); got != (TerminalInputMode{
		ApplicationCursor: true,
		BracketedPaste:    true,
		AlternateScroll:   true,
	}) {
		t.Fatalf("InputMode() = %+v", got)
	}

	surface.Write([]byte("\x1b[?1;1000;1002;1003;1006;1007;2004l"))
	if got := surface.MouseMode(); got != (MouseMode{}) {
		t.Fatalf("MouseMode() after disable = %+v", got)
	}
	if got := surface.InputMode(); got != (TerminalInputMode{}) {
		t.Fatalf("InputMode() after disable = %+v", got)
	}

	surface.Write([]byte("\x1b[1h"))
	if got := surface.InputMode(); got != (TerminalInputMode{}) {
		t.Fatalf("InputMode() after ANSI mode enable = %+v", got)
	}
}

func TestVTTerminalSurfaceSeparatesMouseTrackingFromSGREncoding(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
	t.Cleanup(func() { _ = surface.Close() })

	surface.Write([]byte("\x1b[?1000;1006h"))
	surface.Write([]byte("\x1b[?1000l"))

	if got, want := surface.MouseMode(), (MouseMode{Enabled: false, SGR: true}); got != want {
		t.Fatalf("MouseMode() after disabling the only tracking mode = %+v, want %+v", got, want)
	}
}

func TestVTTerminalSurfaceTracksButtonAndAnyEventModesIndependently(t *testing.T) {
	for _, mode := range []string{"1002", "1003"} {
		t.Run(mode, func(t *testing.T) {
			surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
			t.Cleanup(func() { _ = surface.Close() })

			surface.Write([]byte("\x1b[?" + mode + "h"))
			if got := surface.MouseMode(); got != (MouseMode{Enabled: true}) {
				t.Fatalf("MouseMode() after enabling %s = %+v, want tracking enabled", mode, got)
			}
		})
	}

	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("\x1b[?1002;1003h"))
	surface.Write([]byte("\x1b[?1002l"))
	if got := surface.MouseMode(); got != (MouseMode{Enabled: true}) {
		t.Fatalf("MouseMode() after disabling 1002 with 1003 retained = %+v, want tracking enabled", got)
	}
}

func TestVTTerminalSurfaceDrainsDeviceResponses(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
	t.Cleanup(func() { _ = surface.Close() })
	done := make(chan struct{})
	go func() {
		surface.Write([]byte("\x1b[6n"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("device query blocked terminal output")
	}
}

func TestVTTerminalSurfaceCloseIsIdempotent(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 20, Rows: 4})
	if err := surface.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := surface.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestTerminalCellVisibleOnBlankDocumentsTerminalSemantics(t *testing.T) {
	underlineOnly := uv.Style{Underline: uv.UnderlineSingle}
	if terminalCellVisibleOnBlank(underlineOnly) {
		t.Fatalf("underline-only blank cell should not be visible")
	}

	withBackground := uv.Style{Bg: color.RGBA{B: 4, A: 255}}
	if !terminalCellVisibleOnBlank(withBackground) {
		t.Fatalf("background-styled blank cell should be visible")
	}

	reverse := uv.Style{Attrs: uv.AttrReverse}
	if !terminalCellVisibleOnBlank(reverse) {
		t.Fatalf("reverse-video blank cell should be visible")
	}
}

func TestTerminalSurfaceDoesNotRenderUnderlineOnlyBlankCells(t *testing.T) {
	surface := newVTTerminalSurface(terminalSize{Cols: 40, Rows: 5})
	t.Cleanup(func() { _ = surface.Close() })
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
	t.Cleanup(func() { _ = surface.Close() })
	surface.Write([]byte("\x1b[?1049h\x1b[H\x1b[4m                                        \x1b[0m\x1b[2;1H\"scratch\" [No Name]\x1b[6;1H:"))
	if !surface.IsAltScreen() {
		t.Fatal("IsAltScreen() = false, want true")
	}

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
