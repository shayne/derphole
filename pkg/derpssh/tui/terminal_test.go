// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func newVTTerminalPaneForTest(t *testing.T, cols, rows int) TerminalPane {
	t.Helper()
	pane := NewVTTerminalPane(cols, rows)
	closer, ok := pane.(io.Closer)
	if !ok {
		t.Fatal("VT terminal pane does not implement io.Closer")
	}
	t.Cleanup(func() { _ = closer.Close() })
	return pane
}

func TestVTTerminalPaneForwardsViewportInteraction(t *testing.T) {
	pane := NewVTTerminalPane(12, 5)
	closer, ok := pane.(io.Closer)
	if !ok {
		t.Fatal("VT terminal pane does not implement io.Closer")
	}
	t.Cleanup(func() { _ = closer.Close() })
	viewport, ok := pane.(terminalViewportInteraction)
	if !ok {
		t.Fatal("VT terminal pane does not implement terminalViewportInteraction")
	}

	if _, err := pane.Write([]byte("01\r\n02\r\n03\r\n04\r\n05\r\n06\r\n07")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !viewport.ScrollLines(2) {
		t.Fatal("ScrollLines(2) = false, want visible viewport change")
	}
	if got := viewport.ViewportState().OffsetFromBottom; got != 2 {
		t.Fatalf("offset = %d, want 2", got)
	}
	if view := ansiPattern.ReplaceAllString(pane.View(12, 5), ""); !strings.HasPrefix(view, "01\n02\n03") {
		t.Fatalf("historical pane view = %q", view)
	}
	if !viewport.ResetViewport() || viewport.ViewportState().OffsetFromBottom != 0 {
		t.Fatalf("ResetViewport() did not return pane to live bottom: %+v", viewport.ViewportState())
	}
}

func TestVTTerminalPaneForwardsTerminalInteraction(t *testing.T) {
	pane := NewVTTerminalPane(12, 2)
	closer := pane.(io.Closer)
	t.Cleanup(func() { _ = closer.Close() })
	interaction, ok := pane.(terminalInteraction)
	if !ok {
		t.Fatal("VT terminal pane does not implement terminalInteraction")
	}
	if _, err := pane.Write([]byte("alpha\r\nbeta")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !interaction.BeginSelection(0, 0) || !interaction.UpdateSelection(3, 1) {
		t.Fatal("could not create selection through pane")
	}
	if got, ok := interaction.FinishSelection(); !ok || got != "alpha\nbeta" {
		t.Fatalf("FinishSelection() = (%q, %v), want (alpha\\nbeta, true)", got, ok)
	}
	interaction.ClearSelection()
	if interaction.SelectionActive() {
		t.Fatal("SelectionActive() = true after ClearSelection()")
	}
}

func TestVTTerminalPanePreservesANSIStyleOutput(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 20, 4)

	if _, err := pane.Write([]byte("plain \x1b[31mred\x1b[0m\x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	stripped := ansiPattern.ReplaceAllString(view, "")
	if !strings.Contains(stripped, "plain red") {
		t.Fatalf("View() = %q, want rendered ANSI text", view)
	}
	if !strings.Contains(view, "\x1b[31mred"+ansi.ResetStyle) {
		t.Fatalf("View() stripped terminal color styling: %q", view)
	}
	if width := visibleWidth(strings.Split(view, "\n")[0]); width != len("plain red") {
		t.Fatalf("first line visible width = %d, want %d: %q", width, len("plain red"), view)
	}
}

func TestVTTerminalPanePreservesStyledSpaces(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 20, 4)

	if _, err := pane.Write([]byte("load \x1b[48;5;34m  \x1b[0m done")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	if !strings.Contains(view, "\x1b[48;5;34m  "+ansi.ResetStyle) {
		t.Fatalf("View() stripped styled spaces used by rich TUIs: %q", view)
	}
	if !strings.Contains(view, "load ") || !strings.Contains(view, " done") {
		t.Fatalf("View() missing plain text around styled cells: %q", view)
	}
}

func TestVTTerminalPaneSuppressesUnderlineOnlyBlankCells(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 20, 4)

	if _, err := pane.Write([]byte("vim\x1b[4m          \x1b[0m\x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(20, 4)
	firstLine := strings.Split(view, "\n")[0]
	if strings.Contains(firstLine, "\x1b[4m") {
		t.Fatalf("View() rendered underline-only blank cells as visible rules: %q", view)
	}
	if width := visibleWidth(firstLine); width != len("vim") {
		t.Fatalf("first line visible width = %d, want %d: %q", width, len("vim"), view)
	}
}

func TestVTTerminalPaneHandlesCursorMovement(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 10, 3)

	if _, err := pane.Write([]byte("abc\x1b[2DZ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	stripped := ansiPattern.ReplaceAllString(view, "")
	if !strings.Contains(stripped, "aZc") {
		t.Fatalf("View() = %q, want cursor movement to overwrite middle cell", view)
	}
}

func TestVTTerminalPaneRendersVisibleCursorOnBlankCell(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 10, 3)

	if _, err := pane.Write([]byte("$ ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	if !strings.Contains(view, "\x1b[7m "+ansi.ResetStyle) {
		t.Fatalf("View() = %q, want visible reverse-video cursor cell", view)
	}
	if width := visibleWidth(strings.Split(view, "\n")[0]); width != len("$  ") {
		t.Fatalf("first line visible width = %d, want cursor cell included: %q", width, view)
	}
}

func TestVTTerminalPaneViewClampsReadsToBufferSize(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 101, 30)

	if _, err := pane.Write([]byte("root@host:~# ")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(131, 33)
	lines := strings.Split(view, "\n")
	if len(lines) != 33 {
		t.Fatalf("View line count = %d, want 33", len(lines))
	}
	if !strings.Contains(ansiPattern.ReplaceAllString(lines[0], ""), "root@host") {
		t.Fatalf("View() lost terminal content:\n%s", view)
	}
}

func TestVTTerminalPaneHidesCursorWhenDECTCEMDisabled(t *testing.T) {
	pane := newVTTerminalPaneForTest(t, 10, 3)

	if _, err := pane.Write([]byte("$ \x1b[?25l")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	view := pane.View(10, 3)
	if strings.Contains(view, "\x1b[7m") {
		t.Fatalf("View() = %q, want hidden cursor to omit reverse-video overlay", view)
	}
}
