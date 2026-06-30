// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestCanvasOverlayFillsDialogButtonRow(t *testing.T) {
	dialogStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#CDD6F4")).Background(lipgloss.Color("#1E1E2E"))
	buttonStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#11111B")).Background(lipgloss.Color("#74C7EC"))
	canvas := NewFrameCanvas(80, 24, lipgloss.NewStyle())
	dialog := Rect{X: 20, Y: 8, W: 40, H: 7}

	canvas.Fill(dialog, Cell{Rune: ' ', Style: dialogStyle})
	canvas.DrawText(22, 12, "Restart Shell", buttonStyle)

	for x := dialog.X; x < dialog.X+dialog.W; x++ {
		got := canvas.Cell(x, 12).Style.GetBackground()
		if got != dialogStyle.GetBackground() && got != buttonStyle.GetBackground() {
			t.Fatalf("x=%d button row bg=%q, want dialog or button bg", x, got)
		}
	}
}

func TestFrameCanvasOverlayClipsAndRenders(t *testing.T) {
	base := NewFrameCanvas(6, 2, lipgloss.NewStyle())
	base.DrawText(0, 0, "abcdef", lipgloss.NewStyle())
	overlay := NewFrameCanvas(4, 1, lipgloss.NewStyle().Background(lipgloss.Color("#000000")))
	overlay.DrawText(0, 0, "WXYZ", lipgloss.NewStyle().Background(lipgloss.Color("#000000")))

	base.Overlay(overlay, Point{X: 3, Y: 0})

	got := ansiPattern.ReplaceAllString(strings.Split(base.Render(), "\n")[0], "")
	if got != "abcWXY" {
		t.Fatalf("rendered line = %q, want clipped overlay", got)
	}
}

func TestReadANSISequence(t *testing.T) {
	tests := []struct {
		name string
		in   string
		seq  string
		n    int
	}{
		{name: "none", in: "plain", seq: "", n: 0},
		{name: "single escape", in: "\x1b", seq: "\x1b", n: 1},
		{name: "csi", in: "\x1b[38;2;1;2;3mX", seq: "\x1b[38;2;1;2;3m", n: len("\x1b[38;2;1;2;3m")},
		{name: "osc bel", in: "\x1b]52;c;abc\aX", seq: "\x1b]52;c;abc\a", n: len("\x1b]52;c;abc\a")},
		{name: "osc st", in: "\x1b]0;title\x1b\\X", seq: "\x1b]0;title\x1b\\", n: len("\x1b]0;title\x1b\\")},
		{name: "short", in: "\x1b>X", seq: "\x1b>", n: len("\x1b>")},
		{name: "incomplete csi", in: "\x1b[38;2", seq: "\x1b[38;2", n: len("\x1b[38;2")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seq, n := readANSISequence(tt.in)
			if seq != tt.seq || n != tt.n {
				t.Fatalf("readANSISequence(%q) = (%q, %d), want (%q, %d)", tt.in, seq, n, tt.seq, tt.n)
			}
		})
	}
}
