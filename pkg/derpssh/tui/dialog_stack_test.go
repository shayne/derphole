// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestModalStackDrawsFrontDialogLast(t *testing.T) {
	canvas := NewFrameCanvas(48, 14, lipgloss.NewStyle())
	stack := NewModalStack()
	stack.Push(NewLineDialog(ModalNotice, []string{labelStyle.Render("Back")}))
	stack.Push(NewLineDialog(ModalQuit, []string{labelStyle.Render("Front")}))

	if !stack.HasDialogs() {
		t.Fatal("stack should report active dialogs")
	}
	if got := stack.Front().ID(); got != ModalQuit {
		t.Fatalf("front dialog = %q, want %q", got, ModalQuit)
	}

	stack.Draw(canvas, ModalFrame{Width: 48, Height: 14})

	view := ansiPattern.ReplaceAllString(canvas.Render(), "")
	if !strings.Contains(view, "Front") {
		t.Fatalf("front dialog not drawn:\n%s", view)
	}
	if strings.Contains(view, "Back") {
		t.Fatalf("back dialog cut through front dialog:\n%s", view)
	}
}

func TestLineDialogFillsInteriorBlankCells(t *testing.T) {
	canvas := NewFrameCanvas(48, 14, lipgloss.NewStyle())
	dialog := NewLineDialog(ModalNotice, []string{
		labelStyle.Render("Notice"),
		modalInteriorStyle.Render(""),
	})
	frame := ModalFrame{Width: 48, Height: 14}

	dialog.Draw(canvas, frame)

	bounds := modalBounds(frame, dialog.Lines())
	cell := canvas.Cell(bounds.X+1, bounds.Y+2)
	if got, want := cell.Style.GetBackground(), modalInteriorStyle.GetBackground(); got != want {
		t.Fatalf("blank interior background = %v, want %v", got, want)
	}
}

func TestAppBuildsModalStackInRenderOrder(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	app.openQuitConfirm()
	app.noticeTitle = "Guest left"
	app.noticeBody = "guest quit"

	stack := app.modalStack()
	if got := stack.IDs(); !sameModalIDs(got, []ModalID{ModalApproval, ModalQuit, ModalNotice}) {
		t.Fatalf("modal stack IDs = %v, want approval, quit, notice", got)
	}
	if got := stack.Front().ID(); got != ModalNotice {
		t.Fatalf("front dialog = %q, want %q", got, ModalNotice)
	}
}

func sameModalIDs(got []ModalID, want []ModalID) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
