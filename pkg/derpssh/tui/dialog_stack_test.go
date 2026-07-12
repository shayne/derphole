// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func TestModalStackKeepsFrontDialogLast(t *testing.T) {
	stack := NewModalStack()
	stack.Push(NewLineDialog(ModalNotice, []string{"Back"}))
	stack.Push(NewLineDialog(ModalQuit, []string{"Front"}))

	if !stack.HasDialogs() {
		t.Fatal("stack should report active dialogs")
	}
	if got := stack.Front().ID(); got != ModalQuit {
		t.Fatalf("front dialog = %q, want %q", got, ModalQuit)
	}
	if got := stack.Front().Lines(); len(got) != 1 || got[0] != "Front" {
		t.Fatalf("front dialog lines = %v, want Front", got)
	}
}

func TestLineDialogCopiesLines(t *testing.T) {
	lines := []string{"Notice", ""}
	dialog := NewLineDialog(ModalNotice, []string{
		lines[0],
		lines[1],
	})
	lines[0] = "Changed"
	got := dialog.Lines()
	got[0] = "Mutated"
	if want := "Notice"; dialog.Lines()[0] != want {
		t.Fatalf("dialog line = %q, want %q", dialog.Lines()[0], want)
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
