// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

type ModalID string

const (
	ModalResizeWarning   ModalID = "resize_warning"
	ModalWaitingApproval ModalID = "waiting_approval"
	ModalHelp            ModalID = "help"
	ModalKick            ModalID = "kick"
	ModalPeerAction      ModalID = "peer_action"
	ModalApproval        ModalID = "approval"
	ModalQuit            ModalID = "quit"
	ModalShellExit       ModalID = "shell_exit"
	ModalNotice          ModalID = "notice"
)

type ModalFrame struct {
	Width    int
	Height   int
	Styles   StyleSet
	Backdrop string
}

type ModalDialog interface {
	ID() ModalID
	Lines() []string
}

type LineDialog struct {
	id    ModalID
	lines []string
}

func NewLineDialog(id ModalID, lines []string) LineDialog {
	return LineDialog{id: id, lines: append([]string(nil), lines...)}
}

func (d LineDialog) ID() ModalID {
	return d.id
}

func (d LineDialog) Lines() []string {
	return append([]string(nil), d.lines...)
}

type ModalStack struct {
	dialogs []ModalDialog
}

func NewModalStack(dialogs ...ModalDialog) *ModalStack {
	stack := &ModalStack{}
	for _, dialog := range dialogs {
		stack.Push(dialog)
	}
	return stack
}

func (s *ModalStack) Push(dialog ModalDialog) {
	if s == nil || dialog == nil {
		return
	}
	s.dialogs = append(s.dialogs, dialog)
}

func (s *ModalStack) HasDialogs() bool {
	return s != nil && len(s.dialogs) > 0
}

func (s *ModalStack) Front() ModalDialog {
	if !s.HasDialogs() {
		return nil
	}
	return s.dialogs[len(s.dialogs)-1]
}

func (s *ModalStack) IDs() []ModalID {
	if s == nil {
		return nil
	}
	ids := make([]ModalID, 0, len(s.dialogs))
	for _, dialog := range s.dialogs {
		ids = append(ids, dialog.ID())
	}
	return ids
}

func modalBounds(frame ModalFrame, body []string) Rect {
	boxW := modalBodyWidth(body) +
		frame.Styles.Modal.GetHorizontalBorderSize() +
		frame.Styles.Modal.GetHorizontalPadding()
	if frame.Width > 0 {
		boxW = minInt(boxW, frame.Width-2)
	}
	boxW = maxInt(boxW, 1)
	boxH := len(body) +
		frame.Styles.Modal.GetVerticalBorderSize() +
		frame.Styles.Modal.GetVerticalPadding()
	return Rect{
		X: maxInt((frame.Width-boxW)/2, 0),
		Y: maxInt((frame.Height-boxH)/2, 1),
		W: boxW,
		H: boxH,
	}
}
