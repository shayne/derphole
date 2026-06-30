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
	Width  int
	Height int
}

type ModalDialog interface {
	ID() ModalID
	Lines() []string
	Draw(*FrameCanvas, ModalFrame)
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

func (d LineDialog) Draw(canvas *FrameCanvas, frame ModalFrame) {
	drawModalLines(canvas, frame, d.lines)
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

func (s *ModalStack) Draw(canvas *FrameCanvas, frame ModalFrame) {
	if s == nil {
		return
	}
	for _, dialog := range s.dialogs {
		dialog.Draw(canvas, frame)
	}
}

func drawModalLines(canvas *FrameCanvas, frame ModalFrame, body []string) {
	if canvas == nil || frame.Width <= 0 || frame.Height <= 0 {
		return
	}
	box := renderModalBox(body)
	bounds := modalBounds(frame, body)
	overlay := NewFrameCanvas(bounds.W, bounds.H, modalInteriorStyle)
	for i, line := range box {
		overlay.DrawANSIText(0, i, fitLine(line, bounds.W), modalInteriorStyle)
	}
	canvas.Overlay(overlay, Point{X: bounds.X, Y: bounds.Y})
}

func modalBounds(frame ModalFrame, body []string) Rect {
	box := renderModalBox(body)
	boxW := modalOverlayWidth(frame.Width, box)
	boxH := len(box)
	return Rect{
		X: maxInt((frame.Width-boxW)/2, 0),
		Y: maxInt((frame.Height-boxH)/2, 1),
		W: boxW,
		H: boxH,
	}
}

func modalOverlayWidth(frameWidth int, box []string) int {
	boxW := 0
	for _, line := range box {
		boxW = maxInt(boxW, displayWidth(line))
	}
	if frameWidth > 0 {
		boxW = minInt(boxW, frameWidth-2)
	}
	return maxInt(boxW, 1)
}
