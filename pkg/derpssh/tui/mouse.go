// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"bytes"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
)

const terminalWheelRows = 3

const (
	terminalSelectionAutoscrollMinRows = 3
	terminalSelectionAutoscrollMaxRows = 15
)

var mouseButtonCodes = map[tea.MouseButton]int{
	tea.MouseLeft:      0,
	tea.MouseMiddle:    1,
	tea.MouseRight:     2,
	tea.MouseWheelUp:   64,
	tea.MouseWheelDown: 65,
}

type layerTarget string

type pointerMsg struct {
	Target layerTarget
	Event  tea.MouseMsg
	Mouse  tea.Mouse
}

func newPointerMsg(target layerTarget, msg tea.MouseMsg) pointerMsg {
	return pointerMsg{Target: target, Event: msg, Mouse: msg.Mouse()}
}

func (a *App) handleMouseMessage(msg tea.MouseMsg) tea.Cmd {
	target := a.pointerCapture
	if target == "" {
		mouse := msg.Mouse()
		target = a.buildScene().TargetAt(mouse.X, mouse.Y)
	}
	return HandleMouse(a, newPointerMsg(target, msg))
}

type pointerAction int

const (
	pointerUnknown pointerAction = iota
	pointerClick
	pointerRelease
	pointerMotion
)

func (m pointerMsg) action() pointerAction {
	switch m.Event.(type) {
	case tea.MouseClickMsg, tea.MouseWheelMsg:
		return pointerClick
	case tea.MouseReleaseMsg:
		return pointerRelease
	case tea.MouseMotionMsg:
		return pointerMotion
	default:
		return pointerUnknown
	}
}

func EncodeSGRMouse(msg tea.MouseMsg, terminal Rect) ([]byte, bool) {
	mouse := msg.Mouse()
	if !terminal.contains(mouse.X, mouse.Y) {
		return nil, false
	}
	code := 0
	suffix := "M"
	if _, release := msg.(tea.MouseReleaseMsg); release {
		suffix = "m"
	} else {
		var ok bool
		code, ok = mouseButtonCodes[mouse.Button]
		if !ok {
			return nil, false
		}
		if _, motion := msg.(tea.MouseMotionMsg); motion {
			code += 32
		}
	}
	if mouse.Mod.Contains(tea.ModShift) {
		code += 4
	}
	if mouse.Mod.Contains(tea.ModAlt) {
		code += 8
	}
	if mouse.Mod.Contains(tea.ModCtrl) {
		code += 16
	}
	x := mouse.X - terminal.X + 1
	y := mouse.Y - terminal.Y + 1
	return []byte(fmt.Sprintf("\x1b[<%d;%d;%d%s", code, x, y, suffix)), true
}

func HandleMouse(app *App, pointer pointerMsg) tea.Cmd {
	if app == nil {
		return nil
	}
	if pointer.action() == pointerRelease && !app.terminalSGRReleasePending {
		defer app.releasePointerCapture()
	}
	if cmd, handled := app.handleModalMouse(pointer); handled {
		return cmd
	}
	if app.copyMode {
		if isMouseClick(pointer) && pointer.Target != targetTerminal {
			return app.setCopyMode(false)
		}
		if pointer.Target != targetTerminal {
			return nil
		}
	}
	return app.handleTargetMouse(pointer)
}

func (a *App) handleTargetMouse(pointer pointerMsg) tea.Cmd {
	switch {
	case pointer.Target == targetDivider:
		a.handleDividerMouse(pointer)
		return nil
	case pointer.Target == targetSidebar || pointer.Target == targetComposer:
		a.handleChatMouse(pointer)
		return nil
	case pointer.Target == targetTerminal:
		return a.handleTerminalMouse(pointer)
	case strings.HasPrefix(string(pointer.Target), "action:"):
		return a.handleActionMouse(pointer)
	case strings.HasPrefix(string(pointer.Target), "peer:"):
		a.handlePeerTargetMouse(pointer)
		return nil
	default:
		return nil
	}
}

func isMouseClick(msg pointerMsg) bool {
	_, ok := msg.Event.(tea.MouseClickMsg)
	return ok
}

func (a *App) handleModalMouse(msg pointerMsg) (tea.Cmd, bool) {
	id, ok := a.frontModalID()
	if !ok {
		return nil, false
	}
	switch id {
	case ModalHelp:
		return a.handleHelpMouse(msg), true
	case ModalKick:
		return nil, a.handleKickMouse(msg)
	case ModalPeerAction:
		return a.handlePeerDialogMouse(msg), true
	case ModalApproval:
		return a.handleApprovalMouse(msg)
	case ModalQuit:
		return a.handleQuitMouse(msg), true
	case ModalShellExit:
		return a.handleShellExitMouse(msg), true
	case ModalNotice:
		return nil, a.handleNoticeMouse(msg)
	default:
		a.clearMousePress()
		return nil, true
	}
}

func (a *App) handleShellExitMouse(msg pointerMsg) tea.Cmd {
	choice, ok := shellExitChoiceFromTarget(msg.Target)
	switch msg.action() {
	case pointerClick:
		if !ok {
			a.clearMousePress()
			return nil
		}
		a.shellExitChoice = choice
		a.armMousePress(mousePressShellExit, int(a.shellExitChoice))
	case pointerRelease:
		if ok && a.releaseMousePress(mousePressShellExit, int(choice)) {
			a.shellExitChoice = choice
			a.confirmShellExitChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil
}

func (a *App) handleQuitMouse(msg pointerMsg) tea.Cmd {
	choice, ok := quitChoiceFromTarget(msg.Target)
	switch msg.action() {
	case pointerClick:
		if !ok {
			a.clearMousePress()
			return nil
		}
		a.quitChoice = choice
		a.armMousePress(mousePressQuit, int(a.quitChoice))
	case pointerRelease:
		if ok && a.releaseMousePress(mousePressQuit, int(choice)) {
			a.quitChoice = choice
			a.confirmQuitChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil
}

func (a *App) handlePeerDialogMouse(msg pointerMsg) tea.Cmd {
	choice, ok := peerActionChoiceFromTarget(msg.Target)
	switch msg.action() {
	case pointerClick:
		if !ok {
			a.clearMousePress()
			return nil
		}
		a.peerDialogChoice = choice
		a.armMousePress(mousePressPeerAction, int(a.peerDialogChoice))
	case pointerRelease:
		if ok && a.releaseMousePress(mousePressPeerAction, int(choice)) {
			a.peerDialogChoice = choice
			a.confirmPeerActionChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil
}

func (a *App) handleHelpMouse(msg pointerMsg) tea.Cmd {
	if msg.action() == pointerClick {
		action, ok := actionIDFromTarget(msg.Target)
		if !ok {
			a.helpOpen = false
			return nil
		}
		return a.runMenuAction(action)
	}
	return nil
}

func (a *App) runMenuAction(action ActionID) tea.Cmd {
	a.helpOpen = false
	return a.runAction(action)
}

func (a *App) handleNoticeMouse(msg pointerMsg) bool {
	if !a.noticeOpen() {
		return false
	}
	if msg.action() == pointerClick {
		a.closeNotice()
	}
	return true
}

func (a *App) handleApprovalMouse(msg pointerMsg) (tea.Cmd, bool) {
	choice, ok := approvalChoiceFromTarget(msg.Target)
	switch msg.action() {
	case pointerClick:
		if !ok {
			a.clearMousePress()
			return nil, true
		}
		a.approvalChoice = choice
		a.armMousePress(mousePressApproval, int(a.approvalChoice))
	case pointerRelease:
		if ok && a.releaseMousePress(mousePressApproval, int(choice)) {
			a.approvalChoice = choice
			a.approveSelected()
		} else {
			a.clearMousePress()
		}
	}
	return nil, true
}

func (a *App) handleKickMouse(msg pointerMsg) bool {
	if a.kickPeer == "" {
		return false
	}
	if msg.action() == pointerClick {
		a.kickPeerID = ""
		a.kickPeer = ""
		a.focusTerminal()
	}
	return true
}

func (a *App) armMousePress(kind mousePressKind, choice int) {
	a.mousePress = mousePressTarget{kind: kind, choice: choice}
}

func (a *App) releaseMousePress(kind mousePressKind, choice int) bool {
	pressed := a.mousePress
	a.clearMousePress()
	return pressed.kind == kind && pressed.choice == choice
}

func (a *App) clearMousePress() {
	a.mousePress = mousePressTarget{}
}

func (a *App) clearPointerCapture() {
	a.releasePointerCapture()
	a.clearTerminalSelection()
}

func (a *App) releasePointerCapture() {
	a.stopTerminalSelectionAutoscroll()
	a.terminalSGRReleasePending = false
	a.pointerCapture = ""
	a.draggingDivider = false
	if a.terminalGesture == terminalGestureDrag {
		a.terminalGesture = terminalGestureNone
	}
}

func (a *App) clearTerminalSelection() {
	a.terminalGesture = terminalGestureNone
	a.lastTerminalClick = terminalClick{}
	a.selectionSeq++
	if interaction, ok := a.terminal.(terminalInteraction); ok {
		interaction.ClearSelection()
	}
}

func (a *App) handleDividerMouse(msg pointerMsg) bool {
	if a.draggingDivider {
		switch msg.action() {
		case pointerMotion:
			a.setSidebarWidth(a.width - msg.Mouse.X - 1)
		case pointerRelease:
			a.clearPointerCapture()
		}
		return true
	}
	if msg.action() != pointerClick || msg.Mouse.Button != tea.MouseLeft {
		return false
	}
	a.draggingDivider = true
	a.pointerCapture = targetDivider
	return true
}

func (a *App) handleActionMouse(msg pointerMsg) tea.Cmd {
	if !isMouseClick(msg) {
		return nil
	}
	action, ok := actionIDFromTarget(msg.Target)
	if !ok {
		return nil
	}
	cmd, _ := NewActionRegistry().Run(a, action)
	return cmd
}

func actionIDFromTarget(target layerTarget) (ActionID, bool) {
	value, ok := strings.CutPrefix(string(target), "action:")
	return ActionID(value), ok && value != ""
}

func modalChoice(target layerTarget, id ModalID) (string, bool) {
	value, ok := strings.CutPrefix(string(target), string(id)+":")
	return value, ok && value != ""
}

func approvalChoiceFromTarget(target layerTarget) (approvalChoice, bool) {
	switch choice, ok := modalChoice(target, ModalApproval); choice {
	case "read":
		return approvalChoiceRead, ok
	case "write":
		return approvalChoiceWrite, ok
	case "deny":
		return approvalChoiceDeny, ok
	default:
		return 0, false
	}
}

func peerActionChoiceFromTarget(target layerTarget) (peerActionChoice, bool) {
	switch choice, ok := modalChoice(target, ModalPeerAction); choice {
	case "read":
		return peerActionRead, ok
	case "write":
		return peerActionWrite, ok
	case "kick":
		return peerActionKick, ok
	default:
		return 0, false
	}
}

func quitChoiceFromTarget(target layerTarget) (quitChoice, bool) {
	switch choice, ok := modalChoice(target, ModalQuit); choice {
	case "quit":
		return quitChoiceQuit, ok
	case "cancel":
		return quitChoiceCancel, ok
	default:
		return 0, false
	}
}

func shellExitChoiceFromTarget(target layerTarget) (shellExitChoice, bool) {
	switch choice, ok := modalChoice(target, ModalShellExit); choice {
	case "restart":
		return shellExitChoiceRestart, ok
	case "quit":
		return shellExitChoiceQuit, ok
	default:
		return 0, false
	}
}

func (a *App) handlePeerTargetMouse(msg pointerMsg) {
	if !isMouseClick(msg) {
		return
	}
	id, ok := strings.CutPrefix(string(msg.Target), "peer:")
	if !ok || strings.TrimSpace(id) == "" {
		return
	}
	for _, peer := range a.peers {
		if peer.ID == id {
			a.openPeerDialog(peer)
			return
		}
	}
}

func (a *App) handleChatMouse(msg pointerMsg) {
	if a.handleChatScrollMouse(msg) {
		return
	}
	if isMouseClick(msg) {
		a.focusChat()
	}
}

func (a *App) handleChatScrollMouse(msg pointerMsg) bool {
	if msg.action() != pointerClick {
		return false
	}
	switch msg.Mouse.Button {
	case tea.MouseWheelUp:
		a.chatScroll++
		return true
	case tea.MouseWheelDown:
		if a.chatScroll > 0 {
			a.chatScroll--
		}
		return true
	default:
		return false
	}
}

func (a *App) handleTerminalMouse(msg pointerMsg) tea.Cmd {
	interaction, interactive := a.terminal.(terminalInteraction)
	mode := a.terminal.MouseMode()
	forceLocal := a.shouldHandleTerminalMouseLocally(msg)
	if !interactive {
		return a.handleNoninteractiveTerminalMouse(msg, mode, forceLocal)
	}
	if mode.Enabled && mode.SGR && !forceLocal {
		a.resetTerminalClickCandidate()
		interaction.ResetViewport()
		return a.forwardTerminalMouse(msg, mode)
	}

	terminal := a.currentTerminalRect()
	point, ok := terminalMousePoint(msg.Mouse, terminal)
	if !ok {
		return nil
	}
	switch msg.action() {
	case pointerClick:
		return a.handleLocalTerminalClick(interaction, msg, point)
	case pointerMotion:
		return a.handleLocalTerminalMotion(interaction, msg, point, terminal)
	case pointerRelease:
		return a.handleLocalTerminalRelease(interaction, point)
	}
	return nil
}

func (a *App) handleNoninteractiveTerminalMouse(msg pointerMsg, mode terminalMouseMode, forceLocal bool) tea.Cmd {
	if forceLocal {
		if msg.action() == pointerClick && msg.Mouse.Button == tea.MouseLeft {
			a.pointerCapture = targetTerminal
			a.terminalGesture = terminalGestureDrag
		}
		return nil
	}
	if msg.action() == pointerClick {
		a.focusTerminal()
	}
	return a.forwardTerminalMouse(msg, mode)
}

func (a *App) handleLocalTerminalClick(interaction terminalInteraction, msg pointerMsg, point terminalPoint) tea.Cmd {
	if msg.Mouse.Button == tea.MouseWheelUp || msg.Mouse.Button == tea.MouseWheelDown {
		a.resetTerminalClickCandidate()
		a.handleTerminalWheel(interaction, msg, point)
		return nil
	}
	if msg.Mouse.Button != tea.MouseLeft {
		a.resetTerminalClickCandidate()
		return nil
	}
	a.focusTerminal()
	if a.isTerminalDoubleClick(point, msg.Mouse.Mod) {
		a.resetTerminalClickCandidate()
		a.selectionSeq++
		if text, selected := interaction.SelectWord(point.X, point.Y); selected {
			a.terminalGesture = terminalGestureWord
			a.pointerCapture = targetTerminal
			return tea.Batch(tea.SetClipboard(text), terminalSelectionClearTick(a.selectionSeq))
		}
	}
	a.selectionSeq++
	a.stopTerminalSelectionAutoscroll()
	a.recordTerminalClickCandidate(point, msg.Mouse.Mod)
	if interaction.BeginSelection(point.X, point.Y) {
		a.terminalGesture = terminalGestureDrag
		a.pointerCapture = targetTerminal
	}
	return nil
}

func (a *App) handleLocalTerminalMotion(
	interaction terminalInteraction,
	msg pointerMsg,
	point terminalPoint,
	terminal Rect,
) tea.Cmd {
	if a.terminalGesture != terminalGestureDrag {
		return nil
	}
	a.resetTerminalClickCandidate()
	interaction.UpdateSelection(point.X, point.Y)
	if interaction.ViewportState().AlternateScreen {
		a.stopTerminalSelectionAutoscroll()
		return nil
	}
	return a.updateTerminalSelectionAutoscroll(msg.Mouse, terminal)
}

func (a *App) handleLocalTerminalRelease(interaction terminalInteraction, point terminalPoint) tea.Cmd {
	if a.terminalGesture == terminalGestureWord {
		a.terminalGesture = terminalGestureNone
		return nil
	}
	if a.terminalGesture != terminalGestureDrag {
		return nil
	}
	interaction.UpdateSelection(point.X, point.Y)
	text, selected := interaction.FinishSelection()
	if !selected {
		return nil
	}
	a.resetTerminalClickCandidate()
	cmd := tea.SetClipboard(text)
	interaction.ClearSelection()
	return cmd
}

func (a *App) updateTerminalSelectionAutoscroll(mouse tea.Mouse, terminal Rect) tea.Cmd {
	if mouse.Y >= terminal.Y && mouse.Y < terminal.Y+terminal.H {
		a.stopTerminalSelectionAutoscroll()
		return nil
	}
	a.terminalPointer = terminalPoint{X: mouse.X, Y: mouse.Y}
	a.terminalAutoscrollSeq++
	a.terminalAutoscrollActive = true
	return terminalSelectionAutoscrollTick(a.terminalAutoscrollSeq)
}

func (a *App) stopTerminalSelectionAutoscroll() {
	if a.terminalAutoscrollActive {
		a.terminalAutoscrollSeq++
	}
	a.terminalAutoscrollActive = false
}

func (a *App) handleTerminalSelectionAutoscroll(msg terminalSelectionAutoscrollMsg) tea.Cmd {
	if !a.terminalAutoscrollActive || msg.seq != a.terminalAutoscrollSeq ||
		a.pointerCapture != targetTerminal || a.terminalGesture != terminalGestureDrag || a.modalActive() {
		return nil
	}
	interaction, ok := a.terminal.(terminalInteraction)
	if !ok {
		a.stopTerminalSelectionAutoscroll()
		return nil
	}
	terminal := a.currentTerminalRect()
	distance, direction := terminalSelectionOverflow(a.terminalPointer.Y, terminal)
	if distance == 0 {
		a.stopTerminalSelectionAutoscroll()
		return nil
	}
	rows := minInt(maxInt(distance, terminalSelectionAutoscrollMinRows), terminalSelectionAutoscrollMaxRows)
	interaction.ScrollLines(direction * rows)
	point, pointOK := terminalMousePoint(tea.Mouse{X: a.terminalPointer.X, Y: a.terminalPointer.Y}, terminal)
	if pointOK {
		interaction.UpdateSelection(point.X, point.Y)
	}
	return terminalSelectionAutoscrollTick(msg.seq)
}

func terminalSelectionOverflow(y int, terminal Rect) (distance int, direction int) {
	if y < terminal.Y {
		return terminal.Y - y, 1
	}
	lastRow := terminal.Y + terminal.H - 1
	if y > lastRow {
		return y - lastRow, -1
	}
	return 0, 0
}

func (a *App) isTerminalDoubleClick(point terminalPoint, mod tea.KeyMod) bool {
	if mod != 0 || a.lastTerminalClick.at.IsZero() || a.lastTerminalClick.point != point {
		return false
	}
	elapsed := a.currentTime().Sub(a.lastTerminalClick.at)
	return elapsed >= 0 && elapsed <= terminalDoubleClickInterval
}

func (a *App) recordTerminalClickCandidate(point terminalPoint, mod tea.KeyMod) {
	if mod != 0 {
		a.resetTerminalClickCandidate()
		return
	}
	a.lastTerminalClick = terminalClick{point: point, at: a.currentTime()}
}

func (a *App) resetTerminalClickCandidate() {
	a.lastTerminalClick = terminalClick{}
}

func (a *App) handleTerminalWheel(interaction terminalInteraction, msg pointerMsg, point terminalPoint) {
	delta := terminalWheelRows
	key := tea.KeyUp
	if msg.Mouse.Button == tea.MouseWheelDown {
		delta = -terminalWheelRows
		key = tea.KeyDown
	}
	if interaction.ViewportState().AlternateScreen {
		mode := a.terminal.InputMode()
		mouseMode := a.terminal.MouseMode()
		if mouseMode.Enabled && mouseMode.SGR || !mode.AlternateScroll {
			return
		}
		if data, ok := EncodeTerminalKeyWithMode(tea.KeyPressMsg{Code: key}, mode); ok {
			a.emit(TerminalInputCommand{Data: bytes.Repeat(data, terminalWheelRows)})
		}
		return
	}
	interaction.ScrollLines(delta)
	if a.terminalGesture == terminalGestureDrag {
		interaction.UpdateSelection(point.X, point.Y)
	}
}

func (a *App) forwardTerminalMouse(msg pointerMsg, mode MouseMode) tea.Cmd {
	if msg.action() == pointerRelease && a.terminalSGRReleasePending {
		defer func() { a.terminalSGRReleasePending = false }()
	}
	if !mode.Enabled || !mode.SGR {
		return nil
	}
	if data, ok := EncodeSGRMouse(msg.Event, a.currentTerminalRect()); ok {
		a.emit(TerminalInputCommand{Data: data})
		if msg.action() == pointerClick &&
			(msg.Mouse.Button == tea.MouseMiddle || msg.Mouse.Button == tea.MouseRight) &&
			a.terminalGesture != terminalGestureNone {
			a.terminalSGRReleasePending = true
		}
	}
	return nil
}

func (a *App) shouldHandleTerminalMouseLocally(msg pointerMsg) bool {
	if msg.action() == pointerRelease && a.terminalSGRReleasePending {
		return false
	}
	if !a.copyMode && a.terminalGesture == terminalGestureNone {
		return false
	}
	switch msg.Mouse.Button {
	case tea.MouseLeft, tea.MouseWheelUp, tea.MouseWheelDown:
		return true
	default:
		return msg.action() == pointerRelease && a.terminalGesture != terminalGestureNone
	}
}

func terminalMousePoint(mouse tea.Mouse, terminal Rect) (terminalPoint, bool) {
	if terminal.empty() {
		return terminalPoint{}, false
	}
	return terminalPoint{
		X: minInt(maxInt(mouse.X-terminal.X, 0), terminal.W-1),
		Y: minInt(maxInt(mouse.Y-terminal.Y, 0), terminal.H-1),
	}, true
}
