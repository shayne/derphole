// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"bytes"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	chatWheelRows     = 3
	terminalWheelRows = 3
)

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
	mouse := msg.Mouse()
	a.recordMouseModality(msg)
	target := a.pointerCapture
	if target == "" {
		target = a.buildScene().TargetAt(mouse.X, mouse.Y)
	}
	interaction := HandleMouse(a, newPointerMsg(target, msg))
	var pointer tea.Cmd
	switch msg.(type) {
	case tea.MouseMotionMsg:
		pointer = a.updatePointerShape(target)
	case tea.MouseReleaseMsg:
		target = a.buildScene().TargetAt(mouse.X, mouse.Y)
		a.updateHover(newPointerMsg(target, tea.MouseMotionMsg(mouse)))
		pointer = a.updatePointerShape(target)
	}
	return tea.Batch(interaction, pointer)
}

func (a *App) useKeyboardModality() {
	a.inputModality = inputModalityKeyboard
	a.hoverTarget = ""
}

func (a *App) recordMouseModality(msg tea.MouseMsg) {
	mouse := msg.Mouse()
	position := terminalPoint{X: mouse.X, Y: mouse.Y}
	_, motion := msg.(tea.MouseMotionMsg)
	if !motion || !a.pointerPositionKnown || position != a.lastPointerPosition {
		a.inputModality = inputModalityMouse
	}
	a.lastPointerPosition = position
	a.pointerPositionKnown = true
}

func pointerShapesSupported(term string, termProgram string) bool {
	term = strings.ToLower(strings.TrimSpace(term))
	termProgram = strings.ToLower(strings.TrimSpace(termProgram))
	if termProgram == "ghostty" || termProgram == "iterm.app" || termProgram == "iterm2" {
		return true
	}
	return strings.Contains(term, "ghostty") || strings.Contains(term, "kitty") ||
		term == "foot" || strings.HasPrefix(term, "foot-")
}

func pointerShapeForTarget(target layerTarget) string {
	switch target {
	case targetTerminal:
		return "text"
	case targetDivider:
		return "ew-resize"
	default:
		return "default"
	}
}

func (a *App) updatePointerShape(target layerTarget) tea.Cmd {
	shape := pointerShapeForTarget(target)
	if a.modalActive() {
		shape = "default"
	}
	if shape == a.pointerShape {
		return nil
	}
	a.pointerShape = shape
	if !a.pointerShapes {
		return nil
	}
	return tea.Raw(ansi.SetPointerShape(shape))
}

type pointerAction int

const (
	pointerUnknown pointerAction = iota
	pointerClick
	pointerWheel
	pointerRelease
	pointerMotion
)

func (m pointerMsg) action() pointerAction {
	switch m.Event.(type) {
	case tea.MouseClickMsg:
		return pointerClick
	case tea.MouseWheelMsg:
		return pointerWheel
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
	if app.inviteOpen {
		app.clearLayerInteractionState()
	}
	if pointer.action() == pointerRelease && pointer.Target != app.pressedTarget {
		app.pressedTarget = ""
	}
	app.updateHover(pointer)
	if pointer.action() == pointerRelease && !app.terminalSGRReleasePending {
		defer app.releasePointerCapture()
	}
	if cmd, handled := app.handleModalMouse(pointer); handled {
		return cmd
	}
	if cmd, handled := app.handleCopyModeMouse(pointer); handled {
		return cmd
	}
	return app.handleTargetMouse(pointer)
}

func (a *App) handleCopyModeMouse(pointer pointerMsg) (tea.Cmd, bool) {
	if !a.copyMode || pointer.Target == targetTerminal {
		return nil, false
	}
	if isMouseClick(pointer) {
		return a.setCopyMode(false), true
	}
	return nil, true
}

func (a *App) handleTargetMouse(pointer pointerMsg) tea.Cmd {
	switch {
	case pointer.Target == targetDivider:
		a.handleDividerMouse(pointer)
		return nil
	case strings.HasPrefix(string(pointer.Target), "chat-message:"):
		index, ok := chatMessageIndex(pointer.Target)
		if !ok {
			return nil
		}
		return a.handleChatMessageMouse(pointer, index)
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

func isChromeTarget(target layerTarget) bool {
	value := string(target)
	return strings.HasPrefix(value, "action:") || strings.HasPrefix(value, "peer:")
}

func (a *App) updateHover(pointer pointerMsg) {
	if pointer.action() != pointerMotion || a.pointerCapture != "" ||
		a.inputModality == inputModalityKeyboard {
		return
	}
	if a.modalActive() {
		if a.frontModalHoverTarget(pointer.Target) {
			a.hoverTarget = pointer.Target
		} else {
			a.hoverTarget = ""
		}
		return
	}
	if isChromeTarget(pointer.Target) || pointer.Target == targetDivider ||
		pointer.Target == targetComposer || strings.HasPrefix(string(pointer.Target), "chat-message:") {
		a.hoverTarget = pointer.Target
		return
	}
	a.hoverTarget = ""
}

func (a *App) frontModalHoverTarget(target layerTarget) bool {
	id, ok := a.frontModalID()
	if !ok {
		return false
	}
	switch id {
	case ModalHelp:
		_, ok = actionIDFromTarget(target)
	case ModalPeerAction:
		_, ok = peerActionChoiceFromTarget(target)
	case ModalApproval:
		_, ok = approvalChoiceFromTarget(target)
	case ModalQuit:
		_, ok = quitChoiceFromTarget(target)
	case ModalShellExit:
		_, ok = shellExitChoiceFromTarget(target)
	default:
		ok = false
	}
	return ok
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
	armed, activated := a.handleModalControlPress(msg, ok)
	if armed {
		a.shellExitChoice = choice
	}
	if activated {
		a.shellExitChoice = choice
		a.confirmShellExitChoice()
	}
	return nil
}

func (a *App) handleQuitMouse(msg pointerMsg) tea.Cmd {
	choice, ok := quitChoiceFromTarget(msg.Target)
	armed, activated := a.handleModalControlPress(msg, ok)
	if armed {
		a.quitChoice = choice
	}
	if activated {
		a.quitChoice = choice
		a.confirmQuitChoice()
	}
	return nil
}

func (a *App) handlePeerDialogMouse(msg pointerMsg) tea.Cmd {
	choice, ok := peerActionChoiceFromTarget(msg.Target)
	armed, activated := a.handleModalControlPress(msg, ok)
	if armed {
		a.peerDialogChoice = choice
	}
	if activated {
		a.peerDialogChoice = choice
		return a.confirmPeerActionChoice()
	}
	return nil
}

func (a *App) handleHelpMouse(msg pointerMsg) tea.Cmd {
	action, ok := actionIDFromTarget(msg.Target)
	_, activated := a.handleModalControlPress(msg, ok)
	if activated {
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
	valid := msg.Target == modalTarget(ModalNotice) || msg.Target == targetModalBlocker
	_, activated := a.handleModalControlPress(msg, valid)
	if activated {
		a.closeNotice()
	}
	return true
}

func (a *App) handleApprovalMouse(msg pointerMsg) (tea.Cmd, bool) {
	choice, ok := approvalChoiceFromTarget(msg.Target)
	armed, activated := a.handleModalControlPress(msg, ok)
	if armed {
		a.approvalChoice = choice
	}
	if activated {
		a.approvalChoice = choice
		a.approveSelected()
	}
	return nil, true
}

func (a *App) handleKickMouse(msg pointerMsg) bool {
	if a.kickPeer == "" {
		return false
	}
	valid := msg.Target == modalTarget(ModalKick) || msg.Target == targetModalBlocker
	_, activated := a.handleModalControlPress(msg, valid)
	if activated {
		a.kickPeerID = ""
		a.kickPeer = ""
		a.focusTerminal()
	}
	return true
}

func (a *App) handleModalControlPress(msg pointerMsg, validTarget bool) (armed bool, activated bool) {
	switch msg.action() {
	case pointerClick:
		a.clearMousePress()
		if msg.Mouse.Button != tea.MouseLeft || !validTarget {
			return false, false
		}
		identity, ok := a.frontModalMouseIdentity()
		if !ok {
			return false, false
		}
		a.mousePress = mousePressTarget{modalIdentity: identity, target: msg.Target}
		a.pressedTarget = msg.Target
		return true, false
	case pointerRelease:
		return false, a.releaseModalControlPress(msg, validTarget)
	case pointerWheel:
		a.clearMousePress()
	}
	return false, false
}

func (a *App) releaseModalControlPress(msg pointerMsg, validTarget bool) bool {
	pressed := a.mousePress
	a.clearMousePress()
	identity, ok := a.frontModalMouseIdentity()
	return ok && msg.Mouse.Button == tea.MouseLeft && validTarget &&
		pressed.modalIdentity == identity && pressed.target == msg.Target
}

func (a *App) frontModalMouseIdentity() (string, bool) {
	id, ok := a.frontModalID()
	if !ok {
		return "", false
	}
	owner := ""
	switch id {
	case ModalApproval:
		owner = a.approvalPeerID + "\x00" + a.approvalPeer
	case ModalPeerAction:
		owner = a.peerDialogPeer.ID + "\x00" + a.peerDialogPeer.Name
	case ModalKick:
		owner = a.kickPeerID + "\x00" + a.kickPeer
	case ModalNotice:
		owner = a.noticeTitle + "\x00" + a.noticeBody
	}
	return string(id) + "\x00" + owner, true
}

func (a *App) clearMousePress() {
	a.mousePress = mousePressTarget{}
	a.pressedTarget = ""
}

func (a *App) clearPointerCapture() {
	a.clearLayerInteractionState()
	a.releasePointerCapture()
	a.clearTerminalSelection()
}

func (a *App) clearLayerInteractionState() {
	a.hoverTarget = ""
	a.pressedTarget = ""
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
	matched := a.handleChromePress(msg)
	if msg.action() != pointerRelease || !matched {
		return nil
	}
	action, ok := actionIDFromTarget(msg.Target)
	if !ok {
		return nil
	}
	cmd, _ := NewActionRegistry().Run(a, action)
	return cmd
}

func (a *App) handleChromePress(pointer pointerMsg) bool {
	switch pointer.action() {
	case pointerClick:
		if pointer.Mouse.Button != tea.MouseLeft {
			return false
		}
		a.pressedTarget = pointer.Target
		return true
	case pointerRelease:
		matched := pointer.Mouse.Button == tea.MouseLeft &&
			a.pressedTarget != "" && a.pressedTarget == pointer.Target
		a.pressedTarget = ""
		return matched
	default:
		return false
	}
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
	matched := a.handleChromePress(msg)
	if msg.action() != pointerRelease || !matched {
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

func (a *App) handleChatMessageMouse(msg pointerMsg, index int) tea.Cmd {
	if a.handleChatScrollMouse(msg) {
		return nil
	}
	matched := a.handleChromePress(msg)
	if msg.action() != pointerRelease || !matched {
		return nil
	}
	return a.copyChatMessage(index)
}

func (a *App) copyChatMessage(index int) tea.Cmd {
	a.clearInvalidCopiedChatFeedback()
	if index < 0 || index >= len(a.chatMessages) {
		return nil
	}
	body := a.chatMessages[index].Body
	if strings.TrimSpace(body) == "" {
		return nil
	}
	a.copiedChatSeq++
	a.copiedChatIndex = index
	a.copiedChatActive = true
	return tea.Batch(
		tea.SetClipboard(body),
		clearCopiedChatTick(a.copiedChatSeq),
		a.showToast("Copied message"),
	)
}

func (a *App) handleChatScrollMouse(msg pointerMsg) bool {
	if msg.action() != pointerWheel {
		return false
	}
	switch msg.Mouse.Button {
	case tea.MouseWheelUp, tea.MouseWheelDown:
		viewportHeight := maxInt(a.layout.Sidebar.H-1-a.sidebarComposerRows(a.layout.Sidebar.H), 0)
		maxScroll := maxInt(len(a.chatRows(a.layout.Sidebar.W))-viewportHeight, 0)
		a.chatScroll = clampInt(a.chatScroll, 0, maxScroll)
		if msg.Mouse.Button == tea.MouseWheelUp {
			a.chatScroll = minInt(a.chatScroll+chatWheelRows, maxScroll)
		} else {
			a.chatScroll = maxInt(a.chatScroll-chatWheelRows, 0)
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
	case pointerClick, pointerWheel:
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
