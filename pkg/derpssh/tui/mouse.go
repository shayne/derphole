// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

var mouseButtonCodes = map[tea.MouseButton]int{
	tea.MouseButtonLeft:      0,
	tea.MouseButtonMiddle:    1,
	tea.MouseButtonRight:     2,
	tea.MouseButtonWheelUp:   64,
	tea.MouseButtonWheelDown: 65,
}

func EncodeSGRMouse(msg tea.MouseMsg, terminal Rect) ([]byte, bool) {
	if !terminal.contains(msg.X, msg.Y) {
		return nil, false
	}

	code, ok := mouseButtonCode(msg)
	if !ok {
		return nil, false
	}
	if msg.Action == tea.MouseActionMotion {
		code += 32
	}

	suffix := "M"
	if msg.Action == tea.MouseActionRelease {
		suffix = "m"
	}
	x := msg.X - terminal.X + 1
	y := msg.Y - terminal.Y + 1
	return []byte(fmt.Sprintf("\x1b[<%d;%d;%d%s", code, x, y, suffix)), true
}

func HandleMouse(app *App, msg tea.MouseMsg) tea.Cmd {
	if app == nil || !supportedMouseAction(msg.Action) {
		return nil
	}
	if cmd, handled := app.handleModalMouse(msg); handled {
		return cmd
	}
	if app.copyMode {
		if msg.Action == tea.MouseActionPress && !app.currentTerminalRect().contains(msg.X, msg.Y) {
			return app.setCopyMode(false)
		}
		return nil
	}
	if cmd, handled := app.handleTopBarMouse(msg); handled {
		return cmd
	}
	if app.handleDividerMouse(msg) {
		return nil
	}

	app.handleContentMouse(msg)
	return nil
}

func supportedMouseAction(action tea.MouseAction) bool {
	return action == tea.MouseActionPress || action == tea.MouseActionRelease || action == tea.MouseActionMotion
}

func (a *App) handleModalMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if cmd, handled := a.handleShellExitMouse(msg); handled {
		return cmd, true
	}
	if cmd, handled := a.handleQuitMouse(msg); handled {
		return cmd, true
	}
	if cmd, handled := a.handlePeerDialogMouse(msg); handled {
		return cmd, true
	}
	if cmd, handled := a.handleHelpMouse(msg); handled {
		return cmd, true
	}
	if a.handleNoticeMouse(msg) {
		return nil, true
	}
	if a.handleApprovalMouse(msg) {
		return nil, true
	}
	if a.handleKickMouse(msg) {
		return nil, true
	}
	return nil, false
}

func (a *App) handleShellExitMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.shellExitOpen {
		return nil, false
	}
	switch msg.Action {
	case tea.MouseActionPress:
		if choice := a.shellExitHit(msg.X, msg.Y); choice >= 0 {
			a.shellExitChoice = choice
			a.armMousePress(mousePressShellExit, int(choice))
		} else {
			a.clearMousePress()
		}
	case tea.MouseActionRelease:
		choice := a.shellExitHit(msg.X, msg.Y)
		if choice >= 0 && a.releaseMousePress(mousePressShellExit, int(choice)) {
			a.shellExitChoice = choice
			a.confirmShellExitChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil, true
}

func (a *App) handleQuitMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.quitOpen {
		return nil, false
	}
	switch msg.Action {
	case tea.MouseActionPress:
		if choice := a.quitHit(msg.X, msg.Y); choice >= 0 {
			a.quitChoice = choice
			a.armMousePress(mousePressQuit, int(choice))
		} else {
			a.clearMousePress()
		}
	case tea.MouseActionRelease:
		choice := a.quitHit(msg.X, msg.Y)
		if choice >= 0 && a.releaseMousePress(mousePressQuit, int(choice)) {
			a.quitChoice = choice
			a.confirmQuitChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil, true
}

func (a *App) handlePeerDialogMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.peerDialogOpen {
		return nil, false
	}
	switch msg.Action {
	case tea.MouseActionPress:
		if choice := a.peerActionHit(msg.X, msg.Y); choice >= 0 {
			a.peerDialogChoice = choice
			a.armMousePress(mousePressPeerAction, int(choice))
		} else {
			a.clearMousePress()
		}
	case tea.MouseActionRelease:
		choice := a.peerActionHit(msg.X, msg.Y)
		if choice >= 0 && a.releaseMousePress(mousePressPeerAction, int(choice)) {
			a.peerDialogChoice = choice
			a.confirmPeerActionChoice()
		} else {
			a.clearMousePress()
		}
	}
	return nil, true
}

func (a *App) handleHelpMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.helpOpen {
		return nil, false
	}
	if msg.Action == tea.MouseActionPress {
		action, ok := a.helpActionAt(msg.X, msg.Y)
		if !ok {
			a.helpOpen = false
			return nil, true
		}
		return a.runMenuAction(action), true
	}
	return nil, true
}

func (a *App) helpActionAt(x int, y int) (ActionID, bool) {
	contentX, contentY := a.helpContentOrigin()
	width := a.helpContentWidth()
	row := contentY + 2
	for _, entry := range a.menuEntries() {
		if y == row && x >= contentX && x < contentX+width {
			return entry.action, true
		}
		row++
	}
	return "", false
}

func (a *App) runMenuAction(action ActionID) tea.Cmd {
	a.helpOpen = false
	return a.runAction(action)
}

func (a *App) handleNoticeMouse(msg tea.MouseMsg) bool {
	if !a.noticeOpen() {
		return false
	}
	if msg.Action == tea.MouseActionPress {
		a.closeNotice()
	}
	return true
}

func (a *App) handleApprovalMouse(msg tea.MouseMsg) bool {
	if !a.approvalActive() {
		return false
	}
	switch msg.Action {
	case tea.MouseActionPress:
		hit := a.approvalHit(msg.X, msg.Y)
		if hit != HitNone {
			a.selectApprovalHit(hit)
			a.armMousePress(mousePressApproval, int(hit))
		} else {
			a.clearMousePress()
		}
	case tea.MouseActionRelease:
		hit := a.approvalHit(msg.X, msg.Y)
		if hit != HitNone && a.releaseMousePress(mousePressApproval, int(hit)) {
			a.handleApprovalClick(msg.X, msg.Y)
		} else {
			a.clearMousePress()
		}
	}
	return true
}

func (a *App) selectApprovalHit(hit HitTarget) {
	switch hit {
	case HitApprovalRead:
		a.approvalChoice = approvalChoiceRead
	case HitApprovalWrite:
		a.approvalChoice = approvalChoiceWrite
	case HitApprovalDeny:
		a.approvalChoice = approvalChoiceDeny
	}
}

func (a *App) handleApprovalClick(x int, y int) {
	switch a.approvalHit(x, y) {
	case HitApprovalRead:
		a.approve(RoleRead, false)
	case HitApprovalWrite:
		a.approve(RoleWrite, false)
	case HitApprovalDeny:
		a.approve("", true)
	}
}

func (a *App) handleKickMouse(msg tea.MouseMsg) bool {
	if a.kickPeer == "" || msg.Action != tea.MouseActionPress {
		return false
	}
	a.kickPeerID = ""
	a.kickPeer = ""
	a.focusTerminal()
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

func (a *App) handleTopBarMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if msg.Action != tea.MouseActionPress || !a.layout.TopBar.contains(msg.X, msg.Y) {
		return nil, false
	}
	_ = a.renderTopBar()
	hit, ok := a.topBarHitAt(msg.X, msg.Y)
	if !ok {
		return nil, true
	}
	if hit.action == ActionManagePeer {
		a.openPeerDialog(hit.peer)
		return nil, true
	}
	return a.runAction(hit.action), true
}

func (a *App) topBarHitAt(x int, y int) (topBarHit, bool) {
	for _, hit := range a.topBarHits {
		if hit.rect.contains(x, y) {
			return hit, true
		}
	}
	return topBarHit{}, false
}

func (a *App) handleDividerMouse(msg tea.MouseMsg) bool {
	if a.draggingDivider {
		switch msg.Action {
		case tea.MouseActionMotion:
			a.setSidebarWidth(a.width - msg.X - 1)
		case tea.MouseActionRelease:
			a.draggingDivider = false
		}
		return true
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return false
	}
	if a.layout.Hit(msg.X, msg.Y) != HitDivider {
		return false
	}
	a.draggingDivider = true
	return true
}

func (a *App) handleContentMouse(msg tea.MouseMsg) {
	switch a.layout.Hit(msg.X, msg.Y) {
	case HitSidebar:
		if a.handleChatScrollMouse(msg) {
			return
		}
		if msg.Action == tea.MouseActionPress {
			a.focusChat()
		}
	case HitComposer:
		if a.handleChatScrollMouse(msg) {
			return
		}
		if msg.Action == tea.MouseActionPress {
			a.focusChat()
		}
	case HitTerminal:
		a.handleTerminalMouse(msg)
	}
}

func (a *App) handleChatScrollMouse(msg tea.MouseMsg) bool {
	if msg.Action != tea.MouseActionPress {
		return false
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		a.chatScroll++
		return true
	case tea.MouseButtonWheelDown:
		if a.chatScroll > 0 {
			a.chatScroll--
		}
		return true
	default:
		return false
	}
}

func (a *App) handleTerminalMouse(msg tea.MouseMsg) {
	if msg.Action == tea.MouseActionPress {
		a.focusTerminal()
	}
	mode := a.terminal.MouseMode()
	if !mode.Enabled || !mode.SGR {
		return
	}
	if data, ok := EncodeSGRMouse(msg, a.currentTerminalRect()); ok {
		a.emit(TerminalInputCommand{Data: data})
	}
}

func mouseButtonCode(msg tea.MouseMsg) (int, bool) {
	if msg.Action == tea.MouseActionRelease {
		return 0, true
	}
	code, ok := mouseButtonCodes[msg.Button]
	return code, ok
}
