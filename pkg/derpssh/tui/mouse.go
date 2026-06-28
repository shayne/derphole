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

var menuActionHandlers = map[menuAction]func(*App) tea.Cmd{
	menuActionChat:          toggleSidebarAction,
	menuActionFocusChat:     focusChatAction,
	menuActionFocusTerminal: focusTerminalAction,
	menuActionInvite:        inviteAction,
	menuActionCopyMode:      copyModeAction,
	menuActionQuit:          quitAction,
	menuActionRead:          readRoleAction,
	menuActionWrite:         writeRoleAction,
	menuActionKick:          kickPeerAction,
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
	if ignoreMouse(app, msg) {
		return nil
	}
	if cmd, handled := app.handleModalMouse(msg); handled {
		return cmd
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

func ignoreMouse(app *App, msg tea.MouseMsg) bool {
	return app == nil || app.copyMode || !supportedMouseAction(msg.Action)
}

func supportedMouseAction(action tea.MouseAction) bool {
	return action == tea.MouseActionPress || action == tea.MouseActionRelease || action == tea.MouseActionMotion
}

func (a *App) handleModalMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if cmd, handled := a.handleQuitMouse(msg); handled {
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

func (a *App) handleQuitMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.quitOpen {
		return nil, false
	}
	if msg.Action == tea.MouseActionPress {
		if choice := a.quitHit(msg.X, msg.Y); choice >= 0 {
			a.quitChoice = choice
			a.confirmQuitChoice()
		}
	}
	return nil, true
}

func (a *App) handleHelpMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if !a.helpOpen {
		return nil, false
	}
	if msg.Action == tea.MouseActionPress {
		action := a.helpActionAt(msg.X, msg.Y)
		if action == menuActionNone {
			a.helpOpen = false
			return nil, true
		}
		return a.runMenuAction(action), true
	}
	return nil, true
}

func (a *App) helpActionAt(x int, y int) menuAction {
	contentX, contentY := a.helpContentOrigin()
	width := a.helpContentWidth()
	row := contentY + 2
	for _, entry := range a.menuEntries() {
		if y == row && x >= contentX && x < contentX+width {
			return entry.action
		}
		row++
	}
	return menuActionNone
}

func (a *App) runMenuAction(action menuAction) tea.Cmd {
	a.helpOpen = false
	handler := menuActionHandlers[action]
	if handler == nil {
		return nil
	}
	return handler(a)
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
	if msg.Action == tea.MouseActionPress {
		a.handleApprovalClick(msg.X, msg.Y)
	}
	return true
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

func (a *App) handleTopBarMouse(msg tea.MouseMsg) (tea.Cmd, bool) {
	if msg.Action != tea.MouseActionPress || !a.layout.TopBar.contains(msg.X, msg.Y) {
		return nil, false
	}
	_ = a.renderTopBar()
	switch a.topBarActionAt(msg.X, msg.Y) {
	case topBarActionQuit:
		a.openQuitConfirm()
	case topBarActionChat:
		a.setSidebarOpen(!a.sidebarOpen)
	case topBarActionInvite:
		return a.openInvite(), true
	case topBarActionHelp:
		a.helpOpen = true
	}
	return nil, true
}

func (a *App) topBarActionAt(x int, y int) topBarAction {
	for _, hit := range a.topBarHits {
		if hit.rect.contains(x, y) {
			return hit.action
		}
	}
	return topBarActionNone
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
	if data, ok := EncodeSGRMouse(msg, a.layout.Terminal); ok {
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
