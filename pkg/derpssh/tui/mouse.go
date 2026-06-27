// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"

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
	if app == nil {
		return nil
	}
	if !supportedMouseAction(msg.Action) {
		return nil
	}

	if app.handleApprovalMouse(msg) {
		return nil
	}
	if app.handleKickMouse(msg) {
		return nil
	}
	if app.handleTopBarMouse(msg) {
		return nil
	}

	app.handleContentMouse(msg)
	return nil
}

func supportedMouseAction(action tea.MouseAction) bool {
	return action == tea.MouseActionPress || action == tea.MouseActionRelease || action == tea.MouseActionMotion
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

func (a *App) handleTopBarMouse(msg tea.MouseMsg) bool {
	if msg.Action != tea.MouseActionPress || !a.layout.TopBar.contains(msg.X, msg.Y) {
		return false
	}
	if msg.X < a.layout.Outer.W-12 {
		return false
	}
	a.setSidebarOpen(!a.sidebarOpen)
	return true
}

func (a *App) handleContentMouse(msg tea.MouseMsg) {
	switch a.layout.Hit(msg.X, msg.Y) {
	case HitSidebar:
		if msg.Action == tea.MouseActionPress {
			if a.sidebarInviteHit(msg.X, msg.Y) {
				a.openInvite()
				return
			}
			a.focusChat()
		}
	case HitComposer:
		if msg.Action == tea.MouseActionPress {
			a.focusChat()
		}
	case HitTerminal:
		a.handleTerminalMouse(msg)
	}
}

func (a *App) sidebarInviteHit(x int, y int) bool {
	if strings.TrimSpace(a.inviteCommand) == "" || !a.layout.Sidebar.contains(x, y) {
		return false
	}
	relativeY := y - a.layout.Sidebar.Y
	return relativeY >= 1 && relativeY <= 2
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
