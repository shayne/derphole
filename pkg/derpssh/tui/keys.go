// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var encodedTerminalKeys = map[tea.KeyType][]byte{
	tea.KeySpace:     []byte{' '},
	tea.KeyEnter:     []byte{'\r'},
	tea.KeyTab:       []byte{'\t'},
	tea.KeyBackspace: []byte{0x7f},
	tea.KeyEsc:       []byte{0x1b},
	tea.KeyUp:        []byte("\x1b[A"),
	tea.KeyDown:      []byte("\x1b[B"),
	tea.KeyRight:     []byte("\x1b[C"),
	tea.KeyLeft:      []byte("\x1b[D"),
	tea.KeyHome:      []byte("\x1b[H"),
	tea.KeyEnd:       []byte("\x1b[F"),
	tea.KeyDelete:    []byte("\x1b[3~"),
	tea.KeyInsert:    []byte("\x1b[2~"),
	tea.KeyPgUp:      []byte("\x1b[5~"),
	tea.KeyPgDown:    []byte("\x1b[6~"),
}

var applicationCursorKeys = map[tea.KeyType][]byte{
	tea.KeyUp:    []byte("\x1bOA"),
	tea.KeyDown:  []byte("\x1bOB"),
	tea.KeyRight: []byte("\x1bOC"),
	tea.KeyLeft:  []byte("\x1bOD"),
}

func EncodeTerminalKey(msg tea.KeyMsg) ([]byte, bool) {
	return EncodeTerminalKeyWithMode(msg, TerminalInputMode{})
}

func EncodeTerminalKeyWithMode(msg tea.KeyMsg, mode TerminalInputMode) ([]byte, bool) {
	if msg.Type == tea.KeyRunes {
		if len(msg.Runes) == 0 {
			return nil, false
		}
		data := []byte(string(msg.Runes))
		if msg.Alt {
			data = append([]byte{0x1b}, data...)
		}
		return data, true
	}
	if mode.ApplicationCursor {
		if data, ok := applicationCursorKeys[msg.Type]; ok {
			return append([]byte(nil), data...), true
		}
	}
	if data, ok := encodedTerminalKeys[msg.Type]; ok {
		return append([]byte(nil), data...), true
	}
	if msg.Type >= tea.KeyCtrlAt && msg.Type <= tea.KeyCtrlUnderscore {
		return []byte{byte(msg.Type)}, true
	}
	return nil, false
}

func HandlePrefixKey(app *App, msg tea.KeyMsg) tea.Cmd {
	if app == nil {
		return nil
	}
	app.prefix = false
	key := strings.ToLower(msg.String())

	switch key {
	case "q":
		app.openQuitConfirm()
		return nil
	case "?":
		app.helpOpen = true
		return nil
	}

	if app.approvalActive() {
		app.handleApprovalPrefix(key)
		return nil
	}

	return app.handleGlobalPrefix(key)
}

func (a *App) handleApprovalPrefix(key string) {
	switch key {
	case "r":
		a.approve(RoleRead, false)
	case "w":
		a.approve(RoleWrite, false)
	case "d":
		a.approve("", true)
	}
}

func (a *App) handleGlobalPrefix(key string) tea.Cmd {
	if action, ok := globalPrefixActions[key]; ok {
		return action(a)
	}
	return nil
}

var globalPrefixActions = map[string]func(*App) tea.Cmd{
	"s":     toggleSidebarAction,
	"c":     focusChatAction,
	"t":     focusTerminalAction,
	"i":     inviteAction,
	"y":     copyModeAction,
	"left":  widenChatAction,
	"[":     widenChatAction,
	"right": narrowChatAction,
	"]":     narrowChatAction,
	"q":     quitAction,
	"r":     readRoleAction,
	"w":     writeRoleAction,
	"k":     kickPeerAction,
	"?":     helpAction,
}

func toggleSidebarAction(a *App) tea.Cmd {
	a.setSidebarOpen(!a.sidebarOpen)
	return nil
}

func focusChatAction(a *App) tea.Cmd {
	a.setSidebarOpen(true)
	a.focusChat()
	return nil
}

func focusTerminalAction(a *App) tea.Cmd {
	a.focusTerminal()
	return nil
}

func inviteAction(a *App) tea.Cmd {
	return a.openInvite()
}

func copyModeAction(a *App) tea.Cmd {
	return a.setCopyMode(!a.copyMode)
}

func widenChatAction(a *App) tea.Cmd {
	if a.sidebarOpen {
		a.setSidebarWidth(a.layout.Sidebar.W + 4)
	}
	return nil
}

func narrowChatAction(a *App) tea.Cmd {
	if a.sidebarOpen {
		a.setSidebarWidth(a.layout.Sidebar.W - 4)
	}
	return nil
}

func quitAction(a *App) tea.Cmd {
	a.openQuitConfirm()
	return nil
}

func readRoleAction(a *App) tea.Cmd {
	a.changeFirstPeerRole(RoleRead)
	return nil
}

func writeRoleAction(a *App) tea.Cmd {
	a.changeFirstPeerRole(RoleWrite)
	return nil
}

func kickPeerAction(a *App) tea.Cmd {
	a.beginKickFirstPeer()
	return nil
}

func helpAction(a *App) tea.Cmd {
	a.helpOpen = true
	return nil
}

func (a *App) beginKickFirstPeer() {
	if len(a.peers) == 0 {
		return
	}
	a.kickPeerID = a.peers[0].ID
	a.kickPeer = valueOr(a.peers[0].Name, a.peers[0].ID)
	a.focus = FocusApproval
}
