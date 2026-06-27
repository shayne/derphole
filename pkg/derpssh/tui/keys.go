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

func EncodeTerminalKey(msg tea.KeyMsg) ([]byte, bool) {
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

	if app.approvalActive() {
		app.handleApprovalPrefix(strings.ToLower(msg.String()))
		return nil
	}

	app.handleGlobalPrefix(strings.ToLower(msg.String()))
	return nil
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

func (a *App) handleGlobalPrefix(key string) {
	switch key {
	case "s":
		a.setSidebarOpen(!a.sidebarOpen)
	case "c":
		a.setSidebarOpen(true)
		a.focusChat()
	case "t":
		a.focusTerminal()
	case "i":
		a.openInvite()
	case "q":
		a.emit(QuitCommand{})
	case "r":
		a.changeFirstPeerRole(RoleRead)
	case "w":
		a.changeFirstPeerRole(RoleWrite)
	case "k":
		a.beginKickFirstPeer()
	case "?":
		a.helpOpen = true
	}
}

func (a *App) beginKickFirstPeer() {
	if len(a.peers) == 0 {
		return
	}
	a.kickPeerID = a.peers[0].ID
	a.kickPeer = valueOr(a.peers[0].Name, a.peers[0].ID)
	a.focus = FocusApproval
}
