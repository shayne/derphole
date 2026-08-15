// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import tea "charm.land/bubbletea/v2"

type InputRouter struct {
	app *App
}

func (a *App) routeInput(msg tea.KeyPressMsg) tea.Cmd {
	return InputRouter{app: a}.RouteKey(msg)
}

func (r InputRouter) RouteKey(msg tea.KeyPressMsg) tea.Cmd {
	a := r.app
	if a == nil {
		return nil
	}
	if cmd, handled := a.handleScreenKey(msg); handled {
		return cmd
	}
	if a.prefix {
		return HandlePrefixKey(a, msg)
	}
	if isCtrlKey(msg, 'x') {
		a.prefix = true
		return nil
	}
	if a.copyMode && msg.Code == tea.KeyEsc {
		return a.setCopyMode(false)
	}
	if cmd, handled := a.routeFocusedChatKey(msg); handled {
		return cmd
	}
	if a.handleTerminalViewportKey(msg) {
		return nil
	}
	data, ok := EncodeTerminalKeyWithMode(msg, a.terminal.InputMode())
	if !ok {
		return nil
	}
	a.resetTerminalViewportForInput()
	a.emit(TerminalInputCommand{Data: data})
	return nil
}

func (a *App) routeFocusedChatKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	if a.focus != FocusChat {
		return nil, false
	}
	if a.sidebarVisible() {
		return a.handleChatKey(msg), true
	}
	a.focusTerminal()
	return nil, false
}

func (a *App) handleTerminalViewportKey(msg tea.KeyPressMsg) bool {
	if msg.Mod != 0 || (msg.Code != tea.KeyPgUp && msg.Code != tea.KeyPgDown) {
		return false
	}
	interaction, ok := a.terminal.(terminalViewportInteraction)
	if !ok {
		return false
	}
	state := interaction.ViewportState()
	inputMode := a.terminal.InputMode()
	if state.AlternateScreen || a.terminal.MouseMode().Enabled || inputMode.ApplicationCursor || inputMode.BracketedPaste {
		return false
	}
	delta := state.Rows
	if msg.Code == tea.KeyPgDown {
		delta = -delta
	}
	interaction.ScrollLines(delta)
	return true
}

func (a *App) resetTerminalViewportForInput() {
	if interaction, ok := a.terminal.(terminalViewportInteraction); ok {
		interaction.ResetViewport()
	}
	if interaction, ok := a.terminal.(terminalInteraction); ok {
		interaction.ClearSelection()
	}
}

func (r InputRouter) RoutePaste(msg tea.PasteMsg) tea.Cmd {
	a := r.app
	if a == nil || a.inviteOpen || a.modalActive() || a.prefix {
		return nil
	}
	if a.focus == FocusChat {
		if a.sidebarVisible() {
			var cmd tea.Cmd
			a.composer, cmd = a.composer.Update(msg)
			return cmd
		}
		a.focusTerminal()
	}
	a.resetTerminalViewportForInput()
	a.emit(TerminalInputCommand{Data: EncodeTerminalPaste(msg, a.terminal.InputMode())})
	return nil
}
