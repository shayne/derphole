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
	if a.focus == FocusChat {
		return a.handleChatKey(msg)
	}
	return a.handleTerminalKey(msg)
}

func (r InputRouter) RoutePaste(msg tea.PasteMsg) tea.Cmd {
	a := r.app
	if a == nil || a.inviteOpen || a.modalActive() || a.prefix {
		return nil
	}
	if a.focus == FocusChat {
		var cmd tea.Cmd
		a.composer, cmd = a.composer.Update(msg)
		return cmd
	}
	a.emit(TerminalInputCommand{Data: EncodeTerminalPaste(msg, a.terminal.InputMode())})
	return nil
}
