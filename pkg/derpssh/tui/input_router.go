// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import tea "github.com/charmbracelet/bubbletea"

type InputRouter struct {
	app *App
}

func (a *App) routeInput(msg tea.KeyMsg) tea.Cmd {
	return InputRouter{app: a}.RouteKey(msg)
}

func (r InputRouter) RouteKey(msg tea.KeyMsg) tea.Cmd {
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
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
		return nil
	}
	if a.copyMode && msg.Type == tea.KeyEsc {
		return a.setCopyMode(false)
	}
	if a.focus == FocusChat {
		return a.handleChatKey(msg)
	}
	return a.handleTerminalKey(msg)
}
