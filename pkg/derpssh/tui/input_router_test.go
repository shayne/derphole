// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestInputRouterPassesCtrlRToTerminal(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	_ = app.routeInput(tea.KeyMsg{Type: tea.KeyCtrlR})

	cmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if string(cmd.Data) != "\x12" {
		t.Fatalf("sent %q, want Ctrl-R byte", string(cmd.Data))
	}
}

func TestInputRouterCtrlXStartsPrefixWithoutTerminalInput(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	_ = app.routeInput(tea.KeyMsg{Type: tea.KeyCtrlX})

	if !app.prefix {
		t.Fatal("Ctrl-X did not start prefix mode")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X emitted terminal command %+v, want none", cmd)
	}
}

func TestInputRouterChatFocusRoutesTextToComposer(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.focusChat()

	_ = app.routeInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})

	if got := app.composer.Value(); got != "h" {
		t.Fatalf("composer text = %q, want h", got)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("chat focused key emitted terminal command %+v, want none", cmd)
	}
}
