// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestInputRouterPassesCtrlRToTerminal(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	_ = app.routeInput(modifiedKey('r', "", tea.ModCtrl))

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

	_ = app.routeInput(modifiedKey('x', "", tea.ModCtrl))

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

	_ = app.routeInput(textKey("h"))
	_ = app.routeInput(textKey("i"))
	_ = app.routeInput(keyCode(tea.KeyLeft))
	_ = app.routeInput(textKey("!"))

	if got := app.composer.Value(); got != "h!i" {
		t.Fatalf("composer text after insertion = %q, want h!i", got)
	}
	_ = app.routeInput(keyCode(tea.KeyBackspace))
	if got := app.composer.Value(); got != "hi" {
		t.Fatalf("composer text after deletion = %q, want hi", got)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("chat focused key emitted terminal command %+v, want none", cmd)
	}
}

func TestInputRouterRoutesTerminalPasteWithEmbeddedMode(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{
		view:  "ok",
		input: TerminalInputMode{BracketedPaste: true},
	}})

	app.Update(tea.PasteMsg{Content: "one\ntwo"})

	cmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if got, want := string(cmd.Data), "\x1b[200~one\ntwo\x1b[201~"; got != want {
		t.Fatalf("terminal paste = %q, want %q", got, want)
	}
}

func TestInputRouterRoutesChatPasteToComposer(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.focusChat()

	app.Update(tea.PasteMsg{Content: "one\ntwo"})

	if got := app.composer.Value(); got != "one\ntwo" {
		t.Fatalf("composer value = %q, want pasted text", got)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("chat paste emitted command %+v, want none", cmd)
	}
}

func TestInputRouterSuppressesPasteDuringPrefixOrModal(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*App)
	}{
		{name: "prefix", setup: func(app *App) { app.prefix = true }},
		{name: "modal", setup: func(app *App) { app.helpOpen = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
			tt.setup(app)

			app.Update(tea.PasteMsg{Content: "q"})

			if cmd := readCommand(app); cmd != nil {
				t.Fatalf("suppressed paste emitted command %+v", cmd)
			}
		})
	}
}

func TestInputRouterSuppressesPasteWhileInviteOpen(t *testing.T) {
	pane := &fakePane{view: "ok", input: TerminalInputMode{BracketedPaste: true}}
	app := NewApp(Options{Terminal: pane})
	app.composer.SetValue("draft")
	app.focusTerminal()
	app.inviteOpen = true

	app.Update(tea.PasteMsg{Content: "hidden paste"})

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("invite paste emitted command %+v, want none", cmd)
	}
	if got := app.composer.Value(); got != "draft" {
		t.Fatalf("hidden composer value = %q, want draft", got)
	}
	if got := string(pane.writes); got != "" {
		t.Fatalf("hidden terminal writes = %q, want none", got)
	}
}

func TestInputRouterNilAppIgnoresPaste(t *testing.T) {
	if cmd := (InputRouter{}).RoutePaste(tea.PasteMsg{Content: "ignored"}); cmd != nil {
		t.Fatalf("RoutePaste() = %v, want nil", cmd)
	}
}
