// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestInputRouterRoutesEligiblePageKeysToScrollback(t *testing.T) {
	pane := &interactiveFakePane{
		fakePane: fakePane{view: "ok"},
		viewport: terminalViewportState{Rows: 7, ScrollbackLines: 20, OffsetFromBottom: 7},
	}
	app := NewApp(Options{Terminal: pane})

	app.Update(keyCode(tea.KeyPgUp))
	app.Update(keyCode(tea.KeyPgDown))

	if got, want := pane.scrolls, []int{7, -7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ScrollLines calls = %v, want %v", got, want)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("eligible page keys emitted terminal command %+v, want none", cmd)
	}
}

func TestInputRouterForwardsModifiedPageKeys(t *testing.T) {
	tests := []struct {
		name string
		mod  tea.KeyMod
		want string
	}{
		{name: "shift", mod: tea.ModShift, want: "\x1b[5;2~"},
		{name: "ctrl", mod: tea.ModCtrl, want: "\x1b[5;5~"},
		{name: "alt", mod: tea.ModAlt, want: "\x1b[5;3~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &interactiveFakePane{
				fakePane: fakePane{view: "ok"},
				viewport: terminalViewportState{Rows: 7, ScrollbackLines: 20},
			}
			app := NewApp(Options{Terminal: pane})

			app.Update(modifiedKey(tea.KeyPgUp, "", tt.mod))

			cmd, ok := readCommand(app).(TerminalInputCommand)
			if !ok {
				t.Fatalf("command = %T, want TerminalInputCommand", cmd)
			}
			if got := string(cmd.Data); got != tt.want {
				t.Fatalf("terminal data = %q, want %q", got, tt.want)
			}
			if len(pane.scrolls) != 0 {
				t.Fatalf("ScrollLines calls = %v, want none", pane.scrolls)
			}
		})
	}
}

func TestInputRouterForwardsPageKeysForFullscreenModes(t *testing.T) {
	tests := []struct {
		name     string
		mouse    MouseMode
		input    TerminalInputMode
		viewport terminalViewportState
	}{
		{name: "mouse", mouse: MouseMode{Enabled: true}},
		{name: "application cursor", input: TerminalInputMode{ApplicationCursor: true}},
		{name: "bracketed paste", input: TerminalInputMode{BracketedPaste: true}},
		{name: "alternate screen", viewport: terminalViewportState{AlternateScreen: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &interactiveFakePane{
				fakePane: fakePane{view: "ok", mouse: tt.mouse, input: tt.input},
				viewport: tt.viewport,
			}
			pane.viewport.Rows = 7
			app := NewApp(Options{Terminal: pane})

			app.Update(keyCode(tea.KeyPgDown))

			cmd, ok := readCommand(app).(TerminalInputCommand)
			if !ok {
				t.Fatalf("command = %T, want TerminalInputCommand", cmd)
			}
			if got, want := string(cmd.Data), "\x1b[6~"; got != want {
				t.Fatalf("terminal data = %q, want %q", got, want)
			}
			if len(pane.scrolls) != 0 {
				t.Fatalf("ScrollLines calls = %v, want none", pane.scrolls)
			}
		})
	}
}

func TestInputRouterConsumesPageKeyAtViewportBoundary(t *testing.T) {
	pane := &clampedViewportPane{interactiveFakePane: interactiveFakePane{
		fakePane: fakePane{view: "ok"},
		viewport: terminalViewportState{Rows: 7, ScrollbackLines: 20, OffsetFromBottom: 20},
	}}
	app := NewApp(Options{Terminal: pane})

	app.Update(keyCode(tea.KeyPgUp))

	if got, want := pane.scrolls, []int{7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ScrollLines calls = %v, want %v", got, want)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("clamped page key emitted terminal command %+v, want none", cmd)
	}
}

type clampedViewportPane struct {
	interactiveFakePane
}

func (p *clampedViewportPane) ScrollLines(delta int) bool {
	p.scrolls = append(p.scrolls, delta)
	return false
}

type orderedInteractionPane struct {
	interactiveFakePane
	events []string
}

func (p *orderedInteractionPane) InputMode() TerminalInputMode {
	p.events = append(p.events, "input-mode")
	return p.interactiveFakePane.InputMode()
}

func (p *orderedInteractionPane) ResetViewport() bool {
	p.events = append(p.events, "reset")
	return p.interactiveFakePane.ResetViewport()
}

func (p *orderedInteractionPane) ClearSelection() {
	p.events = append(p.events, "clear")
	p.interactiveFakePane.ClearSelection()
}

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
	pane := &orderedInteractionPane{interactiveFakePane: interactiveFakePane{
		fakePane: fakePane{
			view:  "ok",
			input: TerminalInputMode{BracketedPaste: true},
		},
		viewport:    terminalViewportState{OffsetFromBottom: 4},
		selectionOn: true,
	}}
	app := NewApp(Options{Terminal: pane})

	app.Update(tea.PasteMsg{Content: "one\ntwo"})

	if got, want := pane.events, []string{"reset", "clear", "input-mode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("terminal interaction order = %v, want %v", got, want)
	}
	cmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if got, want := string(cmd.Data), "\x1b[200~one\ntwo\x1b[201~"; got != want {
		t.Fatalf("terminal paste = %q, want %q", got, want)
	}
}

func TestInputRouterRoutesChatPasteToComposer(t *testing.T) {
	pane := &orderedInteractionPane{interactiveFakePane: interactiveFakePane{
		fakePane: fakePane{view: "ok"},
	}}
	app := NewApp(Options{Terminal: pane})
	app.focusChat()

	app.Update(tea.PasteMsg{Content: "one\ntwo"})

	if got := app.composer.Value(); got != "one\ntwo" {
		t.Fatalf("composer value = %q, want pasted text", got)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("chat paste emitted command %+v, want none", cmd)
	}
	if len(pane.events) != 0 {
		t.Fatalf("chat paste terminal interactions = %v, want none", pane.events)
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

func TestInputRouterNonterminalKeysDoNotResetViewportOrSelection(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*App)
		key   tea.KeyPressMsg
	}{
		{name: "prefix start", key: modifiedKey('x', "", tea.ModCtrl)},
		{name: "prefix command", setup: func(app *App) { app.prefix = true }, key: textKey("s")},
		{name: "modal input", setup: func(app *App) { app.helpOpen = true }, key: textKey("q")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &orderedInteractionPane{interactiveFakePane: interactiveFakePane{
				fakePane:    fakePane{view: "ok"},
				viewport:    terminalViewportState{OffsetFromBottom: 4},
				selectionOn: true,
			}}
			app := NewApp(Options{Terminal: pane})
			if tt.setup != nil {
				tt.setup(app)
			}

			app.Update(tt.key)

			if len(pane.events) != 0 {
				t.Fatalf("terminal interactions = %v, want none", pane.events)
			}
		})
	}
}

func TestInputRouterLocalPageKeyDoesNotResetViewportOrSelection(t *testing.T) {
	pane := &orderedInteractionPane{interactiveFakePane: interactiveFakePane{
		fakePane:    fakePane{view: "ok"},
		viewport:    terminalViewportState{Rows: 7, ScrollbackLines: 20, OffsetFromBottom: 4},
		selectionOn: true,
	}}
	app := NewApp(Options{Terminal: pane})

	app.Update(keyCode(tea.KeyPgUp))

	if got, want := pane.events, []string{"input-mode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("terminal interactions = %v, want %v", got, want)
	}
	if got, want := pane.scrolls, []int{7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ScrollLines calls = %v, want %v", got, want)
	}
}
