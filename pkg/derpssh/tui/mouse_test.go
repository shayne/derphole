// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMouseClickSidebarToggle(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	app.Update(leftClick(99, 0))

	if app.sidebarOpen {
		t.Fatalf("sidebarOpen = true, want false after top-bar toggle click")
	}
	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 100, Rows: 28}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
}

func TestMouseClickFocusesTerminalAndChat(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	app.Update(leftClick(app.layout.Terminal.X+1, app.layout.Terminal.Y+1))
	if app.focus != FocusTerminal {
		t.Fatalf("focus after terminal click = %v, want terminal", app.focus)
	}

	app.Update(leftClick(app.layout.Composer.X+1, app.layout.Composer.Y+1))
	if app.focus != FocusChat {
		t.Fatalf("focus after composer click = %v, want chat", app.focus)
	}
}

func TestMouseClickApprovalButtons(t *testing.T) {
	tests := []struct {
		name string
		x    int
		want ApprovalDecisionCommand
	}{
		{name: "read", x: 28, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleRead}},
		{name: "write", x: 38, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleWrite}},
		{name: "deny", x: 49, want: ApprovalDecisionCommand{Peer: "Alex", Deny: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			app.Update(ApprovalRequestMsg{Peer: "Alex"})

			app.Update(leftClick(tt.x, 14))

			got, ok := readCommand(app).(ApprovalDecisionCommand)
			if !ok {
				t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
			}
			if got != tt.want {
				t.Fatalf("approval command = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMouseDuringApprovalDoesNotReachTerminalOrChangeFocus(t *testing.T) {
	pane := &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}
	app := NewApp(Options{Side: "host", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.Update(ApprovalRequestMsg{Peer: "Alex"})

	app.Update(leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("approval terminal click emitted command %+v, want none", cmd)
	}
	if app.focus != FocusApproval {
		t.Fatalf("focus = %v, want approval", app.focus)
	}
}

func TestApprovalDecisionIncludesPeerIDForDuplicateNames(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Alex"})

	app.Update(leftClick(28, 14))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
}

func TestTerminalMouseOnlyForwardsWhenEnabled(t *testing.T) {
	pane := &fakePane{view: "ok"}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	app.Update(leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("mouse with disabled terminal mode emitted %+v, want none", cmd)
	}

	pane.mouse = MouseMode{Enabled: true, SGR: true}
	app.Update(leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))
	cmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	seq := string(cmd.Data)
	if !strings.HasPrefix(seq, "\x1b[<0;") || !strings.HasSuffix(seq, "M") {
		t.Fatalf("mouse sequence = %q, want SGR button press", seq)
	}
}

func TestMouseButtonCodeMapsButtons(t *testing.T) {
	tests := []struct {
		name   string
		button tea.MouseButton
		want   int
	}{
		{name: "left", button: tea.MouseButtonLeft, want: 0},
		{name: "middle", button: tea.MouseButtonMiddle, want: 1},
		{name: "right", button: tea.MouseButtonRight, want: 2},
		{name: "wheel up", button: tea.MouseButtonWheelUp, want: 64},
		{name: "wheel down", button: tea.MouseButtonWheelDown, want: 65},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := mouseButtonCode(tea.MouseMsg{Action: tea.MouseActionPress, Button: tt.button})
			if !ok || got != tt.want {
				t.Fatalf("mouseButtonCode() = %d, %v; want %d, true", got, ok, tt.want)
			}
		})
	}
}

func TestMouseButtonCodeReleaseAndUnknown(t *testing.T) {
	if got, ok := mouseButtonCode(tea.MouseMsg{Action: tea.MouseActionRelease}); !ok || got != 0 {
		t.Fatalf("release mouseButtonCode() = %d, %v; want 0, true", got, ok)
	}
	if got, ok := mouseButtonCode(tea.MouseMsg{Action: tea.MouseActionPress}); ok || got != 0 {
		t.Fatalf("unknown mouseButtonCode() = %d, %v; want 0, false", got, ok)
	}
}

func leftClick(x int, y int) tea.MouseMsg {
	return tea.MouseMsg{
		X:      x,
		Y:      y,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	}
}

func drainCommands(app *App) {
	for {
		if cmd := readCommand(app); cmd == nil {
			return
		}
	}
}
