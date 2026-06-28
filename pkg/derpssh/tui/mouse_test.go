// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMouseClickTopBarChatToggle(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	chat := topBarActionRect(t, app, topBarActionChat)

	app.Update(leftClick(chat.X+chat.W/2, chat.Y))

	if !app.sidebarOpen {
		t.Fatalf("sidebarOpen = false, want true after top-bar chat click")
	}
	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 66, Rows: 29}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
}

func TestMouseClickTopBarQuitOpensConfirmation(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	quit := topBarActionRect(t, app, topBarActionQuit)

	app.Update(leftClick(quit.X+quit.W/2, quit.Y))

	if !app.quitOpen {
		t.Fatalf("quitOpen = false, want true after top-bar X click")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("top-bar X emitted command before confirmation: %+v", cmd)
	}
}

func TestMouseClickQuitConfirmationButtons(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.openQuitConfirm()
	quit, _ := app.quitButtonRects()

	app.Update(leftClick(quit.X+quit.W/2, quit.Y))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("quit confirmation click did not emit QuitCommand")
	}
}

func TestMouseMenuDoesNotExposeInvite(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "npx -y derpssh@latest connect DSH1copyme", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	menu := topBarActionRect(t, app, topBarActionHelp)

	app.Update(leftClick(menu.X+menu.W/2, menu.Y))

	if strings.Contains(app.View(), "Show Invite") || strings.Contains(app.View(), "Ctrl-X I") {
		t.Fatalf("menu exposes invite action:\n%s", app.View())
	}
}

func TestMouseClickFocusesTerminalAndChat(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	drainCommands(app)

	app.Update(leftClick(app.layout.Terminal.X+1, app.layout.Terminal.Y+1))
	if app.focus != FocusTerminal {
		t.Fatalf("focus after terminal click = %v, want terminal", app.focus)
	}

	app.Update(leftClick(app.layout.Composer.X+1, app.layout.Composer.Y))
	if app.focus != FocusChat {
		t.Fatalf("focus after composer click = %v, want chat", app.focus)
	}
}

func TestMouseDragDividerResizesChat(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	drainCommands(app)
	start := app.layout.Divider.X

	app.Update(leftClick(start, app.layout.Divider.Y+2))
	app.Update(tea.MouseMsg{X: 70, Y: app.layout.Divider.Y + 2, Action: tea.MouseActionMotion, Button: tea.MouseButtonLeft})
	app.Update(tea.MouseMsg{X: 70, Y: app.layout.Divider.Y + 2, Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft})

	if app.layout.Sidebar.W != 49 {
		t.Fatalf("Sidebar.W = %d, want 49 after dragging divider", app.layout.Sidebar.W)
	}
	if !app.sidebarOpen {
		t.Fatalf("sidebarOpen = false after divider drag")
	}
}

func TestMouseClickApprovalButtons(t *testing.T) {
	tests := []struct {
		name string
		pick func(read Rect, write Rect, deny Rect) Rect
		want ApprovalDecisionCommand
	}{
		{name: "read", pick: func(read Rect, write Rect, deny Rect) Rect { return read }, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleRead}},
		{name: "write", pick: func(read Rect, write Rect, deny Rect) Rect { return write }, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleWrite}},
		{name: "deny", pick: func(read Rect, write Rect, deny Rect) Rect { return deny }, want: ApprovalDecisionCommand{Peer: "Alex", Deny: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			app.Update(ApprovalRequestMsg{Peer: "Alex"})
			read, write, deny := app.approvalButtonRects()
			button := tt.pick(read, write, deny)

			app.Update(leftClick(button.X+button.W/2, button.Y))

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
	read, _, _ := app.approvalButtonRects()

	app.Update(leftClick(read.X+read.W/2, read.Y))

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

func topBarActionRect(t *testing.T, app *App, action topBarAction) Rect {
	t.Helper()
	app.renderTopBar()
	for _, hit := range app.topBarHits {
		if hit.action == action {
			return hit.rect
		}
	}
	t.Fatalf("missing top-bar action %v in hits %+v", action, app.topBarHits)
	return Rect{}
}

func drainCommands(app *App) {
	for {
		if cmd := readCommand(app); cmd == nil {
			return
		}
	}
}
