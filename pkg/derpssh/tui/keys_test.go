// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"bytes"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestEncodeTerminalKeyPrintable(t *testing.T) {
	got, ok := EncodeTerminalKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if !ok || string(got) != "a" {
		t.Fatalf("EncodeTerminalKey(a) = %q, %v; want a, true", got, ok)
	}

	got, ok = EncodeTerminalKey(tea.KeyMsg{Type: tea.KeySpace})
	if !ok || string(got) != " " {
		t.Fatalf("EncodeTerminalKey(space) = %q, %v; want space, true", got, ok)
	}
}

func TestEncodeTerminalKeyControlBytes(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyMsg
		want []byte
	}{
		{name: "ctrl-c", msg: tea.KeyMsg{Type: tea.KeyCtrlC}, want: []byte{0x03}},
		{name: "ctrl-x", msg: tea.KeyMsg{Type: tea.KeyCtrlX}, want: []byte{0x18}},
		{name: "enter", msg: tea.KeyMsg{Type: tea.KeyEnter}, want: []byte{'\r'}},
		{name: "tab", msg: tea.KeyMsg{Type: tea.KeyTab}, want: []byte{'\t'}},
		{name: "backspace", msg: tea.KeyMsg{Type: tea.KeyBackspace}, want: []byte{0x7f}},
		{name: "escape", msg: tea.KeyMsg{Type: tea.KeyEsc}, want: []byte{0x1b}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKey(tt.msg)
			if !ok || !bytes.Equal(got, tt.want) {
				t.Fatalf("EncodeTerminalKey() = %v, %v; want %v, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeTerminalKeyNavigation(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyMsg
		want string
	}{
		{name: "up", msg: tea.KeyMsg{Type: tea.KeyUp}, want: "\x1b[A"},
		{name: "down", msg: tea.KeyMsg{Type: tea.KeyDown}, want: "\x1b[B"},
		{name: "right", msg: tea.KeyMsg{Type: tea.KeyRight}, want: "\x1b[C"},
		{name: "left", msg: tea.KeyMsg{Type: tea.KeyLeft}, want: "\x1b[D"},
		{name: "home", msg: tea.KeyMsg{Type: tea.KeyHome}, want: "\x1b[H"},
		{name: "end", msg: tea.KeyMsg{Type: tea.KeyEnd}, want: "\x1b[F"},
		{name: "delete", msg: tea.KeyMsg{Type: tea.KeyDelete}, want: "\x1b[3~"},
		{name: "page up", msg: tea.KeyMsg{Type: tea.KeyPgUp}, want: "\x1b[5~"},
		{name: "page down", msg: tea.KeyMsg{Type: tea.KeyPgDown}, want: "\x1b[6~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKey(tt.msg)
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeTerminalKey() = %q, %v; want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestPrefixDoesNotReachPTY(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})

	cmd := readCommand(app)
	if _, ok := cmd.(TerminalInputCommand); ok {
		t.Fatalf("prefix emitted terminal input %+v, want none", cmd)
	}
	if _, ok := cmd.(TerminalResizeCommand); !ok {
		t.Fatalf("prefix command = %T, want TerminalResizeCommand only", cmd)
	}
	if !app.sidebarOpen {
		t.Fatalf("sidebarOpen = false, want true after Ctrl-X S toggle")
	}
}

func TestPrefixSidebarToggleEmitsTerminalResize(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})

	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 67, Rows: 28}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
}

func TestPrefixChatOpenEmitsTerminalResize(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})

	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 67, Rows: 28}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
}

func TestColonIsPlainShellInput(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if string(got.Data) != ":" {
		t.Fatalf("TerminalInputCommand.Data = %q, want colon", got.Data)
	}
}

func TestTerminalFocusEscapeReachesPTY(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	app.Update(tea.KeyMsg{Type: tea.KeyEsc})

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if !bytes.Equal(got.Data, []byte{0x1b}) {
		t.Fatalf("TerminalInputCommand.Data = %v, want escape byte", got.Data)
	}
}

func TestCommandQueueDoesNotDropWhenBufferWouldOverflow(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	for i := 0; i < 100; i++ {
		app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	}

	for i := 0; i < 100; i++ {
		cmd := readCommandEventually(t, app)
		got, ok := cmd.(TerminalInputCommand)
		if !ok {
			t.Fatalf("command %d = %T, want TerminalInputCommand", i, cmd)
		}
		if string(got.Data) != "a" {
			t.Fatalf("command %d data = %q, want a", i, got.Data)
		}
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("extra command after draining 100 = %+v", cmd)
	}
}

func TestCommandQueuePreservesFIFOWhenOverflowActive(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	for i := 0; i < 64; i++ {
		app.emit(TerminalInputCommand{Data: []byte{byte(i)}})
	}
	app.emit(TerminalInputCommand{Data: []byte{64}})

	first := readCommandEventually(t, app)
	if got := commandByte(t, first); got != 0 {
		t.Fatalf("first drained command byte = %d, want 0", got)
	}

	app.emit(TerminalInputCommand{Data: []byte{65}})

	for want := 1; want <= 65; want++ {
		cmd := readCommandEventually(t, app)
		if got := commandByte(t, cmd); got != byte(want) {
			t.Fatalf("drained command byte = %d, want %d", got, want)
		}
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("extra command after FIFO drain = %+v", cmd)
	}
}

func TestPrefixKickCommandIncludesSelectedPeerID(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{
		{ID: "guest-1", Name: "Alex", Role: RoleRead},
		{ID: "guest-2", Name: "Alex", Role: RoleWrite},
	}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	app.Update(tea.KeyMsg{Type: tea.KeyEnter})

	got, ok := readCommand(app).(KickCommand)
	if !ok {
		t.Fatalf("command = %T, want KickCommand", got)
	}
	want := KickCommand{PeerID: "guest-1", Peer: "Alex"}
	if got != want {
		t.Fatalf("kick command = %+v, want %+v", got, want)
	}
}

func TestPrefixRoleCommandsUseSelectedPeerID(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})

	got, ok := readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want := RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleWrite}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})

	got, ok = readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want = RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleRead}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}
}

func TestPrefixInviteOpensInviteScreen(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1copyme"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X I emitted command %+v, want only local invite screen", cmd)
	}
	if !app.inviteOpen {
		t.Fatalf("inviteOpen = false, want true")
	}
}

func TestPrefixQuitCommand(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	cmd := readCommand(app)
	if _, ok := cmd.(QuitCommand); !ok {
		t.Fatalf("command = %T, want QuitCommand", cmd)
	}
}

func TestPrefixQuitWorksDuringApproval(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	cmd := readCommand(app)
	if _, ok := cmd.(QuitCommand); !ok {
		t.Fatalf("command = %T, want QuitCommand", cmd)
	}
	if !app.approvalActive() {
		t.Fatalf("approval should remain active until shutdown resolves it")
	}
}

func TestPrefixQuitWorksDuringHelp(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	cmd := readCommand(app)
	if _, ok := cmd.(QuitCommand); !ok {
		t.Fatalf("command = %T, want QuitCommand", cmd)
	}
}

func TestHelpOverlayCapturesPrintableKeys(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})

	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("help overlay emitted command %+v, want none", cmd)
	}
	if !app.helpOpen {
		t.Fatalf("helpOpen = false, want true")
	}
}

func TestKickOverlayCapturesPrintableKeys(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})

	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("kick overlay emitted command %+v, want none", cmd)
	}
	if app.kickPeerID != "guest-1" {
		t.Fatalf("kickPeerID = %q, want guest-1", app.kickPeerID)
	}
}

func TestPeerCommandsExposeStableIDs(t *testing.T) {
	role := RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleWrite}
	if role.PeerID != "guest-1" || role.Peer != "Alex" || role.Role != RoleWrite {
		t.Fatalf("role command = %+v, want stable ID and display name", role)
	}
	kick := KickCommand{PeerID: "guest-1", Peer: "Alex"}
	if kick.PeerID != "guest-1" || kick.Peer != "Alex" {
		t.Fatalf("kick command = %+v, want stable ID and display name", kick)
	}
}

func commandByte(t *testing.T, cmd Command) byte {
	t.Helper()
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if len(got.Data) != 1 {
		t.Fatalf("command data = %v, want single byte", got.Data)
	}
	return got.Data[0]
}

func readCommand(app *App) Command {
	select {
	case cmd := <-app.Commands():
		return cmd
	default:
		return nil
	}
}

func readCommandEventually(t *testing.T, app *App) Command {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case cmd := <-app.Commands():
		return cmd
	case <-timer.C:
		t.Fatal("timed out waiting for command")
		return nil
	}
}
