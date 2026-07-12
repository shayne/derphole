// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

func TestEncodeTerminalKeyPrintable(t *testing.T) {
	got, ok := EncodeTerminalKey(textKey("a"))
	if !ok || string(got) != "a" {
		t.Fatalf("EncodeTerminalKey(a) = %q, %v; want a, true", got, ok)
	}

	got, ok = EncodeTerminalKey(keyCode(tea.KeySpace))
	if !ok || string(got) != " " {
		t.Fatalf("EncodeTerminalKey(space) = %q, %v; want space, true", got, ok)
	}
}

func TestEncodeTerminalKeyControlBytes(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want []byte
	}{
		{name: "ctrl-c", msg: modifiedKey('c', "", tea.ModCtrl), want: []byte{0x03}},
		{name: "ctrl-x", msg: modifiedKey('x', "", tea.ModCtrl), want: []byte{0x18}},
		{name: "ctrl-space", msg: modifiedKey(tea.KeySpace, "", tea.ModCtrl), want: []byte{0x00}},
		{name: "enter", msg: keyCode(tea.KeyEnter), want: []byte{'\r'}},
		{name: "tab", msg: keyCode(tea.KeyTab), want: []byte{'\t'}},
		{name: "backspace", msg: keyCode(tea.KeyBackspace), want: []byte{0x7f}},
		{name: "escape", msg: keyCode(tea.KeyEsc), want: []byte{0x1b}},
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
		msg  tea.KeyPressMsg
		want string
	}{
		{name: "up", msg: keyCode(tea.KeyUp), want: "\x1b[A"},
		{name: "down", msg: keyCode(tea.KeyDown), want: "\x1b[B"},
		{name: "right", msg: keyCode(tea.KeyRight), want: "\x1b[C"},
		{name: "left", msg: keyCode(tea.KeyLeft), want: "\x1b[D"},
		{name: "home", msg: keyCode(tea.KeyHome), want: "\x1b[H"},
		{name: "end", msg: keyCode(tea.KeyEnd), want: "\x1b[F"},
		{name: "delete", msg: keyCode(tea.KeyDelete), want: "\x1b[3~"},
		{name: "page up", msg: keyCode(tea.KeyPgUp), want: "\x1b[5~"},
		{name: "page down", msg: keyCode(tea.KeyPgDown), want: "\x1b[6~"},
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

func TestEncodeTerminalKeyHtopFunctionKeys(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{name: "f1", msg: keyCode(tea.KeyF1), want: "\x1bOP"},
		{name: "f5", msg: keyCode(tea.KeyF5), want: "\x1b[15~"},
		{name: "f10", msg: keyCode(tea.KeyF10), want: "\x1b[21~"},
		{name: "f12", msg: keyCode(tea.KeyF12), want: "\x1b[24~"},
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

func TestEncodeTerminalKeyApplicationCursorMode(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{name: "up", msg: keyCode(tea.KeyUp), want: "\x1bOA"},
		{name: "down", msg: keyCode(tea.KeyDown), want: "\x1bOB"},
		{name: "right", msg: keyCode(tea.KeyRight), want: "\x1bOC"},
		{name: "left", msg: keyCode(tea.KeyLeft), want: "\x1bOD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKeyWithMode(tt.msg, TerminalInputMode{ApplicationCursor: true})
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeTerminalKeyWithMode() = %q, %v; want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeTerminalKeyV2Modifiers(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{"unicode", textKey("界"), "界"},
		{"alt text", modifiedKey('x', "x", tea.ModAlt), "\x1bx"},
		{"ctrl c", modifiedKey('c', "", tea.ModCtrl), "\x03"},
		{"ctrl shift right", modifiedKey(tea.KeyRight, "", tea.ModCtrl|tea.ModShift), "\x1b[1;6C"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKeyWithMode(tt.msg, TerminalInputMode{})
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeTerminalKeyWithMode() = %q, %v, want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeTerminalKeyAltPrintableFallback(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want string
	}{
		{name: "ascii code", msg: modifiedKey('x', "", tea.ModAlt), want: "\x1bx"},
		{name: "unicode code", msg: modifiedKey('界', "", tea.ModAlt), want: "\x1b界"},
		{name: "shifted code", msg: tea.KeyPressMsg{Code: '1', ShiftedCode: '!', Mod: tea.ModAlt | tea.ModShift}, want: "\x1b!"},
		{name: "alt ctrl ascii", msg: modifiedKey('c', "", tea.ModAlt|tea.ModCtrl), want: "\x1b\x03"},
		{name: "text is authoritative", msg: modifiedKey('x', "é", tea.ModAlt), want: "\x1bé"},
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

func TestEncodeTerminalKeyAltShiftFallbackWithoutShiftedCode(t *testing.T) {
	t.Run("letter", func(t *testing.T) {
		msg := tea.KeyPressMsg{Code: 'p', Mod: tea.ModAlt | tea.ModShift}
		got, ok := EncodeTerminalKey(msg)
		if !ok || string(got) != "\x1bP" {
			t.Fatalf("EncodeTerminalKey(alt+shift+p) = %q, %v; want %q, true", got, ok, "\x1bP")
		}
	})

	t.Run("unrecoverable non-letter", func(t *testing.T) {
		msg := tea.KeyPressMsg{Code: '1', Mod: tea.ModAlt | tea.ModShift}
		got, ok := EncodeTerminalKey(msg)
		if ok || got != nil {
			t.Fatalf("EncodeTerminalKey(alt+shift+1) = %q, %v; want nil, false", got, ok)
		}
	})
}

func TestEncodeTerminalKeyAltPrefixDoesNotInspectPayload(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		want []byte
	}{
		{name: "ctrl bracket", msg: modifiedKey('[', "", tea.ModAlt|tea.ModCtrl), want: []byte{0x1b, 0x1b}},
		{name: "authoritative escape text", msg: modifiedKey('x', "\x1bx", tea.ModAlt), want: []byte{0x1b, 0x1b, 'x'}},
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

func TestEncodeTerminalKeyModifiedSpecialKeys(t *testing.T) {
	tests := []struct {
		name string
		msg  tea.KeyPressMsg
		mode TerminalInputMode
		want string
	}{
		{name: "shift up", msg: modifiedKey(tea.KeyUp, "", tea.ModShift), want: "\x1b[1;2A"},
		{name: "alt down", msg: modifiedKey(tea.KeyDown, "", tea.ModAlt), want: "\x1b[1;3B"},
		{name: "ctrl right", msg: modifiedKey(tea.KeyRight, "", tea.ModCtrl), want: "\x1b[1;5C"},
		{name: "meta left", msg: modifiedKey(tea.KeyLeft, "", tea.ModMeta), want: "\x1b[1;9D"},
		{name: "modified application cursor", msg: modifiedKey(tea.KeyUp, "", tea.ModShift), mode: TerminalInputMode{ApplicationCursor: true}, want: "\x1b[1;2A"},
		{name: "shift insert", msg: modifiedKey(tea.KeyInsert, "", tea.ModShift), want: "\x1b[2;2~"},
		{name: "alt delete", msg: modifiedKey(tea.KeyDelete, "", tea.ModAlt), want: "\x1b[3;3~"},
		{name: "ctrl page up", msg: modifiedKey(tea.KeyPgUp, "", tea.ModCtrl), want: "\x1b[5;5~"},
		{name: "meta page down", msg: modifiedKey(tea.KeyPgDown, "", tea.ModMeta), want: "\x1b[6;9~"},
		{name: "shift f1", msg: modifiedKey(tea.KeyF1, "", tea.ModShift), want: "\x1b[1;2P"},
		{name: "alt f4", msg: modifiedKey(tea.KeyF4, "", tea.ModAlt), want: "\x1b[1;3S"},
		{name: "ctrl f5", msg: modifiedKey(tea.KeyF5, "", tea.ModCtrl), want: "\x1b[15;5~"},
		{name: "meta f12", msg: modifiedKey(tea.KeyF12, "", tea.ModMeta), want: "\x1b[24;9~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := EncodeTerminalKeyWithMode(tt.msg, tt.mode)
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeTerminalKeyWithMode() = %q, %v; want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeTerminalKeyRejectsUnsupportedSpecialKeyModifiers(t *testing.T) {
	for _, mod := range []tea.KeyMod{tea.ModHyper, tea.ModSuper} {
		if got, ok := EncodeTerminalKey(modifiedKey(tea.KeyRight, "", mod)); ok || got != nil {
			t.Fatalf("EncodeTerminalKey(%v+right) = %q, %v; want nil, false", mod, got, ok)
		}
	}
}

func TestEncodeTerminalKeyRejectsUnsupportedFallbackModifiers(t *testing.T) {
	tests := []tea.KeyPressMsg{
		modifiedKey('c', "", tea.ModHyper|tea.ModCtrl),
		modifiedKey('x', "", tea.ModSuper|tea.ModAlt),
	}
	for _, msg := range tests {
		if got, ok := EncodeTerminalKey(msg); ok || got != nil {
			t.Fatalf("EncodeTerminalKey(%v) = %q, %v; want nil, false", msg.Mod, got, ok)
		}
	}
}

func TestEncodeTerminalKeyModifiedSpecialDoesNotDegrade(t *testing.T) {
	t.Run("shift tab", func(t *testing.T) {
		got, ok := EncodeTerminalKey(modifiedKey(tea.KeyTab, "", tea.ModShift))
		if !ok || string(got) != "\x1b[Z" {
			t.Fatalf("EncodeTerminalKey(shift+tab) = %q, %v; want backtab, true", got, ok)
		}
	})

	t.Run("meta enter", func(t *testing.T) {
		got, ok := EncodeTerminalKey(modifiedKey(tea.KeyEnter, "", tea.ModMeta))
		if ok || got != nil {
			t.Fatalf("EncodeTerminalKey(meta+enter) = %q, %v; want nil, false", got, ok)
		}
	})
}

func TestTerminalFocusHtopFunctionKeyReachesPTY(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	app.Update(keyCode(tea.KeyF10))

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if string(got.Data) != "\x1b[21~" {
		t.Fatalf("TerminalInputCommand.Data = %q, want F10 sequence", got.Data)
	}
}

func TestPrefixDoesNotReachPTY(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))

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

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))

	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 66, Rows: 29}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
	if app.focus != FocusChat {
		t.Fatalf("focus = %v, want chat after Ctrl-X S opens chat", app.focus)
	}
	if !app.composer.Focused() {
		t.Fatalf("composer focus = false, want true after Ctrl-X S opens chat")
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))

	if app.sidebarOpen {
		t.Fatalf("sidebarOpen = true, want false after Ctrl-X S closes chat")
	}
	if app.focus != FocusTerminal {
		t.Fatalf("focus = %v, want terminal after Ctrl-X S closes chat", app.focus)
	}
}

func TestPrefixChatOpenEmitsTerminalResize(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))

	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 66, Rows: 29}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
}

func TestColonIsPlainShellInput(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(textKey(":"))

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

	app.Update(keyCode(tea.KeyEsc))

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if !bytes.Equal(got.Data, []byte{0x1b}) {
		t.Fatalf("TerminalInputCommand.Data = %v, want escape byte", got.Data)
	}
}

func TestTerminalFocusCtrlRReachesPTY(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('r', "", tea.ModCtrl))

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if !bytes.Equal(got.Data, []byte{0x12}) {
		t.Fatalf("TerminalInputCommand.Data = %v, want ctrl-r byte", got.Data)
	}
}

func TestTerminalFocusUsesApplicationCursorMode(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok", input: TerminalInputMode{ApplicationCursor: true}}})

	app.Update(keyCode(tea.KeyUp))

	cmd := readCommand(app)
	got, ok := cmd.(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	if !bytes.Equal(got.Data, []byte("\x1bOA")) {
		t.Fatalf("TerminalInputCommand.Data = %q, want application cursor up", got.Data)
	}
}

func TestCommandQueueDoesNotDropWhenBufferWouldOverflow(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})

	for i := 0; i < 100; i++ {
		app.Update(textKey("a"))
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

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("k"))
	app.Update(keyCode(tea.KeyEnter))

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

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("w"))

	got, ok := readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want := RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleWrite}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("r"))

	got, ok = readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want = RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleRead}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}
}

func TestPeerDialogKeyboardNavigationAndConfirm(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.openPeerDialog(Peer{ID: "guest-2", Name: "Blair", Role: RoleWrite})

	app.Update(keyCode(tea.KeyRight))
	if app.peerDialogChoice != peerActionKick {
		t.Fatalf("right key choice = %v, want kick", app.peerDialogChoice)
	}
	app.Update(keyCode(tea.KeyLeft))
	if app.peerDialogChoice != peerActionWrite {
		t.Fatalf("left key choice = %v, want write", app.peerDialogChoice)
	}
	app.Update(keyCode(tea.KeyTab))
	if app.peerDialogChoice != peerActionKick {
		t.Fatalf("tab key choice = %v, want kick", app.peerDialogChoice)
	}
	app.Update(modifiedKey(tea.KeyTab, "", tea.ModShift))
	if app.peerDialogChoice != peerActionWrite {
		t.Fatalf("shift-tab key choice = %v, want write", app.peerDialogChoice)
	}
	app.Update(keyCode(tea.KeyEnter))

	got, ok := readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want := RoleChangeCommand{PeerID: "guest-2", Peer: "Blair", Role: RoleWrite}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}
	if app.peerDialogOpen {
		t.Fatalf("peer dialog still open after confirm")
	}
}

func TestPeerDialogRuneShortcuts(t *testing.T) {
	tests := []struct {
		name string
		key  rune
		want Command
	}{
		{name: "read", key: 'r', want: RoleChangeCommand{PeerID: "guest-2", Peer: "Blair", Role: RoleRead}},
		{name: "write", key: 'w', want: RoleChangeCommand{PeerID: "guest-2", Peer: "Blair", Role: RoleWrite}},
		{name: "kick", key: 'k', want: KickCommand{PeerID: "guest-2", Peer: "Blair"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.openPeerDialog(Peer{ID: "guest-2", Name: "Blair", Role: RoleWrite})

			app.Update(textKey(string(tt.key)))

			if got := readCommand(app); got != tt.want {
				t.Fatalf("command = %+v, want %+v", got, tt.want)
			}
			if app.peerDialogOpen {
				t.Fatalf("peer dialog still open after %q shortcut", tt.key)
			}
		})
	}
}

func TestPeerDialogShortcutAndCancelKeys(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.openPeerDialog(Peer{ID: "guest-2", Name: "Blair", Role: RoleWrite})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	if !app.prefix {
		t.Fatalf("Ctrl-X did not enable prefix while peer dialog was open")
	}
	app.Update(textKey("q"))
	if !app.quitOpen {
		t.Fatalf("Ctrl-X Q did not open quit confirmation while peer dialog was open")
	}

	app.closeQuitConfirm()
	app.openPeerDialog(Peer{ID: "guest-2", Name: "Blair", Role: RoleWrite})
	app.Update(keyCode(tea.KeyEsc))
	if app.peerDialogOpen {
		t.Fatalf("Esc did not close peer dialog")
	}

	app.openPeerDialog(Peer{ID: "guest-2", Name: "Blair", Role: RoleWrite})
	app.Update(textKey("q"))
	if app.peerDialogOpen {
		t.Fatalf("q did not close peer dialog")
	}
}

func TestEscapeClosesActiveOverlays(t *testing.T) {
	t.Run("approval denies", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})

		app.Update(keyCode(tea.KeyEsc))

		got, ok := readCommand(app).(ApprovalDecisionCommand)
		if !ok {
			t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
		}
		if !got.Deny || got.PeerID != "guest-1" || got.Peer != "Alex" {
			t.Fatalf("decision = %+v, want deny for guest-1/Alex", got)
		}
		if app.approvalActive() {
			t.Fatalf("approval still active after Esc")
		}
	})

	t.Run("quit confirm", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.openQuitConfirm()

		app.Update(keyCode(tea.KeyEsc))

		if app.quitOpen {
			t.Fatalf("quit confirmation still open after Esc")
		}
	})

	t.Run("prefix", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.Update(modifiedKey('x', "", tea.ModCtrl))

		app.Update(keyCode(tea.KeyEsc))

		if app.prefix {
			t.Fatalf("prefix still active after Esc")
		}
	})

	t.Run("help", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.helpOpen = true

		app.Update(keyCode(tea.KeyEsc))

		if app.helpOpen {
			t.Fatalf("help still open after Esc")
		}
	})

	t.Run("invite", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.inviteOpen = true

		app.Update(keyCode(tea.KeyEsc))

		if app.inviteOpen {
			t.Fatalf("invite still open after Esc")
		}
	})

	t.Run("kick", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.kickPeerID = "guest-1"
		app.kickPeer = "Alex"

		app.Update(keyCode(tea.KeyEsc))

		if app.kickPeerID != "" || app.kickPeer != "" {
			t.Fatalf("kick confirmation still open after Esc")
		}
	})

	t.Run("notice", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.noticeTitle = "Disconnected"
		app.noticeBody = "Guest quit"

		app.Update(keyCode(tea.KeyEsc))

		if app.noticeOpen() {
			t.Fatalf("notice still open after Esc")
		}
	})

	t.Run("shell exit", func(t *testing.T) {
		app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
		app.shellExitOpen = true

		app.Update(keyCode(tea.KeyEsc))

		if !app.shellExitOpen {
			t.Fatalf("shell-exit dialog closed on Esc, want it to stay open")
		}
	})
}

func TestApprovalIgnoresSelectionKeysDuringInputGrace(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.now = func() time.Time { return now }
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})

	app.Update(keyCode(tea.KeyEnter))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("immediate Enter emitted command %+v, want none during grace", cmd)
	}
	if !app.approvalActive() {
		t.Fatalf("approval was cleared during input grace")
	}

	now = now.Add(approvalInputGrace + time.Millisecond)
	app.Update(keyCode(tea.KeyEnter))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand after grace", got)
	}
	if got.Role != RoleWrite || got.Deny {
		t.Fatalf("decision = %+v, want write approval", got)
	}
}

func TestFrontModalReceivesKeysWhenHelpIsBehind(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.helpOpen = true
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	expireApprovalGrace(app)

	if got := app.modalStack().Front().ID(); got != ModalApproval {
		t.Fatalf("front modal = %q, want approval", got)
	}

	app.Update(keyCode(tea.KeyRight))

	if app.approvalChoice != approvalChoiceDeny {
		t.Fatalf("approval choice = %v, want deny after right key", app.approvalChoice)
	}
	if !app.helpOpen {
		t.Fatalf("help overlay behind approval should remain open")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("right key emitted command %+v, want none", cmd)
	}
}

func TestResizeWarningAllowsPrefixQuit(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	app.Update(RuntimeStateMsg{HostCols: 100, HostRows: 30, LocalRole: RoleWrite})
	drainCommands(app)

	if got := app.modalStack().Front().ID(); got != ModalResizeWarning {
		t.Fatalf("front modal = %q, want resize warning", got)
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X Q emitted command %+v before confirmation", cmd)
	}
	if !app.quitOpen {
		t.Fatalf("Ctrl-X Q did not open quit confirmation over resize warning")
	}
}

func TestPrefixInviteOpensHostInvite(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1copyme"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("i"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X I emitted command %+v, want none", cmd)
	}
	if !app.inviteOpen {
		t.Fatalf("inviteOpen = false, want true")
	}
}

func TestPrefixInviteIgnoredForGuest(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1copyme"
	app := NewApp(Options{Side: "guest", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("i"))

	if app.inviteOpen {
		t.Fatalf("guest inviteOpen = true, want false")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("guest Ctrl-X I emitted command %+v, want none", cmd)
	}
}

func TestPrefixCopyModeTogglesSelectionMode(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	_, cmd := app.Update(modifiedKey('x', "", tea.ModCtrl))
	if cmd != nil {
		t.Fatalf("Ctrl-X command = %T, want nil", cmd)
	}
	_, cmd = app.Update(textKey("y"))

	if !app.copyMode {
		t.Fatalf("copyMode = false, want true")
	}
	if cmd != nil {
		t.Fatalf("copy mode toggle command = %T, want nil", cmd)
	}
	if got := app.View().MouseMode; got != tea.MouseModeNone {
		t.Fatalf("copy mode mouse mode = %v, want none", got)
	}
}

func TestCopyModeEscapeLeavesSelectionMode(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("y"))
	if !app.copyMode {
		t.Fatalf("copyMode = false, want true before escape")
	}

	_, cmd := app.Update(keyCode(tea.KeyEsc))

	if app.copyMode {
		t.Fatalf("copyMode = true, want false after escape")
	}
	if cmd != nil {
		t.Fatalf("escape in copy mode command = %T, want nil", cmd)
	}
	if got := app.View().MouseMode; got != tea.MouseModeCellMotion {
		t.Fatalf("mouse mode after escape = %v, want cell motion", got)
	}
	if got := readCommand(app); got != nil {
		t.Fatalf("escape in copy mode emitted terminal command %+v, want none", got)
	}
}

func TestCopyModeCtrlXShowsExitHint(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 30})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("y"))
	app.Update(modifiedKey('x', "", tea.ModCtrl))

	firstLine := strings.Split(appContent(app), "\n")[0]
	for _, want := range []string{"Y Select off", "Q Quit"} {
		if !strings.Contains(firstLine, want) {
			t.Fatalf("copy-mode prefix bar missing %q:\n%s", want, firstLine)
		}
	}
	if strings.Contains(firstLine, "I Invite") {
		t.Fatalf("copy-mode prefix bar exposes invite action:\n%s", firstLine)
	}
}

func TestPrefixQuitOpensConfirmation(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X Q emitted command %+v before confirmation", cmd)
	}
	if !app.quitOpen {
		t.Fatalf("quitOpen = false, want true")
	}
	app.Update(keyCode(tea.KeyEnter))
	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("confirmed quit did not emit QuitCommand")
	}
}

func TestQuitConfirmationEnterWorksInCopyMode(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.copyMode = true
	app.openQuitConfirm()

	app.Update(keyCode(tea.KeyEnter))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("enter on quit confirmation in copy mode did not emit QuitCommand")
	}
}

func TestPrefixQuitWorksDuringApproval(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X Q emitted command %+v before confirmation", cmd)
	}
	if !app.quitOpen {
		t.Fatalf("quitOpen = false, want true")
	}
	if !app.approvalActive() {
		t.Fatalf("approval should remain active until shutdown resolves it")
	}
	app.Update(keyCode(tea.KeyEnter))
	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("confirmed quit did not emit QuitCommand")
	}
}

func TestPrefixQuitWorksDuringHelp(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("?"))

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("Ctrl-X Q emitted command %+v before confirmation", cmd)
	}
	if !app.quitOpen {
		t.Fatalf("quitOpen = false, want true")
	}
	app.Update(keyCode(tea.KeyEnter))
	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("confirmed quit did not emit QuitCommand")
	}
}

func TestPrefixQuitWorksDuringNotice(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(NoticeMsg{Title: "Shell exited", Body: "Press Ctrl-X Q to quit."})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("Ctrl-X Q during shell-exit quit confirm did not emit QuitCommand")
	}
}

func TestQuitConfirmationCancel(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("q"))
	app.Update(keyCode(tea.KeyRight))
	app.Update(keyCode(tea.KeyEnter))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("cancel emitted command %+v, want none", cmd)
	}
	if app.quitOpen {
		t.Fatalf("quit confirmation still open after cancel")
	}
}

func TestHelpOverlayCapturesPrintableKeys(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("?"))

	app.Update(textKey("a"))

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
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("k"))

	app.Update(textKey("x"))

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
