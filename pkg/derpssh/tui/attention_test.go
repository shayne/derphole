// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
)

func TestDesktopNotificationSanitizesControlsAndBoundsPayload(t *testing.T) {
	cmd := desktopNotification("derpssh\x1b[31m\x07", strings.Repeat("danger\n", 80))
	if cmd == nil {
		t.Fatal("desktopNotification = nil")
	}
	raw, ok := cmd().(tea.RawMsg)
	if !ok {
		t.Fatalf("notification message = %T, want tea.RawMsg", cmd())
	}
	sequence := fmt.Sprint(raw.Msg)
	if !strings.HasPrefix(sequence, "\x1b]9;") || !strings.HasSuffix(sequence, "\x07") {
		t.Fatalf("notification sequence = %q, want OSC 9", sequence)
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(sequence, "\x1b]9;"), "\x07")
	if strings.ContainsAny(payload, "\x1b\x07\n\r") {
		t.Fatalf("notification payload contains controls: %q", payload)
	}
	if got := utf8.RuneCountInString(payload); got > notificationMaxRunes {
		t.Fatalf("notification runes = %d, want <= %d", got, notificationMaxRunes)
	}
}

func TestDesktopNotificationOmitsEmptyTitleSeparator(t *testing.T) {
	cmd := desktopNotification("", "message")
	if cmd == nil {
		t.Fatal("desktopNotification = nil")
	}
	raw := cmd().(tea.RawMsg)
	if got := fmt.Sprint(raw.Msg); got != "\x1b]9;message\x07" {
		t.Fatalf("notification = %q, want body without leading separator", got)
	}
}

func TestRemoteChatNotifiesOnlyWhileOuterTerminalIsBlurred(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)

	if _, cmd := app.Update(ChatMsg{Author: "Alex", Body: "focused"}); cmd != nil {
		t.Fatalf("focused chat notification = %T, want nil", cmd())
	}
	app.Update(tea.BlurMsg{})
	_, cmd := app.Update(ChatMsg{Author: "Alex", Body: "make test"})
	assertDesktopNotification(t, cmd, "Alex: make test")

	if _, cmd = app.Update(ChatMsg{Author: "you", Body: "local", Local: true}); cmd != nil {
		t.Fatalf("local chat notification = %T, want nil", cmd())
	}
	app.Update(tea.FocusMsg{})
	if _, cmd = app.Update(ChatMsg{Author: "Alex", Body: "focused again"}); cmd != nil {
		t.Fatalf("refocused chat notification = %T, want nil", cmd())
	}
}

func TestApprovalRequestNotifiesOnlyWhileOuterTerminalIsBlurred(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	if _, cmd := app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"}); cmd != nil {
		t.Fatalf("focused approval notification = %T, want nil", cmd())
	}

	app.applyApprovalRequest(ApprovalRequestMsg{})
	app.Update(tea.BlurMsg{})
	_, cmd := app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Blair"})
	assertDesktopNotification(t, cmd, "Blair wants to join")
}

func assertDesktopNotification(t *testing.T, cmd tea.Cmd, contains string) {
	t.Helper()
	if cmd == nil {
		t.Fatalf("desktop notification = nil, want %q", contains)
	}
	raw, ok := cmd().(tea.RawMsg)
	if !ok {
		t.Fatalf("desktop notification = %T, want tea.RawMsg", cmd())
	}
	if sequence := fmt.Sprint(raw.Msg); !strings.Contains(sequence, contains) {
		t.Fatalf("desktop notification = %q, want %q", sequence, contains)
	}
}
