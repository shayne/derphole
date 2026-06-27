// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestApprovalKeysChangePendingGuest(t *testing.T) {
	m := NewModel(ModeHost, 100, 30)
	m.SetPendingGuest("guest-1", "Alex")
	m.HandleKey("r")
	if m.Decision().Role != protocol.RoleRead {
		t.Fatalf("Decision role = %q, want read", m.Decision().Role)
	}
	m.SetPendingGuest("guest-1", "Alex")
	m.HandleKey("w")
	if m.Decision().Role != protocol.RoleWrite {
		t.Fatalf("Decision role = %q, want write", m.Decision().Role)
	}
	m.SetPendingGuest("guest-1", "Alex")
	m.HandleKey("n")
	if got := m.Decision(); got.Accepted || got.Role != protocol.RoleDenied {
		t.Fatalf("Decision() = %+v, want denied", got)
	}
}

func TestHandleKeyMutatesModelInPlace(t *testing.T) {
	m := NewModel(ModeHost, 100, 30)
	m.SetPendingGuest("guest-1", "Alex")

	m.HandleKey("r")

	if got := m.Decision(); got.GuestID != "guest-1" || got.Role != protocol.RoleRead {
		t.Fatalf("Decision() = %+v, want guest-1 read", got)
	}
}

func TestViewShowsGuestSizeAndRole(t *testing.T) {
	m := NewModel(ModeGuest, 96, 28)
	m.SetRole(protocol.RoleRead)
	view := m.View()
	for _, want := range []string{"96x28", "read", "terminal", "sidechat", "status"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
}

func TestViewShowsSharedUISurface(t *testing.T) {
	m := NewModel(ModeHost, 100, 30)
	m.SetRole(protocol.RoleWrite)
	m.SetPeer("Alex", protocol.RoleRead)
	m.SetTransportStatus("connected-relay")
	m.SetInviteCommand("npx -y derpssh@latest connect DSH1test")
	m.SetTerminalText("ready\n")
	m.AddSidechatLine("Alex: hello")
	m.SetPendingGuest("guest-1", "Alex")

	view := m.View()
	for _, want := range []string{
		"npx -y derpssh@latest connect DSH1test",
		"terminal",
		"ready",
		"sidechat",
		"Alex: hello",
		"status",
		"connected-relay",
		"peer Alex/read",
		"[r]ead [w]rite [n]o",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
}
