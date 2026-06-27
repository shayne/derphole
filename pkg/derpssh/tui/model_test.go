// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestLegacyModelHandleKeyClearsApprovalModal(t *testing.T) {
	m := NewModel(ModeHost, 80, 24)
	m.SetPendingGuest("guest-1", "Alex")

	m.HandleKey("w")

	if got := m.Decision(); got.GuestID != "guest-1" || got.Role != protocol.RoleWrite {
		t.Fatalf("Decision() = %+v, want guest-1 write", got)
	}
	if m.app.approvalActive() {
		t.Fatalf("approval still active after legacy HandleKey")
	}
	if m.app.focus != FocusTerminal {
		t.Fatalf("focus = %v, want terminal", m.app.focus)
	}
	if view := m.View(); strings.Contains(view, "Approve Alex") || strings.Contains(view, "access request") {
		t.Fatalf("View() still renders approval modal:\n%s", view)
	}
}
