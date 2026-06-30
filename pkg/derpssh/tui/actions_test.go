// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "testing"

func TestActionRegistryHidesHostOnlyInviteForGuest(t *testing.T) {
	reg := NewActionRegistry()
	ctx := ActionContext{Mode: ModeGuest, HasInvite: true}

	actions := reg.Visible(ctx)
	if hasAction(actions, ActionShowInvite) {
		t.Fatalf("guest must not see invite action")
	}
}

func TestActionRegistryShowsPeerActionsOnlyForHostWithPeers(t *testing.T) {
	reg := NewActionRegistry()
	guest := reg.Visible(ActionContext{Mode: ModeGuest, HasPeers: true})
	for _, id := range []ActionID{ActionGrantRead, ActionGrantWrite, ActionKickPeer} {
		if hasAction(guest, id) {
			t.Fatalf("guest visible actions include host peer action %s", id)
		}
	}

	host := reg.Visible(ActionContext{Mode: ModeHost, HasPeers: true})
	for _, id := range []ActionID{ActionGrantRead, ActionGrantWrite, ActionKickPeer} {
		if !hasAction(host, id) {
			t.Fatalf("host visible actions missing peer action %s", id)
		}
	}
}

func hasAction(actions []Action, id ActionID) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}
