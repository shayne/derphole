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

func TestActionRegistryRunsVisibleAction(t *testing.T) {
	reg := NewActionRegistry()
	app := NewApp(Options{
		Side:     "host",
		Terminal: &fakePane{view: "ok"},
	})

	cmd, ok := reg.Run(app, ActionToggleChat)

	if !ok {
		t.Fatalf("Run(ActionToggleChat) ok = false, want true")
	}
	if cmd != nil {
		t.Fatalf("Run(ActionToggleChat) cmd = %+v, want nil", cmd)
	}
	if !app.sidebarOpen {
		t.Fatalf("Run(ActionToggleChat) did not open sidebar")
	}
}

func TestActionRegistryDoesNotRunHiddenAction(t *testing.T) {
	reg := NewActionRegistry()
	app := NewApp(Options{
		Side:          "guest",
		InviteCommand: "npx -y derpssh@latest connect DSH1copyme",
		Terminal:      &fakePane{view: "ok"},
	})

	cmd, ok := reg.Run(app, ActionShowInvite)

	if ok {
		t.Fatalf("Run(ActionShowInvite) ok = true for guest, want false")
	}
	if cmd != nil {
		t.Fatalf("Run(ActionShowInvite) cmd = %+v, want nil", cmd)
	}
	if app.inviteOpen {
		t.Fatalf("Run(ActionShowInvite) opened hidden guest invite")
	}
}

func TestMenuEntriesCarryActionIDs(t *testing.T) {
	app := NewApp(Options{
		Side:          "host",
		InviteCommand: "npx -y derpssh@latest connect DSH1copyme",
		Terminal:      &fakePane{view: "ok"},
	})

	entries := app.menuEntries()
	entry, ok := findMenuEntry(entries, "Show Invite")
	if !ok {
		t.Fatalf("menu entries missing Show Invite action: %+v", entries)
	}
	if entry.action != ActionShowInvite {
		t.Fatalf("Show Invite action = %q, want %q", entry.action, ActionShowInvite)
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

func findMenuEntry(entries []menuEntry, label string) (menuEntry, bool) {
	for _, entry := range entries {
		if entry.label == label {
			return entry, true
		}
	}
	return menuEntry{}, false
}
