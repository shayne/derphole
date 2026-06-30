// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHeaderPeerChipClickOpensPeerDialogForPeerID(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-2", Name: "Alex", Role: RoleRead}}})
	_ = app.View()

	peer := topBarActionRect(t, app, ActionManagePeer)
	app.Update(leftClick(peer.X+peer.W/2, peer.Y))

	if !app.peerDialogOpen {
		t.Fatal("peer dialog did not open")
	}
	if app.peerDialogPeer.ID != "guest-2" {
		t.Fatalf("peer dialog peer ID = %q, want guest-2", app.peerDialogPeer.ID)
	}
	view := app.View()
	for _, want := range []string{"Read", "Write", "Kick"} {
		if !strings.Contains(view, want) {
			t.Fatalf("peer dialog missing %q:\n%s", want, view)
		}
	}
}

func TestHeaderActionHitsCarryActionIDs(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	_ = app.View()

	_ = topBarActionIDRect(t, app, ActionToggleChat)
	_ = topBarActionIDRect(t, app, ActionQuit)
	_ = topBarActionIDRect(t, app, ActionShowMenu)
}

func TestHeaderHidesInviteActionForGuest(t *testing.T) {
	app := NewApp(Options{Side: "guest", InviteCommand: "npx -y derpssh@latest connect DSH1", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	app.helpOpen = true

	if view := app.View(); strings.Contains(view, "Show Invite") {
		t.Fatalf("guest header menu exposes invite action:\n%s", view)
	}
}

func topBarActionIDRect(t *testing.T, app *App, action ActionID) Rect {
	t.Helper()
	for _, hit := range app.topBarHits {
		if hit.action == action {
			return hit.rect
		}
	}
	t.Fatalf("top-bar action %q not found in hits %+v", action, app.topBarHits)
	return Rect{}
}
