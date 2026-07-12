// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestHeaderPeerChipClickOpensPeerDialogForPeerID(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-2", Name: "Alex", Role: RoleRead}}})
	_ = appContent(app)

	peer := topBarPeerRect(t, app, "guest-2")
	dispatchViewMouse(t, app, leftClick(peer.X+peer.W/2, peer.Y))

	if !app.peerDialogOpen {
		t.Fatal("peer dialog did not open")
	}
	if app.peerDialogPeer.ID != "guest-2" {
		t.Fatalf("peer dialog peer ID = %q, want guest-2", app.peerDialogPeer.ID)
	}
}

func TestHeaderActionHitsCarryActionIDs(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	_ = appContent(app)

	_ = topBarActionIDRect(t, app, ActionToggleChat)
	_ = topBarActionIDRect(t, app, ActionQuit)
	_ = topBarActionIDRect(t, app, ActionShowMenu)
}

func TestHeaderHidesInviteActionForGuest(t *testing.T) {
	app := NewApp(Options{Side: "guest", InviteCommand: "npx -y derpssh@latest connect DSH1", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	app.helpOpen = true

	if view := appContent(app); strings.Contains(view, "Show Invite") {
		t.Fatalf("guest header menu exposes invite action:\n%s", view)
	}
}

func topBarActionIDRect(t *testing.T, app *App, action ActionID) Rect {
	t.Helper()
	scene := app.buildScene()
	target := actionTarget(action)
	start := -1
	for x := 0; x < scene.Width; x++ {
		if scene.TargetAt(x, 0) == target {
			if start < 0 {
				start = x
			}
			continue
		}
		if start >= 0 {
			return Rect{X: start, Y: 0, W: x - start, H: 1}
		}
	}
	if start >= 0 {
		return Rect{X: start, Y: 0, W: scene.Width - start, H: 1}
	}
	t.Fatalf("top-bar action target %q not found", target)
	return Rect{}
}
