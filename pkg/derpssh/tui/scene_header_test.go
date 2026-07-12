// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestHeaderLayersExposeActionAndPeerTargets(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-2", Name: "Alex", Role: RoleRead}}})
	scene := app.buildScene()

	want := map[layerTarget]bool{
		actionTarget(ActionQuit):       false,
		actionTarget(ActionToggleChat): false,
		actionTarget(ActionShowMenu):   false,
		peerTarget("guest-2"):          false,
	}
	for x := 0; x < scene.Width; x++ {
		if target := scene.TargetAt(x, 0); target != "" {
			if _, ok := want[target]; ok {
				want[target] = true
			}
		}
	}
	for target, found := range want {
		if !found {
			t.Errorf("header target %q not found", target)
		}
	}
}

func TestPointerDispatchUsesHeaderActionTarget(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})

	app.Update(newPointerMsg(actionTarget(ActionToggleChat), clickAt(1, 5, tea.MouseLeft)))

	if !app.sidebarOpen {
		t.Fatal("sidebarOpen = false, want true after semantic toggle-chat target")
	}
}

func TestPointerDispatchUsesPeerIDTarget(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	app.Update(RuntimeStateMsg{Peers: []Peer{
		{ID: "guest-1", Name: "Alex", Role: RoleRead},
		{ID: "guest-2", Name: "Blair", Role: RoleWrite},
	}})

	app.Update(newPointerMsg(peerTarget("guest-2"), clickAt(1, 5, tea.MouseLeft)))

	if !app.peerDialogOpen || app.peerDialogPeer.ID != "guest-2" {
		t.Fatalf("peer dialog = %v, peer %q; want open for guest-2", app.peerDialogOpen, app.peerDialogPeer.ID)
	}
}

func TestRawMouseMessageDoesNotDispatchPointerAction(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionIDRect(t, app, ActionToggleChat)

	app.Update(clickAt(chat.X, chat.Y, tea.MouseLeft))

	if app.sidebarOpen {
		t.Fatal("raw Bubble Tea mouse message dispatched a second action")
	}
}
