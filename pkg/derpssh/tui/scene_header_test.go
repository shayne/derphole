// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"reflect"
	"strings"
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

func TestHeaderPackingKeepsRightActionsAtTerminalWidth(t *testing.T) {
	for _, width := range []int{56, 80, 120} {
		t.Run(fmt.Sprintf("%d_columns", width), func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: width, Height: 20})
			scene := app.buildScene()
			firstLine := strings.Split(scene.Content, "\n")[0]

			if got := displayWidth(firstLine); got != width {
				t.Fatalf("top-bar display width = %d, want %d", got, width)
			}
			for _, target := range []layerTarget{
				actionTarget(ActionToggleChat),
				actionTarget(ActionShowMenu),
				actionTarget(ActionQuit),
			} {
				found := false
				for x := 0; x < scene.Width; x++ {
					if scene.TargetAt(x, 0) == target {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("header target %q not found at width %d", target, width)
				}
			}
		})
	}
}

func TestHeaderPackingReservesBrandAndFixedControlsBeforeTransientHints(t *testing.T) {
	app := NewApp(Options{
		Side:          "host",
		DisplayName:   "host-with-a-very-long-display-name",
		InviteCommand: "derpssh connect DSH1secret",
		Terminal:      &fakePane{view: "ok"},
	})
	app.Update(tea.WindowSizeMsg{Width: 56, Height: 20})
	app.Update(RuntimeStateMsg{
		Transport: "connected-direct",
		HostCols:  160,
		HostRows:  50,
		LocalRole: RoleWrite,
		Peers:     []Peer{{ID: "guest-1", Name: "peer-with-a-long-name", Role: RoleRead}},
	})
	app.prefix = true

	scene := app.buildScene()
	firstLine := strings.Split(scene.Content, "\n")[0]
	plain := ansiPattern.ReplaceAllString(firstLine, "")
	if got := displayWidth(firstLine); got != 56 {
		t.Fatalf("top-bar display width = %d, want 56", got)
	}
	for _, essential := range []string{"◆ derpssh", "◈ Chat", "⋮", "×"} {
		if !strings.Contains(plain, essential) {
			t.Fatalf("56-column top bar missing essential %q: %q", essential, plain)
		}
	}
	for _, target := range []layerTarget{
		actionTarget(ActionToggleChat),
		actionTarget(ActionShowMenu),
		actionTarget(ActionQuit),
	} {
		found := false
		for x := 0; x < scene.Width; x++ {
			if scene.TargetAt(x, 0) == target {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("56-column top bar missing fixed target %q", target)
		}
	}
	if strings.Contains(plain, "I Invite") {
		t.Fatalf("56-column top bar retained transient invite hint before essentials: %q", plain)
	}
}

func TestHeaderSegmentStyleShowsUnreadChatHover(t *testing.T) {
	for _, tt := range []struct {
		name  string
		pulse bool
	}{
		{name: "warning", pulse: false},
		{name: "pulse", pulse: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
			app.unreadChat = 1
			app.unreadPulse = tt.pulse
			segment := app.chatTopBarSegments()[0]
			target := actionTarget(ActionToggleChat)
			app.hoverTarget = target

			got := app.headerSegmentStyle(segment, target)
			if !reflect.DeepEqual(got.GetBackground(), app.styles.TopBarHover.GetBackground()) {
				t.Fatalf("hovered unread background = %v, want hover %v", got.GetBackground(), app.styles.TopBarHover.GetBackground())
			}
			if reflect.DeepEqual(got.GetBackground(), segment.style.GetBackground()) {
				t.Fatalf("hovered unread background remained unchanged at %v", got.GetBackground())
			}
		})
	}
}

func TestHeaderSegmentStyleShowsOpenChatAndPeerHover(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.sidebarOpen = true
	app.peers = []Peer{{ID: "guest-1", Name: "Alex", Role: RoleWrite}}
	for _, segment := range []topBarSegment{app.chatTopBarSegments()[0], app.peerTopBarSegments()[0]} {
		target := headerSegmentTarget(segment)
		app.hoverTarget = target
		got := app.headerSegmentStyle(segment, target)
		if !reflect.DeepEqual(got.GetBackground(), app.styles.TopBarHover.GetBackground()) {
			t.Fatalf("hovered %q background = %v, want %v", segment.text, got.GetBackground(), app.styles.TopBarHover.GetBackground())
		}
		if reflect.DeepEqual(got.GetBackground(), segment.style.GetBackground()) {
			t.Fatalf("hovered %q retained resting background %v", segment.text, got.GetBackground())
		}
	}
}

func TestHeaderSegmentStylePreservesPrefixHintStyleWhenHovered(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.prefix = true
	segment := app.actionTopBarSegments()[0]
	target := headerSegmentTarget(segment)
	app.hoverTarget = target

	got := app.headerSegmentStyle(segment, target).Render(segment.text)
	want := segment.style.Render(segment.text)
	if got != want {
		t.Fatalf("hovered prefix style = %q, want %q", got, want)
	}
}

func TestPointerDispatchUsesHeaderActionTarget(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})

	app.Update(newPointerMsg(actionTarget(ActionToggleChat), clickAt(1, 5, tea.MouseLeft)))
	app.Update(newPointerMsg(actionTarget(ActionToggleChat), releaseAt(1, 5, tea.MouseLeft)))

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
	app.Update(newPointerMsg(peerTarget("guest-2"), releaseAt(1, 5, tea.MouseLeft)))

	if !app.peerDialogOpen || app.peerDialogPeer.ID != "guest-2" {
		t.Fatalf("peer dialog = %v, peer %q; want open for guest-2", app.peerDialogOpen, app.peerDialogPeer.ID)
	}
}

func TestRawMouseMessageDispatchesHeaderAction(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionIDRect(t, app, ActionToggleChat)

	app.Update(clickAt(chat.X, chat.Y, tea.MouseLeft))
	app.Update(releaseAt(chat.X, chat.Y, tea.MouseLeft))

	if !app.sidebarOpen {
		t.Fatal("sidebarOpen = false, want true after raw toggle-chat click")
	}
}
