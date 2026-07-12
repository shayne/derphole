// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestModalLayersCoverUnderlyingTargetsAndExposeButtons(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	scene := app.buildScene()

	read, write, deny := app.approvalButtonRects()
	for _, tc := range []struct {
		rect Rect
		want layerTarget
	}{
		{read, "approval:read"},
		{write, "approval:write"},
		{deny, "approval:deny"},
	} {
		if got := scene.TargetAt(tc.rect.X, tc.rect.Y); got != tc.want {
			t.Fatalf("TargetAt(%v) = %q, want %q", tc.rect, got, tc.want)
		}
	}
	if got := scene.TargetAt(0, 1); got != targetModalBlocker {
		t.Fatalf("outside modal target = %q, want blocker", got)
	}
}

func TestModalLayersExposeModalChoiceAndHelpActionTargets(t *testing.T) {
	t.Run("peer action", func(t *testing.T) {
		app := newModalSceneApp()
		app.openPeerDialog(Peer{ID: "guest-1", Name: "Alex", Role: RoleWrite})
		scene := app.buildScene()

		read, write, kick := app.peerActionButtonRects()
		assertSceneTargets(t, scene, []sceneTargetCase{
			{read, modalChoiceTarget(ModalPeerAction, "read")},
			{write, modalChoiceTarget(ModalPeerAction, "write")},
			{kick, modalChoiceTarget(ModalPeerAction, "kick")},
		})
		for _, want := range []string{"Read", "Write", "Kick"} {
			if !strings.Contains(scene.Content, want) {
				t.Fatalf("peer action modal missing %q:\n%s", want, scene.Content)
			}
		}
	})

	t.Run("quit", func(t *testing.T) {
		app := newModalSceneApp()
		app.openQuitConfirm()
		scene := app.buildScene()

		quit, cancel := app.quitButtonRects()
		assertSceneTargets(t, scene, []sceneTargetCase{
			{quit, modalChoiceTarget(ModalQuit, "quit")},
			{cancel, modalChoiceTarget(ModalQuit, "cancel")},
		})
	})

	t.Run("shell exit", func(t *testing.T) {
		app := newModalSceneApp()
		app.shellExitOpen = true
		scene := app.buildScene()

		restart, quit := app.shellExitButtonRects()
		assertSceneTargets(t, scene, []sceneTargetCase{
			{restart, modalChoiceTarget(ModalShellExit, "restart")},
			{quit, modalChoiceTarget(ModalShellExit, "quit")},
		})
	})

	t.Run("help", func(t *testing.T) {
		app := newModalSceneApp()
		app.helpOpen = true
		scene := app.buildScene()
		entries := app.menuEntries()
		if len(entries) == 0 {
			t.Fatal("menu entries = 0, want actions")
		}
		contentX, contentY := app.helpContentOrigin()
		if got, want := scene.TargetAt(contentX, contentY+2), actionTarget(entries[0].action); got != want {
			t.Fatalf("first help action target = %q, want %q", got, want)
		}
	})
}

func TestPointerDispatchUsesModalChoiceTarget(t *testing.T) {
	app := newModalSceneApp()
	drainCommands(app)
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	target := modalChoiceTarget(ModalApproval, "read")

	app.Update(newPointerMsg(target, clickAt(0, 0, tea.MouseLeft)))
	app.Update(newPointerMsg(target, releaseAt(0, 0, tea.MouseLeft)))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-1", Peer: "Alex", Role: RoleRead}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
}

func TestPointerDispatchRequiresMatchingModalChoiceRelease(t *testing.T) {
	app := newModalSceneApp()
	drainCommands(app)
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})

	app.Update(newPointerMsg(modalChoiceTarget(ModalApproval, "read"), clickAt(0, 0, tea.MouseLeft)))
	app.Update(newPointerMsg(modalChoiceTarget(ModalApproval, "write"), releaseAt(0, 0, tea.MouseLeft)))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("mismatched modal release emitted command %+v", cmd)
	}
	if !app.approvalActive() {
		t.Fatal("mismatched modal release closed approval")
	}
}

func TestPointerDispatchUsesHelpActionTarget(t *testing.T) {
	app := newModalSceneApp()
	app.helpOpen = true

	app.Update(newPointerMsg(actionTarget(ActionToggleChat), clickAt(0, 0, tea.MouseLeft)))

	if app.helpOpen {
		t.Fatal("helpOpen = true, want false after semantic menu action")
	}
	if !app.sidebarOpen {
		t.Fatal("sidebarOpen = false, want true after semantic menu action")
	}
}

func TestFrontModalCoversBackModalControls(t *testing.T) {
	app := newModalSceneApp()
	app.helpOpen = true
	contentX, contentY := app.helpContentOrigin()
	lastHelpActionY := contentY + 2 + len(app.menuEntries()) - 1
	app.noticeTitle = "Guest left"
	app.noticeBody = "guest quit"

	scene := app.buildScene()
	for _, want := range []string{"derpssh menu", "Guest left"} {
		if !strings.Contains(scene.Content, want) {
			t.Fatalf("stacked modal Scene missing %q:\n%s", want, scene.Content)
		}
	}
	if got, want := scene.TargetAt(contentX, lastHelpActionY), modalTarget(ModalNotice); got != want {
		t.Fatalf("back modal control target = %q, want %q", got, want)
	}
	front := app.modalStack().Front()
	bounds := modalBounds(ModalFrame{Width: app.width, Height: app.height, Styles: app.styles}, front.Lines())
	if got, want := scene.TargetAt(bounds.X, bounds.Y), modalTarget(ModalNotice); got != want {
		t.Fatalf("front modal panel target = %q, want %q", got, want)
	}
}

func TestFrontModalCompositorDropsCoveredBackControls(t *testing.T) {
	app := newModalSceneApp()
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	app.noticeTitle = "Guest left"
	app.noticeBody = "guest quit"

	scene := app.buildScene()
	if layer := scene.Compositor.GetLayer(string(modalChoiceTarget(ModalApproval, "read"))); layer != nil {
		t.Fatal("final compositor retained a fully covered approval control layer")
	}
}

func TestModalSceneRendersTerminalPaneOncePerView(t *testing.T) {
	pane := &countingViewPane{fakePane: fakePane{view: "shell$"}}
	app := NewApp(Options{Side: "host", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.openQuitConfirm()

	_ = app.View()
	if got := pane.calls; got != 1 {
		t.Fatalf("TerminalPane.View calls = %d, want 1", got)
	}
}

func TestModalSceneFillsInteriorBlankCells(t *testing.T) {
	app := newModalSceneApp()
	app.noticeTitle = "Guest left"
	app.noticeBody = "guest quit"
	scene := app.buildScene()

	dialog := app.modalStack().Front()
	bounds := modalBounds(ModalFrame{Width: app.width, Height: app.height, Styles: app.styles}, dialog.Lines())
	content := modalContentRect(bounds, app.styles)
	cell := scene.Canvas.CellAt(content.X+1, content.Y+2)
	if got, want := cell.Style.Bg, app.styles.ModalInterior.GetBackground(); !reflect.DeepEqual(got, want) {
		t.Fatalf("blank interior background = %v, want %v", got, want)
	}
}

type sceneTargetCase struct {
	rect Rect
	want layerTarget
}

func newModalSceneApp() *App {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return app
}

func assertSceneTargets(t *testing.T, scene Scene, cases []sceneTargetCase) {
	t.Helper()
	for _, tc := range cases {
		if got := scene.TargetAt(tc.rect.X, tc.rect.Y); got != tc.want {
			t.Fatalf("TargetAt(%v) = %q, want %q", tc.rect, got, tc.want)
		}
	}
}

type countingViewPane struct {
	fakePane
	calls int
}

func (p *countingViewPane) View(width int, height int) string {
	p.calls++
	return p.fakePane.View(width, height)
}
