// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestMouseClickTopBarChatToggle(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	chat := topBarActionRect(t, app, ActionToggleChat)

	dispatchMouse(t, app, leftClick(chat.X+chat.W/2, chat.Y))

	if !app.sidebarOpen {
		t.Fatalf("sidebarOpen = false, want true after top-bar chat click")
	}
	if app.focus != FocusChat {
		t.Fatalf("focus = %v, want chat after top-bar chat click", app.focus)
	}
	if !app.composer.Focused() {
		t.Fatalf("composer focus = false, want true after top-bar chat click")
	}
	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 66, Rows: 29}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}

	dispatchMouse(t, app, leftClick(chat.X+chat.W/2, chat.Y))

	if app.sidebarOpen {
		t.Fatalf("sidebarOpen = true, want false after second top-bar chat click")
	}
	if app.focus != FocusTerminal {
		t.Fatalf("focus = %v, want terminal after top-bar chat close", app.focus)
	}
}

func TestMouseClickTopBarQuitOpensConfirmation(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	quit := topBarActionRect(t, app, ActionQuit)

	dispatchMouse(t, app, leftClick(quit.X+quit.W/2, quit.Y))

	if !app.quitOpen {
		t.Fatalf("quitOpen = false, want true after top-bar X click")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("top-bar X emitted command before confirmation: %+v", cmd)
	}
}

func TestMouseClickPeerTopBarOpensPeerDialog(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	app.Update(RuntimeStateMsg{Peers: []Peer{
		{ID: "guest-1", Name: "Alex", Role: RoleRead},
		{ID: "guest-2", Name: "Blair", Role: RoleWrite},
	}})
	drainCommands(app)
	peer := topBarPeerRect(t, app, "guest-2")

	dispatchMouse(t, app, leftClick(peer.X+peer.W/2, peer.Y))

	if !app.peerDialogOpen {
		t.Fatal("peer dialog did not open after clicking peer chip")
	}
	if app.peerDialogPeer.ID != "guest-2" {
		t.Fatalf("peer dialog peer ID = %q, want guest-2", app.peerDialogPeer.ID)
	}
	if app.peerDialogChoice != peerActionWrite {
		t.Fatalf("peer dialog choice = %v, want peerActionWrite", app.peerDialogChoice)
	}
}

func TestMouseClickPeerDialogReadChangesClickedPeer(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	app.Update(RuntimeStateMsg{Peers: []Peer{
		{ID: "guest-1", Name: "Alex", Role: RoleWrite},
		{ID: "guest-2", Name: "Blair", Role: RoleWrite},
	}})
	drainCommands(app)
	peer := topBarPeerRect(t, app, "guest-2")
	dispatchMouse(t, app, leftClick(peer.X+peer.W/2, peer.Y))
	read, _, _ := app.peerActionButtonRects()

	dispatchMouse(t, app, leftClick(read.X+read.W/2, read.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("peer dialog press emitted command %+v, want none until release", cmd)
	}

	dispatchMouse(t, app, leftRelease(read.X+read.W/2, read.Y))

	got, ok := readCommand(app).(RoleChangeCommand)
	if !ok {
		t.Fatalf("command = %T, want RoleChangeCommand", got)
	}
	want := RoleChangeCommand{PeerID: "guest-2", Peer: "Blair", Role: RoleRead}
	if got != want {
		t.Fatalf("role command = %+v, want %+v", got, want)
	}
}

func TestMouseClickQuitConfirmationButtons(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.openQuitConfirm()
	quit, _ := app.quitButtonRects()

	dispatchMouse(t, app, leftClick(quit.X+quit.W/2, quit.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("quit confirmation press emitted command %+v, want none until release", cmd)
	}

	dispatchMouse(t, app, leftRelease(quit.X+quit.W/2, quit.Y))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("quit confirmation click did not emit QuitCommand")
	}
}

func TestMouseQuitPressDoesNotSurviveKeyboardClose(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.openQuitConfirm()
	quit, _ := app.quitButtonRects()

	dispatchMouse(t, app, leftClick(quit.X+quit.W/2, quit.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("quit confirmation press emitted command %+v, want none until release", cmd)
	}

	app.Update(keyCode(tea.KeyEsc))
	if app.quitOpen {
		t.Fatal("quit confirmation still open after Esc")
	}

	app.openQuitConfirm()
	quit, _ = app.quitButtonRects()
	dispatchMouse(t, app, leftRelease(quit.X+quit.W/2, quit.Y))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("stale mouse release emitted command %+v, want none without fresh press", cmd)
	}
}

func TestMouseClickQuitConfirmationWorksInCopyMode(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true
	app.openQuitConfirm()
	quit, _ := app.quitButtonRects()

	dispatchMouse(t, app, leftClick(quit.X+quit.W/2, quit.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("quit confirmation press in copy mode emitted command %+v, want none until release", cmd)
	}

	dispatchMouse(t, app, leftRelease(quit.X+quit.W/2, quit.Y))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("quit confirmation click in copy mode did not emit QuitCommand")
	}
}

func TestSelectionModeClickOutsideTerminalRestoresMouse(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true

	_, cmd := app.Update(leftClick(0, 0))

	if app.copyMode {
		t.Fatalf("copyMode = true, want false after click outside terminal")
	}
	if cmd != nil {
		t.Fatalf("click outside selection mode command = %T, want nil", cmd)
	}
	if got := app.View().MouseMode; got != tea.MouseModeCellMotion {
		t.Fatalf("mouse mode after click = %v, want cell motion", got)
	}
}

func TestSelectionModeTerminalClickDoesNotForwardMouse(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true

	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+1, app.layout.Terminal.Y+1))

	if !app.copyMode {
		t.Fatalf("copyMode = false, want true after terminal-area selection click")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("selection-mode terminal click emitted command %+v, want none", cmd)
	}
}

func TestSelectionModeUsesSemanticTerminalTarget(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true

	for _, event := range []tea.MouseMsg{
		leftClick(0, 0),
		tea.MouseMotionMsg{X: 0, Y: 0, Button: tea.MouseLeft},
		leftRelease(0, 0),
	} {
		app.Update(newPointerMsg(targetTerminal, event))
	}

	if !app.copyMode {
		t.Fatal("copyMode = false after terminal-target selection sequence")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("terminal-target selection sequence emitted command %+v, want none", cmd)
	}
}

func TestSelectionModeRejectsNonterminalTargetAtTerminalCoordinates(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	app.copyMode = true
	terminal := app.layout.Terminal

	app.Update(newPointerMsg(targetSidebar, leftClick(terminal.X+1, terminal.Y+1)))

	if app.copyMode {
		t.Fatal("copyMode = true after nonterminal semantic target")
	}
}

func TestMouseClickShellExitQuitCommitsOnRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.shellExitOpen = true
	app.shellExitChoice = shellExitChoiceQuit
	_, quit := app.shellExitButtonRects()

	dispatchMouse(t, app, leftClick(quit.X+quit.W/2, quit.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("shell-exit quit press emitted command %+v, want none until release", cmd)
	}

	dispatchMouse(t, app, leftRelease(quit.X+quit.W/2, quit.Y))

	if _, ok := readCommand(app).(QuitCommand); !ok {
		t.Fatalf("shell-exit quit release did not emit QuitCommand")
	}
}

func TestMouseMenuShowsHostInvite(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "npx -y derpssh@latest connect DSH1copyme", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	menu := topBarActionRect(t, app, ActionShowMenu)

	dispatchMouse(t, app, leftClick(menu.X+menu.W/2, menu.Y))

	if !strings.Contains(appContent(app), "Show Invite") || !strings.Contains(appContent(app), "Ctrl-X I") {
		t.Fatalf("menu missing invite action:\n%s", appContent(app))
	}
}

func TestMouseClickFocusesTerminalAndChat(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	drainCommands(app)

	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+1, app.layout.Terminal.Y+1))
	if app.focus != FocusTerminal {
		t.Fatalf("focus after terminal click = %v, want terminal", app.focus)
	}

	dispatchMouse(t, app, leftClick(app.layout.Composer.X+1, app.layout.Composer.Y))
	if app.focus != FocusChat {
		t.Fatalf("focus after composer click = %v, want chat", app.focus)
	}
}

func TestMouseDragDividerResizesChat(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	drainCommands(app)
	start := app.layout.Divider.X

	dispatchMouse(t, app, leftClick(start, app.layout.Divider.Y+2))
	dispatchMouse(t, app, tea.MouseMotionMsg{X: 70, Y: app.layout.Divider.Y + 2, Button: tea.MouseLeft})
	dispatchMouse(t, app, releaseAt(70, app.layout.Divider.Y+2, tea.MouseLeft))

	if app.layout.Sidebar.W != 49 {
		t.Fatalf("Sidebar.W = %d, want 49 after dragging divider", app.layout.Sidebar.W)
	}
	if !app.sidebarOpen {
		t.Fatalf("sidebarOpen = false after divider drag")
	}
}

func TestMouseDragDividerRepaintsTerminalDuringMotion(t *testing.T) {
	pane := &recordingViewPane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	drainCommands(app)
	start := app.layout.Divider.X

	_ = appContent(app)
	initialWidth := pane.lastViewWidth()
	dispatchMouse(t, app, leftClick(start, app.layout.Divider.Y+2))
	dispatchMouse(t, app, tea.MouseMotionMsg{X: 70, Y: app.layout.Divider.Y + 2, Button: tea.MouseLeft})
	_ = appContent(app)

	if got := pane.lastViewWidth(); got == initialWidth {
		t.Fatalf("terminal view width did not change during divider drag: got %d", got)
	}
	if got := pane.lastViewWidth(); got != app.layout.Terminal.W {
		t.Fatalf("terminal view width = %d, want current layout width %d", got, app.layout.Terminal.W)
	}
}

func TestRawMouseExactDividerPressCapturesSynchronously(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider

	app.Update(clickAt(divider.X, divider.Y+1, tea.MouseLeft))

	if app.pointerCapture != targetDivider || !app.draggingDivider {
		t.Fatalf("capture, dragging = %q, %v; want divider, true", app.pointerCapture, app.draggingDivider)
	}
}

func TestViewDoesNotAsynchronouslyForwardMouseEvents(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	view := app.View()

	if view.OnMouse != nil {
		t.Fatal("View().OnMouse is non-nil; raw mouse events must be ordered through Update")
	}
}

func TestViewDoesNotMutatePointerCapture(t *testing.T) {
	for _, tc := range []struct {
		name          string
		configure     func(*App)
		wantMouseMode tea.MouseMode
	}{
		{
			name: "copy mode",
			configure: func(app *App) {
				app.copyMode = true
			},
			wantMouseMode: tea.MouseModeNone,
		},
		{
			name: "modal",
			configure: func(app *App) {
				app.quitOpen = true
			},
			wantMouseMode: tea.MouseModeCellMotion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
			app.pointerCapture = targetDivider
			app.draggingDivider = true
			tc.configure(app)

			view := app.View()

			if view.MouseMode != tc.wantMouseMode {
				t.Fatalf("MouseMode = %v, want %v", view.MouseMode, tc.wantMouseMode)
			}
			if app.pointerCapture != targetDivider || !app.draggingDivider {
				t.Fatalf("capture, dragging after View = %q, %v; want divider, true", app.pointerCapture, app.draggingDivider)
			}
		})
	}
}

func TestRawMouseDividerHitAreaRemainsExactlyOneCell(t *testing.T) {
	for _, tc := range []struct {
		name string
		dx   int
	}{
		{name: "terminal neighbor", dx: -1},
		{name: "sidebar neighbor", dx: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
			app.setSidebarOpen(true)
			divider := app.layout.Divider

			app.Update(clickAt(divider.X+tc.dx, divider.Y+1, tea.MouseLeft))

			if app.pointerCapture == targetDivider || app.draggingDivider {
				t.Fatalf("neighbor dx %d captured divider", tc.dx)
			}
		})
	}
}

func TestRawMouseUsesRenderedLayerAndCapturesDividerDrag(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider

	dispatchMouse(t, app, clickAt(divider.X, divider.Y+1, tea.MouseLeft))
	if app.pointerCapture != targetDivider {
		t.Fatalf("capture = %q, want divider", app.pointerCapture)
	}
	dispatchMouse(t, app, tea.MouseMotionMsg{X: divider.X - 8, Y: divider.Y + 2, Button: tea.MouseLeft})
	dispatchMouse(t, app, releaseAt(divider.X-8, divider.Y+2, tea.MouseLeft))
	if app.pointerCapture != "" {
		t.Fatalf("capture after release = %q, want empty", app.pointerCapture)
	}
}

func TestPointerCaptureClearsWhenModalOpens(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider
	dispatchMouse(t, app, clickAt(divider.X, divider.Y+1, tea.MouseLeft))

	app.openQuitConfirm()

	if app.pointerCapture != "" || app.draggingDivider {
		t.Fatalf("capture, dragging = %q, %v; want cleared when modal opens", app.pointerCapture, app.draggingDivider)
	}
}

func TestPointerCaptureClearsWhenMouseModeDisabled(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	divider := app.layout.Divider
	dispatchMouse(t, app, clickAt(divider.X, divider.Y+1, tea.MouseLeft))

	app.setCopyMode(true)

	if app.pointerCapture != "" || app.draggingDivider {
		t.Fatalf("capture, dragging = %q, %v; want cleared when mouse mode is disabled", app.pointerCapture, app.draggingDivider)
	}
}

func TestMouseClickApprovalButtons(t *testing.T) {
	tests := []struct {
		name string
		pick func(read Rect, write Rect, deny Rect) Rect
		want ApprovalDecisionCommand
	}{
		{name: "read", pick: func(read Rect, write Rect, deny Rect) Rect { return read }, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleRead}},
		{name: "write", pick: func(read Rect, write Rect, deny Rect) Rect { return write }, want: ApprovalDecisionCommand{Peer: "Alex", Role: RoleWrite}},
		{name: "deny", pick: func(read Rect, write Rect, deny Rect) Rect { return deny }, want: ApprovalDecisionCommand{Peer: "Alex", Deny: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			app.Update(ApprovalRequestMsg{Peer: "Alex"})
			read, write, deny := app.approvalButtonRects()
			button := tt.pick(read, write, deny)

			dispatchMouse(t, app, leftClick(button.X+button.W/2, button.Y))
			if cmd := readCommand(app); cmd != nil {
				t.Fatalf("approval press emitted command %+v, want none until release", cmd)
			}

			dispatchMouse(t, app, leftRelease(button.X+button.W/2, button.Y))

			got, ok := readCommand(app).(ApprovalDecisionCommand)
			if !ok {
				t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
			}
			if got != tt.want {
				t.Fatalf("approval command = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMouseDuringApprovalDoesNotReachTerminalOrChangeFocus(t *testing.T) {
	pane := &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}
	app := NewApp(Options{Side: "host", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.Update(ApprovalRequestMsg{Peer: "Alex"})

	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("approval terminal click emitted command %+v, want none", cmd)
	}
	if app.focus != FocusApproval {
		t.Fatalf("focus = %v, want approval", app.focus)
	}
}

func TestHostApprovalClickAtDisplayedWriteButtonRendersDeclaratively(t *testing.T) {
	pane := &fakePane{view: "ubuntu@host:~$ ", mouse: MouseMode{Enabled: true, SGR: true}}
	app := NewApp(Options{Side: "host", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 101, Height: 30})
	drainCommands(app)
	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "shayne@m5mbp"})

	_, write, _ := app.approvalButtonRects()
	x := write.X + write.W/2
	y := write.Y

	dispatchMouse(t, app, leftClick(x, y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("approval press emitted command %+v, want none until release", cmd)
	}

	_, repaint := app.Update(leftRelease(x, y))
	if repaint != nil {
		t.Fatalf("approval release returned command %T, want declarative render", repaint())
	}
	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-1", Peer: "shayne@m5mbp", Role: RoleWrite}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
	view := appContent(app)
	for _, stale := range []string{"wants to join", "Select access"} {
		if strings.Contains(view, stale) {
			t.Fatalf("view contains stale approval text %q after approval:\n%s", stale, view)
		}
	}

	app.Update(textKey("l"))
	keyCmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("post-approval key command = %T, want TerminalInputCommand", keyCmd)
	}
	if string(keyCmd.Data) != "l" {
		t.Fatalf("post-approval key data = %q, want l", keyCmd.Data)
	}
}

func TestPassiveModalMouseDoesNotReachTerminal(t *testing.T) {
	pane := &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}
	app := NewApp(Options{Side: "guest", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 101, Height: 30})
	drainCommands(app)
	app.Update(RuntimeStateMsg{Transport: "direct", HostCols: 101, HostRows: 29, LocalRole: RolePending})

	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+50, app.layout.Terminal.Y+16))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("passive modal mouse emitted command %+v, want none", cmd)
	}
}

func TestApprovalDecisionIncludesPeerIDForDuplicateNames(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Alex"})
	read, _, _ := app.approvalButtonRects()

	dispatchMouse(t, app, leftClick(read.X+read.W/2, read.Y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("approval press emitted command %+v, want none until release", cmd)
	}

	dispatchMouse(t, app, leftRelease(read.X+read.W/2, read.Y))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
}

func TestTerminalMouseOnlyForwardsWhenEnabled(t *testing.T) {
	pane := &fakePane{view: "ok"}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)

	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("mouse with disabled terminal mode emitted %+v, want none", cmd)
	}

	pane.mouse = MouseMode{Enabled: true, SGR: true}
	dispatchMouse(t, app, leftClick(app.layout.Terminal.X+4, app.layout.Terminal.Y+2))
	cmd, ok := readCommand(app).(TerminalInputCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalInputCommand", cmd)
	}
	seq := string(cmd.Data)
	if !strings.HasPrefix(seq, "\x1b[<0;") || !strings.HasSuffix(seq, "M") {
		t.Fatalf("mouse sequence = %q, want SGR button press", seq)
	}
}

func TestEncodeSGRMouseMapsButtons(t *testing.T) {
	tests := []struct {
		name   string
		button tea.MouseButton
		want   string
	}{
		{name: "left", button: tea.MouseLeft, want: "\x1b[<0;3;4M"},
		{name: "middle", button: tea.MouseMiddle, want: "\x1b[<1;3;4M"},
		{name: "right", button: tea.MouseRight, want: "\x1b[<2;3;4M"},
		{name: "wheel up", button: tea.MouseWheelUp, want: "\x1b[<64;3;4M"},
		{name: "wheel down", button: tea.MouseWheelDown, want: "\x1b[<65;3;4M"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var event tea.MouseMsg = clickAt(2, 4, tt.button)
			if tt.button == tea.MouseWheelUp || tt.button == tea.MouseWheelDown {
				event = tea.MouseWheelMsg{X: 2, Y: 4, Button: tt.button}
			}
			got, ok := EncodeSGRMouse(event, Rect{X: 0, Y: 1, W: 20, H: 10})
			if !ok || string(got) != tt.want {
				t.Fatalf("EncodeSGRMouse() = %q, %v; want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestEncodeSGRMouseReleaseWithoutButtonPreservesModifier(t *testing.T) {
	msg := tea.MouseReleaseMsg{X: 3, Y: 4, Button: tea.MouseNone, Mod: tea.ModCtrl}
	got, ok := EncodeSGRMouse(msg, Rect{X: 0, Y: 1, W: 20, H: 10})
	if !ok || string(got) != "\x1b[<16;4;4m" {
		t.Fatalf("EncodeSGRMouse() = %q, %v, want ctrl-release sequence", got, ok)
	}
}

func TestEncodeSGRMouseRejectsUnknownClickButton(t *testing.T) {
	if got, ok := EncodeSGRMouse(clickAt(0, 1, tea.MouseNone), Rect{W: 20, H: 10}); ok || got != nil {
		t.Fatalf("EncodeSGRMouse() = %q, %v; want nil, false", got, ok)
	}
}

func TestEncodeSGRMousePreservesCtrlModifier(t *testing.T) {
	msg := tea.MouseClickMsg{X: 3, Y: 4, Button: tea.MouseLeft, Mod: tea.ModCtrl}
	got, ok := EncodeSGRMouse(msg, Rect{X: 0, Y: 1, W: 20, H: 10})
	if !ok || string(got) != "\x1b[<16;4;4M" {
		t.Fatalf("EncodeSGRMouse() = %q, %v, want ctrl-left sequence", got, ok)
	}
}

func TestEncodeSGRMousePreservesShiftAndAltModifiers(t *testing.T) {
	msg := tea.MouseClickMsg{X: 3, Y: 4, Button: tea.MouseLeft, Mod: tea.ModShift | tea.ModAlt}
	got, ok := EncodeSGRMouse(msg, Rect{X: 0, Y: 1, W: 20, H: 10})
	if !ok || string(got) != "\x1b[<12;4;4M" {
		t.Fatalf("EncodeSGRMouse() = %q, %v, want shift-alt-left sequence", got, ok)
	}
}

func dispatchMouse(t *testing.T, app *App, msg tea.MouseMsg) {
	t.Helper()
	app.Update(msg)
}

func leftClick(x int, y int) tea.MouseClickMsg {
	return clickAt(x, y, tea.MouseLeft)
}

func leftRelease(x int, y int) tea.MouseReleaseMsg {
	return releaseAt(x, y, tea.MouseLeft)
}

type recordingViewPane struct {
	fakePane
	viewWidths []int
}

func (p *recordingViewPane) View(width int, height int) string {
	p.viewWidths = append(p.viewWidths, width)
	return p.fakePane.View(width, height)
}

func (p *recordingViewPane) lastViewWidth() int {
	if len(p.viewWidths) == 0 {
		return 0
	}
	return p.viewWidths[len(p.viewWidths)-1]
}

func topBarActionRect(t *testing.T, app *App, action ActionID) Rect {
	t.Helper()
	return topBarTargetRect(t, app, actionTarget(action))
}

func topBarPeerRect(t *testing.T, app *App, peerID string) Rect {
	t.Helper()
	return topBarTargetRect(t, app, peerTarget(peerID))
}

func topBarTargetRect(t *testing.T, app *App, target layerTarget) Rect {
	t.Helper()
	scene := app.buildScene()
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
	t.Fatalf("missing top-bar target %q", target)
	return Rect{}
}

func drainCommands(app *App) {
	for {
		if cmd := readCommand(app); cmd == nil {
			return
		}
	}
}
