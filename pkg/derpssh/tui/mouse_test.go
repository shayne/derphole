// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

func TestMouseHoverTracksSemanticTopBarTarget(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionRect(t, app, ActionToggleChat)

	app.Update(tea.MouseMotionMsg{X: chat.X, Y: chat.Y})
	if app.hoverTarget != actionTarget(ActionToggleChat) {
		t.Fatalf("hover = %q, want chat target", app.hoverTarget)
	}
	app.Update(tea.MouseMotionMsg{X: app.layout.Terminal.X, Y: app.layout.Terminal.Y})
	if app.hoverTarget != "" {
		t.Fatalf("hover = %q after leaving chrome, want empty", app.hoverTarget)
	}
}

func TestMousePointerShapeFollowsSemanticSurface(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)

	app.Update(tea.MouseMotionMsg{X: app.layout.Terminal.X + 1, Y: app.layout.Terminal.Y + 1})
	if app.pointerShape != "text" {
		t.Fatalf("terminal pointer = %q, want text", app.pointerShape)
	}
	app.Update(tea.MouseMotionMsg{X: app.layout.Divider.X, Y: app.layout.Divider.Y + 1})
	if app.pointerShape != "ew-resize" {
		t.Fatalf("divider pointer = %q, want ew-resize", app.pointerShape)
	}
	chat := topBarActionRect(t, app, ActionToggleChat)
	app.Update(tea.MouseMotionMsg{X: chat.X, Y: chat.Y})
	if app.pointerShape != "default" {
		t.Fatalf("chrome pointer = %q, want default", app.pointerShape)
	}

	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "Alex"})
	read, _, _ := app.approvalButtonRects()
	app.Update(tea.MouseMotionMsg{X: read.X, Y: read.Y})
	if app.pointerShape != "default" {
		t.Fatalf("dialog pointer = %q, want default", app.pointerShape)
	}
}

func TestMouseTopBarActionRequiresMatchingRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	chat := topBarActionRect(t, app, ActionToggleChat)
	menu := topBarActionRect(t, app, ActionShowMenu)

	app.Update(leftClick(chat.X, chat.Y))
	if app.sidebarOpen {
		t.Fatal("chat opened on press")
	}
	app.Update(leftRelease(menu.X, menu.Y))
	if app.sidebarOpen {
		t.Fatal("chat opened after release on a different target")
	}
}

func TestMouseChatMessageCopiesOnlyBodyOnMatchingRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{{Author: "alex", Body: "sudo systemctl restart derphole"}}
	rect := targetRect(t, app.buildScene(), chatMessageTarget(0))

	app.Update(leftClick(rect.X+1, rect.Y))
	if app.focus != FocusChat {
		// setSidebarOpen focuses chat; the message press itself must not change it.
		t.Fatalf("unexpected focus %v", app.focus)
	}
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))
	assertImmediateClipboard(t, cmd, "sudo systemctl restart derphole")
	if !app.copiedChatActive || app.copiedChatIndex != 0 {
		t.Fatalf("copied state = %v/%d, want active message 0", app.copiedChatActive, app.copiedChatIndex)
	}
}

func TestMouseChatMessageReleaseOnAnotherMessageDoesNotCopy(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{
		{Author: "alex", Body: "one"},
		{Author: "blair", Body: "two"},
	}
	scene := app.buildScene()
	first := targetRect(t, scene, chatMessageTarget(0))
	second := targetRect(t, scene, chatMessageTarget(1))

	app.Update(leftClick(first.X+1, first.Y))
	_, cmd := app.Update(leftRelease(second.X+1, second.Y))

	if cmd != nil {
		t.Fatalf("mismatched release command = %T, want nil", cmd())
	}
	if app.copiedChatActive || app.copiedChatIndex != -1 {
		t.Fatalf("copied state = %v/%d after mismatched release, want inactive", app.copiedChatActive, app.copiedChatIndex)
	}
	if app.pressedTarget != "" {
		t.Fatalf("pressed target = %q after mismatched release, want empty", app.pressedTarget)
	}
}

func TestMouseChatMessageEmptyBodyDoesNotCopy(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{{Author: "alex", Body: " \n\t "}}
	rect := targetRect(t, app.buildScene(), chatMessageTarget(0))

	app.Update(leftClick(rect.X+1, rect.Y))
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))

	if cmd != nil {
		t.Fatalf("empty message command = %T, want nil", cmd())
	}
	if app.copiedChatActive || app.copiedChatIndex != -1 {
		t.Fatalf("copied state = %v/%d for empty body, want inactive", app.copiedChatActive, app.copiedChatIndex)
	}
}

func TestMouseChatMessageCopiesMultilineBodyVerbatim(t *testing.T) {
	const body = "first line\n  indented second line\n"
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.setSidebarOpen(true)
	app.chatMessages = []ChatMessage{{Author: "alex", Body: body}}
	rect := targetRect(t, app.buildScene(), chatMessageTarget(0))

	app.Update(leftClick(rect.X+1, rect.Y))
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))

	assertImmediateClipboard(t, cmd, body)
}

func TestMouseChatMessageRejectsStaleIndex(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.chatMessages = []ChatMessage{{Body: "one"}}

	if cmd := app.copyChatMessage(1); cmd != nil {
		t.Fatalf("stale message command = %T, want nil", cmd())
	}
	if app.copiedChatActive || app.copiedChatIndex != -1 || app.copiedChatSeq != 0 {
		t.Fatalf("copied state = %v/%d seq %d for stale index, want inactive zero state",
			app.copiedChatActive, app.copiedChatIndex, app.copiedChatSeq)
	}
}

func TestMouseChatMessagePreservesScrollFocusAndTerminalSelection(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}, selectionOn: true}
	app := chatAppWithScrollableMessages(t)
	app.terminal = pane
	app.focusTerminal()
	app.chatScroll = 3
	rect := targetRect(t, app.buildScene(), chatMessageTarget(len(app.chatMessages)-2))

	app.Update(leftClick(rect.X+1, rect.Y))
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))

	assertImmediateClipboard(t, cmd, app.chatMessages[len(app.chatMessages)-2].Body)
	if app.chatScroll != 3 {
		t.Fatalf("chatScroll = %d after message click, want 3", app.chatScroll)
	}
	if app.focus != FocusTerminal || app.composer.Focused() {
		t.Fatalf("focus/composer = %v/%v after message click, want terminal/blurred", app.focus, app.composer.Focused())
	}
	if !pane.SelectionActive() || pane.clearCalls != 0 {
		t.Fatalf("terminal selection after message click = active %v, clears %d; want active, zero clears",
			pane.SelectionActive(), pane.clearCalls)
	}
	if app.helpOpen || app.peerDialogOpen || app.quitOpen {
		t.Fatal("message click opened a menu or dialog")
	}
}

func TestMouseChatMessagePreservesOutOfRangeScroll(t *testing.T) {
	app := chatAppWithScrollableMessages(t)
	app.chatScroll = 999
	rect := targetRect(t, app.buildScene(), chatMessageTarget(0))

	app.Update(leftClick(rect.X+1, rect.Y))
	afterPress := app.chatScroll
	_, cmd := app.Update(leftRelease(rect.X+1, rect.Y))

	assertImmediateClipboard(t, cmd, app.chatMessages[0].Body)
	if afterPress != 999 || app.chatScroll != 999 {
		t.Fatalf("chatScroll after press/release = %d/%d, want 999/999", afterPress, app.chatScroll)
	}
}

func TestMouseChatWheelMovesThreeRenderedRows(t *testing.T) {
	app := chatAppWithScrollableMessages(t)
	app.Update(tea.MouseWheelMsg{X: app.layout.Sidebar.X + 2, Y: app.layout.Sidebar.Y + 3, Button: tea.MouseWheelUp})
	if app.chatScroll != 3 {
		t.Fatalf("chatScroll = %d, want 3", app.chatScroll)
	}
	app.Update(tea.MouseWheelMsg{X: app.layout.Sidebar.X + 2, Y: app.layout.Sidebar.Y + 3, Button: tea.MouseWheelDown})
	if app.chatScroll != 0 {
		t.Fatalf("chatScroll after wheel down = %d, want 0", app.chatScroll)
	}
}

func TestMouseChatWheelClampsToRenderedRows(t *testing.T) {
	app := chatAppWithScrollableMessages(t)
	viewportHeight := maxInt(app.layout.Sidebar.H-1-app.sidebarComposerRows(app.layout.Sidebar.H), 0)
	wantMax := maxInt(len(app.chatRows(app.layout.Sidebar.W))-viewportHeight, 0)

	for range 100 {
		app.Update(tea.MouseWheelMsg{X: app.layout.Sidebar.X + 2, Y: app.layout.Sidebar.Y + 3, Button: tea.MouseWheelUp})
	}
	if app.chatScroll != wantMax {
		t.Fatalf("chatScroll = %d after repeated wheel up, want max %d", app.chatScroll, wantMax)
	}
	for range 100 {
		app.Update(tea.MouseWheelMsg{X: app.layout.Sidebar.X + 2, Y: app.layout.Sidebar.Y + 3, Button: tea.MouseWheelDown})
	}
	if app.chatScroll != 0 {
		t.Fatalf("chatScroll = %d after repeated wheel down, want 0", app.chatScroll)
	}
}

func TestMouseClickTopBarChatToggle(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	chat := topBarActionRect(t, app, ActionToggleChat)

	dispatchMouse(t, app, leftClick(chat.X+chat.W/2, chat.Y))
	dispatchMouse(t, app, leftRelease(chat.X+chat.W/2, chat.Y))

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

	chat = topBarActionRect(t, app, ActionToggleChat)
	dispatchMouse(t, app, leftClick(chat.X+chat.W/2, chat.Y))
	dispatchMouse(t, app, leftRelease(chat.X+chat.W/2, chat.Y))

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
	dispatchMouse(t, app, leftRelease(quit.X+quit.W/2, quit.Y))

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
	dispatchMouse(t, app, leftRelease(peer.X+peer.W/2, peer.Y))

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
	dispatchMouse(t, app, leftRelease(peer.X+peer.W/2, peer.Y))
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

func TestMouseLocalTerminalDrag(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	_, cmd := app.Update(leftClick(terminal.X+4, terminal.Y+3))
	if cmd != nil {
		t.Fatalf("selection press command = %T, want nil", cmd)
	}
	if app.focus != FocusTerminal {
		t.Fatalf("focus = %v, want terminal", app.focus)
	}
	if app.pointerCapture != targetTerminal {
		t.Fatalf("pointer capture = %q, want terminal", app.pointerCapture)
	}
	if got := pane.begins; len(got) != 1 || got[0] != (terminalPoint{X: 4, Y: 3}) {
		t.Fatalf("BeginSelection calls = %+v, want (4,3)", got)
	}

	_, cmd = app.Update(tea.MouseMotionMsg{X: terminal.X + 7, Y: 0, Button: tea.MouseLeft})
	if cmd == nil {
		t.Fatal("selection edge motion did not schedule autoscroll")
	}
	if got := pane.updates; len(got) != 1 || got[0] != (terminalPoint{X: 7, Y: 0}) {
		t.Fatalf("UpdateSelection calls = %+v, want captured header motion at pane edge (7,0)", got)
	}

	_, cmd = app.Update(leftRelease(terminal.X+7, 0))
	if pane.finishCalls != 1 {
		t.Fatalf("FinishSelection calls = %d, want 1", pane.finishCalls)
	}
	if app.pointerCapture != "" {
		t.Fatalf("pointer capture after release = %q, want empty", app.pointerCapture)
	}
	if cmd == nil || fmt.Sprint(cmd()) != "selected text" {
		t.Fatalf("selection release clipboard = %v, want selected text", cmd)
	}
	if pane.SelectionActive() {
		t.Fatal("selection remains active after completed drag copy")
	}
}

func TestMouseTerminalClickWithoutDrag(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(leftClick(terminal.X+2, terminal.Y+2))
	_, cmd := app.Update(leftRelease(terminal.X+2, terminal.Y+2))

	if pane.finishCalls != 1 {
		t.Fatalf("FinishSelection calls = %d, want 1", pane.finishCalls)
	}
	if cmd != nil {
		t.Fatalf("click-only selection command = %T, want nil", cmd)
	}
}

func TestMouseTerminalWheelLocal(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelUp})
	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelDown})

	if got, want := fmt.Sprint(pane.scrolls), "[3 -3]"; got != want {
		t.Fatalf("ScrollLines calls = %s, want %s", got, want)
	}
}

func TestMouseTerminalWheelDuringActiveDrag(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(leftClick(terminal.X+2, terminal.Y+2))
	app.Update(tea.MouseWheelMsg{X: terminal.X + 6, Y: terminal.Y + 5, Button: tea.MouseWheelUp})

	if got, want := fmt.Sprint(pane.scrolls), "[3]"; got != want {
		t.Fatalf("ScrollLines calls = %s, want %s", got, want)
	}
	if got := pane.updates; len(got) != 1 || got[0] != (terminalPoint{X: 6, Y: 5}) {
		t.Fatalf("UpdateSelection calls after wheel = %+v, want (6,5)", got)
	}
}

func TestMouseTerminalWheelSGR(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}, viewport: terminalViewportState{OffsetFromBottom: 7}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelUp})

	if len(pane.scrolls) != 0 {
		t.Fatalf("local ScrollLines calls = %v, want none", pane.scrolls)
	}
	if pane.resetCalls != 1 || pane.viewport.OffsetFromBottom != 0 {
		t.Fatalf("ResetViewport calls, offset = %d, %d; want 1, 0", pane.resetCalls, pane.viewport.OffsetFromBottom)
	}
	got, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(got.Data) != "\x1b[<64;3;5M" {
		t.Fatalf("SGR wheel command = %#v, want wheel-up bytes", got)
	}
}

func TestMouseTerminalWheelForcedSelection(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelDown})

	if got, want := fmt.Sprint(pane.scrolls), "[-3]"; got != want {
		t.Fatalf("forced ScrollLines calls = %s, want %s", got, want)
	}
	if pane.resetCalls != 0 {
		t.Fatalf("forced ResetViewport calls = %d, want 0", pane.resetCalls)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("forced wheel emitted terminal command %+v", cmd)
	}
}

func TestMouseForcedSelectionAlternateSGRWheelDoesNotEmitAlternateScroll(t *testing.T) {
	pane := &interactiveFakePane{
		fakePane: fakePane{
			view:  "ok",
			mouse: MouseMode{Enabled: true, SGR: true},
			input: TerminalInputMode{AlternateScroll: true},
		},
		viewport: terminalViewportState{AlternateScreen: true},
	}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelUp})

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("forced alternate-screen SGR wheel emitted remote input %+v, want none", cmd)
	}
	if len(pane.scrolls) != 0 {
		t.Fatalf("forced alternate-screen SGR wheel scrolled host viewport: %v", pane.scrolls)
	}
}

func TestMouseForcedSelectionCustomPaneForwardsNonlocalSGRButtons(t *testing.T) {
	tests := []struct {
		name      string
		button    tea.MouseButton
		wantPress string
	}{
		{name: "middle", button: tea.MouseMiddle, wantPress: "\x1b[<1;3;5M"},
		{name: "right", button: tea.MouseRight, wantPress: "\x1b[<2;3;5M"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}
			app := NewApp(Options{Terminal: pane})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			drainCommands(app)
			app.copyMode = true
			terminal := app.currentTerminalRect()
			x, y := terminal.X+2, terminal.Y+4

			app.Update(clickAt(x, y, tt.button))
			press, ok := readCommand(app).(TerminalInputCommand)
			if !ok || string(press.Data) != tt.wantPress {
				t.Fatalf("forced custom-pane %s press = %#v, want %q", tt.name, press, tt.wantPress)
			}
			app.Update(releaseAt(x, y, tea.MouseNone))
			release, ok := readCommand(app).(TerminalInputCommand)
			if !ok || string(release.Data) != "\x1b[<0;3;5m" {
				t.Fatalf("forced custom-pane %s release = %#v, want forwarded SGR release", tt.name, release)
			}
		})
	}
}

func TestMouseForcedSelectionViewportOnlyPaneOverlappingNonleftSGRPair(t *testing.T) {
	tests := []struct {
		name      string
		button    tea.MouseButton
		wantPress string
	}{
		{name: "middle", button: tea.MouseMiddle, wantPress: "\x1b[<1;3;5M"},
		{name: "right", button: tea.MouseRight, wantPress: "\x1b[<2;3;5M"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &viewportOnlyFakePane{fakePane: fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}}
			app := NewApp(Options{Terminal: pane})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			drainCommands(app)
			app.copyMode = true
			terminal := app.currentTerminalRect()
			x, y := terminal.X+2, terminal.Y+4

			app.Update(leftClick(x, y))
			if app.pointerCapture != targetTerminal || app.terminalGesture != terminalGestureDrag {
				t.Fatalf("forced local left ownership = (%q, %v), want terminal drag", app.pointerCapture, app.terminalGesture)
			}
			if cmd := readCommand(app); cmd != nil {
				t.Fatalf("forced local left press emitted remote input %+v", cmd)
			}

			app.Update(clickAt(x, y, tt.button))
			press, ok := readCommand(app).(TerminalInputCommand)
			if !ok || string(press.Data) != tt.wantPress {
				t.Fatalf("overlapping %s press = %#v, want %q", tt.name, press, tt.wantPress)
			}
			app.Update(releaseAt(x, y, tea.MouseNone))
			release, ok := readCommand(app).(TerminalInputCommand)
			if !ok || string(release.Data) != "\x1b[<0;3;5m" {
				t.Fatalf("overlapping %s release = %#v, want forwarded SGR release", tt.name, release)
			}
			if app.pointerCapture != targetTerminal || app.terminalGesture != terminalGestureDrag {
				t.Fatalf("local left ownership after %s release = (%q, %v), want preserved terminal drag", tt.name, app.pointerCapture, app.terminalGesture)
			}

			app.Update(releaseAt(x, y, tea.MouseNone))
			if cmd := readCommand(app); cmd != nil {
				t.Fatalf("matching local left release emitted remote input %+v", cmd)
			}
			if app.pointerCapture != "" || app.terminalGesture != terminalGestureNone {
				t.Fatalf("local left ownership after matching release = (%q, %v), want cleared", app.pointerCapture, app.terminalGesture)
			}
		})
	}
}

func TestMouseForcedSelectionForwardsRightSGRRelease(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok", mouse: MouseMode{Enabled: true, SGR: true}}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	app.copyMode = true
	terminal := app.currentTerminalRect()
	x, y := terminal.X+2, terminal.Y+4

	app.Update(clickAt(x, y, tea.MouseRight))
	press, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(press.Data) != "\x1b[<2;3;5M" {
		t.Fatalf("forced right press = %#v, want forwarded SGR right press", press)
	}
	app.Update(releaseAt(x, y, tea.MouseNone))
	release, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(release.Data) != "\x1b[<0;3;5m" {
		t.Fatalf("forced right release = %#v, want forwarded SGR release", release)
	}
}

func TestMouseTerminalWheelStaysLocalDuringCapturedDrag(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()
	app.Update(leftClick(terminal.X+2, terminal.Y+2))
	pane.mouse = MouseMode{Enabled: true, SGR: true}

	app.Update(tea.MouseWheelMsg{X: terminal.X + 4, Y: terminal.Y + 4, Button: tea.MouseWheelUp})

	if got, want := fmt.Sprint(pane.scrolls), "[3]"; got != want {
		t.Fatalf("captured drag ScrollLines calls = %s, want %s", got, want)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("captured drag wheel emitted SGR command %+v", cmd)
	}
}

func TestMouseTerminalWheelAlternateScroll(t *testing.T) {
	pane := &interactiveFakePane{
		fakePane: fakePane{view: "ok", input: TerminalInputMode{AlternateScroll: true}},
		viewport: terminalViewportState{AlternateScreen: true},
	}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelUp})
	up, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(up.Data) != "\x1b[A\x1b[A\x1b[A" {
		t.Fatalf("alternate wheel-up command = %#v, want three cursor-up sequences", up)
	}
	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelDown})
	down, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(down.Data) != "\x1b[B\x1b[B\x1b[B" {
		t.Fatalf("alternate wheel-down command = %#v, want three cursor-down sequences", down)
	}
	if len(pane.scrolls) != 0 {
		t.Fatalf("alternate screen ScrollLines calls = %v, want none", pane.scrolls)
	}
}

func TestMouseTerminalWheelAlternateScreenWithoutAlternateScroll(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}, viewport: terminalViewportState{AlternateScreen: true}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()

	app.Update(tea.MouseWheelMsg{X: terminal.X + 2, Y: terminal.Y + 4, Button: tea.MouseWheelUp})

	if len(pane.scrolls) != 0 {
		t.Fatalf("alternate screen ScrollLines calls = %v, want none", pane.scrolls)
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("alternate screen wheel command = %+v, want nil", cmd)
	}
}

func TestMouseDoubleClickCopiesWord(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}, wordText: "selected word"}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	now := time.Unix(1_000, 0)
	app.now = func() time.Time { return now }
	terminal := app.currentTerminalRect()
	x, y := terminal.X+4, terminal.Y+3

	app.Update(leftClick(x, y))
	app.Update(leftRelease(x, y))
	now = now.Add(499 * time.Millisecond)
	_, cmd := app.Update(leftClick(x, y))

	if got := pane.words; len(got) != 1 || got[0] != (terminalPoint{X: 4, Y: 3}) {
		t.Fatalf("SelectWord calls = %+v, want (4,3)", got)
	}
	if app.pointerCapture != targetTerminal {
		t.Fatalf("word pointer capture = %q, want terminal", app.pointerCapture)
	}
	if !pane.SelectionActive() {
		t.Fatal("word selection is not retained for feedback")
	}
	assertImmediateClipboard(t, cmd, "selected word")
	_ = app.View()
	if !pane.SelectionActive() {
		t.Fatal("declarative render cleared word selection before feedback tick")
	}

	app.Update(leftRelease(x, y))
	if app.pointerCapture != "" {
		t.Fatalf("word pointer capture after release = %q, want empty", app.pointerCapture)
	}
	if !pane.SelectionActive() {
		t.Fatal("word release cleared highlight before feedback tick")
	}
}

func TestMouseWordFeedbackReleaseRestoresNonleftSGRPair(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}, wordText: "selected word"}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	now := time.Unix(1_500, 0)
	app.now = func() time.Time { return now }
	terminal := app.currentTerminalRect()
	x, y := terminal.X+4, terminal.Y+3

	app.Update(leftClick(x, y))
	app.Update(leftRelease(x, y))
	now = now.Add(100 * time.Millisecond)
	_, clipboard := app.Update(leftClick(x, y))
	if clipboard == nil || !pane.SelectionActive() {
		t.Fatal("double click did not create retained word feedback")
	}
	pane.mouse = MouseMode{Enabled: true, SGR: true}
	app.Update(leftRelease(x, y))
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("matching word release emitted remote input %+v", cmd)
	}
	if !pane.SelectionActive() {
		t.Fatal("matching word release cleared feedback highlight")
	}

	app.Update(clickAt(x, y, tea.MouseRight))
	press, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(press.Data) != "\x1b[<2;5;4M" {
		t.Fatalf("right press during word feedback = %#v, want forwarded SGR press", press)
	}
	app.Update(releaseAt(x, y, tea.MouseNone))
	release, ok := readCommand(app).(TerminalInputCommand)
	if !ok || string(release.Data) != "\x1b[<0;5;4m" {
		t.Fatalf("right release during word feedback = %#v, want forwarded SGR release", release)
	}
	if !pane.SelectionActive() {
		t.Fatal("forwarded non-left pair cleared word feedback before tick")
	}
}

func TestMouseDoubleClickCandidateReset(t *testing.T) {
	tests := []struct {
		name   string
		second func(*App, *interactiveFakePane, Rect, *time.Time)
	}{
		{
			name: "different cell",
			second: func(app *App, _ *interactiveFakePane, terminal Rect, _ *time.Time) {
				app.Update(leftClick(terminal.X+5, terminal.Y+3))
			},
		},
		{
			name: "modifier",
			second: func(app *App, _ *interactiveFakePane, terminal Rect, _ *time.Time) {
				app.Update(tea.MouseClickMsg{X: terminal.X + 4, Y: terminal.Y + 3, Button: tea.MouseLeft, Mod: tea.ModShift})
			},
		},
		{
			name: "timeout",
			second: func(app *App, _ *interactiveFakePane, terminal Rect, now *time.Time) {
				*now = (*now).Add(501 * time.Millisecond)
				app.Update(leftClick(terminal.X+4, terminal.Y+3))
			},
		},
		{
			name: "drag",
			second: func(app *App, _ *interactiveFakePane, terminal Rect, _ *time.Time) {
				app.Update(tea.MouseMotionMsg{X: terminal.X + 7, Y: terminal.Y + 3, Button: tea.MouseLeft})
				app.Update(leftRelease(terminal.X+7, terminal.Y+3))
				app.Update(leftClick(terminal.X+4, terminal.Y+3))
			},
		},
		{
			name: "forwarded SGR click",
			second: func(app *App, pane *interactiveFakePane, terminal Rect, _ *time.Time) {
				pane.mouse = MouseMode{Enabled: true, SGR: true}
				app.Update(leftClick(terminal.X+4, terminal.Y+3))
				pane.mouse = MouseMode{}
				app.Update(leftClick(terminal.X+4, terminal.Y+3))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
			app := NewApp(Options{Terminal: pane})
			app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			drainCommands(app)
			now := time.Unix(2_000, 0)
			app.now = func() time.Time { return now }
			terminal := app.currentTerminalRect()

			app.Update(leftClick(terminal.X+4, terminal.Y+3))
			if tt.name != "drag" {
				app.Update(leftRelease(terminal.X+4, terminal.Y+3))
			}
			tt.second(app, pane, terminal, &now)

			if len(pane.words) != 0 {
				t.Fatalf("SelectWord calls = %+v, want none", pane.words)
			}
		})
	}
}

func assertImmediateClipboard(t *testing.T, cmd tea.Cmd, want string) {
	t.Helper()
	if cmd == nil {
		t.Fatal("clipboard command = nil")
	}
	msg := cmd()
	if fmt.Sprint(msg) == want {
		return
	}
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("clipboard command message = %T %v, want %q", msg, msg, want)
	}
	results := make(chan tea.Msg, len(batch))
	for _, child := range batch {
		go func(child tea.Cmd) { results <- child() }(child)
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	for range batch {
		select {
		case child := <-results:
			if fmt.Sprint(child) == want {
				return
			}
		case <-timer.C:
			t.Fatalf("clipboard message %q was not immediate", want)
		}
	}
	t.Fatalf("batch contained no clipboard message %q", want)
}

func TestTerminalSelectionAutoscrollSpeedAndReschedule(t *testing.T) {
	pane, app, terminal := startTerminalSelectionForAutoscroll(t)

	_, start := app.Update(tea.MouseMotionMsg{X: terminal.X + 7, Y: terminal.Y - 1, Button: tea.MouseLeft})
	if start == nil {
		t.Fatal("one-row top overflow did not schedule autoscroll")
	}
	seq := app.terminalAutoscrollSeq
	_, next := app.Update(terminalSelectionAutoscrollMsg{seq: seq})
	if got, want := fmt.Sprint(pane.scrolls), "[3]"; got != want {
		t.Fatalf("one-row top overflow ScrollLines = %s, want %s", got, want)
	}
	if got := pane.updates[len(pane.updates)-1]; got != (terminalPoint{X: 7, Y: 0}) {
		t.Fatalf("top autoscroll endpoint = %+v, want (7,0)", got)
	}
	if next == nil {
		t.Fatal("valid autoscroll tick did not reschedule")
	}

	_, start = app.Update(tea.MouseMotionMsg{X: terminal.X + 8, Y: terminal.Y - 8, Button: tea.MouseLeft})
	if start == nil {
		t.Fatal("medium top overflow did not schedule autoscroll")
	}
	seq = app.terminalAutoscrollSeq
	app.Update(terminalSelectionAutoscrollMsg{seq: seq})
	if got := pane.scrolls[len(pane.scrolls)-1]; got != 8 {
		t.Fatalf("eight-row top overflow ScrollLines = %d, want 8", got)
	}

	_, start = app.Update(tea.MouseMotionMsg{X: terminal.X + 9, Y: terminal.Y + terminal.H + 20, Button: tea.MouseLeft})
	if start == nil {
		t.Fatal("far bottom overflow did not schedule autoscroll")
	}
	seq = app.terminalAutoscrollSeq
	app.Update(terminalSelectionAutoscrollMsg{seq: seq})
	if got := pane.scrolls[len(pane.scrolls)-1]; got != -15 {
		t.Fatalf("far bottom overflow ScrollLines = %d, want -15 cap", got)
	}
	if got := pane.updates[len(pane.updates)-1]; got != (terminalPoint{X: 9, Y: terminal.H - 1}) {
		t.Fatalf("bottom autoscroll endpoint = %+v, want (9,%d)", got, terminal.H-1)
	}
}

func TestTerminalSelectionAutoscrollDoesNotScrollAlternateScreen(t *testing.T) {
	pane, app, terminal := startTerminalSelectionForAutoscroll(t)
	pane.viewport.AlternateScreen = true
	app.pointerShape = "text"

	_, cmd := app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y - 1, Button: tea.MouseLeft})

	if cmd != nil {
		t.Fatalf("alternate-screen edge motion scheduled %T, want no host autoscroll", cmd)
	}
	if len(pane.scrolls) != 0 {
		t.Fatalf("alternate-screen edge motion scrolled host viewport: %v", pane.scrolls)
	}
}

func TestTerminalSelectionAutoscrollStopsOnHostTerminalResize(t *testing.T) {
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Side: "guest", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	app.Update(RuntimeStateMsg{HostCols: 80, HostRows: 24, LocalRole: RoleRead})
	drainCommands(app)
	terminal := app.currentTerminalRect()
	app.Update(leftClick(terminal.X+2, terminal.Y+2))
	pane.clearCalls = 0
	app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y - 1, Button: tea.MouseLeft})
	seq := app.terminalAutoscrollSeq

	app.Update(RuntimeStateMsg{HostCols: 81, HostRows: 24, LocalRole: RoleRead})
	app.Update(terminalSelectionAutoscrollMsg{seq: seq})

	if len(pane.scrolls) != 0 {
		t.Fatalf("host-resize stale tick scrolled: %v", pane.scrolls)
	}
	if pane.clearCalls == 0 {
		t.Fatal("host terminal resize did not clear active selection")
	}
}

func TestTerminalSelectionAutoscrollStops(t *testing.T) {
	tests := []struct {
		name      string
		stop      func(*App, Rect)
		wantClear bool
	}{
		{
			name: "pointer re-entry",
			stop: func(app *App, terminal Rect) {
				app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y + 2, Button: tea.MouseLeft})
			},
		},
		{
			name: "release",
			stop: func(app *App, terminal Rect) {
				app.Update(leftRelease(terminal.X+2, terminal.Y-1))
			},
		},
		{
			name: "modal open",
			stop: func(app *App, _ Rect) {
				app.openQuitConfirm()
			},
			wantClear: true,
		},
		{
			name: "resize",
			stop: func(app *App, _ Rect) {
				app.Update(tea.WindowSizeMsg{Width: 101, Height: 31})
			},
			wantClear: true,
		},
		{
			name: "forced mode exit",
			stop: func(app *App, _ Rect) {
				app.copyMode = true
				app.setCopyMode(false)
			},
			wantClear: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pane, app, terminal := startTerminalSelectionForAutoscroll(t)
			app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y - 1, Button: tea.MouseLeft})
			seq := app.terminalAutoscrollSeq
			clearCalls := pane.clearCalls

			tt.stop(app, terminal)
			app.Update(terminalSelectionAutoscrollMsg{seq: seq})

			if len(pane.scrolls) != 0 {
				t.Fatalf("stale autoscroll tick scrolled after stop: %v", pane.scrolls)
			}
			if tt.wantClear && pane.clearCalls <= clearCalls {
				t.Fatalf("selection clear calls = %d, want more than %d", pane.clearCalls, clearCalls)
			}
		})
	}
}

func TestTerminalSelectionAutoscrollSequenceReplacement(t *testing.T) {
	pane, app, terminal := startTerminalSelectionForAutoscroll(t)
	app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y - 1, Button: tea.MouseLeft})
	stale := app.terminalAutoscrollSeq
	app.Update(tea.MouseMotionMsg{X: terminal.X + 2, Y: terminal.Y - 3, Button: tea.MouseLeft})
	current := app.terminalAutoscrollSeq
	if current == stale {
		t.Fatalf("autoscroll sequence = %d after pointer replacement, want new sequence", current)
	}

	app.Update(terminalSelectionAutoscrollMsg{seq: stale})
	if len(pane.scrolls) != 0 {
		t.Fatalf("stale replacement tick scrolled: %v", pane.scrolls)
	}
	app.Update(terminalSelectionAutoscrollMsg{seq: current})
	if got, want := fmt.Sprint(pane.scrolls), "[3]"; got != want {
		t.Fatalf("current replacement tick ScrollLines = %s, want %s", got, want)
	}
}

func startTerminalSelectionForAutoscroll(t *testing.T) (*interactiveFakePane, *App, Rect) {
	t.Helper()
	pane := &interactiveFakePane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	drainCommands(app)
	terminal := app.currentTerminalRect()
	app.Update(leftClick(terminal.X+2, terminal.Y+2))
	pane.clearCalls = 0
	return pane, app, terminal
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
	dispatchMouse(t, app, leftRelease(menu.X+menu.W/2, menu.Y))

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

func TestMouseDividerCaptureSurvivesResizeAcknowledgementUntilRelease(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	app.setSidebarOpen(true)
	start := app.layout.Divider

	app.Update(leftClick(start.X, start.Y+2))
	app.Update(tea.MouseMotionMsg{X: start.X - 1, Y: start.Y + 2, Button: tea.MouseLeft})
	app.Update(RuntimeStateMsg{HostCols: app.hostCols + 1, HostRows: 29})
	if app.pointerCapture != targetDivider || !app.draggingDivider {
		t.Fatalf("capture after resize acknowledgement = %q/%v, want divider/true", app.pointerCapture, app.draggingDivider)
	}

	app.Update(tea.MouseMotionMsg{X: start.X - 8, Y: start.Y + 2, Button: tea.MouseLeft})
	if app.sidebarWidth < 8 {
		t.Fatalf("sidebar width after continued drag = %d, want motion to continue", app.sidebarWidth)
	}
	app.Update(leftRelease(start.X-8, start.Y+2))
	if app.pointerCapture != "" || app.draggingDivider {
		t.Fatalf("capture after release = %q/%v, want cleared", app.pointerCapture, app.draggingDivider)
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
			wantMouseMode: tea.MouseModeCellMotion,
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

func targetRect(t *testing.T, scene Scene, target layerTarget) Rect {
	t.Helper()
	for y := 0; y < scene.Height; y++ {
		start := -1
		for x := 0; x <= scene.Width; x++ {
			matches := x < scene.Width && scene.TargetAt(x, y) == target
			if matches && start < 0 {
				start = x
			}
			if !matches && start >= 0 {
				return Rect{X: start, Y: y, W: x - start, H: 1}
			}
		}
	}
	t.Fatalf("scene target %q not found", target)
	return Rect{}
}

func chatAppWithScrollableMessages(t *testing.T) *App {
	t.Helper()
	app := NewApp(Options{Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 12})
	app.setSidebarOpen(true)
	for index := range 12 {
		app.chatMessages = append(app.chatMessages, ChatMessage{
			Author: fmt.Sprintf("peer-%d", index),
			Body:   fmt.Sprintf("message-%d", index),
		})
	}
	return app
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

type viewportOnlyFakePane struct {
	fakePane
	viewport terminalViewportState
}

var _ terminalViewportInteraction = (*viewportOnlyFakePane)(nil)

func (p *viewportOnlyFakePane) ScrollLines(int) bool { return true }

func (p *viewportOnlyFakePane) ResetViewport() bool { return true }

func (p *viewportOnlyFakePane) ViewportState() terminalViewportState { return p.viewport }

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
