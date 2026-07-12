// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/mattn/go-runewidth"
	"github.com/shayne/derphole/pkg/derpssh/brand"
)

var _ tea.Model = (*App)(nil)

func TestViewDeclaresTerminalModes(t *testing.T) {
	app := NewApp(Options{Terminal: &fakePane{view: "shell$"}})
	view := app.View()
	if !view.AltScreen {
		t.Fatal("View().AltScreen = false, want true")
	}
	if view.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("View().MouseMode = %v, want cell motion", view.MouseMode)
	}
	if !view.KeyboardEnhancements.ReportAlternateKeys ||
		!view.KeyboardEnhancements.ReportAllKeysAsEscapeCodes ||
		!view.KeyboardEnhancements.ReportAssociatedText ||
		view.KeyboardEnhancements.ReportEventTypes {
		t.Fatalf("unexpected keyboard enhancements: %+v", view.KeyboardEnhancements)
	}
}

func TestInviteCopyUsesBubbleTeaClipboardCommand(t *testing.T) {
	app := NewApp(Options{
		Side: "host", InviteCommand: "  derpssh connect invite \n",
		Terminal: &fakePane{view: "shell$"},
	})
	app.inviteOpen = true
	cmd := app.handleInviteKey(textKey("c"))
	if cmd == nil {
		t.Fatal("copy command = nil, want Bubble Tea clipboard message")
	}
	if got, want := fmt.Sprint(cmd()), "derpssh connect invite"; got != want {
		t.Fatalf("clipboard content = %q, want %q", got, want)
	}
}

func TestViewDeclarativelyDisablesMouseForSelectionAndInvite(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "invite"})
	app.copyMode = true
	if got := app.View().MouseMode; got != tea.MouseModeNone {
		t.Fatalf("selection mouse mode = %v", got)
	}
	app.copyMode = false
	app.inviteOpen = true
	if got := app.View().MouseMode; got != tea.MouseModeNone {
		t.Fatalf("invite mouse mode = %v", got)
	}
}

func TestBackgroundColorMessageRebuildsConcreteStyles(t *testing.T) {
	app := NewApp(Options{})
	if app.styles.Scheme != SchemeDark {
		t.Fatalf("initial scheme = %q, want dark", app.styles.Scheme)
	}
	app.Update(backgroundMsg(lipgloss.Color("#ffffff")))
	if app.styles.Scheme != SchemeLight {
		t.Fatalf("scheme after white background = %q, want light", app.styles.Scheme)
	}
	composerStyles := app.composer.Styles()
	if got, want := colorString(composerStyles.Focused.Base.GetBackground()), colorString(app.styles.Composer.GetBackground()); got != want {
		t.Fatalf("textarea background after scheme change = %q, want %q", got, want)
	}
	if got, want := colorString(composerStyles.Cursor.Color), colorString(app.styles.ComposerCursor.GetForeground()); got != want {
		t.Fatalf("textarea cursor after scheme change = %q, want %q", got, want)
	}
}

func TestAppUsesAltScreenCompatibleView(t *testing.T) {
	pane := &fakePane{view: "shell$ ready"}
	app := NewApp(Options{
		Side:          "host",
		DisplayName:   "Sam",
		InviteCommand: "npx -y derpssh@latest connect DSH1topsecretvalue",
		Terminal:      pane,
	})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	view := appContent(app)
	for _, want := range []string{"derpssh", "host", "shell$ ready"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
	for _, old := range []string{"terminal\n-----", "sidechat\n-----", "status\n-----", "Status "} {
		if strings.Contains(view, old) {
			t.Fatalf("View() contains old dashboard section %q:\n%s", old, view)
		}
	}
}

func TestTerminalDataUpdatesTerminalPane(t *testing.T) {
	pane := &fakePane{}
	app := NewApp(Options{Terminal: pane})

	app.Update(TerminalDataMsg("ready\n"))

	if got := string(pane.writes); got != "ready\n" {
		t.Fatalf("terminal writes = %q, want %q", got, "ready\n")
	}
}

func TestShellExitedNoticeShowsRestartDialog(t *testing.T) {
	app := NewApp(Options{Side: string(ModeHost), DisplayName: "root@hetz", Terminal: NewVTTerminalPane(80, 24)})
	app.SetWindowSize(100, 30)
	app.Update(NoticeMsg{Title: "Shell exited", Body: "The shared shell exited."})

	view := appContent(app)
	for _, want := range []string{"Shell exited", "Restart Shell", "Quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
}

func TestShellExitedRestartChoiceEmitsRestartCommand(t *testing.T) {
	app := NewApp(Options{Side: string(ModeHost), DisplayName: "root@hetz", Terminal: NewVTTerminalPane(80, 24)})
	app.SetWindowSize(100, 30)
	app.Update(NoticeMsg{Title: "Shell exited", Body: "The shared shell exited."})

	app.Update(keyCode(tea.KeyEnter))
	if _, ok := readCommand(app).(RestartShellCommand); !ok {
		t.Fatal("command is not RestartShellCommand")
	}
}

func TestRuntimeStateUpdatesTopBar(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	app.Update(RuntimeStateMsg{
		Transport: "connected-relay",
		HostCols:  120,
		HostRows:  40,
		LocalRole: RoleRead,
		Peers:     []Peer{{Name: "Alex", Role: RoleRead}},
	})

	view := appContent(app)
	for _, want := range []string{"relay", "120x40", "Alex", "read"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "connected-relay") || strings.Contains(view, "role read") {
		t.Fatalf("View() renders noisy raw status:\n%s", view)
	}
}

func TestWindowResizeEmitsTerminalPaneSize(t *testing.T) {
	pane := &fakePane{}
	app := NewApp(Options{Side: "host", Terminal: pane})

	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	got, ok := readCommand(app).(TerminalResizeCommand)
	if !ok {
		t.Fatalf("command = %T, want TerminalResizeCommand", got)
	}
	want := TerminalResizeCommand{Cols: 100, Rows: 29}
	if got != want {
		t.Fatalf("resize command = %+v, want %+v", got, want)
	}
	if pane.cols != 100 || pane.rows != 29 {
		t.Fatalf("pane size = %dx%d, want 100x29", pane.cols, pane.rows)
	}
}

func TestApprovalRequestRendersModal(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{Peer: "Alex"})

	view := appContent(app)
	for _, want := range []string{"Alex wants to join", "Read", "Write", "Deny"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
}

func TestGuestPendingRoleRendersWaitingApprovalModal(t *testing.T) {
	app := NewApp(Options{Side: "guest", DisplayName: "shayne", Terminal: &fakePane{view: ""}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	app.Update(RuntimeStateMsg{Transport: "direct", LocalRole: RolePending})

	view := appContent(app)
	for _, want := range []string{"Waiting for host approval", "The host will choose read or write access."} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}

	app.Update(RuntimeStateMsg{Transport: "direct", LocalRole: RoleWrite})
	if view := appContent(app); strings.Contains(view, "Waiting for host approval") {
		t.Fatalf("waiting approval modal still visible after approval:\n%s", view)
	}
}

func TestGuestWaitingApprovalSuppressesResizeWarning(t *testing.T) {
	app := NewApp(Options{Side: "guest", DisplayName: "shayne", Terminal: &fakePane{view: ""}})
	app.Update(tea.WindowSizeMsg{Width: 101, Height: 30})
	app.Update(RuntimeStateMsg{Transport: "direct", HostCols: 101, HostRows: 30, LocalRole: RolePending})

	if !app.waitingApprovalOpen() {
		t.Fatal("pending guest did not open waiting approval modal")
	}
	if app.resizeWarningOpen() {
		t.Fatal("pending guest opened resize warning while waiting for approval")
	}

	view := appContent(app)
	if !strings.Contains(view, "Waiting for host approval") {
		t.Fatalf("View() missing waiting approval modal:\n%s", view)
	}
	if strings.Contains(view, "Resize terminal") {
		t.Fatalf("pending guest showed resize warning behind approval modal:\n%s", view)
	}
}

func TestNoticeMsgRendersDismissibleModal(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})

	app.Update(NoticeMsg{Title: "Guest left", Body: "guest quit"})

	view := appContent(app)
	if !strings.Contains(view, "Guest left") || !strings.Contains(view, "guest quit") {
		t.Fatalf("notice missing from view:\n%s", view)
	}
	app.Update(keyCode(tea.KeyEnter))
	view = appContent(app)
	if strings.Contains(view, "Guest left") || strings.Contains(view, "guest quit") {
		t.Fatalf("notice still visible after Enter:\n%s", view)
	}
	if !strings.Contains(view, "shell$") {
		t.Fatalf("terminal not restored after notice dismissed:\n%s", view)
	}
}

func TestApprovalModalCapturesPrintableKeys(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{Peer: "Alex"})

	app.Update(textKey("x"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("approval key emitted command %+v, want none", cmd)
	}
	if app.focus != FocusApproval {
		t.Fatalf("focus = %v, want approval", app.focus)
	}
}

func TestApprovalEscapeDeniesPendingRequest(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Alex"})

	app.Update(keyCode(tea.KeyEsc))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Deny: true}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
	if app.approvalActive() {
		t.Fatalf("approval still active after Esc deny")
	}
	if app.focus != FocusTerminal {
		t.Fatalf("focus = %v, want terminal", app.focus)
	}
}

func TestApprovalEnterConfirmsSelectedAccessNotHiddenKick(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("k"))
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Blair"})
	expireApprovalGrace(app)

	app.Update(keyCode(tea.KeyEnter))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Blair", Role: RoleWrite}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
	if app.approvalActive() {
		t.Fatalf("approval still active after Enter")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("extra command after approval = %+v", cmd)
	}
}

func TestApprovalKeyboardSelection(t *testing.T) {
	tests := []struct {
		name string
		keys []tea.KeyPressMsg
		want ApprovalDecisionCommand
	}{
		{
			name: "default write",
			keys: []tea.KeyPressMsg{keyCode(tea.KeyEnter)},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleWrite},
		},
		{
			name: "left selects read",
			keys: []tea.KeyPressMsg{keyCode(tea.KeyLeft), keyCode(tea.KeyEnter)},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
		{
			name: "right selects deny",
			keys: []tea.KeyPressMsg{keyCode(tea.KeyRight), keyCode(tea.KeyEnter)},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Deny: true},
		},
		{
			name: "tab wraps selection",
			keys: []tea.KeyPressMsg{keyCode(tea.KeyTab), keyCode(tea.KeyTab), keyCode(tea.KeyEnter)},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
		{
			name: "shift tab wraps backward",
			keys: []tea.KeyPressMsg{modifiedKey(tea.KeyTab, "", tea.ModShift), keyCode(tea.KeyEnter)},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Alex"})
			expireApprovalGrace(app)

			for _, key := range tt.keys {
				app.Update(key)
			}

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

func expireApprovalGrace(app *App) {
	app.approvalGraceEnd = app.currentTime()
}

func TestApprovalEscapeWinsOverHiddenKick(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("k"))
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Blair"})

	app.Update(keyCode(tea.KeyEsc))

	got, ok := readCommand(app).(ApprovalDecisionCommand)
	if !ok {
		t.Fatalf("command = %T, want ApprovalDecisionCommand", got)
	}
	want := ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Blair", Deny: true}
	if got != want {
		t.Fatalf("approval command = %+v, want %+v", got, want)
	}
	if app.approvalActive() {
		t.Fatalf("approval still active after Esc")
	}
	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("extra command after approval deny = %+v", cmd)
	}
}

func TestViewDoesNotExposeFullInviteTokenInMainLayout(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1verysecretinvitetoken1234567890"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	view := appContent(app)
	if strings.Contains(view, invite) || strings.Contains(view, "DSH1verysecretinvitetoken1234567890") {
		t.Fatalf("View() exposes full invite token:\n%s", view)
	}
	if strings.Contains(view, "invite ready") || strings.Contains(view, "DSH1...") {
		t.Fatalf("View() renders invite status in main session chrome:\n%s", view)
	}
}

func TestViewRendersSingleQuietTopBar(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	view := appContent(app)
	firstLine := strings.Split(view, "\n")[0]
	for _, want := range []string{"derpssh", "host", "Chat", "☰"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing top-bar item %q:\n%s", want, view)
		}
	}
	if strings.Contains(firstLine, "Ctrl-X") {
		t.Fatalf("top bar should keep keyboard hints out of normal chrome:\n%s", view)
	}
	for _, noisy := range []string{"Status approved", "Status ", "role write", "chat open", "Ctrl-X S", "Ctrl-X C", "Ctrl-X I", "Ctrl-X Q", "Ctrl-X T"} {
		if strings.Contains(view, noisy) {
			t.Fatalf("View() renders noisy shortcut %q:\n%s", noisy, view)
		}
	}
}

func TestTopBarHidesInviteBehindMenu(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1verysecretinvitetoken1234567890"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	firstLine := strings.Split(appContent(app), "\n")[0]
	if strings.Contains(firstLine, "Invite") {
		t.Fatalf("top bar exposes invite chip:\n%s", firstLine)
	}
	if strings.Contains(firstLine, "?") {
		t.Fatalf("top bar should use the menu glyph, not a question mark:\n%s", firstLine)
	}
	if !strings.Contains(firstLine, "☰") {
		t.Fatalf("top bar missing menu glyph:\n%s", firstLine)
	}
}

func TestGuestPrefixHintsDoNotShowInvite(t *testing.T) {
	app := NewApp(Options{Side: "guest", InviteCommand: "npx -y derpssh@latest connect DSH1copyme", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(modifiedKey('x', "", tea.ModCtrl))

	firstLine := strings.Split(appContent(app), "\n")[0]
	if strings.Contains(firstLine, "Invite") || strings.Contains(firstLine, "Ctrl-X I") {
		t.Fatalf("guest prefix hints expose invite:\n%s", firstLine)
	}
}

func TestMenuShowsInviteForHostOnly(t *testing.T) {
	host := NewApp(Options{Side: "host", InviteCommand: "npx -y derpssh@latest connect DSH1copyme", Terminal: &fakePane{view: "ok"}})
	host.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	host.Update(modifiedKey('x', "", tea.ModCtrl))
	host.Update(textKey("?"))
	if !strings.Contains(appContent(host), "Show Invite") || !strings.Contains(appContent(host), "Ctrl-X I") {
		t.Fatalf("host menu missing invite action:\n%s", appContent(host))
	}

	guest := NewApp(Options{Side: "guest", InviteCommand: "npx -y derpssh@latest connect DSH1copyme", Terminal: &fakePane{view: "ok"}})
	guest.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	guest.Update(modifiedKey('x', "", tea.ModCtrl))
	guest.Update(textKey("?"))
	if strings.Contains(appContent(guest), "Show Invite") || strings.Contains(appContent(guest), "Ctrl-X I") {
		t.Fatalf("guest menu exposes invite action:\n%s", appContent(guest))
	}
}

func TestGuestTooSmallShowsHostSizeWarning(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(RuntimeStateMsg{Transport: "connected-direct", HostCols: 101, HostRows: 30, LocalRole: RoleWrite})

	view := appContent(app)
	for _, want := range []string{"101x30", "Resize terminal", "80x23"} {
		if !strings.Contains(view, want) {
			t.Fatalf("resize warning missing %q:\n%s", want, view)
		}
	}
}

func TestGuestSidebarDoesNotResizeHostTerminalBuffer(t *testing.T) {
	pane := &fakePane{view: "shell$"}
	app := NewApp(Options{Side: "guest", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	drainCommands(app)
	app.Update(RuntimeStateMsg{Transport: "connected-direct", HostCols: 101, HostRows: 30, LocalRole: RoleWrite})

	_ = appContent(app)
	if pane.cols != 101 || pane.rows != 30 {
		t.Fatalf("guest terminal buffer = %dx%d, want host 101x30", pane.cols, pane.rows)
	}
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	_ = appContent(app)
	if pane.cols != 101 || pane.rows != 30 {
		t.Fatalf("guest terminal buffer changed after chat opened = %dx%d, want host 101x30", pane.cols, pane.rows)
	}
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	_ = appContent(app)
	if pane.cols != 101 || pane.rows != 30 {
		t.Fatalf("guest terminal buffer changed after chat closed = %dx%d, want host 101x30", pane.cols, pane.rows)
	}
}

func TestGuestChatOverlayDoesNotShrinkEffectiveTerminalViewport(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 120, Height: 31})
	drainCommands(app)
	app.Update(RuntimeStateMsg{Transport: "direct", HostCols: 101, HostRows: 30, LocalRole: RoleWrite})
	if view := appContent(app); strings.Contains(view, "Resize terminal") {
		t.Fatalf("unexpected resize warning before chat opens:\n%s", view)
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("guest chat overlay emitted resize command %+v, want none", cmd)
	}
	cols, rows := app.TerminalSize()
	if cols != 120 || rows != 30 {
		t.Fatalf("TerminalSize with guest chat = %dx%d, want 120x30", cols, rows)
	}
	if view := appContent(app); strings.Contains(view, "Resize terminal") {
		t.Fatalf("guest chat overlay triggered resize warning:\n%s", view)
	}
}

func TestClosingChatRestoresTerminalContent(t *testing.T) {
	pane := &fakePane{view: "terminal-left " + strings.Repeat(".", 48) + " terminal-right"}
	app := NewApp(Options{Side: "host", Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	closedLine := ansiPattern.ReplaceAllString(strings.Split(appContent(app), "\n")[1], "")
	if !strings.Contains(closedLine, "terminal-right") {
		t.Fatalf("closed chat baseline missing right edge terminal content: %q", closedLine)
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	openLine := ansiPattern.ReplaceAllString(strings.Split(appContent(app), "\n")[1], "")
	if strings.Contains(openLine, "terminal-right") {
		t.Fatalf("open chat did not cover right edge terminal content: %q", openLine)
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	restoredLine := ansiPattern.ReplaceAllString(strings.Split(appContent(app), "\n")[1], "")
	if restoredLine != closedLine {
		t.Fatalf("closed chat did not repaint terminal line\n got: %q\nwant: %q", restoredLine, closedLine)
	}
}

func TestLocalChatAuthorDefaultsToUser(t *testing.T) {
	t.Setenv("USER", "shayne")
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	for _, r := range "hello" {
		app.Update(textKey(string(r)))
	}
	app.Update(keyCode(tea.KeyEnter))

	view := appContent(app)
	if !strings.Contains(view, "shayne: hello") {
		t.Fatalf("View() missing USER chat author:\n%s", view)
	}
	if strings.Contains(view, "me: hello") {
		t.Fatalf("View() used generic me author:\n%s", view)
	}
}

func TestLocalChatEchoIsDeduplicated(t *testing.T) {
	app := NewApp(Options{Side: "host", DisplayName: "root@hetz", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	for _, r := range "hello" {
		app.Update(textKey(string(r)))
	}
	app.Update(keyCode(tea.KeyEnter))
	app.Update(ChatMsg{Author: "root@hetz", Body: "hello"})

	view := appContent(app)
	if got := strings.Count(view, "root@hetz: hello"); got != 0 {
		t.Fatalf("chat message rendered with host-qualified local name %d times, want compact username:\n%s", got, view)
	}
	if got := strings.Count(view, "root: hello"); got != 1 {
		t.Fatalf("chat message rendered %d times, want once:\n%s", got, view)
	}
	if got := strings.Count(view, "Message"); got > 1 {
		t.Fatalf("composer label rendered %d Message copies, want at most one:\n%s", got, view)
	}
}

func TestInviteShortcutOpensHostInvite(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1verysecretinvitetoken1234567890"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("i"))

	view := appContent(app)
	if !app.inviteOpen {
		t.Fatalf("inviteOpen = false, want true")
	}
	for _, line := range hardWrapPlainLine(invite, 40) {
		if !strings.Contains(view, line) {
			t.Fatalf("invite screen missing command line %q:\n%s", line, view)
		}
	}
	if !strings.Contains(view, brand.Wordmark()) {
		t.Fatalf("invite screen missing derpssh wordmark:\n%s", view)
	}
}

func TestCopyModeInviteUsesSceneRendering(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1copyme"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("y"))
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("i"))

	if !app.copyMode || !app.inviteOpen {
		t.Fatalf("copyMode, inviteOpen = %v, %v; want true, true", app.copyMode, app.inviteOpen)
	}
	if got, want := app.View().Content, app.buildScene().Content; got != want {
		t.Fatalf("invite View content differs from Scene content:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if got := app.View().Content; !strings.Contains(got, "DSH1copyme") {
		t.Fatalf("invite Scene missing command:\n%s", got)
	}
}

func TestCopyModeUsesSceneRendering(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	app.copyMode = true

	if got, want := app.View().Content, app.buildScene().Content; got != want {
		t.Fatalf("copy-mode View content differs from Scene content:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestChatPaneUsesChatLabelAndWrapsMessages(t *testing.T) {
	app := NewApp(Options{Side: "guest", DisplayName: "shayne", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 72, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	app.Update(ChatMsg{Author: "eric@Erics-mini.local", Body: "this message should wrap instead of disappearing off the side of the chat pane"})

	view := appContent(app)
	if !strings.Contains(view, "Chat") {
		t.Fatalf("View() missing Chat label:\n%s", view)
	}
	if strings.Contains(view, "Sidechat") {
		t.Fatalf("View() still says Sidechat:\n%s", view)
	}
	if !strings.Contains(view, "disappearing") || !strings.Contains(view, "pane") {
		t.Fatalf("wrapped chat text missing expected fragments:\n%s", view)
	}
	for i, line := range strings.Split(view, "\n") {
		if got := visibleWidth(line); got > 72 {
			t.Fatalf("line %d width = %d, want <= 72: %q", i+1, got, line)
		}
	}
}

func TestHardWrapPlainLine(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		width int
		want  []string
	}{
		{name: "fits", line: "abc", width: 5, want: []string{"abc"}},
		{name: "long token", line: "abcdef", width: 2, want: []string{"ab", "cd", "ef"}},
		{name: "wide glyph", line: "界界", width: 2, want: []string{"界", "界"}},
		{name: "zero width", line: "abc", width: 0, want: []string{""}},
		{name: "empty", line: "", width: 4, want: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hardWrapPlainLine(tt.line, tt.width)
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Fatalf("hardWrapPlainLine() = %#v, want %#v", got, tt.want)
			}
			for _, line := range got {
				if tt.width > 0 && visibleWidth(line) > tt.width {
					t.Fatalf("wrapped line width = %d, want <= %d: %q", visibleWidth(line), tt.width, line)
				}
			}
		})
	}
}

func TestChatAutoScrollsToNewestMessages(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 9})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	for i := 0; i < 12; i++ {
		app.Update(ChatMsg{Author: "alex", Body: "message " + intStringForTest(i)})
	}

	view := appContent(app)
	if strings.Contains(view, "message 0") {
		t.Fatalf("chat did not scroll away from oldest message:\n%s", view)
	}
	if !strings.Contains(view, "message 11") {
		t.Fatalf("chat did not auto-scroll to newest message:\n%s", view)
	}
}

func TestChatComposerGrowsToThreeRows(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))

	for _, r := range "this message is long enough to wrap across multiple visible composer rows" {
		app.Update(textKey(string(r)))
	}
	appContent(app)

	if app.layout.Composer.H != 3 {
		t.Fatalf("composer height = %d, want 3", app.layout.Composer.H)
	}
	view := appContent(app)
	for _, want := range []string{"this message is long", "composer rows"} {
		if !strings.Contains(view, want) {
			t.Fatalf("composer missing visible text fragment %q:\n%s", want, view)
		}
	}
}

func TestChatComposerShowsAllRowsWhileGrowingToThree(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	appContent(app)
	width := app.layout.Composer.W
	if width < 10 {
		t.Fatalf("composer width = %d, want useful test width", width)
	}

	// Bubbles reserves the trailing cell at an exact wrap boundary so the real
	// cursor can move consistently. Keep each input segment just below that
	// boundary when asserting the dynamic one-to-three row growth.
	first := strings.Repeat("a", width-1)
	second := strings.Repeat("b", width-1)
	third := strings.Repeat("c", width-1)
	typeRunes(app, first)
	typeRunes(app, second)
	view := ansiPattern.ReplaceAllString(appContent(app), "")
	if app.layout.Composer.H != 2 {
		t.Fatalf("composer height after two wrapped rows = %d, want 2", app.layout.Composer.H)
	}
	for _, want := range []string{strings.Repeat("a", width-3), strings.Repeat("b", width-3)} {
		if !strings.Contains(view, want) {
			t.Fatalf("composer missing wrapped row %q while growing to two rows:\n%s", want, view)
		}
	}

	typeRunes(app, third)
	view = ansiPattern.ReplaceAllString(appContent(app), "")
	if app.layout.Composer.H != 3 {
		t.Fatalf("composer height after three wrapped rows = %d, want 3", app.layout.Composer.H)
	}
	for _, want := range []string{
		strings.Repeat("a", width-3),
		strings.Repeat("b", width-3),
		strings.Repeat("c", width-3),
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("composer missing wrapped row %q while growing to three rows:\n%s", want, view)
		}
	}
}

func TestChatComposerPlaceholderUsesInputBackground(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	appContent(app)

	styles := app.composer.Styles()
	if got, want := colorString(styles.Focused.Placeholder.GetForeground()), colorString(app.styles.ComposerPlaceholder.GetForeground()); got != want {
		t.Fatalf("placeholder foreground = %q, want %q", got, want)
	}
	if got, want := colorString(styles.Focused.Placeholder.GetBackground()), colorString(app.styles.Composer.GetBackground()); got != want {
		t.Fatalf("placeholder background = %q, want composer background %q", got, want)
	}
	if got := app.View().Content; !strings.Contains(got, "Message") {
		t.Fatalf("textarea view missing placeholder:\n%s", got)
	}
}

func TestFocusedEmptyChatComposerShowsBlockCursor(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	appContent(app)

	view := app.View()
	if view.Cursor == nil {
		t.Fatal("focused empty composer cursor = nil")
	}
	if view.Cursor.Shape != tea.CursorBlock {
		t.Fatalf("cursor shape = %v, want block", view.Cursor.Shape)
	}
	if got, want := colorString(view.Cursor.Color), colorString(app.styles.ComposerCursor.GetForeground()); got != want {
		t.Fatalf("cursor color = %q, want %q", got, want)
	}
}

func TestFocusedEmptyChatComposerShowsCursorBeforePlaceholder(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	appContent(app)

	view := app.View()
	if view.Cursor == nil {
		t.Fatal("focused empty composer cursor = nil")
	}
	if got, want := view.Cursor.Position.X, app.layout.Composer.X; got != want {
		t.Fatalf("empty composer cursor X = %d, want placeholder start %d", got, want)
	}
	if !strings.Contains(view.Content, "Message") {
		t.Fatalf("focused empty composer missing placeholder:\n%s", view.Content)
	}
}

func TestClosedChatShowsUnreadNotification(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(ChatMsg{Author: "alex", Body: "ping"})

	view := appContent(app)
	if !strings.Contains(strings.Split(view, "\n")[0], "Chat 1") {
		t.Fatalf("closed chat missing unread top-bar notification:\n%s", view)
	}
	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	if strings.Contains(strings.Split(appContent(app), "\n")[0], "Chat 1") {
		t.Fatalf("unread notification did not clear after opening chat:\n%s", appContent(app))
	}
}

func TestClosedChatUnreadPulsesTopBar(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	_, cmd := app.Update(ChatMsg{Author: "alex", Body: "ping"})
	if cmd == nil {
		t.Fatal("remote unread chat did not start a pulse tick")
	}
	firstLine := strings.Split(appContent(app), "\n")[0]
	firstPlain := ansiPattern.ReplaceAllString(firstLine, "")
	if !strings.Contains(firstPlain, "Chat 1") {
		t.Fatalf("closed chat missing unread top-bar notification:\n%s", appContent(app))
	}

	app.Update(unreadChatPulseMsg{seq: app.unreadPulseSeq})
	secondLine := strings.Split(appContent(app), "\n")[0]
	if secondLine == firstLine {
		t.Fatalf("unread top-bar style did not pulse:\nfirst:  %q\nsecond: %q", firstLine, secondLine)
	}
	if secondPlain := ansiPattern.ReplaceAllString(secondLine, ""); secondPlain != firstPlain {
		t.Fatalf("unread pulse changed visible label:\nfirst:  %q\nsecond: %q", firstPlain, secondPlain)
	}

	app.Update(unreadChatPulseMsg{seq: app.unreadPulseSeq})
	thirdLine := strings.Split(appContent(app), "\n")[0]
	if thirdLine != firstLine {
		t.Fatalf("unread top-bar pulse did not return to original style:\nfirst: %q\nthird: %q", firstLine, thirdLine)
	}
}

func TestClosedChatUnreadIgnoresStalePulseTick(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(ChatMsg{Author: "alex", Body: "ping"})
	staleSeq := app.unreadPulseSeq

	app.setSidebarOpen(true)
	app.setSidebarOpen(false)
	app.Update(ChatMsg{Author: "alex", Body: "again"})
	currentSeq := app.unreadPulseSeq
	if currentSeq == staleSeq {
		t.Fatalf("new unread pulse reused stale sequence %d", currentSeq)
	}

	app.Update(unreadChatPulseMsg{seq: staleSeq})
	if app.unreadPulse {
		t.Fatal("stale unread pulse tick changed pulse state")
	}

	app.Update(unreadChatPulseMsg{seq: currentSeq})
	if !app.unreadPulse {
		t.Fatal("current unread pulse tick did not change pulse state")
	}
}

func TestClosedChatUnreadEmitsBellCommand(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})

	app.Update(ChatMsg{Author: "alex", Body: "ping"})
	if _, ok := readCommand(app).(TerminalBellCommand); !ok {
		t.Fatal("remote unread chat did not emit TerminalBellCommand")
	}

	app.Update(ChatMsg{Author: "alex", Body: "again"})
	if _, ok := readCommand(app).(TerminalBellCommand); !ok {
		t.Fatal("next remote unread chat did not emit another TerminalBellCommand")
	}

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("s"))
	app.Update(ChatMsg{Author: "alex", Body: "open chat"})
	for cmd := readCommand(app); cmd != nil; cmd = readCommand(app) {
		if _, ok := cmd.(TerminalBellCommand); ok {
			t.Fatal("open chat emitted TerminalBellCommand")
		}
	}

	app.Update(ChatMsg{Author: "me", Body: "local", Local: true})
	for cmd := readCommand(app); cmd != nil; cmd = readCommand(app) {
		if _, ok := cmd.(TerminalBellCommand); ok {
			t.Fatal("local chat emitted TerminalBellCommand")
		}
	}
}

func TestTransportStatusIsReducedToPath(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(RuntimeStateMsg{Transport: "connected-relay"})

	view := appContent(app)
	if !strings.Contains(strings.Split(view, "\n")[0], "relay") {
		t.Fatalf("top bar missing relay status:\n%s", view)
	}
	if strings.Contains(view, "connected-relay") {
		t.Fatalf("top bar did not reduce raw transport status:\n%s", view)
	}
}

func TestTerminalCursorSuppressedWhenChatFocused(t *testing.T) {
	pane := &focusPane{fakePane: fakePane{view: "ok"}}
	app := NewApp(Options{Terminal: pane})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(modifiedKey('x', "", tea.ModCtrl))
	app.Update(textKey("c"))
	appContent(app)

	if pane.cursorActive {
		t.Fatalf("terminal cursor active while chat is focused")
	}
}

func TestInviteScreenEscapeReturnsToTerminal(t *testing.T) {
	app := NewApp(Options{
		Side:              "host",
		InviteCommand:     "npx -y derpssh@latest connect DSH1test",
		InitialInviteOpen: true,
		Terminal:          &fakePane{view: "shell$"},
	})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})

	app.Update(keyCode(tea.KeyEsc))

	view := appContent(app)
	if !strings.Contains(view, "shell$") {
		t.Fatalf("Esc did not return to terminal view:\n%s", view)
	}
	if strings.Contains(view, "npx -y derpssh@latest connect") {
		t.Fatalf("invite command still visible after Esc:\n%s", view)
	}
}

func TestApprovalRequestDismissesInitialInviteScreen(t *testing.T) {
	app := NewApp(Options{
		Side:              "host",
		InviteCommand:     "npx -y derpssh@latest connect DSH1test",
		InitialInviteOpen: true,
		Terminal:          &fakePane{view: "shell$"},
	})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})

	app.Update(ApprovalRequestMsg{PeerID: "guest-1", Peer: "shayne"})

	view := appContent(app)
	if strings.Contains(view, "npx -y derpssh@latest connect") {
		t.Fatalf("approval did not dismiss invite screen:\n%s", view)
	}
	if !strings.Contains(view, "shayne wants to join") {
		t.Fatalf("approval modal missing after invite dismissal:\n%s", view)
	}
}

func TestInviteScreenQReturnsToTerminal(t *testing.T) {
	app := NewApp(Options{
		Side:              "host",
		InviteCommand:     "npx -y derpssh@latest connect DSH1test",
		InitialInviteOpen: true,
		Terminal:          &fakePane{view: "shell$"},
	})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	drainCommands(app)

	app.Update(textKey("q"))

	if cmd := readCommand(app); cmd != nil {
		t.Fatalf("invite q emitted command %+v, want none", cmd)
	}
	if !strings.Contains(appContent(app), "shell$") {
		t.Fatalf("invite q did not return to terminal:\n%s", appContent(app))
	}
}

func TestFitLinePreservesANSIStyles(t *testing.T) {
	got := fitLine("\x1b[31mred\x1b[0m", 5)

	if !strings.Contains(got, "\x1b[31m") {
		t.Fatalf("fitLine stripped ANSI styling: %q", got)
	}
	if width := visibleWidth(got); width != 5 {
		t.Fatalf("fitLine width = %d, want 5: %q", width, got)
	}
}

func TestViewFitsNarrowWindow(t *testing.T) {
	app := NewApp(Options{
		Side:        "guest",
		DisplayName: "A very long local display name",
		Terminal:    &fakePane{view: "this terminal line is intentionally much wider than the viewport"},
	})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	app.Update(RuntimeStateMsg{
		Transport: "connected-through-a-very-long-relay-name",
		HostCols:  200,
		HostRows:  80,
		Peers:     []Peer{{Name: "Peer With A Long Name", Role: RoleWrite}},
	})

	for i, line := range strings.Split(appContent(app), "\n") {
		if got := visibleWidth(line); got > 40 {
			t.Fatalf("line %d width = %d, want <= 40: %q", i+1, got, line)
		}
	}
}

func TestViewFitsWideGlyphNarrowWindow(t *testing.T) {
	app := NewApp(Options{
		Side:     "guest",
		Terminal: &fakePane{view: strings.Repeat("界", 24)},
	})
	app.Update(tea.WindowSizeMsg{Width: 11, Height: 8})

	for i, line := range strings.Split(appContent(app), "\n") {
		if got := visibleWidth(line); got > 11 {
			t.Fatalf("line %d cell width = %d, want <= 11: %q", i+1, got, line)
		}
	}
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func visibleWidth(line string) int {
	return runewidth.StringWidth(ansiPattern.ReplaceAllString(line, ""))
}

func typeRunes(app *App, text string) {
	for _, r := range text {
		app.Update(textKey(string(r)))
	}
}

type fakePane struct {
	writes []byte
	cols   int
	rows   int
	view   string
	mouse  MouseMode
	input  TerminalInputMode
}

func (p *fakePane) Write(b []byte) (int, error) {
	p.writes = append(p.writes, b...)
	return len(b), nil
}

func (p *fakePane) Resize(cols int, rows int) {
	p.cols = cols
	p.rows = rows
}

func (p *fakePane) View(width int, height int) string {
	if p.view == "" {
		return strings.Repeat(" ", width)
	}
	return p.view
}

func (p *fakePane) MouseMode() MouseMode {
	return p.mouse
}

func (p *fakePane) InputMode() TerminalInputMode {
	return p.input
}

type focusPane struct {
	fakePane
	cursorActive bool
}

func (p *focusPane) SetCursorActive(active bool) {
	p.cursorActive = active
}

func intStringForTest(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
