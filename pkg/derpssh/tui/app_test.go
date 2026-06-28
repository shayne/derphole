// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
)

func TestAppUsesAltScreenCompatibleView(t *testing.T) {
	pane := &fakePane{view: "shell$ ready"}
	app := NewApp(Options{
		Side:          "host",
		DisplayName:   "Sam",
		InviteCommand: "npx -y derpssh@latest connect DSH1topsecretvalue",
		Terminal:      pane,
	})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	view := app.View()
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

	view := app.View()
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

	view := app.View()
	for _, want := range []string{"Alex wants to join", "Read", "Write", "Deny"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
}

func TestApprovalModalCapturesPrintableKeys(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app.Update(ApprovalRequestMsg{Peer: "Alex"})

	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})

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

	app.Update(tea.KeyMsg{Type: tea.KeyEsc})

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
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Blair"})

	app.Update(tea.KeyMsg{Type: tea.KeyEnter})

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
		keys []tea.KeyMsg
		want ApprovalDecisionCommand
	}{
		{
			name: "default write",
			keys: []tea.KeyMsg{{Type: tea.KeyEnter}},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleWrite},
		},
		{
			name: "left selects read",
			keys: []tea.KeyMsg{{Type: tea.KeyLeft}, {Type: tea.KeyEnter}},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
		{
			name: "right selects deny",
			keys: []tea.KeyMsg{{Type: tea.KeyRight}, {Type: tea.KeyEnter}},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Deny: true},
		},
		{
			name: "tab wraps selection",
			keys: []tea.KeyMsg{{Type: tea.KeyTab}, {Type: tea.KeyTab}, {Type: tea.KeyEnter}},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
		{
			name: "shift tab wraps backward",
			keys: []tea.KeyMsg{{Type: tea.KeyShiftTab}, {Type: tea.KeyEnter}},
			want: ApprovalDecisionCommand{PeerID: "guest-2", Peer: "Alex", Role: RoleRead},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
			app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Alex"})

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

func TestApprovalEscapeWinsOverHiddenKick(t *testing.T) {
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})
	app.Update(RuntimeStateMsg{Peers: []Peer{{ID: "guest-1", Name: "Alex", Role: RoleRead}}})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	app.Update(ApprovalRequestMsg{PeerID: "guest-2", Peer: "Blair"})

	app.Update(tea.KeyMsg{Type: tea.KeyEsc})

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

	view := app.View()
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

	view := app.View()
	firstLine := strings.Split(view, "\n")[0]
	for _, want := range []string{"derpssh", "host"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing top-bar item %q:\n%s", want, view)
		}
	}
	if !strings.Contains(firstLine, "Ctrl-X") || !strings.Contains(firstLine, "?") {
		t.Fatalf("top bar missing compact help affordance:\n%s", view)
	}
	for _, noisy := range []string{"Status approved", "Status ", "role write", "chat open", "Ctrl-X S", "Ctrl-X C", "Ctrl-X I", "Ctrl-X Q", "Ctrl-X T"} {
		if strings.Contains(view, noisy) {
			t.Fatalf("View() renders noisy shortcut %q:\n%s", noisy, view)
		}
	}
}

func TestLocalChatAuthorDefaultsToUser(t *testing.T) {
	t.Setenv("USER", "shayne")
	app := NewApp(Options{Side: "host", Terminal: &fakePane{view: "ok"}})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	for _, r := range "hello" {
		app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	app.Update(tea.KeyMsg{Type: tea.KeyEnter})

	view := app.View()
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

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	for _, r := range "hello" {
		app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	app.Update(tea.KeyMsg{Type: tea.KeyEnter})
	app.Update(ChatMsg{Author: "root@hetz", Body: "hello"})

	view := app.View()
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

func TestInviteShortcutShowsFullScreenPlainInvite(t *testing.T) {
	invite := "npx -y derpssh@latest connect DSH1verysecretinvitetoken1234567890"
	app := NewApp(Options{Side: "host", InviteCommand: invite, Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 40, Height: 12})

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})

	view := app.View()
	if !strings.Contains(view, invite) {
		t.Fatalf("invite view missing full command:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, invite) {
			continue
		}
		if visibleWidth(line) > 40 {
			t.Fatalf("invite line width = %d, want <= 40: %q", visibleWidth(line), line)
		}
	}
	if strings.Contains(view, "\x1b[") {
		t.Fatalf("invite view contains ANSI styling:\n%q", view)
	}
	if strings.Contains(view, "shell$") || strings.Contains(view, "Sidechat") {
		t.Fatalf("invite view did not replace main TUI:\n%s", view)
	}
}

func TestChatPaneUsesChatLabelAndWrapsMessages(t *testing.T) {
	app := NewApp(Options{Side: "guest", DisplayName: "shayne", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 72, Height: 12})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	app.Update(ChatMsg{Author: "eric@Erics-mini.local", Body: "this message should wrap instead of disappearing off the side of the chat pane"})

	view := app.View()
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

func TestChatAutoScrollsToNewestMessages(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 9})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	for i := 0; i < 12; i++ {
		app.Update(ChatMsg{Author: "alex", Body: "message " + intStringForTest(i)})
	}

	view := app.View()
	if strings.Contains(view, "message 0") {
		t.Fatalf("chat did not scroll away from oldest message:\n%s", view)
	}
	if !strings.Contains(view, "message 11") {
		t.Fatalf("chat did not auto-scroll to newest message:\n%s", view)
	}
}

func TestClosedChatShowsUnreadNotification(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(ChatMsg{Author: "alex", Body: "ping"})

	view := app.View()
	if !strings.Contains(strings.Split(view, "\n")[0], "1 new") || !strings.Contains(view, "Ctrl-X S") {
		t.Fatalf("closed chat missing unread top-bar notification:\n%s", view)
	}
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if strings.Contains(strings.Split(app.View(), "\n")[0], "1 new") {
		t.Fatalf("unread notification did not clear after opening chat:\n%s", app.View())
	}
}

func TestTransportStatusIsReducedToPath(t *testing.T) {
	app := NewApp(Options{Side: "guest", Terminal: &fakePane{view: "ok"}})
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 20})

	app.Update(RuntimeStateMsg{Transport: "connected-relay"})

	view := app.View()
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

	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	app.View()

	if pane.cursorActive {
		t.Fatalf("terminal cursor active while chat is focused")
	}
}

func TestInviteScreenEscapeReturnsToTerminal(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "npx -y derpssh@latest connect DSH1test", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})

	app.Update(tea.KeyMsg{Type: tea.KeyEsc})

	view := app.View()
	if !strings.Contains(view, "shell$") {
		t.Fatalf("Esc did not return to terminal view:\n%s", view)
	}
	if strings.Contains(view, "npx -y derpssh@latest connect") {
		t.Fatalf("invite command still visible after Esc:\n%s", view)
	}
}

func TestInviteScreenQEmitsQuit(t *testing.T) {
	app := NewApp(Options{Side: "host", InviteCommand: "npx -y derpssh@latest connect DSH1test", Terminal: &fakePane{view: "shell$"}})
	app.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	drainCommands(app)
	app.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})

	app.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	if _, ok := readCommandEventually(t, app).(QuitCommand); !ok {
		t.Fatalf("invite q did not emit QuitCommand")
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

	for i, line := range strings.Split(app.View(), "\n") {
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

	for i, line := range strings.Split(app.View(), "\n") {
		if got := visibleWidth(line); got > 11 {
			t.Fatalf("line %d cell width = %d, want <= 11: %q", i+1, got, line)
		}
	}
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func visibleWidth(line string) int {
	return runewidth.StringWidth(ansiPattern.ReplaceAllString(line, ""))
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
