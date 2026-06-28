// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/tui"
)

func TestTUIConsoleWriteSendsTerminalData(t *testing.T) {
	pane := &recordingTerminalPane{}
	console := newHeadlessTUIConsole(tui.ModeGuest, 100, 30, pane)

	n, err := console.Write([]byte("ready\n"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len("ready\n") {
		t.Fatalf("Write() = %d, want %d", n, len("ready\n"))
	}
	if got := string(pane.writes); got != "ready\n" {
		t.Fatalf("terminal writes = %q, want ready newline", got)
	}
}

func TestTUIConsoleSendBeforeStartDoesNotCallProgramSend(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	program := &sendBeforeRunProgram{}
	console.program = program

	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "waiting for host approval"})

	if program.sends != 0 {
		t.Fatalf("Program.Send called %d time(s) before Run", program.sends)
	}
	if view := console.View(); !strings.Contains(view, "waiting approval") {
		t.Fatalf("console view missing startup status:\n%s", view)
	}
}

func TestTUIConsoleStopBeforeStartDoesNotQuitProgram(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	program := newBlockingQuitProgram()
	console.program = program

	done := make(chan struct{})
	go func() {
		console.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-program.quitEntered:
		program.releaseQuit()
		t.Fatal("Stop called Program.Quit before Start")
	case <-time.After(time.Second):
		program.releaseQuit()
		t.Fatal("Stop blocked before Start")
	}
}

func TestTUIConsoleApprovalStatusClearsWhenRoleGranted(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeGuest, 100, 30, &recordingTerminalPane{view: "shell$"})

	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "waiting for host approval"})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventRole, Role: protocol.RoleWrite})

	view := console.View()
	if strings.Contains(view, "waiting for host approval") {
		t.Fatalf("view still shows stale approval status after role grant:\n%s", view)
	}
	if !strings.Contains(view, "write") || !strings.Contains(view, "connected") {
		t.Fatalf("view missing granted role/approval state:\n%s", view)
	}
}

func TestTUIConsoleGuestPendingStatusClearsWhenPeerApproved(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})

	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "guest pending"})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-1",
		DisplayName:   "shayne",
		Role:          protocol.RoleWrite,
	})

	view := console.View()
	if strings.Contains(view, "guest pending") {
		t.Fatalf("view still shows stale pending status after peer approval:\n%s", view)
	}
	if !strings.Contains(view, "connected") || !strings.Contains(view, "shayne/write") {
		t.Fatalf("view missing connected peer state:\n%s", view)
	}
}

func TestTUIConsoleHostCloseEventClearsPeerAndShowsNotice(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-1",
		DisplayName:   "shayne",
		Role:          protocol.RoleWrite,
	})

	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventClose,
		ParticipantID: "guest-1",
		DisplayName:   "shayne",
		Message:       "guest quit",
	})

	view := console.View()
	if !strings.Contains(view, "Guest left") || !strings.Contains(view, "guest quit") {
		t.Fatalf("view missing guest-left notice:\n%s", view)
	}
	if strings.Contains(strings.Split(view, "\n")[0], "shayne/write") {
		t.Fatalf("top bar still shows departed peer:\n%s", view)
	}
}

func TestTUIConsoleProgramRequiresInputAndOutputTTY(t *testing.T) {
	stdin, stdout := openPipeFiles(t)
	oldIsTerminalFD := isTerminalFD
	oldNewTeaProgram := newTeaProgram
	defer func() {
		isTerminalFD = oldIsTerminalFD
		newTeaProgram = oldNewTeaProgram
	}()
	created := 0
	newTeaProgram = func(tea.Model, ...tea.ProgramOption) teaProgram {
		created++
		return &sendBeforeRunProgram{}
	}

	isTerminalFD = func(fd uintptr) bool {
		return fd == stdout.Fd()
	}
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdin:    stdin,
		Stdout:   stdout,
		Terminal: &recordingTerminalPane{},
	})
	if console.program != nil || console.tty {
		t.Fatal("console created Bubble Tea program when only stdout was a TTY")
	}
	if created != 0 {
		t.Fatalf("program factory calls = %d, want 0", created)
	}

	isTerminalFD = func(fd uintptr) bool {
		return fd == stdin.Fd() || fd == stdout.Fd()
	}
	console = newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdin:    stdin,
		Stdout:   stdout,
		Terminal: &recordingTerminalPane{},
	})
	if console.program == nil || !console.tty {
		t.Fatal("console did not create Bubble Tea program when stdin and stdout were TTYs")
	}
	if created != 1 {
		t.Fatalf("program factory calls = %d, want 1", created)
	}
}

func TestTUIConsoleProgramDispatcherDoesNotBlockCallerAndPreservesOrder(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	program := newRunGatedProgram()
	console.program = program

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	console.Start(ctx)

	done := make(chan struct{})
	go func() {
		console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "first"})
		console.OnRuntimeEvent(RuntimeEvent{
			Kind: RuntimeEventChat,
			Chat: ChatMessage{ParticipantID: "guest-1", DisplayName: "Alex", Text: "second"},
		})
		close(done)
	}()

	select {
	case <-time.After(25 * time.Millisecond):
		t.Fatal("send path blocked while Program.Send was waiting for Run")
	case <-done:
	}
	select {
	case msg := <-program.sends:
		t.Fatalf("Program.Send delivered before Run began with %T", msg)
	default:
	}
	close(program.allowRun)

	select {
	case msg := <-program.sends:
		if _, ok := msg.(tui.RuntimeStateMsg); !ok {
			t.Fatalf("first Program.Send message = %T, want RuntimeStateMsg", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("first Program.Send was not called after Run began")
	}
	select {
	case msg := <-program.sends:
		if _, ok := msg.(tui.ChatMsg); !ok {
			t.Fatalf("second Program.Send message = %T, want ChatMsg", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("second Program.Send was not called after Run began")
	}
}

func TestTUIConsoleNonTTYTranscriptWritesSnapshots(t *testing.T) {
	var out strings.Builder
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeGuest,
		Cols:     100,
		Rows:     30,
		Stdout:   &out,
		Terminal: &recordingTerminalPane{view: "shell$"},
	})

	if _, err := console.Write([]byte("ready\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "connected-relay"})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventRole, Role: protocol.RoleWrite})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind: RuntimeEventChat,
		Chat: ChatMessage{ParticipantID: "guest-1", DisplayName: "Alex", Text: "hello"},
	})

	transcript := out.String()
	for _, want := range []string{
		"derpssh transcript",
		"terminal: ready",
		"status: connected-relay",
		"role: write",
		"chat: Alex: hello",
	} {
		if !strings.Contains(transcript, want) {
			t.Fatalf("transcript missing %q:\n%s", want, transcript)
		}
	}
	if strings.Contains(transcript, "terminal\n-----") || strings.Contains(transcript, "sidechat\n-----") {
		t.Fatalf("transcript uses old section dashboard:\n%s", transcript)
	}
}

func TestTUIConsoleCopyInviteWritesOSC52(t *testing.T) {
	var out strings.Builder
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &out,
		Terminal: &recordingTerminalPane{view: "shell$"},
	})

	console.handleCommand(context.Background(), tui.CopyInviteCommand{Command: "npx -y derpssh@latest connect DSH1copyme"})

	got := out.String()
	if !strings.HasPrefix(got, "\x1b]52;c;") || !strings.HasSuffix(got, "\x07") {
		t.Fatalf("OSC52 output malformed: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("OSC52 output contains newline: %q", got)
	}
}

func TestTUIConsoleNonTTYApprovalDeniesWithoutEnv(t *testing.T) {
	var out strings.Builder
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &out,
		Terminal: &recordingTerminalPane{view: "shell$"},
	})

	if got := console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleDenied)
	}
	if transcript := out.String(); !strings.Contains(transcript, "approval denied: Alex") {
		t.Fatalf("transcript missing approval denial:\n%s", transcript)
	}
}

func TestTUIConsoleNonTTYHarnessActionsCallCallbacks(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_HOST_ACTIONS", strings.Join([]string{
		`input whoami\n`,
		"chat hello there",
		"role guest-1 write",
		"kick guest-1",
	}, "\n"))
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	var calls recordedConsoleCalls
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		TerminalInput: func(_ context.Context, data []byte) error {
			calls.setTerminalInput(data)
			return nil
		},
		Chat: func(_ context.Context, body string) error {
			calls.setChat(body)
			return nil
		},
		RoleChange: func(_ context.Context, peerID string, role protocol.Role) error {
			calls.setRole(peerID, role)
			return nil
		},
		Kick: func(_ context.Context, peerID string, reason string) error {
			calls.setKick(peerID, reason)
			return nil
		},
	})

	console.Start(context.Background())

	want := expectedConsoleCalls{
		terminalInput: []byte("whoami\n"),
		chat:          "hello there",
		rolePeerID:    "guest-1",
		role:          protocol.RoleWrite,
		kickPeerID:    "guest-1",
		kickReason:    "kicked",
	}
	waitForConsoleCalls(t, &calls, want)
}

func TestTUIConsoleHarnessQuitActionCallsCallback(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_HOST_ACTIONS", strings.Join([]string{
		"sleep 1ms",
		"quit",
	}, "\n"))
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	called := make(chan struct{}, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		Quit: func(context.Context) error {
			called <- struct{}{}
			return nil
		},
	})
	console.Start(context.Background())

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("harness quit action did not call Quit callback")
	}
}

func TestTUIConsoleHarnessActionsWaitForCallbacksAfterStart(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_HOST_ACTIONS", "chat after-bind")
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})

	console.Start(context.Background())
	time.Sleep(25 * time.Millisecond)

	called := make(chan string, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		Chat: func(_ context.Context, body string) error {
			called <- body
			return nil
		},
	})

	select {
	case got := <-called:
		if got != "after-bind" {
			t.Fatalf("chat callback = %q, want after-bind", got)
		}
	case <-time.After(time.Second):
		t.Fatal("harness action did not run after callbacks were bound")
	}
}

func TestTUIConsoleHarnessActionsRunAsyncWhenCallbacksBoundBeforeStart(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_HOST_ACTIONS", "input blocking")
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		TerminalInput: func(context.Context, []byte) error {
			close(entered)
			<-release
			return nil
		},
	})

	started := make(chan struct{})
	go func() {
		console.Start(context.Background())
		close(started)
	}()

	select {
	case <-started:
	case <-time.After(25 * time.Millisecond):
		t.Fatal("Start blocked behind harness action callback")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("harness action did not run after Start")
	}
	close(release)
}

func TestTUIConsoleHarnessActionsRequireOptIn(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HOST_ACTIONS", "input ignored")
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	called := make(chan []byte, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		TerminalInput: func(_ context.Context, data []byte) error {
			called <- append([]byte(nil), data...)
			return nil
		},
	})

	console.Start(context.Background())

	select {
	case data := <-called:
		t.Fatalf("test harness action ran without opt-in: %q", string(data))
	case <-time.After(25 * time.Millisecond):
	}
}

func TestTUIConsoleGuestHarnessActionsRequireOptIn(t *testing.T) {
	t.Setenv("DERPSSH_TEST_GUEST_ACTIONS", "chat ignored")
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeGuest,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	called := make(chan string, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		Chat: func(_ context.Context, body string) error {
			called <- body
			return nil
		},
	})

	console.Start(context.Background())

	select {
	case body := <-called:
		t.Fatalf("guest test harness action ran without opt-in: %q", body)
	case <-time.After(25 * time.Millisecond):
	}

	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	console = newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeGuest,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})
	called = make(chan string, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		Chat: func(_ context.Context, body string) error {
			called <- body
			return nil
		},
	})
	console.Start(context.Background())

	select {
	case body := <-called:
		if body != "ignored" {
			t.Fatalf("guest test harness action = %q, want ignored", body)
		}
	case <-time.After(time.Second):
		t.Fatal("guest test harness action did not run with opt-in")
	}
}

func TestTUIConsoleRuntimeEventsUpdateApp(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 140, 30, &recordingTerminalPane{view: "shell$"})

	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "connected-relay"})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
		Role:          protocol.RoleRead,
	})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-2",
		DisplayName:   "Blair",
		Role:          protocol.RoleDenied,
	})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventRole, Role: protocol.RoleWrite})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, Cols: 120, Rows: 40})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind: RuntimeEventChat,
		Chat: ChatMessage{ParticipantID: "guest-1", DisplayName: "Alex", Text: "hello"},
	})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventClose, Message: "done"})
	console.send(tea.KeyMsg{Type: tea.KeyCtrlX})
	console.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})

	view := console.View()
	for _, want := range []string{"closed: done", "120x40", "write", "Alex", "read", "Blair", "denied", "Alex: hello"} {
		if !strings.Contains(view, want) {
			t.Fatalf("console view missing %q:\n%s", want, view)
		}
	}
}

func TestTUIConsoleIgnoresParticipantResizeForHostSize(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeGuest, 140, 30, &recordingTerminalPane{view: "shell$"})

	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, Cols: 101, Rows: 30})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, ParticipantID: "guest-1", Cols: 68, Rows: 29})

	firstLine := strings.Split(console.View(), "\n")[0]
	if !strings.Contains(firstLine, "101x30") {
		t.Fatalf("header missing host size after participant resize:\n%s", firstLine)
	}
	if strings.Contains(firstLine, "68x29") {
		t.Fatalf("header used guest-local size instead of host size:\n%s", firstLine)
	}
}

func TestTUIConsolePeerUpdatePreservesDisplayName(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 140, 30, &recordingTerminalPane{view: "shell$"})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
		Role:          protocol.RoleRead,
	})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind:          RuntimeEventPeer,
		ParticipantID: "guest-1",
		Role:          protocol.RoleWrite,
	})

	view := console.View()
	if !strings.Contains(view, "Alex/write") {
		t.Fatalf("view missing preserved peer display name and updated role:\n%s", view)
	}
	if strings.Contains(view, "guest-1/write") {
		t.Fatalf("partial peer event replaced display name with ID:\n%s", view)
	}
}

func TestTUIConsoleApprovalWaitsForDecision(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	done := make(chan protocol.Role, 1)
	go func() {
		done <- console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"})
	}()

	waitForView(t, console, "Alex wants to join")
	console.handleCommand(context.Background(), tui.ApprovalDecisionCommand{
		PeerID: "other-guest",
		Peer:   "Other",
		Role:   tui.RoleRead,
	})
	select {
	case got := <-done:
		t.Fatalf("Approve returned for mismatched peer with role %q", got)
	case <-time.After(25 * time.Millisecond):
	}

	console.handleCommand(context.Background(), tui.ApprovalDecisionCommand{
		PeerID: "guest-1",
		Peer:   "Alex",
		Role:   tui.RoleWrite,
	})
	select {
	case got := <-done:
		if got != protocol.RoleWrite {
			t.Fatalf("Approve() = %q, want %q", got, protocol.RoleWrite)
		}
	case <-time.After(time.Second):
		t.Fatal("Approve did not return after matching approval decision")
	}
}

func TestTUIConsoleApprovalStopReturnsDenied(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	done := make(chan protocol.Role, 1)
	go func() {
		done <- console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"})
	}()

	waitForView(t, console, "Alex wants to join")
	console.Stop()

	assertApprovalRole(t, done, protocol.RoleDenied)
}

func TestTUIConsoleApprovalContextCancelReturnsDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{view: "shell$"})
	console.Start(ctx)
	done := make(chan protocol.Role, 1)
	go func() {
		done <- console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"})
	}()

	waitForView(t, console, "Alex wants to join")
	cancel()

	assertApprovalRole(t, done, protocol.RoleDenied)
}

func TestTUIConsoleApprovalEnvBypassesUIWait(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "read")
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &blockingTerminalPane{})

	if got := console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleRead {
		t.Fatalf("Approve(test env) = %q, want %q", got, protocol.RoleRead)
	}
}

func TestTUIConsoleApprovalEnvRequiresHarness(t *testing.T) {
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "read")
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:     tui.ModeHost,
		Cols:     100,
		Rows:     30,
		Stdout:   &strings.Builder{},
		Terminal: &recordingTerminalPane{},
	})

	if got := console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve(test env without harness) = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestTUIConsoleCommandsCallCallbacks(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 100, 30, &recordingTerminalPane{})
	var calls recordedConsoleCalls
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		TerminalInput: func(_ context.Context, data []byte) error {
			calls.setTerminalInput(data)
			return nil
		},
		Chat: func(_ context.Context, body string) error {
			calls.setChat(body)
			return nil
		},
		RoleChange: func(_ context.Context, peerID string, role protocol.Role) error {
			calls.setRole(peerID, role)
			return nil
		},
		Kick: func(_ context.Context, peerID string, reason string) error {
			calls.setKick(peerID, reason)
			return nil
		},
		Resize: func(_ context.Context, cols int, rows int) error {
			calls.setResize(cols, rows)
			return nil
		},
	})

	console.handleCommand(context.Background(), tui.TerminalInputCommand{Data: []byte("whoami\n")})
	console.handleCommand(context.Background(), tui.ChatSendCommand{Body: "hello"})
	console.handleCommand(context.Background(), tui.RoleChangeCommand{PeerID: "guest-1", Peer: "Alex", Role: tui.RoleWrite})
	console.handleCommand(context.Background(), tui.KickCommand{PeerID: "guest-1", Peer: "Alex"})
	console.handleCommand(context.Background(), tui.TerminalResizeCommand{Cols: 67, Rows: 28})

	if got := string(calls.terminalInput); got != "whoami\n" {
		t.Fatalf("terminal input callback = %q, want whoami newline", got)
	}
	if calls.chat != "hello" {
		t.Fatalf("chat callback = %q, want hello", calls.chat)
	}
	if calls.rolePeerID != "guest-1" || calls.role != protocol.RoleWrite {
		t.Fatalf("role callback = (%q, %q), want (guest-1, write)", calls.rolePeerID, calls.role)
	}
	if calls.kickPeerID != "guest-1" || calls.kickReason != "kicked" {
		t.Fatalf("kick callback = (%q, %q), want (guest-1, kicked)", calls.kickPeerID, calls.kickReason)
	}
	if calls.resizeCols != 67 || calls.resizeRows != 28 {
		t.Fatalf("resize callback = %dx%d, want 67x28", calls.resizeCols, calls.resizeRows)
	}
}

func TestHostConsoleCallbacksSendChat(t *testing.T) {
	host := NewHostRuntime(HostConfig{HostID: "host-1", HostName: "host"})
	hostConn, peerConn := net.Pipe()
	defer func() {
		_ = hostConn.Close()
		_ = peerConn.Close()
	}()
	host.chatReady <- hostConn

	errCh := make(chan error, 1)
	go func() {
		errCh <- hostConsoleCallbacks(host).Chat(context.Background(), "host-side")
	}()

	msg, err := protocol.ReadFrame(peerConn)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if msg.Type != protocol.MessageChat || msg.Chat == nil {
		t.Fatalf("message = %+v, want chat", msg)
	}
	if msg.Chat.Text != "host-side" || msg.Chat.DisplayName != "host" {
		t.Fatalf("chat = %+v, want host-side from host", msg.Chat)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("chat callback error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("chat callback did not return")
	}
}

type recordingTerminalPane struct {
	writes []byte
	cols   int
	rows   int
	view   string
}

func (p *recordingTerminalPane) Write(b []byte) (int, error) {
	p.writes = append(p.writes, b...)
	if p.view == "" {
		p.view = string(p.writes)
	}
	return len(b), nil
}

func (p *recordingTerminalPane) Resize(cols int, rows int) {
	p.cols = cols
	p.rows = rows
}

func (p *recordingTerminalPane) View(width int, height int) string {
	if p.view == "" {
		return strings.Repeat(" ", width)
	}
	return p.view
}

func (p *recordingTerminalPane) MouseMode() tui.MouseMode {
	return tui.MouseMode{}
}

func (p *recordingTerminalPane) InputMode() tui.TerminalInputMode {
	return tui.TerminalInputMode{}
}

type blockingTerminalPane struct{}

func (p *blockingTerminalPane) Write([]byte) (int, error) { panic("unexpected terminal write") }
func (p *blockingTerminalPane) Resize(int, int)           {}
func (p *blockingTerminalPane) View(int, int) string      { return "" }
func (p *blockingTerminalPane) MouseMode() tui.MouseMode  { return tui.MouseMode{} }
func (p *blockingTerminalPane) InputMode() tui.TerminalInputMode {
	return tui.TerminalInputMode{}
}

type recordedConsoleCalls struct {
	mu            sync.Mutex
	terminalInput []byte
	chat          string
	rolePeerID    string
	role          protocol.Role
	kickPeerID    string
	kickReason    string
	resizeCols    int
	resizeRows    int
}

type sendBeforeRunProgram struct {
	sends int
}

func (p *sendBeforeRunProgram) Send(tea.Msg) {
	p.sends++
}

func (p *sendBeforeRunProgram) Run() (tea.Model, error) {
	return nil, nil
}

func (p *sendBeforeRunProgram) Quit() {}

type runGatedProgram struct {
	allowRun   chan struct{}
	runEntered chan struct{}
	sends      chan tea.Msg
	quit       chan struct{}
}

func newRunGatedProgram() *runGatedProgram {
	return &runGatedProgram{
		allowRun:   make(chan struct{}),
		runEntered: make(chan struct{}),
		sends:      make(chan tea.Msg, 4),
		quit:       make(chan struct{}),
	}
}

func (p *runGatedProgram) Send(msg tea.Msg) {
	<-p.runEntered
	p.sends <- msg
}

func (p *runGatedProgram) Run() (tea.Model, error) {
	<-p.allowRun
	close(p.runEntered)
	<-p.quit
	return nil, nil
}

func (p *runGatedProgram) Quit() {
	select {
	case <-p.quit:
	default:
		close(p.quit)
	}
}

type blockingQuitProgram struct {
	quitEntered chan struct{}
	release     chan struct{}
	once        sync.Once
}

func newBlockingQuitProgram() *blockingQuitProgram {
	return &blockingQuitProgram{
		quitEntered: make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (p *blockingQuitProgram) Send(tea.Msg) {}

func (p *blockingQuitProgram) Run() (tea.Model, error) {
	return nil, nil
}

func (p *blockingQuitProgram) Quit() {
	p.once.Do(func() {
		close(p.quitEntered)
	})
	<-p.release
}

func (p *blockingQuitProgram) releaseQuit() {
	select {
	case <-p.release:
	default:
		close(p.release)
	}
}

func openPipeFiles(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	stdin, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	stdoutReader, stdout, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdinWriter.Close()
		t.Fatalf("create stdout pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = stdout.Close()
	})
	return stdin, stdout
}

func (c *recordedConsoleCalls) setTerminalInput(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.terminalInput = append([]byte(nil), data...)
}

func (c *recordedConsoleCalls) setChat(body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chat = body
}

func (c *recordedConsoleCalls) setRole(peerID string, role protocol.Role) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rolePeerID = peerID
	c.role = role
}

func (c *recordedConsoleCalls) setKick(peerID string, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kickPeerID = peerID
	c.kickReason = reason
}

func (c *recordedConsoleCalls) setResize(cols int, rows int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resizeCols = cols
	c.resizeRows = rows
}

func waitForView(t *testing.T, console *tuiConsole, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(console.View(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("view never contained %q:\n%s", want, console.View())
}

func assertApprovalRole(t *testing.T, done <-chan protocol.Role, want protocol.Role) {
	t.Helper()
	select {
	case got := <-done:
		if got != want {
			t.Fatalf("Approve() = %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("Approve() did not return %q before timeout", want)
	}
}

type expectedConsoleCalls struct {
	terminalInput []byte
	chat          string
	rolePeerID    string
	role          protocol.Role
	kickPeerID    string
	kickReason    string
}

func waitForConsoleCalls(t *testing.T, calls *recordedConsoleCalls, want expectedConsoleCalls) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		calls.mu.Lock()
		got := expectedConsoleCalls{
			terminalInput: append([]byte(nil), calls.terminalInput...),
			chat:          calls.chat,
			rolePeerID:    calls.rolePeerID,
			role:          calls.role,
			kickPeerID:    calls.kickPeerID,
			kickReason:    calls.kickReason,
		}
		calls.mu.Unlock()
		if reflect.DeepEqual(got.terminalInput, want.terminalInput) &&
			got.chat == want.chat &&
			got.rolePeerID == want.rolePeerID &&
			got.role == want.role &&
			got.kickPeerID == want.kickPeerID &&
			got.kickReason == want.kickReason {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	t.Fatalf("callbacks = input %q chat %q role (%q,%q) kick (%q,%q)",
		string(calls.terminalInput), calls.chat, calls.rolePeerID, calls.role, calls.kickPeerID, calls.kickReason)
}
