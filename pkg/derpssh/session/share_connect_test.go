// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derptun"
	appsession "github.com/shayne/derphole/pkg/session"
)

func TestInviteRoundTrip(t *testing.T) {
	encoded, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	if !strings.HasPrefix(encoded, InvitePrefix) {
		t.Fatalf("invite = %q, want %s prefix", encoded, InvitePrefix)
	}
	decoded, err := DecodeInvite(encoded)
	if err != nil {
		t.Fatalf("DecodeInvite() error = %v", err)
	}
	if decoded.ClientToken != "dtc1_test" {
		t.Fatalf("ClientToken = %q, want dtc1_test", decoded.ClientToken)
	}
}

func TestDecodeInviteRejectsWrongPrefix(t *testing.T) {
	if _, err := DecodeInvite("DT1test"); err == nil {
		t.Fatal("DecodeInvite(wrong prefix) error = nil, want error")
	}
}

func TestDecodeInviteRejectsEmptyClientToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":""}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(empty client token) error = nil, want error")
	}
}

func TestDecodeInviteRejectsNonClientTokenPrefix(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":"not-a-client-token"}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(non-client token) error = nil, want error")
	}
}

func TestTerminalShareApprovalDeniesByDefault(t *testing.T) {
	approval := newTerminalShareApproval(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stderr: io.Discard,
	})
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve(EOF) = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestShareAutoApproveEnvSkipsPrompt(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "write")
	approval := newTerminalShareApproval(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stderr: io.Discard,
	})
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleWrite {
		t.Fatalf("Approve(test auto approve) = %q, want %q", got, protocol.RoleWrite)
	}
}

func TestShareAutoApproveEnvRequiresHarness(t *testing.T) {
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "write")
	approval := newTerminalShareApproval(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stderr: io.Discard,
	})
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve(test auto approve without harness) = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestShareTestCommandBacksHostTerminal(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_COMMAND", `read line; printf input:%s "$line"`)

	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldStartPTY := startPTY
	oldNewApproval := newShareApproval
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		startPTY = oldStartPTY
		newShareApproval = oldNewApproval
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	startPTY = func(pty.StartConfig) (*pty.Session, error) {
		t.Fatal("startPTY called for DERPSSH_TEST_COMMAND")
		return nil, nil
	}
	newShareApproval = func(ShareConfig) Approval {
		return StaticApproval{Role: protocol.RoleWrite}
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		return cfg.OnMux(ctx, nil)
	}
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = bindConsole
		_ = ctx
		if _, err := io.WriteString(cfg.PTYInput, "hello\n"); err != nil {
			t.Fatalf("write command input: %v", err)
		}
		if closer, ok := cfg.PTYInput.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				t.Fatalf("close command input: %v", err)
			}
		}
		raw, err := io.ReadAll(cfg.PTYOutput)
		if err != nil {
			t.Fatalf("read command output: %v", err)
		}
		if got := string(raw); got != "input:hello" {
			t.Fatalf("command output = %q, want input:hello", got)
		}
		return errors.New("stop")
	}

	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Share() error = %v, want stop", err)
	}
}

func TestShareTestCommandRequiresHarness(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", `printf ignored`)

	oldStartPTY := startPTY
	defer func() { startPTY = oldStartPTY }()
	sentinel := errors.New("pty sentinel")
	called := 0
	startPTY = func(pty.StartConfig) (*pty.Session, error) {
		called++
		return nil, sentinel
	}

	terminal, err := startShareTerminal(pty.Size{Cols: 80, Rows: 24})
	if terminal != nil {
		_ = terminal.Close()
		_ = terminal.Wait()
	}
	if called != 1 {
		t.Fatalf("DERPSSH_TEST_COMMAND was honored without harness; startPTY calls = %d, want 1", called)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("startShareTerminal() error = %v, want %v", err, sentinel)
	}
}

func TestStartShareTerminalUsesRichTermFallback(t *testing.T) {
	t.Setenv("TERM", "dumb")

	oldStartPTY := startPTY
	defer func() { startPTY = oldStartPTY }()
	var got pty.StartConfig
	startPTY = func(cfg pty.StartConfig) (*pty.Session, error) {
		got = cfg
		return nil, errors.New("stop")
	}

	terminal, err := startShareTerminal(pty.Size{Cols: 80, Rows: 24})
	if terminal != nil {
		_ = terminal.Close()
		_ = terminal.Wait()
	}
	if err == nil || err.Error() != "stop" {
		t.Fatalf("startShareTerminal() error = %v, want stop", err)
	}
	if got.Term != "xterm-256color" {
		t.Fatalf("StartConfig.Term = %q, want xterm-256color fallback", got.Term)
	}
}

func TestStartShareTerminalPreservesCapableParentTerm(t *testing.T) {
	t.Setenv("TERM", "xterm-kitty")

	oldStartPTY := startPTY
	defer func() { startPTY = oldStartPTY }()
	var got pty.StartConfig
	startPTY = func(cfg pty.StartConfig) (*pty.Session, error) {
		got = cfg
		return nil, errors.New("stop")
	}

	terminal, err := startShareTerminal(pty.Size{Cols: 80, Rows: 24})
	if terminal != nil {
		_ = terminal.Close()
		_ = terminal.Wait()
	}
	if err == nil || err.Error() != "stop" {
		t.Fatalf("startShareTerminal() error = %v, want stop", err)
	}
	if got.Term != "" {
		t.Fatalf("StartConfig.Term = %q, want parent TERM preserved by pty.Start", got.Term)
	}
}

func TestShareRunsInvitePreflightBeforeTerminal(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldShowPreflight := showShareInvitePreflight
	oldStartPTY := startPTY
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		showShareInvitePreflight = oldShowPreflight
		startPTY = oldStartPTY
	}()

	sentinel := errors.New("preflight sentinel")
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	showShareInvitePreflight = func(stdin io.Reader, stdout io.Writer, command string) (bool, error) {
		if !strings.Contains(command, "npx -y derpssh@latest connect DSH1") {
			t.Fatalf("preflight command = %q, want derpssh connect invite", command)
		}
		return true, sentinel
	}
	startPTY = func(pty.StartConfig) (*pty.Session, error) {
		t.Fatal("startPTY called before preflight completed")
		return nil, nil
	}

	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Share() error = %v, want %v", err, sentinel)
	}
}

func TestInvitePreflightScreenContainsPlainFullCommand(t *testing.T) {
	command := "npx -y derpssh@latest connect DSH1verysecretinvitetoken1234567890"
	screen := invitePreflightScreen(command)
	if !strings.Contains(screen, command) {
		t.Fatalf("preflight screen missing full command:\n%s", screen)
	}
	if strings.Contains(screen, "\x1b[") {
		t.Fatalf("preflight screen contains ANSI styling:\n%q", screen)
	}
}

func TestReadInvitePreflightInputContinuesOnEnter(t *testing.T) {
	shown, err := readInvitePreflightInput(strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("readInvitePreflightInput() error = %v", err)
	}
	if !shown {
		t.Fatal("readInvitePreflightInput() shown = false, want true")
	}
}

func TestReadInvitePreflightInputQuitsOnQ(t *testing.T) {
	shown, err := readInvitePreflightInput(strings.NewReader("q"))
	if !errors.Is(err, errInvitePreflightQuit) {
		t.Fatalf("readInvitePreflightInput() error = %v, want invite quit", err)
	}
	if !shown {
		t.Fatal("readInvitePreflightInput() shown = false, want true")
	}
}

func TestReadInvitePreflightInputQuitsOnCtrlC(t *testing.T) {
	shown, err := readInvitePreflightInput(strings.NewReader("\x03"))
	if !errors.Is(err, errInvitePreflightQuit) {
		t.Fatalf("readInvitePreflightInput() error = %v, want invite quit", err)
	}
	if !shown {
		t.Fatal("readInvitePreflightInput() shown = false, want true")
	}
}

func TestWaitingShareConsoleBuffersChatUntilHostCallbacks(t *testing.T) {
	pending := newPendingShareChats()
	callbacks := waitingShareConsoleCallbacks(nil, func() {}, pending)

	if err := callbacks.Chat(context.Background(), "host-side"); err != nil {
		t.Fatalf("waiting Chat() error = %v", err)
	}

	var got []string
	pending.flush(context.Background(), func(ctx context.Context, body string) error {
		_ = ctx
		got = append(got, body)
		return nil
	})
	if len(got) != 1 || got[0] != "host-side" {
		t.Fatalf("flushed chats = %#v, want host-side", got)
	}
}

func TestShareStartsTerminalBeforeGuestMux(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldStartPTY := startPTY
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		startPTY = oldStartPTY
	}()

	sentinel := errors.New("pty start sentinel")
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	startPTY = func(pty.StartConfig) (*pty.Session, error) {
		return nil, sentinel
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := Share(ctx, ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Share() error = %v, want %v", err, sentinel)
	}
}

func TestShareRendersHostTerminalBeforeGuestMux(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_COMMAND", `printf ready; sleep 10`)

	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newStringCapture()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Share(ctx, ShareConfig{Stdin: strings.NewReader(""), Stdout: stdout, Stderr: io.Discard})
	}()

	waitForString(t, ctx, stdout.String, "terminal: ready")
	cancel()
	<-errCh
}

func TestShareUsesApprovalSeam(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldStartPTY := startPTY
	oldNewApproval := newShareApproval
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		startPTY = oldStartPTY
		newShareApproval = oldNewApproval
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	startPTY = func(pty.StartConfig) (*pty.Session, error) { return &pty.Session{}, nil }
	newShareApproval = func(ShareConfig) Approval {
		return StaticApproval{Role: protocol.RoleRead}
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		return cfg.OnMux(ctx, nil)
	}
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = bindConsole
		_ = ctx
		if got := cfg.Approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleRead {
			t.Fatalf("approval role = %q, want %q", got, protocol.RoleRead)
		}
		return errors.New("stop")
	}

	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Share() error = %v, want stop", err)
	}
}

func TestShareDoesNotPassStdinToHostLocalInputWhenUsingTUI(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_COMMAND", `printf ready`)

	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldNewApproval := newShareApproval
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		newShareApproval = oldNewApproval
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	newShareApproval = func(ShareConfig) Approval {
		return StaticApproval{Role: protocol.RoleRead}
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		return cfg.OnMux(ctx, nil)
	}
	stdin := strings.NewReader("whoami\n")
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = bindConsole
		_ = ctx
		if cfg.LocalInput == stdin {
			t.Fatal("HostConfig.LocalInput is original stdin; TUI should own interactive input")
		}
		if _, ok := cfg.LocalInput.(emptyReader); !ok {
			t.Fatalf("HostConfig.LocalInput = %T, want emptyReader", cfg.LocalInput)
		}
		return errors.New("stop")
	}

	err := Share(context.Background(), ShareConfig{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Share() error = %v, want stop", err)
	}
}

func TestShareStartsPTYAtTerminalPaneSize(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldStartPTY := startPTY
	oldNewApproval := newShareApproval
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		startPTY = oldStartPTY
		newShareApproval = oldNewApproval
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return "dtc1_test", nil }
	var startedSize pty.Size
	startPTY = func(cfg pty.StartConfig) (*pty.Session, error) {
		startedSize = cfg.Size
		return &pty.Session{}, nil
	}
	newShareApproval = func(ShareConfig) Approval {
		return StaticApproval{Role: protocol.RoleRead}
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		return cfg.OnMux(ctx, nil)
	}
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = bindConsole
		_ = ctx
		if startedSize != (pty.Size{Cols: 80, Rows: 22}) {
			t.Fatalf("started PTY size = %+v, want 80x22 terminal pane", startedSize)
		}
		if cfg.InitialCols != 80 || cfg.InitialRows != 22 {
			t.Fatalf("HostConfig initial size = %dx%d, want 80x22", cfg.InitialCols, cfg.InitialRows)
		}
		if cfg.PTYResize == nil {
			t.Fatal("HostConfig.PTYResize = nil, want resize hook")
		}
		return errors.New("stop")
	}

	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Share() error = %v, want stop", err)
	}
}

func TestSharePrintsConnectCommandBeforeServing(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) {
		return "server-token", nil
	}
	generateClientToken = func(opts derptun.ClientTokenOptions) (string, error) {
		if opts.ServerToken != "server-token" {
			t.Fatalf("ServerToken = %q, want server-token", opts.ServerToken)
		}
		return "dtc1_test", nil
	}
	serveErr := errors.New("stop")
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		_, _ = ctx, cfg
		return serveErr
	}

	var stderr strings.Builder
	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: &stderr})
	if !errors.Is(err, serveErr) {
		t.Fatalf("Share() error = %v, want %v", err, serveErr)
	}
	if !strings.Contains(stderr.String(), "npx -y derpssh@latest connect DSH1") {
		t.Fatalf("stderr missing connect command:\n%s", stderr.String())
	}
}

func TestConnectDecodesInviteAndDials(t *testing.T) {
	oldDial := dialAppMux
	defer func() { dialAppMux = oldDial }()

	invite, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	dialAppMux = func(ctx context.Context, cfg appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		_, _ = ctx, cfg.Emitter
		if cfg.ClientToken != "dtc1_test" {
			t.Fatalf("ClientToken = %q, want dtc1_test", cfg.ClientToken)
		}
		return nil, func() {}, errors.New("stop")
	}

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Connect() error = %v, want stop", err)
	}
}

func TestConnectClosesStdinWhenGuestRunExits(t *testing.T) {
	oldDial := dialAppMux
	oldRunGuest := runGuestSession
	defer func() {
		dialAppMux = oldDial
		runGuestSession = oldRunGuest
	}()
	invite, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	stdin := newCloseAwareReader()
	dialAppMux = func(context.Context, appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		return &derptun.Mux{}, func() {}, nil
	}
	runGuestSession = func(context.Context, *GuestRuntime) error {
		return errors.New("stop")
	}

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       stdin,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Connect() error = %v, want stop", err)
	}
	if !stdin.closed.Load() {
		t.Fatal("stdin was not closed when guest run exited")
	}
}

func TestConnectStartsConsoleBeforeInitialStatus(t *testing.T) {
	oldDial := dialAppMux
	oldRunGuest := runGuestSession
	oldNewConsole := newConnectConsole
	defer func() {
		dialAppMux = oldDial
		runGuestSession = oldRunGuest
		newConnectConsole = oldNewConsole
	}()
	invite, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	console := &connectStartOrderConsole{}
	newConnectConsole = func(tuiConsoleOptions) connectConsole {
		return console
	}
	dialAppMux = func(context.Context, appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		return &derptun.Mux{}, func() {}, nil
	}
	runGuestSession = func(context.Context, *GuestRuntime) error {
		return errors.New("stop")
	}

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Connect() error = %v, want stop", err)
	}
	if console.statusBeforeStart {
		t.Fatal("initial status event was sent before console.Start")
	}
	if !console.sawWaitingStatus {
		t.Fatal("waiting status event was not sent")
	}
}

func TestConnectStartsGuestCommandPumpInsteadOfRawStdinPump(t *testing.T) {
	oldDial := dialAppMux
	oldRunGuest := runGuestSession
	defer func() {
		dialAppMux = oldDial
		runGuestSession = oldRunGuest
	}()
	invite, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	stdin := newReadTrackingReader()
	dialAppMux = func(context.Context, appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		return &derptun.Mux{}, func() {}, nil
	}
	runGuestSession = func(context.Context, *GuestRuntime) error {
		select {
		case <-stdin.readStarted:
			return errors.New("raw stdin pump used")
		case <-time.After(50 * time.Millisecond):
			return errors.New("stop")
		}
	}

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       stdin,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil {
		t.Fatal("Connect() error = nil, want stop")
	}
	if err.Error() == "raw stdin pump used" {
		t.Fatal("Connect started the old raw stdin pump; TUI command callbacks should own input")
	}
	if err.Error() != "stop" {
		t.Fatalf("Connect() error = %v, want stop", err)
	}
}

func TestSendGuestInputWaitsForWriteBeforeSending(t *testing.T) {
	guest := &fakeInputGuest{role: protocol.RolePending, sent: make(chan []byte, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		sendGuestInput(ctx, guest, []byte("whoami\n"))
		close(done)
	}()

	select {
	case got := <-guest.sent:
		t.Fatalf("SendInput called while role pending with %q", string(got))
	case <-time.After(50 * time.Millisecond):
	}
	guest.setRole(protocol.RoleWrite)

	select {
	case got := <-guest.sent:
		if string(got) != "whoami\n" {
			t.Fatalf("sent input = %q, want whoami", string(got))
		}
	case <-ctx.Done():
		t.Fatal("SendInput was not called after write approval")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("sendGuestInput did not return after sending")
	}
}

type closeAwareReader struct {
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once
}

type readTrackingReader struct {
	readStarted chan struct{}
	done        chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
}

type connectStartOrderConsole struct {
	started           bool
	statusBeforeStart bool
	sawWaitingStatus  bool
}

func (c *connectStartOrderConsole) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *connectStartOrderConsole) OnRuntimeEvent(event RuntimeEvent) {
	if event.Kind != RuntimeEventStatus || event.Message != "waiting for host approval" {
		return
	}
	c.sawWaitingStatus = true
	if !c.started {
		c.statusBeforeStart = true
	}
}

func (c *connectStartOrderConsole) Start(context.Context) {
	c.started = true
}

func (c *connectStartOrderConsole) Stop() {}

func (c *connectStartOrderConsole) SetCommandCallbacks(tuiConsoleCallbacks) {}

func newReadTrackingReader() *readTrackingReader {
	return &readTrackingReader{
		readStarted: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

func (r *readTrackingReader) Read([]byte) (int, error) {
	r.readOnce.Do(func() { close(r.readStarted) })
	<-r.done
	return 0, io.ErrClosedPipe
}

func (r *readTrackingReader) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	return nil
}

func newCloseAwareReader() *closeAwareReader {
	return &closeAwareReader{done: make(chan struct{})}
}

func (r *closeAwareReader) Read([]byte) (int, error) {
	<-r.done
	return 0, io.ErrClosedPipe
}

func (r *closeAwareReader) Close() error {
	r.closed.Store(true)
	r.once.Do(func() { close(r.done) })
	return nil
}

type fakeInputGuest struct {
	mu   sync.Mutex
	role protocol.Role
	sent chan []byte
}

func (g *fakeInputGuest) Role() protocol.Role {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.role
}

func (g *fakeInputGuest) setRole(role protocol.Role) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.role = role
}

func (g *fakeInputGuest) SendInput(_ context.Context, data []byte) error {
	g.sent <- append([]byte(nil), data...)
	return nil
}
