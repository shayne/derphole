// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	creackpty "github.com/creack/pty"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derptun"
	appsession "github.com/shayne/derphole/pkg/session"
)

func TestInviteRoundTrip(t *testing.T) {
	clientToken := newTestDerptunClientToken(t)
	encoded, err := EncodeInvite(Invite{ClientToken: clientToken})
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
	if decoded.ClientToken != clientToken {
		t.Fatalf("ClientToken = %q, want %q", decoded.ClientToken, clientToken)
	}
}

func TestShareInviteCustomDERPCredentialsDelegateTransportToDerptunAppMux(t *testing.T) {
	t.Setenv(derpbind.CustomDERPServerEnv, "https://derp.example.com:8443/derp")
	serverToken, command, err := newShareInviteCommand()
	if err != nil {
		t.Fatalf("newShareInviteCommand() error = %v", err)
	}
	if !strings.HasPrefix(serverToken, derptun.CustomServerTokenPrefix) {
		t.Fatalf("server token = %q, want %s prefix", serverToken, derptun.CustomServerTokenPrefix)
	}
	t.Setenv(derpbind.CustomDERPServerEnv, "")
	fields := strings.Fields(command)
	if len(fields) == 0 {
		t.Fatalf("command = %q, want invite", command)
	}
	inv, err := DecodeInvite(fields[len(fields)-1])
	if err != nil {
		t.Fatalf("DecodeInvite() error = %v", err)
	}
	client, err := derptun.DecodeClientToken(inv.ClientToken, time.Now())
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	server, err := derptun.DecodeServerToken(serverToken, time.Now())
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	if server.DERPRoute == nil || client.DERPRoute == nil || *server.DERPRoute != *client.DERPRoute {
		t.Fatalf("credential DERP routes = server %+v client %+v, want identical embedded routes", server.DERPRoute, client.DERPRoute)
	}
	if client.DERPRoute.Host != "derp.example.com" || client.DERPRoute.DERPPort != 8443 {
		t.Fatalf("client DERPRoute = %+v, want creator environment route", client.DERPRoute)
	}
}

func TestShareRejectsInvalidAutoAcceptRoleBeforeInvite(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	defer func() { generateServerToken = oldGenerateServerToken }()

	called := false
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) {
		called = true
		return "", errors.New("invite generation should not run")
	}
	err := Share(context.Background(), ShareConfig{
		Stdin:          strings.NewReader(""),
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		AutoAcceptRole: protocol.Role("admin"),
	})
	if err == nil || !strings.Contains(err.Error(), `invalid auto-accept role "admin"`) {
		t.Fatalf("Share() error = %v, want invalid role", err)
	}
	if called {
		t.Fatal("generateServerToken called before auto-accept validation")
	}
}

func newTestDerptunClientToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return client
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

func TestDecodeInviteRejectsMalformedClientTokenWithCanonicalPrefix(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":"DT1not-valid"}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(malformed client token) error = nil, want error")
	}
}

func TestDecodeInviteRejectsRemovedClientTokenFormat(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":"dtc1_legacy"}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(old client token) error = nil, want error")
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
		raw := make([]byte, len("input:hello"))
		_, err := io.ReadFull(cfg.PTYOutput, raw)
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

func TestShareReturnsPlainInviteStartErrorBeforeServing(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", "cat")
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldCanUsePreflight := canUseShareInvitePreflight
	oldStartPreflight := startShareInvitePreflight
	oldServe := serveAppMux
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		canUseShareInvitePreflight = oldCanUsePreflight
		startShareInvitePreflight = oldStartPreflight
		serveAppMux = oldServe
	}()

	sentinel := errors.New("preflight sentinel")
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
	canUseShareInvitePreflight = func(ShareConfig) bool { return true }
	startShareInvitePreflight = func(_ context.Context, _ ShareConfig, command string) (shareInvitePreflight, error) {
		if !strings.Contains(command, "npx -y derpssh@latest connect DSH1") {
			t.Fatalf("preflight command = %q, want derpssh connect invite", command)
		}
		return nil, sentinel
	}
	serveAppMux = func(context.Context, appsession.DerptunAppServeConfig) error {
		t.Fatal("serveAppMux called after plain invite failed to start")
		return nil
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
	if got := strings.Count(screen, "\n"+command+"\n"); got != 1 {
		t.Fatalf("preflight screen should render command as one physical line, count=%d:\n%s", got, screen)
	}
	if strings.Contains(screen, "\x1b[") {
		t.Fatalf("preflight screen contains ANSI styling:\n%q", screen)
	}
}

func TestPresentShareInviteClearsPreflightBeforeTUI(t *testing.T) {
	oldShowPreflight := showShareInvitePreflight
	defer func() { showShareInvitePreflight = oldShowPreflight }()

	showShareInvitePreflight = func(stdin io.Reader, stdout io.Writer, command string) (bool, error) {
		_, _, _ = stdin, stdout, command
		return true, nil
	}
	var stdout strings.Builder
	if err := presentShareInvite(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: io.Discard,
	}, "npx -y derpssh@latest connect DSH1test"); err != nil {
		t.Fatalf("presentShareInvite() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "\x1b[3J") {
		t.Fatalf("stdout missing clear-screen sequence: %q", stdout.String())
	}
}

func TestPresentShareInviteClearsPreflightOnQuit(t *testing.T) {
	oldShowPreflight := showShareInvitePreflight
	defer func() { showShareInvitePreflight = oldShowPreflight }()

	showShareInvitePreflight = func(stdin io.Reader, stdout io.Writer, command string) (bool, error) {
		_, _, _ = stdin, stdout, command
		return true, errInvitePreflightQuit
	}
	var stdout strings.Builder
	err := presentShareInvite(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: io.Discard,
	}, "npx -y derpssh@latest connect DSH1test")
	if !errors.Is(err, errInvitePreflightQuit) {
		t.Fatalf("presentShareInvite() error = %v, want invite quit", err)
	}
	if !strings.Contains(stdout.String(), "\x1b[3J") {
		t.Fatalf("stdout missing scrollback clear on quit: %q", stdout.String())
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

func TestReadInvitePreflightInputInterruptibleContinuesOnEnter(t *testing.T) {
	inR, inW := testPipe(t)
	wakeR, wakeW := testPipe(t)
	defer closeFiles(inR, inW, wakeR, wakeW)

	if _, err := inW.Write([]byte("\n")); err != nil {
		t.Fatalf("write input pipe: %v", err)
	}

	result := readInvitePreflightInputInterruptible(inR, wakeR)
	if result.Err != nil || result.Action != invitePreflightContinue {
		t.Fatalf("interruptible input result = %+v, want continue", result)
	}
}

func TestReadInvitePreflightInputInterruptibleQuitsOnQ(t *testing.T) {
	inR, inW := testPipe(t)
	wakeR, wakeW := testPipe(t)
	defer closeFiles(inR, inW, wakeR, wakeW)

	if _, err := inW.Write([]byte("q")); err != nil {
		t.Fatalf("write input pipe: %v", err)
	}

	result := readInvitePreflightInputInterruptible(inR, wakeR)
	if result.Err != nil || result.Action != invitePreflightQuit {
		t.Fatalf("interruptible input result = %+v, want quit", result)
	}
}

func TestReadInvitePreflightInputInterruptibleWakesOnInterrupt(t *testing.T) {
	inR, inW := testPipe(t)
	wakeR, wakeW := testPipe(t)
	defer closeFiles(inR, inW, wakeR, wakeW)

	if _, err := wakeW.Write([]byte{1}); err != nil {
		t.Fatalf("write wake pipe: %v", err)
	}

	result := readInvitePreflightInputInterruptible(inR, wakeR)
	if result.Err != nil || result.Action != invitePreflightInterrupted {
		t.Fatalf("interruptible input result = %+v, want interrupted", result)
	}
}

func TestReadInvitePreflightInputInterruptibleIgnoresUnknownKeys(t *testing.T) {
	inR, inW := testPipe(t)
	wakeR, wakeW := testPipe(t)
	defer closeFiles(inR, inW, wakeR, wakeW)

	if _, err := inW.Write([]byte("x\n")); err != nil {
		t.Fatalf("write input pipe: %v", err)
	}

	result := readInvitePreflightInputInterruptible(inR, wakeR)
	if result.Err != nil || result.Action != invitePreflightContinue {
		t.Fatalf("interruptible input result = %+v, want continue after ignored key", result)
	}
}

func TestRawShareInvitePreflightTerminalQuitsOnQ(t *testing.T) {
	master, slave, err := creackpty.Open()
	if err != nil {
		t.Fatalf("pty open: %v", err)
	}
	defer closeFiles(master, slave)
	output := newStringCapture()
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(output, master)
		close(copyDone)
	}()

	preflight, err := startRawShareInvitePreflight(context.Background(), ShareConfig{
		Stdin:  slave,
		Stdout: slave,
	}, "npx -y derpssh@latest connect DSH1test")
	if err != nil {
		t.Fatalf("startRawShareInvitePreflight() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitForString(t, ctx, output.String, "Press Enter to start sharing. Press q to quit.")
	if _, err := master.Write([]byte("q")); err != nil {
		t.Fatalf("write q: %v", err)
	}

	resultCh := make(chan shareInvitePreflightResult, 1)
	go func() { resultCh <- preflight.Wait() }()
	select {
	case result := <-resultCh:
		if result.Err != nil || result.Action != invitePreflightQuit {
			t.Fatalf("preflight result = %+v, want quit", result)
		}
	case <-ctx.Done():
		t.Fatalf("preflight did not quit after q; output:\n%s", output.String())
	}
	closeFiles(slave, master)
	<-copyDone
}

func TestSharePlainInviteTerminalQuitsOnQ(t *testing.T) {
	t.Setenv("DERPSSH_TEST_HARNESS", "1")
	t.Setenv("DERPSSH_TEST_COMMAND", "cat")

	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
	serveStarted := make(chan struct{})
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		_ = cfg
		close(serveStarted)
		<-ctx.Done()
		return ctx.Err()
	}

	master, slave, err := creackpty.Open()
	if err != nil {
		t.Fatalf("pty open: %v", err)
	}
	defer closeFiles(master, slave)
	output := newStringCapture()
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(output, master)
		close(copyDone)
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Share(context.Background(), ShareConfig{Stdin: slave, Stdout: slave, Stderr: io.Discard})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitForString(t, ctx, output.String, "Press Enter to start sharing. Press q to quit.")
	select {
	case <-serveStarted:
	case <-ctx.Done():
		t.Fatal("share server did not start while plain invite waited")
	}

	if _, err := master.Write([]byte("q")); err != nil {
		t.Fatalf("write q: %v", err)
	}
	quitCtx, quitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer quitCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Share() after q = %v, want nil", err)
		}
	case <-quitCtx.Done():
		t.Fatalf("Share() did not quit after q; output:\n%s", output.String())
	}
	closeFiles(slave, master)
	<-copyDone
}

func TestWaitingShareConsoleBuffersChatUntilHostCallbacks(t *testing.T) {
	pending := newPendingShareChats()
	callbacks := waitingShareConsoleCallbacks(nil, func() {}, pending, nil)

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

func TestWaitingShareConsoleQuitReportsHostReason(t *testing.T) {
	var gotReason string
	cancelled := false
	callbacks := waitingShareConsoleCallbacks(nil, func() { cancelled = true }, nil, func(reason string) {
		gotReason = reason
	})

	if err := callbacks.Quit(context.Background()); err != nil {
		t.Fatalf("Quit() error = %v", err)
	}
	if gotReason != hostQuitReason {
		t.Fatalf("close reason = %q, want %q", gotReason, hostQuitReason)
	}
	if !cancelled {
		t.Fatal("Quit() did not cancel share")
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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

func TestSelectShareApprovalAutoAcceptsEveryJoinWithoutConsoleApproval(t *testing.T) {
	oldNewApproval := newShareApproval
	defer func() { newShareApproval = oldNewApproval }()
	interactiveFactoryCalls := 0
	newShareApproval = func(ShareConfig) Approval {
		interactiveFactoryCalls++
		return StaticApproval{Role: protocol.RoleDenied}
	}

	for _, role := range []protocol.Role{protocol.RoleRead, protocol.RoleWrite} {
		t.Run(string(role), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			console := newTerminalConsoleWithOptions(tuiConsoleOptions{ForceHeadless: true})
			defer console.Stop()
			preflight := newFakeShareInvitePreflight()
			starter := newShareConsoleStarter(console, ctx, preflight)
			modalCalls := 0
			consoleApproval := approvalFunc(func(JoinRequest) protocol.Role {
				modalCalls++
				return protocol.RoleDenied
			})
			approval := selectShareApproval(
				ShareConfig{AutoAcceptRole: role},
				consoleApproval,
				starter.Start,
			)
			for _, req := range []JoinRequest{
				{ParticipantID: "guest-1", DisplayName: "Alex"},
				{ParticipantID: "guest-2", DisplayName: "Sam"},
			} {
				if got := approval.Approve(req); got != role {
					t.Fatalf("Approve(%s) = %q, want %q", req.ParticipantID, got, role)
				}
			}
			if modalCalls != 0 {
				t.Fatalf("console approval calls = %d, want 0", modalCalls)
			}
			if interactiveFactoryCalls != 0 {
				t.Fatalf("interactive approval factory calls = %d, want 0", interactiveFactoryCalls)
			}
			if got := preflight.interruptCalls.Load(); got != 1 {
				t.Fatalf("preflight interrupt calls = %d, want 1", got)
			}
		})
	}
}

func TestSelectShareApprovalDeniesAutoAcceptWhenInviteQuitWins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{ForceHeadless: true})
	defer console.Stop()
	preflight := newFakeShareInvitePreflight()
	preflight.finish(shareInvitePreflightResult{Action: invitePreflightQuit})
	starter := newShareConsoleStarter(console, ctx, preflight)
	approval := selectShareApproval(
		ShareConfig{AutoAcceptRole: protocol.RoleWrite},
		StaticApproval{Role: protocol.RoleDenied},
		starter.Start,
	)

	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestSelectShareApprovalDeniesAutoAcceptWhenInvitePreflightFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{ForceHeadless: true})
	defer console.Stop()
	preflight := newFakeShareInvitePreflight()
	preflight.finish(shareInvitePreflightResult{Action: invitePreflightContinue, Err: errors.New("preflight failed")})
	starter := newShareConsoleStarter(console, ctx, preflight)
	approval := selectShareApproval(
		ShareConfig{AutoAcceptRole: protocol.RoleRead},
		StaticApproval{Role: protocol.RoleDenied},
		starter.Start,
	)

	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestSelectShareApprovalDeniesAutoAcceptWhenShareContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{ForceHeadless: true})
	defer console.Stop()
	starter := newShareConsoleStarter(console, ctx, nil)
	approval := selectShareApproval(
		ShareConfig{AutoAcceptRole: protocol.RoleRead},
		StaticApproval{Role: protocol.RoleDenied},
		starter.Start,
	)

	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleDenied {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleDenied)
	}
}

func TestSelectShareApprovalKeepsInteractiveConsolePath(t *testing.T) {
	oldNewApproval := newShareApproval
	defer func() { newShareApproval = oldNewApproval }()
	newShareApproval = func(cfg ShareConfig) Approval {
		return terminalShareApproval{stdin: cfg.Stdin, stderr: cfg.Stderr}
	}

	modalCalls := 0
	consoleApproval := approvalFunc(func(JoinRequest) protocol.Role {
		modalCalls++
		return protocol.RoleRead
	})
	startCalls := 0
	approval := selectShareApproval(ShareConfig{}, consoleApproval, func() bool {
		startCalls++
		return true
	})
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleRead {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleRead)
	}
	if modalCalls != 1 || startCalls != 1 {
		t.Fatalf("modal/start calls = %d/%d, want 1/1", modalCalls, startCalls)
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
		if startedSize != (pty.Size{Cols: 80, Rows: 23}) {
			t.Fatalf("started PTY size = %+v, want 80x23 terminal pane", startedSize)
		}
		if cfg.InitialCols != 80 || cfg.InitialRows != 23 {
			t.Fatalf("HostConfig initial size = %dx%d, want 80x23", cfg.InitialCols, cfg.InitialRows)
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

func TestShareUsesUserAtHostDisplayName(t *testing.T) {
	t.Setenv("USER", "root")
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		t.Skipf("hostname unavailable: %v", err)
	}

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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
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
		want := "root@" + host
		if cfg.HostName != want {
			t.Fatalf("HostConfig.HostName = %q, want %q", cfg.HostName, want)
		}
		return errors.New("stop")
	}

	err = Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
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
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(opts derptun.ClientTokenOptions) (string, error) {
		if opts.ServerToken != "server-token" {
			t.Fatalf("ServerToken = %q, want server-token", opts.ServerToken)
		}
		return clientToken, nil
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

func TestShareStartsServingWhilePlainInviteWaits(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", "cat")
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldCanUsePreflight := canUseShareInvitePreflight
	oldStartPreflight := startShareInvitePreflight
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		canUseShareInvitePreflight = oldCanUsePreflight
		startShareInvitePreflight = oldStartPreflight
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
	canUseShareInvitePreflight = func(ShareConfig) bool { return true }
	preflight := newFakeShareInvitePreflight()
	preflightStarted := make(chan struct{})
	var gotCommand string
	startShareInvitePreflight = func(_ context.Context, _ ShareConfig, command string) (shareInvitePreflight, error) {
		gotCommand = command
		close(preflightStarted)
		return preflight, nil
	}
	served := make(chan struct{})
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		_, _ = cfg, ctx
		close(served)
		<-ctx.Done()
		return ctx.Err()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	}()

	select {
	case <-preflightStarted:
	case <-time.After(time.Second):
		t.Fatal("plain invite preflight did not start")
	}
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("share server did not start while invite preflight was waiting")
	}
	select {
	case err := <-errCh:
		t.Fatalf("Share() returned before invite action: %v", err)
	default:
	}
	if !strings.Contains(gotCommand, "npx -y derpssh@latest connect DSH1") {
		t.Fatalf("preflight command = %q, want derpssh connect invite", gotCommand)
	}
	preflight.finish(shareInvitePreflightResult{Action: invitePreflightQuit})
	if err := <-errCh; err != nil {
		t.Fatalf("Share() after invite quit = %v, want nil", err)
	}
}

func TestShareGuestApprovalInterruptsPlainInvite(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", "cat")
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldCanUsePreflight := canUseShareInvitePreflight
	oldStartPreflight := startShareInvitePreflight
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		canUseShareInvitePreflight = oldCanUsePreflight
		startShareInvitePreflight = oldStartPreflight
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
	canUseShareInvitePreflight = func(ShareConfig) bool { return true }
	preflight := newFakeShareInvitePreflight()
	startShareInvitePreflight = func(context.Context, ShareConfig, string) (shareInvitePreflight, error) {
		return preflight, nil
	}
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		return cfg.OnMux(ctx, nil)
	}
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = ctx
		_ = bindConsole
		_ = cfg.Approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "shayne"})
		if !preflight.interrupted.Load() {
			t.Fatal("approval did not interrupt plain invite preflight before starting the console")
		}
		return errors.New("stop")
	}

	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Share() error = %v, want stop", err)
	}
}

func TestShareCancelsServerAfterHostQuit(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", "cat")
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	oldRunHost := runHostSession
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
		runHostSession = oldRunHost
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) { return "server-token", nil }
	clientToken := newTestDerptunClientToken(t)
	generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		if err := cfg.OnMux(ctx, nil); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return errors.New("share server kept running after host quit")
		}
	}
	runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
		_ = ctx
		host := NewHostRuntime(cfg)
		if bindConsole != nil {
			bindConsole(host)
		}
		host.setCloseReason(hostQuitReason)
		return nil
	}

	if err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}); err != nil {
		t.Fatalf("Share() error = %v, want nil", err)
	}
}

func TestStartShareTerminalCloseStopsTestCommand(t *testing.T) {
	t.Setenv("DERPSSH_TEST_COMMAND", "sleep 1")

	terminal, err := startShareTerminal(pty.Size{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("startShareTerminal() error = %v", err)
	}

	if err := terminal.Close(); err != nil {
		t.Fatalf("terminal.Close() error = %v", err)
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- terminal.Wait()
	}()

	select {
	case <-waitErr:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("terminal.Wait() did not return promptly after Close")
	}
}

func TestConnectDecodesInviteAndDials(t *testing.T) {
	oldDial := dialAppMux
	defer func() { dialAppMux = oldDial }()

	clientToken := newTestDerptunClientToken(t)
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	dialAppMux = func(ctx context.Context, cfg appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		_, _ = ctx, cfg.Emitter
		if cfg.ClientToken != clientToken {
			t.Fatalf("ClientToken = %q, want %q", cfg.ClientToken, clientToken)
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
	clientToken := newTestDerptunClientToken(t)
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
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

func TestConnectReportsGuestCloseReason(t *testing.T) {
	oldDial := dialAppMux
	oldRunGuest := runGuestSession
	defer func() {
		dialAppMux = oldDial
		runGuestSession = oldRunGuest
	}()
	clientToken := newTestDerptunClientToken(t)
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	dialAppMux = func(context.Context, appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		return &derptun.Mux{}, func() {}, nil
	}
	runGuestSession = func(_ context.Context, guest *GuestRuntime) error {
		guest.setCloseReason(hostQuitReason)
		return nil
	}
	var stderr strings.Builder

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("Connect() error = %v, want nil", err)
	}
	if got, want := stderr.String(), "derpssh: session ended: host quit\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
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
	clientToken := newTestDerptunClientToken(t)
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	console := &connectStartOrderConsole{}
	newConnectConsole = func(tuiConsoleOptions) connectConsole {
		return console
	}
	dialAppMux = func(_ context.Context, cfg appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		cfg.Emitter.Status("connected-relay")
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
	if console.transportBeforeStart {
		t.Fatal("transport status event was sent before console.Start")
	}
	if !console.sawWaitingStatus {
		t.Fatal("waiting status event was not sent")
	}
	if !console.sawTransportStatus {
		t.Fatal("transport status event was not replayed after console.Start")
	}
}

func TestConnectStartsGuestCommandPumpInsteadOfRawStdinPump(t *testing.T) {
	oldDial := dialAppMux
	oldRunGuest := runGuestSession
	defer func() {
		dialAppMux = oldDial
		runGuestSession = oldRunGuest
	}()
	clientToken := newTestDerptunClientToken(t)
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
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

func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	return r, w
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

type fakeShareInvitePreflight struct {
	interrupted    atomic.Bool
	interruptCalls atomic.Int32
	done           chan shareInvitePreflightResult
	once           sync.Once
	waitOnce       sync.Once
	result         shareInvitePreflightResult
}

func newFakeShareInvitePreflight() *fakeShareInvitePreflight {
	return &fakeShareInvitePreflight{done: make(chan shareInvitePreflightResult, 1)}
}

func (p *fakeShareInvitePreflight) Interrupt() {
	p.interruptCalls.Add(1)
	p.interrupted.Store(true)
	p.finish(shareInvitePreflightResult{Action: invitePreflightInterrupted})
}

func (p *fakeShareInvitePreflight) finish(result shareInvitePreflightResult) {
	p.once.Do(func() {
		p.done <- result
		close(p.done)
	})
}

func (p *fakeShareInvitePreflight) Wait() shareInvitePreflightResult {
	p.waitOnce.Do(func() {
		result, ok := <-p.done
		if !ok {
			result = shareInvitePreflightResult{Action: invitePreflightInterrupted}
		}
		p.result = result
	})
	return p.result
}

type readTrackingReader struct {
	readStarted chan struct{}
	done        chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
}

type connectStartOrderConsole struct {
	started              bool
	statusBeforeStart    bool
	transportBeforeStart bool
	sawWaitingStatus     bool
	sawTransportStatus   bool
}

func (c *connectStartOrderConsole) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *connectStartOrderConsole) OnRuntimeEvent(event RuntimeEvent) {
	if event.Kind != RuntimeEventStatus {
		return
	}
	switch event.Message {
	case "waiting for host approval":
		c.sawWaitingStatus = true
		if !c.started {
			c.statusBeforeStart = true
		}
	case "connected-relay":
		c.sawTransportStatus = true
		if !c.started {
			c.transportBeforeStart = true
		}
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
