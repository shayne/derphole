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
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "write")
	approval := newTerminalShareApproval(ShareConfig{
		Stdin:  strings.NewReader(""),
		Stderr: io.Discard,
	})
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleWrite {
		t.Fatalf("Approve(test auto approve) = %q, want %q", got, protocol.RoleWrite)
	}
}

func TestShareTestCommandBacksHostTerminal(t *testing.T) {
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
	runHostSession = func(ctx context.Context, cfg HostConfig) error {
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
	runHostSession = func(ctx context.Context, cfg HostConfig) error {
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
