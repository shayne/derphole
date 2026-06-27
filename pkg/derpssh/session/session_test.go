// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derptun"
)

func TestHostRejectsReadOnlyGuestInput(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader("ready\n"),
		Approval:    StaticApproval{Role: protocol.RoleRead},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleRead)
	if err := guest.SendInput(ctx, []byte("whoami\n")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("SendInput(read-only) error = %v, want %v", err, ErrReadOnly)
	}
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostAcceptsWriteGuestInput(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	input := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    input,
		PTYOutput:   strings.NewReader("ready\n"),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	if err := guest.SendInput(ctx, []byte("whoami\n")); err != nil {
		t.Fatalf("SendInput(write) error = %v", err)
	}
	waitForCapturedWrite(t, ctx, input, "whoami\n")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestGuestReceivesHostTerminalOutput(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	output := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader("ready\n"),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:            guestMux,
		ParticipantID:  "guest-1",
		DisplayName:    "Alex",
		TerminalOutput: output,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	waitForCapturedWrite(t, ctx, output, "ready\n")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestGuestReceivesFanoutTerminalOutputAfterEarlyHostStart(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	ptyReader, ptyWriter := io.Pipe()
	localOutput := newCaptureWriter()
	fanout := newTerminalFanout(ptyReader, localOutput)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = fanout.Run(ctx) }()
	if _, err := ptyWriter.Write([]byte("ready")); err != nil {
		t.Fatalf("write initial output: %v", err)
	}
	waitForCapturedWrite(t, ctx, localOutput, "ready")

	hostInput := writerFunc(func(p []byte) (int, error) {
		if string(p) == "hello\n" {
			_, _ = ptyWriter.Write([]byte("input:hello"))
		}
		return len(p), nil
	})
	guestOutput := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    hostInput,
		PTYOutput:   fanout.Reader(),
		LocalOutput: io.Discard,
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:            guestMux,
		ParticipantID:  "guest-1",
		DisplayName:    "Alex",
		TerminalOutput: guestOutput,
	})

	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	waitForCapturedWrite(t, ctx, guestOutput, "ready")
	if err := guest.SendInput(ctx, []byte("hello\n")); err != nil {
		t.Fatalf("SendInput() error = %v", err)
	}
	waitForCapturedWrite(t, ctx, guestOutput, "input:hello")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostReceivesLocalTerminalOutput(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	localOutput := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader("ready\n"),
		LocalOutput: localOutput,
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	waitForCapturedWrite(t, ctx, localOutput, "ready\n")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostLocalInputWritesPTY(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	input := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    input,
		PTYOutput:   strings.NewReader("ready\n"),
		LocalInput:  strings.NewReader("from-host\n"),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	waitForCapturedWrite(t, ctx, input, "from-host\n")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostAcceptsApprovedGuestStreamsOutOfOrder(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	input := newCaptureWriter()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    input,
		PTYOutput:   strings.NewReader("ready\n"),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hostErrCh := make(chan error, 1)
	go func() { hostErrCh <- host.Run(ctx) }()

	control, err := openGuestControl(ctx, guestMux, "guest-1", "Alex")
	if err != nil {
		t.Fatalf("open guest control: %v", err)
	}
	defer control.Close()
	if got := readGuestDecisionRole(t, control); got != protocol.RoleWrite {
		t.Fatalf("decision role = %q, want %q", got, protocol.RoleWrite)
	}

	chatConn, err := openStream(ctx, guestMux, protocol.StreamChat, "guest-1")
	if err != nil {
		t.Fatalf("open chat stream first: %v", err)
	}
	defer chatConn.Close()
	terminalIn, err := openStream(ctx, guestMux, protocol.StreamTerminalIn, "guest-1")
	if err != nil {
		t.Fatalf("open terminal-in stream second: %v", err)
	}
	defer terminalIn.Close()

	terminalOut, err := acceptStream(ctx, guestMux, protocol.StreamTerminalOut)
	if err != nil {
		t.Fatalf("accept terminal-out stream: %v", err)
	}
	defer terminalOut.Close()
	if got := readTerminalOutput(t, terminalOut); got != "ready\n" {
		t.Fatalf("terminal output = %q, want ready", got)
	}

	if err := protocol.WriteFrame(terminalIn, protocol.Message{
		Type:     protocol.MessageTerminal,
		Terminal: &protocol.TerminalEvent{Data: []byte("whoami\n")},
	}); err != nil {
		t.Fatalf("write terminal input: %v", err)
	}
	waitForCapturedWrite(t, ctx, input, "whoami\n")

	cancel()
	waitRuntimeExit(t, hostErrCh, 1)
}

func TestDeniedGuestCannotOpenApprovedStreams(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader("ready\n"),
		Approval:    StaticApproval{Role: protocol.RoleDenied},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hostErrCh := make(chan error, 1)
	go func() { hostErrCh <- host.Run(ctx) }()

	control, err := guestMux.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream(control) error = %v", err)
	}
	defer control.Close()
	if err := protocol.WriteFrame(control, protocol.Message{
		Type: protocol.MessageHello,
		Hello: &protocol.Hello{
			ProtocolVersion: protocol.ProtocolVersion,
			ParticipantID:   "guest-1",
			DisplayName:     "Alex",
			Role:            protocol.RolePending,
		},
	}); err != nil {
		t.Fatalf("WriteFrame(control hello) error = %v", err)
	}
	decision, err := protocol.ReadFrame(control)
	if err != nil {
		t.Fatalf("ReadFrame(denial) error = %v", err)
	}
	if decision.Type != protocol.MessageDecision || decision.Decision == nil || decision.Decision.Accepted {
		t.Fatalf("denial decision = %#v, want rejected decision", decision)
	}

	if got, ok := maliciousDeniedTerminalOutput(ctx, guestMux); ok {
		t.Fatalf("denied guest received terminal output %q", got)
	}
	_ = control.Close()
	waitRuntimeExit(t, hostErrCh, 1)
}

func TestHostClosesPTYOutputOnShutdown(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	output := newBlockingPTYOutput()
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   output,
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	waitForBlockingRead(t, ctx, output)
	cancel()
	waitRuntimeExit(t, errCh, 2)
	waitForOutputClosed(t, context.Background(), output)
	waitForOutputReadReturned(t, context.Background(), output)
}

func TestChatMessagesRoundTrip(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader(""),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	if err := guest.SendChat(ctx, "hello host"); err != nil {
		t.Fatalf("guest SendChat() error = %v", err)
	}
	if err := host.SendChat(ctx, "hello Alex"); err != nil {
		t.Fatalf("host SendChat() error = %v", err)
	}

	waitForChatText(t, ctx, host.ChatMessages, "Alex", "hello host")
	waitForChatText(t, ctx, guest.ChatMessages, "host", "hello Alex")
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostResizeBroadcastsCanonicalSize(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	var resizedCols, resizedRows int
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader(""),
		PTYResize: func(cols int, rows int) error {
			resizedCols, resizedRows = cols, rows
			return nil
		},
		Approval: StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	if err := host.Resize(ctx, 100, 32); err != nil {
		t.Fatalf("host Resize() error = %v", err)
	}
	if resizedCols != 100 || resizedRows != 32 {
		t.Fatalf("PTYResize = %dx%d, want 100x32", resizedCols, resizedRows)
	}
	if err := guest.ReportSize(ctx, 200, 60); err != nil {
		t.Fatalf("guest ReportSize() error = %v", err)
	}
	waitForGuestSize(t, ctx, guest, 100, 32)
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestHostRoleChangeBroadcastsToGuest(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader(""),
		Approval:    StaticApproval{Role: protocol.RoleRead},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleRead)
	if err := host.SetGuestRole(ctx, "guest-1", protocol.RoleWrite); err != nil {
		t.Fatalf("host SetGuestRole(write) error = %v", err)
	}
	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	if err := host.SetGuestRole(ctx, "guest-1", protocol.RoleRead); err != nil {
		t.Fatalf("host SetGuestRole(read) error = %v", err)
	}
	waitForGuestRole(t, ctx, guest, protocol.RoleRead)
	cancel()
	waitRuntimeExit(t, errCh, 2)
}

func TestKickClosesGuestCleanly(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    io.Discard,
		PTYOutput:   strings.NewReader(""),
		Approval:    StaticApproval{Role: protocol.RoleWrite},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hostErrCh := make(chan error, 1)
	guestErrCh := make(chan error, 1)
	go func() { hostErrCh <- host.Run(ctx) }()
	go func() { guestErrCh <- guest.Run(ctx) }()

	waitForGuestRole(t, ctx, guest, protocol.RoleWrite)
	if err := host.Kick(ctx, "guest-1", "kicked by host"); err != nil {
		t.Fatalf("host Kick() error = %v", err)
	}
	select {
	case err := <-guestErrCh:
		if err != nil {
			t.Fatalf("guest Run() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("guest Run() did not exit after kick")
	}
	if reason := guest.CloseReason(); !strings.Contains(reason, "kicked") {
		t.Fatalf("guest CloseReason() = %q, want kicked", reason)
	}
	cancel()
	waitRuntimeExit(t, hostErrCh, 1)
}

func newTestMuxPair(t *testing.T) (*derptun.Mux, *derptun.Mux, func()) {
	t.Helper()
	hostConn, guestConn := net.Pipe()
	hostMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: time.Second})
	guestMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: time.Second})
	hostMux.ReplaceCarrier(hostConn)
	guestMux.ReplaceCarrier(guestConn)
	return hostMux, guestMux, func() {
		_ = hostMux.Close()
		_ = guestMux.Close()
	}
}

func waitForGuestRole(t *testing.T, ctx context.Context, guest *GuestRuntime, want protocol.Role) {
	t.Helper()
	for {
		if guest.Role() == want {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("guest role = %q, want %q before timeout", guest.Role(), want)
		}
	}
}

func waitForCapturedWrite(t *testing.T, ctx context.Context, writer *captureWriter, want string) {
	t.Helper()
	select {
	case got := <-writer.writes:
		if got != want {
			t.Fatalf("captured write = %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatalf("captured write missing before timeout")
	}
}

func waitForString(t *testing.T, ctx context.Context, value func() string, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		if strings.Contains(value(), want) {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("output missing %q before timeout:\n%s", want, value())
		}
	}
}

func openGuestControl(ctx context.Context, mux *derptun.Mux, participantID, displayName string) (net.Conn, error) {
	control, err := mux.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(control, protocol.Message{
		Type: protocol.MessageHello,
		Hello: &protocol.Hello{
			ProtocolVersion: protocol.ProtocolVersion,
			ParticipantID:   participantID,
			DisplayName:     displayName,
			Role:            protocol.RolePending,
		},
	}); err != nil {
		_ = control.Close()
		return nil, err
	}
	return control, nil
}

func readGuestDecisionRole(t *testing.T, conn net.Conn) protocol.Role {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set control read deadline: %v", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read decision: %v", err)
		}
		if msg.Type == protocol.MessageDecision && msg.Decision != nil && msg.Decision.Accepted {
			return msg.Decision.Role
		}
	}
}

func readTerminalOutput(t *testing.T, conn net.Conn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set terminal read deadline: %v", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	msg, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read terminal output: %v", err)
	}
	if msg.Type != protocol.MessageTerminal || msg.Terminal == nil {
		t.Fatalf("terminal output message = %#v", msg)
	}
	return string(msg.Terminal.Data)
}

func waitForChatText(t *testing.T, ctx context.Context, messages func() []ChatMessage, name, text string) {
	t.Helper()
	for {
		for _, msg := range messages() {
			if msg.DisplayName == name && msg.Text == text {
				return
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("chat missing %q from %q before timeout: %#v", text, name, messages())
		}
	}
}

func waitForGuestSize(t *testing.T, ctx context.Context, guest *GuestRuntime, cols, rows int) {
	t.Helper()
	for {
		gotCols, gotRows := guest.TerminalSize()
		if gotCols == cols && gotRows == rows {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			gotCols, gotRows := guest.TerminalSize()
			t.Fatalf("guest TerminalSize() = %dx%d, want %dx%d before timeout", gotCols, gotRows, cols, rows)
		}
	}
}

func waitRuntimeExit(t *testing.T, errCh <-chan error, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("runtime exit error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("runtime did not exit")
		}
	}
}

func maliciousDeniedTerminalOutput(ctx context.Context, mux *derptun.Mux) (string, bool) {
	attemptCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if conn, err := openMaliciousStream(attemptCtx, mux, protocol.StreamTerminalIn); err == nil {
		defer conn.Close()
	}
	if conn, err := openMaliciousStream(attemptCtx, mux, protocol.StreamChat); err == nil {
		defer conn.Close()
	}
	conn, err := mux.Accept(attemptCtx)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if _, err := protocol.ReadFrame(conn); err != nil {
		return "", false
	}
	msg, err := protocol.ReadFrame(conn)
	if err != nil || msg.Type != protocol.MessageTerminal || msg.Terminal == nil {
		return "", false
	}
	return string(msg.Terminal.Data), true
}

func openMaliciousStream(ctx context.Context, mux *derptun.Mux, kind protocol.StreamKind) (net.Conn, error) {
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = protocol.WriteFrame(conn, protocol.Message{
		Type: protocol.MessageHello,
		Hello: &protocol.Hello{
			ProtocolVersion: protocol.ProtocolVersion,
			ParticipantID:   "guest-1",
			DisplayName:     string(kind),
			Role:            protocol.RolePending,
		},
	})
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type captureWriter struct {
	mu     sync.Mutex
	buffer strings.Builder
	writes chan string
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{writes: make(chan string, 1)}
}

func (w *captureWriter) Write(p []byte) (int, error) {
	data := string(p)
	w.mu.Lock()
	w.buffer.WriteString(data)
	w.mu.Unlock()
	w.writes <- data
	return len(p), nil
}

func (w *captureWriter) Contains(s string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Contains(w.buffer.String(), s)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

type stringCapture struct {
	mu sync.Mutex
	b  strings.Builder
}

func newStringCapture() *stringCapture {
	return &stringCapture{}
}

func (w *stringCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *stringCapture) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

type blockingPTYOutput struct {
	reading chan struct{}
	closed  chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newBlockingPTYOutput() *blockingPTYOutput {
	return &blockingPTYOutput{
		reading: make(chan struct{}),
		closed:  make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (r *blockingPTYOutput) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.reading) })
	<-r.closed
	close(r.done)
	return 0, io.ErrClosedPipe
}

func (r *blockingPTYOutput) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func waitForBlockingRead(t *testing.T, ctx context.Context, output *blockingPTYOutput) {
	t.Helper()
	select {
	case <-output.reading:
	case <-ctx.Done():
		t.Fatal("PTYOutput.Read was not reached before timeout")
	}
}

func waitForOutputClosed(t *testing.T, ctx context.Context, output *blockingPTYOutput) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	select {
	case <-output.closed:
	case <-ctx.Done():
		t.Fatal("PTYOutput was not closed")
	}
}

func waitForOutputReadReturned(t *testing.T, ctx context.Context, output *blockingPTYOutput) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	select {
	case <-output.done:
	case <-ctx.Done():
		t.Fatal("PTYOutput.Read did not return after Close")
	}
}
