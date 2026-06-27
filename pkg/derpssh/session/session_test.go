// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
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

	var input bytes.Buffer
	host := NewHostRuntime(HostConfig{
		Mux:         hostMux,
		HostID:      "host",
		HostName:    "host",
		InitialCols: 80,
		InitialRows: 24,
		PTYInput:    &input,
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
	waitForBuffer(t, ctx, &input, "whoami\n")
	cancel()
	waitRuntimeExit(t, errCh, 2)
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
	if err := host.Resize(ctx, 100, 32); err != nil {
		t.Fatalf("host Resize() error = %v", err)
	}
	if err := guest.ReportSize(ctx, 200, 60); err != nil {
		t.Fatalf("guest ReportSize() error = %v", err)
	}
	waitForGuestSize(t, ctx, guest, 100, 32)
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

func waitForBuffer(t *testing.T, ctx context.Context, buf *bytes.Buffer, want string) {
	t.Helper()
	for {
		if buf.String() == want {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("buffer = %q, want %q before timeout", buf.String(), want)
		}
	}
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
