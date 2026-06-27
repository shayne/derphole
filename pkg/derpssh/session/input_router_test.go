// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestInputRouterSendsChatWithoutTerminalEcho(t *testing.T) {
	sink := &recordingInputSink{}
	err := pumpRoutedInput(context.Background(), strings.NewReader(":chat hello there\nwhoami\n"), sink.sink())
	if err != nil {
		t.Fatalf("pumpRoutedInput() error = %v", err)
	}
	if got := strings.Join(sink.chat, "|"); got != "hello there" {
		t.Fatalf("chat = %q, want hello there", got)
	}
	if got := string(sink.data); got != "whoami\n" {
		t.Fatalf("terminal data = %q, want whoami", got)
	}
}

func TestInputRouterHandlesSplitChatCommand(t *testing.T) {
	sink := &recordingInputSink{}
	router := newInputRouter()
	if err := router.route(context.Background(), []byte(":chat hel"), sink.sink()); err != nil {
		t.Fatalf("route(part 1) error = %v", err)
	}
	if string(sink.data) != "" || len(sink.chat) != 0 {
		t.Fatalf("sink after partial command = data %q chat %#v, want empty", string(sink.data), sink.chat)
	}
	if err := router.route(context.Background(), []byte("lo\n"), sink.sink()); err != nil {
		t.Fatalf("route(part 2) error = %v", err)
	}
	if got := strings.Join(sink.chat, "|"); got != "hello" {
		t.Fatalf("chat = %q, want hello", got)
	}
}

func TestInputRouterHostPermissionCommands(t *testing.T) {
	sink := &recordingInputSink{}
	err := pumpRoutedInput(context.Background(), strings.NewReader(":read\n:write\n:kick done\n"), sink.sink())
	if err != nil {
		t.Fatalf("pumpRoutedInput() error = %v", err)
	}
	if got := strings.Join(sink.commands, "|"); got != "read=|write=|kick=done" {
		t.Fatalf("commands = %q, want read/write/kick", got)
	}
	if got := string(sink.data); got != "" {
		t.Fatalf("terminal data = %q, want empty", got)
	}
}

func TestGuestInputRoutesChatBeforeRoleGate(t *testing.T) {
	guest := &fakeInteractiveGuest{role: protocol.RoleRead}
	err := pumpRoutedInput(context.Background(), strings.NewReader(":chat still here\nwhoami\n"), guestInputSink(guest))
	if err != nil {
		t.Fatalf("pumpRoutedInput() error = %v", err)
	}
	if got := strings.Join(guest.chat, "|"); got != "still here" {
		t.Fatalf("guest chat = %q, want still here", got)
	}
	if got := string(guest.input); got != "" {
		t.Fatalf("guest input = %q, want read-only input dropped", got)
	}
}

type recordingInputSink struct {
	data     []byte
	chat     []string
	commands []string
}

func (s *recordingInputSink) sink() routedInputSink {
	return routedInputSink{
		sendData: func(_ context.Context, data []byte) error {
			s.data = append(s.data, data...)
			return nil
		},
		sendChat: func(_ context.Context, text string) error {
			s.chat = append(s.chat, text)
			return nil
		},
		handleCommand: func(_ context.Context, cmd inputCommand) (bool, error) {
			switch cmd.Name {
			case "read", "write", "kick":
				s.commands = append(s.commands, cmd.Name+"="+cmd.Arg)
				return true, nil
			default:
				return false, nil
			}
		},
	}
}

type fakeInteractiveGuest struct {
	role  protocol.Role
	input []byte
	chat  []string
}

func (g *fakeInteractiveGuest) Role() protocol.Role {
	return g.role
}

func (g *fakeInteractiveGuest) SendInput(_ context.Context, data []byte) error {
	g.input = append(g.input, data...)
	return nil
}

func (g *fakeInteractiveGuest) SendChat(_ context.Context, text string) error {
	g.chat = append(g.chat, text)
	return nil
}
