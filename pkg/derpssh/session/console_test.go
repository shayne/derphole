// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/tui"
)

func TestTerminalConsoleApproveFromInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want protocol.Role
	}{
		{name: "read", in: "r\n", want: protocol.RoleRead},
		{name: "write", in: "w\n", want: protocol.RoleWrite},
		{name: "deny", in: "n\n", want: protocol.RoleDenied},
		{name: "default deny", in: "\n", want: protocol.RoleDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			console := newTerminalConsole(tui.ModeHost, 100, 30, strings.NewReader(tt.in), &out)
			got := console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"})
			if got != tt.want {
				t.Fatalf("Approve() = %q, want %q", got, tt.want)
			}
			for _, want := range []string{"approve Alex", "terminal", "sidechat", "status"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("approval view missing %q:\n%s", want, out.String())
				}
			}
		})
	}
}

func TestTerminalConsoleApproveFromEnv(t *testing.T) {
	t.Setenv("DERPSSH_TEST_AUTO_APPROVE", "write")
	console := newTerminalConsole(tui.ModeHost, 100, 30, strings.NewReader(""), nil)
	if got := console.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleWrite {
		t.Fatalf("Approve(test env) = %q, want write", got)
	}
}

func TestTerminalConsoleRendersRuntimeEvents(t *testing.T) {
	var out strings.Builder
	console := newTerminalConsole(tui.ModeGuest, 90, 25, strings.NewReader(""), &out)
	if _, err := console.Write([]byte("ready\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventRole, Role: protocol.RoleRead})
	console.OnRuntimeEvent(RuntimeEvent{
		Kind: RuntimeEventChat,
		Chat: ChatMessage{ParticipantID: "guest-1", DisplayName: "Alex", Text: "hello"},
	})
	view := out.String()
	for _, want := range []string{"ready", "role read", "Alex: hello", "sidechat"} {
		if !strings.Contains(view, want) {
			t.Fatalf("console output missing %q:\n%s", want, view)
		}
	}
}
