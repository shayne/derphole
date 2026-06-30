// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/brand"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestInviteInterstitialPrintsCommandAsOneLogicalLine(t *testing.T) {
	var out bytes.Buffer
	cmd := "npx -y derpssh@latest connect DSH1longtoken"
	i := NewInviteInterstitial(InviteOptions{Output: &out, Command: cmd})

	if err := i.Print(); err != nil {
		t.Fatalf("Print() error = %v", err)
	}

	got := out.String()
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("invite output should end with newline: %q", got)
	}
	if !strings.Contains(got, brand.Wordmark()) {
		t.Fatalf("invite output missing derpssh wordmark:\n%s", got)
	}
	if strings.Count(got, cmd) != 1 {
		t.Fatalf("invite command not printed exactly once: %q", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.Contains(line, "npx -y derpssh@latest connect") && line != cmd {
			t.Fatalf("invite command is not one copyable line: %q", line)
		}
	}
}

func TestInviteInterstitialGuestPendingStartsTUIBeforeApproval(t *testing.T) {
	var order []string
	approval := startingShareApproval{
		Start: func() { order = append(order, "start") },
		Approval: approvalFunc(func(JoinRequest) protocol.Role {
			order = append(order, "approve")
			return protocol.RoleRead
		}),
	}

	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "shayne"}); got != protocol.RoleRead {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleRead)
	}
	if strings.Join(order, ",") != "start,approve" {
		t.Fatalf("guest pending order = %#v, want TUI start before approval", order)
	}
}

func TestInviteInterstitialQuitWhileGuestConnectsUsesPreApprovalCloseReason(t *testing.T) {
	reason := inviteInterstitialQuitReason(true)

	if reason.Code != hostQuitBeforeApprovalReason {
		t.Fatalf("CloseReason.Code = %q, want %q", reason.Code, hostQuitBeforeApprovalReason)
	}
	if !strings.Contains(reason.Message, "host quit") || !strings.Contains(reason.Message, "approval") {
		t.Fatalf("CloseReason.Message = %q, want host quit before approval", reason.Message)
	}
}

type approvalFunc func(JoinRequest) protocol.Role

func (f approvalFunc) Approve(req JoinRequest) protocol.Role {
	return f(req)
}
