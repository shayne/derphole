// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

import (
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestGuestInputRequiresWriteRole(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.AddPendingGuest("guest-1", "Alex")
	if s.GuestCanWrite("guest-1") {
		t.Fatal("pending guest can write")
	}
	if err := s.ApproveGuest("guest-1", protocol.RoleRead); err != nil {
		t.Fatalf("ApproveGuest(read) error = %v", err)
	}
	if s.GuestCanWrite("guest-1") {
		t.Fatal("read guest can write")
	}
	if err := s.SetGuestRole("guest-1", protocol.RoleWrite); err != nil {
		t.Fatalf("SetGuestRole(write) error = %v", err)
	}
	if !s.GuestCanWrite("guest-1") {
		t.Fatal("write guest cannot write")
	}
}

func TestGuestResizeDoesNotChangeHostSize(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.NoteGuestSize("guest-1", 200, 60)
	cols, rows := s.HostSize()
	if cols != 100 || rows != 30 {
		t.Fatalf("HostSize() = %dx%d, want 100x30", cols, rows)
	}
}

func TestKickGuestMarksRoleKicked(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.AddPendingGuest("guest-1", "Alex")
	if err := s.KickGuest("guest-1"); err != nil {
		t.Fatalf("KickGuest() error = %v", err)
	}
	got, ok := s.Guest("guest-1")
	if !ok {
		t.Fatal("Guest() ok = false, want true")
	}
	if got.Role != protocol.RoleKicked {
		t.Fatalf("guest role = %q, want kicked", got.Role)
	}
}
