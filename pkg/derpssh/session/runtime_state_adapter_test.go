// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestRuntimeStateAdapterDeduplicatesReconnects(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeHost})
	a.UpsertPeer(PeerState{ID: "c1", Display: "shayne", Role: protocol.RoleWrite, Active: true})
	a.RemovePeer("c1", CloseReason{Code: "guest_quit", Message: "guest quit"})
	a.UpsertPeer(PeerState{ID: "c2", Display: "shayne", Role: protocol.RoleWrite, Active: true})

	peers := a.Snapshot().ActivePeers
	if len(peers) != 1 || peers[0].ID != "c2" {
		t.Fatalf("active peers = %#v, want c2 only", peers)
	}
}

func TestRuntimeStateAdapterRemovesDuplicateActiveDisplayName(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeHost})
	a.UpsertPeer(PeerState{ID: "c1", Display: "shayne", Role: protocol.RoleRead, Active: true})
	a.UpsertPeer(PeerState{ID: "c2", Display: "alex", Role: protocol.RoleRead, Active: true})
	a.UpsertPeer(PeerState{ID: "c3", Display: "shayne", Role: protocol.RoleWrite, Active: true})

	peers := a.Snapshot().ActivePeers
	if len(peers) != 2 {
		t.Fatalf("active peers = %#v, want two unique displays", peers)
	}
	if peers[0].ID != "c2" || peers[1].ID != "c3" {
		t.Fatalf("active peer order = %#v, want alex then latest shayne", peers)
	}
}

func TestRuntimeStateAdapterTracksCloseReason(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeGuest})
	a.SetCloseReason(CloseReason{Code: "host_quit", Message: "host quit"})

	reason := a.Snapshot().CloseReason
	if reason.Code != "host_quit" || reason.Message != "host quit" {
		t.Fatalf("CloseReason = %#v, want host quit", reason)
	}
}

func TestRuntimeStateAdapterPreservesDisplayNameOnRoleOnlyUpdate(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeHost})
	a.UpsertPeer(PeerState{ID: "guest-1", Display: "Alex", Role: protocol.RoleRead, Active: true})
	a.UpsertPeer(PeerState{ID: "guest-1", Role: protocol.RoleWrite, Active: true})

	peers := a.Snapshot().ActivePeers
	if len(peers) != 1 || peers[0].Display != "Alex" || peers[0].Role != protocol.RoleWrite {
		t.Fatalf("active peers = %#v, want Alex/write", peers)
	}
}

func TestRuntimeStateAdapterKeepsHostAuthoritativeSize(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeGuest, CanonicalCols: 80, CanonicalRows: 24})
	a.SetCanonicalSize(101, 30)

	snapshot := a.Snapshot()
	if snapshot.CanonicalCols != 101 || snapshot.CanonicalRows != 30 {
		t.Fatalf("canonical size = %dx%d, want 101x30", snapshot.CanonicalCols, snapshot.CanonicalRows)
	}
}

func TestRuntimeStateAdapterMapsApprovalFromLocalRole(t *testing.T) {
	a := NewRuntimeStateAdapter(RuntimeStateOptions{Mode: ModeGuest})
	a.SetLocalRole(protocol.RolePending)
	if got := a.Snapshot().Approval; got != ApprovalPending {
		t.Fatalf("pending approval = %q, want %q", got, ApprovalPending)
	}
	a.SetLocalRole(protocol.RoleWrite)
	if got := a.Snapshot().Approval; got != ApprovalApproved {
		t.Fatalf("write approval = %q, want %q", got, ApprovalApproved)
	}
}
