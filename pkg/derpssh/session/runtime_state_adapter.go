// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type RuntimeMode string

const (
	ModeHost  RuntimeMode = "host"
	ModeGuest RuntimeMode = "guest"
)

type DisplayName string

type ShellState string

const (
	ShellUnknown ShellState = ""
	ShellRunning ShellState = "running"
	ShellExited  ShellState = "exited"
)

type ApprovalState string

const (
	ApprovalUnknown  ApprovalState = ""
	ApprovalPending  ApprovalState = "pending"
	ApprovalApproved ApprovalState = "approved"
	ApprovalDenied   ApprovalState = "denied"
)

type PeerState struct {
	ID      string
	Display DisplayName
	Role    protocol.Role
	Active  bool
}

type RuntimeSnapshot struct {
	Mode          RuntimeMode
	LocalName     DisplayName
	Transport     string
	CanonicalCols int
	CanonicalRows int
	Shell         ShellState
	Approval      ApprovalState
	LocalRole     protocol.Role
	ActivePeers   []PeerState
	CloseReason   CloseReason
}

type RuntimeStateOptions struct {
	Mode          RuntimeMode
	LocalName     DisplayName
	CanonicalCols int
	CanonicalRows int
}

type RuntimeStateAdapter struct {
	mu       sync.Mutex
	snapshot RuntimeSnapshot
	peers    map[string]PeerState
	order    []string
}

func NewRuntimeStateAdapter(opts RuntimeStateOptions) *RuntimeStateAdapter {
	mode := opts.Mode
	if mode == "" {
		mode = ModeGuest
	}
	return &RuntimeStateAdapter{
		snapshot: RuntimeSnapshot{
			Mode:          mode,
			LocalName:     opts.LocalName,
			CanonicalCols: opts.CanonicalCols,
			CanonicalRows: opts.CanonicalRows,
			Shell:         ShellRunning,
			Approval:      ApprovalUnknown,
			LocalRole:     protocol.RolePending,
		},
		peers: make(map[string]PeerState),
	}
}

func (a *RuntimeStateAdapter) SetTransport(transport string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.Transport = strings.TrimSpace(transport)
}

func (a *RuntimeStateAdapter) SetLocalRole(role protocol.Role) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.LocalRole = normalizeRuntimeRole(role)
	switch {
	case roleGranted(a.snapshot.LocalRole):
		a.snapshot.Approval = ApprovalApproved
	case a.snapshot.LocalRole == protocol.RoleDenied:
		a.snapshot.Approval = ApprovalDenied
	default:
		a.snapshot.Approval = ApprovalPending
	}
}

func (a *RuntimeStateAdapter) SetCanonicalSize(cols, rows int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.CanonicalCols = cols
	a.snapshot.CanonicalRows = rows
}

func (a *RuntimeStateAdapter) SetShell(shell ShellState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.Shell = shell
}

func (a *RuntimeStateAdapter) SetCloseReason(reason CloseReason) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.CloseReason = reason
}

func (a *RuntimeStateAdapter) UpsertPeer(peer PeerState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	peer.ID = strings.TrimSpace(peer.ID)
	peer.Display = DisplayName(strings.TrimSpace(string(peer.Display)))
	if peer.ID == "" {
		peer.ID = string(peer.Display)
	}
	if peer.ID == "" {
		return
	}
	if peer.Role == "" {
		peer.Role = protocol.RolePending
	}
	existing, hasExisting := a.peers[peer.ID]
	if peer.Display == "" {
		if hasExisting {
			peer.Display = existing.Display
		}
		if peer.Display == "" {
			peer.Display = DisplayName(peer.ID)
		}
	}
	if !peer.Active {
		a.removePeerLocked(peer.ID)
		return
	}
	a.removeDuplicateDisplayLocked(peer.ID, peer.Display)
	if _, ok := a.peers[peer.ID]; !ok {
		a.order = append(a.order, peer.ID)
	}
	a.peers[peer.ID] = peer
}

func (a *RuntimeStateAdapter) RemovePeer(id string, reason CloseReason) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removePeerLocked(id)
	if reason.Code != "" || reason.Message != "" {
		a.snapshot.CloseReason = reason
	}
}

func (a *RuntimeStateAdapter) ClearPeers() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.peers)
	a.order = nil
}

func (a *RuntimeStateAdapter) Snapshot() RuntimeSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot := a.snapshot
	snapshot.ActivePeers = make([]PeerState, 0, len(a.order))
	for _, id := range a.order {
		peer, ok := a.peers[id]
		if ok && peer.Active {
			snapshot.ActivePeers = append(snapshot.ActivePeers, peer)
		}
	}
	return snapshot
}

func (a *RuntimeStateAdapter) removeDuplicateDisplayLocked(id string, display DisplayName) {
	if strings.TrimSpace(string(display)) == "" {
		return
	}
	for _, existingID := range a.order {
		if existingID == id {
			continue
		}
		existing := a.peers[existingID]
		if existing.Active && existing.Display == display {
			delete(a.peers, existingID)
		}
	}
	a.compactOrderLocked()
}

func (a *RuntimeStateAdapter) removePeerLocked(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	delete(a.peers, id)
	a.compactOrderLocked()
}

func (a *RuntimeStateAdapter) compactOrderLocked() {
	if len(a.order) == 0 {
		return
	}
	compact := a.order[:0]
	for _, id := range a.order {
		if peer, ok := a.peers[id]; ok && peer.Active {
			compact = append(compact, id)
		}
	}
	a.order = compact
}

func normalizeRuntimeRole(role protocol.Role) protocol.Role {
	if role == "" {
		return protocol.RolePending
	}
	return role
}
