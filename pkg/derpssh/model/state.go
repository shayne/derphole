// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package model

import (
	"fmt"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type Participant struct {
	ID          string
	DisplayName string
	Role        protocol.Role
	Cols        int
	Rows        int
}

type HostState struct {
	hostID string
	cols   int
	rows   int
	guests map[string]Participant
}

func NewHostState(hostID string, cols, rows int) *HostState {
	return &HostState{hostID: hostID, cols: cols, rows: rows, guests: make(map[string]Participant)}
}

func (s *HostState) AddPendingGuest(id, name string) {
	s.guests[id] = Participant{ID: id, DisplayName: name, Role: protocol.RolePending}
}

func (s *HostState) ApproveGuest(id string, role protocol.Role) error {
	if role != protocol.RoleRead && role != protocol.RoleWrite {
		return fmt.Errorf("invalid approval role %q", role)
	}
	return s.SetGuestRole(id, role)
}

func (s *HostState) SetGuestRole(id string, role protocol.Role) error {
	p, ok := s.guests[id]
	if !ok {
		return fmt.Errorf("unknown guest %q", id)
	}
	p.Role = role
	s.guests[id] = p
	return nil
}

func (s *HostState) GuestCanWrite(id string) bool {
	p, ok := s.guests[id]
	return ok && p.Role.CanWrite()
}

func (s *HostState) Guest(id string) (Participant, bool) {
	p, ok := s.guests[id]
	return p, ok
}

func (s *HostState) KickGuest(id string) error {
	return s.SetGuestRole(id, protocol.RoleKicked)
}

func (s *HostState) NoteGuestSize(id string, cols, rows int) {
	p, ok := s.guests[id]
	if !ok {
		return
	}
	p.ID = id
	p.Cols = cols
	p.Rows = rows
	s.guests[id] = p
}

func (s *HostState) SetHostSize(cols, rows int) {
	s.cols, s.rows = cols, rows
}

func (s *HostState) HostSize() (int, int) {
	return s.cols, s.rows
}
