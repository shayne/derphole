// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/shayne/derphole/pkg/derpssh/protocol"

func (m *Model) HandleKey(key string) {
	if m.mode != ModeHost || m.pendingGuest.id == "" {
		return
	}

	switch key {
	case "r", "R":
		m.decide(protocol.RoleRead)
	case "w", "W":
		m.decide(protocol.RoleWrite)
	case "n", "N":
		m.deny()
	}
}

func (m *Model) decide(role protocol.Role) {
	m.decision = Decision{
		GuestID:   m.pendingGuest.id,
		GuestName: m.pendingGuest.name,
		Accepted:  true,
		Role:      role,
	}
	m.pendingGuest = pendingGuest{}
}

func (m *Model) deny() {
	m.decision = Decision{
		GuestID:   m.pendingGuest.id,
		GuestName: m.pendingGuest.name,
		Accepted:  false,
		Role:      protocol.RoleDenied,
	}
	m.pendingGuest = pendingGuest{}
}
