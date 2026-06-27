// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/shayne/derphole/pkg/derpssh/protocol"

type Mode string

const (
	ModeHost  Mode = "host"
	ModeGuest Mode = "guest"
)

type Decision struct {
	GuestID   string
	GuestName string
	Accepted  bool
	Role      protocol.Role
}

type pendingGuest struct {
	id   string
	name string
}

type Model struct {
	mode Mode
	cols int
	rows int

	role         protocol.Role
	pendingGuest pendingGuest
	decision     Decision

	terminalText  string
	sidechatLines []string
}

func NewModel(mode Mode, cols, rows int) Model {
	if mode == "" {
		mode = ModeGuest
	}
	return Model{
		mode: mode,
		cols: cols,
		rows: rows,
		role: protocol.RolePending,
	}
}

func (m Model) Decision() Decision {
	return m.decision
}

func (m *Model) SetPendingGuest(id, name string) {
	m.pendingGuest = pendingGuest{id: id, name: name}
	m.decision = Decision{}
}

func (m *Model) SetRole(role protocol.Role) {
	m.role = role
}

func (m *Model) SetTerminalText(text string) {
	m.terminalText = text
}

func (m *Model) AddSidechatLine(line string) {
	m.sidechatLines = append(m.sidechatLines, line)
}
