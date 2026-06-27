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

	role          protocol.Role
	peerName      string
	peerRole      protocol.Role
	transport     string
	focus         string
	inviteCommand string
	pendingGuest  pendingGuest
	decision      Decision

	terminalText  string
	sidechatLines []string
}

func NewModel(mode Mode, cols, rows int) Model {
	if mode == "" {
		mode = ModeGuest
	}
	return Model{
		mode:      mode,
		cols:      cols,
		rows:      rows,
		role:      protocol.RolePending,
		peerRole:  protocol.RolePending,
		transport: "starting",
		focus:     "terminal",
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

func (m *Model) SetSize(cols, rows int) {
	if cols > 0 {
		m.cols = cols
	}
	if rows > 0 {
		m.rows = rows
	}
}

func (m *Model) SetPeer(name string, role protocol.Role) {
	m.peerName = name
	m.peerRole = role
}

func (m *Model) SetTransportStatus(status string) {
	m.transport = status
}

func (m *Model) SetFocus(focus string) {
	m.focus = focus
}

func (m *Model) SetInviteCommand(command string) {
	m.inviteCommand = command
}

func (m *Model) SetTerminalText(text string) {
	m.terminalText = text
}

func (m *Model) AppendTerminalText(text string, limit int) {
	if text == "" {
		return
	}
	m.terminalText += text
	if limit > 0 && len(m.terminalText) > limit {
		m.terminalText = m.terminalText[len(m.terminalText)-limit:]
	}
}

func (m *Model) AddSidechatLine(line string) {
	m.sidechatLines = append(m.sidechatLines, line)
	if len(m.sidechatLines) > 128 {
		tail := m.sidechatLines[len(m.sidechatLines)-128:]
		m.sidechatLines = append([]string(nil), tail...)
	}
}
