// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "github.com/shayne/derphole/pkg/derpssh/protocol"

type Focus int

const (
	FocusTerminal Focus = iota
	FocusChat
	FocusApproval
)

type Role string

const (
	RolePending Role = "pending"
	RoleRead    Role = "read"
	RoleWrite   Role = "write"
)

type Peer struct {
	ID   string
	Name string
	Role Role
}

type ChatMessage struct {
	Author string
	Body   string
	Local  bool
}

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
	app          *App
	pendingGuest pendingGuest
	decision     Decision
}

func NewModel(mode Mode, cols, rows int) Model {
	if mode == "" {
		mode = ModeGuest
	}
	app := NewApp(Options{Side: string(mode), Terminal: NewVTTerminalPane(cols, rows)})
	app.SetWindowSize(cols, rows)
	return Model{app: app}
}

func (m Model) Decision() Decision {
	return m.decision
}

func (m *Model) SetPendingGuest(id, name string) {
	m.pendingGuest = pendingGuest{id: id, name: name}
	m.decision = Decision{}
	if m.app != nil {
		m.app.approvalPeerID = id
		m.app.approvalPeer = name
		m.app.focus = FocusApproval
	}
}

func (m *Model) SetRole(role protocol.Role) {
	if m.app != nil {
		m.app.localRole = Role(role)
	}
}

func (m *Model) SetSize(cols, rows int) {
	if m.app != nil {
		m.app.SetWindowSize(cols, rows)
	}
}

func (m *Model) SetPeer(name string, role protocol.Role) {
	if m.app == nil {
		return
	}
	if name == "" {
		m.app.peers = nil
		return
	}
	m.app.peers = []Peer{{Name: name, Role: Role(role)}}
}

func (m *Model) SetTransportStatus(status string) {
	if m.app != nil {
		m.app.transport = status
	}
}

func (m *Model) SetFocus(focus string) {
	if m.app == nil {
		return
	}
	switch focus {
	case "chat", "composer", "sidechat":
		m.app.focusChat()
	case "approval":
		m.app.focus = FocusApproval
	default:
		m.app.focusTerminal()
	}
}

func (m *Model) SetInviteCommand(command string) {
	if m.app != nil {
		m.app.inviteCommand = command
	}
}

func (m *Model) SetTerminalText(text string) {
	if m.app != nil {
		m.app.terminal = &staticTerminalPane{text: text}
	}
}

func (m *Model) AppendTerminalText(text string, limit int) {
	if text == "" || m.app == nil {
		return
	}
	_, _ = m.app.terminal.Write([]byte(text))
}

func (m *Model) AddSidechatLine(line string) {
	if m.app == nil {
		return
	}
	m.app.chatMessages = append(m.app.chatMessages, ChatMessage{Author: "sidechat", Body: line})
	if len(m.app.chatMessages) > 128 {
		tail := m.app.chatMessages[len(m.app.chatMessages)-128:]
		m.app.chatMessages = append([]ChatMessage(nil), tail...)
	}
}

func (m *Model) HandleKey(key string) {
	if m.pendingGuest.id == "" {
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

func (m Model) View() string {
	if m.app == nil {
		return ""
	}
	return m.app.View().Content
}

func (m *Model) decide(role protocol.Role) {
	m.decision = Decision{
		GuestID:   m.pendingGuest.id,
		GuestName: m.pendingGuest.name,
		Accepted:  true,
		Role:      role,
	}
	m.pendingGuest = pendingGuest{}
	if m.app != nil {
		m.app.approvalPeerID = ""
		m.app.approvalPeer = ""
		m.app.focusTerminal()
	}
}

func (m *Model) deny() {
	m.decision = Decision{
		GuestID:   m.pendingGuest.id,
		GuestName: m.pendingGuest.name,
		Accepted:  false,
		Role:      protocol.RoleDenied,
	}
	m.pendingGuest = pendingGuest{}
	if m.app != nil {
		m.app.approvalPeerID = ""
		m.app.approvalPeer = ""
		m.app.focusTerminal()
	}
}
