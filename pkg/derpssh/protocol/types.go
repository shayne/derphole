// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

const ProtocolVersion = 1

type Role string

const (
	RolePending Role = "pending"
	RoleRead    Role = "read"
	RoleWrite   Role = "write"
	RoleDenied  Role = "denied"
	RoleKicked  Role = "kicked"
)

func (r Role) CanWrite() bool {
	return r == RoleWrite
}

type StreamKind string

const (
	StreamControl     StreamKind = "control"
	StreamTerminalOut StreamKind = "terminal-out"
	StreamTerminalIn  StreamKind = "terminal-in"
	StreamChat        StreamKind = "chat"
)

type MessageType string

const (
	MessageHello       MessageType = "hello"
	MessageJoinRequest MessageType = "join-request"
	MessageDecision    MessageType = "decision"
	MessageRoleChange  MessageType = "role-change"
	MessageKick        MessageType = "kick"
	MessageResize      MessageType = "resize"
	MessageChat        MessageType = "chat"
	MessageTerminal    MessageType = "terminal"
	MessageClose       MessageType = "close"
	MessagePing        MessageType = "ping"
	MessagePong        MessageType = "pong"
)

type Message struct {
	Type       MessageType    `json:"type"`
	Hello      *Hello         `json:"hello,omitempty"`
	Decision   *Decision      `json:"decision,omitempty"`
	RoleChange *RoleChange    `json:"role_change,omitempty"`
	Kick       *Kick          `json:"kick,omitempty"`
	Resize     *Resize        `json:"resize,omitempty"`
	Chat       *Chat          `json:"chat,omitempty"`
	Terminal   *TerminalEvent `json:"terminal,omitempty"`
	Close      *Close         `json:"close,omitempty"`
	Ping       *Ping          `json:"ping,omitempty"`
	Pong       *Pong          `json:"pong,omitempty"`
}

type Hello struct {
	ProtocolVersion int    `json:"protocol_version"`
	ParticipantID   string `json:"participant_id"`
	DisplayName     string `json:"display_name"`
	Role            Role   `json:"role"`
}

type Decision struct {
	Accepted bool   `json:"accepted"`
	Role     Role   `json:"role,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type RoleChange struct {
	ParticipantID string `json:"participant_id"`
	Role          Role   `json:"role"`
}

type Kick struct {
	ParticipantID string `json:"participant_id"`
	Reason        string `json:"reason,omitempty"`
}

type Resize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type Chat struct {
	ParticipantID string `json:"participant_id"`
	DisplayName   string `json:"display_name"`
	Text          string `json:"text"`
	Seq           uint64 `json:"seq"`
}

type TerminalEvent struct {
	Seq  uint64 `json:"seq"`
	Data []byte `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type Close struct {
	Reason string `json:"reason"`
}

type Ping struct {
	ID uint64 `json:"id"`
}

type Pong struct {
	ID uint64 `json:"id"`
}
