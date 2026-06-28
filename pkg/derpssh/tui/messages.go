// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

type Command interface {
	command()
}

type TerminalInputCommand struct {
	Data []byte
}

func (TerminalInputCommand) command() {}

type TerminalResizeCommand struct {
	Cols int
	Rows int
}

func (TerminalResizeCommand) command() {}

type ChatSendCommand struct {
	Body string
}

func (ChatSendCommand) command() {}

type QuitCommand struct{}

func (QuitCommand) command() {}

type CopyInviteCommand struct {
	Command string
}

func (CopyInviteCommand) command() {}

type RoleChangeCommand struct {
	PeerID string
	Peer   string
	Role   Role
}

func (RoleChangeCommand) command() {}

type KickCommand struct {
	PeerID string
	Peer   string
}

func (KickCommand) command() {}

type ApprovalDecisionCommand struct {
	PeerID string
	Peer   string
	Role   Role
	Deny   bool
}

func (ApprovalDecisionCommand) command() {}

type TerminalDataMsg []byte

type RuntimeStateMsg struct {
	Transport string
	HostCols  int
	HostRows  int
	LocalRole Role
	Peers     []Peer
}

type ChatMsg ChatMessage

type ApprovalRequestMsg struct {
	PeerID string
	Peer   string
}

type NoticeMsg struct {
	Title string
	Body  string
}
