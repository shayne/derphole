// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"io"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derptun"
)

type Approval interface {
	Approve(JoinRequest) protocol.Role
}

type JoinRequest struct {
	ParticipantID string
	DisplayName   string
}

type StaticApproval struct {
	Role protocol.Role
}

func (a StaticApproval) Approve(JoinRequest) protocol.Role {
	return a.Role
}

type HostConfig struct {
	Mux         *derptun.Mux
	HostID      string
	HostName    string
	InitialCols int
	InitialRows int
	PTYInput    io.Writer
	PTYOutput   io.Reader
	LocalInput  io.Reader
	LocalOutput io.Writer
	Approval    Approval
	Observer    RuntimeObserver
}

type GuestConfig struct {
	Mux            *derptun.Mux
	ParticipantID  string
	DisplayName    string
	TerminalOutput io.Writer
	Observer       RuntimeObserver
}
