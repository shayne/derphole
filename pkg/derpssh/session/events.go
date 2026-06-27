// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "github.com/shayne/derphole/pkg/derpssh/protocol"

type RuntimeEventKind string

const (
	RuntimeEventStatus RuntimeEventKind = "status"
	RuntimeEventChat   RuntimeEventKind = "chat"
	RuntimeEventRole   RuntimeEventKind = "role"
	RuntimeEventPeer   RuntimeEventKind = "peer"
	RuntimeEventResize RuntimeEventKind = "resize"
	RuntimeEventClose  RuntimeEventKind = "close"
)

type RuntimeEvent struct {
	Kind          RuntimeEventKind
	Message       string
	ParticipantID string
	DisplayName   string
	Role          protocol.Role
	Cols          int
	Rows          int
	Chat          ChatMessage
}

type RuntimeObserver interface {
	OnRuntimeEvent(RuntimeEvent)
}
