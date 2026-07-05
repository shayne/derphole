// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import "github.com/shayne/derphole/pkg/transport"

type NodeCommandType string

const (
	CommandPeerControl      NodeCommandType = "peer-control"
	CommandRelayDelivery    NodeCommandType = "relay-delivery"
	CommandSendPeerDatagram NodeCommandType = "send-peer-datagram"
	CommandSetCandidates    NodeCommandType = "set-candidates"
	CommandSetPortmap       NodeCommandType = "set-portmap"
	CommandStop             NodeCommandType = "stop"
)

type NodeCommand struct {
	Type              NodeCommandType          `json:"type"`
	Node              string                   `json:"node,omitempty"`
	Peer              string                   `json:"peer,omitempty"`
	Control           transport.ControlMessage `json:"control,omitempty"`
	Payload           []byte                   `json:"payload,omitempty"`
	Candidates        []string                 `json:"candidates,omitempty"`
	PortmapCandidates []string                 `json:"portmapCandidates,omitempty"`
}

type NodeEventType string

const (
	EventReady        NodeEventType = "ready"
	EventPath         NodeEventType = "path"
	EventPeerControl  NodeEventType = "peer-control"
	EventRelaySend    NodeEventType = "relay-send"
	EventPeerDatagram NodeEventType = "peer-datagram"
	EventError        NodeEventType = "error"
)

type NodeEvent struct {
	Type       NodeEventType            `json:"type"`
	Node       string                   `json:"node,omitempty"`
	Peer       string                   `json:"peer,omitempty"`
	Path       string                   `json:"path,omitempty"`
	Direct     string                   `json:"direct,omitempty"`
	Control    transport.ControlMessage `json:"control,omitempty"`
	Payload    []byte                   `json:"payload,omitempty"`
	Candidates []string                 `json:"candidates,omitempty"`
	Error      string                   `json:"error,omitempty"`
}
