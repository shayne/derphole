// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/shayne/derphole/pkg/transport"
)

func TestNodeCommandPeerControlRoundTrip(t *testing.T) {
	t.Parallel()

	command := NodeCommand{
		Type: CommandPeerControl,
		Peer: "right",
		Control: transport.ControlMessage{
			Type:       transport.ControlCandidates,
			Candidates: []string{"10.42.0.2:40000"},
		},
	}

	data, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("Marshal(NodeCommand) error = %v", err)
	}
	var got NodeCommand
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal(NodeCommand) error = %v", err)
	}
	if !reflect.DeepEqual(got, command) {
		t.Fatalf("NodeCommand round trip = %#v, want %#v", got, command)
	}
}

func TestNodeEventDirectPathRoundTrip(t *testing.T) {
	t.Parallel()

	event := NodeEvent{
		Type:   EventPath,
		Node:   "left",
		Path:   PathDirectName,
		Direct: "10.42.0.3:40001",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal(NodeEvent) error = %v", err)
	}
	var got NodeEvent
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal(NodeEvent) error = %v", err)
	}
	if !reflect.DeepEqual(got, event) {
		t.Fatalf("NodeEvent round trip = %#v, want %#v", got, event)
	}
}
