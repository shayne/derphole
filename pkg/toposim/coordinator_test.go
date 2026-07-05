// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/transport"
)

func TestCoordinatorForwardsPeerControls(t *testing.T) {
	t.Parallel()

	left := newTestNodeEndpoint("left")
	right := newTestNodeEndpoint("right")
	coordinator, cancel := runTestCoordinator(t, "peer-control", left, right)
	defer cancel()

	left.emit(NodeEvent{
		Type: EventPeerControl,
		Node: "left",
		Peer: "right",
		Control: transport.ControlMessage{
			Type:       transport.ControlCandidates,
			Candidates: []string{"10.0.0.2:40000"},
		},
	})

	command := right.mustCommand(t)
	if command.Type != CommandPeerControl {
		t.Fatalf("forwarded command type = %q, want %q", command.Type, CommandPeerControl)
	}
	if command.Peer != "left" {
		t.Fatalf("forwarded command peer = %q, want left", command.Peer)
	}
	if command.Control.Type != transport.ControlCandidates || len(command.Control.Candidates) != 1 {
		t.Fatalf("forwarded control = %#v, want candidates", command.Control)
	}
	if got, want := coordinator.ForwardedControlCount(), 1; got != want {
		t.Fatalf("ForwardedControlCount() = %d, want %d", got, want)
	}
}

func TestCoordinatorForwardsRelayPayloads(t *testing.T) {
	t.Parallel()

	left := newTestNodeEndpoint("left")
	right := newTestNodeEndpoint("right")
	coordinator, cancel := runTestCoordinator(t, "relay", left, right)
	defer cancel()

	left.emit(NodeEvent{Type: EventRelaySend, Node: "left", Peer: "right", Payload: []byte("payload")})

	command := right.mustCommand(t)
	if command.Type != CommandRelayDelivery {
		t.Fatalf("forwarded command type = %q, want %q", command.Type, CommandRelayDelivery)
	}
	if string(command.Payload) != "payload" {
		t.Fatalf("forwarded payload = %q, want payload", command.Payload)
	}
	if got, want := coordinator.ForwardedRelayCount(), 1; got != want {
		t.Fatalf("ForwardedRelayCount() = %d, want %d", got, want)
	}
}

func TestCoordinatorRecordsPathTransitions(t *testing.T) {
	t.Parallel()

	left := newTestNodeEndpoint("left")
	coordinator, cancel := runTestCoordinator(t, "paths", left)
	defer cancel()

	left.emit(NodeEvent{Type: EventPath, Node: "left", Path: PathDirectName, Direct: "10.0.0.2:40000"})

	ctx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if err := coordinator.WaitForPath(ctx, ExpectedTransition{Node: "left", Path: PathDirectName, Direct: "10.0.0.2:40000"}); err != nil {
		t.Fatalf("WaitForPath() error = %v", err)
	}
	result := coordinator.Result()
	if !result.Saw(ExpectedTransition{Node: "left", Path: PathDirectName, Direct: "10.0.0.2:40000"}) {
		t.Fatalf("Result() did not record direct transition: %#v", result.Transitions)
	}
}

func TestCoordinatorWaitForPathTimesOutWithScenarioName(t *testing.T) {
	t.Parallel()

	coordinator := NewCoordinatorForTest("relay-fallback")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	err := coordinator.WaitForPath(ctx, ExpectedTransition{Node: "left", Path: PathDirectName})
	if err == nil {
		t.Fatal("WaitForPath() error = nil, want timeout")
	}
	if !strings.Contains(err.Error(), "relay-fallback") {
		t.Fatalf("WaitForPath() error = %v, want scenario name", err)
	}
}

func TestProcessWaitErrorIncludesStderr(t *testing.T) {
	t.Parallel()

	err := processWaitError(fmt.Errorf("exit status 1"), "node failed\n")
	if err == nil {
		t.Fatal("processWaitError() error = nil, want wrapped error")
	}
	if !strings.Contains(err.Error(), "node failed") {
		t.Fatalf("processWaitError() = %v, want stderr text", err)
	}
	if processWaitError(nil, "ignored") != nil {
		t.Fatal("processWaitError(nil) != nil")
	}
}

func runTestCoordinator(t *testing.T, scenario string, endpoints ...nodeEndpoint) (*Coordinator, context.CancelFunc) {
	t.Helper()

	coordinator := NewCoordinatorForTest(scenario, endpoints...)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- coordinator.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Coordinator.Run() error = %v", err)
		}
	})
	return coordinator, cancel
}

type testNodeEndpoint struct {
	name     string
	events   chan NodeEvent
	commands chan NodeCommand
}

func newTestNodeEndpoint(name string) *testNodeEndpoint {
	return &testNodeEndpoint{
		name:     name,
		events:   make(chan NodeEvent, 8),
		commands: make(chan NodeCommand, 8),
	}
}

func (e *testNodeEndpoint) Name() string {
	return e.name
}

func (e *testNodeEndpoint) Events() <-chan NodeEvent {
	return e.events
}

func (e *testNodeEndpoint) Send(_ context.Context, command NodeCommand) error {
	e.commands <- command
	return nil
}

func (e *testNodeEndpoint) Stop() error {
	close(e.events)
	return nil
}

func (e *testNodeEndpoint) emit(event NodeEvent) {
	e.events <- event
}

func (e *testNodeEndpoint) mustCommand(t *testing.T) NodeCommand {
	t.Helper()

	select {
	case command := <-e.commands:
		return command
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for node command")
		return NodeCommand{}
	}
}
