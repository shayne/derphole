// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

type nodeEndpoint interface {
	Name() string
	Events() <-chan NodeEvent
	Send(context.Context, NodeCommand) error
	Stop() error
}

type Coordinator struct {
	scenario string
	nodes    map[string]nodeEndpoint
	start    time.Time

	mu               sync.Mutex
	events           []NodeEvent
	transitions      []ObservedTransition
	candidateCounts  map[string]int
	forwardedControl int
	forwardedRelay   int
	notify           chan struct{}
}

type ObservedTransition struct {
	Node   string
	Path   string
	Direct string
	At     time.Duration
}

type Result struct {
	Transitions     []ObservedTransition
	CandidateCounts map[string]int
	Events          []NodeEvent
}

func NewCoordinatorForTest(scenario string, endpoints ...nodeEndpoint) *Coordinator {
	c := &Coordinator{
		scenario:        scenario,
		nodes:           make(map[string]nodeEndpoint, len(endpoints)),
		start:           time.Now(),
		candidateCounts: make(map[string]int),
		notify:          make(chan struct{}),
	}
	for _, endpoint := range endpoints {
		c.nodes[endpoint.Name()] = endpoint
	}
	return c
}

func (c *Coordinator) Run(ctx context.Context) error {
	errCh := make(chan error, len(c.nodes))
	for _, endpoint := range c.nodes {
		endpoint := endpoint
		go func() {
			errCh <- c.runEndpoint(ctx, endpoint)
		}()
	}

	remaining := len(c.nodes)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			for _, endpoint := range c.nodes {
				_ = endpoint.Stop()
			}
			return ctx.Err()
		case err := <-errCh:
			remaining--
			if err != nil {
				for _, endpoint := range c.nodes {
					_ = endpoint.Stop()
				}
				return err
			}
		}
	}
	return nil
}

func (c *Coordinator) runEndpoint(ctx context.Context, endpoint nodeEndpoint) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-endpoint.Events():
			if !ok {
				return nil
			}
			if err := c.handleEvent(ctx, event); err != nil {
				return err
			}
		}
	}
}

func (c *Coordinator) handleEvent(ctx context.Context, event NodeEvent) error {
	c.recordEvent(event)

	switch event.Type {
	case EventPeerControl:
		peer := c.peerName(event)
		if peer == "" {
			return fmt.Errorf("%s: peer-control from %q has no peer", c.scenario, event.Node)
		}
		return c.send(ctx, peer, NodeCommand{Type: CommandPeerControl, Peer: event.Node, Control: event.Control})
	case EventRelaySend:
		peer := c.peerName(event)
		if peer == "" {
			return fmt.Errorf("%s: relay-send from %q has no peer", c.scenario, event.Node)
		}
		return c.send(ctx, peer, NodeCommand{Type: CommandRelayDelivery, Peer: event.Node, Payload: event.Payload})
	case EventError:
		return fmt.Errorf("%s: node %s: %s", c.scenario, event.Node, event.Error)
	default:
		return nil
	}
}

func (c *Coordinator) recordEvent(event NodeEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.events = append(c.events, event)
	if len(event.Candidates) > c.candidateCounts[event.Node] {
		c.candidateCounts[event.Node] = len(event.Candidates)
	}
	if event.Type == EventPath {
		c.transitions = append(c.transitions, ObservedTransition{
			Node:   event.Node,
			Path:   event.Path,
			Direct: event.Direct,
			At:     time.Since(c.start),
		})
	}
	c.signalLocked()
}

func (c *Coordinator) send(ctx context.Context, node string, command NodeCommand) error {
	endpoint := c.nodes[node]
	if endpoint == nil {
		return fmt.Errorf("%s: unknown node %q", c.scenario, node)
	}
	if err := endpoint.Send(ctx, command); err != nil {
		return err
	}

	c.mu.Lock()
	switch command.Type {
	case CommandPeerControl:
		c.forwardedControl++
	case CommandRelayDelivery:
		c.forwardedRelay++
	}
	c.signalLocked()
	c.mu.Unlock()
	return nil
}

func (c *Coordinator) SendNode(ctx context.Context, node string, command NodeCommand) error {
	return c.send(ctx, node, command)
}

func (c *Coordinator) peerName(event NodeEvent) string {
	if event.Peer != "" {
		return event.Peer
	}
	for name := range c.nodes {
		if name != event.Node {
			return name
		}
	}
	return ""
}

func (c *Coordinator) WaitForPath(ctx context.Context, expect ExpectedTransition) error {
	if expect.Within > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, expect.Within)
		defer cancel()
	}
	for {
		c.mu.Lock()
		if c.resultLocked().Saw(expect) {
			c.mu.Unlock()
			return nil
		}
		notify := c.notify
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: timed out waiting for %s path on %s: %w", c.scenario, expect.Path, expect.Node, ctx.Err())
		case <-notify:
		}
	}
}

func (c *Coordinator) Result() Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resultLocked()
}

func (c *Coordinator) resultLocked() Result {
	transitions := append([]ObservedTransition(nil), c.transitions...)
	events := append([]NodeEvent(nil), c.events...)
	candidateCounts := make(map[string]int, len(c.candidateCounts))
	for node, count := range c.candidateCounts {
		candidateCounts[node] = count
	}
	return Result{Transitions: transitions, CandidateCounts: candidateCounts, Events: events}
}

func (c *Coordinator) ForwardedControlCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forwardedControl
}

func (c *Coordinator) ForwardedRelayCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forwardedRelay
}

func (c *Coordinator) signalLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

func (r Result) Saw(expect ExpectedTransition) bool {
	for _, transition := range r.Transitions {
		if transition.Node != expect.Node || transition.Path != expect.Path {
			continue
		}
		if expect.Direct != "" && transition.Direct != expect.Direct {
			continue
		}
		if expect.Within > 0 && transition.At > expect.Within {
			continue
		}
		return true
	}
	return false
}

func (r Result) CandidateCountAtMost(node string, max int) bool {
	count, ok := r.CandidateCounts[node]
	return ok && count <= max
}

type ProcessEndpoint struct {
	name   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	events chan NodeEvent
	wait   chan error
	stderr bytes.Buffer
}

func StartProcessEndpoint(ctx context.Context, name string, command []string) (*ProcessEndpoint, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("empty process command for %s", name)
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	endpoint, stdout, err := newProcessEndpoint(name, cmd)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	endpoint.watch(stdout)
	return endpoint, nil
}

func newProcessEndpoint(name string, cmd *exec.Cmd) (*ProcessEndpoint, io.Reader, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	endpoint := &ProcessEndpoint{
		name:   name,
		cmd:    cmd,
		stdin:  stdin,
		events: make(chan NodeEvent, 64),
		wait:   make(chan error, 1),
	}
	cmd.Stderr = &endpoint.stderr
	return endpoint, stdout, nil
}

func (e *ProcessEndpoint) watch(stdout io.Reader) {
	go func() {
		e.wait <- processWaitError(e.cmd.Wait(), e.stderr.String())
	}()
	go e.readEvents(stdout)
}

func processWaitError(err error, stderr string) error {
	if err != nil && stderr != "" {
		return fmt.Errorf("%w: %s", err, stderr)
	}
	return err
}

func (e *ProcessEndpoint) Name() string {
	return e.name
}

func (e *ProcessEndpoint) Events() <-chan NodeEvent {
	return e.events
}

func (e *ProcessEndpoint) Send(_ context.Context, command NodeCommand) error {
	data, err := json.Marshal(command)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.stdin, "%s\n", data)
	return err
}

func (e *ProcessEndpoint) Stop() error {
	_ = e.Send(context.Background(), NodeCommand{Type: CommandStop})
	_ = e.stdin.Close()
	select {
	case err := <-e.wait:
		return err
	case <-time.After(5 * time.Second):
		if e.cmd.Process != nil {
			_ = e.cmd.Process.Kill()
		}
		return fmt.Errorf("timed out stopping %s", e.name)
	}
}

func (e *ProcessEndpoint) readEvents(stdout io.Reader) {
	defer close(e.events)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var event NodeEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			e.events <- NodeEvent{Type: EventError, Node: e.name, Error: err.Error()}
			continue
		}
		if event.Node == "" {
			event.Node = e.name
		}
		e.events <- event
	}
	if err := scanner.Err(); err != nil {
		e.events <- NodeEvent{Type: EventError, Node: e.name, Error: err.Error()}
	}
}
