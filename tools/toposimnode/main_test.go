// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/toposim"
	"github.com/shayne/derphole/pkg/transport"
)

func TestParseNodeCommand(t *testing.T) {
	t.Parallel()

	want := toposim.NodeCommand{
		Type:    toposim.CommandSendPeerDatagram,
		Payload: []byte("hello"),
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal(NodeCommand) error = %v", err)
	}

	got, err := parseNodeCommand(data)
	if err != nil {
		t.Fatalf("parseNodeCommand() error = %v", err)
	}
	if got.Type != want.Type || string(got.Payload) != string(want.Payload) {
		t.Fatalf("parseNodeCommand() = %#v, want %#v", got, want)
	}
}

func TestPathName(t *testing.T) {
	t.Parallel()

	if got := pathName(transport.PathRelay); got != toposim.PathRelayName {
		t.Fatalf("pathName(PathRelay) = %q, want %q", got, toposim.PathRelayName)
	}
	if got := pathName(transport.PathDirect); got != toposim.PathDirectName {
		t.Fatalf("pathName(PathDirect) = %q, want %q", got, toposim.PathDirectName)
	}
}

func TestHandleNodeCommandRoutesControlRelayAndState(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	peer := &fakePeerDatagramConn{}
	runtime := &nodeRuntime{
		ctx:        ctx,
		cancel:     cancel,
		events:     newEventWriter("left", &out),
		candidates: newAddrSet(nil),
		portmap:    newStaticPortmap(nil),
		controlCh:  make(chan transport.ControlMessage, 1),
		relayCh:    make(chan []byte, 1),
		peer:       peer,
	}

	if err := runtime.handleNodeCommand(toposim.NodeCommand{
		Type:       toposim.CommandPeerControl,
		Control:    transport.ControlMessage{Type: transport.ControlCandidates, Candidates: []string{"10.0.0.2:40000"}},
		Candidates: []string{"ignored"},
	}); err != nil {
		t.Fatalf("handle peer-control error = %v", err)
	}
	if got := <-runtime.controlCh; got.Type != transport.ControlCandidates {
		t.Fatalf("control type = %q, want candidates", got.Type)
	}

	if err := runtime.handleNodeCommand(toposim.NodeCommand{Type: toposim.CommandRelayDelivery, Payload: []byte("relay")}); err != nil {
		t.Fatalf("handle relay-delivery error = %v", err)
	}
	if got := string(<-runtime.relayCh); got != "relay" {
		t.Fatalf("relay payload = %q, want relay", got)
	}

	if err := runtime.handleNodeCommand(toposim.NodeCommand{Type: toposim.CommandSendPeerDatagram, Payload: []byte("peer")}); err != nil {
		t.Fatalf("handle send-peer-datagram error = %v", err)
	}
	if got := string(peer.sent); got != "peer" {
		t.Fatalf("peer sent = %q, want peer", got)
	}

	if err := runtime.handleNodeCommand(toposim.NodeCommand{Type: toposim.CommandSetCandidates, Candidates: []string{"10.0.0.3:40001"}}); err != nil {
		t.Fatalf("handle set-candidates error = %v", err)
	}
	if got := runtime.candidates.Snapshot()[0].String(); got != "10.0.0.3:40001" {
		t.Fatalf("candidate = %q, want 10.0.0.3:40001", got)
	}

	if err := runtime.handleNodeCommand(toposim.NodeCommand{Type: toposim.CommandSetPortmap, PortmapCandidates: []string{"10.0.0.4:41000"}}); err != nil {
		t.Fatalf("handle set-portmap error = %v", err)
	}
	if !runtime.portmap.Refresh(time.Now()) {
		t.Fatal("portmap Refresh() = false, want changed after set-portmap")
	}
	if got := runtime.portmap.SnapshotAddrs()[0].String(); got != "10.0.0.4:41000" {
		t.Fatalf("portmap candidate = %q, want 10.0.0.4:41000", got)
	}
}

func TestScanNodeCommandsReportsMalformedInputAndStops(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	runtime := &nodeRuntime{
		ctx:        ctx,
		cancel:     cancel,
		events:     newEventWriter("left", &out),
		candidates: newAddrSet(nil),
		portmap:    newStaticPortmap(nil),
		controlCh:  make(chan transport.ControlMessage, 1),
		relayCh:    make(chan []byte, 1),
		peer:       &fakePeerDatagramConn{},
	}
	input := strings.Join([]string{
		"{not-json",
		string(mustMarshalNodeCommand(t, toposim.NodeCommand{Type: toposim.CommandSetCandidates, Candidates: []string{"10.0.0.9:40000"}})),
		string(mustMarshalNodeCommand(t, toposim.NodeCommand{Type: toposim.CommandStop})),
	}, "\n")

	if err := runtime.scanNodeCommands(bufio.NewScanner(strings.NewReader(input))); err != nil {
		t.Fatalf("scanNodeCommands() error = %v", err)
	}
	if got := runtime.candidates.Snapshot()[0].String(); got != "10.0.0.9:40000" {
		t.Fatalf("candidate after scan = %q, want 10.0.0.9:40000", got)
	}
	events := decodeNodeEvents(t, out.Bytes())
	if len(events) != 1 || events[0].Type != toposim.EventError {
		t.Fatalf("events = %#v, want one parse error event", events)
	}
	if ctx.Err() == nil {
		t.Fatal("context error = nil, want canceled after stop command")
	}
}

func TestNodeRuntimeManagerCallbacksRouteEventsAndChannels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	runtime := &nodeRuntime{
		ctx:        ctx,
		cancel:     cancel,
		events:     newEventWriter("left", &out),
		candidates: newAddrSet([]string{"10.0.0.1:40000"}),
		portmap:    newStaticPortmap(nil),
		controlCh:  make(chan transport.ControlMessage, 1),
		relayCh:    make(chan []byte, 1),
	}

	if err := runtime.relaySend(ctx, []byte("relay-out")); err != nil {
		t.Fatalf("relaySend() error = %v", err)
	}
	runtime.relayCh <- []byte("relay-in")
	relayPayload, err := runtime.receiveRelay(ctx)
	if err != nil {
		t.Fatalf("receiveRelay() error = %v", err)
	}
	if string(relayPayload) != "relay-in" {
		t.Fatalf("receiveRelay() = %q, want relay-in", relayPayload)
	}
	if got := runtime.candidateSource(ctx)[0].String(); got != "10.0.0.1:40000" {
		t.Fatalf("candidateSource() = %q, want 10.0.0.1:40000", got)
	}
	if err := runtime.sendControl(ctx, transport.ControlMessage{Type: transport.ControlCandidates, Candidates: []string{"10.0.0.2:40001"}}); err != nil {
		t.Fatalf("sendControl() error = %v", err)
	}
	runtime.controlCh <- transport.ControlMessage{Type: transport.ControlCandidates, Candidates: []string{"10.0.0.3:40002"}}
	control, err := runtime.receiveControl(ctx)
	if err != nil {
		t.Fatalf("receiveControl() error = %v", err)
	}
	if got := control.Candidates[0]; got != "10.0.0.3:40002" {
		t.Fatalf("receiveControl() candidate = %q, want 10.0.0.3:40002", got)
	}

	events := decodeNodeEvents(t, out.Bytes())
	if len(events) != 2 {
		t.Fatalf("events = %#v, want relay-send and peer-control", events)
	}
	if events[0].Type != toposim.EventRelaySend || string(events[0].Payload) != "relay-out" {
		t.Fatalf("relay event = %#v, want relay-send relay-out", events[0])
	}
	if events[1].Type != toposim.EventPeerControl || events[1].Candidates[0] != "10.0.0.2:40001" {
		t.Fatalf("control event = %#v, want peer-control candidates", events[1])
	}
}

func mustMarshalNodeCommand(t *testing.T, command toposim.NodeCommand) []byte {
	t.Helper()
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("Marshal(NodeCommand) error = %v", err)
	}
	return data
}

func decodeNodeEvents(t *testing.T, data []byte) []toposim.NodeEvent {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var events []toposim.NodeEvent
	for {
		var event toposim.NodeEvent
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				return events
			}
			t.Fatalf("Decode(NodeEvent) error = %v; data=%q", err, data)
		}
		events = append(events, event)
	}
}

type fakePeerDatagramConn struct {
	sent []byte
}

func (p *fakePeerDatagramConn) SendDatagram(payload []byte) error {
	p.sent = append([]byte(nil), payload...)
	return nil
}

func (p *fakePeerDatagramConn) RecvDatagram(context.Context) ([]byte, net.Addr, error) {
	return nil, nil, context.Canceled
}

func (p *fakePeerDatagramConn) LocalAddr() net.Addr {
	return nil
}

func (p *fakePeerDatagramConn) RemoteAddr() net.Addr {
	return nil
}

func (p *fakePeerDatagramConn) ReleaseDatagram([]byte) {}

func (p *fakePeerDatagramConn) Close() error {
	return nil
}
