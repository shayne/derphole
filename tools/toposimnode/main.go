// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/toposim"
	"github.com/shayne/derphole/pkg/transport"
)

var errStopNode = errors.New("stop toposim node")

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("toposimnode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "node name")
	directPort := fs.Int("direct-port", 0, "direct UDP port")
	candidates := fs.String("candidates", "", "comma-separated local candidates")
	portmapCandidates := fs.String("portmap-candidates", "", "comma-separated mapped candidates")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("missing -name")
	}
	if *directPort <= 0 || *directPort > 65535 {
		return errors.New("missing or invalid -direct-port")
	}

	cfg := nodeConfig{
		name:              *name,
		directPort:        *directPort,
		candidates:        splitCSV(*candidates),
		portmapCandidates: splitCSV(*portmapCandidates),
	}
	return runNode(context.Background(), cfg, stdin, stdout)
}

type nodeConfig struct {
	name              string
	directPort        int
	candidates        []string
	portmapCandidates []string
}

func runNode(parent context.Context, cfg nodeConfig, stdin io.Reader, stdout io.Writer) error {
	runtime, err := newNodeRuntime(parent, cfg, stdin, stdout)
	if err != nil {
		return err
	}
	defer runtime.close()
	if err := runtime.start(); err != nil {
		return err
	}
	return runtime.runCommandLoop()
}

type nodeRuntime struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cfg        nodeConfig
	stdin      io.Reader
	events     *eventWriter
	candidates *addrSet
	portmap    *staticPortmap
	controlCh  chan transport.ControlMessage
	relayCh    chan []byte
	manager    *transport.Manager
	peer       transport.PeerDatagramConn
	directConn net.PacketConn
}

func newNodeRuntime(parent context.Context, cfg nodeConfig, stdin io.Reader, stdout io.Writer) (*nodeRuntime, error) {
	ctx, cancel := context.WithCancel(parent)
	directConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.directPort))
	if err != nil {
		cancel()
		return nil, err
	}
	return &nodeRuntime{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		stdin:      stdin,
		events:     newEventWriter(cfg.name, stdout),
		candidates: newAddrSet(cfg.candidates),
		portmap:    newStaticPortmap(cfg.portmapCandidates),
		controlCh:  make(chan transport.ControlMessage, 64),
		relayCh:    make(chan []byte, 64),
		directConn: directConn,
	}, nil
}

func (r *nodeRuntime) start() error {
	r.manager = transport.NewManager(r.managerConfig())
	if err := r.manager.Start(r.ctx); err != nil {
		return err
	}
	r.peer = r.manager.PeerDatagramConn(r.ctx)

	_ = r.events.Emit(toposim.NodeEvent{Type: toposim.EventReady})
	go emitPathUpdates(r.ctx, r.cfg.name, r.manager, r.events)
	go emitPeerDatagrams(r.ctx, r.peer, r.events)
	return nil
}

func (r *nodeRuntime) managerConfig() transport.ManagerConfig {
	return transport.ManagerConfig{
		RelaySend:               r.relaySend,
		ReceiveRelay:            r.receiveRelay,
		RelayAddr:               &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9},
		DirectConn:              r.directConn,
		CandidateSource:         r.candidateSource,
		Portmap:                 r.portmap,
		SendControl:             r.sendControl,
		ReceiveControl:          r.receiveControl,
		DiscoveryInterval:       100 * time.Millisecond,
		EndpointRefreshInterval: 100 * time.Millisecond,
		DirectStaleTimeout:      750 * time.Millisecond,
	}
}

func (r *nodeRuntime) relaySend(_ context.Context, payload []byte) error {
	return r.events.Emit(toposim.NodeEvent{Type: toposim.EventRelaySend, Payload: append([]byte(nil), payload...)})
}

func (r *nodeRuntime) receiveRelay(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-r.relayCh:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *nodeRuntime) candidateSource(context.Context) []net.Addr {
	return r.candidates.Snapshot()
}

func (r *nodeRuntime) sendControl(_ context.Context, msg transport.ControlMessage) error {
	event := toposim.NodeEvent{Type: toposim.EventPeerControl, Control: msg}
	if msg.Type == transport.ControlCandidates {
		event.Candidates = append([]string(nil), msg.Candidates...)
	}
	return r.events.Emit(event)
}

func (r *nodeRuntime) receiveControl(ctx context.Context) (transport.ControlMessage, error) {
	select {
	case msg := <-r.controlCh:
		return msg, nil
	case <-ctx.Done():
		return transport.ControlMessage{}, ctx.Err()
	}
}

func (r *nodeRuntime) runCommandLoop() error {
	return r.scanNodeCommands(bufio.NewScanner(r.stdin))
}

func (r *nodeRuntime) scanNodeCommands(scanner *bufio.Scanner) error {
	for scanner.Scan() {
		stop, err := r.scanNodeCommand(scanner.Bytes())
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return scanner.Err()
}

func (r *nodeRuntime) scanNodeCommand(data []byte) (bool, error) {
	command, err := parseNodeCommand(data)
	if err != nil {
		_ = r.events.Emit(toposim.NodeEvent{Type: toposim.EventError, Error: err.Error()})
		return false, nil
	}
	err = r.handleNodeCommand(command)
	if errors.Is(err, errStopNode) {
		return true, nil
	}
	return false, err
}

func (r *nodeRuntime) handleNodeCommand(command toposim.NodeCommand) error {
	switch command.Type {
	case toposim.CommandPeerControl:
		return sendOrCancel(r.ctx, r.controlCh, command.Control)
	case toposim.CommandRelayDelivery:
		return sendOrCancel(r.ctx, r.relayCh, append([]byte(nil), command.Payload...))
	case toposim.CommandSendPeerDatagram:
		return r.sendPeerDatagram(command.Payload)
	case toposim.CommandSetCandidates:
		r.candidates.Set(command.Candidates)
		return nil
	case toposim.CommandSetPortmap:
		r.portmap.Set(command.PortmapCandidates)
		return nil
	case toposim.CommandStop:
		r.cancel()
		return errStopNode
	default:
		_ = r.events.Emit(toposim.NodeEvent{Type: toposim.EventError, Error: fmt.Sprintf("unknown command type %q", command.Type)})
		return nil
	}
}

func sendOrCancel[T any](ctx context.Context, ch chan<- T, value T) error {
	select {
	case ch <- value:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *nodeRuntime) sendPeerDatagram(payload []byte) error {
	if r.peer == nil {
		return errors.New("peer datagram connection is not ready")
	}
	if err := r.peer.SendDatagram(payload); err != nil {
		_ = r.events.Emit(toposim.NodeEvent{Type: toposim.EventError, Error: err.Error()})
	}
	return nil
}

func (r *nodeRuntime) close() {
	r.cancel()
	if r.peer != nil {
		_ = r.peer.Close()
	}
	if r.manager != nil {
		r.manager.Wait()
	}
	if r.directConn != nil {
		_ = r.directConn.Close()
	}
}

func parseNodeCommand(data []byte) (toposim.NodeCommand, error) {
	var command toposim.NodeCommand
	if err := json.Unmarshal(data, &command); err != nil {
		return toposim.NodeCommand{}, err
	}
	if command.Type == "" {
		return toposim.NodeCommand{}, errors.New("missing command type")
	}
	return command, nil
}

func emitPathUpdates(ctx context.Context, node string, manager *transport.Manager, events *eventWriter) {
	for update := range manager.Updates(ctx) {
		event := toposim.NodeEvent{Type: toposim.EventPath, Node: node, Path: pathName(update.Path)}
		if direct, ok := manager.DirectPath(); ok {
			event.Direct = direct
		}
		_ = events.Emit(event)
	}
}

func emitPeerDatagrams(ctx context.Context, peer transport.PeerDatagramConn, events *eventWriter) {
	for {
		payload, _, err := peer.RecvDatagram(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			_ = events.Emit(toposim.NodeEvent{Type: toposim.EventError, Error: err.Error()})
			return
		}
		_ = events.Emit(toposim.NodeEvent{Type: toposim.EventPeerDatagram, Payload: append([]byte(nil), payload...)})
		peer.ReleaseDatagram(payload)
	}
}

func pathName(path transport.Path) string {
	switch path {
	case transport.PathRelay:
		return toposim.PathRelayName
	case transport.PathDirect:
		return toposim.PathDirectName
	default:
		return "unknown"
	}
}

type eventWriter struct {
	node string
	mu   sync.Mutex
	enc  *json.Encoder
}

func newEventWriter(node string, out io.Writer) *eventWriter {
	return &eventWriter{node: node, enc: json.NewEncoder(out)}
}

func (w *eventWriter) Emit(event toposim.NodeEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if event.Node == "" {
		event.Node = w.node
	}
	return w.enc.Encode(event)
}

type addrSet struct {
	mu    sync.Mutex
	addrs []net.Addr
}

func newAddrSet(values []string) *addrSet {
	return &addrSet{addrs: parseUDPAddrs(values)}
}

func (s *addrSet) Set(values []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrs = parseUDPAddrs(values)
}

func (s *addrSet) Snapshot() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAddrs(s.addrs)
}

type staticPortmap struct {
	mu      sync.Mutex
	addrs   []net.Addr
	changed bool
}

func newStaticPortmap(values []string) *staticPortmap {
	return &staticPortmap{addrs: parseUDPAddrs(values), changed: len(values) > 0}
}

func (p *staticPortmap) Set(values []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addrs = parseUDPAddrs(values)
	p.changed = true
}

func (p *staticPortmap) Refresh(time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	changed := p.changed
	p.changed = false
	return changed
}

func (p *staticPortmap) SnapshotAddrs() []net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneAddrs(p.addrs)
}

func parseUDPAddrs(values []string) []net.Addr {
	out := make([]net.Addr, 0, len(values))
	for _, value := range values {
		addr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(value))
		if err == nil && addr != nil {
			out = append(out, addr)
		}
	}
	return out
}

func cloneAddrs(addrs []net.Addr) []net.Addr {
	out := make([]net.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if udp, ok := addr.(*net.UDPAddr); ok {
			clone := *udp
			if udp.IP != nil {
				clone.IP = append(net.IP(nil), udp.IP...)
			}
			out = append(out, &clone)
			continue
		}
		out = append(out, addr)
	}
	return out
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
