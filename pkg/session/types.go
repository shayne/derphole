// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
)

type ListenConfig struct {
	Emitter       *telemetry.Emitter
	TokenSink     chan<- string
	StdioOut      io.Writer
	ForceRelay    bool
	UsePublicDERP bool
	Trace         *transfertrace.Recorder
}

type AttachListenConfig struct {
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type SendConfig struct {
	Token              string
	Emitter            *telemetry.Emitter
	StdioIn            io.Reader
	StdioExpectedBytes int64
	ForceRelay         bool
	UsePublicDERP      bool
	ParallelPolicy     ParallelPolicy
	Trace              *transfertrace.Recorder
	Progress           func(bytesReceived int64, transferElapsedMS int64)

	// Relay-prefix upgrades already have a live payload path. Blocking pre-data
	// UDP probes would create an app-visible stall, so the data path ramps using
	// real transfer feedback instead.
	skipDirectUDPRateProbes bool
}

type OfferConfig struct {
	Emitter            *telemetry.Emitter
	TokenSink          chan<- string
	StdioIn            io.Reader
	StdioExpectedBytes int64
	ForceRelay         bool
	UsePublicDERP      bool
	ParallelPolicy     ParallelPolicy
	Trace              *transfertrace.Recorder
	Progress           func(bytesReceived int64, transferElapsedMS int64)
}

type ReceiveConfig struct {
	Token         string
	Emitter       *telemetry.Emitter
	StdioOut      io.Writer
	ForceRelay    bool
	UsePublicDERP bool
	Trace         *transfertrace.Recorder
}

type AttachDialConfig struct {
	Token          string
	Emitter        *telemetry.Emitter
	ForceRelay     bool
	UsePublicDERP  bool
	ParallelPolicy ParallelPolicy
}

type ShareConfig struct {
	Emitter       *telemetry.Emitter
	TokenSink     chan<- string
	TargetAddr    string
	ForceRelay    bool
	UsePublicDERP bool
}

type OpenConfig struct {
	Token          string
	BindAddr       string
	BindAddrSink   chan<- string
	Emitter        *telemetry.Emitter
	ForceRelay     bool
	UsePublicDERP  bool
	ParallelPolicy ParallelPolicy
}

type AttachListener struct {
	Token  string
	accept func(context.Context) (net.Conn, error)
	close  func() error
}

type State string

const (
	StateWaiting  State = "waiting-for-claim"
	StateClaimed  State = "claimed"
	StateProbing  State = "probing-direct"
	StateDirect   State = "connected-direct"
	StateRelay    State = "connected-relay"
	StateComplete State = "stream-complete"
)

func emitStatus(emitter *telemetry.Emitter, state State) {
	if emitter != nil {
		emitter.Status(string(state))
	}
}

func (l *AttachListener) Accept(ctx context.Context) (net.Conn, error) {
	if l == nil || l.accept == nil {
		return nil, net.ErrClosed
	}
	return l.accept(ctx)
}

func (l *AttachListener) Close() error {
	if l == nil || l.close == nil {
		return net.ErrClosed
	}
	return l.close()
}

type transportPathEmitter struct {
	mu                      sync.Mutex
	emitter                 *telemetry.Emitter
	last                    transport.Path
	closed                  bool
	suppressRelayRegression bool
	suppressWatcherDirect   bool
	cancel                  context.CancelFunc
	done                    chan struct{}
}

func newTransportPathEmitter(emitter *telemetry.Emitter) *transportPathEmitter {
	return &transportPathEmitter{
		emitter: emitter,
		last:    transport.PathUnknown,
	}
}

func (e *transportPathEmitter) Handle(path transport.Path) {
	if e == nil || e.emitter == nil || path == transport.PathUnknown {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || path == e.last {
		return
	}
	if e.suppressesPathLocked(path) {
		return
	}
	e.last = path

	switch path {
	case transport.PathDirect:
		e.emitter.Status(string(StateDirect))
	case transport.PathRelay:
		e.emitter.Status(string(StateRelay))
	}
}

func (e *transportPathEmitter) suppressesPathLocked(path transport.Path) bool {
	if path == transport.PathDirect && e.suppressWatcherDirect {
		return true
	}
	return path == transport.PathRelay && e.suppressRelayRegression && e.last == transport.PathDirect
}

func (e *transportPathEmitter) Watch(ctx context.Context, manager *transport.Manager) {
	if e == nil || manager == nil {
		return
	}

	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	e.mu.Lock()
	e.cancel = cancel
	e.done = done
	e.mu.Unlock()

	go func() {
		defer close(done)
		for update := range manager.Updates(watchCtx) {
			e.Handle(update.Path)
		}
	}()
}

func (e *transportPathEmitter) Flush(manager *transport.Manager) {
	if e == nil || manager == nil {
		return
	}
	e.Handle(manager.PathState())
}

func (e *transportPathEmitter) Emit(state State) {
	if e == nil || e.emitter == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	switch state {
	case StateDirect:
		if e.last == transport.PathDirect {
			return
		}
		e.last = transport.PathDirect
	case StateRelay:
		if e.suppressRelayRegression && e.last == transport.PathDirect {
			return
		}
		if e.last == transport.PathRelay {
			return
		}
		e.last = transport.PathRelay
	}
	e.emitter.Status(string(state))
}

func (e *transportPathEmitter) SuppressRelayRegression() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressRelayRegression = true
}

func (e *transportPathEmitter) SuppressWatcherDirect() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressWatcherDirect = true
}

func (e *transportPathEmitter) ResumeWatcherDirect() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressWatcherDirect = false
}

func (e *transportPathEmitter) ResumeRelayRegression() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressRelayRegression = false
}

func (e *transportPathEmitter) Complete(manager *transport.Manager) {
	if e == nil {
		return
	}
	e.stopWatching()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.emitter == nil || e.closed {
		return
	}
	if manager != nil {
		e.emitTransportManagerSummaryLocked(manager)
	}
	e.closed = true
	e.emitter.Status(string(StateComplete))
}

func (e *transportPathEmitter) emitTransportManagerSummaryLocked(manager *transport.Manager) {
	emitPositiveUintDebug(e.emitter, "transport-dropped-datagrams", manager.DroppedPeerDatagrams())
	emitPositiveUintDebug(e.emitter, "transport-rejected-direct-datagrams", manager.RejectedDirectDatagrams())
	emitPositiveIntDebug(e.emitter, "transport-max-peer-recv-queue-depth", manager.MaxPeerRecvQueueDepth())
	if path := manager.PathState(); path == transport.PathDirect && e.last != transport.PathDirect && !e.suppressWatcherDirect {
		e.last = transport.PathDirect
		e.emitter.Status(string(StateDirect))
	}
}

func emitPositiveUintDebug(emitter *telemetry.Emitter, key string, value uint64) {
	if value > 0 {
		emitter.Debug(fmt.Sprintf("%s=%d", key, value))
	}
}

func emitPositiveIntDebug(emitter *telemetry.Emitter, key string, value int) {
	if value > 0 {
		emitter.Debug(fmt.Sprintf("%s=%d", key, value))
	}
}

func (e *transportPathEmitter) stopWatching() {
	if e == nil {
		return
	}

	e.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.cancel = nil
	e.done = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
