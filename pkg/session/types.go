package session

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/transport"
)

type ListenConfig struct {
	Emitter       *telemetry.Emitter
	TokenSink     chan<- string
	StdioOut      io.Writer
	ForceRelay    bool
	UsePublicDERP bool
}

type SendConfig struct {
	Token         string
	Emitter       *telemetry.Emitter
	StdioIn       io.Reader
	ForceRelay    bool
	UsePublicDERP bool
}

type ShareConfig struct {
	Emitter       *telemetry.Emitter
	TokenSink     chan<- string
	TargetAddr    string
	ForceRelay    bool
	UsePublicDERP bool
}

type OpenConfig struct {
	Token         string
	BindAddr      string
	BindAddrSink  chan<- string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
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

type transportPathEmitter struct {
	mu      sync.Mutex
	emitter *telemetry.Emitter
	last    transport.Path
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
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
	e.last = path

	switch path {
	case transport.PathDirect:
		e.emitter.Status(string(StateDirect))
	case transport.PathRelay:
		e.emitter.Status(string(StateRelay))
	}
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
		if e.last == transport.PathRelay {
			return
		}
		e.last = transport.PathRelay
	}
	e.emitter.Status(string(state))
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
		if drops := manager.DroppedPeerDatagrams(); drops > 0 {
			e.emitter.Debug(fmt.Sprintf("transport-dropped-datagrams=%d", drops))
		}
		if rejected := manager.RejectedDirectDatagrams(); rejected > 0 {
			e.emitter.Debug(fmt.Sprintf("transport-rejected-direct-datagrams=%d", rejected))
		}
		if depth := manager.MaxPeerRecvQueueDepth(); depth > 0 {
			e.emitter.Debug(fmt.Sprintf("transport-max-peer-recv-queue-depth=%d", depth))
		}
		if path := manager.PathState(); path == transport.PathDirect && e.last != transport.PathDirect {
			e.last = transport.PathDirect
			e.emitter.Status(string(StateDirect))
		}
	}
	e.closed = true
	e.emitter.Status(string(StateComplete))
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
