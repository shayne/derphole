package session

import (
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
	if path == e.last {
		e.mu.Unlock()
		return
	}
	e.last = path
	e.mu.Unlock()

	switch path {
	case transport.PathDirect:
		emitStatus(e.emitter, StateDirect)
	case transport.PathRelay:
		emitStatus(e.emitter, StateRelay)
	}
}

func (e *transportPathEmitter) Flush(manager *transport.Manager) {
	if e == nil || manager == nil {
		return
	}
	e.Handle(manager.PathState())
}
