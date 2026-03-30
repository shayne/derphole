package session

import (
	"context"
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

func emitTransportPathTransitions(ctx context.Context, emitter *telemetry.Emitter, manager *transport.Manager) func() {
	if emitter == nil || manager == nil {
		return func() {}
	}

	var mu sync.Mutex
	last := transport.PathUnknown
	emitPath := func(path transport.Path) {
		if path == transport.PathUnknown {
			return
		}

		mu.Lock()
		if path == last {
			mu.Unlock()
			return
		}
		last = path
		mu.Unlock()

		switch path {
		case transport.PathDirect:
			emitStatus(emitter, StateDirect)
		case transport.PathRelay:
			emitStatus(emitter, StateRelay)
		}
	}

	go func() {
		for update := range manager.Updates(ctx) {
			emitPath(update.Path)
		}
	}()

	return func() {
		emitPath(manager.PathState())
	}
}
