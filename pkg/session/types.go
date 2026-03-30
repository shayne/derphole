package session

import (
	"context"
	"io"
	"time"

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

func emitTransportPathTransitions(ctx context.Context, emitter *telemetry.Emitter, manager *transport.Manager) {
	if emitter == nil || manager == nil {
		return
	}

	last := manager.PathState()
	switch last {
	case transport.PathDirect:
		emitStatus(emitter, StateDirect)
	case transport.PathRelay:
		emitStatus(emitter, StateRelay)
	}

	go func(last transport.Path) {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			path := manager.PathState()
			if path == last {
				continue
			}
			switch path {
			case transport.PathDirect:
				emitStatus(emitter, StateDirect)
			case transport.PathRelay:
				emitStatus(emitter, StateRelay)
			}
			last = path
		}
	}(last)
}
