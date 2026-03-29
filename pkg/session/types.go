package session

import (
	"io"

	"github.com/shayne/derpcat/pkg/telemetry"
)

type ListenConfig struct {
	Emitter    *telemetry.Emitter
	TokenSink  chan<- string
	StdioOut   io.Writer
	Attachment io.ReadWriter
	ForceRelay bool
}

type SendConfig struct {
	Token      string
	Emitter    *telemetry.Emitter
	StdioIn    io.Reader
	Attachment io.ReadWriter
	ForceRelay bool
}

type State string

const (
	StateWaiting  State = "waiting-for-claim"
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
