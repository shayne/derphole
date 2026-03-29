package session

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/token"
)

var (
	relayMu        sync.Mutex
	relayMailboxes = map[string]chan relayMessage{}
)

type relayMessage struct {
	payload []byte
	ack     chan error
}

func issueToken() (string, chan relayMessage, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return "", nil, err
	}

	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		return "", nil, err
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		ExpiresUnix:  time.Now().Add(10 * time.Minute).Unix(),
		BearerSecret: bearerSecret,
		Capabilities: token.CapabilityStdio | token.CapabilityTCP,
	})
	if err != nil {
		return "", nil, err
	}

	mailbox := make(chan relayMessage)
	relayMu.Lock()
	relayMailboxes[tok] = mailbox
	relayMu.Unlock()
	return tok, mailbox, nil
}

func deleteRelayMailbox(tok string, mailbox chan relayMessage) {
	relayMu.Lock()
	defer relayMu.Unlock()
	if relayMailboxes[tok] == mailbox {
		delete(relayMailboxes, tok)
	}
}

func listenOutput(cfg ListenConfig) io.Writer {
	if cfg.Attachment != nil {
		return cfg.Attachment
	}
	if cfg.StdioOut != nil {
		return cfg.StdioOut
	}
	return io.Discard
}

func Listen(ctx context.Context, cfg ListenConfig) (string, error) {
	tok, mailbox, err := issueToken()
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, mailbox)

	emitStatus(cfg.Emitter, StateWaiting)
	if cfg.TokenSink != nil {
		select {
		case cfg.TokenSink <- tok:
		case <-ctx.Done():
			return tok, ctx.Err()
		}
	}

	select {
	case msg := <-mailbox:
		emitStatus(cfg.Emitter, StateRelay)
		_, err := listenOutput(cfg).Write(msg.payload)
		msg.ack <- err
		if err != nil {
			return tok, err
		}
		emitStatus(cfg.Emitter, StateComplete)
		return tok, nil
	case <-ctx.Done():
		return tok, ctx.Err()
	}
}
