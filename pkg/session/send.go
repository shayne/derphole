package session

import (
	"bytes"
	"context"
	"errors"
	"io"
)

var ErrUnknownSession = errors.New("unknown session")

func relayMailbox(tok string) (chan relayMessage, bool) {
	relayMu.Lock()
	defer relayMu.Unlock()
	mailbox, ok := relayMailboxes[tok]
	return mailbox, ok
}

func sendInput(cfg SendConfig) io.Reader {
	if cfg.Attachment != nil {
		return cfg.Attachment
	}
	if cfg.StdioIn != nil {
		return cfg.StdioIn
	}
	return bytes.NewReader(nil)
}

func Send(ctx context.Context, cfg SendConfig) error {
	emitStatus(cfg.Emitter, StateProbing)

	payload, err := io.ReadAll(sendInput(cfg))
	if err != nil {
		return err
	}

	mailbox, ok := relayMailbox(cfg.Token)
	if !ok {
		return ErrUnknownSession
	}

	ack := make(chan error, 1)
	select {
	case mailbox <- relayMessage{payload: payload, ack: ack}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-ack:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	emitStatus(cfg.Emitter, StateRelay)
	emitStatus(cfg.Emitter, StateComplete)
	return nil
}
