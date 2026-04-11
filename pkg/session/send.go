package session

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/shayne/derpcat/pkg/traversal"
)

var ErrUnknownSession = errors.New("unknown session")

func relayMailbox(tok string) (*relaySession, bool) {
	relayMu.Lock()
	defer relayMu.Unlock()
	session, ok := relayMailboxes[tok]
	return session, ok
}

func Send(ctx context.Context, cfg SendConfig) error {
	session, ok := relayMailbox(cfg.Token)
	if !ok {
		if cfg.UsePublicDERP {
			return sendExternal(ctx, cfg)
		}
		return ErrUnknownSession
	}

	emitStatus(cfg.Emitter, StateProbing)

	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	payload, err := io.ReadAll(src)
	if err != nil {
		return err
	}

	path := detectPath(ctx, cfg.ForceRelay, session.probeConn)
	ack := make(chan error, 1)
	select {
	case session.mailbox <- relayMessage{payload: payload, ack: ack, path: path}:
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

	emitStatus(cfg.Emitter, path)
	emitStatus(cfg.Emitter, StateComplete)
	return nil
}

func choosePath(forceRelay bool, probe traversal.Result) State {
	if forceRelay {
		return StateRelay
	}
	if probe.Direct {
		return StateDirect
	}
	return StateRelay
}

func detectPath(ctx context.Context, forceRelay bool, peer net.PacketConn) State {
	if forceRelay || peer == nil {
		return StateRelay
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return StateRelay
	}
	defer conn.Close()

	probe, err := traversal.ProbeDirect(ctx, conn, peer.LocalAddr().String(), peer, conn.LocalAddr().String())
	if err != nil {
		return StateRelay
	}
	return choosePath(forceRelay, probe)
}
