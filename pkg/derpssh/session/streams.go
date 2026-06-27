// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/model"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derptun"
)

var ErrReadOnly = errors.New("guest is read-only")

type ChatMessage = model.ChatMessage

type lockedWriter struct {
	conn net.Conn
	mu   *sync.Mutex
}

func (w lockedWriter) write(msg protocol.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return protocol.WriteFrame(w.conn, msg)
}

type acceptedStream struct {
	conn net.Conn
	kind protocol.StreamKind
}

func acceptStream(ctx context.Context, mux *derptun.Mux, kind protocol.StreamKind) (net.Conn, error) {
	stream, err := acceptAnyStream(ctx, mux)
	if err != nil {
		return nil, err
	}
	if stream.kind != kind {
		_ = stream.conn.Close()
		return nil, fmt.Errorf("unexpected %s stream hello: %s", kind, stream.kind)
	}
	return stream.conn, nil
}

func acceptAnyStream(ctx context.Context, mux *derptun.Mux) (acceptedStream, error) {
	conn, err := mux.Accept(ctx)
	if err != nil {
		return acceptedStream{}, err
	}
	msg, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return acceptedStream{}, err
	}
	if msg.Type != protocol.MessageHello || msg.Hello == nil {
		_ = conn.Close()
		return acceptedStream{}, fmt.Errorf("unexpected stream hello: %#v", msg)
	}
	kind := protocol.StreamKind(msg.Hello.DisplayName)
	switch kind {
	case protocol.StreamTerminalIn, protocol.StreamTerminalOut, protocol.StreamChat:
		return acceptedStream{conn: conn, kind: kind}, nil
	default:
		_ = conn.Close()
		return acceptedStream{}, fmt.Errorf("unexpected stream kind: %s", kind)
	}
}

func openStream(ctx context.Context, mux *derptun.Mux, kind protocol.StreamKind, participantID string) (net.Conn, error) {
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(conn, protocol.Message{
		Type: protocol.MessageHello,
		Hello: &protocol.Hello{
			ProtocolVersion: protocol.ProtocolVersion,
			ParticipantID:   participantID,
			DisplayName:     string(kind),
			Role:            protocol.RolePending,
		},
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func waitConn(ctx context.Context, ch <-chan net.Conn) (net.Conn, error) {
	select {
	case conn := <-ch:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func closeReady(ch chan net.Conn) {
	select {
	case ch <- nil:
	default:
	}
}

func roleGranted(role protocol.Role) bool {
	return role == protocol.RoleRead || role == protocol.RoleWrite
}

func guestFromHello(msg protocol.Message) (string, string, error) {
	if msg.Type != protocol.MessageHello || msg.Hello == nil {
		return "", "", errors.New("missing guest hello")
	}
	return msg.Hello.ParticipantID, msg.Hello.DisplayName, nil
}
