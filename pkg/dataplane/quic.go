// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dataplane

import (
	"context"
	"io"

	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

type QUICClient struct {
	manager  *transport.Manager
	identity quicpath.SessionIdentity
	peer     [32]byte
	endpoint *directquic.Endpoint
	adapter  *quicpath.Adapter
}

type QUICServer struct {
	manager  *transport.Manager
	identity quicpath.SessionIdentity
	peer     [32]byte
	endpoint *directquic.Endpoint
	adapter  *quicpath.Adapter
}

func NewQUICClient(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICClient {
	return &QUICClient{manager: manager, identity: identity, peer: peer}
}

func NewQUICServer(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICServer {
	return &QUICServer{manager: manager, identity: identity, peer: peer}
}

func (q *QUICClient) Open(ctx context.Context) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   q.identity,
		PeerPublic: q.peer,
	})
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		_ = endpoint.Close()
		_ = adapter.Close()
		return nil, err
	}
	q.endpoint = endpoint
	q.adapter = adapter
	return writeOnlyStream{WriteCloser: stream}, nil
}

func (q *QUICClient) Accept(ctx context.Context) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   q.identity,
		PeerPublic: q.peer,
	})
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}
	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		_ = endpoint.Close()
		_ = adapter.Close()
		return nil, err
	}
	q.endpoint = endpoint
	q.adapter = adapter
	return readOnlyStream{ReadCloser: stream}, nil
}

func (q *QUICServer) Accept(ctx context.Context) (Stream, error) {
	return q.AcceptWithReady(ctx, nil)
}

func (q *QUICServer) AcceptWithReady(ctx context.Context, ready func() error) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	endpoint, err := directquic.ListenWithReady(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, ready)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}
	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		_ = endpoint.Close()
		_ = adapter.Close()
		return nil, err
	}
	q.endpoint = endpoint
	q.adapter = adapter
	return readOnlyStream{ReadCloser: stream}, nil
}

func (q *QUICServer) OpenWithReady(ctx context.Context, ready func() error) (Stream, error) {
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	endpoint, err := directquic.ListenWithReady(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, ready)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		_ = endpoint.Close()
		_ = adapter.Close()
		return nil, err
	}
	q.endpoint = endpoint
	q.adapter = adapter
	return writeOnlyStream{WriteCloser: stream}, nil
}

func (q *QUICClient) Stats() Stats {
	return convertStats(q.endpoint)
}

func (q *QUICServer) Stats() Stats {
	return convertStats(q.endpoint)
}

func (q *QUICClient) CloseWithError(code uint64, reason string) error {
	return closeEndpointAndAdapter(q.endpoint, q.adapter, code, reason)
}

func (q *QUICServer) CloseWithError(code uint64, reason string) error {
	return closeEndpointAndAdapter(q.endpoint, q.adapter, code, reason)
}

type writeOnlyStream struct{ io.WriteCloser }

func (s writeOnlyStream) Read([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type readOnlyStream struct{ io.ReadCloser }

func (s readOnlyStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func closeEndpointAndAdapter(endpoint *directquic.Endpoint, adapter *quicpath.Adapter, code uint64, reason string) error {
	var err error
	if endpoint != nil {
		err = endpoint.CloseWithError(code, reason)
	}
	if adapter != nil {
		if adapterErr := adapter.Close(); err == nil {
			err = adapterErr
		}
	}
	return err
}

func convertStats(endpoint *directquic.Endpoint) Stats {
	if endpoint == nil {
		return Stats{}
	}
	stats := endpoint.Stats()
	return Stats{
		BytesSent:     stats.BytesSent,
		BytesReceived: stats.BytesReceived,
		HandshakeMS:   stats.HandshakeMS,
		FirstByteMS:   stats.FirstByteMS,
		OpenedAt:      stats.OpenedAt,
		HandshakeAt:   stats.HandshakeAt,
		FirstByteAt:   stats.FirstByteAt,
		ClosedAt:      stats.ClosedAt,
		CloseReason:   stats.CloseReason,
	}
}
