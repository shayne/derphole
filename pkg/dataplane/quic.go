// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dataplane

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

type QUICClient struct {
	manager   *transport.Manager
	identity  quicpath.SessionIdentity
	peer      [32]byte
	endpoint  *directquic.Endpoint
	endpoints []*directquic.Endpoint
	adapter   *quicpath.Adapter
	conn      net.PacketConn
	remote    net.Addr
	conns     []net.PacketConn
	remotes   []net.Addr
}

type QUICServer struct {
	manager   *transport.Manager
	identity  quicpath.SessionIdentity
	peer      [32]byte
	endpoint  *directquic.Endpoint
	endpoints []*directquic.Endpoint
	adapter   *quicpath.Adapter
	conn      net.PacketConn
	remote    net.Addr
	conns     []net.PacketConn
}

type packetPath struct {
	conn    net.PacketConn
	remote  net.Addr
	adapter *quicpath.Adapter
}

func NewQUICClient(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICClient {
	return &QUICClient{manager: manager, identity: identity, peer: peer}
}

func NewQUICClientOnPacketConn(conn net.PacketConn, remote net.Addr, identity quicpath.SessionIdentity, peer [32]byte) *QUICClient {
	return &QUICClient{conn: conn, remote: remote, identity: identity, peer: peer}
}

func NewQUICClientOnPacketConns(conns []net.PacketConn, remotes []net.Addr, identity quicpath.SessionIdentity, peer [32]byte) *QUICClient {
	return &QUICClient{
		conns:    append([]net.PacketConn(nil), conns...),
		remotes:  append([]net.Addr(nil), remotes...),
		identity: identity,
		peer:     peer,
	}
}

func NewQUICServer(manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) *QUICServer {
	return &QUICServer{manager: manager, identity: identity, peer: peer}
}

func NewQUICServerOnPacketConn(conn net.PacketConn, identity quicpath.SessionIdentity, peer [32]byte) *QUICServer {
	return &QUICServer{conn: conn, identity: identity, peer: peer}
}

func NewQUICServerOnPacketConns(conns []net.PacketConn, identity quicpath.SessionIdentity, peer [32]byte) *QUICServer {
	return &QUICServer{
		conns:    append([]net.PacketConn(nil), conns...),
		identity: identity,
		peer:     peer,
	}
}

func (q *QUICClient) Open(ctx context.Context) (Stream, error) {
	streams, err := q.OpenStreams(ctx, 1)
	if err != nil {
		return nil, err
	}
	return writeOnlyStream{WriteCloser: streams[0]}, nil
}

func (q *QUICClient) OpenStreams(ctx context.Context, count int) ([]io.WriteCloser, error) {
	paths := q.packetPaths(ctx)
	if len(paths) > 1 {
		endpoints, streams, err := dialSendStreams(ctx, paths, count, q.identity, q.peer)
		if err != nil {
			closePacketPaths(paths)
			return nil, err
		}
		q.endpoints = endpoints
		q.endpoint = firstEndpoint(endpoints)
		return streams, nil
	}
	path := paths[0]
	endpointCount := endpointConnectionCount(path, count)
	endpoint, err := directquic.DialConnections(ctx, directquic.DialConfig{
		PacketConn: path.conn,
		RemoteAddr: path.remote,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, endpointCount)
	if err != nil {
		closePacketPath(path)
		return nil, err
	}
	streams, err := endpoint.OpenSendStreams(ctx, count)
	if err != nil {
		_ = endpoint.Close()
		closePacketPath(path)
		return nil, err
	}
	q.endpoint = endpoint
	q.endpoints = []*directquic.Endpoint{endpoint}
	q.adapter = path.adapter
	return streams, nil
}

func (q *QUICClient) Accept(ctx context.Context) (Stream, error) {
	streams, err := q.AcceptStreams(ctx, 1)
	if err != nil {
		return nil, err
	}
	return readOnlyStream{ReadCloser: streams[0]}, nil
}

func (q *QUICClient) AcceptStreams(ctx context.Context, count int) ([]io.ReadCloser, error) {
	paths := q.packetPaths(ctx)
	if len(paths) > 1 {
		endpoints, streams, err := dialReceiveStreams(ctx, paths, count, q.identity, q.peer)
		if err != nil {
			closePacketPaths(paths)
			return nil, err
		}
		q.endpoints = endpoints
		q.endpoint = firstEndpoint(endpoints)
		return streams, nil
	}
	path := paths[0]
	endpointCount := endpointConnectionCount(path, count)
	endpoint, err := directquic.DialConnections(ctx, directquic.DialConfig{
		PacketConn: path.conn,
		RemoteAddr: path.remote,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, endpointCount)
	if err != nil {
		closePacketPath(path)
		return nil, err
	}
	streams, err := endpoint.AcceptReceiveStreams(ctx, count)
	if err != nil {
		_ = endpoint.Close()
		closePacketPath(path)
		return nil, err
	}
	q.endpoint = endpoint
	q.endpoints = []*directquic.Endpoint{endpoint}
	q.adapter = path.adapter
	return streams, nil
}

func (q *QUICServer) Accept(ctx context.Context) (Stream, error) {
	return q.AcceptWithReady(ctx, nil)
}

func (q *QUICServer) AcceptWithReady(ctx context.Context, ready func() error) (Stream, error) {
	streams, err := q.AcceptStreamsWithReady(ctx, 1, ready)
	if err != nil {
		return nil, err
	}
	return readOnlyStream{ReadCloser: streams[0]}, nil
}

func (q *QUICServer) AcceptStreamsWithReady(ctx context.Context, count int, ready func() error) ([]io.ReadCloser, error) {
	paths := q.packetPaths(ctx)
	if len(paths) > 1 {
		endpoints, streams, err := listenReceiveStreams(ctx, paths, count, q.identity, q.peer, ready)
		if err != nil {
			closePacketPaths(paths)
			return nil, err
		}
		q.endpoints = endpoints
		q.endpoint = firstEndpoint(endpoints)
		return streams, nil
	}
	path := paths[0]
	endpointCount := endpointConnectionCount(path, count)
	endpoint, err := directquic.ListenConnectionsWithReady(ctx, directquic.ListenConfig{
		PacketConn: path.conn,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, endpointCount, ready)
	if err != nil {
		closePacketPath(path)
		return nil, err
	}
	streams, err := endpoint.AcceptReceiveStreams(ctx, count)
	if err != nil {
		_ = endpoint.Close()
		closePacketPath(path)
		return nil, err
	}
	q.endpoint = endpoint
	q.endpoints = []*directquic.Endpoint{endpoint}
	q.adapter = path.adapter
	return streams, nil
}

func (q *QUICServer) OpenWithReady(ctx context.Context, ready func() error) (Stream, error) {
	streams, err := q.OpenStreamsWithReady(ctx, 1, ready)
	if err != nil {
		return nil, err
	}
	return writeOnlyStream{WriteCloser: streams[0]}, nil
}

func (q *QUICServer) OpenStreamsWithReady(ctx context.Context, count int, ready func() error) ([]io.WriteCloser, error) {
	paths := q.packetPaths(ctx)
	if len(paths) > 1 {
		endpoints, streams, err := listenSendStreams(ctx, paths, count, q.identity, q.peer, ready)
		if err != nil {
			closePacketPaths(paths)
			return nil, err
		}
		q.endpoints = endpoints
		q.endpoint = firstEndpoint(endpoints)
		return streams, nil
	}
	path := paths[0]
	endpointCount := endpointConnectionCount(path, count)
	endpoint, err := directquic.ListenConnectionsWithReady(ctx, directquic.ListenConfig{
		PacketConn: path.conn,
		Identity:   q.identity,
		PeerPublic: q.peer,
	}, endpointCount, ready)
	if err != nil {
		closePacketPath(path)
		return nil, err
	}
	streams, err := endpoint.OpenSendStreams(ctx, count)
	if err != nil {
		_ = endpoint.Close()
		closePacketPath(path)
		return nil, err
	}
	q.endpoint = endpoint
	q.endpoints = []*directquic.Endpoint{endpoint}
	q.adapter = path.adapter
	return streams, nil
}

func (q *QUICClient) packetPaths(ctx context.Context) []packetPath {
	if len(q.conns) > 0 {
		paths := make([]packetPath, 0, min(len(q.conns), len(q.remotes)))
		for i := 0; i < len(q.conns) && i < len(q.remotes); i++ {
			paths = append(paths, packetPath{conn: q.conns[i], remote: q.remotes[i]})
		}
		return paths
	}
	if q.conn != nil {
		return []packetPath{{conn: q.conn, remote: q.remote}}
	}
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	return []packetPath{{conn: adapter, remote: peerConn.RemoteAddr(), adapter: adapter}}
}

func (q *QUICServer) packetPaths(ctx context.Context) []packetPath {
	if len(q.conns) > 0 {
		paths := make([]packetPath, 0, len(q.conns))
		for _, conn := range q.conns {
			paths = append(paths, packetPath{conn: conn})
		}
		return paths
	}
	if q.conn != nil {
		return []packetPath{{conn: q.conn, remote: q.remote}}
	}
	peerConn := q.manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	return []packetPath{{conn: adapter, remote: peerConn.RemoteAddr(), adapter: adapter}}
}

func closePacketPath(path packetPath) {
	if path.adapter != nil {
		_ = path.adapter.Close()
	}
}

func closePacketPaths(paths []packetPath) {
	for _, path := range paths {
		closePacketPath(path)
	}
}

func endpointConnectionCount(path packetPath, streams int) int {
	if path.adapter != nil {
		return 1
	}
	return streams
}

func (q *QUICClient) Stats() Stats {
	return convertStats(q.endpoints)
}

func (q *QUICServer) Stats() Stats {
	return convertStats(q.endpoints)
}

func (q *QUICClient) CloseWithError(code uint64, reason string) error {
	return closeEndpointsAndAdapter(q.endpoints, q.adapter, code, reason)
}

func (q *QUICServer) CloseWithError(code uint64, reason string) error {
	return closeEndpointsAndAdapter(q.endpoints, q.adapter, code, reason)
}

type writeOnlyStream struct{ io.WriteCloser }

func (s writeOnlyStream) Read([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type readOnlyStream struct{ io.ReadCloser }

func (s readOnlyStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func closeEndpointsAndAdapter(endpoints []*directquic.Endpoint, adapter *quicpath.Adapter, code uint64, reason string) error {
	var err error
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		if endpointErr := endpoint.CloseWithError(code, reason); err == nil {
			err = endpointErr
		}
	}
	if adapter != nil {
		if adapterErr := adapter.Close(); err == nil {
			err = adapterErr
		}
	}
	return err
}

func convertStats(endpoints []*directquic.Endpoint) Stats {
	if len(endpoints) == 0 || endpoints[0] == nil {
		return Stats{}
	}
	stats := endpoints[0].Stats()
	for _, endpoint := range endpoints[1:] {
		next := endpoint.Stats()
		stats.BytesSent += next.BytesSent
		stats.BytesReceived += next.BytesReceived
		if stats.OpenedAt.IsZero() || (!next.OpenedAt.IsZero() && next.OpenedAt.Before(stats.OpenedAt)) {
			stats.OpenedAt = next.OpenedAt
		}
		if next.ClosedAt.After(stats.ClosedAt) {
			stats.ClosedAt = next.ClosedAt
		}
	}
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

func dialSendStreams(ctx context.Context, paths []packetPath, count int, identity quicpath.SessionIdentity, peer [32]byte) ([]*directquic.Endpoint, []io.WriteCloser, error) {
	paths = trimPacketPaths(paths, count)
	endpoints := make([]*directquic.Endpoint, 0, len(paths))
	for _, path := range paths {
		endpoint, err := dialPacketPath(ctx, path, identity, peer)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			return nil, nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	streams := make([]io.WriteCloser, 0, len(endpoints))
	for _, endpoint := range endpoints {
		stream, err := endpoint.OpenSendStream(ctx)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			closeWriteClosers(streams)
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return endpoints, streams, nil
}

func dialReceiveStreams(ctx context.Context, paths []packetPath, count int, identity quicpath.SessionIdentity, peer [32]byte) ([]*directquic.Endpoint, []io.ReadCloser, error) {
	paths = trimPacketPaths(paths, count)
	endpoints := make([]*directquic.Endpoint, 0, len(paths))
	for _, path := range paths {
		endpoint, err := dialPacketPath(ctx, path, identity, peer)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			return nil, nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	streams := make([]io.ReadCloser, 0, len(endpoints))
	for _, endpoint := range endpoints {
		stream, err := endpoint.AcceptReceiveStream(ctx)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			closeReadClosers(streams)
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return endpoints, streams, nil
}

func listenReceiveStreams(ctx context.Context, paths []packetPath, count int, identity quicpath.SessionIdentity, peer [32]byte, ready func() error) ([]*directquic.Endpoint, []io.ReadCloser, error) {
	endpoints, err := listenPacketPaths(ctx, paths, count, identity, peer, ready)
	if err != nil {
		return nil, nil, err
	}
	streams := make([]io.ReadCloser, 0, len(endpoints))
	for _, endpoint := range endpoints {
		stream, err := endpoint.AcceptReceiveStream(ctx)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			closeReadClosers(streams)
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return endpoints, streams, nil
}

func listenSendStreams(ctx context.Context, paths []packetPath, count int, identity quicpath.SessionIdentity, peer [32]byte, ready func() error) ([]*directquic.Endpoint, []io.WriteCloser, error) {
	endpoints, err := listenPacketPaths(ctx, paths, count, identity, peer, ready)
	if err != nil {
		return nil, nil, err
	}
	streams := make([]io.WriteCloser, 0, len(endpoints))
	for _, endpoint := range endpoints {
		stream, err := endpoint.OpenSendStream(ctx)
		if err != nil {
			closeDirectQUICEndpoints(endpoints)
			closeWriteClosers(streams)
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return endpoints, streams, nil
}

func dialPacketPath(ctx context.Context, path packetPath, identity quicpath.SessionIdentity, peer [32]byte) (*directquic.Endpoint, error) {
	return directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: path.conn,
		RemoteAddr: path.remote,
		Identity:   identity,
		PeerPublic: peer,
	})
}

func listenPacketPaths(ctx context.Context, paths []packetPath, count int, identity quicpath.SessionIdentity, peer [32]byte, ready func() error) ([]*directquic.Endpoint, error) {
	paths = trimPacketPaths(paths, count)
	state := newListenPacketPathState(ctx, len(paths))
	defer state.release()
	for i, path := range paths {
		go listenPacketPath(ctx, path, i, identity, peer, state)
	}
	if err := state.waitReady(len(paths)); err != nil {
		return nil, err
	}
	if err := state.notifyReady(ready); err != nil {
		return nil, err
	}
	return state.collect(len(paths))
}

type listenPacketPathResult struct {
	index    int
	endpoint *directquic.Endpoint
	err      error
}

type listenPacketPathState struct {
	ctx              context.Context
	results          chan listenPacketPathResult
	listenersReady   chan struct{}
	releaseListeners chan struct{}
	releaseOnce      sync.Once
	readyErr         error
}

func newListenPacketPathState(ctx context.Context, count int) *listenPacketPathState {
	return &listenPacketPathState{
		ctx:              ctx,
		results:          make(chan listenPacketPathResult, count),
		listenersReady:   make(chan struct{}, count),
		releaseListeners: make(chan struct{}),
	}
}

func listenPacketPath(ctx context.Context, path packetPath, index int, identity quicpath.SessionIdentity, peer [32]byte, state *listenPacketPathState) {
	endpoint, err := directquic.ListenWithReady(ctx, directquic.ListenConfig{
		PacketConn: path.conn,
		Identity:   identity,
		PeerPublic: peer,
	}, state.pathReady)
	state.results <- listenPacketPathResult{index: index, endpoint: endpoint, err: err}
}

func (s *listenPacketPathState) pathReady() error {
	s.listenersReady <- struct{}{}
	select {
	case <-s.releaseListeners:
		return s.readyErr
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *listenPacketPathState) waitReady(count int) error {
	for range count {
		if err := s.waitOneReady(); err != nil {
			s.release()
			return err
		}
	}
	return nil
}

func (s *listenPacketPathState) waitOneReady() error {
	select {
	case <-s.listenersReady:
		return nil
	case result := <-s.results:
		return result.err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *listenPacketPathState) notifyReady(ready func() error) error {
	if ready != nil {
		s.readyErr = ready()
	}
	s.release()
	return s.readyErr
}

func (s *listenPacketPathState) release() {
	s.releaseOnce.Do(func() {
		close(s.releaseListeners)
	})
}

func (s *listenPacketPathState) collect(count int) ([]*directquic.Endpoint, error) {
	endpoints := make([]*directquic.Endpoint, count)
	for range count {
		result := <-s.results
		if result.err != nil {
			closeDirectQUICEndpoints(endpoints)
			return nil, result.err
		}
		endpoints[result.index] = result.endpoint
	}
	return endpoints, nil
}

func trimPacketPaths(paths []packetPath, count int) []packetPath {
	if count < len(paths) {
		return paths[:count]
	}
	return paths
}

func firstEndpoint(endpoints []*directquic.Endpoint) *directquic.Endpoint {
	if len(endpoints) == 0 {
		return nil
	}
	return endpoints[0]
}

func closeDirectQUICEndpoints(endpoints []*directquic.Endpoint) {
	for _, endpoint := range endpoints {
		if endpoint != nil {
			_ = endpoint.Close()
		}
	}
}

func closeWriteClosers(closers []io.WriteCloser) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}

func closeReadClosers(closers []io.ReadCloser) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}
