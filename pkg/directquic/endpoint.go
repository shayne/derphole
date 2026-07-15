// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package directquic

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/quicpath"
)

var (
	errNilPacketConn = errors.New("directquic: nil packet conn")
	errNilRemoteAddr = errors.New("directquic: nil remote addr")
	errZeroPeerKey   = errors.New("directquic: zero peer public key")
)

type ListenConfig struct {
	PacketConn net.PacketConn
	Identity   quicpath.SessionIdentity
	PeerPublic [32]byte
}

type DialConfig struct {
	PacketConn net.PacketConn
	RemoteAddr net.Addr
	Identity   quicpath.SessionIdentity
	PeerPublic [32]byte
}

type Stats struct {
	BytesSent            int64
	BytesReceived        int64
	TelemetryPresent     bool
	Connections          uint32
	Streams              uint32
	PacketsSent          uint64
	PacketsReceived      uint64
	PacketsLost          uint64
	WireBytesSent        uint64
	RecoveryWireBytes    uint64
	SmoothedRTT          time.Duration
	HandshakeDuration    time.Duration
	FirstByteDuration    time.Duration
	StreamBytesSent      uint64
	StreamBytesReceived  uint64
	Version              string
	RawSocketBackend     string
	NativeSendBackend    string
	NativeReceiveBackend string
	NativeGSO            string
	NativeReceiveBatch   string
	HandshakeMS          int64
	FirstByteMS          int64
	OpenedAt             time.Time
	HandshakeAt          time.Time
	FirstByteAt          time.Time
	ClosedAt             time.Time
	CloseReason          string
}

type Endpoint struct {
	conns     []*quic.Conn
	listener  *quic.Listener
	transport *quic.Transport
	mechanism *quicpath.MechanismTrace
	backend   endpointBackend

	mu           sync.Mutex
	stats        Stats
	closed       bool
	firstByteSet bool
}

func Listen(ctx context.Context, cfg ListenConfig) (*Endpoint, error) {
	return ListenWithReady(ctx, cfg, nil)
}

func ListenWithReady(ctx context.Context, cfg ListenConfig, ready func() error) (*Endpoint, error) {
	return ListenConnectionsWithReady(ctx, cfg, 1, ready)
}

func ListenConnectionsWithReady(ctx context.Context, cfg ListenConfig, count int, ready func() error) (*Endpoint, error) {
	if err := validateCommon(cfg.PacketConn, cfg.PeerPublic); err != nil {
		return nil, err
	}
	if err := validateConnectionCount(count); err != nil {
		return nil, err
	}
	if count == 1 {
		return listenSingleWithReady(ctx, cfg, ready)
	}
	openedAt := time.Now()
	mechanism := quicpath.NewMechanismTrace()
	transport := &quic.Transport{Conn: cfg.PacketConn}
	listener, err := transport.Listen(quicpath.ServerTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig(mechanism))
	if err != nil {
		return nil, err
	}
	if ready != nil {
		if err := ready(); err != nil {
			_ = listener.Close()
			_ = transport.Close()
			return nil, err
		}
	}
	conns := make([]*quic.Conn, 0, count)
	for len(conns) < count {
		conn, err := listener.Accept(ctx)
		if err != nil {
			closeQUICConns(conns, 1, "accept failed")
			_ = listener.Close()
			_ = transport.Close()
			return nil, err
		}
		conns = append(conns, conn)
	}
	return newEndpoint(conns, listener, transport, openedAt, mechanism, classifyEndpointBackend(cfg.PacketConn)), nil
}

func Dial(ctx context.Context, cfg DialConfig) (*Endpoint, error) {
	return DialConnections(ctx, cfg, 1)
}

func DialConnections(ctx context.Context, cfg DialConfig, count int) (*Endpoint, error) {
	if err := validateCommon(cfg.PacketConn, cfg.PeerPublic); err != nil {
		return nil, err
	}
	if cfg.RemoteAddr == nil {
		return nil, errNilRemoteAddr
	}
	if err := validateConnectionCount(count); err != nil {
		return nil, err
	}
	if count == 1 {
		return dialSingle(ctx, cfg)
	}
	openedAt := time.Now()
	mechanism := quicpath.NewMechanismTrace()
	transport := &quic.Transport{Conn: cfg.PacketConn}
	conns := make([]*quic.Conn, 0, count)
	for len(conns) < count {
		conn, err := transport.Dial(ctx, cfg.RemoteAddr, quicpath.ClientTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig(mechanism))
		if err != nil {
			closeQUICConns(conns, 1, "dial failed")
			_ = transport.Close()
			return nil, err
		}
		conns = append(conns, conn)
	}
	return newEndpoint(conns, nil, transport, openedAt, mechanism, classifyEndpointBackend(cfg.PacketConn)), nil
}

func listenSingleWithReady(ctx context.Context, cfg ListenConfig, ready func() error) (*Endpoint, error) {
	openedAt := time.Now()
	mechanism := quicpath.NewMechanismTrace()
	listener, err := quic.Listen(cfg.PacketConn, quicpath.ServerTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig(mechanism))
	if err != nil {
		return nil, err
	}
	if ready != nil {
		if err := ready(); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return newEndpoint([]*quic.Conn{conn}, listener, nil, openedAt, mechanism, classifyEndpointBackend(cfg.PacketConn)), nil
}

func dialSingle(ctx context.Context, cfg DialConfig) (*Endpoint, error) {
	openedAt := time.Now()
	mechanism := quicpath.NewMechanismTrace()
	conn, err := quic.Dial(ctx, cfg.PacketConn, cfg.RemoteAddr, quicpath.ClientTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig(mechanism))
	if err != nil {
		return nil, err
	}
	return newEndpoint([]*quic.Conn{conn}, nil, nil, openedAt, mechanism, classifyEndpointBackend(cfg.PacketConn)), nil
}

func validateConnectionCount(count int) error {
	if count < 1 {
		return errors.New("directquic: connection count must be positive")
	}
	return nil
}

func newEndpoint(conns []*quic.Conn, listener *quic.Listener, transport *quic.Transport, openedAt time.Time, mechanism *quicpath.MechanismTrace, backend endpointBackend) *Endpoint {
	handshakeAt := time.Now()
	handshakeDuration := handshakeAt.Sub(openedAt)
	return &Endpoint{
		conns:     conns,
		listener:  listener,
		transport: transport,
		mechanism: mechanism,
		backend:   backend,
		stats: Stats{
			OpenedAt:          openedAt,
			HandshakeAt:       handshakeAt,
			HandshakeMS:       handshakeDuration.Milliseconds(),
			HandshakeDuration: handshakeDuration,
		},
	}
}

func (e *Endpoint) OpenSendStream(ctx context.Context) (io.WriteCloser, error) {
	if len(e.conns) == 0 {
		return nil, errors.New("directquic: no open connections")
	}
	return e.openSendStream(ctx, e.conns[0])
}

func (e *Endpoint) openSendStream(ctx context.Context, conn *quic.Conn) (io.WriteCloser, error) {
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	e.addStream()
	return sendStreamStatsWriter{stream: stream, endpoint: e}, nil
}

func (e *Endpoint) OpenSendStreams(ctx context.Context, count int) ([]io.WriteCloser, error) {
	if count < 1 {
		return nil, errors.New("directquic: send stream count must be positive")
	}
	streams := make([]io.WriteCloser, 0, count)
	for len(streams) < count {
		conn, err := e.connForIndex(len(streams))
		if err != nil {
			closeWriteClosers(streams)
			return nil, err
		}
		stream, err := e.openSendStream(ctx, conn)
		if err != nil {
			closeWriteClosers(streams)
			return nil, err
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

func (e *Endpoint) AcceptReceiveStream(ctx context.Context) (io.ReadCloser, error) {
	if len(e.conns) == 0 {
		return nil, errors.New("directquic: no open connections")
	}
	return e.acceptReceiveStream(ctx, e.conns[0])
}

func (e *Endpoint) acceptReceiveStream(ctx context.Context, conn *quic.Conn) (io.ReadCloser, error) {
	stream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	e.addStream()
	return receiveStreamCloser{stream: stream, endpoint: e}, nil
}

func (e *Endpoint) AcceptReceiveStreams(ctx context.Context, count int) ([]io.ReadCloser, error) {
	if count < 1 {
		return nil, errors.New("directquic: receive stream count must be positive")
	}
	streams := make([]io.ReadCloser, 0, count)
	for len(streams) < count {
		conn, err := e.connForIndex(len(streams))
		if err != nil {
			closeReadClosers(streams)
			return nil, err
		}
		stream, err := e.acceptReceiveStream(ctx, conn)
		if err != nil {
			closeReadClosers(streams)
			return nil, err
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

func (e *Endpoint) connForIndex(index int) (*quic.Conn, error) {
	if len(e.conns) == 0 {
		return nil, errors.New("directquic: no open connections")
	}
	return e.conns[index%len(e.conns)], nil
}

func (e *Endpoint) Close() error {
	return e.CloseWithError(0, "")
}

func (e *Endpoint) WaitClosed(ctx context.Context) error {
	if e == nil || len(e.conns) == 0 || e.conns[0] == nil {
		return nil
	}
	select {
	case <-e.conns[0].Context().Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Endpoint) CloseWithError(code uint64, reason string) error {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.stats.CloseReason = reason
	e.stats.ClosedAt = time.Now()
	conns := append([]*quic.Conn(nil), e.conns...)
	listener := e.listener
	transport := e.transport
	e.mu.Unlock()

	var err error
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		if connErr := conn.CloseWithError(quic.ApplicationErrorCode(code), reason); err == nil {
			err = connErr
		}
	}
	if listener != nil {
		if listenerErr := listener.Close(); err == nil {
			err = listenerErr
		}
	}
	if transport != nil {
		if transportErr := transport.Close(); err == nil {
			err = transportErr
		}
	}
	return err
}

func (e *Endpoint) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	stats := e.stats
	conns := append([]*quic.Conn(nil), e.conns...)
	mechanism := e.mechanism
	backend := e.backend
	e.mu.Unlock()

	stats = applyMechanismSnapshot(stats, mechanism.Snapshot())
	stats = applyConnectionSnapshots(stats, conns, backend)
	return stats
}

func applyMechanismSnapshot(stats Stats, snapshot quicpath.MechanismSnapshot) Stats {
	stats.TelemetryPresent = snapshot.TelemetryPresent
	stats.Connections = snapshot.Connections
	stats.Streams = max(stats.Streams, snapshot.Streams)
	stats.PacketsSent = snapshot.PacketsSent
	stats.PacketsReceived = snapshot.PacketsReceived
	stats.PacketsLost = snapshot.PacketsLost
	stats.WireBytesSent = snapshot.WireBytesSent
	stats.RecoveryWireBytes = snapshot.RecoveryWireBytes
	stats.SmoothedRTT = snapshot.SmoothedRTT
	return stats
}

func applyConnectionSnapshots(stats Stats, conns []*quic.Conn, backend endpointBackend) Stats {
	if len(conns) > 0 {
		stats.Connections = uint32(len(conns))
		stats.RawSocketBackend = backend.rawSocket
		stats.NativeSendBackend = backend.send
		stats.NativeReceiveBackend = backend.receive
		stats.NativeReceiveBatch = backend.receiveBatch
	}
	stats.NativeGSO = ""

	var connectionPacketsSent uint64
	var connectionPacketsReceived uint64
	var connectionPacketsLost uint64
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		connectionPacketsSent, connectionPacketsReceived, connectionPacketsLost = mergeConnectionSnapshot(
			&stats, conn, connectionPacketsSent, connectionPacketsReceived, connectionPacketsLost,
		)
	}
	stats.PacketsSent = max(stats.PacketsSent, connectionPacketsSent)
	stats.PacketsReceived = max(stats.PacketsReceived, connectionPacketsReceived)
	stats.PacketsLost = max(stats.PacketsLost, connectionPacketsLost)
	return stats
}

func mergeConnectionSnapshot(stats *Stats, conn *quic.Conn, sent, received, lost uint64) (uint64, uint64, uint64) {
	connectionStats := conn.ConnectionStats()
	sent += connectionStats.PacketsSent
	received += connectionStats.PacketsReceived
	lost += connectionStats.PacketsLost
	stats.SmoothedRTT = max(stats.SmoothedRTT, connectionStats.SmoothedRTT)
	state := conn.ConnectionState()
	if stats.NativeGSO == "" {
		stats.NativeGSO = "false"
	}
	version := state.Version.String()
	if stats.Version == "" {
		stats.Version = version
	} else if version != stats.Version {
		stats.Version = "mixed"
	}
	if state.GSO {
		stats.NativeGSO = "true"
	}
	return sent, received, lost
}

func (e *Endpoint) addStream() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.stats.Streams++
	e.mu.Unlock()
}

func (e *Endpoint) addBytesSent(n int) {
	if e == nil || n <= 0 {
		return
	}
	e.mu.Lock()
	e.stats.BytesSent += int64(n)
	e.stats.StreamBytesSent += uint64(n)
	e.recordFirstByteLocked(time.Now())
	e.mu.Unlock()
}

func closeQUICConns(conns []*quic.Conn, code uint64, reason string) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
		}
	}
}

func (e *Endpoint) addBytesReceived(n int) {
	if e == nil || n <= 0 {
		return
	}
	e.mu.Lock()
	e.stats.BytesReceived += int64(n)
	e.stats.StreamBytesReceived += uint64(n)
	e.recordFirstByteLocked(time.Now())
	e.mu.Unlock()
}

func (e *Endpoint) recordFirstByteLocked(at time.Time) {
	if e.firstByteSet {
		return
	}
	e.firstByteSet = true
	e.stats.FirstByteAt = at
	e.stats.FirstByteDuration = at.Sub(e.stats.OpenedAt)
	e.stats.FirstByteMS = e.stats.FirstByteDuration.Milliseconds()
}

func validateCommon(packetConn net.PacketConn, peerPublic [32]byte) error {
	if packetConn == nil {
		return errNilPacketConn
	}
	if peerPublic == ([32]byte{}) {
		return errZeroPeerKey
	}
	return nil
}

func endpointQUICConfig(mechanism *quicpath.MechanismTrace) *quic.Config {
	cfg := quicpath.DefaultQUICConfig()
	cfg.MaxIncomingUniStreams = quicpath.MaxIncomingStreams
	cfg.Tracer = quicpath.TracerWithMechanism(mechanism)
	return cfg
}

type endpointBackend struct {
	rawSocket    string
	send         string
	receive      string
	receiveBatch string
}

func classifyEndpointBackend(conn net.PacketConn) endpointBackend {
	if _, ok := conn.(quic.OOBCapablePacketConn); !ok {
		return endpointBackend{
			rawSocket:    "packet-conn",
			send:         "packetconn-writeto",
			receive:      "packetconn-readfrom",
			receiveBatch: "false",
		}
	}
	backend := endpointBackend{
		rawSocket: "quic-go-oob",
		send:      "udp-sendmsg",
		receive:   "udp-recvmsg",
	}
	switch runtime.GOOS {
	case "linux":
		backend.send = "udp-gso-or-sendmsg"
		backend.receive = "udp-recvmmsg"
		backend.receiveBatch = "true"
	case "freebsd":
		backend.receive = "udp-recvmmsg"
		backend.receiveBatch = "true"
	case "darwin", "windows":
		backend.receiveBatch = "false"
	default:
		backend.receiveBatch = "unsupported"
	}
	return backend
}

type sendStreamStatsWriter struct {
	stream   *quic.SendStream
	endpoint *Endpoint
}

func (s sendStreamStatsWriter) Write(p []byte) (int, error) {
	n, err := s.stream.Write(p)
	s.endpoint.addBytesSent(n)
	return n, err
}

func (s sendStreamStatsWriter) Close() error {
	return s.stream.Close()
}

type receiveStreamCloser struct {
	stream   *quic.ReceiveStream
	endpoint *Endpoint
}

func (r receiveStreamCloser) Read(p []byte) (int, error) {
	n, err := r.stream.Read(p)
	r.endpoint.addBytesReceived(n)
	return n, err
}

func (r receiveStreamCloser) Close() error {
	r.stream.CancelRead(0)
	return nil
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
