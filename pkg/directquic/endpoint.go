// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package directquic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

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
	BytesSent     int64
	BytesReceived int64
	CloseReason   string
}

type Endpoint struct {
	conn     *quic.Conn
	listener *quic.Listener

	mu     sync.Mutex
	stats  Stats
	closed bool
}

func Listen(ctx context.Context, cfg ListenConfig) (*Endpoint, error) {
	if err := validateCommon(cfg.PacketConn, cfg.PeerPublic); err != nil {
		return nil, err
	}
	listener, err := quic.Listen(cfg.PacketConn, quicpath.ServerTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig())
	if err != nil {
		return nil, err
	}
	conn, err := listener.Accept(ctx)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return &Endpoint{conn: conn, listener: listener}, nil
}

func Dial(ctx context.Context, cfg DialConfig) (*Endpoint, error) {
	if err := validateCommon(cfg.PacketConn, cfg.PeerPublic); err != nil {
		return nil, err
	}
	if cfg.RemoteAddr == nil {
		return nil, errNilRemoteAddr
	}
	conn, err := quic.Dial(ctx, cfg.PacketConn, cfg.RemoteAddr, quicpath.ClientTLSConfig(cfg.Identity, cfg.PeerPublic), endpointQUICConfig())
	if err != nil {
		return nil, err
	}
	return &Endpoint{conn: conn}, nil
}

func (e *Endpoint) OpenSendStream(ctx context.Context) (io.WriteCloser, error) {
	stream, err := e.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return sendStreamStatsWriter{stream: stream, endpoint: e}, nil
}

func (e *Endpoint) AcceptReceiveStream(ctx context.Context) (io.ReadCloser, error) {
	stream, err := e.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return receiveStreamCloser{stream: stream, endpoint: e}, nil
}

func (e *Endpoint) Close() error {
	return e.CloseWithError(0, "")
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
	conn := e.conn
	listener := e.listener
	e.mu.Unlock()

	var err error
	if conn != nil {
		err = conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
	}
	if listener != nil {
		if listenerErr := listener.Close(); err == nil {
			err = listenerErr
		}
	}
	return err
}

func (e *Endpoint) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

func (e *Endpoint) addBytesSent(n int) {
	if e == nil || n <= 0 {
		return
	}
	e.mu.Lock()
	e.stats.BytesSent += int64(n)
	e.mu.Unlock()
}

func (e *Endpoint) addBytesReceived(n int) {
	if e == nil || n <= 0 {
		return
	}
	e.mu.Lock()
	e.stats.BytesReceived += int64(n)
	e.mu.Unlock()
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

func endpointQUICConfig() *quic.Config {
	cfg := quicpath.DefaultQUICConfig()
	cfg.MaxIncomingUniStreams = quicpath.MaxIncomingStreams
	return cfg
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
