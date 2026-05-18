// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package directquic

import (
	"context"
	"errors"
	"io"
	"net"

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

type Endpoint struct {
	conn     *quic.Conn
	listener *quic.Listener
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
	return e.conn.OpenUniStreamSync(ctx)
}

func (e *Endpoint) AcceptReceiveStream(ctx context.Context) (io.ReadCloser, error) {
	stream, err := e.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return receiveStreamCloser{stream: stream}, nil
}

func (e *Endpoint) Close() error {
	if e == nil {
		return nil
	}
	var err error
	if e.conn != nil {
		err = e.conn.CloseWithError(0, "")
	}
	if e.listener != nil {
		if listenerErr := e.listener.Close(); err == nil {
			err = listenerErr
		}
	}
	return err
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

type receiveStreamCloser struct {
	stream *quic.ReceiveStream
}

func (r receiveStreamCloser) Read(p []byte) (int, error) {
	return r.stream.Read(p)
}

func (r receiveStreamCloser) Close() error {
	r.stream.CancelRead(0)
	return nil
}
