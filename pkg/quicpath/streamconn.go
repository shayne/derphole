// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

type StreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func WrapStream(conn *quic.Conn, stream *quic.Stream) net.Conn {
	return &StreamConn{
		stream: stream,
		conn:   conn,
	}
}

func (c *StreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *StreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *StreamConn) Close() error                { return c.stream.Close() }
func (c *StreamConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *StreamConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}
func (c *StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}
func (c *StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
