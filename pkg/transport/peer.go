// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
)

const peerDatagramPayloadPoolSize = 2048

var peerDatagramPayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, peerDatagramPayloadPoolSize)
		return &buf
	},
}

type PeerDatagramConn interface {
	SendDatagram([]byte) error
	RecvDatagram(context.Context) ([]byte, net.Addr, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ReleaseDatagram([]byte)
	Close() error
}

type peerDatagramConn struct {
	manager *Manager
	ctx     context.Context
	cancel  context.CancelFunc
}

type peerPacket struct {
	payload []byte
	addr    net.Addr
}

func (m *Manager) PeerDatagramConn(ctx context.Context) PeerDatagramConn {
	connCtx, cancel := context.WithCancel(ctx)
	return &peerDatagramConn{
		manager: m,
		ctx:     connCtx,
		cancel:  cancel,
	}
}

func (c *peerDatagramConn) SendDatagram(payload []byte) error {
	return c.manager.sendPeerDatagram(c.ctx, payload)
}

func (c *peerDatagramConn) RecvDatagram(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case pkt := <-c.manager.peerRecvCh:
		return pkt.payload, pkt.addr, nil
	case err := <-c.manager.peerRecvErrCh:
		return nil, nil, err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, nil, c.ctx.Err()
	}
}

func (c *peerDatagramConn) LocalAddr() net.Addr {
	return c.manager.localPeerAddr()
}

func (c *peerDatagramConn) RemoteAddr() net.Addr {
	return c.manager.remotePeerAddr()
}

func (c *peerDatagramConn) ReleaseDatagram(payload []byte) {
	releasePeerDatagramPayload(payload)
}

func (c *peerDatagramConn) Close() error {
	c.cancel()
	return nil
}

func (c *peerDatagramConn) SetReadBuffer(bytes int) error {
	type readBufferConn interface {
		SetReadBuffer(int) error
	}
	if conn, ok := c.manager.cfg.DirectConn.(readBufferConn); ok {
		return conn.SetReadBuffer(bytes)
	}
	return nil
}

func (c *peerDatagramConn) SetWriteBuffer(bytes int) error {
	type writeBufferConn interface {
		SetWriteBuffer(int) error
	}
	if conn, ok := c.manager.cfg.DirectConn.(writeBufferConn); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return nil
}

func (m *Manager) sendPeerDatagram(ctx context.Context, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	if addr, active := m.DirectAddr(); active && m.cfg.DirectConn != nil {
		if _, writeErr := m.cfg.DirectConn.WriteTo(payload, addr); writeErr == nil {
			m.NoteDirectActivity(addr)
			return nil
		} else if errors.Is(writeErr, syscall.EMSGSIZE) {
			return writeErr
		} else if m.cfg.RelaySend == nil {
			return writeErr
		} else {
			_ = m.MarkDirectBroken()
		}
	}

	if m.cfg.RelaySend != nil {
		return m.cfg.RelaySend(ctx, payload)
	}
	return errors.New("transport has no active relay or direct path")
}

func (m *Manager) relayReadLoop(ctx context.Context) {
	if m.cfg.ReceiveRelay == nil {
		return
	}

	for {
		payload, err := m.cfg.ReceiveRelay(ctx)
		if err != nil {
			if ctx.Err() != nil || isTerminalReadError(err) {
				return
			}
			if !m.waitForNextControlRead(ctx) {
				return
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}
		m.enqueuePeerDatagram(m.cfg.RelayAddr, payload)
	}
}

func (m *Manager) enqueuePeerDatagram(addr net.Addr, payload []byte) {
	pkt := peerPacket{payload: clonePeerDatagramPayload(payload), addr: addr}
	select {
	case m.peerRecvCh <- pkt:
		m.notePeerRecvDepth(len(m.peerRecvCh))
	default:
		m.peerRecvDrops.Add(1)
		select {
		case dropped := <-m.peerRecvCh:
			releasePeerDatagramPayload(dropped.payload)
		default:
		}
		m.peerRecvCh <- pkt
		m.notePeerRecvDepth(len(m.peerRecvCh))
	}
}

func (m *Manager) localPeerAddr() net.Addr {
	if m.cfg.DirectConn != nil {
		return m.cfg.DirectConn.LocalAddr()
	}
	if m.cfg.RelayConn != nil {
		return m.cfg.RelayConn.LocalAddr()
	}
	return nil
}

func (m *Manager) remotePeerAddr() net.Addr {
	if m.cfg.RelayAddr != nil {
		return m.cfg.RelayAddr
	}
	if addr, active := m.DirectAddr(); active {
		return addr
	}
	return nil
}

func clonePeerDatagramPayload(payload []byte) []byte {
	if len(payload) > peerDatagramPayloadPoolSize {
		return append([]byte(nil), payload...)
	}
	bufPtr := peerDatagramPayloadPool.Get().(*[]byte)
	buf := (*bufPtr)[:len(payload)]
	copy(buf, payload)
	return buf
}

func releasePeerDatagramPayload(payload []byte) {
	if cap(payload) != peerDatagramPayloadPoolSize {
		return
	}
	clear(payload)
	buf := payload[:peerDatagramPayloadPoolSize]
	peerDatagramPayloadPool.Put(&buf)
}
