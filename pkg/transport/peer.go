package transport

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type PeerDatagramConn interface {
	SendDatagram([]byte) error
	RecvDatagram(context.Context) ([]byte, net.Addr, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
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
		return append([]byte(nil), pkt.payload...), pkt.addr, nil
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

	if endpoint, active := m.DirectPath(); active && m.cfg.DirectConn != nil {
		if addr, err := net.ResolveUDPAddr("udp", endpoint); err == nil {
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
	pkt := peerPacket{payload: append([]byte(nil), payload...), addr: cloneAddr(addr)}
	select {
	case m.peerRecvCh <- pkt:
	default:
		select {
		case <-m.peerRecvCh:
		default:
		}
		m.peerRecvCh <- pkt
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
	if endpoint, active := m.DirectPath(); active {
		if addr, err := net.ResolveUDPAddr("udp", endpoint); err == nil {
			return addr
		}
	}
	return nil
}
