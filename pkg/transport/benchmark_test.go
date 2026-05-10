// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

type benchmarkPacketConn struct {
	local net.Addr
}

func (c benchmarkPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c benchmarkPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c benchmarkPacketConn) Close() error                     { return nil }
func (c benchmarkPacketConn) LocalAddr() net.Addr              { return c.local }
func (c benchmarkPacketConn) SetDeadline(time.Time) error      { return nil }
func (c benchmarkPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c benchmarkPacketConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkManagerSendPeerDatagramDirectPath(b *testing.B) {
	clock := newFakeClock(time.Unix(1700001015, 0))
	peerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 42424}
	mgr := NewManager(ManagerConfig{
		DirectConn: benchmarkPacketConn{
			local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		},
		Clock:              clock,
		DirectStaleTimeout: 30 * time.Second,
	})

	mgr.mu.Lock()
	mgr.state.endpoints[peerAddr.String()] = peerAddr
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerAddr.String()
	mgr.state.lastDirectAt = clock.Now()
	mgr.mu.Unlock()

	payload := make([]byte, 1200)
	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := mgr.sendPeerDatagram(ctx, payload); err != nil {
			b.Fatalf("sendPeerDatagram() error = %v", err)
		}
	}
}

func BenchmarkPeerDatagramConnRecvDatagram(b *testing.B) {
	mgr := NewManager(ManagerConfig{
		Clock: realClock{},
	})
	conn := mgr.PeerDatagramConn(context.Background())
	peerAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 42424}
	payload := make([]byte, 1200)
	ctx := context.Background()

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.peerRecvCh <- peerPacket{payload: payload, addr: peerAddr}
		if _, _, err := conn.RecvDatagram(ctx); err != nil {
			b.Fatalf("RecvDatagram() error = %v", err)
		}
	}
}
