package quicpath

import (
	"context"
	"net"
	"testing"
)

type benchmarkPeerDatagramConn struct {
	local   net.Addr
	remote  net.Addr
	payload []byte
}

func (c benchmarkPeerDatagramConn) SendDatagram([]byte) error {
	return nil
}

func (c benchmarkPeerDatagramConn) RecvDatagram(context.Context) ([]byte, net.Addr, error) {
	return c.payload, c.remote, nil
}

func (c benchmarkPeerDatagramConn) LocalAddr() net.Addr  { return c.local }
func (c benchmarkPeerDatagramConn) RemoteAddr() net.Addr { return c.remote }
func (c benchmarkPeerDatagramConn) ReleaseDatagram([]byte) {
}
func (c benchmarkPeerDatagramConn) Close() error { return nil }

func BenchmarkAdapterWriteTo(b *testing.B) {
	conn := NewAdapter(benchmarkPeerDatagramConn{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222},
	})
	payload := make([]byte, 1200)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, nil); err != nil {
			b.Fatalf("WriteTo() error = %v", err)
		}
	}
}

func BenchmarkAdapterReadFrom(b *testing.B) {
	conn := NewAdapter(benchmarkPeerDatagramConn{
		local:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		remote:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222},
		payload: make([]byte, 1200),
	})
	buf := make([]byte, 1500)

	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := conn.ReadFrom(buf); err != nil {
			b.Fatalf("ReadFrom() error = %v", err)
		}
	}
}
