//go:build !linux

package probe

import "net"

func newPlatformBatcher(conn net.PacketConn, requested string) packetBatcher {
	return nil
}

func platformSetSocketBuffers(conn net.PacketConn, caps *TransportCaps, size int) {
	if conn == nil {
		return
	}
	type readBufferSetter interface {
		SetReadBuffer(int) error
	}
	type writeBufferSetter interface {
		SetWriteBuffer(int) error
	}
	if setter, ok := conn.(readBufferSetter); ok {
		_ = setter.SetReadBuffer(size)
	}
	if setter, ok := conn.(writeBufferSetter); ok {
		_ = setter.SetWriteBuffer(size)
	}
	_ = caps
}

func platformSetSocketPacing(conn net.PacketConn, bytesPerSecond uint64) bool {
	return false
}
