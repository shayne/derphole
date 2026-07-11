// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "net"

const externalPacketConnSocketBufferBytes = 8 << 20

type externalPacketConnSocketBufferStats struct {
	RequestedBytes int
	ReadBytes      int
	WriteBytes     int
	ReadSetError   error
	WriteSetError  error
	InspectError   error
}

func tuneExternalPacketConn(conn net.PacketConn) externalPacketConnSocketBufferStats {
	stats := externalPacketConnSocketBufferStats{
		RequestedBytes: externalPacketConnSocketBufferBytes,
	}
	if setter, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		stats.ReadSetError = setter.SetReadBuffer(externalPacketConnSocketBufferBytes)
	}
	if setter, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		stats.WriteSetError = setter.SetWriteBuffer(externalPacketConnSocketBufferBytes)
	}
	stats.ReadBytes, stats.WriteBytes, stats.InspectError =
		readExternalPacketConnSocketBuffers(conn)
	return stats
}
