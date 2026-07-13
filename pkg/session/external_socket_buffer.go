// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "net"

// Two MiB per lane gives an eight-lane path 16 MiB of requested receive and
// send buffering. Linux reports doubled kernel accounting, so this bounds the
// effective eight-lane receive and send buffers to 32 MiB each on small hosts.
const externalPacketConnSocketBufferBytes = 2 << 20

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

func tuneExternalPacketConnReceive(conn net.PacketConn, requestedBytes int) externalPacketConnSocketBufferStats {
	stats := externalPacketConnSocketBufferStats{RequestedBytes: requestedBytes}
	if setter, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		stats.ReadSetError = setter.SetReadBuffer(requestedBytes)
	}
	stats.ReadBytes, stats.WriteBytes, stats.InspectError = readExternalPacketConnSocketBuffers(conn)
	return stats
}
