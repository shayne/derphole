//go:build darwin || linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func readExternalPacketConnSocketBuffers(conn net.PacketConn) (int, int, error) {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, 0, fmt.Errorf("%T does not expose syscall.Conn", conn)
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var readBytes int
	var writeBytes int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		readBytes, socketErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_RCVBUF,
		)
		if socketErr != nil {
			return
		}
		writeBytes, socketErr = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_SNDBUF,
		)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return readBytes, writeBytes, nil
}
