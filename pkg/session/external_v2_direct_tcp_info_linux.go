// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func externalV2DirectTCPRetransmits(path *externalV2DirectTCPPath) (int64, bool) {
	if path == nil || len(path.conns) == 0 {
		return 0, false
	}
	var total int64
	for _, conn := range path.conns {
		if conn == nil {
			return 0, false
		}
		retransmits, ok := externalV2DirectTCPConnRetransmits(conn.NetConn())
		if !ok {
			return 0, false
		}
		total += retransmits
	}
	return total, true
}

func externalV2DirectTCPConnRetransmits(conn net.Conn) (int64, bool) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		info, socketErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || socketErr != nil || info == nil {
		return 0, false
	}
	return int64(info.Total_retrans), true
}
