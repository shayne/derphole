// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package transportbench

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type tcpInfoSnapshot struct {
	retransmits  uint64
	cwndSegments uint32
}

func tcpInfoForConn(conn net.Conn) (tcpInfoSnapshot, bool) {
	conn = unwrapTCPInfoConn(conn)
	raw, ok := tcpInfoRawConn(conn)
	if !ok {
		return tcpInfoSnapshot{}, false
	}
	info, ok := loadTCPInfo(raw)
	if !ok {
		return tcpInfoSnapshot{}, false
	}
	return tcpInfoSnapshot{retransmits: uint64(info.Total_retrans), cwndSegments: info.Snd_cwnd}, true
}

func unwrapTCPInfoConn(conn net.Conn) net.Conn {
	if unwrapper, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return unwrapper.NetConn()
	}
	return conn
}

func tcpInfoRawConn(conn net.Conn) (syscall.RawConn, bool) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, false
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, false
	}
	return raw, true
}

func loadTCPInfo(raw syscall.RawConn) (*unix.TCPInfo, bool) {
	var info *unix.TCPInfo
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		info, socketErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return nil, false
	}
	if socketErr != nil {
		return nil, false
	}
	return info, info != nil
}
