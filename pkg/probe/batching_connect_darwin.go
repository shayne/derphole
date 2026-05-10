// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package probe

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/sys/unix"
)

func platformConnectUDP(conn *net.UDPConn, peer *net.UDPAddr) error {
	if conn == nil || peer == nil {
		return errors.New("nil udp conn or peer")
	}
	sa, err := udpSockaddr(conn.LocalAddr(), peer)
	if err != nil {
		return err
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var connectErr error
	if err := rawConn.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), sa)
	}); err != nil {
		return err
	}
	return connectErr
}

func udpSockaddr(local net.Addr, peer *net.UDPAddr) (unix.Sockaddr, error) {
	ap := peer.AddrPort()
	if !ap.IsValid() {
		return nil, errors.New("invalid udp peer")
	}
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		if localUDPAddrIs6(local) {
			v4 := addr.As4()
			var v6 [16]byte
			v6[10] = 0xff
			v6[11] = 0xff
			copy(v6[12:], v4[:])
			return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: v6}, nil
		}
		v4 := addr.As4()
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: v4}, nil
	}
	if addr.Is6() {
		v6 := addr.As16()
		return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: v6, ZoneId: zoneID(addr)}, nil
	}
	return nil, errors.New("unsupported udp peer address")
}

func localUDPAddrIs6(addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return false
	}
	ap := udpAddr.AddrPort()
	return ap.IsValid() && ap.Addr().Is6()
}

func zoneID(addr netip.Addr) uint32 {
	zone := addr.Zone()
	if zone == "" {
		return 0
	}
	if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(id)
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		return uint32(iface.Index)
	}
	return 0
}
