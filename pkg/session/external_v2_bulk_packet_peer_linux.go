// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type externalV2BulkPacketLinuxPeer struct {
	family uint16
	port   uint16
	zone   uint32
	addr   [16]byte
}

type externalV2BulkPacketLinuxPeerOps struct {
	connect     func(int, unix.Sockaddr) error
	getpeername func(int) (unix.Sockaddr, error)
	disconnect  func(int) error
}

func externalV2BulkPacketLinuxSystemPeerOps() externalV2BulkPacketLinuxPeerOps {
	return externalV2BulkPacketLinuxPeerOps{
		connect:     unix.Connect,
		getpeername: unix.Getpeername,
		disconnect:  externalV2BulkPacketLinuxDisconnectFD,
	}
}

func externalV2BulkPacketLinuxPeerFromAddr(addr net.Addr) (externalV2BulkPacketLinuxPeer, unix.Sockaddr, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 1<<16-1 {
		return externalV2BulkPacketLinuxPeer{}, nil, false
	}
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		peer := externalV2BulkPacketLinuxPeer{family: unix.AF_INET, port: uint16(udpAddr.Port)}
		copy(peer.addr[:4], ip4)
		sockaddr := &unix.SockaddrInet4{Port: udpAddr.Port}
		copy(sockaddr.Addr[:], ip4)
		return peer, sockaddr, true
	}
	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return externalV2BulkPacketLinuxPeer{}, nil, false
	}
	peer := externalV2BulkPacketLinuxPeer{family: unix.AF_INET6, port: uint16(udpAddr.Port)}
	copy(peer.addr[:], ip6)
	sockaddr := &unix.SockaddrInet6{Port: udpAddr.Port}
	copy(sockaddr.Addr[:], ip6)
	if udpAddr.Zone != "" {
		zone, ok := externalV2BulkPacketLinuxZoneID(udpAddr.Zone)
		if !ok {
			return externalV2BulkPacketLinuxPeer{}, nil, false
		}
		peer.zone = zone
		sockaddr.ZoneId = peer.zone
	}
	return peer, sockaddr, true
}

func externalV2BulkPacketLinuxZoneID(zone string) (uint32, bool) {
	if zone == "" {
		return 0, true
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		if iface.Index <= 0 || uint64(iface.Index) > uint64(^uint32(0)) {
			return 0, false
		}
		return uint32(iface.Index), true
	}
	index, err := strconv.ParseUint(zone, 10, 32)
	if err != nil || index == 0 {
		return 0, false
	}
	return uint32(index), true
}

func externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr unix.Sockaddr) (externalV2BulkPacketLinuxPeer, bool) {
	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		if addr == nil || addr.Port < 0 || addr.Port > 1<<16-1 {
			return externalV2BulkPacketLinuxPeer{}, false
		}
		peer := externalV2BulkPacketLinuxPeer{family: unix.AF_INET, port: uint16(addr.Port)}
		copy(peer.addr[:4], addr.Addr[:])
		return peer, true
	case *unix.SockaddrInet6:
		if addr == nil || addr.Port < 0 || addr.Port > 1<<16-1 {
			return externalV2BulkPacketLinuxPeer{}, false
		}
		peer := externalV2BulkPacketLinuxPeer{
			family: unix.AF_INET6,
			port:   uint16(addr.Port),
			zone:   addr.ZoneId,
			addr:   addr.Addr,
		}
		return peer, true
	default:
		return externalV2BulkPacketLinuxPeer{}, false
	}
}

func externalV2BulkPacketLinuxConnectFixedPeer(raw syscall.RawConn, addr net.Addr) error {
	return externalV2BulkPacketLinuxConnectFixedPeerWithOps(raw, addr, externalV2BulkPacketLinuxSystemPeerOps())
}

func externalV2BulkPacketLinuxConnectFixedPeerWithOps(raw syscall.RawConn, addr net.Addr, ops externalV2BulkPacketLinuxPeerOps) error {
	peer, sockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(addr)
	if !ok {
		return fmt.Errorf("invalid bulk packet fixed peer %v", addr)
	}
	if raw == nil {
		return errors.New("bulk packet fixed peer has no raw socket")
	}
	connectErr, controlErr := externalV2BulkPacketLinuxControl(raw, func(fd int) error {
		return ops.connect(fd, sockaddr)
	})
	if controlErr != nil {
		rollbackErr := externalV2BulkPacketLinuxDisconnectRawWithOps(raw, ops)
		return errors.Join(
			externalV2BulkPacketLinuxWrapError("connect bulk packet fixed peer", connectErr),
			externalV2BulkPacketLinuxWrapError("control bulk packet fixed peer connect", controlErr),
			externalV2BulkPacketLinuxWrapError("rollback bulk packet fixed peer connect", rollbackErr),
		)
	}
	if connectErr != nil {
		return fmt.Errorf("connect bulk packet fixed peer: %w", connectErr)
	}
	return externalV2BulkPacketLinuxVerifyPeerWithOps(raw, peer, ops)
}

func externalV2BulkPacketLinuxVerifyPeer(raw syscall.RawConn, expected externalV2BulkPacketLinuxPeer) error {
	return externalV2BulkPacketLinuxVerifyPeerWithOps(raw, expected, externalV2BulkPacketLinuxSystemPeerOps())
}

func externalV2BulkPacketLinuxVerifyPeerWithOps(raw syscall.RawConn, expected externalV2BulkPacketLinuxPeer, ops externalV2BulkPacketLinuxPeerOps) error {
	if raw == nil {
		return errors.New("verify bulk packet fixed peer without a raw socket")
	}
	verifyErr, controlErr := externalV2BulkPacketLinuxControl(raw, func(fd int) error {
		return externalV2BulkPacketLinuxVerifyPeerFDWithOps(fd, expected, ops)
	})
	if verifyErr == nil && controlErr == nil {
		return nil
	}
	rollbackErr := externalV2BulkPacketLinuxDisconnectRawWithOps(raw, ops)
	return errors.Join(
		externalV2BulkPacketLinuxWrapError("verify bulk packet fixed peer", verifyErr),
		externalV2BulkPacketLinuxWrapError("control bulk packet fixed peer verification", controlErr),
		externalV2BulkPacketLinuxWrapError("rollback unverified bulk packet fixed peer", rollbackErr),
	)
}

func externalV2BulkPacketLinuxVerifyPeerFDWithOps(fd int, expected externalV2BulkPacketLinuxPeer, ops externalV2BulkPacketLinuxPeerOps) error {
	sockaddr, err := ops.getpeername(fd)
	if err != nil {
		return fmt.Errorf("get bulk packet fixed peer: %w", err)
	}
	actual, ok := externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr)
	if !ok {
		return fmt.Errorf("unsupported bulk packet fixed peer %T", sockaddr)
	}
	if actual != expected {
		return fmt.Errorf("bulk packet fixed peer mismatch: got %#v want %#v", actual, expected)
	}
	return nil
}

func externalV2BulkPacketLinuxDisconnectRawWithOps(raw syscall.RawConn, ops externalV2BulkPacketLinuxPeerOps) error {
	if raw == nil {
		return errors.New("disconnect bulk packet fixed peer without a raw socket")
	}
	disconnectErr, controlErr := externalV2BulkPacketLinuxControl(raw, ops.disconnect)
	return errors.Join(
		externalV2BulkPacketLinuxWrapError("disconnect bulk packet fixed peer", disconnectErr),
		externalV2BulkPacketLinuxWrapError("control bulk packet fixed peer disconnect", controlErr),
	)
}

func externalV2BulkPacketLinuxControl(raw syscall.RawConn, callback func(int) error) (callbackErr, controlErr error) {
	controlErr = raw.Control(func(fd uintptr) {
		callbackErr = callback(int(fd))
	})
	return callbackErr, controlErr
}

func externalV2BulkPacketLinuxWrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func externalV2BulkPacketLinuxDisconnectFD(fd int) error {
	addr := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	_, _, errno := unix.Syscall(
		unix.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)
	runtime.KeepAlive(&addr)
	if errno != 0 {
		return errno
	}
	return nil
}
