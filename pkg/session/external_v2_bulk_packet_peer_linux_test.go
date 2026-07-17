// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketLinuxPeerIPv4BinaryRoundTrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123}
	peer, sockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(addr)
	if !ok {
		t.Fatal("IPv4 peer was rejected")
	}
	wantAddr := [16]byte{127, 0, 0, 1}
	if peer != (externalV2BulkPacketLinuxPeer{family: unix.AF_INET, port: 8123, addr: wantAddr}) {
		t.Fatalf("IPv4 peer = %#v", peer)
	}
	if got, typeOK := sockaddr.(*unix.SockaddrInet4); !typeOK || got.Port != 8123 || got.Addr != [4]byte{127, 0, 0, 1} {
		t.Fatalf("IPv4 sockaddr = %#v", sockaddr)
	}
	if roundTrip, ok := externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr); !ok || roundTrip != peer {
		t.Fatalf("IPv4 round trip = %#v, %t", roundTrip, ok)
	}
}

func TestExternalV2BulkPacketLinuxPeerIPv6ZoneBinaryRoundTrip(t *testing.T) {
	loopback := externalV2BulkPacketLinuxLoopbackInterface(t)
	addr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 8124, Zone: loopback.Name}
	peer, sockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(addr)
	if !ok {
		t.Fatal("IPv6 peer with zone was rejected")
	}
	wantAddr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if peer != (externalV2BulkPacketLinuxPeer{family: unix.AF_INET6, port: 8124, zone: uint32(loopback.Index), addr: wantAddr}) {
		t.Fatalf("IPv6 peer = %#v", peer)
	}
	if got, typeOK := sockaddr.(*unix.SockaddrInet6); !typeOK || got.Port != 8124 || got.ZoneId != uint32(loopback.Index) || got.Addr != wantAddr {
		t.Fatalf("IPv6 sockaddr = %#v", sockaddr)
	}
	if roundTrip, ok := externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr); !ok || roundTrip != peer {
		t.Fatalf("IPv6 round trip = %#v, %t", roundTrip, ok)
	}
}

func TestExternalV2BulkPacketLinuxPeerIPv6DecimalZone(t *testing.T) {
	for _, test := range []struct {
		zone     string
		wantZone uint32
		wantOK   bool
	}{
		{zone: "3", wantZone: 3, wantOK: true},
		{zone: "0003", wantZone: 3, wantOK: true},
		{zone: "4294967295", wantZone: 1<<32 - 1, wantOK: true},
		{zone: "0"},
		{zone: "0000"},
		{zone: "4294967296"},
		{zone: "3x"},
		{zone: "-1"},
	} {
		t.Run(test.zone, func(t *testing.T) {
			peer, sockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(&net.UDPAddr{
				IP: net.ParseIP("fe80::1"), Port: 8124, Zone: test.zone,
			})
			if ok != test.wantOK {
				t.Fatalf("zone %q accepted = %t, want %t", test.zone, ok, test.wantOK)
			}
			if !ok {
				return
			}
			if peer.zone != test.wantZone {
				t.Fatalf("zone %q peer scope = %d, want %d", test.zone, peer.zone, test.wantZone)
			}
			if got := sockaddr.(*unix.SockaddrInet6).ZoneId; got != test.wantZone {
				t.Fatalf("zone %q sockaddr scope = %d, want %d", test.zone, got, test.wantZone)
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxPeerRejectsInvalidAddresses(t *testing.T) {
	for _, test := range []struct {
		name string
		addr net.Addr
	}{
		{name: "nil"},
		{name: "wrong network", addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123}},
		{name: "negative port", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: -1}},
		{name: "oversized port", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1 << 16}},
		{name: "invalid IP", addr: &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 8123}},
		{name: "invalid zone", addr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 8123, Zone: "missing-interface"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if peer, sockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(test.addr); ok {
				t.Fatalf("invalid peer accepted: peer=%#v sockaddr=%#v", peer, sockaddr)
			}
		})
	}
	for _, sockaddr := range []unix.Sockaddr{
		&unix.SockaddrUnix{Name: "not-udp"},
		&unix.SockaddrInet4{Port: -1},
		&unix.SockaddrInet6{Port: 1 << 16},
	} {
		if peer, ok := externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr); ok {
			t.Fatalf("invalid sockaddr accepted: peer=%#v sockaddr=%#v", peer, sockaddr)
		}
	}
}

func TestExternalV2BulkPacketLinuxFixedPeerRejectsInvalidPeer(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "connected-gso3")

	for name, addr := range map[string]net.Addr{
		"nil":           nil,
		"wrong network": &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123},
		"invalid IP":    &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 8123},
	} {
		t.Run(name, func(t *testing.T) {
			conn := listenExternalV2BulkPacketLinuxUDP(t)
			defer conn.Close()
			batch := newExternalV2BulkPacketBatchConn(conn)
			if err := enableExternalV2BulkPacketFixedPeerConnect(batch, addr); err == nil {
				t.Fatalf("invalid peer %v was accepted", addr)
			}
			if err := externalV2BulkPacketLinuxGetpeernameError(conn); !errors.Is(err, unix.ENOTCONN) {
				t.Fatalf("invalid peer left socket connected: %v", err)
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxFixedPeerMismatchDisconnects(t *testing.T) {
	first := listenExternalV2BulkPacketLinuxUDP(t)
	defer first.Close()
	second := listenExternalV2BulkPacketLinuxUDP(t)
	defer second.Close()
	sender := listenExternalV2BulkPacketLinuxUDP(t)
	defer sender.Close()
	raw, err := sender.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_, firstSockaddr, ok := externalV2BulkPacketLinuxPeerFromAddr(first.LocalAddr())
	if !ok {
		t.Fatal("first peer conversion failed")
	}
	secondPeer, _, ok := externalV2BulkPacketLinuxPeerFromAddr(second.LocalAddr())
	if !ok {
		t.Fatal("second peer conversion failed")
	}
	var connectErr error
	if err := raw.Control(func(fd uintptr) { connectErr = unix.Connect(int(fd), firstSockaddr) }); err != nil {
		t.Fatal(err)
	}
	if connectErr != nil {
		t.Fatal(connectErr)
	}
	if err := externalV2BulkPacketLinuxVerifyPeer(raw, secondPeer); err == nil {
		t.Fatal("mismatched peer verification succeeded")
	}
	if err := externalV2BulkPacketLinuxGetpeernameError(sender); !errors.Is(err, unix.ENOTCONN) {
		t.Fatalf("mismatch did not disconnect socket: %v", err)
	}
	if _, err := sender.WriteToUDP([]byte("disconnected"), second.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write after disconnect: %v", err)
	}
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, _, err := second.ReadFromUDP(buffer); err != nil || string(buffer[:n]) != "disconnected" {
		t.Fatalf("read after disconnect: n=%d payload=%q err=%v", n, buffer[:n], err)
	}
}

func TestExternalV2BulkPacketLinuxFixedPeerConnectJoinsControlAndRollbackErrors(t *testing.T) {
	connectCallbackErr := errors.New("connect callback")
	connectControlErr := errors.New("connect control")
	rollbackCallbackErr := errors.New("rollback callback")
	rollbackControlErr := errors.New("rollback control")
	connected := false
	raw := &scriptedExternalV2BulkPacketLinuxRawConn{controlErrors: []error{connectControlErr, rollbackControlErr}}
	ops := externalV2BulkPacketLinuxPeerOps{
		connect: func(int, unix.Sockaddr) error {
			connected = true
			return connectCallbackErr
		},
		getpeername: func(int) (unix.Sockaddr, error) {
			return nil, errors.New("unexpected getpeername")
		},
		disconnect: func(int) error {
			connected = false
			return rollbackCallbackErr
		},
	}
	err := externalV2BulkPacketLinuxConnectFixedPeerWithOps(raw, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: 8123,
	}, ops)
	assertExternalV2BulkPacketLinuxErrors(t, err,
		connectCallbackErr, connectControlErr, rollbackCallbackErr, rollbackControlErr,
	)
	if connected {
		t.Fatal("uncertain connect state leaked after Control failure")
	}
	if raw.controlCalls != 2 {
		t.Fatalf("Control calls = %d, want connect plus rollback", raw.controlCalls)
	}
}

func TestExternalV2BulkPacketLinuxFixedPeerVerifyJoinsControlAndRollbackErrors(t *testing.T) {
	verifyCallbackErr := errors.New("verify callback")
	verifyControlErr := errors.New("verify control")
	rollbackCallbackErr := errors.New("rollback callback")
	rollbackControlErr := errors.New("rollback control")
	connected := true
	raw := &scriptedExternalV2BulkPacketLinuxRawConn{controlErrors: []error{verifyControlErr, rollbackControlErr}}
	ops := externalV2BulkPacketLinuxPeerOps{
		connect: func(int, unix.Sockaddr) error {
			return errors.New("unexpected connect")
		},
		getpeername: func(int) (unix.Sockaddr, error) {
			return nil, verifyCallbackErr
		},
		disconnect: func(int) error {
			connected = false
			return rollbackCallbackErr
		},
	}
	err := externalV2BulkPacketLinuxVerifyPeerWithOps(raw, externalV2BulkPacketLinuxPeer{}, ops)
	assertExternalV2BulkPacketLinuxErrors(t, err,
		verifyCallbackErr, verifyControlErr, rollbackCallbackErr, rollbackControlErr,
	)
	if connected {
		t.Fatal("unverified peer remained connected after Control failure")
	}
	if raw.controlCalls != 2 {
		t.Fatalf("Control calls = %d, want verify plus rollback", raw.controlCalls)
	}
}

func TestExternalV2BulkPacketLinuxFixedPeerDisconnectJoinsCallbackAndControlErrors(t *testing.T) {
	disconnectCallbackErr := errors.New("disconnect callback")
	disconnectControlErr := errors.New("disconnect control")
	connected := true
	raw := &scriptedExternalV2BulkPacketLinuxRawConn{controlErrors: []error{disconnectControlErr}}
	ops := externalV2BulkPacketLinuxPeerOps{
		disconnect: func(int) error {
			connected = false
			return disconnectCallbackErr
		},
	}
	err := externalV2BulkPacketLinuxDisconnectRawWithOps(raw, ops)
	assertExternalV2BulkPacketLinuxErrors(t, err, disconnectCallbackErr, disconnectControlErr)
	if connected {
		t.Fatal("disconnect callback did not clear connected state")
	}
	if raw.controlCalls != 1 {
		t.Fatalf("Control calls = %d, want 1", raw.controlCalls)
	}
}

func TestExternalV2BulkPacketLinuxFixedPeersLeaveFifthSocketForSealedControl(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "connected-gso3")

	const laneCount = 4
	path := externalV2BulkPacketPath{Conns: make([]net.PacketConn, laneCount+1), Addrs: make([]net.Addr, laneCount+1)}
	receivers := make([]*net.UDPConn, laneCount+1)
	batches := make([]externalV2BulkPacketBatchConn, laneCount)
	for lane := range laneCount + 1 {
		receivers[lane] = listenExternalV2BulkPacketLinuxUDP(t)
		t.Cleanup(func() { receivers[lane].Close() })
		sender := listenExternalV2BulkPacketLinuxUDP(t)
		t.Cleanup(func() { sender.Close() })
		path.Conns[lane] = sender
		path.Addrs[lane] = receivers[lane].LocalAddr()
		if lane < laneCount {
			batches[lane] = newExternalV2BulkPacketBatchConn(sender)
		}
	}
	if err := enableExternalV2BulkPacketFixedPeers(path, batches, laneCount); err != nil {
		t.Fatal(err)
	}
	for lane := range laneCount {
		peer, err := externalV2BulkPacketLinuxSocketPeer(path.Conns[lane].(*net.UDPConn))
		if err != nil {
			t.Fatalf("lane %d peer: %v", lane, err)
		}
		want, _, ok := externalV2BulkPacketLinuxPeerFromAddr(path.Addrs[lane])
		if !ok || peer != want {
			t.Fatalf("lane %d peer = %#v, want %#v", lane, peer, want)
		}
	}
	if err := externalV2BulkPacketLinuxGetpeernameError(path.Conns[laneCount].(*net.UDPConn)); !errors.Is(err, unix.ENOTCONN) {
		t.Fatalf("fifth socket peer error = %v, want ENOTCONN", err)
	}

	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	frames := []struct {
		header  externalV2BulkPacketHeader
		payload []byte
	}{
		{header: externalV2BulkPacketHeader{kind: externalV2BulkPacketHello, total: 1}},
		{header: externalV2BulkPacketHeader{kind: externalV2BulkPacketAck, runID: 9, total: 1}, payload: encodeExternalV2BulkPacketAck(1, 2)},
	}
	buffer := make([]byte, externalV2BulkPacketMaxSize)
	for _, frame := range frames {
		if err := writeExternalV2BulkPacketControl(path, auth, frame.header, frame.payload); err != nil {
			t.Fatal(err)
		}
		if err := receivers[laneCount].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := receivers[laneCount].ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		header, payload, ok := openExternalV2BulkPacket(auth.control, buffer[:n])
		if !ok || header.kind != frame.header.kind || header.runID != frame.header.runID || string(payload) != string(frame.payload) {
			t.Fatalf("sealed control frame = header %+v payload %x ok=%t", header, payload, ok)
		}
	}
}

func externalV2BulkPacketLinuxLoopbackInterface(t *testing.T) net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface
		}
	}
	t.Fatal("no loopback interface")
	return net.Interface{}
}

func externalV2BulkPacketLinuxSocketPeer(conn *net.UDPConn) (externalV2BulkPacketLinuxPeer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return externalV2BulkPacketLinuxPeer{}, err
	}
	var peer externalV2BulkPacketLinuxPeer
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		sockaddr, err := unix.Getpeername(int(fd))
		if err != nil {
			peerErr = err
			return
		}
		var ok bool
		peer, ok = externalV2BulkPacketLinuxPeerFromSockaddr(sockaddr)
		if !ok {
			peerErr = syscall.EINVAL
		}
	}); err != nil {
		return externalV2BulkPacketLinuxPeer{}, err
	}
	return peer, peerErr
}

func externalV2BulkPacketLinuxGetpeernameError(conn *net.UDPConn) error {
	_, err := externalV2BulkPacketLinuxSocketPeer(conn)
	return err
}

type scriptedExternalV2BulkPacketLinuxRawConn struct {
	controlErrors []error
	controlCalls  int
}

func (c *scriptedExternalV2BulkPacketLinuxRawConn) Control(callback func(uintptr)) error {
	index := c.controlCalls
	c.controlCalls++
	callback(uintptr(index + 1))
	if index >= len(c.controlErrors) {
		return nil
	}
	return c.controlErrors[index]
}

func (*scriptedExternalV2BulkPacketLinuxRawConn) Read(func(uintptr) bool) error {
	return errors.New("unexpected RawConn.Read")
}

func (*scriptedExternalV2BulkPacketLinuxRawConn) Write(func(uintptr) bool) error {
	return errors.New("unexpected RawConn.Write")
}

func assertExternalV2BulkPacketLinuxErrors(t *testing.T, err error, wants ...error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	for _, want := range wants {
		if !errors.Is(err, want) {
			t.Fatalf("error %v does not contain %v", err, want)
		}
	}
}
