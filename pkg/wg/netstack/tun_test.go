// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestCloseUnblocksWriteNotify(t *testing.T) {
	tun := &netTun{
		ep:             channel.New(16, 1500, ""),
		incomingPacket: make(chan *buffer.View),
		closeCh:        make(chan struct{}),
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x14}),
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if n, tcpErr := tun.ep.WritePackets(pkts); tcpErr != nil || n != 1 {
		t.Fatalf("WritePackets() = (%d, %v), want (1, nil)", n, tcpErr)
	}

	writeDone := make(chan struct{})
	go func() {
		tun.WriteNotify()
		close(writeDone)
	}()

	select {
	case <-writeDone:
		t.Fatal("WriteNotify() returned before Close()")
	case <-time.After(20 * time.Millisecond):
	}

	closeDone := make(chan struct{})
	go func() {
		_ = tun.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked while WriteNotify() was waiting on incomingPacket")
	}

	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteNotify() remained blocked after Close()")
	}
}

func TestCreateNetTUNConfiguresDeviceAndRoutes(t *testing.T) {
	t.Parallel()

	dev, netTun, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	defer dev.Close()

	if name, err := dev.Name(); err != nil || name != "go" {
		t.Fatalf("Name() = %q, %v; want go, nil", name, err)
	}
	if got := dev.File(); got != nil {
		t.Fatalf("File() = %#v, want nil", got)
	}
	if mtu, err := dev.MTU(); err != nil || mtu != 1280 {
		t.Fatalf("MTU() = %d, %v; want 1280, nil", mtu, err)
	}
	if batch := dev.BatchSize(); batch != 1 {
		t.Fatalf("BatchSize() = %d, want 1", batch)
	}
	if !(*netTun).hasV4 || !(*netTun).hasV6 {
		t.Fatalf("IP families = v4:%v v6:%v, want both", (*netTun).hasV4, (*netTun).hasV6)
	}
	if got := (*netTun).dnsServers; len(got) != 1 || got[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("dnsServers = %v, want [1.1.1.1]", got)
	}

	select {
	case event := <-dev.Events():
		if event != tun.EventUp {
			t.Fatalf("event = %v, want EventUp", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for EventUp")
	}
}

func TestNetTUNReadWriteAndClosePaths(t *testing.T) {
	t.Parallel()

	dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	defer dev.Close()

	if n, err := dev.Write([][]byte{{0x00}}, 0); !errors.Is(err, syscall.EAFNOSUPPORT) || n != 0 {
		t.Fatalf("Write(unsupported) = %d, %v; want 0, EAFNOSUPPORT", n, err)
	}
	if n, err := dev.Write([][]byte{{}, {0x45, 0x00, 0x00, 0x14}}, 0); err != nil || n != 2 {
		t.Fatalf("Write(IPv4) = %d, %v; want 2, nil", n, err)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	bufs := [][]byte{make([]byte, 64)}
	sizes := []int{0}
	if n, err := dev.Read(bufs, sizes, 0); !errors.Is(err, os.ErrClosed) || n != 0 {
		t.Fatalf("Read(after close) = %d, %v; want 0, os.ErrClosed", n, err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestNetTUNTCPAndUDPAdaptersLoopback(t *testing.T) {
	t.Parallel()

	dev, netTun, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	defer dev.Close()

	listener, err := netTun.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.1:0"))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct {
		payload string
		err     error
	}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- struct {
				payload string
				err     error
			}{err: err}
			return
		}
		defer conn.Close()
		buf := make([]byte, len("netstack tcp"))
		_, err = io.ReadFull(conn, buf)
		accepted <- struct {
			payload string
			err     error
		}{payload: string(buf), err: err}
	}()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	client, err := netTun.DialContextTCP(context.Background(), tcpAddr)
	if err != nil {
		t.Fatalf("DialContextTCP() error = %v", err)
	}
	if _, err := client.Write([]byte("netstack tcp")); err != nil {
		t.Fatalf("TCP Write() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("TCP Close() error = %v", err)
	}
	got := <-accepted
	if got.err != nil || got.payload != "netstack tcp" {
		t.Fatalf("accepted TCP = %q, %v; want payload", got.payload, got.err)
	}

	udp, err := netTun.DialUDPAddrPort(netip.MustParseAddrPort("100.64.0.1:0"), netip.AddrPort{})
	if err != nil {
		t.Fatalf("DialUDPAddrPort() error = %v", err)
	}
	if udp.LocalAddr() == nil {
		t.Fatal("UDP LocalAddr() = nil, want bound address")
	}
	if err := udp.Close(); err != nil {
		t.Fatalf("UDP Close() error = %v", err)
	}
}

func TestNetTUNTCPConvenienceWrappers(t *testing.T) {
	t.Parallel()

	dev, netTun, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN() error = %v", err)
	}
	defer dev.Close()

	listener, err := netTun.ListenTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan error, 2)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		accepted <- conn.Close()
	}()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	addrPort := netip.AddrPortFrom(netip.MustParseAddr("100.64.0.1"), uint16(tcpAddr.Port))
	client, err := netTun.DialTCPAddrPort(addrPort)
	if err != nil {
		t.Fatalf("DialTCPAddrPort() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accepted Close() error = %v", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		accepted <- conn.Close()
	}()
	client, err = netTun.DialTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: tcpAddr.Port})
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accepted Close() error = %v", err)
	}
}

func TestNetTUNAddressHelpers(t *testing.T) {
	t.Parallel()

	v4 := netip.MustParseAddrPort("192.0.2.44:443")
	full, proto := convertToFullAddr(v4)
	if proto != ipv4.ProtocolNumber || full.Port != 443 {
		t.Fatalf("convertToFullAddr(v4) = %#v, %v; want IPv4 port 443", full, proto)
	}
	if got := networkProtocol(v4.Addr()); got != ipv4.ProtocolNumber {
		t.Fatalf("networkProtocol(v4) = %v, want IPv4", got)
	}

	v6 := netip.MustParseAddrPort("[2001:db8::1]:8443")
	full, proto = convertToFullAddr(v6)
	if proto != ipv6.ProtocolNumber || full.Port != 8443 {
		t.Fatalf("convertToFullAddr(v6) = %#v, %v; want IPv6 port 8443", full, proto)
	}
	protoAddr := protocolAddress(v6.Addr())
	if protoAddr.Protocol != ipv6.ProtocolNumber {
		t.Fatalf("protocolAddress(v6).Protocol = %v, want IPv6", protoAddr.Protocol)
	}
}
