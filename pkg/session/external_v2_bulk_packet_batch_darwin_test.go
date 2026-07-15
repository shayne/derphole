// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package session

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketDarwinReceiveBatchUsesRecvmsgX(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	const packetCount = 32
	for index := range packetCount {
		payload := []byte(fmt.Sprintf("packet-%02d", index))
		if _, err := senderConn.WriteTo(payload, receiverConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
	}
	receiver := newExternalV2BulkPacketBatchConn(receiverConn)
	count, err := receiver.ReadBatch(context.Background(), messages)
	if err != nil {
		t.Fatal(err)
	}
	if count <= 1 {
		t.Fatalf("recvmsg_x batch count = %d, want more than one queued datagram", count)
	}
	stats := receiver.Stats()
	if stats.Backend != "darwin-recvmsg-x" || stats.ReceiveCalls != 1 || stats.ReceiveDatagrams != uint64(count) || stats.MaxReceiveBatch != uint32(count) {
		t.Fatalf("receive stats = %+v", stats)
	}
}

func TestExternalV2BulkPacketDarwinReceiveCoalescingBatchesAndDrainsTail(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	receiver := newExternalV2BulkPacketBatchConn(receiverConn)
	enableExternalV2BulkPacketReceiveCoalescing(receiver)
	darwinReceiver, ok := receiver.(*externalV2BulkPacketDarwinBatchConn)
	if !ok || !darwinReceiver.receiveCoalescing {
		t.Fatal("Darwin receive coalescing was not enabled")
	}

	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
	}

	const packetCount = 16
	payload := make([]byte, externalV2BulkPacketMaxSize)
	darwinReceiver.receiveCoalesceDelay = 50 * time.Millisecond
	type readResult struct {
		count int
		err   error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		count, err := receiver.ReadBatch(context.Background(), messages)
		resultCh <- readResult{count: count, err: err}
	}()
	if _, err := senderConn.WriteTo(payload, receiverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-resultCh:
		t.Fatalf("coalesced read returned early with count=%d err=%v", result.count, result.err)
	case <-time.After(5 * time.Millisecond):
	}
	for range packetCount - 1 {
		if _, err := senderConn.WriteTo(payload, receiverConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	var result readResult
	select {
	case result = <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("coalesced read did not return after reaching its low water")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.count < packetCount {
		t.Fatalf("coalesced batch = %d, want at least %d", result.count, packetCount)
	}

	darwinReceiver.receiveCoalesceDelay = externalV2BulkPacketDarwinReceiveCoalesceDelay
	if _, err := senderConn.WriteTo(payload, receiverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	count, err := receiver.ReadBatch(context.Background(), messages)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("tail batch = %d, want 1", count)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Millisecond {
		t.Fatalf("tail drain took %s, want at most 20ms", elapsed)
	}
}

func TestExternalV2BulkPacketDarwinSendmsgXWritesBatch(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	const packetCount = 32
	messages := make([]externalV2BulkPacketBatchMessage, packetCount)
	for index := range messages {
		messages[index] = externalV2BulkPacketBatchMessage{
			Buffers: [][]byte{{byte(index), 0xaa}},
			Addr:    receiverConn.LocalAddr(),
		}
	}
	sender := newExternalV2BulkPacketBatchConn(senderConn)
	if err := enableExternalV2BulkPacketFixedPeerConnect(sender, receiverConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	darwinSender, ok := sender.(*externalV2BulkPacketDarwinBatchConn)
	if !ok || darwinSender.fixedPeer == nil || darwinSender.fixedPeer.String() != receiverConn.LocalAddr().String() {
		t.Fatalf("Darwin fixed peer = %v, want %v", darwinSender.fixedPeer, receiverConn.LocalAddr())
	}
	if darwinSender.connectAttempted || darwinSender.connected {
		t.Fatal("Darwin fixed peer connected before the first batch write")
	}
	written, err := sender.WriteBatch(context.Background(), messages)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(messages) {
		t.Fatalf("written = %d, want %d", written, len(messages))
	}
	if !ok || !darwinSender.connected {
		t.Fatal("Darwin batch sender did not connect its fixed-peer UDP socket")
	}
	for index := range messages {
		if darwinSender.headers[index].Name != nil || darwinSender.headers[index].NameLen != 0 {
			t.Fatalf("message %d retained a destination on a connected socket", index)
		}
	}
	seen := make([]bool, packetCount)
	buffer := make([]byte, 16)
	for range packetCount {
		if err := receiverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := receiverConn.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 || int(buffer[0]) >= packetCount || buffer[1] != 0xaa {
			t.Fatalf("unexpected datagram %x", buffer[:n])
		}
		seen[buffer[0]] = true
	}
	for index, ok := range seen {
		if !ok {
			t.Fatalf("datagram %d missing", index)
		}
	}
	spareReceiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spareReceiver.Close()
	spareSender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spareSender.Close()
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	controlPath := externalV2BulkPacketPath{
		Conns: []net.PacketConn{senderConn, spareSender},
		Addrs: []net.Addr{receiverConn.LocalAddr(), spareReceiver.LocalAddr()},
	}
	if err := writeExternalV2BulkPacketControl(controlPath, auth, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketHello, runID: 9, index: 1, total: 1,
	}, nil); err != nil {
		t.Fatalf("control write with a spare unconnected lane: %v", err)
	}
	if err := spareReceiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := spareReceiver.ReadFrom(buffer); err != nil || n == 0 {
		t.Fatalf("control datagram on spare lane: n=%d err=%v", n, err)
	}
	stats := sender.Stats()
	if stats.Backend != "darwin-sendmsg-x" || stats.SendCalls != 1 || stats.SendDatagrams != packetCount {
		t.Fatalf("send stats = %+v", stats)
	}
}

func TestExternalV2BulkPacketDarwinConnectSockaddr(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		addr net.Addr
		ok   bool
		v4   bool
	}{
		{name: "nil"},
		{name: "negative port", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: -1}},
		{name: "oversized port", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1 << 16}},
		{name: "invalid IP", addr: &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 8123}},
		{name: "invalid zone", addr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 8123, Zone: "missing-interface"}},
		{name: "IPv4", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123}, ok: true, v4: true},
		{name: "IPv6", addr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 8123}, ok: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sockaddr, ok := externalV2BulkPacketDarwinConnectSockaddr(tt.addr)
			if ok != tt.ok {
				t.Fatalf("ok = %t, want %t (sockaddr=%#v)", ok, tt.ok, sockaddr)
			}
			if !ok {
				return
			}
			if tt.v4 {
				if got, typeOK := sockaddr.(*unix.SockaddrInet4); !typeOK || got.Port != 8123 || got.Addr != [4]byte{127, 0, 0, 1} {
					t.Fatalf("IPv4 sockaddr = %#v", sockaddr)
				}
				return
			}
			if got, typeOK := sockaddr.(*unix.SockaddrInet6); !typeOK || got.Port != 8123 || got.Addr != [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} {
				t.Fatalf("IPv6 sockaddr = %#v", sockaddr)
			}
		})
	}
}
