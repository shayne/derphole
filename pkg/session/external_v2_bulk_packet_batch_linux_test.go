// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExternalV2BulkPacketLinuxBatchRoundTrip(t *testing.T) {
	receiverConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer receiverConn.Close()
	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	sender := newExternalV2BulkPacketBatchConn(senderConn)
	receiver := newExternalV2BulkPacketBatchConn(receiverConn)

	const packetCount = 32
	messages := make([]externalV2BulkPacketBatchMessage, packetCount)
	want := make(map[string]struct{}, packetCount)
	for index := range messages {
		payload := []byte(fmt.Sprintf("packet-%02d-%s", index, string(make([]byte, 96))))
		messages[index] = externalV2BulkPacketBatchMessage{Buffers: [][]byte{payload}, Addr: receiverConn.LocalAddr()}
		want[string(payload)] = struct{}{}
	}
	if err := writeExternalV2BulkPacketBatchAll(context.Background(), sender, messages); err != nil {
		t.Fatal(err)
	}

	readMessages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range readMessages {
		readMessages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
		readMessages[index].OOB = make([]byte, unix.CmsgSpace(2))
	}
	for len(want) > 0 {
		count, err := receiver.ReadBatch(context.Background(), readMessages)
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < count; index++ {
			payload := string(readMessages[index].Buffers[0][:readMessages[index].N])
			if _, ok := want[payload]; !ok {
				t.Fatalf("unexpected or duplicate payload %q", payload)
			}
			delete(want, payload)
		}
	}

	sendStats := sender.Stats()
	receiveStats := receiver.Stats()
	if sendStats.Backend != "linux-gso" && sendStats.Backend != "linux-sendmmsg" {
		t.Fatalf("send backend = %q", sendStats.Backend)
	}
	if sendStats.SendDatagrams != packetCount || sendStats.MaxSendBatch == 0 {
		t.Fatalf("send stats = %+v", sendStats)
	}
	if receiveStats.Backend != "linux-recvmmsg" || receiveStats.ReceiveDatagrams != packetCount || receiveStats.MaxReceiveBatch == 0 {
		t.Fatalf("receive stats = %+v", receiveStats)
	}
}

func TestExternalV2BulkPacketLinuxBatchDoesNotEnableUDPGRO(t *testing.T) {
	conn := listenExternalV2BulkPacketLinuxUDP(t)
	defer conn.Close()
	_ = newExternalV2BulkPacketBatchConn(conn)
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	gro := -1
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		gro, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	if gro != 0 {
		t.Fatalf("UDP_GRO = %d, want disabled", gro)
	}
}

func TestExternalV2BulkPacketLinuxBatchReadHonorsCancellation(t *testing.T) {
	conn := listenExternalV2BulkPacketLinuxUDP(t)
	defer conn.Close()
	batch := newExternalV2BulkPacketBatchConn(conn)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := batch.ReadBatch(ctx, []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{make([]byte, externalV2BulkPacketMaxSize)}}})
		result <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("recvmmsg did not return after cancellation")
	}
}

func TestExternalV2BulkPacketLinuxGSOControlMessage(t *testing.T) {
	control := make([]byte, 0, unix.CmsgSpace(2))
	externalV2BulkPacketSetGSOSize(&control, 1400)
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Header.Level != unix.SOL_UDP || messages[0].Header.Type != unix.UDP_SEGMENT {
		t.Fatalf("control messages = %+v", messages)
	}
	if got := binary.NativeEndian.Uint16(messages[0].Data); got != 1400 {
		t.Fatalf("GSO size = %d, want 1400", got)
	}
}

func listenExternalV2BulkPacketLinuxUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

var _ syscall.Conn = (*net.UDPConn)(nil)
