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
	"sync/atomic"
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
			if readMessages[index].Addr != nil || readMessages[index].NN != 0 {
				t.Fatalf("connected receive unpacked unused source metadata: addr=%v oob=%d", readMessages[index].Addr, readMessages[index].NN)
			}
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

func TestExternalV2BulkPacketLinuxPrepareReadReusesScratch(t *testing.T) {
	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
	}
	var headers [externalV2BulkPacketMaxBatch]externalV2BulkPacketMMsgHdr
	var iovecs [externalV2BulkPacketMaxBatch]unix.Iovec
	allocations := testing.AllocsPerRun(100, func() {
		prepared, preparedHeaders, err := externalV2BulkPacketPrepareRead(messages, headers[:], iovecs[:])
		if err != nil || len(prepared) != len(messages) || len(preparedHeaders) != len(messages) {
			t.Fatalf("prepare read = %d/%d, error %v", len(prepared), len(preparedHeaders), err)
		}
	})
	if allocations != 0 {
		t.Fatalf("prepare-read allocations = %f, want 0", allocations)
	}
}

func TestExternalV2BulkPacketLinuxBatchReusesReadDeadlineAcrossSuccess(t *testing.T) {
	receiverUDP := listenExternalV2BulkPacketLinuxUDP(t)
	receiverConn := &readDeadlineRecordingLinuxUDPConn{UDPConn: receiverUDP}
	defer receiverConn.Close()
	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	receiver := newExternalV2BulkPacketBatchConn(receiverConn)
	message := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{make([]byte, externalV2BulkPacketMaxSize)}}}
	for index := range 3 {
		if _, err := senderConn.WriteToUDP([]byte{byte(index)}, receiverUDP.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		if count, err := receiver.ReadBatch(context.Background(), message); err != nil || count != 1 {
			t.Fatalf("read %d = %d, error %v", index, count, err)
		}
	}
	if got := receiverConn.nonzeroReadDeadlines.Load(); got != 1 {
		t.Fatalf("nonzero read deadlines = %d, want 1", got)
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

func TestExternalV2BulkPacketLinuxGSOLimitsQdiscDropAmplification(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 8123}
	messages := make([]externalV2BulkPacketBatchMessage, 45)
	for index := range messages {
		messages[index] = externalV2BulkPacketBatchMessage{
			Buffers: [][]byte{make([]byte, 1400)},
			Addr:    addr,
		}
	}
	var scratch externalV2BulkPacketLinuxGSOScratch
	groups, groupEnds := externalV2BulkPacketPrepareLinuxGSOGroups(messages, &scratch)
	if got, want := len(groups), 15; got != want {
		t.Fatalf("GSO groups = %d, want %d", got, want)
	}
	for index := range groups {
		if got, want := len(groups[index].Buffers), 3; got != want {
			t.Fatalf("GSO group %d segments = %d, want %d", index, got, want)
		}
		if groups[index].Addr.String() != addr.String() {
			t.Fatalf("GSO group %d addr = %v, want %v", index, groups[index].Addr, addr)
		}
		control, err := unix.ParseSocketControlMessage(groups[index].OOB)
		if err != nil || len(control) != 1 {
			t.Fatalf("GSO group %d control = %+v, error %v", index, control, err)
		}
		if got := binary.NativeEndian.Uint16(control[0].Data); got != 1400 {
			t.Fatalf("GSO group %d size = %d, want 1400", index, got)
		}
		if got, want := groupEnds[index], (index+1)*3; got != want {
			t.Fatalf("GSO group %d logical end = %d, want %d", index, got, want)
		}
	}
}

func TestExternalV2BulkPacketLinuxGSOWrittenMapsPartialGroups(t *testing.T) {
	groupEnds := []int{12, 24, 36, 45}
	for _, test := range []struct {
		groups int
		want   int
	}{
		{groups: 0, want: 0},
		{groups: 1, want: 12},
		{groups: 2, want: 24},
		{groups: 4, want: 45},
	} {
		if got := externalV2BulkPacketLinuxGSOWritten(test.groups, groupEnds); got != test.want {
			t.Fatalf("%d written GSO groups = %d logical packets, want %d", test.groups, got, test.want)
		}
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

type readDeadlineRecordingLinuxUDPConn struct {
	*net.UDPConn
	nonzeroReadDeadlines atomic.Int32
}

func (c *readDeadlineRecordingLinuxUDPConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.nonzeroReadDeadlines.Add(1)
	}
	return c.UDPConn.SetReadDeadline(deadline)
}

var _ syscall.Conn = (*net.UDPConn)(nil)
