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
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

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
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	headers, groupEnds, err := externalV2BulkPacketPrepareLinuxAddressedGSO(messages, 3, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(headers), 15; got != want {
		t.Fatalf("GSO groups = %d, want %d", got, want)
	}
	for index := range headers {
		if got, want := int(headers[index].hdr.Iovlen), 3; got != want {
			t.Fatalf("GSO group %d segments = %d, want %d", index, got, want)
		}
		if headers[index].hdr.Name == nil || headers[index].hdr.Namelen != unix.SizeofSockaddrInet4 {
			t.Fatalf("GSO group %d name = %p/%d, want IPv4 sockaddr", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
		}
		controlBytes := unsafe.Slice(headers[index].hdr.Control, int(headers[index].hdr.Controllen))
		control, err := unix.ParseSocketControlMessage(controlBytes)
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

func TestExternalV2BulkPacketLinuxConnectedGSOCandidates(t *testing.T) {
	for _, segments := range []int{1, 2, 3, 4, 6, 8, 12} {
		t.Run(strconv.Itoa(segments), func(t *testing.T) {
			messages := externalV2BulkPacketLinuxGSOSendTestMessages(45, 1400, 1400)
			scratch := new(externalV2BulkPacketLinuxSendScratch)
			headers, ends, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, segments, scratch)
			if err != nil || len(headers) != (45+segments-1)/segments || len(ends) != len(headers) || ends[len(ends)-1] != 45 {
				t.Fatalf("headers=%d ends=%v error=%v", len(headers), ends, err)
			}
			for index := range headers {
				if headers[index].hdr.Name != nil || headers[index].hdr.Namelen != 0 {
					t.Fatalf("header %d name = %p/%d, want nil/0", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
				}
				wantSegments := min(segments, 45-index*segments)
				if got := int(headers[index].hdr.Iovlen); got != wantSegments {
					t.Fatalf("header %d iovecs = %d, want %d", index, got, wantSegments)
				}
				if segments == 1 {
					if headers[index].hdr.Control != nil || headers[index].hdr.Controllen != 0 {
						t.Fatalf("non-GSO header %d has control data", index)
					}
					continue
				}
				control := unsafe.Slice(headers[index].hdr.Control, int(headers[index].hdr.Controllen))
				controlMessages, parseErr := unix.ParseSocketControlMessage(control)
				if parseErr != nil || len(controlMessages) != 1 {
					t.Fatalf("header %d control = %+v, error %v", index, controlMessages, parseErr)
				}
				if controlMessages[0].Header.Level != unix.SOL_UDP || controlMessages[0].Header.Type != unix.UDP_SEGMENT {
					t.Fatalf("header %d control header = %+v", index, controlMessages[0].Header)
				}
				if got := binary.NativeEndian.Uint16(controlMessages[0].Data); got != 1400 {
					t.Fatalf("header %d segment size = %d, want 1400", index, got)
				}
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSOAllowsOnlyShortFinalSegment(t *testing.T) {
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(5, 1400, 713)
	headers, ends, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 3, newExternalV2BulkPacketLinuxSendScratch())
	if err != nil || len(headers) != 2 || fmt.Sprint(ends) != fmt.Sprint([]int{3, 5}) {
		t.Fatalf("headers=%d ends=%v error=%v", len(headers), ends, err)
	}
	secondIovecs := unsafe.Slice(headers[1].hdr.Iov, int(headers[1].hdr.Iovlen))
	if len(secondIovecs) != 2 || secondIovecs[0].Len != 1400 || secondIovecs[1].Len != 713 {
		t.Fatalf("final GSO iovecs = %+v", secondIovecs)
	}

	for _, test := range []struct {
		name     string
		messages []externalV2BulkPacketBatchMessage
	}{
		{name: "short-before-final", messages: externalV2BulkPacketLinuxGSOSendTestMessages(5, 1400, 1400)},
		{name: "larger-final", messages: externalV2BulkPacketLinuxGSOSendTestMessages(5, 1400, 1500)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "short-before-final" {
				test.messages[2].Buffers[0] = test.messages[2].Buffers[0][:713]
			}
			if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(test.messages, 3, newExternalV2BulkPacketLinuxSendScratch()); err == nil {
				t.Fatal("invalid segment order was accepted")
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSOMaximumBatchReusesScratch(t *testing.T) {
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(externalV2BulkPacketMaxBatch, 1400, 1400)
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 2, scratch); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(100, func() {
		headers, ends, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 2, scratch)
		if err != nil || len(headers) != externalV2BulkPacketMaxBatch/2 || ends[len(ends)-1] != externalV2BulkPacketMaxBatch {
			t.Fatalf("headers=%d ends=%v error=%v", len(headers), ends, err)
		}
	})
	if allocations != 0 {
		t.Fatalf("maximum connected GSO preparation allocations = %f, want 0", allocations)
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSORejectsUnboundedSegments(t *testing.T) {
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(4, 1400, 1400)
	for _, segments := range []int{-1, 0, 5, 7, 9, 11, 13} {
		if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, segments, newExternalV2BulkPacketLinuxSendScratch()); err == nil {
			t.Fatalf("segment count %d was accepted", segments)
		}
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSOInvalidSegmentsClearReusedScratch(t *testing.T) {
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(45, 1400, 1400)
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	scratch.headers[100].len = 99
	scratch.iovecs[100].Len = 99
	scratch.groupEnds[100] = 99

	for _, segments := range []int{-1, 0, 5, 7, 9, 11, 13} {
		if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 12, scratch); err != nil {
			t.Fatal(err)
		}
		activeHeaders, activeIovecs := scratch.activeHeaders, scratch.activeIovecs
		if activeHeaders != 4 || activeIovecs != 45 {
			t.Fatalf("populated scratch = %d headers/%d iovecs, want 4/45", activeHeaders, activeIovecs)
		}

		if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, segments, scratch); err == nil {
			t.Fatalf("segment count %d was accepted", segments)
		}
		if scratch.activeHeaders != 0 || scratch.activeIovecs != 0 {
			t.Fatalf("invalid segment count %d retained active scratch = %d headers/%d iovecs", segments, scratch.activeHeaders, scratch.activeIovecs)
		}
		for index := range activeIovecs {
			if scratch.headers[index].hdr.Iov != nil || scratch.iovecs[index].Base != nil || scratch.groupEnds[index] != 0 {
				t.Fatalf("invalid segment count %d retained prior scratch slot %d", segments, index)
			}
		}
		if scratch.headers[100].len != 99 || scratch.iovecs[100].Len != 99 || scratch.groupEnds[100] != 99 {
			t.Fatalf("invalid segment count %d cleared scratch outside prior active ranges", segments)
		}
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSORejectClearsScratchPointers(t *testing.T) {
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(4, 1400, 1400)
	messages[2].Buffers = [][]byte{{1}, {2}}
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 3, scratch); err == nil {
		t.Fatal("connected GSO preparation accepted multiple buffers")
	}
	for index := range externalV2BulkPacketMaxBatch {
		if scratch.headers[index].hdr.Iov != nil || scratch.iovecs[index].Base != nil || scratch.groupEnds[index] != 0 {
			t.Fatalf("scratch %d retained stale payload state after GSO preparation failure", index)
		}
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSORejectsInvalidFirstMessageWithoutPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("connected GSO preparation panicked: %v", recovered)
		}
	}()
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(4, 1400, 1400)
	messages[0].Buffers = nil
	if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 3, newExternalV2BulkPacketLinuxSendScratch()); err == nil {
		t.Fatal("connected GSO preparation accepted an empty first message")
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSOScratchTracksHeaderAndIovecRanges(t *testing.T) {
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(45, 1400, 1400)
	if _, _, err := externalV2BulkPacketPrepareLinuxConnectedGSO(messages, 12, scratch); err != nil {
		t.Fatal(err)
	}
	if scratch.activeHeaders != 4 || scratch.activeIovecs != 45 {
		t.Fatalf("active scratch = %d headers/%d iovecs, want 4/45", scratch.activeHeaders, scratch.activeIovecs)
	}

	scratch.headers[100].len = 99
	scratch.iovecs[100].Len = 99
	if _, err := externalV2BulkPacketPrepareLinuxConnectedSend(externalV2BulkPacketLinuxSendTestMessages(2), scratch); err != nil {
		t.Fatal(err)
	}
	if scratch.activeHeaders != 2 || scratch.activeIovecs != 2 {
		t.Fatalf("active scratch after non-GSO = %d headers/%d iovecs, want 2/2", scratch.activeHeaders, scratch.activeIovecs)
	}
	for index := 2; index < 45; index++ {
		if scratch.headers[index].hdr.Iov != nil || scratch.iovecs[index].Base != nil || scratch.groupEnds[index] != 0 {
			t.Fatalf("prior active scratch %d was not cleared", index)
		}
	}
	if scratch.headers[100].len != 99 || scratch.iovecs[100].Len != 99 {
		t.Fatal("scratch reset cleared slots outside the prior active ranges")
	}
}

func externalV2BulkPacketLinuxGSOSendTestMessages(count, segmentSize, finalSize int) []externalV2BulkPacketBatchMessage {
	messages := make([]externalV2BulkPacketBatchMessage, count)
	for index := range messages {
		size := segmentSize
		if index == len(messages)-1 {
			size = finalSize
		}
		payload := make([]byte, size)
		payload[0] = byte(index)
		messages[index].Buffers = [][]byte{payload}
	}
	return messages
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
