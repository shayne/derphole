// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestExternalV2BulkPacketLinuxConnectedSendMMsgRoundTrip(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "connected-gso3")

	receiver := listenExternalV2BulkPacketLinuxUDP(t)
	defer receiver.Close()
	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	sender := newExternalV2BulkPacketBatchConn(senderConn).(*externalV2BulkPacketLinuxBatchConn)
	if err := sender.enableFixedPeerConnect(receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	systemSendMMsg := sender.sendMMsg
	sendMMsgCalls := 0
	sender.sendMMsg = func(fd uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		sendMMsgCalls++
		for index := range headers {
			if headers[index].hdr.Name != nil || headers[index].hdr.Namelen != 0 {
				t.Fatalf("round-trip header %d name = %p/%d, want nil/0", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
			}
		}
		return systemSendMMsg(fd, headers)
	}

	messages := make([]externalV2BulkPacketBatchMessage, 4)
	for index := range messages {
		messages[index] = externalV2BulkPacketBatchMessage{
			Buffers: [][]byte{[]byte(fmt.Sprintf("connected-%d", index))},
			Addr:    receiver.LocalAddr(),
		}
	}
	if err := writeExternalV2BulkPacketBatchAll(context.Background(), sender, messages); err != nil {
		t.Fatal(err)
	}
	if sendMMsgCalls == 0 {
		t.Fatal("connected round trip did not use raw sendmmsg")
	}

	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	for index := range messages {
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("connected-%d", index)
		if got := string(buffer[:n]); got != want {
			t.Fatalf("datagram %d = %q, want %q", index, got, want)
		}
		if messages[index].N != len(want) {
			t.Fatalf("message %d N = %d, want %d", index, messages[index].N, len(want))
		}
	}
}

func TestExternalV2BulkPacketLinuxAddressedSendMMsgCountsEveryRawCallback(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 8123}
	messages := externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 10, 20, 30)
	batch := externalV2BulkPacketLinuxAddressedSendTestBatch(t)
	calls := 0
	batch.sendMMsg = func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		for index := range headers {
			if headers[index].hdr.Name == nil || headers[index].hdr.Namelen == 0 {
				t.Fatalf("addressed header %d name = %p/%d, want socket address", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
			}
		}
		stats := batch.stats.snapshot()
		if stats.NativeSendAttempts != uint64(calls+1) || stats.NativeSendSyscalls != uint64(calls) {
			t.Fatalf("callback %d stats = attempts %d syscalls %d, want %d/%d", calls, stats.NativeSendAttempts, stats.NativeSendSyscalls, calls+1, calls)
		}
		calls++
		if calls == 1 {
			return 0, unix.EAGAIN
		}
		return len(headers), 0
	}

	written, err := batch.writePreparedBatch(messages)
	if err != nil || written != len(messages) {
		t.Fatalf("addressed write = %d, error %v, want %d/nil", written, err, len(messages))
	}
	stats := batch.stats.snapshot()
	if calls != 2 || stats.NativeSendAttempts != 2 || stats.NativeSendSyscalls != 2 {
		t.Fatalf("native callbacks = calls %d attempts %d syscalls %d, want 2/2/2", calls, stats.NativeSendAttempts, stats.NativeSendSyscalls)
	}
	if stats.LogicalDatagrams != 3 || stats.NativeAcceptedPayloadBytes != 60 {
		t.Fatalf("accepted = datagrams %d payload %d, want 3/60", stats.LogicalDatagrams, stats.NativeAcceptedPayloadBytes)
	}
}

func TestExternalV2BulkPacketLinuxAddressedSendMMsgMapsPartialLogicalPrefix(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 11), Port: 8123}
	messages := externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 11, 13, 17)
	batch := externalV2BulkPacketLinuxAddressedSendTestBatch(t)
	batch.sendMMsg = func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		return 2, 0
	}

	written, err := batch.writePreparedBatch(messages)
	if err != nil || written != 2 {
		t.Fatalf("addressed partial write = %d, error %v, want 2/nil", written, err)
	}
	stats := batch.stats.snapshot()
	if stats.LogicalDatagrams != 2 || stats.NativeAcceptedPayloadBytes != 24 {
		t.Fatalf("accepted prefix = datagrams %d payload %d, want 2/24", stats.LogicalDatagrams, stats.NativeAcceptedPayloadBytes)
	}
	for index, message := range messages {
		want := 0
		if index < 2 {
			want = len(message.Buffers[0])
		}
		if message.N != want {
			t.Fatalf("message %d N = %d, want %d", index, message.N, want)
		}
	}
}

func TestExternalV2BulkPacketLinuxAddressedGSOFallbackCountsBothNativeSyscalls(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 12), Port: 8123}
	messages := externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 1400, 1400, 1400)
	batch := externalV2BulkPacketLinuxAddressedSendTestBatch(t)
	batch.gsoCapable.Store(true)
	calls := 0
	batch.sendMMsg = func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		calls++
		if calls == 1 {
			if headers[0].hdr.Control == nil || headers[0].hdr.Controllen == 0 {
				t.Fatal("first addressed send did not carry UDP GSO control")
			}
			return 0, unix.EOPNOTSUPP
		}
		for index := range headers {
			if headers[index].hdr.Control != nil || headers[index].hdr.Controllen != 0 {
				t.Fatalf("fallback header %d retained GSO control", index)
			}
		}
		return len(headers), 0
	}

	written, err := batch.writePreparedBatch(messages)
	if err != nil || written != len(messages) {
		t.Fatalf("addressed GSO fallback = %d, error %v, want %d/nil", written, err, len(messages))
	}
	stats := batch.stats.snapshot()
	if calls != 2 || stats.NativeSendAttempts != 2 || stats.NativeSendSyscalls != 2 {
		t.Fatalf("native fallback = calls %d attempts %d syscalls %d, want 2/2/2", calls, stats.NativeSendAttempts, stats.NativeSendSyscalls)
	}
	if stats.NativeGSOMessages != 0 || stats.LogicalDatagrams != 3 || stats.NativeAcceptedPayloadBytes != 4200 {
		t.Fatalf("fallback accepted = GSO %d datagrams %d payload %d, want 0/3/4200", stats.NativeGSOMessages, stats.LogicalDatagrams, stats.NativeAcceptedPayloadBytes)
	}
}

func TestExternalV2BulkPacketLinuxAddressedGSOErrorClearsOnlyActiveScratch(t *testing.T) {
	validAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 13), Port: 8123}
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	valid := externalV2BulkPacketLinuxAddressedSendTestMessages(validAddr, 1400, 1400, 1400)
	if _, _, err := externalV2BulkPacketPrepareLinuxAddressedGSO(valid, 2, scratch); err != nil {
		t.Fatal(err)
	}

	sentinel := byte(0x7f)
	scratch.headers[3].len = 99
	scratch.iovecs[3].Base = &sentinel
	scratch.sockaddrs[3].Family = unix.AF_INET6
	invalid := externalV2BulkPacketLinuxAddressedSendTestMessages(validAddr, 1400, 1400, 1400)
	invalid[2].Addr = &net.IPAddr{IP: net.IPv4(203, 0, 113, 14)}
	if _, _, err := externalV2BulkPacketPrepareLinuxAddressedGSO(invalid, 2, scratch); err == nil {
		t.Fatal("addressed GSO preparation accepted a non-UDP destination")
	}
	for index := range 3 {
		if scratch.headers[index].hdr.Iov != nil || scratch.headers[index].hdr.Name != nil || scratch.iovecs[index].Base != nil || scratch.sockaddrs[index].Family != 0 {
			t.Fatalf("scratch %d retained active payload or address state after preparation error", index)
		}
	}
	if scratch.headers[3].len != 99 || scratch.iovecs[3].Base != &sentinel || scratch.sockaddrs[3].Family != unix.AF_INET6 {
		t.Fatal("addressed GSO error reset out-of-range scratch sentinel")
	}
}

func TestExternalV2BulkPacketLinuxAddressedSendMMsgSerializesPrimaryAndRepairWriters(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 15), Port: 8123}
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	batch := externalV2BulkPacketLinuxAddressedSendTestBatch(t)
	batch.conn = &externalV2BulkPacketLinuxWriteDeadlineConn{}
	batch.rawConn = externalV2BulkPacketLinuxConcurrentWriteRawConn{}
	batch.sendMMsg = func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		inFlight := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maxActive.Load()
			if inFlight <= observed || maxActive.CompareAndSwap(observed, inFlight) {
				break
			}
		}
		if len(headers) != 1 || headers[0].hdr.Name == nil || headers[0].hdr.Namelen == 0 {
			return 0, unix.EINVAL
		}
		switch calls.Add(1) {
		case 1:
			close(firstEntered)
		case 2:
			close(secondEntered)
		}
		<-release
		return 1, 0
	}

	type result struct {
		written int
		err     error
	}
	primaryResult := make(chan result, 1)
	repairResult := make(chan result, 1)
	primary := externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 7)
	repair := externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 6)
	go func() {
		written, err := batch.WriteBatch(context.Background(), primary)
		primaryResult <- result{written: written, err: err}
	}()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("addressed primary did not enter sendmmsg")
	}
	go func() {
		written, err := batch.WriteBatch(context.Background(), repair)
		repairResult <- result{written: written, err: err}
	}()
	select {
	case <-secondEntered:
		t.Fatal("addressed repair entered shared send scratch concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for name, resultCh := range map[string]<-chan result{"primary": primaryResult, "repair": repairResult} {
		select {
		case got := <-resultCh:
			if got.written != 1 || got.err != nil {
				t.Fatalf("%s addressed write = %d, error %v, want 1/nil", name, got.written, got.err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s addressed write did not finish", name)
		}
	}
	if maxActive.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("addressed send concurrency/calls = %d/%d, want 1/2", maxActive.Load(), calls.Load())
	}
}

func TestExternalV2BulkPacketLinuxAddressedSendMMsgQueuedWriterHonorsCancellation(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 16), Port: 8123}
	batch := externalV2BulkPacketLinuxAddressedSendTestBatch(t)
	batch.conn = &externalV2BulkPacketLinuxWriteDeadlineConn{}
	if err := batch.acquireConnectedWriteGate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := batch.WriteBatch(ctx, externalV2BulkPacketLinuxAddressedSendTestMessages(addr, 7))
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued addressed write error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued addressed write ignored cancellation while waiting for shared scratch")
	}
	batch.releaseConnectedWriteGate()
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgUsesNilNames(t *testing.T) {
	messages := externalV2BulkPacketLinuxSendTestMessages(3)
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	wantControl := externalV2BulkPacketMaxBatch * unix.CmsgSpace(2)
	if cap(scratch.control) != wantControl {
		t.Fatalf("control capacity = %d, want %d", cap(scratch.control), wantControl)
	}
	allocations := testing.AllocsPerRun(100, func() {
		headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
		if err != nil || len(headers) != len(messages) {
			t.Fatalf("prepare connected send = %d headers, error %v", len(headers), err)
		}
	})
	if allocations != 0 {
		t.Fatalf("prepare connected-send allocations = %f, want 0", allocations)
	}
	headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
	if err != nil {
		t.Fatal(err)
	}

	raw := &externalV2BulkPacketLinuxWriteRawConn{}
	stats := newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg")
	send := externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{{written: len(headers)}})
	written, err := externalV2BulkPacketSendMMsg(raw, headers, func(fd uintptr, got []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		if !raw.inCallback {
			t.Fatal("sendmmsg syscall ran outside RawConn.Write callback")
		}
		if snapshot := stats.snapshot(); snapshot.NativeSendAttempts != 1 || snapshot.NativeSendSyscalls != 0 {
			t.Fatalf("native callback boundary = attempts %d syscalls %d, want 1/0 before syscall", snapshot.NativeSendAttempts, snapshot.NativeSendSyscalls)
		}
		return send(fd, got)
	}, stats)
	if err != nil || written != len(messages) {
		t.Fatalf("sendmmsg = %d, error %v", written, err)
	}

	invalid := externalV2BulkPacketLinuxSendTestMessages(3)
	invalid[1].Buffers = [][]byte{{1}, {2}}
	if _, err := externalV2BulkPacketPrepareLinuxConnectedSend(invalid, scratch); err == nil {
		t.Fatal("connected send accepted multiple buffers")
	}
	for index := range 3 {
		if scratch.headers[index].hdr.Iov != nil || scratch.iovecs[index].Base != nil || scratch.groupEnds[index] != 0 {
			t.Fatalf("scratch %d retained stale payload state after preparation failure", index)
		}
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgResumesAfterPartial(t *testing.T) {
	starts := make([]byte, 0, 2)
	batch := externalV2BulkPacketLinuxConnectedSendTestBatch(t, []externalV2BulkPacketLinuxSendResult{
		{written: 2},
		{written: 2},
	}, &starts)
	messages := externalV2BulkPacketLinuxSendTestMessages(4)

	if err := writeExternalV2BulkPacketBatchAll(context.Background(), batch, messages); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(starts) != fmt.Sprint([]byte{0, 2}) {
		t.Fatalf("send starts = %v, want [0 2]", starts)
	}
	for index := range messages {
		if messages[index].N != 1 {
			t.Fatalf("message %d N = %d, want 1", index, messages[index].N)
		}
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgRetriesEAGAIN(t *testing.T) {
	messages := externalV2BulkPacketLinuxSendTestMessages(2)
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
	if err != nil {
		t.Fatal(err)
	}
	raw := &externalV2BulkPacketLinuxWriteRawConn{}
	send := externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{
		{errno: unix.EAGAIN},
		{written: len(headers)},
	})
	stats := newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg")
	written, err := externalV2BulkPacketSendMMsg(raw, headers, send, stats)
	if err != nil || written != len(headers) {
		t.Fatalf("sendmmsg = %d, error %v", written, err)
	}
	if snapshot := stats.snapshot(); snapshot.NativeSendAttempts != 2 || snapshot.NativeSendSyscalls != 2 || raw.callbackCalls != 2 {
		t.Fatalf("attempts = %d syscalls = %d callbacks = %d, want 2/2/2", snapshot.NativeSendAttempts, snapshot.NativeSendSyscalls, raw.callbackCalls)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgNativeTelemetryCountsAttemptsAndAcceptedPrefix(t *testing.T) {
	batch := externalV2BulkPacketLinuxConnectedSendTestBatch(t, []externalV2BulkPacketLinuxSendResult{
		{errno: unix.EAGAIN},
		{written: 2, errno: unix.ENOBUFS},
	}, nil)
	messages := externalV2BulkPacketLinuxSendTestMessages(3)
	messages[0].PayloadBytes = 11
	messages[1].PayloadBytes = 13
	messages[2].PayloadBytes = 17

	written, err := batch.WriteBatch(context.Background(), messages)
	if written != 2 || !errors.Is(err, unix.ENOBUFS) {
		t.Fatalf("WriteBatch = %d, error %v, want 2/ENOBUFS", written, err)
	}
	stats := batch.Stats()
	if stats.NativeSendAttempts != 2 || stats.NativeSendSyscalls != 2 {
		t.Fatalf("native attempts/syscalls = %d/%d, want 2/2", stats.NativeSendAttempts, stats.NativeSendSyscalls)
	}
	if stats.NativeGSOMessages != 0 || stats.LogicalDatagrams != 2 || stats.NativeAcceptedPayloadBytes != 24 {
		t.Fatalf("native accepted stats = %+v, want 0 GSO messages, 2 datagrams, 24 payload bytes", stats)
	}
	if stats.GSOSegmentsPerMessage != 0 || stats.CandidateID != "combined-gso3" {
		t.Fatalf("native identity = segments %d candidate %q", stats.GSOSegmentsPerMessage, stats.CandidateID)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgReturnsENOBUFS(t *testing.T) {
	messages := externalV2BulkPacketLinuxSendTestMessages(3)
	scratch := newExternalV2BulkPacketLinuxSendScratch()
	headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
	if err != nil {
		t.Fatal(err)
	}
	rawWriteErr := errors.New("injected RawConn.Write error")
	raw := &externalV2BulkPacketLinuxWriteRawConn{writeErr: rawWriteErr}
	send := externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{{written: 1, errno: unix.ENOBUFS}})
	written, err := externalV2BulkPacketSendMMsg(raw, headers, send, nil)
	if written != 1 || !errors.Is(err, unix.ENOBUFS) || !errors.Is(err, rawWriteErr) {
		t.Fatalf("sendmmsg = %d, error %v, want partial count with ENOBUFS and RawConn error", written, err)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgHonorsDeadline(t *testing.T) {
	batch := externalV2BulkPacketLinuxConnectedSendTestBatch(t, []externalV2BulkPacketLinuxSendResult{{written: 1}}, nil)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	written, err := batch.WriteBatch(ctx, externalV2BulkPacketLinuxSendTestMessages(1))
	if written != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WriteBatch = %d, error %v, want 0/context deadline", written, err)
	}
	if batch.rawConn.(*externalV2BulkPacketLinuxWriteRawConn).callbackCalls != 0 {
		t.Fatal("expired deadline reached sendmmsg")
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgHonorsCancellation(t *testing.T) {
	deadlineConn := &externalV2BulkPacketLinuxWriteDeadlineConn{deadlineSet: make(chan struct{})}
	raw := &externalV2BulkPacketLinuxWriteRawConn{waitForWriteDeadline: deadlineConn.deadlineSet}
	attempted := make(chan struct{})
	var attemptedOnce sync.Once
	send := externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{{errno: unix.EAGAIN}})
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn:        deadlineConn,
		connected:   true,
		rawConn:     raw,
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg: func(fd uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
			attemptedOnce.Do(func() { close(attempted) })
			return send(fd, headers)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	batch.armConnectedWriteCancellation(ctx)
	allocations := testing.AllocsPerRun(100, func() {
		batch.armConnectedWriteCancellation(ctx)
	})
	if allocations != 0 {
		t.Fatalf("rearming unchanged cancellation context allocated %f times, want 0", allocations)
	}
	result := make(chan struct {
		written int
		err     error
	}, 1)
	go func() {
		written, err := batch.WriteBatch(ctx, externalV2BulkPacketLinuxSendTestMessages(1))
		result <- struct {
			written int
			err     error
		}{written: written, err: err}
	}()
	<-attempted
	cancel()
	got := <-result
	written, err := got.written, got.err
	if written != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteBatch = %d, error %v, want 0/context canceled", written, err)
	}
	if deadlineConn.nonzeroWriteDeadlines != 1 || raw.waitTimedOut {
		t.Fatalf("cancellation deadline wakeups = %d, raw wait timed out = %t", deadlineConn.nonzeroWriteDeadlines, raw.waitTimedOut)
	}
	replacement, cancelReplacement := context.WithCancel(context.Background())
	batch.armConnectedWriteCancellation(replacement)
	if deadlineConn.zeroWriteDeadlines != 1 {
		t.Fatalf("replacement context cleared %d deadlines, want 1", deadlineConn.zeroWriteDeadlines)
	}
	batch.armConnectedWriteCancellation(context.Background())
	cancelReplacement()
	if deadlineConn.nonzeroWriteDeadlines != 1 {
		t.Fatalf("stopped replacement context added a deadline wakeup: %d", deadlineConn.nonzeroWriteDeadlines)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgSerializesPrimaryAndRepairWriters(t *testing.T) {
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	primaryCtx, cancelPrimary := context.WithCancel(rootCtx)
	defer cancelPrimary()

	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	var payloadsMu sync.Mutex
	var payloads [][]byte
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn:        &externalV2BulkPacketLinuxWriteDeadlineConn{},
		connected:   true,
		rawConn:     externalV2BulkPacketLinuxConcurrentWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg: func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
			inFlight := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maxActive.Load()
				if inFlight <= observed || maxActive.CompareAndSwap(observed, inFlight) {
					break
				}
			}
			if len(headers) != 1 || headers[0].hdr.Name != nil || headers[0].hdr.Namelen != 0 || headers[0].hdr.Iov == nil {
				return 0, unix.EINVAL
			}
			payload := append([]byte(nil), unsafe.Slice(headers[0].hdr.Iov.Base, int(headers[0].hdr.Iov.Len))...)
			payloadsMu.Lock()
			payloads = append(payloads, payload)
			payloadsMu.Unlock()
			switch calls.Add(1) {
			case 1:
				close(firstEntered)
			case 2:
				close(secondEntered)
			}
			<-release
			return 1, 0
		},
	}

	type writeResult struct {
		written int
		err     error
	}
	primaryResult := make(chan writeResult, 1)
	repairResult := make(chan writeResult, 1)
	primaryMessages := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{[]byte("primary")}}}
	repairMessages := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{[]byte("repair")}}}
	go func() {
		written, err := batch.WriteBatch(primaryCtx, primaryMessages)
		primaryResult <- writeResult{written: written, err: err}
	}()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("primary writer did not reach sendmmsg")
	}
	go func() {
		written, err := batch.WriteBatch(rootCtx, repairMessages)
		repairResult <- writeResult{written: written, err: err}
	}()

	overlapped := false
	select {
	case <-secondEntered:
		overlapped = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for name, resultCh := range map[string]<-chan writeResult{
		"primary": primaryResult,
		"repair":  repairResult,
	} {
		select {
		case result := <-resultCh:
			if result.written != 1 || result.err != nil {
				t.Fatalf("%s WriteBatch = %d, error %v, want 1/nil", name, result.written, result.err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s WriteBatch did not return", name)
		}
	}
	batch.armConnectedWriteCancellation(context.Background())

	if overlapped || maxActive.Load() != 1 {
		t.Fatalf("connected sendmmsg max concurrent calls = %d, want 1", maxActive.Load())
	}
	payloadsMu.Lock()
	gotPayloads := fmt.Sprint(payloads)
	payloadsMu.Unlock()
	if want := fmt.Sprint([][]byte{[]byte("primary"), []byte("repair")}); gotPayloads != want {
		t.Fatalf("sendmmsg payloads = %s, want %s", gotPayloads, want)
	}
	if primaryMessages[0].N != len("primary") || repairMessages[0].N != len("repair") {
		t.Fatalf("message lengths = %d/%d, want %d/%d", primaryMessages[0].N, repairMessages[0].N, len("primary"), len("repair"))
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgQueuedPrimaryHonorsCancellation(t *testing.T) {
	parentCtx, cancelParent := context.WithCancel(context.Background())
	childCtx, cancelChild := context.WithCancel(parentCtx)
	defer cancelChild()
	defer cancelParent()

	repairEntered := make(chan struct{})
	releaseRepair := make(chan struct{})
	var calls atomic.Int32
	var gotPayload string
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn: &externalV2BulkPacketLinuxWriteDeadlineConn{
			deadlineSet: make(chan struct{}),
		},
		connected:   true,
		rawConn:     externalV2BulkPacketLinuxConcurrentWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg: func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
			if calls.Add(1) != 1 || len(headers) != 1 || headers[0].hdr.Iov == nil {
				return 0, unix.EINVAL
			}
			gotPayload = string(unsafe.Slice(headers[0].hdr.Iov.Base, int(headers[0].hdr.Iov.Len)))
			close(repairEntered)
			<-releaseRepair
			return 1, 0
		},
	}

	type writeResult struct {
		written int
		err     error
	}
	repairResult := make(chan writeResult, 1)
	primaryResult := make(chan writeResult, 1)
	repairMessages := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{[]byte("repair")}}}
	primaryMessages := []externalV2BulkPacketBatchMessage{{Buffers: [][]byte{[]byte("primary")}}}
	go func() {
		written, err := batch.WriteBatch(parentCtx, repairMessages)
		repairResult <- writeResult{written: written, err: err}
	}()
	select {
	case <-repairEntered:
	case <-time.After(time.Second):
		t.Fatal("repair writer did not reach sendmmsg")
	}
	go func() {
		written, err := batch.WriteBatch(childCtx, primaryMessages)
		primaryResult <- writeResult{written: written, err: err}
	}()
	cancelChild()

	primaryReturnedBeforeRelease := false
	var primary writeResult
	select {
	case primary = <-primaryResult:
		primaryReturnedBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseRepair)
	if !primaryReturnedBeforeRelease {
		select {
		case primary = <-primaryResult:
		case <-time.After(time.Second):
			t.Fatal("queued primary did not return after repair release")
		}
	}
	if primary.written != 0 || !errors.Is(primary.err, context.Canceled) {
		t.Fatalf("primary WriteBatch = %d, error %v, want 0/context canceled", primary.written, primary.err)
	}
	if !primaryReturnedBeforeRelease {
		t.Fatal("queued primary ignored cancellation until the repair released the connected send gate")
	}

	select {
	case repair := <-repairResult:
		if repair.written != 1 || repair.err != nil {
			t.Fatalf("repair WriteBatch = %d, error %v, want 1/nil", repair.written, repair.err)
		}
	case <-time.After(time.Second):
		t.Fatal("repair writer did not finish after release")
	}
	cancelParent()
	batch.disarmWriteCancellation()
	if calls.Load() != 1 || gotPayload != "repair" {
		t.Fatalf("sendmmsg calls/payload = %d/%q, want 1/repair", calls.Load(), gotPayload)
	}
	if repairMessages[0].N != len("repair") || primaryMessages[0].N != 0 {
		t.Fatalf("message lengths = repair %d, primary %d, want %d/0", repairMessages[0].N, primaryMessages[0].N, len("repair"))
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgGateDoesNotAllocatePerBatch(t *testing.T) {
	batch := &externalV2BulkPacketLinuxBatchConn{}
	allocations := testing.AllocsPerRun(100, func() {
		if err := batch.acquireConnectedWriteGate(context.Background()); err != nil {
			t.Fatal(err)
		}
		batch.releaseConnectedWriteGate()
	})
	if allocations != 0 {
		t.Fatalf("connected write gate allocations = %f, want 0", allocations)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgWritePathDoesNotAllocate(t *testing.T) {
	batch := externalV2BulkPacketLinuxConnectedAllocationTestBatch(1)
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(6, 1400, 1400)
	if written, err := batch.writePreparedBatch(messages); err != nil || written != len(messages) {
		t.Fatalf("prewarm connected sendmmsg write = %d, error %v, want %d/nil", written, err, len(messages))
	}
	allocations := testing.AllocsPerRun(100, func() {
		written, err := batch.writePreparedBatch(messages)
		if err != nil || written != len(messages) {
			t.Fatalf("connected sendmmsg write = %d, error %v, want %d/nil", written, err, len(messages))
		}
	})
	if allocations != 0 {
		t.Fatalf("connected sendmmsg write-path allocations = %f, want 0", allocations)
	}
}

func TestExternalV2BulkPacketLinuxConnectedGSOWritePathDoesNotAllocate(t *testing.T) {
	batch := externalV2BulkPacketLinuxConnectedAllocationTestBatch(3)
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(6, 1400, 1400)
	if written, err := batch.writePreparedBatch(messages); err != nil || written != len(messages) {
		t.Fatalf("prewarm connected GSO write = %d, error %v, want %d/nil", written, err, len(messages))
	}
	allocations := testing.AllocsPerRun(100, func() {
		written, err := batch.writePreparedBatch(messages)
		if err != nil || written != len(messages) {
			t.Fatalf("connected GSO write = %d, error %v, want %d/nil", written, err, len(messages))
		}
	})
	if allocations != 0 {
		t.Fatalf("connected GSO write-path allocations = %f, want 0", allocations)
	}
}

func externalV2BulkPacketLinuxConnectedAllocationTestBatch(segments int) *externalV2BulkPacketLinuxBatchConn {
	batch := &externalV2BulkPacketLinuxBatchConn{
		connected:   true,
		rawConn:     &externalV2BulkPacketLinuxWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg: func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
			return len(headers), 0
		},
		candidateConfig: externalV2BulkPacketCandidateConfig{
			NativeConnectedSend: true,
			GSOSegments:         segments,
		},
	}
	batch.gsoCapable.Store(segments > 1)
	return batch
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgDisarmWaitsBeforeFinalDeadlineClear(t *testing.T) {
	deadlineConn := &externalV2BulkPacketLinuxDelayedWriteDeadlineConn{
		callbackStarted: make(chan struct{}),
		releaseCallback: make(chan struct{}),
	}
	batch := &externalV2BulkPacketLinuxBatchConn{conn: deadlineConn, connected: true}
	ctx, cancel := context.WithCancel(context.Background())
	batch.armConnectedWriteCancellation(ctx)
	cancel()
	select {
	case <-deadlineConn.callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not start")
	}

	cleanupDone := make(chan error, 1)
	go func() {
		batchConns := []externalV2BulkPacketBatchConn{batch}
		disarmExternalV2BulkPacketWriteCancellations(batchConns)
		disarmExternalV2BulkPacketWriteCancellations(batchConns)
		cleanupDone <- clearExternalV2BulkPacketDeadlines(externalV2BulkPacketPath{
			Conns: []net.PacketConn{deadlineConn},
		})
	}()
	select {
	case err := <-cleanupDone:
		t.Fatalf("cleanup returned before cancellation callback completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(deadlineConn.releaseCallback)
	select {
	case err := <-cleanupDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not return after cancellation callback completed")
	}

	deadlines := deadlineConn.writeDeadlineHistory()
	if len(deadlines) != 2 || deadlines[0].IsZero() || !deadlines[1].IsZero() {
		t.Fatalf("write deadline history = %v, want [expired zero]", deadlines)
	}
}

func TestExternalV2BulkPacketLinuxConnectedSendMMsgRejectsZeroProgress(t *testing.T) {
	for _, test := range []struct {
		name           string
		written        int
		wantNoProgress bool
	}{
		{name: "zero", written: 0, wantNoProgress: true},
		{name: "negative", written: -1},
		{name: "oversized", written: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			messages := externalV2BulkPacketLinuxSendTestMessages(1)
			scratch := newExternalV2BulkPacketLinuxSendScratch()
			headers, err := externalV2BulkPacketPrepareLinuxConnectedSend(messages, scratch)
			if err != nil {
				t.Fatal(err)
			}
			raw := &externalV2BulkPacketLinuxWriteRawConn{}
			send := externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{{written: test.written}})
			written, err := externalV2BulkPacketSendMMsg(raw, headers, send, nil)
			if test.wantNoProgress {
				if written != 0 || !errors.Is(err, errExternalV2BulkPacketBatchNoProgress) {
					t.Fatalf("sendmmsg = %d, error %v, want no progress", written, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("sendmmsg accepted invalid count %d", test.written)
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxBatchFallsBackAddressedBeforeConnect(t *testing.T) {
	receiver := listenExternalV2BulkPacketLinuxUDP(t)
	defer receiver.Close()
	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	batch := newExternalV2BulkPacketBatchConn(senderConn).(*externalV2BulkPacketLinuxBatchConn)
	systemSendMMsg := batch.sendMMsg
	batch.sendMMsg = func(fd uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		for index := range headers {
			if headers[index].hdr.Name == nil || headers[index].hdr.Namelen == 0 {
				t.Fatalf("addressed header %d name = %p/%d, want destination", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
			}
		}
		return systemSendMMsg(fd, headers)
	}

	payload := []byte("addressed-before-connect")
	written, err := batch.WriteBatch(context.Background(), []externalV2BulkPacketBatchMessage{{
		Buffers: [][]byte{payload}, Addr: receiver.LocalAddr(),
	}})
	if err != nil || written != 1 {
		t.Fatalf("WriteBatch = %d, error %v", written, err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, _, err := receiver.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != string(payload) {
		t.Fatalf("addressed read = %q, error %v", buffer[:n], err)
	}
}

func TestExternalV2BulkPacketLinuxBatchFailsCleanlyAfterConnectedFatalError(t *testing.T) {
	useExternalV2BulkPacketCandidate(t, "connected-gso3")

	receiver := listenExternalV2BulkPacketLinuxUDP(t)
	defer receiver.Close()
	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	batch := newExternalV2BulkPacketBatchConn(senderConn).(*externalV2BulkPacketLinuxBatchConn)
	if err := batch.enableFixedPeerConnect(receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	batch.sendMMsg = externalV2BulkPacketLinuxInjectedSend(t, []externalV2BulkPacketLinuxSendResult{{errno: unix.EPERM}})
	payload := []byte("must-not-fall-back-addressed")
	written, err := batch.WriteBatch(context.Background(), []externalV2BulkPacketBatchMessage{{
		Buffers: [][]byte{payload}, Addr: receiver.LocalAddr(),
	}})
	if written != 0 || !errors.Is(err, unix.EPERM) {
		t.Fatalf("WriteBatch = %d, error %v, want 0/EPERM", written, err)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if n, _, err := receiver.ReadFromUDP(buffer); err == nil {
		t.Fatalf("fatal connected send fell back and delivered %q", buffer[:n])
	} else if networkErr, ok := err.(net.Error); !ok || !networkErr.Timeout() {
		t.Fatalf("read after fatal connected send = %v, want timeout", err)
	}
}

func TestExternalV2BulkPacketLinuxConfiguredGSOSegmentsOneUsesNonGSO(t *testing.T) {
	batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, 1, func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		for index := range headers {
			if headers[index].hdr.Control != nil || headers[index].hdr.Controllen != 0 || headers[index].hdr.Iovlen != 1 {
				t.Fatalf("header %d unexpectedly used GSO: %+v", index, headers[index].hdr)
			}
		}
		return len(headers), 0
	})
	messages := externalV2BulkPacketLinuxSendTestMessages(7)
	written, err := batch.WriteBatch(context.Background(), messages)
	if err != nil || written != len(messages) {
		t.Fatalf("WriteBatch = %d, error %v", written, err)
	}
	if stats := batch.Stats(); stats.GSOAttempted || stats.GSOActive {
		t.Fatalf("segments=1 stats = %+v", stats)
	}
}

func TestExternalV2BulkPacketLinuxConfiguredGSOMapsPartialLogicalCompletion(t *testing.T) {
	calls := 0
	batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, 3, func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		calls++
		if len(headers) != 3 || headers[0].hdr.Iovlen != 3 || headers[0].hdr.Controllen == 0 {
			t.Fatalf("GSO headers = %d first=%+v", len(headers), headers[0].hdr)
		}
		return 2, unix.EPERM
	})
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(8, 1400, 1400)
	for index := range messages {
		messages[index].PayloadBytes = index + 1
	}
	written, err := batch.WriteBatch(context.Background(), messages)
	if written != 6 || !errors.Is(err, unix.EPERM) || calls != 1 {
		t.Fatalf("WriteBatch = %d, error %v, calls %d, want 6/EPERM/1", written, err, calls)
	}
	for index := range messages {
		want := 0
		if index < 6 {
			want = len(messages[index].Buffers[0])
		}
		if messages[index].N != want {
			t.Fatalf("message %d N = %d, want %d", index, messages[index].N, want)
		}
	}
	stats := batch.Stats()
	if stats.NativeSendAttempts != 1 || stats.NativeSendSyscalls != 1 || stats.NativeGSOMessages != 2 || stats.LogicalDatagrams != 6 {
		t.Fatalf("native GSO counters = %+v", stats)
	}
	if stats.NativeAcceptedPayloadBytes != 21 || stats.GSOSegmentsPerMessage != 3 || stats.CandidateID != "combined-gso3" {
		t.Fatalf("native GSO payload/identity = %+v", stats)
	}
}

func TestExternalV2BulkPacketLinuxConfiguredGSOFeatureErrorsFallbackConnected(t *testing.T) {
	for _, featureErr := range []syscall.Errno{unix.EINVAL, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.ENOSYS, unix.EIO} {
		t.Run(featureErr.Error(), func(t *testing.T) {
			calls := 0
			batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, 3, func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
				calls++
				switch calls {
				case 1:
					if headers[0].hdr.Controllen == 0 || headers[0].hdr.Iovlen != 3 {
						t.Fatalf("first call was not connected GSO: %+v", headers[0].hdr)
					}
					return 0, featureErr
				case 2:
					for index := range headers {
						if headers[index].hdr.Name != nil || headers[index].hdr.Controllen != 0 || headers[index].hdr.Iovlen != 1 {
							t.Fatalf("fallback header %d = %+v", index, headers[index].hdr)
						}
					}
					return len(headers), 0
				default:
					t.Fatalf("unexpected sendmmsg call %d", calls)
					return 0, unix.EIO
				}
			})
			messages := externalV2BulkPacketLinuxGSOSendTestMessages(8, 1400, 1400)
			written, err := batch.WriteBatch(context.Background(), messages)
			if err != nil || written != len(messages) || calls != 2 {
				t.Fatalf("WriteBatch = %d, error %v, calls %d", written, err, calls)
			}
			if batch.gsoCapable.Load() {
				t.Fatal("feature rejection did not disable GSO")
			}
		})
	}
}

func TestExternalV2BulkPacketLinuxConfiguredGSOFallbackResumesExactUnsentSuffix(t *testing.T) {
	starts := make([]byte, 0, 3)
	calls := 0
	batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, 3, func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		calls++
		starts = append(starts, *headers[0].hdr.Iov.Base)
		switch calls {
		case 1:
			return 1, unix.EOPNOTSUPP
		case 2:
			return 2, 0
		case 3:
			return len(headers), 0
		default:
			return 0, unix.EIO
		}
	})
	messages := externalV2BulkPacketLinuxGSOSendTestMessages(8, 1400, 1400)
	for index := range messages {
		messages[index].PayloadBytes = index + 1
	}
	if err := writeExternalV2BulkPacketBatchAll(context.Background(), batch, messages); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(starts), fmt.Sprint([]byte{0, 3, 5}); got != want {
		t.Fatalf("send starts = %s, want %s", got, want)
	}
	for index := range messages {
		if messages[index].N != len(messages[index].Buffers[0]) {
			t.Fatalf("message %d N = %d, want %d", index, messages[index].N, len(messages[index].Buffers[0]))
		}
	}
	stats := batch.Stats()
	if stats.NativeSendAttempts != 3 || stats.NativeSendSyscalls != 3 || stats.NativeGSOMessages != 1 || stats.LogicalDatagrams != 8 {
		t.Fatalf("fallback native counters = %+v", stats)
	}
	if stats.NativeAcceptedPayloadBytes != 36 || stats.GSOSegmentsPerMessage != 3 {
		t.Fatalf("fallback double-counted or omitted payload: %+v", stats)
	}
}

func TestExternalV2BulkPacketLinuxConnectedWriterRetainsBuffersAcrossRawWrite(t *testing.T) {
	const wantLogical = 45
	for _, segments := range []int{1, 3} {
		t.Run(fmt.Sprintf("gso%d", segments), func(t *testing.T) {
			batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, segments, func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
				logical := 0
				for _, header := range headers {
					if header.hdr.Iov == nil || header.hdr.Iovlen == 0 {
						t.Fatal("native header lost its iovecs across RawConn.Write")
					}
					for _, iovec := range unsafe.Slice(header.hdr.Iov, int(header.hdr.Iovlen)) {
						if iovec.Base == nil || iovec.Len == 0 {
							t.Fatal("native iovec lost its payload across RawConn.Write")
						}
						payload := unsafe.Slice(iovec.Base, int(iovec.Len))
						if payload[0] != byte(logical) || len(payload) != 1400 {
							t.Fatalf("logical datagram %d = first %d length %d", logical, payload[0], len(payload))
						}
						logical++
					}
				}
				if logical != wantLogical {
					t.Fatalf("syscall observed %d logical datagrams, want %d", logical, wantLogical)
				}
				return len(headers), 0
			})
			batch.rawConn = externalV2BulkPacketLinuxGCWriteRawConn{}
			written, err := externalV2BulkPacketLinuxRunRetainsBuffersWrite(batch, wantLogical)
			if err != nil || written != wantLogical {
				t.Fatalf("WriteBatch = %d, error %v", written, err)
			}
		})
	}
}

//go:noinline
func externalV2BulkPacketLinuxRunRetainsBuffersWrite(batch *externalV2BulkPacketLinuxBatchConn, count int) (int, error) {
	return batch.WriteBatch(context.Background(), externalV2BulkPacketLinuxGSOSendTestMessages(count, 1400, 1400))
}

func TestExternalV2BulkPacketLinuxConfiguredGSOFatalErrorNeverFallsBackAddressed(t *testing.T) {
	calls := 0
	batch := externalV2BulkPacketLinuxConfiguredGSOTestBatch(t, 4, func(_ uintptr, _ []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		calls++
		return 0, unix.EPERM
	})
	written, err := batch.WriteBatch(context.Background(), externalV2BulkPacketLinuxGSOSendTestMessages(7, 1400, 1400))
	if written != 0 || !errors.Is(err, unix.EPERM) || calls != 1 {
		t.Fatalf("WriteBatch = %d, error %v, calls %d, want 0/EPERM/1", written, err, calls)
	}
}

func TestExternalV2BulkPacketCandidateInvalidLinkerValueFailsInitializationAndWrite(t *testing.T) {
	previous := externalV2BulkPacketBenchmarkCandidate
	externalV2BulkPacketBenchmarkCandidate = "combined-gso5"
	t.Cleanup(func() { externalV2BulkPacketBenchmarkCandidate = previous })

	senderConn := listenExternalV2BulkPacketLinuxUDP(t)
	defer senderConn.Close()
	batch := newExternalV2BulkPacketBatchConn(senderConn).(*externalV2BulkPacketLinuxBatchConn)
	if err := batch.enableFixedPeerConnect(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123}); err == nil {
		t.Fatal("invalid linker candidate did not fail fixed-peer initialization")
	}
	written, err := batch.WriteBatch(context.Background(), externalV2BulkPacketLinuxSendTestMessages(1))
	if written != 0 || err == nil {
		t.Fatalf("WriteBatch = %d, error %v, want candidate error", written, err)
	}

	portableFallback := newExternalV2BulkPacketBatchConn(&externalV2BulkPacketLinuxWriteDeadlineConn{})
	written, err = portableFallback.WriteBatch(context.Background(), []externalV2BulkPacketBatchMessage{{
		Buffers: [][]byte{[]byte("invalid-candidate")},
		Addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8123},
	}})
	if written != 0 || err == nil || !strings.Contains(err.Error(), "invalid bulk packet benchmark candidate") {
		t.Fatalf("portable fallback WriteBatch = %d, error %v, want linker candidate error", written, err)
	}
}

func externalV2BulkPacketLinuxConfiguredGSOTestBatch(
	t *testing.T,
	segments int,
	send externalV2BulkPacketLinuxSendSyscall,
) *externalV2BulkPacketLinuxBatchConn {
	t.Helper()
	batch := &externalV2BulkPacketLinuxBatchConn{
		connected:   true,
		rawConn:     &externalV2BulkPacketLinuxWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg:    send,
		candidateConfig: externalV2BulkPacketCandidateConfig{
			ID:                  fmt.Sprintf("combined-gso%d", segments),
			CoalescedReads:      true,
			NativeConnectedSend: true,
			GSOSegments:         segments,
		},
	}
	batch.stats.setCandidateID("combined-gso3")
	batch.gsoCapable.Store(true)
	return batch
}

type externalV2BulkPacketLinuxSendResult struct {
	written int
	errno   syscall.Errno
}

type externalV2BulkPacketLinuxWriteRawConn struct {
	inCallback           bool
	callbackCalls        int
	writeErr             error
	waitForWriteDeadline <-chan struct{}
	waitTimedOut         bool
}

type externalV2BulkPacketLinuxConcurrentWriteRawConn struct{}

type externalV2BulkPacketLinuxGCWriteRawConn struct{}

func (externalV2BulkPacketLinuxGCWriteRawConn) Control(func(uintptr)) error {
	return errors.New("unexpected RawConn.Control")
}

func (externalV2BulkPacketLinuxGCWriteRawConn) Read(func(uintptr) bool) error {
	return errors.New("unexpected RawConn.Read")
}

func (externalV2BulkPacketLinuxGCWriteRawConn) Write(callback func(uintptr) bool) error {
	runtime.GC()
	if !callback(123) {
		return errors.New("RawConn.Write callback made no progress")
	}
	return nil
}

func (externalV2BulkPacketLinuxConcurrentWriteRawConn) Control(func(uintptr)) error {
	return errors.New("unexpected RawConn.Control")
}

func (externalV2BulkPacketLinuxConcurrentWriteRawConn) Read(func(uintptr) bool) error {
	return errors.New("unexpected RawConn.Read")
}

func (externalV2BulkPacketLinuxConcurrentWriteRawConn) Write(callback func(uintptr) bool) error {
	if !callback(123) {
		return errors.New("RawConn.Write callback made no progress")
	}
	return nil
}

func (*externalV2BulkPacketLinuxWriteRawConn) Control(func(uintptr)) error {
	return errors.New("unexpected RawConn.Control")
}

func (*externalV2BulkPacketLinuxWriteRawConn) Read(func(uintptr) bool) error {
	return errors.New("unexpected RawConn.Read")
}

func (c *externalV2BulkPacketLinuxWriteRawConn) Write(callback func(uintptr) bool) error {
	for range 16 {
		c.callbackCalls++
		c.inCallback = true
		done := callback(123)
		c.inCallback = false
		if done {
			return c.writeErr
		}
		if c.waitForWriteDeadline != nil {
			select {
			case <-c.waitForWriteDeadline:
				return os.ErrDeadlineExceeded
			case <-time.After(100 * time.Millisecond):
				c.waitTimedOut = true
				return errors.New("RawConn.Write was not interrupted by cancellation")
			}
		}
	}
	return errors.New("RawConn.Write callback made no progress")
}

type externalV2BulkPacketLinuxWriteDeadlineConn struct {
	deadlineSet           chan struct{}
	deadlineOnce          sync.Once
	nonzeroWriteDeadlines int
	zeroWriteDeadlines    int
}

type externalV2BulkPacketLinuxDelayedWriteDeadlineConn struct {
	callbackStarted chan struct{}
	releaseCallback chan struct{}
	callbackOnce    sync.Once
	mu              sync.Mutex
	writeDeadlines  []time.Time
}

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected PacketConn.ReadFrom")
}

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("unexpected PacketConn.WriteTo")
}

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) Close() error { return nil }

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) SetDeadline(time.Time) error {
	return nil
}

func (*externalV2BulkPacketLinuxDelayedWriteDeadlineConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *externalV2BulkPacketLinuxDelayedWriteDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		wait := false
		c.callbackOnce.Do(func() {
			wait = true
			close(c.callbackStarted)
		})
		if wait {
			<-c.releaseCallback
		}
	}
	c.mu.Lock()
	c.writeDeadlines = append(c.writeDeadlines, deadline)
	c.mu.Unlock()
	return nil
}

func (c *externalV2BulkPacketLinuxDelayedWriteDeadlineConn) writeDeadlineHistory() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.writeDeadlines...)
}

func (*externalV2BulkPacketLinuxWriteDeadlineConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected PacketConn.ReadFrom")
}

func (*externalV2BulkPacketLinuxWriteDeadlineConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("unexpected PacketConn.WriteTo")
}

func (*externalV2BulkPacketLinuxWriteDeadlineConn) Close() error { return nil }

func (*externalV2BulkPacketLinuxWriteDeadlineConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (*externalV2BulkPacketLinuxWriteDeadlineConn) SetDeadline(time.Time) error { return nil }

func (*externalV2BulkPacketLinuxWriteDeadlineConn) SetReadDeadline(time.Time) error { return nil }

func (c *externalV2BulkPacketLinuxWriteDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.nonzeroWriteDeadlines++
		c.deadlineOnce.Do(func() { close(c.deadlineSet) })
	} else {
		c.zeroWriteDeadlines++
	}
	return nil
}

func externalV2BulkPacketLinuxInjectedSend(
	t *testing.T,
	results []externalV2BulkPacketLinuxSendResult,
) externalV2BulkPacketLinuxSendSyscall {
	t.Helper()
	call := 0
	return func(_ uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
		t.Helper()
		for index := range headers {
			if headers[index].hdr.Name != nil || headers[index].hdr.Namelen != 0 {
				t.Errorf("header %d name = %p/%d, want nil/0", index, headers[index].hdr.Name, headers[index].hdr.Namelen)
				return 0, unix.EINVAL
			}
		}
		if call >= len(results) {
			t.Errorf("sendmmsg call %d exceeds %d scripted results", call, len(results))
			return 0, unix.EIO
		}
		result := results[call]
		call++
		return result.written, result.errno
	}
}

func externalV2BulkPacketLinuxConnectedSendTestBatch(
	t *testing.T,
	results []externalV2BulkPacketLinuxSendResult,
	starts *[]byte,
) *externalV2BulkPacketLinuxBatchConn {
	t.Helper()
	send := externalV2BulkPacketLinuxInjectedSend(t, results)
	batch := &externalV2BulkPacketLinuxBatchConn{
		connected:   true,
		rawConn:     &externalV2BulkPacketLinuxWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
		sendMMsg: func(fd uintptr, headers []externalV2BulkPacketMMsgHdr) (int, syscall.Errno) {
			if starts != nil && len(headers) > 0 {
				*starts = append(*starts, *headers[0].hdr.Iov.Base)
			}
			return send(fd, headers)
		},
	}
	batch.stats.setCandidateID("combined-gso3")
	return batch
}

func externalV2BulkPacketLinuxSendTestMessages(count int) []externalV2BulkPacketBatchMessage {
	messages := make([]externalV2BulkPacketBatchMessage, count)
	for index := range messages {
		messages[index].Buffers = [][]byte{{byte(index)}}
	}
	return messages
}

func externalV2BulkPacketLinuxAddressedSendTestBatch(t *testing.T) *externalV2BulkPacketLinuxBatchConn {
	t.Helper()
	batch := &externalV2BulkPacketLinuxBatchConn{
		rawConn:     &externalV2BulkPacketLinuxWriteRawConn{},
		stats:       newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
		sendScratch: newExternalV2BulkPacketLinuxSendScratch(),
	}
	batch.stats.setCandidateID("coalesced-gso3")
	return batch
}

func externalV2BulkPacketLinuxAddressedSendTestMessages(addr net.Addr, payloadBytes ...int) []externalV2BulkPacketBatchMessage {
	messages := make([]externalV2BulkPacketBatchMessage, len(payloadBytes))
	for index, payload := range payloadBytes {
		messages[index] = externalV2BulkPacketBatchMessage{
			Buffers:      [][]byte{make([]byte, payload)},
			Addr:         addr,
			PayloadBytes: payload,
		}
	}
	return messages
}
