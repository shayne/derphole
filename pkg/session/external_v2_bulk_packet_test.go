// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"go4.org/mem"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketSendPacketChargesIPv4WireBytes(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: senders,
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, false); err != nil {
		t.Fatalf("sendPacket() error = %v", err)
	}
	if got, want := sender.primaryWireBytes.Load(), int64(1428); got != want {
		t.Fatalf("primary wire bytes = %d, want %d", got, want)
	}
	if got := sender.repairWireBytes.Load(); got != 0 {
		t.Fatalf("repair wire bytes = %d, want 0", got)
	}
}

func TestExternalV2BulkPacketSendPacketCountsSuccessfulRepair(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: senders,
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, true); err != nil {
		t.Fatalf("sendPacket() error = %v", err)
	}
	if got, want := sender.repairWireBytes.Load(), int64(1428); got != want {
		t.Fatalf("repair wire bytes = %d, want %d", got, want)
	}
	if got, want := sender.repairPackets.Load(), int64(1); got != want {
		t.Fatalf("repair packets = %d, want %d", got, want)
	}
	if got, want := sender.repairPayloadBytes.Load(), int64(externalV2BulkPacketPayloadSize); got != want {
		t.Fatalf("repair payload bytes = %d, want %d", got, want)
	}
	if got := sender.primaryWireBytes.Load(); got != 0 {
		t.Fatalf("primary wire bytes = %d, want 0", got)
	}
}

func TestExternalV2BulkPacketSendPacketDoesNotCountShortWrite(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{shortWriteBulkPacketConn{PacketConn: senders[0]}},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, true); err != io.ErrShortWrite {
		t.Fatalf("sendPacket() error = %v, want %v", err, io.ErrShortWrite)
	}
	if got := sender.sentPackets.Load(); got != 0 {
		t.Fatalf("sent packets = %d, want 0", got)
	}
	if got := sender.sentPayload.Load(); got != 0 {
		t.Fatalf("sent payload = %d, want 0", got)
	}
	if got := sender.repairPackets.Load(); got != 0 {
		t.Fatalf("repair packets = %d, want 0", got)
	}
	if got := sender.repairPayloadBytes.Load(); got != 0 {
		t.Fatalf("repair payload bytes = %d, want 0", got)
	}
}

func TestExternalV2BulkPacketSendPacketRetriesTransientNoBufferSpace(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{
		PacketConn: senders[0],
	}
	conn.remaining.Store(3)
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, false); err != nil {
		t.Fatalf("sendPacket() error = %v, want transient write retry", err)
	}
	if got := conn.attempts.Load(); got != 4 {
		t.Fatalf("write attempts = %d, want 4", got)
	}
	if got := sender.sentPackets.Load(); got != 1 {
		t.Fatalf("sent packets = %d, want 1", got)
	}
}

func TestExternalV2BulkPacketSendPacketCountsLocalENOBUFSPressure(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{PacketConn: senders[0]}
	conn.remaining.Store(3)
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	if err := sender.sendPacket(0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := sender.localENOBUFSRetries.Load(); got != 3 {
		t.Fatalf("local ENOBUFS retries = %d, want 3", got)
	}
	if got := sender.localENOBUFSMaxConsecutive.Load(); got != 3 {
		t.Fatalf("max consecutive local ENOBUFS = %d, want 3", got)
	}
	if got := sender.localENOBUFSWaitNanos.Load(); got <= 0 {
		t.Fatalf("local ENOBUFS wait nanos = %d, want positive", got)
	}
}

func TestExternalV2BulkPacketCancellationPublishesENOBUFSEvent(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{
		PacketConn: senders[0],
		attempted:  make(chan struct{}),
	}
	conn.remaining.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{Payload: bytes.NewReader([]byte{0x5a}), PayloadSize: 1},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)
	errCh := make(chan error, 1)
	go func() { errCh <- sender.sendPacket(0, 0, false) }()
	<-conn.attempted
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("sendPacket() error = %v, want context canceled", err)
	}
	if got := sender.localENOBUFSRetries.Load(); got != 1 {
		t.Fatalf("local ENOBUFS retries = %d, want 1", got)
	}
}

func TestExternalV2BulkPacketSendPacketStopsNoBufferSpaceRetriesOnCancellation(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &transientWriteFailureBulkPacketConn{
		PacketConn: senders[0],
		attempted:  make(chan struct{}),
	}
	conn.remaining.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)

	errCh := make(chan error, 1)
	go func() {
		errCh <- sender.sendPacket(0, 0, false)
	}()
	select {
	case <-conn.attempted:
	case <-time.After(time.Second):
		t.Fatal("sendPacket did not attempt WriteTo")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("sendPacket() error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("sendPacket did not stop after cancellation")
	}
}

func TestExternalV2BulkPacketSenderCancellationUnblocksWrite(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	blockingConn := &deadlineBlockingBulkPacketConn{
		PacketConn: senders[0],
		started:    make(chan struct{}),
		unblocked:  make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	sender := newExternalV2BulkPacketSender(
		ctx,
		&BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		},
		externalV2BulkPacketPath{
			Conns: []net.PacketConn{blockingConn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		},
		auth,
		nil,
	)
	sender.pacer = rate.NewLimiter(0, externalV2BulkPacketPaceBurstBytes)
	deadlineDone := startExternalV2BulkPacketWriteDeadlineCancel(ctx, sender.path)

	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- sender.sendPacket(0, 0, false)
	}()
	select {
	case <-blockingConn.started:
	case <-time.After(time.Second):
		t.Fatal("sendPacket did not start WriteTo")
	}
	cancel()
	select {
	case <-deadlineDone:
	case <-time.After(time.Second):
		t.Fatal("write deadline watcher did not stop")
	}
	select {
	case err := <-writeErrCh:
		if err != context.DeadlineExceeded {
			t.Fatalf("sendPacket() error = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(time.Second):
		t.Fatal("sendPacket remained blocked after cancellation")
	}
	if err := clearExternalV2BulkPacketDeadlines(sender.path); err != nil {
		t.Fatalf("clear deadlines: %v", err)
	}
	if got := blockingConn.writeDeadline(); !got.IsZero() {
		t.Fatalf("write deadline = %v, want cleared", got)
	}
}

func TestExternalV2BulkPacketTopLevelClearsReadAndWriteDeadlines(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := newLifecycleBulkPacketConn(senders[0])
	ctx, cancel := context.WithCancel(context.Background())
	stopHello := startExternalV2BulkPacketHelloLoop(ctx, externalV2BulkPacketPath{
		Conns: receivers,
		Addrs: externalV2BulkPacketTestAddrs(senders),
	}, auth, 1)
	defer stopHello()

	resultCh := make(chan error, 1)
	go func() {
		_, err := sendExternalV2BulkBlockPacketsWithProbe(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil, false)
		resultCh <- err
	}()

	select {
	case <-conn.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("top-level sender did not start WriteTo")
	}
	cancel()
	select {
	case err := <-resultCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("sendExternalV2BulkBlockPackets() error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("top-level sender did not stop after cancellation")
	}
	readDeadline, writeDeadline := conn.deadlines()
	if !readDeadline.IsZero() || !writeDeadline.IsZero() {
		t.Fatalf("deadlines after return = read %v write %v, want both cleared", readDeadline, writeDeadline)
	}
}

func TestExternalV2BulkPacketControlReaderReusesDeadlineAcrossSuccessfulReads(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const runID = 7
	conn := &scriptedReadBulkPacketConn{reads: []scriptedBulkPacketRead{
		{packet: testExternalV2BulkPacketControlPacket(t, auth, externalV2BulkPacketHeader{kind: externalV2BulkPacketHello, total: 1})},
		{packet: testExternalV2BulkPacketControlPacket(t, auth, externalV2BulkPacketHeader{kind: externalV2BulkPacketHello, total: 1})},
		{packet: testExternalV2BulkPacketControlPacket(t, auth, externalV2BulkPacketHeader{kind: externalV2BulkPacketDone, runID: runID})},
	}}

	readExternalV2BulkPacketControlLoop(
		context.Background(),
		conn,
		auth,
		runID,
		1,
		make(chan []uint32, 1),
		make(chan struct{}, 1),
		make(chan struct{}, 2),
		nil,
		make(chan error, 1),
		nil,
		nil,
	)

	if got := conn.nonzeroReadDeadlines.Load(); got != 1 {
		t.Fatalf("nonzero SetReadDeadline calls = %d, want 1 for three successful reads", got)
	}
}

func TestExternalV2BulkPacketControlReaderRefreshesDeadlineAfterTimeout(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const runID = 7
	conn := &scriptedReadBulkPacketConn{reads: []scriptedBulkPacketRead{
		{packet: testExternalV2BulkPacketControlPacket(t, auth, externalV2BulkPacketHeader{kind: externalV2BulkPacketHello, total: 1})},
		{err: context.DeadlineExceeded},
		{packet: testExternalV2BulkPacketControlPacket(t, auth, externalV2BulkPacketHeader{kind: externalV2BulkPacketDone, runID: runID})},
	}}

	readExternalV2BulkPacketControlLoop(
		context.Background(),
		conn,
		auth,
		runID,
		1,
		make(chan []uint32, 1),
		make(chan struct{}, 1),
		make(chan struct{}, 1),
		nil,
		make(chan error, 1),
		nil,
		nil,
	)

	if got := conn.nonzeroReadDeadlines.Load(); got != 2 {
		t.Fatalf("nonzero SetReadDeadline calls = %d, want 2 after one timeout", got)
	}
}

func TestExternalV2BulkPacketDataReadOwnsPayloadAfterReadBufferReuse(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	packet, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketData,
		runID: 7,
		index: 3,
		total: 9,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	conn := &repeatingReadBulkPacketConn{packet: packet}
	reader := externalV2BulkPacketReader{conn: conn}
	buf := make([]byte, externalV2BulkPacketMaxSize)
	pool := newTrackingExternalV2BulkPacketPayloadPool()

	result, ok, stop := readExternalV2BulkPacketDataWithPool(context.Background(), &reader, auth, buf, nil, pool)
	if !ok || stop {
		t.Fatalf("readExternalV2BulkPacketDataWithPool() = ok %v, stop %v", ok, stop)
	}
	for i := range buf {
		buf[i] = 0xa5
	}
	if !bytes.Equal(result.data, payload) {
		t.Fatalf("result data changed after encrypted read buffer reuse")
	}
	if got := pool.putCount(); got != 0 {
		t.Fatalf("pool returns before result release = %d, want 0", got)
	}
	result.release()
	result.release()
	if got := pool.putCount(); got != 1 {
		t.Fatalf("pool returns after two result releases = %d, want 1", got)
	}
	if result.data != nil {
		t.Fatalf("result data after release = %d bytes, want nil", len(result.data))
	}
}

func TestExternalV2BulkPacketDataReadRecyclesPayloadAllocation(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	packet, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketData,
		runID: 7,
		index: 3,
		total: 9,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	conn := &repeatingReadBulkPacketConn{packet: packet}
	reader := externalV2BulkPacketReader{conn: conn}
	buf := make([]byte, externalV2BulkPacketMaxSize)

	header, ok := parseExternalV2BulkPacketHeader(packet)
	if !ok {
		t.Fatal("parseExternalV2BulkPacketHeader() failed")
	}
	var nonceScratch [externalV2BulkPacketMaximumNonceSize]byte
	nonce := nonceScratch[:auth.data.NonceSize()]
	fillExternalV2BulkPacketNonce(nonce, header)
	openBuf := make([]byte, 0, externalV2BulkPacketPayloadSize)
	directOpenAllocs := testing.AllocsPerRun(1000, func() {
		openedPayload, err := auth.data.Open(openBuf[:0], nonce, header.payload, packet[:externalV2BulkPacketHeaderSize])
		if err != nil || len(openedPayload) != len(payload) {
			t.Fatalf("AEAD.Open() = len %d, error %v", len(openedPayload), err)
		}
	})
	openIntoAllocs := testing.AllocsPerRun(1000, func() {
		_, openedPayload, opened := openExternalV2BulkPacketInto(auth.data, packet, openBuf[:0])
		if !opened || len(openedPayload) != len(payload) {
			t.Fatalf("openExternalV2BulkPacketInto() = len %d, opened %v", len(openedPayload), opened)
		}
	})
	readAllocs := testing.AllocsPerRun(1000, func() {
		result, ok, stop := readExternalV2BulkPacketData(context.Background(), &reader, auth, buf, nil)
		if !ok || stop || len(result.data) != len(payload) {
			t.Fatalf("readExternalV2BulkPacketData() = len %d, ok %v, stop %v", len(result.data), ok, stop)
		}
		result.release()
	})
	// Direct preallocated AEAD open measures zero payload allocations. The
	// open-into wrapper independently measures the nonce/interface escape.
	// Successful data read plus release must also be allocation-free.
	t.Logf("allocations per successful data read plus release = %.0f, packet open-into = %.0f, direct preallocated AEAD open = %.0f", readAllocs, openIntoAllocs, directOpenAllocs)
	if readAllocs != 0 {
		t.Fatalf("allocations per successful data read plus release = %.0f, want 0", readAllocs)
	}
}

func TestExternalV2BulkPacketReaderNonceScratchHandlesSequentialVariedHeaders(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		header  externalV2BulkPacketHeader
		payload []byte
	}{
		{
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketHello, runID: 0x0102030405060708, index: 0x11121314, total: 0x21222324,
			},
			payload: []byte{0x31},
		},
		{
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketMiss, runID: 0xf1e2d3c4b5a69788, index: 0xa1b2c3d4, total: 0xe5f60718,
			},
			payload: []byte{0x41, 0x42, 0x43, 0x44, 0x45},
		},
		{
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketDone, runID: 0x8070605040302010, index: 0x99887766, total: 0x55443322,
			},
			payload: []byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59},
		},
	}

	conn := &scriptedReadBulkPacketConn{}
	for _, tt := range tests {
		packet, err := sealExternalV2BulkPacket(auth.control, tt.header, tt.payload)
		if err != nil {
			t.Fatal(err)
		}
		conn.reads = append(conn.reads, scriptedBulkPacketRead{packet: packet})
	}
	reader := externalV2BulkPacketReader{conn: conn}
	buf := make([]byte, externalV2BulkPacketMaxSize)
	for i, tt := range tests {
		header, payload, ok, stop := readExternalV2BulkPacketControl(context.Background(), &reader, auth, buf, nil)
		if !ok || stop {
			t.Fatalf("read %d = ok %v, stop %v", i, ok, stop)
		}
		if header.kind != tt.header.kind || header.runID != tt.header.runID || header.index != tt.header.index || header.total != tt.header.total || header.length != uint16(len(tt.payload)) {
			t.Fatalf("read %d header = %+v, want kind %d run ID %x index %x total %x length %d", i, header, tt.header.kind, tt.header.runID, tt.header.index, tt.header.total, len(tt.payload))
		}
		if !bytes.Equal(payload, tt.payload) {
			t.Fatalf("read %d payload = %x, want %x", i, payload, tt.payload)
		}
	}
}

func TestExternalV2BulkPacketReaderNonceScratchIsConcurrentReaderLocal(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	const (
		readerCount = 8
		readCount   = 250
	)
	start := make(chan struct{})
	errCh := make(chan error, readerCount)
	var readers sync.WaitGroup
	readers.Add(readerCount)
	for i := range readerCount {
		header := externalV2BulkPacketHeader{
			kind:  externalV2BulkPacketData,
			runID: uint64(i+1) * 0x1011121314151617,
			index: uint32(i)*0x01020304 + 1,
			total: uint32(i)*0x10203040 + 7,
		}
		payload := bytes.Repeat([]byte{byte(0x80 + i)}, i+1)
		packet, err := sealExternalV2BulkPacket(auth.data, header, payload)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer readers.Done()
			<-start
			reader := externalV2BulkPacketReader{conn: &repeatingReadBulkPacketConn{packet: packet}}
			buf := make([]byte, externalV2BulkPacketMaxSize)
			for read := range readCount {
				result, ok, stop := readExternalV2BulkPacketData(context.Background(), &reader, auth, buf, nil)
				if !ok || stop {
					errCh <- fmt.Errorf("reader %d read %d = ok %v, stop %v", i, read, ok, stop)
					return
				}
				if result.header.runID != header.runID || result.header.index != header.index || result.header.total != header.total || !bytes.Equal(result.data, payload) {
					resultErr := fmt.Errorf("reader %d read %d result = header %+v payload %x, want header %+v payload %x", i, read, result.header, result.data, header, payload)
					result.release()
					errCh <- resultErr
					return
				}
				result.release()
			}
		}()
	}
	close(start)
	readers.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestExternalV2BulkPacketNonceAndWireVector(t *testing.T) {
	keyBytes := [chacha20poly1305.KeySize]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	aead, err := chacha20poly1305.NewX(keyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	header := externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketData,
		runID:  0x0102030405060708,
		index:  0x090a0b0c,
		total:  0x0d0e0f10,
		length: 3,
	}
	nonce := externalV2BulkPacketNonce(header)
	if got, want := hex.EncodeToString(nonce[:]), "010203040506070801090a0b0c0d0e0f1000030000000000"; got != want {
		t.Fatalf("nonce = %s, want %s", got, want)
	}
	packet, err := sealExternalV2BulkPacket(aead, header, []byte{0x11, 0x22, 0x33})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(packet), "44563242010000000102030405060708090a0b0c0d0e0f100003c01fd34ec5f7fc29b8c1329cc7e4bcb9e0168f"; got != want {
		t.Fatalf("wire packet = %s, want %s", got, want)
	}
	openedHeader, openedPayload, ok := openExternalV2BulkPacket(aead, packet)
	if !ok || openedHeader.kind != header.kind || openedHeader.runID != header.runID || openedHeader.index != header.index || openedHeader.total != header.total || openedHeader.length != header.length || !bytes.Equal(openedPayload, []byte{0x11, 0x22, 0x33}) {
		t.Fatalf("open vector = header %+v payload %x ok %v", openedHeader, openedPayload, ok)
	}
}

func TestExternalV2BulkPacketSessionAuthUsesAESGCMNonce(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if auth.data.NonceSize() != 12 || auth.control.NonceSize() != 12 || auth.grouped.NonceSize() != 12 {
		t.Fatalf("nonce sizes data/control/grouped = %d/%d/%d, want AES-GCM 12-byte nonces", auth.data.NonceSize(), auth.control.NonceSize(), auth.grouped.NonceSize())
	}
	if auth.grouped.Overhead() != 16 {
		t.Fatalf("grouped AES-GCM overhead = %d, want 16", auth.grouped.Overhead())
	}
}

func TestExternalV2BulkPacketDataReadReturnsPayloadOnRejection(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	dataPacket, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketData,
		runID: 7,
		index: 3,
		total: 9,
	}, bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize))
	if err != nil {
		t.Fatal(err)
	}
	nonDataPacket, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketMiss,
		runID: 7,
		index: 3,
		total: 9,
	}, []byte{0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	authFailurePacket := append([]byte(nil), dataPacket...)
	authFailurePacket[len(authFailurePacket)-1] ^= 0xff

	for _, tt := range []struct {
		name   string
		packet []byte
	}{
		{name: "authentication failure", packet: authFailurePacket},
		{name: "non-data packet", packet: nonDataPacket},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool := newTrackingExternalV2BulkPacketPayloadPool()
			reader := externalV2BulkPacketReader{conn: &repeatingReadBulkPacketConn{packet: tt.packet}}
			result, ok, stop := readExternalV2BulkPacketDataWithPool(
				context.Background(),
				&reader,
				auth,
				make([]byte, externalV2BulkPacketMaxSize),
				nil,
				pool,
			)
			if ok || stop {
				t.Fatalf("readExternalV2BulkPacketDataWithPool() = result %#v, ok %v, stop %v", result, ok, stop)
			}
			if gets, puts := pool.counts(); gets != 1 || puts != 1 {
				t.Fatalf("pool lifecycle = gets %d, puts %d, want 1, 1", gets, puts)
			}
		})
	}
}

func TestExternalV2BulkPacketDataReaderReturnsPayloadOnEnqueueCancellation(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketData,
		runID: 7,
		index: 0,
		total: 1,
	}, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan struct{})
	conn := &notifyingReadBulkPacketConn{
		repeatingReadBulkPacketConn: repeatingReadBulkPacketConn{packet: packet},
		read:                        read,
	}
	pool := newTrackingExternalV2BulkPacketPayloadPool()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		readExternalV2BulkPacketDataLoopWithPool(
			ctx,
			conn,
			auth,
			make(chan externalV2BulkPacketReceiveResult),
			make(chan error, 1),
			pool,
		)
	}()
	<-read
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("data reader did not stop after enqueue cancellation")
	}
	if gets, puts := pool.counts(); gets != 1 || puts != 1 {
		t.Fatalf("pool lifecycle = gets %d, puts %d, want 1, 1", gets, puts)
	}
}

func TestExternalV2BulkPacketReceiverReturnsPayloadAfterHandling(t *testing.T) {
	for _, tt := range []struct {
		name        string
		configure   func(*externalV2BulkPacketReceiver)
		header      externalV2BulkPacketHeader
		data        []byte
		payloadSize int64
		wantRunErr  bool
		wantContext bool
	}{
		{
			name: "success",
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 1,
			},
			data:        []byte("payload"),
			payloadSize: int64(len("payload")),
		},
		{
			name: "duplicate",
			configure: func(receiver *externalV2BulkPacketReceiver) {
				receiver.runID = 7
				receiver.seen[0] = true
			},
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2,
			},
			data:        bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize),
			payloadSize: externalV2BulkPacketPayloadSize + 1,
			wantRunErr:  true,
			wantContext: true,
		},
		{
			name: "invalid header",
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 3,
			},
			data:        bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize),
			payloadSize: externalV2BulkPacketPayloadSize + 1,
			wantRunErr:  true,
			wantContext: true,
		},
		{
			name: "invalid payload",
			header: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2,
			},
			data:        []byte("short"),
			payloadSize: externalV2BulkPacketPayloadSize + 1,
			wantRunErr:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sink := newMemoryBlockSink(tt.payloadSize)
			receiver := newExternalV2BulkPacketReceiver(
				sink,
				externalV2BlockReceiveConfig{PayloadSize: tt.payloadSize, ChunkSize: externalV2BulkPacketPayloadSize},
				externalV2BulkPacketPath{},
				externalV2BulkPacketAuth{},
				nil,
			)
			receiver.stopHello = func() {}
			if tt.configure != nil {
				tt.configure(receiver)
			}
			pool := newTrackingExternalV2BulkPacketPayloadPool()
			result := pool.result(tt.header, tt.data)
			dataCh := make(chan externalV2BulkPacketReceiveResult)
			ctx, cancel := context.WithCancel(context.Background())
			sent := make(chan struct{})
			go func() {
				dataCh <- result
				close(sent)
			}()
			if tt.wantContext {
				go func() {
					<-sent
					cancel()
				}()
			} else {
				defer cancel()
			}
			_, _, runErr := receiver.run(ctx, dataCh, make(chan error))
			if tt.wantRunErr != (runErr != nil) {
				t.Fatalf("receiver.run() error = %v, want error %v", runErr, tt.wantRunErr)
			}
			if tt.wantContext && !errors.Is(runErr, context.Canceled) {
				t.Fatalf("receiver.run() error = %v, want context canceled", runErr)
			}
			if gets, puts := pool.counts(); gets != 1 || puts != 1 {
				t.Fatalf("pool lifecycle = gets %d, puts %d, want 1, 1", gets, puts)
			}
		})
	}
}

func TestExternalV2BulkPacketReceiverCountsOnlyAuthenticatedCommittedPayload(t *testing.T) {
	payload := []byte("authenticated-payload")
	metrics := newExternalTransferMetricsWithTrace(time.Unix(220, 0), nil, transfertrace.RoleReceive)
	receiver := newExternalV2BulkPacketReceiver(
		newMemoryBlockSink(int64(len(payload))),
		externalV2BlockReceiveConfig{PayloadSize: int64(len(payload)), ChunkSize: len(payload)},
		externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, metrics,
	)
	receiver.stopHello = func() {}
	valid := externalV2BulkPacketReceiveResult{
		header: externalV2BulkPacketHeader{kind: externalV2BulkPacketData, runID: 7, index: 0, total: 1},
		data:   payload,
	}
	if err := receiver.handleDataResult(valid); err != nil {
		t.Fatal(err)
	}
	if err := receiver.handleDataResult(valid); err != nil {
		t.Fatal(err)
	}
	wrongRun := valid
	wrongRun.header.runID = 8
	if err := receiver.handleDataResult(wrongRun); err != nil {
		t.Fatal(err)
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.filePayloadEngine != transfertrace.FilePayloadEngineBulk ||
		metrics.filePayloadBytesCommitted != int64(len(payload)) ||
		metrics.filePayloadBytesBulk != int64(len(payload)) || metrics.filePayloadBytesQUIC != 0 {
		t.Fatalf("engine=%q committed=%d bulk=%d quic=%d", metrics.filePayloadEngine, metrics.filePayloadBytesCommitted, metrics.filePayloadBytesBulk, metrics.filePayloadBytesQUIC)
	}
}

func TestExternalV2BulkPacketAssemblerCopiesBeforePayloadRelease(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, externalV2BulkPacketPayloadSize)
	second := bytes.Repeat([]byte{0x22}, externalV2BulkPacketPayloadSize)
	sink := newMemoryBlockSink(int64(len(first) + len(second)))
	receiver := newExternalV2BulkPacketReceiver(
		sink,
		externalV2BlockReceiveConfig{
			PayloadSize: int64(len(first) + len(second)),
			ChunkSize:   len(first) + len(second),
		},
		externalV2BulkPacketPath{},
		externalV2BulkPacketAuth{},
		nil,
	)
	receiver.stopHello = func() {}
	pool := newTrackingExternalV2BulkPacketPayloadPool()
	result := pool.result(externalV2BulkPacketHeader{
		kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2,
	}, first)
	dataCh := make(chan externalV2BulkPacketReceiveResult)
	ctx, cancel := context.WithCancel(context.Background())
	sent := make(chan struct{})
	go func() {
		dataCh <- result
		close(sent)
	}()
	go func() {
		<-sent
		cancel()
	}()
	_, _, err := receiver.run(ctx, dataCh, make(chan error))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("receiver.run() error = %v, want context canceled", err)
	}
	reused := pool.get()
	if len(reused.data) != 0 {
		t.Fatalf("reused payload buffer length = %d, want 0", len(reused.data))
	}
	reused.data = reused.data[:externalV2BulkPacketPayloadSize]
	for i := range reused.data {
		reused.data[i] = 0xee
	}
	if _, err := receiver.assembler.add(1, second); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), second...)
	if got := sink.bytes(); !bytes.Equal(got, want) {
		t.Fatal("assembler retained released payload storage instead of its synchronous copy")
	}
	pool.put(reused)
}

func TestExternalV2BulkPacketManualReceiveResultReleaseIsNoOp(t *testing.T) {
	result := externalV2BulkPacketReceiveResult{data: []byte("manual")}
	result.release()
	result.release()
	if !bytes.Equal(result.data, []byte("manual")) {
		t.Fatalf("manual result data = %q, want unchanged", result.data)
	}
}

func TestExternalV2BulkPacketReceiveAckIsMonotonic(t *testing.T) {
	var ack externalV2BulkPacketReceiveAck
	ack.record(1024, 64<<20)
	ack.record(512, 64<<20)
	bytes, window, set := ack.snapshot()
	if !set || bytes != 1024 || window != 64<<20 {
		t.Fatalf("receive ack = %d window %d/%t", bytes, window, set)
	}
}

func TestExternalV2BulkPacketReceiverAcknowledgesUniqueAuthenticatedArrivals(t *testing.T) {
	arrivals := newExternalV2BulkPacketArrivalTracker(4)
	arrivals.markData(externalV2BulkPacketHeader{index: 0, total: 4, length: externalV2BulkPacketPayloadSize})
	arrivals.markData(externalV2BulkPacketHeader{index: 1, total: 4, length: externalV2BulkPacketPayloadSize})
	arrivals.markData(externalV2BulkPacketHeader{index: 3, total: 4, length: externalV2BulkPacketPayloadSize})
	receiver := &externalV2BulkPacketReceiver{
		seen:         make([]bool, 4),
		arrivals:     arrivals,
		totalPackets: 4,
		cfg:          externalV2BlockReceiveConfig{PayloadSize: 4 * externalV2BulkPacketPayloadSize},
	}
	if got := receiver.authenticatedPayloadCredit(); got != 3*externalV2BulkPacketPayloadSize {
		t.Fatalf("out-of-order authenticated credit = %d", got)
	}
	arrivals.markData(externalV2BulkPacketHeader{index: 2, total: 4, length: externalV2BulkPacketPayloadSize})
	if got := receiver.authenticatedPayloadCredit(); got != 4*externalV2BulkPacketPayloadSize {
		t.Fatalf("complete authenticated credit = %d", got)
	}
}

func TestExternalV2BulkPacketAckPayloadRoundTrip(t *testing.T) {
	encoded := encodeExternalV2BulkPacketAck(987654321, 64<<20)
	decoded, window, ok := decodeExternalV2BulkPacketAck(encoded)
	if !ok || decoded != 987654321 || window != 64<<20 {
		t.Fatalf("ack round trip = %d window %d/%t", decoded, window, ok)
	}
	if _, _, ok := decodeExternalV2BulkPacketAck(encoded[:7]); ok {
		t.Fatal("short ack payload was accepted")
	}
	if decoded, window, ok := decodeExternalV2BulkPacketAck(encoded[:8]); !ok || decoded != 987654321 || window != externalV2BulkPacketBufferedReceiveWindow {
		t.Fatalf("legacy ack = %d window %d/%t", decoded, window, ok)
	}
}

func TestExternalV2BulkPacketControlAcceptsAckForCurrentTransfer(t *testing.T) {
	const (
		runID        = 17
		totalPackets = 23
	)
	var ack externalV2BulkPacketReceiveAck
	valid := externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketAck,
		runID: runID,
		total: totalPackets,
	}
	if stop := handleExternalV2BulkPacketControl(valid, encodeExternalV2BulkPacketAck(4096, 64<<20), runID, totalPackets, nil, nil, nil, nil, nil, &ack); stop {
		t.Fatal("ACK stopped the control reader")
	}
	if got, window, set := ack.snapshot(); !set || got != 4096 || window != 64<<20 {
		t.Fatalf("accepted ACK = %d window %d/%t", got, window, set)
	}

	wrongRun := valid
	wrongRun.runID++
	handleExternalV2BulkPacketControl(wrongRun, encodeExternalV2BulkPacketAck(8192, 64<<20), runID, totalPackets, nil, nil, nil, nil, nil, &ack)
	wrongTotal := valid
	wrongTotal.total++
	handleExternalV2BulkPacketControl(wrongTotal, encodeExternalV2BulkPacketAck(8192, 64<<20), runID, totalPackets, nil, nil, nil, nil, nil, &ack)
	if got, _, _ := ack.snapshot(); got != 4096 {
		t.Fatalf("mismatched ACK advanced frontier to %d", got)
	}
}

func TestExternalV2BulkPacketReceiverShutdownReturnsQueuedPayloads(t *testing.T) {
	for _, tt := range []struct {
		name        string
		payloadSize int64
		firstHeader externalV2BulkPacketHeader
		firstData   []byte
		cancelFirst bool
		wantRunErr  bool
	}{
		{
			name:        "success",
			payloadSize: int64(len("payload")),
			firstHeader: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 1,
			},
			firstData: []byte("payload"),
		},
		{
			name:        "receiver error",
			payloadSize: externalV2BulkPacketPayloadSize + 1,
			firstHeader: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2,
			},
			firstData:  []byte("short"),
			wantRunErr: true,
		},
		{
			name:        "context cancellation",
			payloadSize: externalV2BulkPacketPayloadSize + 1,
			firstHeader: externalV2BulkPacketHeader{
				kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2,
			},
			firstData:   bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize),
			cancelFirst: true,
			wantRunErr:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			receiver := newExternalV2BulkPacketReceiver(
				newMemoryBlockSink(tt.payloadSize),
				externalV2BlockReceiveConfig{PayloadSize: tt.payloadSize, ChunkSize: externalV2BulkPacketPayloadSize},
				externalV2BulkPacketPath{},
				externalV2BulkPacketAuth{},
				nil,
			)
			receiver.stopHello = func() {}
			pool := newTrackingExternalV2BulkPacketPayloadPool()
			results := []externalV2BulkPacketReceiveResult{
				pool.result(tt.firstHeader, tt.firstData),
				pool.result(externalV2BulkPacketHeader{
					kind: externalV2BulkPacketData, runID: 7, index: 1, total: 2,
				}, []byte{0x99}),
			}
			dataCh := make(chan externalV2BulkPacketReceiveBatch, 1)
			batch := externalV2BulkPacketReceiveBatch{results: results}
			readersDone := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			if tt.cancelFirst {
				cancel()
				readersCancel := make(chan struct{})
				cancel = func() { close(readersCancel) }
				go func() {
					<-readersCancel
					dataCh <- batch
					close(readersDone)
				}()
			} else {
				dataCh <- batch
				close(readersDone)
			}
			_, _, err := runExternalV2BulkPacketReceiver(
				ctx,
				receiver,
				cancel,
				readersDone,
				dataCh,
				make(chan error),
			)
			if tt.wantRunErr != (err != nil) {
				t.Fatalf("runExternalV2BulkPacketReceiver() error = %v, want error %v", err, tt.wantRunErr)
			}
			if tt.cancelFirst && !errors.Is(err, context.Canceled) {
				t.Fatalf("runExternalV2BulkPacketReceiver() error = %v, want context canceled", err)
			}
			if gets, puts := pool.counts(); gets != 2 || puts != 2 {
				t.Fatalf("pool lifecycle after receiver shutdown = gets %d, puts %d, want 2, 2", gets, puts)
			}
			if got := len(dataCh); got != 0 {
				t.Fatalf("queued receive results after shutdown = %d, want 0", got)
			}
		})
	}
}

func TestExternalV2BulkPacketTopLevelStopsWhenReadDeadlineCannotBeSet(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := &readDeadlineFailBulkPacketConn{
		PacketConn: senders[0],
		release:    make(chan struct{}),
	}
	defer conn.forceReadReturn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan error, 1)
	go func() {
		_, err := sendExternalV2BulkBlockPacketsWithProbe(ctx, &BlockSource{
			Payload:     bytes.NewReader([]byte{0x5a}),
			PayloadSize: 1,
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil, false)
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		if !errors.Is(err, errTestBulkPacketSetReadDeadline) {
			t.Fatalf("sendExternalV2BulkBlockPackets() error = %v, want read deadline error", err)
		}
		if conn.readCalled.Load() {
			t.Fatal("ReadFrom was called after SetReadDeadline failed")
		}
	case <-time.After(500 * time.Millisecond):
		conn.forceReadReturn()
		cancel()
		<-resultCh
		t.Fatal("top-level sender did not stop after SetReadDeadline failed")
	}
}

func TestExternalV2BulkPacketTopLevelClosesBlockedWriteWhenDeadlinesFail(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := newDeadlineFailureBulkPacketConn(senders[0])
	defer conn.forceClose()
	ctx, cancel := context.WithCancel(context.Background())
	stopHello := startExternalV2BulkPacketHelloLoop(ctx, externalV2BulkPacketPath{
		Conns: receivers,
		Addrs: externalV2BulkPacketTestAddrs(senders),
	}, auth, 1)
	defer stopHello()

	resultCh := make(chan error, 1)
	go func() {
		_, err := sendExternalV2BulkBlockPacketsWithProbe(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil, false)
		resultCh <- err
	}()

	select {
	case <-conn.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("top-level sender did not start WriteTo")
	}
	cancel()
	select {
	case err := <-resultCh:
		for name, target := range map[string]error{
			"blocked write":      errTestBulkPacketBlockedWrite,
			"write deadline":     errTestBulkPacketSetWriteDeadline,
			"generic deadline":   errTestBulkPacketSetDeadline,
			"unreusable cleanup": errTestBulkPacketCleanupState,
		} {
			if !errors.Is(err, target) {
				t.Errorf("sendExternalV2BulkBlockPackets() error = %v, missing %s error %v", err, name, target)
			}
		}
	case <-time.After(500 * time.Millisecond):
		conn.forceClose()
		<-resultCh
		t.Fatal("top-level sender remained blocked after deadline setters failed")
	}
}

func TestExternalV2BulkPacketTopLevelInterruptsInitialSendOnPostHelloWorkerError(t *testing.T) {
	senders, receivers := listenExternalV2BulkPacketTestConns(t, 1)
	payload := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn := newPostHelloWorkerFailureBulkPacketConn(senders[0])
	defer conn.forceClose()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopHello := startExternalV2BulkPacketHelloLoop(ctx, externalV2BulkPacketPath{
		Conns: receivers,
		Addrs: externalV2BulkPacketTestAddrs(senders),
	}, auth, 1)
	defer stopHello()

	resultCh := make(chan error, 1)
	go func() {
		_, err := sendExternalV2BulkBlockPacketsWithProbe(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil, false)
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		if !errors.Is(err, errTestBulkPacketPostHelloReadDeadline) {
			t.Errorf("sendExternalV2BulkBlockPackets() error = %v, missing post-HELLO worker error", err)
		}
		if !errors.Is(err, errTestBulkPacketPostHelloWriteInterrupted) {
			t.Errorf("sendExternalV2BulkBlockPackets() error = %v, missing interrupted write error", err)
		}
	case <-time.After(500 * time.Millisecond):
		conn.forceClose()
		cancel()
		<-resultCh
		t.Fatal("top-level sender did not interrupt the initial write after a post-HELLO worker error")
	}
}

func TestExternalV2BulkPacketSendStatsUseExactRepairCounters(t *testing.T) {
	stats := externalV2BulkPacketSendStats(
		4096,
		4096,
		4608,
		1,
		512,
		2,
		1,
		1000,
		1000,
		true,
	)
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1", stats.Retransmits)
	}
	if stats.Diagnostics.RepairBytes != 512 {
		t.Fatalf("RepairBytes = %d, want 512", stats.Diagnostics.RepairBytes)
	}
	if stats.Diagnostics.RepairRequests != 2 {
		t.Fatalf("RepairRequests = %d, want 2", stats.Diagnostics.RepairRequests)
	}
	if stats.Diagnostics.DirectPacketBytes != 4608 {
		t.Fatalf("DirectPacketBytes = %d, want 4608", stats.Diagnostics.DirectPacketBytes)
	}
	if stats.Diagnostics.DirectCommittedBytes != 4096 {
		t.Fatalf("DirectCommittedBytes = %d, want 4096", stats.Diagnostics.DirectCommittedBytes)
	}
	if stats.Diagnostics.ControllerDecision != "" || stats.Diagnostics.ControllerReason != "" {
		t.Fatalf("terminal controller event = %q/%q, want empty", stats.Diagnostics.ControllerDecision, stats.Diagnostics.ControllerReason)
	}
}

func TestExternalV2BulkPacketSendStatsPreservePartialProgressOnError(t *testing.T) {
	stats := externalV2BulkPacketSendStats(
		4096,
		1358,
		1870,
		1,
		512,
		2,
		1,
		1000,
		850,
		false,
	)
	if stats.BytesSent != 1358 {
		t.Fatalf("BytesSent = %d, want 1358", stats.BytesSent)
	}
	if stats.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1", stats.Retransmits)
	}
	if stats.Diagnostics.DirectPacketBytes != 1870 {
		t.Fatalf("DirectPacketBytes = %d, want 1870", stats.Diagnostics.DirectPacketBytes)
	}
	if stats.Diagnostics.DirectCommittedBytes != 0 {
		t.Fatalf("DirectCommittedBytes = %d, want 0", stats.Diagnostics.DirectCommittedBytes)
	}
}

func TestExternalV2BulkPacketReceiverResultReportsRepairEfficiency(t *testing.T) {
	receiver := &externalV2BulkPacketReceiver{
		cfg: externalV2BlockReceiveConfig{
			PayloadSize: 8192,
			HeaderBytes: 7,
		},
		laneCount:        4,
		committedPayload: 4096,
		repairRequests:   32,
		missing: &externalV2BulkPacketMissingTracker{
			scanChecks:       790_545,
			pendingCount:     0,
			pendingPeak:      1234,
			requestedPackets: 4567,
			requestBatches:   32,
		},
		receiveRate: externalV2BulkPacketReceiveRate{
			trail:   22_000,
			ewmaPPS: 88_000,
		},
	}

	received, stats, err := receiver.result(nil)
	if err != nil {
		t.Fatalf("result() error = %v", err)
	}
	if received != 4103 || stats.BytesReceived != 4096 ||
		stats.Diagnostics.DirectPacketBytes != 4096 ||
		stats.Diagnostics.DirectCommittedBytes != 4096 {
		t.Fatalf("byte accounting changed: received=%d stats=%#v", received, stats)
	}
	diagnostics := stats.Diagnostics
	if diagnostics.MissingScanChecks != 790_545 ||
		diagnostics.PendingMissing != 0 ||
		diagnostics.PendingMissingPeak != 1234 ||
		diagnostics.RepairRequestedPackets != 4567 ||
		diagnostics.RepairRequestBatches != 32 ||
		diagnostics.ReorderTrailPackets != externalV2BulkPacketMaximumActiveRepairTrail ||
		diagnostics.ReceivePacketRatePPS != 88_000 {
		t.Fatalf("repair efficiency diagnostics = %#v", diagnostics)
	}
}

func TestExternalV2BulkPacketSenderPublishesControllerBeforeCompletion(t *testing.T) {
	start := time.Unix(230, 0)
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	sender := &externalV2BulkPacketSender{
		metrics:         metrics,
		initialPaceMbps: 1000,
		laneCount:       8,
		pacer:           rate.NewLimiter(externalV2BulkPacketRateLimit(1000), externalV2BulkPacketPaceBurstBytes),
		controller:      newExternalV2BulkPacketController(externalV2BulkPacketDefaultInitialWireMbps),
	}
	sender.currentPaceMbps.Store(1000)
	sender.publishControllerDiagnostics(start, externalV2BulkPacketControllerDecision{
		TargetMbps: 1000,
		Action:     "hold",
		Reason:     "initial-target",
	})
	sender.repairPackets.Store(12)
	sender.repairPayloadBytes.Store(16_296)
	sender.repairRequests.Store(3)
	sender.localENOBUFSRetries.Store(7)
	sender.localENOBUFSWaitNanos.Store(int64(912*time.Microsecond + 1))
	sender.localENOBUFSMaxConsecutive.Store(3)
	sender.publishControllerDiagnostics(start.Add(600*time.Millisecond), externalV2BulkPacketControllerDecision{
		TargetMbps: 850,
		Action:     "decrease",
		Reason:     "repair-pressure",
	})
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	if len(rows) != 2 ||
		rows[0]["rate_target_mbps"] != "1000" ||
		rows[1]["rate_target_mbps"] != "850" ||
		rows[1]["controller_decision"] != "decrease" ||
		rows[1]["retransmits"] != "12" ||
		rows[1]["repair_bytes"] != "16296" ||
		rows[1]["local_enobufs_retries"] != "7" ||
		rows[1]["local_enobufs_wait_us"] != "913" ||
		rows[1]["local_enobufs_max_consecutive"] != "3" {
		t.Fatalf("controller rows = %#v", rows)
	}
}

func TestExternalV2BulkPacketSenderUsesEnvironmentInitialRate(t *testing.T) {
	t.Setenv(externalV2BulkPacketInitialWireMbpsEnv, "800")
	start := time.Unix(232, 0)
	var out bytes.Buffer
	rec, err := transfertrace.NewRecorder(&out, transfertrace.RoleSend, start)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(start, rec, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	sender := newExternalV2BulkPacketSender(
		context.Background(),
		&BlockSource{PayloadSize: 4096},
		externalV2BulkPacketPath{},
		externalV2BulkPacketAuth{},
		metrics,
	)

	// The test override is sampled once per sender. Later environment changes
	// must not make periodic and terminal diagnostics disagree.
	t.Setenv(externalV2BulkPacketInitialWireMbpsEnv, "900")
	sender.observeController(start)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	rows := readTransferTraceRows(t, out.String())
	if len(rows) != 1 ||
		rows[0]["rate_target_mbps"] != "800" ||
		rows[0]["rate_selected_mbps"] != "800" {
		t.Fatalf("initial controller rows = %#v", rows)
	}
	stats := sender.stats(false)
	if sender.initialPaceMbps != 800 ||
		stats.Diagnostics.RateTargetMbps != 800 ||
		stats.Diagnostics.RateSelectedMbps != 800 {
		t.Fatalf("initial sender rate = %d, terminal diagnostics = %#v", sender.initialPaceMbps, stats.Diagnostics)
	}
}

func TestExternalV2BulkPacketControllerPublishDoesNotDoubleCountPacketProgress(t *testing.T) {
	const successfulPayload = int64(externalV2BulkPacketPayloadSize)
	metrics := newExternalTransferMetrics(time.Unix(231, 0))
	sender := &externalV2BulkPacketSender{
		metrics:   metrics,
		laneCount: 1,
	}
	sender.sentPayload.Store(successfulPayload)

	// Reproduce the dangerous sendPacket interleaving: the sender counters have
	// advanced, the controller publishes, then RecordDirectPacketSend runs.
	sender.publishControllerDiagnostics(time.Unix(231, 0), externalV2BulkPacketControllerDecision{
		TargetMbps: 1000,
		Action:     "hold",
		Reason:     "healthy-delivery",
	})
	metrics.RecordDirectPacketSend(successfulPayload, time.Unix(231, int64(time.Millisecond)))

	metrics.mu.Lock()
	directPacketBytes := metrics.directPacketBytes
	localSentBytes := metrics.localSentBytes
	metrics.mu.Unlock()
	if directPacketBytes > successfulPayload {
		t.Fatalf("direct packet bytes = %d, exceed successful payload %d", directPacketBytes, successfulPayload)
	}
	if localSentBytes > successfulPayload {
		t.Fatalf("local sent bytes = %d, exceed successful payload %d", localSentBytes, successfulPayload)
	}
}

func TestExternalV2BulkPacketAuthMatchesTokenReceiverDERP(t *testing.T) {
	senderDERP := key.NewNode().Public()
	receiverDERP := key.NewNode().Public()
	tok := testExternalV2BulkPacketToken()
	tok.DERPPublic = derpPublicKeyRaw32(receiverDERP)

	senderAuth, err := externalV2BulkPacketAuthForToken(tok, senderDERP, key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:])))
	if err != nil {
		t.Fatalf("sender auth: %v", err)
	}
	receiverAuth, err := externalV2BulkPacketAuthForToken(tok, senderDERP, receiverDERP)
	if err != nil {
		t.Fatalf("receiver auth: %v", err)
	}

	dataPacket, err := sealExternalV2BulkPacket(senderAuth.data, externalV2BulkPacketHeader{
		kind:   externalV2BulkPacketData,
		runID:  42,
		index:  7,
		total:  9,
		length: 4,
	}, []byte("data"))
	if err != nil {
		t.Fatalf("seal data packet: %v", err)
	}
	if _, payload, ok := openExternalV2BulkPacket(receiverAuth.data, dataPacket); !ok || !bytes.Equal(payload, []byte("data")) {
		t.Fatalf("receiver failed to open sender data packet ok=%v payload=%q", ok, payload)
	}

	helloPacket, err := sealExternalV2BulkPacket(receiverAuth.control, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketHello,
		index: 1,
		total: 9,
	}, nil)
	if err != nil {
		t.Fatalf("seal hello packet: %v", err)
	}
	if header, _, ok := openExternalV2BulkPacket(senderAuth.control, helloPacket); !ok || header.kind != externalV2BulkPacketHello {
		t.Fatalf("sender failed to open receiver hello ok=%v header=%+v", ok, header)
	}
}

func TestExternalV2BulkPacketNoProbeReceiverSelectsEngineAfterAuthenticatedPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senders, receiverConns := listenExternalV2BulkPacketTestConns(t, 1)
	setupBlocked := make(chan struct{})
	setupRelease := make(chan struct{})
	receivers := []net.PacketConn{&blockingReadBufferBulkPacketConn{
		PacketConn: receiverConns[0],
		blocked:    setupBlocked,
		release:    setupRelease,
	}}
	payload := bytes.Repeat([]byte{0x6b}, externalV2BulkPacketPayloadSize)
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	metrics := newExternalTransferMetricsWithTrace(time.Unix(240, 0), nil, transfertrace.RoleReceive)
	receiveErr := make(chan error, 1)
	go func() {
		_, _, err := receiveExternalV2BulkBlockPacketsWithProbe(
			ctx,
			sink,
			externalV2BlockReceiveConfig{PayloadSize: int64(len(payload)), ChunkSize: len(payload)},
			externalV2BulkPacketPath{Conns: receivers, Addrs: externalV2BulkPacketTestAddrs(senders)},
			auth,
			metrics,
			false,
		)
		receiveErr <- err
	}()

	released := false
	defer func() {
		if !released {
			close(setupRelease)
		}
	}()
	select {
	case <-setupBlocked:
	case <-ctx.Done():
		t.Fatalf("receiver did not reach no-probe payload setup: %v", ctx.Err())
	}
	metrics.mu.Lock()
	engineBeforePayload := metrics.filePayloadEngine
	metrics.mu.Unlock()
	if engineBeforePayload != "" {
		t.Fatalf("no-probe receiver selected engine before authenticated payload: %q", engineBeforePayload)
	}

	close(setupRelease)
	released = true
	_, err = sendExternalV2BulkBlockPacketsWithProbe(
		ctx,
		&BlockSource{Payload: bytes.NewReader(payload), PayloadSize: int64(len(payload)), ChunkSize: len(payload)},
		externalV2BulkPacketPath{Conns: senders, Addrs: externalV2BulkPacketTestAddrs(receiverConns)},
		auth,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-receiveErr; err != nil {
		t.Fatal(err)
	}
	metrics.mu.Lock()
	engineAfterPayload := metrics.filePayloadEngine
	metrics.mu.Unlock()
	if engineAfterPayload != transfertrace.FilePayloadEngineBulk {
		t.Fatalf("no-probe receiver engine after authenticated payload = %q, want %q", engineAfterPayload, transfertrace.FilePayloadEngineBulk)
	}
}

func TestExternalV2BulkPacketTransferRepairsDroppedPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatalf("externalV2BulkPacketAuthForToken() error = %v", err)
	}

	receiveErr := make(chan error, 1)
	var received int64
	var receiveStats externalDirectTransferStats
	go func() {
		var err error
		received, receiveStats, err = receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)),
			ChunkSize:   1180,
			HeaderBytes: 7,
		}, externalV2BulkPacketPath{
			Conns: receivers,
			Addrs: externalV2BulkPacketTestAddrs(senders),
		}, auth, nil)
		receiveErr <- err
	}()

	sendConns := make([]net.PacketConn, 0, len(senders))
	for _, conn := range senders {
		sendConns = append(sendConns, &dropFirstBulkDataPacketConn{PacketConn: conn, modulo: 5})
	}
	sendStats, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
		ChunkSize:   1180,
	}, externalV2BulkPacketPath{
		Conns: sendConns,
		Addrs: externalV2BulkPacketTestAddrs(receivers),
	}, auth, nil)
	if err != nil {
		t.Fatalf("sendExternalV2BulkBlockPackets() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("receiveExternalV2BulkBlockPackets() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
	if received != int64(len(payload))+7 {
		t.Fatalf("received bytes = %d, want payload plus header %d", received, len(payload)+7)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("received payload does not match source payload")
	}
	if sendStats.Retransmits == 0 {
		t.Fatal("send stats retransmits = 0, want repair retransmits")
	}
	if receiveStats.Diagnostics.RepairRequests == 0 {
		t.Fatal("receive stats repair requests = 0, want missing-packet repair requests")
	}
}

func TestExternalV2BulkPacketTransferSurvivesPrimaryControlLaneLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatalf("externalV2BulkPacketAuthForToken() error = %v", err)
	}

	receiveErr := make(chan error, 1)
	var received int64
	var receiveStats externalDirectTransferStats
	receiveConns := append([]net.PacketConn(nil), receivers...)
	receiveConns[0] = &dropBulkControlPacketConn{PacketConn: receivers[0]}
	go func() {
		var err error
		received, receiveStats, err = receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)),
			ChunkSize:   1180,
			HeaderBytes: 7,
		}, externalV2BulkPacketPath{
			Conns: receiveConns,
			Addrs: externalV2BulkPacketTestAddrs(senders),
		}, auth, nil)
		receiveErr <- err
	}()

	sendConns := make([]net.PacketConn, 0, len(senders))
	for _, conn := range senders {
		sendConns = append(sendConns, &dropFirstBulkDataPacketConn{PacketConn: conn, modulo: 5})
	}
	sendStats, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
		ChunkSize:   1180,
	}, externalV2BulkPacketPath{
		Conns: sendConns,
		Addrs: externalV2BulkPacketTestAddrs(receivers),
	}, auth, nil)
	if err != nil {
		t.Fatalf("sendExternalV2BulkBlockPackets() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("receiveExternalV2BulkBlockPackets() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
	if received != int64(len(payload))+7 {
		t.Fatalf("received bytes = %d, want payload plus header %d", received, len(payload)+7)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("received payload does not match source payload")
	}
	if sendStats.Retransmits == 0 {
		t.Fatal("send stats retransmits = 0, want repair retransmits")
	}
	if receiveStats.Diagnostics.RepairRequests == 0 {
		t.Fatal("receive stats repair requests = 0, want missing-packet repair requests")
	}
}

func TestExternalV2BulkPacketRepairsUseAlternateLanes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	sink := newMemoryBlockSink(int64(len(payload)))
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatalf("externalV2BulkPacketAuthForToken() error = %v", err)
	}

	receiveErr := make(chan error, 1)
	var received int64
	var receiveStats externalDirectTransferStats
	go func() {
		var err error
		received, receiveStats, err = receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)),
			ChunkSize:   1180,
			HeaderBytes: 7,
		}, externalV2BulkPacketPath{
			Conns: receivers,
			Addrs: externalV2BulkPacketTestAddrs(senders),
		}, auth, nil)
		receiveErr <- err
	}()

	sendConns := make([]net.PacketConn, 0, len(senders))
	for lane, conn := range senders {
		sendConns = append(sendConns, &dropPrimaryBulkDataPacketConn{
			PacketConn: conn,
			lane:       lane,
			laneCount:  len(senders),
			modulo:     7,
		})
	}
	sendStats, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
		ChunkSize:   1180,
	}, externalV2BulkPacketPath{
		Conns: sendConns,
		Addrs: externalV2BulkPacketTestAddrs(receivers),
	}, auth, nil)
	if err != nil {
		t.Fatalf("sendExternalV2BulkBlockPackets() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("receiveExternalV2BulkBlockPackets() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
	if received != int64(len(payload))+7 {
		t.Fatalf("received bytes = %d, want payload plus header %d", received, len(payload)+7)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("received payload does not match source payload")
	}
	if sendStats.Retransmits == 0 {
		t.Fatal("send stats retransmits = 0, want alternate-lane repair retransmits")
	}
	if receiveStats.Diagnostics.RepairRequests == 0 {
		t.Fatal("receive stats repair requests = 0, want missing-packet repair requests")
	}
}

func TestExternalV2BulkPacketReceiveCoalescesSinkWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	senders, receivers := listenExternalV2BulkPacketTestConns(t, 4)

	packetCount := 20
	payload := bytes.Repeat([]byte("x"), externalV2BulkPacketPayloadSize*packetCount)
	sink := &writeCountingBlockSink{memoryBlockSink: newMemoryBlockSink(int64(len(payload)))}
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatalf("externalV2BulkPacketAuthForToken() error = %v", err)
	}

	receiveErr := make(chan error, 1)
	var received int64
	go func() {
		var err error
		received, _, err = receiveExternalV2BulkBlockPackets(ctx, sink, externalV2BlockReceiveConfig{
			PayloadSize: int64(len(payload)),
			ChunkSize:   externalV2BulkPacketPayloadSize * 8,
			HeaderBytes: 7,
		}, externalV2BulkPacketPath{
			Conns: receivers,
			Addrs: externalV2BulkPacketTestAddrs(senders),
		}, auth, nil)
		receiveErr <- err
	}()

	_, err = sendExternalV2BulkBlockPackets(ctx, &BlockSource{
		Payload:     bytes.NewReader(payload),
		PayloadSize: int64(len(payload)),
		ChunkSize:   externalV2BulkPacketPayloadSize * 8,
	}, externalV2BulkPacketPath{
		Conns: senders,
		Addrs: externalV2BulkPacketTestAddrs(receivers),
	}, auth, nil)
	if err != nil {
		t.Fatalf("sendExternalV2BulkBlockPackets() error = %v", err)
	}
	select {
	case err := <-receiveErr:
		if err != nil {
			t.Fatalf("receiveExternalV2BulkBlockPackets() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receiver: %v", ctx.Err())
	}
	if received != int64(len(payload))+7 {
		t.Fatalf("received bytes = %d, want payload plus header %d", received, len(payload)+7)
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("received payload does not match source payload")
	}
	if sink.writes != 3 {
		t.Fatalf("sink writes = %d, want 3 coalesced group writes", sink.writes)
	}
}

func TestExternalV2BulkPacketDataPacketUsesConservativeMTU(t *testing.T) {
	if got, want := externalV2BulkPacketMaxSize, 1400; got != want {
		t.Fatalf("max packet size = %d, want %d", got, want)
	}
	if got, want := externalV2BulkPacketPayloadSize, 1358; got != want {
		t.Fatalf("payload size = %d, want %d", got, want)
	}
}

func TestExternalV2BulkPacketActiveRepairDoesNotRescanHistory(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 100_000 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 80_000
	for i := range 80_000 {
		receiver.seen[i] = true
	}
	receiver.seen[10] = false
	receiver.receiveRate.update(88_000, time.Second)
	start := time.Unix(50, 0)

	receiver.sendActiveMissing(start)
	first := receiver.missing.stats().ScanChecks
	receiver.sendActiveMissing(start.Add(externalV2BulkPacketActiveRequestInterval))
	second := receiver.missing.stats().ScanChecks
	if first == 0 || second != first {
		t.Fatalf("scan checks first=%d second=%d, want no historical rescan", first, second)
	}
}

func TestExternalV2BulkPacketActiveRepairKeepsRecentReorder(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 100_000 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 50_000
	receiver.receiveRate.update(88_000, time.Second)
	for i := range 50_000 {
		receiver.seen[i] = true
	}
	receiver.seen[49_000] = false
	receiver.sendActiveMissing(time.Unix(60, 0))
	if receiver.repairRequests != 0 {
		t.Fatalf("repair requests = %d, want recent gap inside reorder window", receiver.repairRequests)
	}
}

func TestExternalV2BulkPacketIdleRepairForcesTailGap(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 20 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 1
	receiver.highestSeenPlusOne = 20
	for i := range 20 {
		receiver.seen[i] = true
	}
	receiver.seen[19] = false
	receiver.sendIdleMissing(time.Unix(70, 0))
	if receiver.repairRequests != 1 {
		t.Fatalf("repair requests = %d, want immediate idle request", receiver.repairRequests)
	}
}

func TestExternalV2BulkPacketIdleRepairWaitsForRun(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 20 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.highestSeenPlusOne = 20
	for i := range 20 {
		receiver.seen[i] = true
	}
	receiver.seen[19] = false
	now := time.Unix(80, 0)

	receiver.sendIdleMissing(now)
	if got := receiver.missing.stats().ScanChecks; got != 0 {
		t.Fatalf("pre-run scan checks = %d, want 0", got)
	}
	if receiver.repairRequests != 0 || receiver.controlSeq != 0 {
		t.Fatalf("pre-run repair requests = %d, control writes = %d, want 0, 0", receiver.repairRequests, receiver.controlSeq)
	}

	receiver.runID = 1
	receiver.sendIdleMissing(now)
	if got := receiver.missing.stats().ScanChecks; got != 20 {
		t.Fatalf("started scan checks = %d, want 20", got)
	}
	if receiver.repairRequests != 1 || receiver.controlSeq != 1 {
		t.Fatalf("started repair requests = %d, control writes = %d, want 1, 1", receiver.repairRequests, receiver.controlSeq)
	}
}

func TestExternalV2BulkPacketRepairNoOpAfterReceiveComplete(t *testing.T) {
	tests := []struct {
		name string
		send func(*externalV2BulkPacketReceiver, time.Time)
	}{
		{name: "active", send: (*externalV2BulkPacketReceiver).sendActiveMissing},
		{name: "idle", send: (*externalV2BulkPacketReceiver).sendIdleMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{PayloadSize: 10_000 * externalV2BulkPacketPayloadSize}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
			receiver.runID = 1
			receiver.receivedPackets = receiver.totalPackets
			receiver.highestSeenPlusOne = receiver.totalPackets

			tt.send(receiver, time.Unix(90, 0))
			if got := receiver.missing.stats().ScanChecks; got != 0 {
				t.Fatalf("scan checks = %d, want 0", got)
			}
			if receiver.repairRequests != 0 || receiver.controlSeq != 0 {
				t.Fatalf("repair requests = %d, control writes = %d, want 0, 0", receiver.repairRequests, receiver.controlSeq)
			}
		})
	}
}

func TestExternalV2BulkPacketActiveRepairWaitsForPublicPathReorderWindow(t *testing.T) {
	receiver := &externalV2BulkPacketReceiver{
		totalPackets:       8192,
		seen:               make([]bool, 8192),
		runID:              1,
		highestSeenPlusOne: 4096,
	}

	receiver.sendActiveMissing(time.Now())
	if receiver.repairRequests != 0 {
		t.Fatalf("active repair requests = %d, want 0 while still inside reorder window", receiver.repairRequests)
	}
}

func TestExternalV2BulkPacketRepairLaneRotatesAwayFromPrimary(t *testing.T) {
	primary := externalV2BulkPacketPrimaryLane(6, 4)
	if primary != 2 {
		t.Fatalf("primary lane = %d, want 2", primary)
	}
	for attempt := uint64(0); attempt < 3; attempt++ {
		lane := externalV2BulkPacketRepairLane(6, 4, attempt)
		if lane == primary {
			t.Fatalf("repair attempt %d used primary lane %d", attempt, primary)
		}
	}
	if lane := externalV2BulkPacketRepairLane(6, 1, 0); lane != 0 {
		t.Fatalf("single-lane repair lane = %d, want 0", lane)
	}
}

func TestExternalV2BulkPacketPrimaryCompleteIsAuthenticated(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(
		testExternalV2BulkPacketToken(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealExternalV2BulkPacket(auth.data, externalV2BulkPacketHeader{
		kind:  externalV2BulkPacketPrimaryComplete,
		runID: 91,
		index: 2,
		total: 700,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [externalV2BulkPacketMaximumNonceSize]byte
	header, ok := openExternalV2BulkPacketPrimaryComplete(auth.data, packet, &nonce)
	if !ok || header.runID != 91 || header.total != 700 {
		t.Fatalf("primary-complete open = %#v, %t", header, ok)
	}
	packet[len(packet)-1] ^= 0x80
	if _, ok := openExternalV2BulkPacketPrimaryComplete(auth.data, packet, &nonce); ok {
		t.Fatal("forged primary-complete marker authenticated")
	}
}

func listenExternalV2BulkPacketTestConns(t *testing.T, count int) ([]net.PacketConn, []net.PacketConn) {
	t.Helper()
	senders := make([]net.PacketConn, 0, count)
	receivers := make([]net.PacketConn, 0, count)
	for range count {
		sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen sender packet conn: %v", err)
		}
		t.Cleanup(func() { _ = sender.Close() })
		receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen receiver packet conn: %v", err)
		}
		t.Cleanup(func() { _ = receiver.Close() })
		senders = append(senders, sender)
		receivers = append(receivers, receiver)
	}
	return senders, receivers
}

func externalV2BulkPacketTestAddrs(conns []net.PacketConn) []net.Addr {
	addrs := make([]net.Addr, 0, len(conns))
	for _, conn := range conns {
		addrs = append(addrs, conn.LocalAddr())
	}
	return addrs
}

func testExternalV2BulkPacketToken() token.Token {
	return token.Token{
		SessionID:    [16]byte{1, 2, 3, 4},
		BearerSecret: [32]byte{5, 6, 7, 8},
	}
}

type dropFirstBulkDataPacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	modulo  uint32
	dropped map[uint32]struct{}
}

type scriptedBulkPacketRead struct {
	packet []byte
	err    error
}

type scriptedReadBulkPacketConn struct {
	net.PacketConn
	reads                []scriptedBulkPacketRead
	nextRead             atomic.Int64
	nonzeroReadDeadlines atomic.Int64
}

type repeatingReadBulkPacketConn struct {
	net.PacketConn
	packet []byte
}

type notifyingReadBulkPacketConn struct {
	repeatingReadBulkPacketConn
	read chan struct{}
	once sync.Once
}

func (c *notifyingReadBulkPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.repeatingReadBulkPacketConn.ReadFrom(p)
	c.once.Do(func() { close(c.read) })
	return n, addr, err
}

type trackingExternalV2BulkPacketPayloadPool struct {
	mu      sync.Mutex
	gets    int
	puts    int
	buffers []*externalV2BulkPacketPayloadBuffer
}

func newTrackingExternalV2BulkPacketPayloadPool() *trackingExternalV2BulkPacketPayloadPool {
	return &trackingExternalV2BulkPacketPayloadPool{
		buffers: []*externalV2BulkPacketPayloadBuffer{{
			data: make([]byte, 0, externalV2BulkPacketPayloadSize),
		}},
	}
}

func (p *trackingExternalV2BulkPacketPayloadPool) get() *externalV2BulkPacketPayloadBuffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gets++
	if len(p.buffers) == 0 {
		return &externalV2BulkPacketPayloadBuffer{data: make([]byte, 0, externalV2BulkPacketPayloadSize)}
	}
	last := len(p.buffers) - 1
	buffer := p.buffers[last]
	p.buffers = p.buffers[:last]
	buffer.data = buffer.data[:0]
	return buffer
}

func (p *trackingExternalV2BulkPacketPayloadPool) put(buffer *externalV2BulkPacketPayloadBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.puts++
	buffer.data = buffer.data[:0]
	p.buffers = append(p.buffers, buffer)
}

func (p *trackingExternalV2BulkPacketPayloadPool) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gets, p.puts
}

func (p *trackingExternalV2BulkPacketPayloadPool) putCount() int {
	_, puts := p.counts()
	return puts
}

func (p *trackingExternalV2BulkPacketPayloadPool) result(header externalV2BulkPacketHeader, data []byte) externalV2BulkPacketReceiveResult {
	buffer := p.get()
	buffer.data = append(buffer.data[:0], data...)
	return externalV2BulkPacketReceiveResult{
		header:        header,
		data:          buffer.data,
		payloadBuffer: buffer,
		payloadPool:   p,
	}
}

func (c *repeatingReadBulkPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.packet), nil, nil
}

func (c *repeatingReadBulkPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *scriptedReadBulkPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	index := int(c.nextRead.Add(1) - 1)
	if index >= len(c.reads) {
		return 0, nil, errors.New("unexpected bulk packet read")
	}
	read := c.reads[index]
	return copy(p, read.packet), nil, read.err
}

func (c *scriptedReadBulkPacketConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.nonzeroReadDeadlines.Add(1)
	}
	return nil
}

func testExternalV2BulkPacketControlPacket(t *testing.T, auth externalV2BulkPacketAuth, header externalV2BulkPacketHeader) []byte {
	t.Helper()
	packet, err := sealExternalV2BulkPacket(auth.control, header, nil)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func (c *dropFirstBulkDataPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	header, ok := parseExternalV2BulkPacketHeader(p)
	if !ok || header.kind != externalV2BulkPacketData || c.modulo == 0 || header.index%c.modulo != 0 {
		return c.PacketConn.WriteTo(p, addr)
	}
	c.mu.Lock()
	if c.dropped == nil {
		c.dropped = make(map[uint32]struct{})
	}
	_, alreadyDropped := c.dropped[header.index]
	if !alreadyDropped {
		c.dropped[header.index] = struct{}{}
	}
	c.mu.Unlock()
	if !alreadyDropped {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type dropBulkControlPacketConn struct {
	net.PacketConn
}

func (c *dropBulkControlPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	header, ok := parseExternalV2BulkPacketHeader(p)
	if ok && header.kind != externalV2BulkPacketData {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type shortWriteBulkPacketConn struct {
	net.PacketConn
}

func (c shortWriteBulkPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p) - 1, nil
}

type transientWriteFailureBulkPacketConn struct {
	net.PacketConn
	remaining   atomic.Int64
	attempts    atomic.Int64
	attempted   chan struct{}
	attemptOnce sync.Once
}

func (c *transientWriteFailureBulkPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.attempts.Add(1)
	if c.attempted != nil {
		c.attemptOnce.Do(func() { close(c.attempted) })
	}
	if c.remaining.Add(-1) >= 0 {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "udp4",
			Source: c.LocalAddr(),
			Addr:   addr,
			Err: &os.SyscallError{
				Syscall: "sendto",
				Err:     syscall.ENOBUFS,
			},
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

type deadlineBlockingBulkPacketConn struct {
	net.PacketConn
	started     chan struct{}
	unblocked   chan struct{}
	startOnce   sync.Once
	unblockOnce sync.Once
	mu          sync.Mutex
	deadline    time.Time
}

type lifecycleBulkPacketConn struct {
	net.PacketConn
	started     chan struct{}
	unblocked   chan struct{}
	startOnce   sync.Once
	unblockOnce sync.Once
	mu          sync.Mutex
	read        time.Time
	write       time.Time
}

var errTestBulkPacketSetReadDeadline = errors.New("test bulk packet read deadline")

var (
	errTestBulkPacketSetWriteDeadline          = errors.New("test bulk packet write deadline")
	errTestBulkPacketSetDeadline               = errors.New("test bulk packet generic deadline")
	errTestBulkPacketBlockedWrite              = errors.New("test bulk packet blocked write")
	errTestBulkPacketCleanupState              = errors.New("test bulk packet cleanup state")
	errTestBulkPacketPostHelloReadDeadline     = errors.New("test bulk packet post-HELLO read deadline")
	errTestBulkPacketPostHelloWriteInterrupted = errors.New("test bulk packet post-HELLO write interrupted")
)

type readDeadlineFailBulkPacketConn struct {
	net.PacketConn
	release     chan struct{}
	releaseOnce sync.Once
	readCalled  atomic.Bool
}

func (c *readDeadlineFailBulkPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	c.readCalled.Store(true)
	<-c.release
	return 0, nil, net.ErrClosed
}

func (c *readDeadlineFailBulkPacketConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		return errTestBulkPacketSetReadDeadline
	}
	return c.PacketConn.SetReadDeadline(deadline)
}

func (c *readDeadlineFailBulkPacketConn) forceReadReturn() {
	c.releaseOnce.Do(func() { close(c.release) })
}

type deadlineFailureBulkPacketConn struct {
	net.PacketConn
	started   chan struct{}
	unblocked chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newDeadlineFailureBulkPacketConn(conn net.PacketConn) *deadlineFailureBulkPacketConn {
	return &deadlineFailureBulkPacketConn{
		PacketConn: conn,
		started:    make(chan struct{}),
		unblocked:  make(chan struct{}),
	}
}

func (c *deadlineFailureBulkPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	<-c.unblocked
	return 0, errTestBulkPacketBlockedWrite
}

func (c *deadlineFailureBulkPacketConn) SetWriteDeadline(time.Time) error {
	return errTestBulkPacketSetWriteDeadline
}

func (c *deadlineFailureBulkPacketConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return errTestBulkPacketCleanupState
	}
	return c.PacketConn.SetReadDeadline(deadline)
}

func (c *deadlineFailureBulkPacketConn) SetDeadline(time.Time) error {
	return errTestBulkPacketSetDeadline
}

func (c *deadlineFailureBulkPacketConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		close(c.unblocked)
		closeErr = c.PacketConn.Close()
	})
	return closeErr
}

func (c *deadlineFailureBulkPacketConn) forceClose() {
	_ = c.Close()
}

type postHelloWorkerFailureBulkPacketConn struct {
	net.PacketConn
	writeStarted chan struct{}
	unblocked    chan struct{}
	readCalls    atomic.Int64
	startOnce    sync.Once
	unblockOnce  sync.Once
	closeOnce    sync.Once
}

func newPostHelloWorkerFailureBulkPacketConn(conn net.PacketConn) *postHelloWorkerFailureBulkPacketConn {
	return &postHelloWorkerFailureBulkPacketConn{
		PacketConn:   conn,
		writeStarted: make(chan struct{}),
		unblocked:    make(chan struct{}),
	}
}

func (c *postHelloWorkerFailureBulkPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.unblocked
	return 0, errTestBulkPacketPostHelloWriteInterrupted
}

func (c *postHelloWorkerFailureBulkPacketConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.PacketConn.SetReadDeadline(deadline)
	}
	if c.readCalls.Add(1) == 1 {
		return c.PacketConn.SetReadDeadline(deadline)
	}
	<-c.writeStarted
	return errTestBulkPacketPostHelloReadDeadline
}

func (c *postHelloWorkerFailureBulkPacketConn) SetWriteDeadline(deadline time.Time) error {
	err := c.PacketConn.SetWriteDeadline(deadline)
	if err == nil && !deadline.IsZero() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
	}
	return err
}

func (c *postHelloWorkerFailureBulkPacketConn) SetDeadline(deadline time.Time) error {
	err := c.PacketConn.SetDeadline(deadline)
	if err == nil && !deadline.IsZero() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
	}
	return err
}

func (c *postHelloWorkerFailureBulkPacketConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
		closeErr = c.PacketConn.Close()
	})
	return closeErr
}

func (c *postHelloWorkerFailureBulkPacketConn) forceClose() {
	_ = c.Close()
}

func newLifecycleBulkPacketConn(conn net.PacketConn) *lifecycleBulkPacketConn {
	return &lifecycleBulkPacketConn{
		PacketConn: conn,
		started:    make(chan struct{}),
		unblocked:  make(chan struct{}),
	}
}

func (c *lifecycleBulkPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	<-c.unblocked
	return 0, context.DeadlineExceeded
}

func (c *lifecycleBulkPacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.read = deadline
	c.mu.Unlock()
	return c.PacketConn.SetReadDeadline(deadline)
}

func (c *lifecycleBulkPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.write = deadline
	c.mu.Unlock()
	err := c.PacketConn.SetWriteDeadline(deadline)
	if err == nil && !deadline.IsZero() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
	}
	return err
}

func (c *lifecycleBulkPacketConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.read = deadline
	c.write = deadline
	c.mu.Unlock()
	err := c.PacketConn.SetDeadline(deadline)
	if err == nil && !deadline.IsZero() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
	}
	return err
}

func (c *lifecycleBulkPacketConn) deadlines() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read, c.write
}

func (c *deadlineBlockingBulkPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	<-c.unblocked
	return 0, context.DeadlineExceeded
}

func (c *deadlineBlockingBulkPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	if !deadline.IsZero() {
		c.unblockOnce.Do(func() { close(c.unblocked) })
	}
	return nil
}

func (c *deadlineBlockingBulkPacketConn) writeDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

type dropPrimaryBulkDataPacketConn struct {
	net.PacketConn
	lane      int
	laneCount int
	modulo    uint32
}

func (c *dropPrimaryBulkDataPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	header, ok := parseExternalV2BulkPacketHeader(p)
	if ok && header.kind == externalV2BulkPacketData && c.modulo != 0 && header.index%c.modulo == 0 && int(header.index%uint32(c.laneCount)) == c.lane {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type writeCountingBlockSink struct {
	*memoryBlockSink
	writes int
}

type blockingReadBufferBulkPacketConn struct {
	net.PacketConn
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingReadBufferBulkPacketConn) SetReadBuffer(bytes int) error {
	c.once.Do(func() { close(c.blocked) })
	<-c.release
	if setter, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(bytes)
	}
	return nil
}

func (s *writeCountingBlockSink) WriteAt(p []byte, off int64) (int, error) {
	s.writes++
	return s.memoryBlockSink.WriteAt(p, off)
}
