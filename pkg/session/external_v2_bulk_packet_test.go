// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"go4.org/mem"
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
		_, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil)
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
		_, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
			Payload:     bytes.NewReader([]byte{0x5a}),
			PayloadSize: 1,
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil)
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
		_, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil)
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
		_, err := sendExternalV2BulkBlockPackets(ctx, &BlockSource{
			Payload:     bytes.NewReader(payload),
			PayloadSize: int64(len(payload)),
		}, externalV2BulkPacketPath{
			Conns: []net.PacketConn{conn},
			Addrs: externalV2BulkPacketTestAddrs(receivers),
		}, auth, nil)
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
		metrics:    metrics,
		laneCount:  8,
		pacer:      rate.NewLimiter(externalV2BulkPacketRateLimit(1000), externalV2BulkPacketPaceBurstBytes),
		controller: newExternalV2BulkPacketController(),
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
		rows[1]["repair_bytes"] != "16296" {
		t.Fatalf("controller rows = %#v", rows)
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

func TestExternalV2BulkPacketMissingBatchesHonorsLimit(t *testing.T) {
	seen := []bool{true, false, false, true, false}

	batches := externalV2BulkPacketMissingBatches(seen, 3)
	if got, want := len(batches), 1; got != want {
		t.Fatalf("len(batches) = %d, want %d", got, want)
	}
	if got, want := batches[0], []uint32{1, 2}; !slices.Equal(got, want) {
		t.Fatalf("limited missing batch = %v, want %v", got, want)
	}

	batches = externalV2BulkPacketMissingBatches(seen, 99)
	if got, want := len(batches), 1; got != want {
		t.Fatalf("len(batches) after clamped limit = %d, want %d", got, want)
	}
	if got, want := batches[0], []uint32{1, 2, 4}; !slices.Equal(got, want) {
		t.Fatalf("clamped missing batch = %v, want %v", got, want)
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

func (s *writeCountingBlockSink) WriteAt(p []byte, off int64) (int, error) {
	s.writes++
	return s.memoryBlockSink.WriteAt(p, off)
}
