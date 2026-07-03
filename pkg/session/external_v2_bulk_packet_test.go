// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
)

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

func TestExternalV2BulkPacketBackoffMbpsClampsToMinimum(t *testing.T) {
	if got, want := externalV2BulkPacketBackoffMbps(800), int64(680); got != want {
		t.Fatalf("backoff from 800 = %d, want %d", got, want)
	}
	if got, want := externalV2BulkPacketBackoffMbps(140), int64(externalV2BulkPacketMinPaceMbps); got != want {
		t.Fatalf("backoff near minimum = %d, want %d", got, want)
	}
	if got, want := externalV2BulkPacketBackoffMbps(20), int64(externalV2BulkPacketMinPaceMbps); got != want {
		t.Fatalf("backoff below minimum = %d, want %d", got, want)
	}
}

func TestExternalV2BulkPacketBackoffPaceUpdatesLimiter(t *testing.T) {
	var current atomic.Int64
	var lastBackoff atomic.Int64
	current.Store(externalV2BulkPacketPaceMbps)
	pacer := rate.NewLimiter(externalV2BulkPacketRateLimit(externalV2BulkPacketPaceMbps), externalV2BulkPacketPaceBurst)

	externalV2BulkPacketBackoffPace(pacer, &current, &lastBackoff)
	if got, want := current.Load(), int64(680); got != want {
		t.Fatalf("current pace after first backoff = %d, want %d", got, want)
	}
	if got, want := pacer.Limit(), externalV2BulkPacketRateLimit(680); got != want {
		t.Fatalf("pacer limit after first backoff = %v, want %v", got, want)
	}

	externalV2BulkPacketBackoffPace(pacer, &current, &lastBackoff)
	if got, want := current.Load(), int64(680); got != want {
		t.Fatalf("current pace after immediate backoff = %d, want %d", got, want)
	}

	lastBackoff.Store(time.Now().Add(-externalV2BulkPacketPaceBackoff - time.Millisecond).UnixNano())
	externalV2BulkPacketBackoffPace(pacer, &current, &lastBackoff)
	if got, want := current.Load(), int64(578); got != want {
		t.Fatalf("current pace after delayed backoff = %d, want %d", got, want)
	}
}

func TestExternalV2BulkPacketBackoffRequiresDenseMissingBatch(t *testing.T) {
	if externalV2BulkPacketShouldBackoffForMissing(externalV2BulkPacketBackoffMissing - 1) {
		t.Fatal("sparse missing batch triggered rate backoff")
	}
	if !externalV2BulkPacketShouldBackoffForMissing(externalV2BulkPacketBackoffMissing) {
		t.Fatal("dense missing batch did not trigger rate backoff")
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
