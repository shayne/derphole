// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketRepairCadenceContinuesUnderContinuousData(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	conn := &captureControlExternalV2BulkPacketConn{writes: make(chan []byte, 1)}
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{
		PayloadSize: 2 * externalV2BulkPacketPayloadSize,
	}, externalV2BulkPacketPath{
		Conns: []net.PacketConn{conn},
		Addrs: []net.Addr{dummyExternalV2BulkPacketAddr("peer")},
	}, auth, nil)
	receiver.runID = 7
	receiver.seen[0] = true
	receiver.receivedPackets = 1
	receiver.highestSeenPlusOne = 1
	receiver.stopHello = func() {}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	dataCh := make(chan externalV2BulkPacketReceiveResult, 4096)
	duplicate := externalV2BulkPacketReceiveResult{header: externalV2BulkPacketHeader{kind: externalV2BulkPacketData, runID: 7, index: 0, total: 2}}
	go func() {
		for {
			select {
			case dataCh <- duplicate:
			case <-ctx.Done():
				return
			}
		}
	}()
	runDone := make(chan error, 1)
	go func() {
		_, _, err := receiver.run(ctx, dataCh, make(chan error))
		runDone <- err
	}()

	select {
	case packet := <-conn.writes:
		header, payload, ok := openExternalV2BulkPacket(auth.control, packet)
		if !ok || header.kind != externalV2BulkPacketMiss {
			t.Fatalf("control packet = header %+v ok %v", header, ok)
		}
		missing := decodeExternalV2BulkPacketMissing(payload)
		if len(missing) != 1 || missing[0] != 1 {
			t.Fatalf("missing = %v, want [1]", missing)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("repair cadence was starved by continuous data")
	}
	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("receiver error = %v, want context.Canceled", err)
	}
}

func TestExternalV2BulkPacketRepairTickDoesNotRequestUnsentLookaheadDuringActiveProgress(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{
		PayloadSize: 20_000 * externalV2BulkPacketPayloadSize,
	}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 7
	receiver.highestSeenPlusOne = 10_000
	receiver.receivedPackets = 10_000
	for index := range uint32(10_000) {
		receiver.seen[index] = true
	}
	now := time.Unix(100, 0)
	receiver.lastDataAt = now

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle / 2))
	if receiver.repairRequests != 0 {
		t.Fatalf("active repair requests = %d, want 0 for unsent lookahead", receiver.repairRequests)
	}

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle))
	if receiver.repairRequests == 0 {
		t.Fatal("idle repair requests = 0, want tail/lookahead repair after a full idle interval")
	}
}

type captureControlExternalV2BulkPacketConn struct {
	writes chan []byte
}

func (c *captureControlExternalV2BulkPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	packet := append([]byte(nil), payload...)
	select {
	case c.writes <- packet:
	default:
	}
	return len(payload), nil
}

func (*captureControlExternalV2BulkPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("unexpected read")
}
func (*captureControlExternalV2BulkPacketConn) Close() error { return nil }
func (*captureControlExternalV2BulkPacketConn) LocalAddr() net.Addr {
	return dummyExternalV2BulkPacketAddr("local")
}
func (*captureControlExternalV2BulkPacketConn) SetDeadline(time.Time) error      { return nil }
func (*captureControlExternalV2BulkPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*captureControlExternalV2BulkPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dummyExternalV2BulkPacketAddr string

func (a dummyExternalV2BulkPacketAddr) Network() string { return "udp" }
func (a dummyExternalV2BulkPacketAddr) String() string  { return string(a) }
