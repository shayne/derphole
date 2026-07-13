// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"testing"
	"time"
)

func TestExternalV2BulkPacketRepairTickRequestsOnlyOldGapsDuringActiveProgress(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{
		PayloadSize: 20_000 * externalV2BulkPacketPayloadSize,
	}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 7
	receiver.highestSeenPlusOne = 10_000
	receiver.receivedPackets = 10_000
	for index := range uint32(10_000) {
		receiver.seen[index] = true
	}
	receiver.seen[0] = false
	receiver.receivedPackets--
	now := time.Unix(100, 0)
	receiver.lastDataAt = now

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle / 2))
	if receiver.repairRequests != 1 {
		t.Fatalf("active repair requests = %d, want one old-gap request", receiver.repairRequests)
	}
	if checks := receiver.missing.stats().ScanChecks; checks != uint64(10_000-externalV2BulkPacketMinimumActiveRepairTrail) {
		t.Fatalf("active scan checks = %d, want old high-water range without unsent lookahead", checks)
	}

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle))
	if receiver.repairRequests == 0 {
		t.Fatal("idle repair requests = 0, want tail/lookahead repair after a full idle interval")
	}
}

func TestExternalV2BulkPacketRepairTickUsesArrivalBitmapWhileAuthenticationLags(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{
		PayloadSize: 20_000 * externalV2BulkPacketPayloadSize,
	}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 7
	receiver.highestSeenPlusOne = 10_000
	receiver.receivedPackets = 10_000
	for index := range uint32(10_000) {
		receiver.seen[index] = true
	}
	receiver.seen[0] = false
	receiver.receivedPackets--
	now := time.Unix(100, 0)
	receiver.lastDataAt = now.Add(-time.Second)
	receiver.arrivals.observeActivity(now)

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle / 2))
	if receiver.repairRequests != 1 {
		t.Fatalf("active repair requests = %d, want one genuinely absent old-gap request", receiver.repairRequests)
	}

	receiver.repairTick(now.Add(externalV2BulkPacketReadIdle))
	if receiver.repairRequests == 0 {
		t.Fatal("idle repair requests = 0, want repair after accepted socket traffic stops")
	}
}

func TestExternalV2BulkPacketPrimaryCompleteForcesTailRepair(t *testing.T) {
	receiver := newExternalV2BulkPacketReceiver(nil, externalV2BlockReceiveConfig{
		PayloadSize: 10 * externalV2BulkPacketPayloadSize,
	}, externalV2BulkPacketPath{}, externalV2BulkPacketAuth{}, nil)
	receiver.runID = 7
	receiver.highestSeenPlusOne = receiver.totalPackets
	receiver.receivedPackets = receiver.totalPackets - 1
	for index := range receiver.totalPackets {
		receiver.seen[index] = true
	}
	receiver.seen[3] = false
	receiver.lastDataAt = time.Unix(200, 0)

	if err := receiver.handleDataBatch(externalV2BulkPacketReceiveBatch{results: []externalV2BulkPacketReceiveResult{{
		header: externalV2BulkPacketHeader{
			kind:  externalV2BulkPacketPrimaryComplete,
			runID: receiver.runID,
			total: receiver.totalPackets,
		},
		primaryComplete: true,
	}}}, receiver.lastDataAt); err != nil {
		t.Fatal(err)
	}
	if !receiver.primaryComplete {
		t.Fatal("authenticated primary-complete marker did not arm fast repair")
	}
	receiver.sendPrimaryCompleteRepair(receiver.lastDataAt.Add(time.Millisecond))
	if receiver.repairRequests == 0 {
		t.Fatal("primary-complete repair waited for the normal idle interval")
	}
	if receiver.primaryComplete {
		t.Fatal("primary-complete repair remained armed after firing")
	}
}
