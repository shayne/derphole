// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"testing"
)

func TestExternalV2BulkPacketReceiveMemoryCoversDirectWindowWithBoundedBuffers(t *testing.T) {
	const productionLanes = externalV2BulkPacketMaximumDataLanes
	residentGroupBytes := externalV2BulkPacketReceiveGroupLimit * externalV2BulkPacketWriteGroup
	concurrentBatchHeadroom := productionLanes * externalV2BulkPacketDataBatchSize * externalV2BulkPacketPayloadSize
	if residentGroupBytes < externalV2BulkPacketBufferedReceiveWindow+concurrentBatchHeadroom {
		t.Fatalf("resident groups = %d, need at least buffered window %d + concurrent batch headroom %d", residentGroupBytes, externalV2BulkPacketBufferedReceiveWindow, concurrentBatchHeadroom)
	}
	if residentGroupBytes > 40<<20 {
		t.Fatalf("resident groups = %d, want at most 40 MiB on a small receiver", residentGroupBytes)
	}
	if externalPacketConnSocketBufferBytes > 2<<20 {
		t.Fatalf("socket buffer request = %d per lane, want at most 2 MiB", externalPacketConnSocketBufferBytes)
	}
	if externalV2BulkPacketWriteGroup < 1<<20 {
		t.Fatalf("write group = %d, want at least 1 MiB to amortize pwrite", externalV2BulkPacketWriteGroup)
	}
	queuedWriterBytes := externalV2BulkPacketWriterQueue * externalV2BulkPacketWriteGroup
	if queuedWriterBytes < 2*externalV2BulkPacketBufferedReceiveWindow {
		t.Fatalf("writer queue = %d bytes, want two direct receive windows", queuedWriterBytes)
	}
}

func TestExternalV2BulkPacketAsyncAssemblerCommitsAfterWriterDrain(t *testing.T) {
	payload := make([]byte, 600<<10+37)
	for index := range payload {
		payload[index] = byte((index*17 + 3) % 251)
	}
	totalPackets := externalV2BulkPacketCount(int64(len(payload)))
	sink := newMemoryBlockSink(int64(len(payload)))
	assembler := newExternalV2BulkPacketAsyncReceiveAssembler(
		context.Background(),
		sink,
		externalV2BlockReceiveConfig{PayloadSize: int64(len(payload)), ChunkSize: 1 << 20},
		totalPackets,
		nil,
	)
	for index := uint32(0); index < totalPackets; index++ {
		offset := int(index) * externalV2BulkPacketPayloadSize
		end := min(len(payload), offset+externalV2BulkPacketPayloadSize)
		committed, err := assembler.add(index, payload[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		if committed != 0 {
			t.Fatalf("add committed %d bytes synchronously", committed)
		}
	}
	committed, err := assembler.finish()
	if err != nil {
		t.Fatal(err)
	}
	if committed != int64(len(payload)) {
		t.Fatalf("committed = %d, want %d", committed, len(payload))
	}
	if !bytes.Equal(sink.bytes(), payload) {
		t.Fatal("assembled payload does not match")
	}
	if peak := assembler.writerQueuePeak(); peak == 0 || peak > externalV2BulkPacketWriterQueue {
		t.Fatalf("writer queue peak = %d", peak)
	}
}

func TestExternalV2BulkPacketAssemblerSpillsIncompleteGroupsWithoutDropping(t *testing.T) {
	const packetsPerGroup = uint32(8)
	const extraGroups = uint32(5)
	totalGroups := uint32(externalV2BulkPacketReceiveGroupLimit) + extraGroups
	totalPackets := totalGroups * packetsPerGroup
	payloadSize := int64(totalPackets) * externalV2BulkPacketPayloadSize
	sink := newMemoryBlockSink(payloadSize)
	assembler := newExternalV2BulkPacketReceiveAssemblerWithGroup(
		sink,
		externalV2BlockReceiveConfig{PayloadSize: payloadSize},
		totalPackets,
		int(packetsPerGroup)*externalV2BulkPacketPayloadSize,
	)
	data := bytes.Repeat([]byte{0x5a}, externalV2BulkPacketPayloadSize)
	accepted := 0
	for groupID := uint32(0); groupID < totalGroups; groupID++ {
		_, ok, err := assembler.addPacket(groupID*packetsPerGroup, data)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			accepted++
		}
	}
	if accepted != int(totalGroups) {
		t.Fatalf("accepted incomplete groups = %d, want %d", accepted, totalGroups)
	}
	if got := len(assembler.groups); got != externalV2BulkPacketReceiveGroupLimit {
		t.Fatalf("resident incomplete groups = %d, want %d", got, externalV2BulkPacketReceiveGroupLimit)
	}
	if !assembler.flushedGroups[0] {
		t.Fatal("oldest incomplete group was not marked flushed")
	}
	if got := sink.bytes()[:externalV2BulkPacketPayloadSize]; !bytes.Equal(got, data) {
		t.Fatal("oldest incomplete group payload was not spilled to the sink")
	}

	late := bytes.Repeat([]byte{0xa5}, externalV2BulkPacketPayloadSize)
	_, ok, err := assembler.addPacket(1, late)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("late packet for a flushed group was rejected")
	}
	if got := len(assembler.groups); got != externalV2BulkPacketReceiveGroupLimit {
		t.Fatalf("late packet recreated resident group: got %d groups", got)
	}
	start := externalV2BulkPacketPayloadSize
	if got := sink.bytes()[start : start+externalV2BulkPacketPayloadSize]; !bytes.Equal(got, late) {
		t.Fatal("late packet for a flushed group was not written directly")
	}
}
