// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"testing"
)

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
