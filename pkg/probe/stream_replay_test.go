// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

func TestStreamReplayWindowRetainsRepairPacketsUntilAckFloor(t *testing.T) {
	runID := testRunID(0x71)
	window := newStreamReplayWindow(runID, 1024, 16<<10, nil)

	packet, err := window.AddDataPacket(0, 7, 4096, []byte("repair-me"))
	if err != nil {
		t.Fatalf("AddDataPacket() error = %v", err)
	}
	if got := window.Packet(7); !bytes.Equal(got, packet) {
		t.Fatalf("Packet(7) = %x, want original packet %x", got, packet)
	}

	decoded, err := UnmarshalPacket(window.Packet(7), nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket(Packet(7)) error = %v", err)
	}
	if decoded.Type != PacketTypeData || decoded.RunID != runID || decoded.Seq != 7 || decoded.Offset != 4096 || string(decoded.Payload) != "repair-me" {
		t.Fatalf("decoded repair packet = %+v", decoded)
	}

	window.AckFloor(8)
	if got := window.Packet(7); got != nil {
		t.Fatalf("Packet(7) after AckFloor(8) = %x, want nil", got)
	}
}

func TestStreamReplayWindowEnforcesByteBudgetAndFreesAckedPackets(t *testing.T) {
	window := newStreamReplayWindow(testRunID(0x72), 1024, uint64(headerLen+4), nil)

	if _, err := window.AddDataPacket(0, 0, 0, []byte("aaaa")); err != nil {
		t.Fatalf("AddDataPacket(seq 0) error = %v", err)
	}
	if _, err := window.AddDataPacket(0, 1, 4, []byte("bbbb")); !errors.Is(err, errStreamReplayWindowFull) {
		t.Fatalf("AddDataPacket(seq 1) error = %v, want %v", err, errStreamReplayWindowFull)
	}

	window.AckFloor(1)
	if _, err := window.AddDataPacket(0, 1, 4, []byte("bbbb")); err != nil {
		t.Fatalf("AddDataPacket(seq 1) after ack error = %v", err)
	}
	if got := window.RetainedBytes(); got == 0 || got > uint64(headerLen+4) {
		t.Fatalf("RetainedBytes() = %d, want within one-packet budget", got)
	}
}

func TestStreamReplayWindowAEADAddDataPacketKeepsAllocationsBounded(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	payload := bytes.Repeat([]byte("x"), 1384)
	window := newStreamReplayWindow(testRunID(0x74), len(payload), 64<<20, aead)

	if _, err := window.AddDataPacket(0, 0, 0, payload); err != nil {
		t.Fatalf("warm AddDataPacket() error = %v", err)
	}
	window.AckFloor(1)

	seq := uint64(1)
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := window.AddDataPacket(0, seq, seq*uint64(len(payload)), payload); err != nil {
			t.Fatalf("AddDataPacket() error = %v", err)
		}
		window.AckFloor(seq + 1)
		seq++
	})
	if allocs > 0 {
		t.Fatalf("AddDataPacket() allocations = %.2f, want 0 steady-state allocations", allocs)
	}
}

func BenchmarkStreamReplayWindowAddAck(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1384)
	window := newStreamReplayWindow(testRunID(0x73), len(payload), 64<<20, nil)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		seq := uint64(i)
		if _, err := window.AddDataPacket(0, seq, seq*uint64(len(payload)), payload); err != nil {
			b.Fatal(err)
		}
		window.AckFloor(seq)
	}
}
