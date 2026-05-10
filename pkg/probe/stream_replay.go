// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"crypto/cipher"
	"errors"
	"sync"
)

var errStreamReplayWindowFull = errors.New("stream replay window full")

const defaultStreamReplayWindowBytes = 256 << 20

type streamReplayWindow struct {
	mu           sync.Mutex
	runID        [16]byte
	maxBytes     uint64
	packetAEAD   cipher.AEAD
	packetStride int
	slabSize     int
	slotsPerSlab int
	slots        []streamReplaySlot
	slabs        [][]byte
	retained     uint64
	maxRetained  uint64
	ackFloor     uint64
	nonce        [12]byte
}

type streamReplaySlot struct {
	seq     uint64
	packet  []byte
	bytes   uint64
	present bool
}

func newStreamReplayWindow(runID [16]byte, chunkSize int, maxBytes uint64, packetAEAD cipher.AEAD) *streamReplayWindow {
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if maxBytes == 0 {
		maxBytes = defaultStreamReplayWindowBytes
	}
	overhead := 0
	if packetAEAD != nil {
		overhead = packetAEAD.Overhead()
	}
	packetStride := headerLen + chunkSize + overhead
	if packetStride <= headerLen {
		packetStride = headerLen + 1 + overhead
	}
	slotCount := int(maxBytes / uint64(packetStride))
	if slotCount < 1 {
		slotCount = 1
	}
	slabSize := blastRepairMemorySlab
	if maxBytes < uint64(slabSize) {
		slabSize = int(max(maxBytes, uint64(packetStride)))
	}
	slotsPerSlab := slabSize / packetStride
	if slotsPerSlab < 1 {
		slotsPerSlab = 1
	}
	slabCount := (slotCount + slotsPerSlab - 1) / slotsPerSlab
	return &streamReplayWindow{
		runID:        runID,
		maxBytes:     maxBytes,
		packetAEAD:   packetAEAD,
		packetStride: packetStride,
		slabSize:     slabSize,
		slotsPerSlab: slotsPerSlab,
		slots:        make([]streamReplaySlot, slotCount),
		slabs:        make([][]byte, slabCount),
	}
}

func (w *streamReplayWindow) AddDataPacket(stripeID uint16, seq uint64, offset uint64, payload []byte) ([]byte, error) {
	return w.AddPacket(PacketTypeData, stripeID, seq, offset, payload)
}

func (w *streamReplayWindow) AddPacket(packetType PacketType, stripeID uint16, seq uint64, offset uint64, payload []byte) ([]byte, error) {
	if w == nil {
		return nil, errors.New("nil stream replay window")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	slotIndex := int(seq % uint64(len(w.slots)))
	slot := &w.slots[slotIndex]
	if slot.present && slot.seq != seq {
		return nil, errStreamReplayWindowFull
	}
	packetBytes := uint64(headerLen + len(payload))
	if w.packetAEAD != nil {
		packetBytes += uint64(w.packetAEAD.Overhead())
	}
	if packetBytes > uint64(w.packetStride) {
		return nil, errors.New("stream replay packet exceeds slot size")
	}
	retainedAfterReplace := w.retained
	if slot.present && slot.bytes <= retainedAfterReplace {
		retainedAfterReplace -= slot.bytes
	}
	if w.maxBytes > 0 && retainedAfterReplace+packetBytes > w.maxBytes {
		return nil, errStreamReplayWindowFull
	}
	packetBuf := w.packetBufferForSlot(slotIndex, int(packetBytes))
	wire, err := marshalBlastPayloadPacketInto(packetBuf, packetType, w.runID, stripeID, seq, offset, 0, 0, payload, w.packetAEAD, &w.nonce)
	if err != nil {
		return nil, err
	}
	if slot.present {
		w.retained -= min(w.retained, slot.bytes)
	}
	slot.seq = seq
	slot.packet = wire
	slot.bytes = packetBytes
	slot.present = true
	w.retained += packetBytes
	w.maxRetained = max(w.maxRetained, w.retained)
	return wire, nil
}

func (w *streamReplayWindow) AckFloor(seq uint64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq <= w.ackFloor {
		return
	}
	for acked := w.ackFloor; acked < seq; acked++ {
		w.delete(acked)
	}
	w.ackFloor = seq
}

func (w *streamReplayWindow) Packet(seq uint64) []byte {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	slot := w.slot(seq)
	if slot == nil || !slot.present || slot.seq != seq {
		return nil
	}
	return slot.packet
}

func (w *streamReplayWindow) RetainedBytes() uint64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.retained
}

func (w *streamReplayWindow) MaxRetainedBytes() uint64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.maxRetained
}

func (w *streamReplayWindow) MaxBytes() uint64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.maxBytes
}

func (w *streamReplayWindow) delete(seq uint64) {
	slot := w.slot(seq)
	if slot == nil || !slot.present || slot.seq != seq {
		return
	}
	if slot.bytes >= w.retained {
		w.retained = 0
	} else {
		w.retained -= slot.bytes
	}
	slot.present = false
	slot.packet = nil
	slot.bytes = 0
}

func (w *streamReplayWindow) slot(seq uint64) *streamReplaySlot {
	if w == nil || len(w.slots) == 0 {
		return nil
	}
	return &w.slots[int(seq%uint64(len(w.slots)))]
}

func (w *streamReplayWindow) packetBufferForSlot(slotIndex int, packetBytes int) []byte {
	slabIndex := slotIndex / w.slotsPerSlab
	slabOffset := (slotIndex % w.slotsPerSlab) * w.packetStride
	if w.slabs[slabIndex] == nil {
		w.slabs[slabIndex] = make([]byte, w.slabSize)
	}
	return w.slabs[slabIndex][slabOffset : slabOffset+packetBytes]
}
