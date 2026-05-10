// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	ProtocolVersion = 2
	headerLen       = 52
)

const packetAEADNonceSeqBits = 40

type PacketType uint8

const (
	PacketTypeHello PacketType = iota + 1
	PacketTypeHelloAck
	PacketTypeData
	PacketTypeAck
	PacketTypeDone
	PacketTypeStats
	PacketTypeRepairRequest
	PacketTypeRepairComplete
	PacketTypeParity
)

type Packet struct {
	Version  uint8
	Type     PacketType
	StripeID uint16
	RunID    [16]byte
	Seq      uint64
	Offset   uint64
	AckFloor uint64
	AckMask  uint64
	Payload  []byte
}

func MarshalPacket(p Packet, aead cipher.AEAD) ([]byte, error) {
	capacity := headerLen + len(p.Payload)
	if aead != nil {
		capacity += aead.Overhead()
	}
	buf := make([]byte, headerLen, capacity)
	buf[0] = p.Version
	buf[1] = byte(p.Type)
	binary.BigEndian.PutUint16(buf[2:4], p.StripeID)
	copy(buf[4:20], p.RunID[:])
	binary.BigEndian.PutUint64(buf[20:28], p.Seq)
	binary.BigEndian.PutUint64(buf[28:36], p.Offset)
	binary.BigEndian.PutUint64(buf[36:44], p.AckFloor)
	binary.BigEndian.PutUint64(buf[44:52], p.AckMask)
	if aead != nil {
		var nonce [12]byte
		if aead.NonceSize() != len(nonce) {
			return nil, errors.New("unsupported packet AEAD nonce size")
		}
		nonceBuf := nonce[:]
		if err := packetAEADNonceTo(nonceBuf, buf[:headerLen]); err != nil {
			return nil, err
		}
		return aead.Seal(buf, nonceBuf, p.Payload, buf[:headerLen]), nil
	}
	buf = buf[:headerLen+len(p.Payload)]
	copy(buf[52:], p.Payload)
	return buf, nil
}

func UnmarshalPacket(buf []byte, aead cipher.AEAD) (Packet, error) {
	if len(buf) < headerLen {
		return Packet{}, errors.New("short packet")
	}
	if buf[0] != ProtocolVersion {
		return Packet{}, errors.New("unsupported protocol version")
	}

	var p Packet
	p.Version = buf[0]
	p.Type = PacketType(buf[1])
	p.StripeID = binary.BigEndian.Uint16(buf[2:4])
	copy(p.RunID[:], buf[4:20])
	p.Seq = binary.BigEndian.Uint64(buf[20:28])
	p.Offset = binary.BigEndian.Uint64(buf[28:36])
	p.AckFloor = binary.BigEndian.Uint64(buf[36:44])
	p.AckMask = binary.BigEndian.Uint64(buf[44:52])
	if aead != nil {
		var nonce [12]byte
		if aead.NonceSize() != len(nonce) {
			return Packet{}, errors.New("unsupported packet AEAD nonce size")
		}
		nonceBuf := nonce[:]
		if err := packetAEADNonceTo(nonceBuf, buf[:headerLen]); err != nil {
			return Packet{}, err
		}
		payload, err := aead.Open(buf[52:52], nonceBuf, buf[52:], buf[:headerLen])
		if err != nil {
			return Packet{}, err
		}
		p.Payload = payload
		return p, nil
	}
	p.Payload = buf[52:]
	return p, nil
}

func packetAEADNonceTo(dst []byte, header []byte) error {
	if len(header) < headerLen {
		return errors.New("short packet header")
	}
	if len(dst) != 12 {
		return errors.New("unsupported packet AEAD nonce size")
	}
	seq := binary.BigEndian.Uint64(header[20:28])
	if seq >= 1<<packetAEADNonceSeqBits {
		return errors.New("packet sequence exceeds AEAD nonce range")
	}
	clear(dst)
	dst[0] = header[1]
	copy(dst[1:3], header[2:4])
	copy(dst[3:7], header[4:8])
	dst[7] = byte(seq >> 32)
	dst[8] = byte(seq >> 24)
	dst[9] = byte(seq >> 16)
	dst[10] = byte(seq >> 8)
	dst[11] = byte(seq)
	return nil
}
