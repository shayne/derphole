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
	if aead != nil {
		return nil, errors.New("encrypted mode not implemented")
	}

	buf := make([]byte, headerLen+len(p.Payload))
	buf[0] = p.Version
	buf[1] = byte(p.Type)
	binary.BigEndian.PutUint16(buf[2:4], p.StripeID)
	copy(buf[4:20], p.RunID[:])
	binary.BigEndian.PutUint64(buf[20:28], p.Seq)
	binary.BigEndian.PutUint64(buf[28:36], p.Offset)
	binary.BigEndian.PutUint64(buf[36:44], p.AckFloor)
	binary.BigEndian.PutUint64(buf[44:52], p.AckMask)
	copy(buf[52:], p.Payload)
	return buf, nil
}

func UnmarshalPacket(buf []byte, aead cipher.AEAD) (Packet, error) {
	if len(buf) < headerLen {
		return Packet{}, errors.New("short packet")
	}
	if aead != nil {
		return Packet{}, errors.New("encrypted mode not implemented")
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
	p.Payload = buf[52:]
	return p, nil
}
