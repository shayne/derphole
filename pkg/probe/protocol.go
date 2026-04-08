package probe

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	ProtocolVersion = 2
	headerLen       = 52
)

var packetAEADNonceDomain = []byte("derpcat-probe-packet-aead-v1")

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
		return aead.Seal(buf, packetAEADNonce(aead, buf[:headerLen]), p.Payload, buf[:headerLen]), nil
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
		payload, err := aead.Open(nil, packetAEADNonce(aead, buf[:headerLen]), buf[52:], buf[:headerLen])
		if err != nil {
			return Packet{}, err
		}
		p.Payload = payload
		return p, nil
	}
	p.Payload = buf[52:]
	return p, nil
}

func packetAEADNonce(aead cipher.AEAD, header []byte) []byte {
	sum := sha256.New()
	_, _ = sum.Write(packetAEADNonceDomain)
	_, _ = sum.Write(header)
	digest := sum.Sum(nil)
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, digest)
	return nonce
}
