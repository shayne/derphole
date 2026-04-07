package probe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	p := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 3,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		AckFloor: 4096,
		AckMask:  0x8040201008040201,
		Payload:  []byte("hello"),
	}

	buf, err := MarshalPacket(p, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}

	got, err := UnmarshalPacket(buf, nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}

	if got.Version != p.Version || got.Type != p.Type || got.StripeID != p.StripeID || !bytes.Equal(got.RunID[:], p.RunID[:]) || got.Seq != p.Seq || got.Offset != p.Offset || got.AckFloor != p.AckFloor || got.AckMask != p.AckMask || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("round trip mismatch: got %#v want %#v", got, p)
	}
}

func TestUnmarshalPacketRejectsShortHeader(t *testing.T) {
	if _, err := UnmarshalPacket([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("UnmarshalPacket() error = nil, want short header error")
	}
}

func TestUnmarshalPacketRejectsWrongVersion(t *testing.T) {
	buf, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeAck,
	}, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}

	buf[0] = ProtocolVersion - 1
	if _, err := UnmarshalPacket(buf, nil); err == nil {
		t.Fatal("UnmarshalPacket() error = nil, want version error")
	}
}

func TestPacketRejectsAEAD(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	if _, err := MarshalPacket(Packet{}, aead); err == nil {
		t.Fatal("MarshalPacket() error = nil, want encrypted mode error")
	}

	if _, err := UnmarshalPacket(make([]byte, headerLen), aead); err == nil {
		t.Fatal("UnmarshalPacket() error = nil, want encrypted mode error")
	}
}
