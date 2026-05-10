// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func TestPacketRoundTripAEADAuthenticatesPayloadAndHeader(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	packet := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		AckFloor: 4096,
		AckMask:  0x8040201008040201,
		Payload:  []byte("wire-secret-payload"),
	}

	buf, err := MarshalPacket(packet, aead)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	if bytes.Contains(buf, packet.Payload) {
		t.Fatal("encrypted packet contains plaintext payload")
	}
	wire := append([]byte(nil), buf...)

	got, err := UnmarshalPacket(buf, aead)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	if got.Version != packet.Version || got.Type != packet.Type || got.StripeID != packet.StripeID || !bytes.Equal(got.RunID[:], packet.RunID[:]) || got.Seq != packet.Seq || got.Offset != packet.Offset || got.AckFloor != packet.AckFloor || got.AckMask != packet.AckMask || !bytes.Equal(got.Payload, packet.Payload) {
		t.Fatalf("round trip mismatch: got %#v want %#v", got, packet)
	}

	tampered := append([]byte(nil), wire...)
	tampered[20] ^= 0x80
	if _, err := UnmarshalPacket(tampered, aead); err == nil {
		t.Fatal("UnmarshalPacket() error = nil after authenticated header tamper")
	}
}

func TestMarshalPacketAEADKeepsAllocationsBounded(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	packet := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		Payload:  bytes.Repeat([]byte("x"), 1384),
	}

	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := MarshalPacket(packet, aead); err != nil {
			t.Fatalf("MarshalPacket() error = %v", err)
		}
	})
	if allocs > 2 {
		t.Fatalf("MarshalPacket() allocations = %.2f, want <= 2", allocs)
	}
}

func TestUnmarshalPacketAEADKeepsAllocationsBounded(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	packet := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		Payload:  bytes.Repeat([]byte("x"), 1384),
	}
	buf, err := MarshalPacket(packet, aead)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	work := make([]byte, len(buf))

	allocs := testing.AllocsPerRun(1000, func() {
		copy(work, buf)
		if _, err := UnmarshalPacket(work, aead); err != nil {
			t.Fatalf("UnmarshalPacket() error = %v", err)
		}
	})
	if allocs > 1 {
		t.Fatalf("UnmarshalPacket() allocations = %.2f, want <= 1", allocs)
	}
}

func TestPacketAEADNonceSeparatesPacketMetadata(t *testing.T) {
	base := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
	}
	nonce := func(p Packet) [12]byte {
		buf, err := MarshalPacket(p, nil)
		if err != nil {
			t.Fatalf("MarshalPacket() error = %v", err)
		}
		var out [12]byte
		if err := packetAEADNonceTo(out[:], buf[:headerLen]); err != nil {
			t.Fatalf("packetAEADNonceTo() error = %v", err)
		}
		return out
	}
	baseNonce := nonce(base)

	for _, tt := range []struct {
		name string
		mut  func(*Packet)
	}{
		{name: "type", mut: func(p *Packet) { p.Type = PacketTypeParity }},
		{name: "stripe", mut: func(p *Packet) { p.StripeID++ }},
		{name: "run", mut: func(p *Packet) { p.RunID[0]++ }},
		{name: "seq", mut: func(p *Packet) { p.Seq++ }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			tt.mut(&p)
			if got := nonce(p); got == baseNonce {
				t.Fatalf("nonce did not change after %s mutation", tt.name)
			}
		})
	}
}

func TestPacketAEADNonceRejectsSequenceOverflow(t *testing.T) {
	buf, err := MarshalPacket(Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		Seq:     1 << packetAEADNonceSeqBits,
	}, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	var nonce [12]byte
	if err := packetAEADNonceTo(nonce[:], buf[:headerLen]); err == nil {
		t.Fatal("packetAEADNonceTo() error = nil, want sequence overflow")
	}
}

func BenchmarkMarshalPacketAEAD(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("cipher.NewGCM() error = %v", err)
	}
	packet := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Offset:   8192,
		Payload:  bytes.Repeat([]byte("x"), 1384),
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(packet.Payload)))
	for i := 0; i < b.N; i++ {
		packet.Seq = uint64(i)
		if _, err := MarshalPacket(packet, aead); err != nil {
			b.Fatalf("MarshalPacket() error = %v", err)
		}
	}
}

func BenchmarkUnmarshalPacketAEAD(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("cipher.NewGCM() error = %v", err)
	}
	packet := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		StripeID: 7,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		Payload:  bytes.Repeat([]byte("x"), 1384),
	}
	wire, err := MarshalPacket(packet, aead)
	if err != nil {
		b.Fatalf("MarshalPacket() error = %v", err)
	}
	work := make([]byte, len(wire))

	b.ReportAllocs()
	b.SetBytes(int64(len(packet.Payload)))
	for i := 0; i < b.N; i++ {
		copy(work, wire)
		if _, err := UnmarshalPacket(work, aead); err != nil {
			b.Fatalf("UnmarshalPacket() error = %v", err)
		}
	}
}
