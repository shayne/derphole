// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     time.Now().Add(5 * time.Minute).Unix(),
		BootstrapRegion: 12,
		DERPPublic:      [32]byte{5, 6, 7, 8},
		BearerSecret:    [32]byte{17, 18, 19, 20},
		Capabilities:    CapabilityStdio | CapabilityShare,
		QUICPublic:      [32]byte{21, 22, 23, 24},
	}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded != tok {
		t.Fatalf("decoded token = %+v, want %+v", decoded, tok)
	}
}

func TestEncodeDefaultsZeroVersion(t *testing.T) {
	tok := Token{ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Version != SupportedVersion {
		t.Fatalf("Version = %d, want %d", decoded.Version, SupportedVersion)
	}
}

func TestEncodeRejectsUnsupportedVersion(t *testing.T) {
	_, err := Encode(Token{Version: SupportedVersion + 1, ExpiresUnix: time.Now().Add(time.Minute).Unix()})
	if err != ErrUnsupportedVersion {
		t.Fatalf("Encode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[0] = SupportedVersion + 1
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrUnsupportedVersion {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsExpiredToken(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(-time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, time.Now()); err != ErrExpired {
		t.Fatalf("Decode() error = %v, want ErrExpired", err)
	}
}

func TestDecodeRejectsTokenAtExpiryBoundary(t *testing.T) {
	now := time.Now().UTC()
	tok := Token{Version: SupportedVersion, ExpiresUnix: now.Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, now); err != ErrExpired {
		t.Fatalf("Decode() error = %v, want ErrExpired", err)
	}
}

func TestDecodeRejectsCorruptedChecksum(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrChecksum {
		t.Fatalf("Decode() error = %v, want ErrChecksum", err)
	}
}

func TestEncodeWireFormatContract(t *testing.T) {
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ExpiresUnix:     1700000000,
		BootstrapRegion: 0x1234,
		DERPPublic:      [32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
		BearerSecret:    [32]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
		Capabilities:    CapabilityStdio | CapabilityShare,
		QUICPublic:      [32]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("encoded token = %q, want raw URL-safe base64 without padding", encoded)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if got, want := len(raw), fixedPayloadSizeV4+4; got != want {
		t.Fatalf("raw length = %d, want %d", got, want)
	}
	decoded, err := Decode(encoded, time.Unix(tok.ExpiresUnix-1, 0))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.QUICPublic != tok.QUICPublic {
		t.Fatalf("decoded QUICPublic = %x, want %x", decoded.QUICPublic, tok.QUICPublic)
	}
}

func TestEncodeDecodeRoundTripPublicShareToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     now.Add(time.Hour).Unix(),
		BootstrapRegion: 7,
		DERPPublic:      [32]byte{9, 9, 9, 9},
		BearerSecret:    [32]byte{8, 8, 8, 8},
		Capabilities:    CapabilityShare,
		QUICPublic:      [32]byte{7, 7, 7, 7},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.QUICPublic != tok.QUICPublic {
		t.Fatalf("QUICPublic = %x, want %x", decoded.QUICPublic, tok.QUICPublic)
	}
}

func TestEncodeDecodeRoundTripAttachToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:      SupportedVersion,
		SessionID:    [16]byte{9, 8, 7, 6},
		ExpiresUnix:  now.Add(time.Hour).Unix(),
		BearerSecret: [32]byte{6, 7, 8, 9},
		Capabilities: CapabilityStdio | CapabilityShare | CapabilityAttach,
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.Capabilities&CapabilityAttach == 0 {
		t.Fatalf("Capabilities = %08b, want attach bit set", decoded.Capabilities)
	}
	if decoded.Capabilities&CapabilityStdio == 0 || decoded.Capabilities&CapabilityShare == 0 {
		t.Fatalf("Capabilities = %08b, want mixed capability bits preserved", decoded.Capabilities)
	}
}

func TestEncodeDecodeRoundTripWithNativeTCPBootstrap(t *testing.T) {
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     time.Now().Add(5 * time.Minute).Unix(),
		BootstrapRegion: 12,
		DERPPublic:      [32]byte{5, 6, 7, 8},
		BearerSecret:    [32]byte{17, 18, 19, 20},
		Capabilities:    CapabilityStdio | CapabilityShare,
		QUICPublic:      [32]byte{21, 22, 23, 24},
	}
	wantAddr := netip.MustParseAddrPort("108.18.210.19:8321")
	tok.SetNativeTCPBootstrapAddr(wantAddr)

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, ok := decoded.NativeTCPBootstrapAddr(); !ok || got != wantAddr {
		t.Fatalf("NativeTCPBootstrapAddr() = (%v, %v), want (%v, true)", got, ok, wantAddr)
	}
}

func TestDecodeAcceptsLegacyVersion3Token(t *testing.T) {
	tok := Token{
		Version:         3,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     time.Now().Add(5 * time.Minute).Unix(),
		BootstrapRegion: 12,
		DERPPublic:      [32]byte{5, 6, 7, 8},
		BearerSecret:    [32]byte{17, 18, 19, 20},
		Capabilities:    CapabilityStdio,
		QUICPublic:      [32]byte{21, 22, 23, 24},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Version != 3 {
		t.Fatalf("Version = %d, want 3", decoded.Version)
	}
	if _, ok := decoded.NativeTCPBootstrapAddr(); ok {
		t.Fatal("NativeTCPBootstrapAddr() ok = true, want false for legacy token")
	}
}

func TestDecodeRejectsMalformedLength(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrInvalidLength {
		t.Fatalf("Decode() error = %v, want ErrInvalidLength", err)
	}
}

func TestDecodeRejectsUnsupportedVersionWithWrongLength(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[0] = SupportedVersion + 1
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrUnsupportedVersion {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func FuzzDecode(f *testing.F) {
	now := time.Unix(1700000000, 0)
	valid, err := Encode(Token{
		Version:      SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4},
		ExpiresUnix:  now.Add(time.Hour).Unix(),
		BearerSecret: [32]byte{5, 6, 7, 8},
		Capabilities: CapabilityStdio | CapabilityShare,
	})
	if err != nil {
		f.Fatalf("Encode(seed) error = %v", err)
	}
	for _, seed := range []string{
		valid,
		"",
		"bad",
		"AAAA",
		strings.TrimRight(valid, "A"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		decoded, err := Decode(encoded, now)
		if err != nil {
			return
		}
		roundTrip, err := Encode(decoded)
		if err != nil {
			t.Fatalf("Encode(decoded) error = %v", err)
		}
		decodedAgain, err := Decode(roundTrip, now)
		if err != nil {
			t.Fatalf("Decode(re-encoded) error = %v", err)
		}
		if decodedAgain != decoded {
			t.Fatalf("decoded token changed after re-encode: %+v != %+v", decodedAgain, decoded)
		}
	})
}

func FuzzEncodeDecode(f *testing.F) {
	f.Add([]byte("derphole seed"), int64(1), uint32(CapabilityStdio), false)
	f.Add([]byte(strings.Repeat("x", 128)), int64(3600), uint32(CapabilityShare), true)

	f.Fuzz(func(t *testing.T, seed []byte, expiresDelta int64, capabilities uint32, legacy bool) {
		now := time.Unix(1700000000, 0)
		if expiresDelta < 0 {
			expiresDelta = -expiresDelta
		}
		tok := Token{
			Version:      SupportedVersion,
			ExpiresUnix:  now.Unix() + 1 + expiresDelta%86400,
			Capabilities: capabilities,
		}
		if legacy {
			tok.Version = legacyVersion
		}
		copy(tok.SessionID[:], seed)
		copy(tok.DERPPublic[:], seed)
		if len(seed) > 32 {
			copy(tok.QUICPublic[:], seed[32:])
		} else {
			copy(tok.QUICPublic[:], seed)
		}
		if len(seed) > 64 {
			copy(tok.BearerSecret[:], seed[64:])
		} else {
			copy(tok.BearerSecret[:], seed)
		}
		if !legacy && len(seed) > 0 {
			tok.SetNativeTCPBootstrapAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, seed[0]}), 12345))
		}

		encoded, err := Encode(tok)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		decoded, err := Decode(encoded, now)
		if err != nil {
			t.Fatalf("Decode(Encode(tok)) error = %v", err)
		}
		if decoded != tok {
			t.Fatalf("Decode(Encode(tok)) = %+v, want %+v", decoded, tok)
		}
	})
}
