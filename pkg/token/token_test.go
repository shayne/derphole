package token

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
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
		WGPublic:        [32]byte{9, 10, 11, 12},
		DiscoPublic:     [32]byte{13, 14, 15, 16},
		BearerSecret:    [32]byte{17, 18, 19, 20},
		Capabilities:    CapabilityStdio | CapabilityTCP,
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
	sum := crc32.ChecksumIEEE(raw[:len(raw)-4])
	binary.BigEndian.PutUint32(raw[len(raw)-4:], sum)
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
		WGPublic:        [32]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
		DiscoPublic:     [32]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80},
		BearerSecret:    [32]byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0},
		Capabilities:    CapabilityStdio | CapabilityTCP,
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("encoded token = %q, want raw URL-safe base64 without padding", encoded)
	}
	wantEncodedLen := 4 * ((payloadSize + 4) / 3)
	switch (payloadSize + 4) % 3 {
	case 1:
		wantEncodedLen += 2
	case 2:
		wantEncodedLen += 3
	}
	if got := len(encoded); got != wantEncodedLen {
		t.Fatalf("encoded length = %d, want %d", got, wantEncodedLen)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if got, want := len(raw), payloadSize+4; got != want {
		t.Fatalf("raw length = %d, want %d", got, want)
	}

	const wantEncoded = "AQECAwQFBgcICQoLDA0ODxAAAAAAZVPxABI0ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6AAAAADDIq30w"
	if encoded != wantEncoded {
		t.Fatalf("encoded token = %q, want %q", encoded, wantEncoded)
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
	if _, err := Decode(encoded, time.Now()); err == nil || err.Error() != "invalid token length" {
		t.Fatalf("Decode() error = %v, want invalid token length", err)
	}
}
