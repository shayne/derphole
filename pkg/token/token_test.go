package token

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tok := Token{
		Version:         1,
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

func TestDecodeRejectsExpiredToken(t *testing.T) {
	tok := Token{Version: 1, ExpiresUnix: time.Now().Add(-time.Minute).Unix()}
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
	tok := Token{Version: 1, ExpiresUnix: now.Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, now); err != ErrExpired {
		t.Fatalf("Decode() error = %v, want ErrExpired", err)
	}
}

func TestDecodeRejectsCorruptedChecksum(t *testing.T) {
	tok := Token{Version: 1, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
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
