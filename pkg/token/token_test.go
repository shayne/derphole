package token

import (
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tok := Token{
		Version:         1,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     time.Now().Add(5 * time.Minute).Unix(),
		BootstrapRegion: 12,
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
	if decoded.SessionID != tok.SessionID {
		t.Fatalf("SessionID = %x, want %x", decoded.SessionID, tok.SessionID)
	}
}

func TestDecodeRejectsExpiredToken(t *testing.T) {
	tok := Token{Version: 1, ExpiresUnix: time.Now().Add(-time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, time.Now()); err == nil {
		t.Fatal("Decode() error = nil, want expiry failure")
	}
}

func TestDecodeRejectsCorruptedChecksum(t *testing.T) {
	tok := Token{Version: 1, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	encoded = encoded[:len(encoded)-1] + strings.Repeat("A", 1)
	if _, err := Decode(encoded, time.Now()); err == nil {
		t.Fatal("Decode() error = nil, want checksum failure")
	}
}
