package webproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello")
	raw, err := Marshal(FrameData, 42, payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if frame.Kind != FrameData {
		t.Fatalf("Kind = %v, want %v", frame.Kind, FrameData)
	}
	if frame.Seq != 42 {
		t.Fatalf("Seq = %d, want 42", frame.Seq)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("Payload = %q, want %q", frame.Payload, payload)
	}
}

func TestFrameRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, MaxPayloadBytes+1)
	if _, err := Marshal(FrameData, 0, payload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Marshal() error = %v, want %v", err, ErrPayloadTooLarge)
	}
}

func TestParseRejectsInvalidFrame(t *testing.T) {
	raw, err := Marshal(FrameData, 0, []byte("ok"))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	raw[0] = 'x'
	if _, err := Parse(raw); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Parse() error = %v, want %v", err, ErrInvalidFrame)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	in := Meta{
		Name: "example.bin",
		Size: 1234,
	}
	payload, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal(meta) error = %v", err)
	}
	raw, err := Marshal(FrameMeta, 0, payload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}

	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var out Meta
	if err := json.Unmarshal(frame.Payload, &out); err != nil {
		t.Fatalf("Unmarshal(meta) error = %v", err)
	}
	if out != in {
		t.Fatalf("Meta = %+v, want %+v", out, in)
	}
}
