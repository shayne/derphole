// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func TestIsWebFrameChecksMagicAndVersion(t *testing.T) {
	raw, err := Marshal(FrameData, 1, []byte("payload"))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !IsWebFrame(raw) {
		t.Fatal("IsWebFrame(valid frame) = false, want true")
	}
	raw[4] = 99
	if IsWebFrame(raw) {
		t.Fatal("IsWebFrame(wrong version) = true, want false")
	}
	if IsWebFrame([]byte("DHP")) {
		t.Fatal("IsWebFrame(short frame) = true, want false")
	}
}

func TestFrameRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, MaxPayloadBytes+1)
	if _, err := Marshal(FrameData, 0, payload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Marshal() error = %v, want %v", err, ErrPayloadTooLarge)
	}
}

func TestPayloadLimitsKeepRelaySmallAndAllowLargerDirectFrames(t *testing.T) {
	const want = 16 << 10
	if MaxRelayPayloadBytes != want {
		t.Fatalf("MaxRelayPayloadBytes = %d, want %d", MaxRelayPayloadBytes, want)
	}
	if MaxPayloadBytes <= MaxRelayPayloadBytes {
		t.Fatalf("MaxPayloadBytes = %d, want larger than relay limit %d", MaxPayloadBytes, MaxRelayPayloadBytes)
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

func TestWebRTCSignalRoundTrip(t *testing.T) {
	payload, err := json.Marshal(WebRTCSignal{
		Kind:      "offer",
		Type:      "offer",
		SDP:       "v=0\r\n",
		Candidate: "",
	})
	if err != nil {
		t.Fatalf("Marshal(signal) error = %v", err)
	}
	raw, err := Marshal(FrameWebRTCOffer, 7, payload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}
	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if frame.Kind != FrameWebRTCOffer {
		t.Fatalf("Kind = %v, want %v", frame.Kind, FrameWebRTCOffer)
	}
	var got WebRTCSignal
	if err := json.Unmarshal(frame.Payload, &got); err != nil {
		t.Fatalf("Unmarshal(signal) error = %v", err)
	}
	if got.Kind != "offer" || got.Type != "offer" || got.SDP != "v=0\r\n" {
		t.Fatalf("Signal = %+v", got)
	}
}

func TestDirectReadyRoundTrip(t *testing.T) {
	payload, err := json.Marshal(DirectReady{
		BytesReceived: 123456,
		NextSeq:       88,
	})
	if err != nil {
		t.Fatalf("Marshal(direct ready) error = %v", err)
	}
	raw, err := Marshal(FrameDirectReady, 88, payload)
	if err != nil {
		t.Fatalf("Marshal(frame) error = %v", err)
	}
	frame, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	var got DirectReady
	if err := json.Unmarshal(frame.Payload, &got); err != nil {
		t.Fatalf("Unmarshal(direct ready) error = %v", err)
	}
	if got.BytesReceived != 123456 || got.NextSeq != 88 {
		t.Fatalf("DirectReady = %+v", got)
	}
}
