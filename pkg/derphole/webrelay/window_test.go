package webrelay

import (
	"bytes"
	"testing"
)

func TestRelayWindowEnforcesFrameAndByteLimits(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 6, MaxFrames: 2})
	if !w.canSend(3) {
		t.Fatal("window should accept first 3 byte frame")
	}
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	if w.canSend(1) {
		t.Fatal("window accepted frame past frame limit")
	}
	w.ack(3)
	if !w.canSend(1) {
		t.Fatal("window did not free capacity after cumulative ACK")
	}
}

func TestRelayWindowAckRetiresOnlyCommittedFrames(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	w.push(relayFrame{Seq: 3, Offset: 6, NextOffset: 9, Payload: []byte("ghi")})
	w.ack(5)
	if got := w.ackedOffset(); got != 5 {
		t.Fatalf("ackedOffset = %d, want 5", got)
	}
	if got := w.inFlightBytes(); got != 4 {
		t.Fatalf("inFlightBytes = %d, want 4", got)
	}
	w.ack(6)
	if got := w.inFlightBytes(); got != 3 {
		t.Fatalf("inFlightBytes = %d, want 3", got)
	}
}

func TestRelayWindowReplayFromOffset(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	w.push(relayFrame{Seq: 3, Offset: 6, NextOffset: 9, Payload: []byte("ghi")})
	w.ack(3)

	replay := w.replayFrom(3)
	if len(replay) != 2 {
		t.Fatalf("replay frame count = %d, want 2", len(replay))
	}
	if replay[0].Seq != 2 || !bytes.Equal(replay[0].Payload, []byte("def")) {
		t.Fatalf("first replay frame = %+v", replay[0])
	}
	if replay[1].Seq != 3 || !bytes.Equal(replay[1].Payload, []byte("ghi")) {
		t.Fatalf("second replay frame = %+v", replay[1])
	}
}

func TestRelayWindowBoundsUnknownLengthBufferedBytes(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 10, MaxFrames: 10})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 4, Payload: []byte("aaaa")})
	w.push(relayFrame{Seq: 2, Offset: 4, NextOffset: 8, Payload: []byte("bbbb")})
	if w.canSend(4) {
		t.Fatal("window accepted payload that would exceed MaxBytes")
	}
	if got := w.bufferedPayloadBytes(); got != 8 {
		t.Fatalf("bufferedPayloadBytes = %d, want 8", got)
	}
}

func TestRelayWindowTracksUnsentFramesAndEmpty(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	if !w.empty() {
		t.Fatal("new window should be empty")
	}
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 3, Payload: []byte("abc")})
	w.push(relayFrame{Seq: 2, Offset: 3, NextOffset: 6, Payload: []byte("def")})
	if w.empty() {
		t.Fatal("window should not be empty after pushes")
	}
	w.markSent(1)
	unsent := w.unsent()
	if len(unsent) != 1 {
		t.Fatalf("unsent frame count = %d, want 1", len(unsent))
	}
	if unsent[0].Seq != 2 {
		t.Fatalf("unsent frame seq = %d, want 2", unsent[0].Seq)
	}
	unsent[0].Payload[0] = 'x'
	if w.frames[1].Payload[0] != 'd' {
		t.Fatal("unsent returned a non-cloned payload")
	}
	w.ack(6)
	if !w.empty() {
		t.Fatal("window should be empty after all frames are acked")
	}
}

func TestRelayWindowPartialAckTrimsHeadFrame(t *testing.T) {
	w := newRelayWindow(relayWindowConfig{MaxBytes: 64, MaxFrames: 8})
	w.push(relayFrame{Seq: 1, Offset: 0, NextOffset: 6, Payload: []byte("abcdef")})
	w.push(relayFrame{Seq: 2, Offset: 6, NextOffset: 9, Payload: []byte("ghi")})
	w.ack(3)
	if got := w.inFlightBytes(); got != 6 {
		t.Fatalf("inFlightBytes = %d, want 6", got)
	}
	replay := w.replayFrom(3)
	if len(replay) != 2 {
		t.Fatalf("replay frame count = %d, want 2", len(replay))
	}
	if replay[0].Seq != 1 || replay[0].Offset != 3 || replay[0].NextOffset != 6 || string(replay[0].Payload) != "def" {
		t.Fatalf("first replay frame = %+v", replay[0])
	}
	if replay[1].Seq != 2 || replay[1].Offset != 6 || replay[1].NextOffset != 9 || string(replay[1].Payload) != "ghi" {
		t.Fatalf("second replay frame = %+v", replay[1])
	}
}
