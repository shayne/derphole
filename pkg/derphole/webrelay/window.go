// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webrelay

type relayWindowConfig struct {
	MaxBytes  int64
	MaxFrames int
}

type relayFrame struct {
	Seq        uint64
	Offset     int64
	NextOffset int64
	Payload    []byte
	Sent       bool
}

type relayWindow struct {
	cfg           relayWindowConfig
	frames        []relayFrame
	acked         int64
	inFlight      int64
	bufferedBytes int64
}

func newRelayWindow(cfg relayWindowConfig) *relayWindow {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = int64(relayChunkBytes)
	}
	if cfg.MaxFrames <= 0 {
		cfg.MaxFrames = 1
	}
	return &relayWindow{cfg: cfg}
}

func (w *relayWindow) canSend(payloadBytes int) bool {
	if payloadBytes < 0 {
		return false
	}
	if len(w.frames) >= w.cfg.MaxFrames {
		return false
	}
	return w.inFlight+int64(payloadBytes) <= w.cfg.MaxBytes
}

func (w *relayWindow) push(frame relayFrame) {
	frame.Payload = append([]byte(nil), frame.Payload...)
	w.frames = append(w.frames, frame)
	w.inFlight += int64(len(frame.Payload))
	w.bufferedBytes += int64(len(frame.Payload))
}

func (w *relayWindow) markSent(seq uint64) {
	for i := range w.frames {
		if w.frames[i].Seq == seq {
			w.frames[i].Sent = true
			return
		}
	}
}

func (w *relayWindow) unsent() []relayFrame {
	out := make([]relayFrame, 0, len(w.frames))
	for _, frame := range w.frames {
		if !frame.Sent {
			out = append(out, cloneRelayFrame(frame))
		}
	}
	return out
}

func (w *relayWindow) firstUnacked() (relayFrame, bool) {
	if len(w.frames) == 0 {
		return relayFrame{}, false
	}
	return cloneRelayFrame(w.frames[0]), true
}

func (w *relayWindow) ack(bytesReceived int64) {
	if bytesReceived <= w.acked {
		return
	}
	w.acked = bytesReceived
	kept := w.frames[:0]
	var inFlight int64
	var buffered int64
	for _, frame := range w.frames {
		if frame.NextOffset <= bytesReceived {
			continue
		}
		if frame.Offset < bytesReceived {
			frame = trimRelayFramePrefix(frame, bytesReceived-frame.Offset)
		}
		kept = append(kept, frame)
		inFlight += int64(len(frame.Payload))
		buffered += int64(len(frame.Payload))
	}
	w.frames = kept
	w.inFlight = inFlight
	w.bufferedBytes = buffered
}

func (w *relayWindow) ackedOffset() int64 {
	return w.acked
}

func (w *relayWindow) inFlightBytes() int64 {
	return w.inFlight
}

func (w *relayWindow) bufferedPayloadBytes() int64 {
	return w.bufferedBytes
}

func (w *relayWindow) empty() bool {
	return len(w.frames) == 0
}

func (w *relayWindow) replayFrom(offset int64) []relayFrame {
	out := make([]relayFrame, 0, len(w.frames))
	for _, frame := range w.frames {
		if frame.NextOffset <= offset {
			continue
		}
		if frame.Offset < offset {
			frame = trimRelayFramePrefix(frame, offset-frame.Offset)
		}
		out = append(out, cloneRelayFrame(frame))
	}
	return out
}

func cloneRelayFrame(frame relayFrame) relayFrame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}

func trimRelayFramePrefix(frame relayFrame, trimBytes int64) relayFrame {
	if trimBytes <= 0 {
		return cloneRelayFrame(frame)
	}
	if trimBytes >= int64(len(frame.Payload)) {
		frame.Payload = nil
		frame.Offset = frame.NextOffset
		return frame
	}
	frame.Offset += trimBytes
	frame.Payload = append([]byte(nil), frame.Payload[int(trimBytes):]...)
	return frame
}
