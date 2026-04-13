package webproto

import (
	"encoding/binary"
	"errors"
)

const (
	// Keep browser DERP/WebSocket packets close to real WireGuard packet
	// sizing. Public DERP accepts larger theoretical packets, but browser
	// WebSocket connections have been observed to close on near-64KiB frames.
	MaxPayloadBytes = 16 << 10

	magic     = "DHPW"
	version   = 1
	headerLen = 18
)

var (
	ErrInvalidFrame    = errors.New("invalid web relay frame")
	ErrPayloadTooLarge = errors.New("web relay frame payload too large")
)

type FrameKind uint8

const (
	FrameClaim FrameKind = iota + 1
	FrameDecision
	FrameMeta
	FrameData
	FrameDone
	FrameAck
	FrameAbort
	FrameWebRTCOffer
	FrameWebRTCAnswer
	FrameWebRTCIceCandidate
	FrameWebRTCIceComplete
	FrameDirectReady
	FramePathSwitch
	FrameDirectFailed
)

type Frame struct {
	Kind    FrameKind
	Seq     uint64
	Payload []byte
}

type Meta struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type Ack struct {
	BytesReceived int64 `json:"bytes_received"`
}

type Abort struct {
	Reason string `json:"reason,omitempty"`
}

type WebRTCSignal struct {
	Kind             string `json:"kind"`
	Type             string `json:"type"`
	SDP              string `json:"sdp,omitempty"`
	Candidate        string `json:"candidate,omitempty"`
	SDPMid           string `json:"sdpMid,omitempty"`
	SDPMLineIndex    int    `json:"sdpMLineIndex,omitempty"`
	UsernameFragment string `json:"usernameFragment,omitempty"`
}

type DirectReady struct {
	BytesReceived int64  `json:"bytes_received"`
	NextSeq       uint64 `json:"next_seq"`
}

type PathSwitch struct {
	Path          string `json:"path"`
	BytesReceived int64  `json:"bytes_received"`
	NextSeq       uint64 `json:"next_seq"`
}

type DirectFailed struct {
	Reason string `json:"reason,omitempty"`
}

func Marshal(kind FrameKind, seq uint64, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayloadBytes {
		return nil, ErrPayloadTooLarge
	}
	if !validKind(kind) {
		return nil, ErrInvalidFrame
	}
	out := make([]byte, headerLen+len(payload))
	copy(out[:4], magic)
	out[4] = version
	out[5] = byte(kind)
	binary.BigEndian.PutUint64(out[6:14], seq)
	binary.BigEndian.PutUint32(out[14:18], uint32(len(payload)))
	copy(out[headerLen:], payload)
	return out, nil
}

func Parse(raw []byte) (Frame, error) {
	var frame Frame
	if len(raw) < headerLen || string(raw[:4]) != magic || raw[4] != version {
		return frame, ErrInvalidFrame
	}
	kind := FrameKind(raw[5])
	if !validKind(kind) {
		return frame, ErrInvalidFrame
	}
	payloadLen := int(binary.BigEndian.Uint32(raw[14:18]))
	if payloadLen > MaxPayloadBytes || len(raw[headerLen:]) != payloadLen {
		return frame, ErrInvalidFrame
	}
	frame.Kind = kind
	frame.Seq = binary.BigEndian.Uint64(raw[6:14])
	frame.Payload = raw[headerLen:]
	return frame, nil
}

func IsWebFrame(raw []byte) bool {
	return len(raw) >= headerLen && string(raw[:4]) == magic && raw[4] == version
}

func validKind(kind FrameKind) bool {
	return kind >= FrameClaim && kind <= FrameDirectFailed
}
