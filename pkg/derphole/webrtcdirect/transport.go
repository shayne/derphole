// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webrtcdirect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/pion/webrtc/v4"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

const (
	dataChannelCount      = 2
	receiveQueueFrames    = 512
	sctpReceiveBufferSize = 128 << 20
)

type Transport struct {
	mu       sync.Mutex
	pcs      []*webrtc.PeerConnection
	dcs      []*webrtc.DataChannel
	open     map[*webrtc.DataChannel]bool
	pending  map[int][]webrtc.ICECandidateInit
	readyCh  chan struct{}
	failCh   chan error
	recvCh   chan []byte
	ready    bool
	closed   bool
	failOnce sync.Once
	nextSend uint64
}

func New() *Transport {
	return &Transport{
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, receiveQueueFrames),
		open:    make(map[*webrtc.DataChannel]bool),
		pending: make(map[int][]webrtc.ICECandidateInit),
	}
}

func (t *Transport) Start(ctx context.Context, role webrelay.DirectRole, peer webrelay.DirectSignalPeer) error {
	config := webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{URLs: []string{"stun:stun.cloudflare.com:3478"}},
	}}
	pcs := make([]*webrtc.PeerConnection, 0, dataChannelCount)
	for lane := 0; lane < dataChannelCount; lane++ {
		pc, err := newPeerConnection(config)
		if err != nil {
			return err
		}
		t.configurePeerConnection(ctx, peer, lane, pc)
		pcs = append(pcs, pc)
	}
	t.mu.Lock()
	t.pcs = append(t.pcs, pcs...)
	t.mu.Unlock()

	go t.forwardSignals(ctx, peer)

	if role == webrelay.DirectRoleSender {
		for lane, pc := range pcs {
			dc, err := pc.CreateDataChannel("derphole-"+strconv.Itoa(lane), &webrtc.DataChannelInit{Ordered: boolPtr(false)})
			if err != nil {
				t.fail(err)
				return err
			}
			t.attachDataChannel(dc)
			offer, err := pc.CreateOffer(nil)
			if err != nil {
				t.fail(err)
				return err
			}
			if err := pc.SetLocalDescription(offer); err != nil {
				t.fail(err)
				return err
			}
			if err := sendSignal(ctx, peer, webproto.FrameWebRTCOffer, webproto.WebRTCSignal{Lane: lane, Kind: "offer", Type: offer.Type.String(), SDP: offer.SDP}); err != nil {
				t.fail(err)
				return err
			}
		}
	}
	return nil
}

func (t *Transport) configurePeerConnection(ctx context.Context, peer webrelay.DirectSignalPeer, lane int, pc *webrtc.PeerConnection) {
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceComplete, webproto.WebRTCSignal{Lane: lane, Kind: "ice-complete"})
			return
		}
		init := candidate.ToJSON()
		_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceCandidate, webproto.WebRTCSignal{
			Lane:             lane,
			Kind:             "candidate",
			Candidate:        init.Candidate,
			SDPMid:           stringValue(init.SDPMid),
			SDPMLineIndex:    uint16Value(init.SDPMLineIndex),
			UsernameFragment: stringValue(init.UsernameFragment),
		})
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateDisconnected:
			t.fail(errors.New("webrtc lane " + strconv.Itoa(lane) + " " + state.String()))
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.attachDataChannel(dc)
	})
}

func newPeerConnection(config webrtc.Configuration) (*webrtc.PeerConnection, error) {
	var settings webrtc.SettingEngine
	settings.SetSCTPMaxReceiveBufferSize(sctpReceiveBufferSize)
	return webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(config)
}

func (t *Transport) Ready() <-chan struct{} { return t.readyCh }

func (t *Transport) Failed() <-chan error { return t.failCh }

func (t *Transport) ReceiveFrames() <-chan []byte { return t.recvCh }

func (t *Transport) SendFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-t.readyCh:
	case err := <-t.failCh:
		if err == nil {
			err = errors.New("direct path failed")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	dcs := t.openDataChannels()
	if len(dcs) == 0 {
		return errors.New("webrtc datachannel is not open")
	}
	dc := dcs[int(atomic.AddUint64(&t.nextSend, 1)-1)%len(dcs)]
	return dc.Send(frame)
}

func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	dcs := append([]*webrtc.DataChannel(nil), t.dcs...)
	pcs := append([]*webrtc.PeerConnection(nil), t.pcs...)
	t.mu.Unlock()
	for _, dc := range dcs {
		_ = dc.Close()
	}
	var err error
	for _, pc := range pcs {
		if closeErr := pc.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

func (t *Transport) attachDataChannel(dc *webrtc.DataChannel) {
	t.mu.Lock()
	t.dcs = append(t.dcs, dc)
	t.mu.Unlock()
	dc.OnOpen(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.closed {
			return
		}
		t.open[dc] = true
		if !t.ready && len(t.open) >= dataChannelCount {
			t.ready = true
			close(t.readyCh)
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		raw := append([]byte(nil), msg.Data...)
		select {
		case t.recvCh <- raw:
		default:
			t.fail(errors.New("direct receive queue full"))
		}
	})
	dc.OnError(func(err error) {
		t.fail(err)
	})
	dc.OnClose(func() {
		t.mu.Lock()
		ready := t.ready
		delete(t.open, dc)
		remaining := len(t.open)
		t.mu.Unlock()
		if !ready {
			t.fail(errors.New("webrtc datachannel closed before open"))
			return
		}
		if remaining == 0 {
			t.fail(errors.New("webrtc datachannels closed"))
		}
	})
}

func (t *Transport) openDataChannels() []*webrtc.DataChannel {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*webrtc.DataChannel, 0, len(t.open))
	for _, dc := range t.dcs {
		if t.open[dc] && dc.ReadyState() == webrtc.DataChannelStateOpen {
			out = append(out, dc)
		}
	}
	return out
}

func (t *Transport) openChannelCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.open)
}

func (t *Transport) peerConnectionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pcs)
}

func (t *Transport) forwardSignals(ctx context.Context, peer webrelay.DirectSignalPeer) {
	for {
		select {
		case frame, ok := <-peer.Signals():
			if !ok {
				return
			}
			if err := t.applySignal(ctx, peer, frame); err != nil {
				t.fail(err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (t *Transport) applySignal(ctx context.Context, peer webrelay.DirectSignalPeer, frame webproto.Frame) error {
	var signal webproto.WebRTCSignal
	if err := json.Unmarshal(frame.Payload, &signal); err != nil {
		return err
	}
	if signal.Lane < 0 || signal.Lane >= dataChannelCount {
		return errors.New("invalid webrtc signal lane")
	}
	t.mu.Lock()
	if signal.Lane >= len(t.pcs) {
		t.mu.Unlock()
		return errors.New("webrtc peer connection is not started")
	}
	pc := t.pcs[signal.Lane]
	t.mu.Unlock()
	switch frame.Kind {
	case webproto.FrameWebRTCOffer:
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: signal.SDP}); err != nil {
			return err
		}
		if err := t.flushPendingCandidates(pc, signal.Lane); err != nil {
			return err
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			return err
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			return err
		}
		return sendSignal(ctx, peer, webproto.FrameWebRTCAnswer, webproto.WebRTCSignal{Lane: signal.Lane, Kind: "answer", Type: answer.Type.String(), SDP: answer.SDP})
	case webproto.FrameWebRTCAnswer:
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.SDP}); err != nil {
			return err
		}
		return t.flushPendingCandidates(pc, signal.Lane)
	case webproto.FrameWebRTCIceCandidate:
		candidate := webrtc.ICECandidateInit{
			Candidate:        signal.Candidate,
			SDPMid:           &signal.SDPMid,
			SDPMLineIndex:    uint16Ptr(uint16(signal.SDPMLineIndex)),
			UsernameFragment: &signal.UsernameFragment,
		}
		if pc.RemoteDescription() == nil {
			t.mu.Lock()
			t.pending[signal.Lane] = append(t.pending[signal.Lane], candidate)
			t.mu.Unlock()
			return nil
		}
		return pc.AddICECandidate(candidate)
	case webproto.FrameWebRTCIceComplete:
		return nil
	default:
		return nil
	}
}

func (t *Transport) flushPendingCandidates(pc *webrtc.PeerConnection, lane int) error {
	t.mu.Lock()
	candidates := append([]webrtc.ICECandidateInit(nil), t.pending[lane]...)
	delete(t.pending, lane)
	t.mu.Unlock()
	for _, candidate := range candidates {
		if err := pc.AddICECandidate(candidate); err != nil {
			return err
		}
	}
	return nil
}

func sendSignal(ctx context.Context, peer webrelay.DirectSignalPeer, kind webproto.FrameKind, signal webproto.WebRTCSignal) error {
	payload, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	return peer.SendSignal(ctx, kind, 0, payload)
}

func (t *Transport) fail(err error) {
	if err == nil {
		err = errors.New("direct path failed")
	}
	t.failOnce.Do(func() {
		select {
		case t.failCh <- err:
		default:
		}
	})
}

func boolPtr(v bool) *bool { return &v }

func uint16Ptr(v uint16) *uint16 { return &v }

func stringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func uint16Value(v *uint16) int {
	if v == nil {
		return 0
	}
	return int(*v)
}
