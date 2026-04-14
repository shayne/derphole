package webrtcdirect

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/pion/webrtc/v4"
	"github.com/shayne/derpcat/pkg/derphole/webproto"
	"github.com/shayne/derpcat/pkg/derphole/webrelay"
)

const receiveQueueFrames = 512

type Transport struct {
	mu       sync.Mutex
	pc       *webrtc.PeerConnection
	dc       *webrtc.DataChannel
	readyCh  chan struct{}
	failCh   chan error
	recvCh   chan []byte
	ready    bool
	closed   bool
	failOnce sync.Once
}

func New() *Transport {
	return &Transport{
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, receiveQueueFrames),
	}
}

func (t *Transport) Start(ctx context.Context, role webrelay.DirectRole, peer webrelay.DirectSignalPeer) error {
	config := webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{URLs: []string{"stun:stun.cloudflare.com:3478"}},
	}}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.pc = pc
	t.mu.Unlock()

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceComplete, webproto.WebRTCSignal{Kind: "ice-complete"})
			return
		}
		init := candidate.ToJSON()
		_ = sendSignal(ctx, peer, webproto.FrameWebRTCIceCandidate, webproto.WebRTCSignal{
			Kind:             "candidate",
			Candidate:        init.Candidate,
			SDPMid:           stringValue(init.SDPMid),
			SDPMLineIndex:    uint16Value(init.SDPMLineIndex),
			UsernameFragment: stringValue(init.UsernameFragment),
		})
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			t.fail(errors.New("webrtc " + state.String()))
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.attachDataChannel(dc)
	})

	go t.forwardSignals(ctx, peer)

	if role == webrelay.DirectRoleSender {
		dc, err := pc.CreateDataChannel("derphole", &webrtc.DataChannelInit{Ordered: boolPtr(true)})
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
		if err := sendSignal(ctx, peer, webproto.FrameWebRTCOffer, webproto.WebRTCSignal{Kind: "offer", Type: offer.Type.String(), SDP: offer.SDP}); err != nil {
			t.fail(err)
			return err
		}
	}
	return nil
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
	t.mu.Lock()
	dc := t.dc
	t.mu.Unlock()
	if dc == nil {
		return errors.New("webrtc datachannel is not open")
	}
	return dc.Send(frame)
}

func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	dc := t.dc
	pc := t.pc
	t.mu.Unlock()
	if dc != nil {
		_ = dc.Close()
	}
	if pc != nil {
		return pc.Close()
	}
	return nil
}

func (t *Transport) attachDataChannel(dc *webrtc.DataChannel) {
	t.mu.Lock()
	t.dc = dc
	t.mu.Unlock()
	dc.OnOpen(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.ready || t.closed {
			return
		}
		t.ready = true
		close(t.readyCh)
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
		t.mu.Unlock()
		if !ready {
			t.fail(errors.New("webrtc datachannel closed before open"))
		}
	})
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
	t.mu.Lock()
	pc := t.pc
	t.mu.Unlock()
	if pc == nil {
		return errors.New("webrtc peer connection is not started")
	}
	var signal webproto.WebRTCSignal
	if err := json.Unmarshal(frame.Payload, &signal); err != nil {
		return err
	}
	switch frame.Kind {
	case webproto.FrameWebRTCOffer:
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: signal.SDP}); err != nil {
			return err
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			return err
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			return err
		}
		return sendSignal(ctx, peer, webproto.FrameWebRTCAnswer, webproto.WebRTCSignal{Kind: "answer", Type: answer.Type.String(), SDP: answer.SDP})
	case webproto.FrameWebRTCAnswer:
		return pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.SDP})
	case webproto.FrameWebRTCIceCandidate:
		return pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate:        signal.Candidate,
			SDPMid:           &signal.SDPMid,
			SDPMLineIndex:    uint16Ptr(uint16(signal.SDPMLineIndex)),
			UsernameFragment: &signal.UsernameFragment,
		})
	case webproto.FrameWebRTCIceComplete:
		return nil
	default:
		return nil
	}
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
