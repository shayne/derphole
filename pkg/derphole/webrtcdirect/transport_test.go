// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webrtcdirect

import (
	"context"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

type memoryPeer struct {
	in  chan webproto.Frame
	out chan webproto.Frame
}

func newMemoryPeerPair() (*memoryPeer, *memoryPeer) {
	a := &memoryPeer{in: make(chan webproto.Frame, 64), out: make(chan webproto.Frame, 64)}
	b := &memoryPeer{in: a.out, out: a.in}
	return a, b
}

func (p *memoryPeer) SendSignal(_ context.Context, kind webproto.FrameKind, seq uint64, payload []byte) error {
	p.out <- webproto.Frame{Kind: kind, Seq: seq, Payload: append([]byte(nil), payload...)}
	return nil
}

func (p *memoryPeer) Signals() <-chan webproto.Frame {
	return p.in
}

func TestTransportLoopbackSendsFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPeer, receiverPeer := newMemoryPeerPair()
	sender := New()
	receiver := New()
	defer sender.Close()
	defer receiver.Close()

	if err := receiver.Start(ctx, webrelay.DirectRoleReceiver, receiverPeer); err != nil {
		t.Fatalf("receiver Start() error = %v", err)
	}
	if err := sender.Start(ctx, webrelay.DirectRoleSender, senderPeer); err != nil {
		t.Fatalf("sender Start() error = %v", err)
	}

	select {
	case <-sender.Ready():
	case err := <-sender.Failed():
		t.Fatalf("sender failed before ready: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for sender ready")
	}
	select {
	case <-receiver.Ready():
	case err := <-receiver.Failed():
		t.Fatalf("receiver failed before ready: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for receiver ready")
	}

	raw, err := webproto.Marshal(webproto.FrameData, 1, []byte("abc"))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := sender.SendFrame(ctx, raw); err != nil {
		t.Fatalf("SendFrame() error = %v", err)
	}

	select {
	case got := <-receiver.ReceiveFrames():
		frame, err := webproto.Parse(got)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if frame.Kind != webproto.FrameData || frame.Seq != 1 || string(frame.Payload) != "abc" {
			t.Fatalf("received frame = %+v", frame)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for received frame")
	}
}

func TestTransportLoopbackOpensStripedChannels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPeer, receiverPeer := newMemoryPeerPair()
	sender := New()
	receiver := New()
	defer sender.Close()
	defer receiver.Close()

	if err := receiver.Start(ctx, webrelay.DirectRoleReceiver, receiverPeer); err != nil {
		t.Fatalf("receiver Start() error = %v", err)
	}
	if err := sender.Start(ctx, webrelay.DirectRoleSender, senderPeer); err != nil {
		t.Fatalf("sender Start() error = %v", err)
	}

	waitTransportReady(t, ctx, sender, "sender")
	waitTransportReady(t, ctx, receiver, "receiver")

	if got := sender.openChannelCount(); got != dataChannelCount {
		t.Fatalf("sender openChannelCount() = %d, want %d", got, dataChannelCount)
	}
	if got := receiver.openChannelCount(); got != dataChannelCount {
		t.Fatalf("receiver openChannelCount() = %d, want %d", got, dataChannelCount)
	}
	if got := sender.peerConnectionCount(); got != dataChannelCount {
		t.Fatalf("sender peerConnectionCount() = %d, want %d independent SCTP associations", got, dataChannelCount)
	}
	if got := receiver.peerConnectionCount(); got != dataChannelCount {
		t.Fatalf("receiver peerConnectionCount() = %d, want %d independent SCTP associations", got, dataChannelCount)
	}

	for seq := uint64(1); seq <= uint64(dataChannelCount*2); seq++ {
		raw, err := webproto.Marshal(webproto.FrameData, seq, []byte{byte(seq)})
		if err != nil {
			t.Fatalf("Marshal(%d) error = %v", seq, err)
		}
		if err := sender.SendFrame(ctx, raw); err != nil {
			t.Fatalf("SendFrame(%d) error = %v", seq, err)
		}
	}

	seen := make(map[uint64]bool)
	for len(seen) < dataChannelCount*2 {
		select {
		case raw := <-receiver.ReceiveFrames():
			frame, err := webproto.Parse(raw)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			seen[frame.Seq] = true
		case <-ctx.Done():
			t.Fatalf("timed out waiting for striped frames; got %d", len(seen))
		}
	}
}

func TestSCTPReceiveBufferCoversHighBDPBrowserTransfers(t *testing.T) {
	const minHighBDPBuffer = 64 << 20
	if sctpReceiveBufferSize < minHighBDPBuffer {
		t.Fatalf("sctpReceiveBufferSize = %d, want at least %d", sctpReceiveBufferSize, minHighBDPBuffer)
	}
}

func waitTransportReady(t *testing.T, ctx context.Context, tr *Transport, name string) {
	t.Helper()
	select {
	case <-tr.Ready():
	case err := <-tr.Failed():
		t.Fatalf("%s failed before ready: %v", name, err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s ready", name)
	}
}
