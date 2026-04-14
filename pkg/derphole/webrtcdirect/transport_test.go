package webrtcdirect

import (
	"context"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derphole/webproto"
	"github.com/shayne/derpcat/pkg/derphole/webrelay"
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
