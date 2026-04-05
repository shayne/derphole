package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPunchDirectLoopback(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := PunchDirect(ctx, a, b.LocalAddr().String(), b, a.LocalAddr().String())
	if err != nil {
		t.Fatalf("PunchDirect() error = %v", err)
	}
	if !got.Direct {
		t.Fatal("PunchDirect() direct = false, want true")
	}
}
