package traversal

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbePromotesDirectPath(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := ProbeDirect(ctx, a, b.LocalAddr().String(), b, a.LocalAddr().String())
	if err != nil {
		t.Fatalf("ProbeDirect() error = %v", err)
	}
	if !result.Direct {
		t.Fatalf("Direct = false, want true")
	}
}

func TestProbeFallsBackWhenNoPeerResponds(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	result, err := ProbeDirect(ctx, a, "127.0.0.1:9", nil, "")
	if err != nil {
		t.Fatalf("ProbeDirect() error = %v", err)
	}
	if result.Direct {
		t.Fatalf("Direct = true, want false")
	}
}

func TestGatherCandidatesRejectsNilDERPMap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := GatherCandidates(ctx, nil); err == nil {
		t.Fatal("GatherCandidates() error = nil, want non-nil")
	}
}
