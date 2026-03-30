package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestManagerStartsRelayAndLaterUpgradesDirect(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		DirectConn: direct,
	})

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}

	if err := mgr.WaitForUpgrade(ctx); err != nil {
		t.Fatalf("WaitForUpgrade() error = %v", err)
	}

	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() = %v, want %v", got, PathDirect)
	}
}

func TestManagerFallsBackToRelayWhenDirectBreaks(t *testing.T) {
	t.Helper()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		DirectConn: direct,
	})

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}
}

func TestManagerDoesNotReportDirectForUnownedUDPNoise(t *testing.T) {
	t.Helper()

	relay := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001})
	noise := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 54321})

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		NoiseConn:  noise,
		DirectConn: nil,
	})

	if err := mgr.ObserveInboundUDPNoise(noise.LocalAddr(), []byte("random udp noise")); err != nil {
		t.Fatalf("ObserveInboundUDPNoise() error = %v", err)
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}
}
