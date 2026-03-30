package transport

import (
	"context"
	"net"
	"testing"
)

func TestManagerStartUpgradesRelayToDirect(t *testing.T) {
	t.Helper()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		DirectConn: direct,
	})

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
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

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() = %v, want %v before fallback", got, PathDirect)
	}

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}
}

func TestManagerDirectOnlyBrokenDoesNotInventRelay(t *testing.T) {
	t.Helper()

	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		DirectConn: direct,
	})

	if got := mgr.PathState(); got != PathUnknown {
		t.Fatalf("PathState() before Start = %v, want %v", got, PathUnknown)
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() = %v, want %v before fallback", got, PathDirect)
	}

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}

	if got := mgr.PathState(); got != PathUnknown {
		t.Fatalf("PathState() = %v, want %v", got, PathUnknown)
	}
}

func TestManagerRelayOnlyStartKeepsRelay(t *testing.T) {
	t.Helper()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		RelayConn: relay,
	})

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() before Start = %v, want %v", got, PathRelay)
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after Start = %v, want %v", got, PathRelay)
	}
}

func TestManagerCanceledStartCanBeRetried(t *testing.T) {
	t.Helper()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		DirectConn: direct,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := mgr.Start(ctx); err == nil {
		t.Fatal("Start() error = nil, want context cancellation")
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after canceled start = %v, want %v", got, PathRelay)
	}

	if err := mgr.Start(context.Background()); err != nil {
		t.Fatalf("Start() retry error = %v", err)
	}

	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() after retry = %v, want %v", got, PathDirect)
	}
}
