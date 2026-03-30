package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestManagerUpgradesDirectViaJSONControlAndProbeAck(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 2), Port: 12345}
	localCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 9), Port: 54321}

	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		CandidateSource:         func(context.Context) []net.Addr { return []net.Addr{localCandidate} },
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		DiscoveryInterval:       10 * time.Millisecond,
		EndpointRefreshInterval: 20 * time.Millisecond,
		DirectStaleTimeout:      40 * time.Millisecond,
	})

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	callMeMaybe := controls.waitForSentType(ControlCallMeMaybe, 200*time.Millisecond)
	if callMeMaybe == nil {
		t.Fatal("manager did not send call-me-maybe control")
	}

	if !controls.deliver(ControlMessage{Type: ControlCallMeMaybe}, 200*time.Millisecond) {
		t.Fatal("failed to deliver peer call-me-maybe control")
	}

	candidates := controls.waitForSentType(ControlCandidates, 200*time.Millisecond)
	if candidates == nil {
		t.Fatal("manager did not respond to call-me-maybe with candidates control")
	}
	if len(candidates.Candidates) != 1 || candidates.Candidates[0] != localCandidate.String() {
		t.Fatalf("candidate control = %#v, want %q", candidates, localCandidate.String())
	}

	if !direct.waitForWritePayloadTo(peerCandidate, discoProbePayload, 200*time.Millisecond) {
		t.Fatalf("manager did not send %q probe to %v", string(discoProbePayload), peerCandidate)
	}

	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v", mgr.PathState(), PathDirect)
	}
}

func TestManagerRestartsDiscoveryWhenDirectBecomesStale(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 3), Port: 23456}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		DiscoveryInterval:       10 * time.Millisecond,
		EndpointRefreshInterval: 20 * time.Millisecond,
		DirectStaleTimeout:      35 * time.Millisecond,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver initial candidates control")
	}

	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after initial probe", mgr.PathState(), PathDirect)
	}

	initialProbes := direct.writeCountTo(peerCandidate)
	if initialProbes == 0 {
		t.Fatal("expected at least one initial probe")
	}

	if !direct.waitForWriteCountTo(peerCandidate, initialProbes+1, 300*time.Millisecond) {
		t.Fatal("manager did not retry discovery after the direct path went stale")
	}

	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() after stale retry = %v, want %v", got, PathDirect)
	}
}

func TestManagerFallsBackToRelayAndRetriesDiscovery(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 4), Port: 34567}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		DiscoveryInterval:       10 * time.Millisecond,
		EndpointRefreshInterval: 20 * time.Millisecond,
		DirectStaleTimeout:      40 * time.Millisecond,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v before fallback", mgr.PathState(), PathDirect)
	}

	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)
	probeCount := direct.writeCountTo(peerCandidate)

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}
	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after fallback = %v, want %v", got, PathRelay)
	}

	if !controls.waitForSentCount(ControlCallMeMaybe, callMeMaybeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not send a fresh call-me-maybe after fallback")
	}
	if !direct.waitForWriteCountTo(peerCandidate, probeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not retry direct probes after fallback")
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() after fallback recovery = %v, want %v", mgr.PathState(), PathDirect)
	}
}

func TestManagerIgnoresUnexpectedDirectNoise(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	controls := newFakeControlPipe()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		DiscoveryInterval:       10 * time.Millisecond,
		EndpointRefreshInterval: 20 * time.Millisecond,
		DirectStaleTimeout:      40 * time.Millisecond,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	direct.enqueueRead([]byte("derpcat-ack"), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 99), Port: 9999})
	direct.enqueueRead([]byte("udp-noise"), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 100), Port: 10000})
	time.Sleep(50 * time.Millisecond)

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after unexpected direct packets = %v, want %v", got, PathRelay)
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

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after retry = %v, want %v before discovery", got, PathRelay)
	}
}

func waitForPath(t *testing.T, mgr *Manager, want Path, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if mgr.PathState() == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return mgr.PathState() == want
}
