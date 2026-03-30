package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestManagerUpgradesDirectViaDelayedCallMeMaybe(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000000, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 2), Port: 12345}
	localCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 9), Port: 54321}

	controls := newFakeControlPipe()
	controls.enablePeerCandidateAfter(clock, 3*time.Second, peerCandidate)
	controls.deliverAfter(clock, 3*time.Second, ControlMessage{Type: ControlCallMeMaybe})
	direct.enableResponderAfter(clock, 3*time.Second, peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		CandidateSource:         func(context.Context) []net.Addr { return []net.Addr{localCandidate} },
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() = %v, want %v", got, PathRelay)
	}

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	if controls.sentCount(ControlCallMeMaybe) != 0 {
		t.Fatal("manager sent discovery traffic before the first scheduled tick")
	}

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send call-me-maybe on the first scheduled tick")
	}

	clock.Advance(1 * time.Second)
	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() before delayed enablement = %v, want %v", got, PathRelay)
	}

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not respond to delayed call-me-maybe with candidates control")
	}
	candidates := controls.lastSentType(ControlCandidates)
	if candidates == nil {
		t.Fatal("manager did not record the delayed candidates control")
	}
	if len(candidates.Candidates) != 1 || candidates.Candidates[0] != localCandidate.String() {
		t.Fatalf("candidate control = %#v, want %q", candidates, localCandidate.String())
	}
	if !controls.waitForReceiveCount(2, 200*time.Millisecond) {
		t.Fatal("manager did not consume the delayed call-me-maybe and candidate controls")
	}

	if !direct.waitForWritePayloadTo(peerCandidate, discoProbePayload, 200*time.Millisecond) {
		t.Fatalf("manager did not send %q probe to %v", string(discoProbePayload), peerCandidate)
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after delayed upgrade", mgr.PathState(), PathDirect)
	}
}

func TestManagerRestartsDiscoveryWhenDirectBecomesStale(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000010, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 3), Port: 23456}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      3 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver initial candidates control")
	}

	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after initial probe", mgr.PathState(), PathDirect)
	}

	initialProbes := direct.writeCountTo(peerCandidate)
	if initialProbes == 0 {
		t.Fatal("expected at least one initial probe")
	}

	clock.Advance(3 * time.Second)
	if !direct.waitForWriteCountTo(peerCandidate, initialProbes+1, 200*time.Millisecond) {
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

	clock := newFakeClock(time.Unix(1700000020, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 4), Port: 34567}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
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

	clock.Advance(1 * time.Second)
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

func TestManagerFallbackWaitsForInFlightDiscovery(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000021, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 41), Port: 44567}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      3 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v before stale rediscovery", mgr.PathState(), PathDirect)
	}

	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)
	probeCount := direct.writeCountTo(peerCandidate)
	controls.blockSend(ControlCandidates)

	clock.Advance(3 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not start the stale discovery refresh")
	}

	done := make(chan error, 1)
	go func() {
		done <- mgr.MarkDirectBroken()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MarkDirectBroken() error = %v", err)
		}
		t.Fatal("MarkDirectBroken returned before the in-flight discovery round finished")
	case <-time.After(50 * time.Millisecond):
	}

	controls.unblockSend(ControlCandidates)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MarkDirectBroken() error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("MarkDirectBroken did not finish after the blocked discovery round completed")
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after fallback = %v, want %v", got, PathRelay)
	}

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, callMeMaybeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not send a fresh call-me-maybe immediately after fallback")
	}
	if !direct.waitForWriteCountTo(peerCandidate, probeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not retry direct probes immediately after fallback")
	}
}

func TestManagerKeepsRefreshingLocallyAfterPeerCandidatesArrive(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000025, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 5), Port: 45678}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)
	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send initial call-me-maybe")
	}

	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver peer candidates")
	}

	clock.Advance(2 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, 2, 200*time.Millisecond) {
		t.Fatal("peer candidate arrival suppressed local refresh/call-me-maybe retry")
	}
}

func TestManagerRefreshRetryAfterControlSendFailure(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000027, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)
	controls := newFakeControlPipe()
	controls.failNextSend(ControlCandidates)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 3 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 1, 200*time.Millisecond) {
		t.Fatal("manager did not attempt the first scheduled candidates refresh")
	}
	waitForManagerTimers(t, clock, 0, 2)

	clock.Advance(1 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not retry candidates refresh after send failure")
	}
}

func TestManagerIgnoresAckWithoutOutstandingProbe(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000029, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	controls := newFakeControlPipe()
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 6), Port: 56789}
	direct.failNextWriteTo(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver peer candidates")
	}

	if !direct.waitForWritePayloadTo(peerCandidate, discoProbePayload, 200*time.Millisecond) {
		t.Fatal("manager did not send initial probe")
	}
	if !waitForPath(t, mgr, PathUnknown, 100*time.Millisecond) {
		t.Fatalf("PathState() before unsolicited ack = %v, want %v", mgr.PathState(), PathUnknown)
	}

	direct.enqueueRead([]byte("derpcat-ack"), peerCandidate)

	if !waitForPath(t, mgr, PathUnknown, 100*time.Millisecond) {
		t.Fatalf("PathState() after unsolicited ack = %v, want %v", mgr.PathState(), PathUnknown)
	}
	if got := mgr.PathState(); got != PathUnknown {
		t.Fatalf("PathState() after unsolicited ack = %v, want %v", got, PathUnknown)
	}
}

func TestManagerRespondsToInboundProbeWithAck(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000031, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 7), Port: 60000}
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	direct.enqueueRead(discoProbePayload, peerCandidate)
	if !direct.waitForWritePayloadTo(peerCandidate, discoAckPayload, 200*time.Millisecond) {
		t.Fatal("manager did not reply to inbound probe with derpcat-ack")
	}
}

func TestManagerStopsOnTerminalDirectReadError(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000032, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	direct.failNextRead(io.EOF)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)
	if !direct.waitForReadAttempts(1, 200*time.Millisecond) {
		t.Fatal("direct read loop did not observe the terminal reader shutdown")
	}

	clock.Advance(5 * time.Second)
	if got := direct.readAttemptsCount(); got != 1 {
		t.Fatalf("direct read attempts after terminal error = %d, want 1", got)
	}
}

func TestManagerRetriesAfterTransientDirectReadError(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000033, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	direct.failNextRead(context.DeadlineExceeded)
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 70), Port: 60100}
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)
	if !direct.waitForReadAttempts(1, 200*time.Millisecond) {
		t.Fatal("direct read loop did not hit the transient read error")
	}
	waitForManagerTimers(t, clock, baseTimers, 3)

	direct.enqueueRead(discoProbePayload, peerCandidate)
	clock.Advance(250 * time.Millisecond)
	if !direct.waitForReadAttempts(2, 200*time.Millisecond) {
		t.Fatal("direct read loop did not retry after transient read error")
	}
	if !direct.waitForWritePayloadTo(peerCandidate, discoAckPayload, 200*time.Millisecond) {
		t.Fatal("manager did not recover to answer a probe after transient direct read error")
	}
}

func TestManagerIgnoresUnexpectedDirectNoise(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000030, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)
	controls := newFakeControlPipe()
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	direct.enqueueRead([]byte("derpcat-ack"), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 99), Port: 9999})
	direct.enqueueRead([]byte("udp-noise"), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 100), Port: 10000})
	direct.enqueueRead(append(append([]byte(nil), discoAckPayload...), []byte("-extra")...), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 101), Port: 10001})
	clock.Advance(1 * time.Second)

	if !waitForPath(t, mgr, PathRelay, 100*time.Millisecond) {
		t.Fatalf("PathState() after unexpected direct packets = %v, want %v", mgr.PathState(), PathRelay)
	}
	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after unexpected direct packets = %v, want %v", got, PathRelay)
	}
}

func TestManagerRetriesAfterTransientReceiveControlError(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000035, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	controls := newFakeControlPipe()
	controls.failNextReceive()
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 8), Port: 61000}
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver candidates after transient receive error")
	}
	if !controls.waitForReceiveErrorsDrained(200 * time.Millisecond) {
		t.Fatal("receive control loop did not hit the transient read error")
	}
	waitForManagerTimers(t, clock, baseTimers, 3)
	clock.Advance(250 * time.Millisecond)
	if !controls.waitForReceiveCount(1, 200*time.Millisecond) {
		t.Fatal("receive control loop did not recover after transient error")
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() after transient receive error recovery = %v, want %v", mgr.PathState(), PathDirect)
	}
}

func TestManagerStopsOnTerminalReceiveControlError(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000036, 0))
	controls := newFakeControlPipe()
	controls.closeReceive(io.EOF)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		ReceiveControl:    controls.receive,
		Clock:             clock,
		DiscoveryInterval: 1 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 1)
	if !controls.waitForReceiveAttempts(1, 200*time.Millisecond) {
		t.Fatal("receive control loop did not observe the terminal reader shutdown")
	}

	clock.Advance(5 * time.Second)
	if got := controls.receiveAttemptsCount(); got != 1 {
		t.Fatalf("receive control attempts after terminal error = %d, want 1", got)
	}
}

func TestManagerSerializesDiscoveryTriggers(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000037, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)
	controls := newFakeControlPipe()
	controls.blockSend(ControlCandidates)
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 9), Port: 62000}
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 5 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 1, 200*time.Millisecond) {
		t.Fatal("manager did not start the scheduled discovery refresh")
	}
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver concurrent peer candidates")
	}
	if !controls.waitForReceiveCount(1, 200*time.Millisecond) {
		t.Fatal("manager did not receive the concurrent candidates control")
	}
	if controls.waitForSendAttempts(ControlCandidates, 2, 50*time.Millisecond) {
		t.Fatal("candidate-triggered discovery overlapped with the in-flight periodic discovery")
	}

	controls.unblockSend(ControlCandidates)
}

func TestManagerSerializesCallMeMaybeTriggeredRefresh(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000038, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)
	controls := newFakeControlPipe()
	controls.blockSend(ControlCandidates)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 5 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 1, 200*time.Millisecond) {
		t.Fatal("manager did not start the scheduled discovery refresh")
	}
	if !controls.deliver(ControlMessage{Type: ControlCallMeMaybe}, 200*time.Millisecond) {
		t.Fatal("failed to deliver concurrent call-me-maybe")
	}
	if !controls.waitForReceiveCount(1, 200*time.Millisecond) {
		t.Fatal("manager did not receive the concurrent call-me-maybe")
	}
	if controls.waitForSendAttempts(ControlCandidates, 2, 50*time.Millisecond) {
		t.Fatal("call-me-maybe-triggered candidate refresh overlapped with the in-flight discovery work")
	}

	controls.unblockSend(ControlCandidates)
}

func TestManagerRelayOnlyStartKeepsRelay(t *testing.T) {
	t.Helper()

	clock := newFakeClock(time.Unix(1700000040, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)

	mgr := NewManager(ManagerConfig{
		RelayConn: relay,
		Clock:     clock,
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

	clock := newFakeClock(time.Unix(1700000050, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	mgr := NewManager(ManagerConfig{
		RelayConn:  relay,
		DirectConn: direct,
		Clock:      clock,
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

func waitForManagerTimers(t *testing.T, clock *fakeClock, base, added int) {
	t.Helper()

	want := base + added
	if !clock.waitForTimerCountAtLeast(want, 200*time.Millisecond) {
		t.Fatalf("fake clock armed %d timers, want at least %d", clock.timerCount(), want)
	}
}

func waitForPath(t *testing.T, mgr *Manager, want Path, timeout time.Duration) bool {
	t.Helper()

	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		if mgr.PathState() == want {
			return true, nil
		}
		return false, mgr.stateChanged()
	})
}
