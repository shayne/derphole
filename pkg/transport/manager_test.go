package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/net/stun"
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
	controls.deliverAfter(clock, 3*time.Second, ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	})
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

	if !controls.waitForSentCount(ControlCallMeMaybe, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send startup call-me-maybe")
	}

	if !waitForDiscoveryIdle(t, mgr, 200*time.Millisecond) {
		t.Fatal("manager did not finish startup discovery before the first refresh interval")
	}

	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)
	clock.Advance(2 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, callMeMaybeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not send call-me-maybe on the first refresh interval")
	}
	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() before delayed enablement = %v, want %v", got, PathRelay)
	}

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not respond to delayed call-me-maybe with candidates control")
	}
	if !controls.waitForReceiveCount(2, 200*time.Millisecond) {
		t.Fatal("manager did not consume the delayed call-me-maybe and candidate controls")
	}
	candidates := controls.lastSentType(ControlCandidates)
	if candidates == nil {
		t.Fatal("manager did not record the delayed candidates control")
	}
	if len(candidates.Candidates) != 1 || candidates.Candidates[0] != localCandidate.String() {
		t.Fatalf("candidate control = %#v, want %q", candidates, localCandidate.String())
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after delayed upgrade", mgr.PathState(), PathDirect)
	}
	if !direct.hasWritePayloadTo(peerCandidate, discoProbePayload) {
		t.Fatalf("manager did not send %q probe to %v", string(discoProbePayload), peerCandidate)
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

func TestManagerSeedsRemoteCandidatesWithoutWaitingForDiscoveryTick(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000012, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 12), Port: 21212}
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
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

	mgr.SeedRemoteCandidates(ctx, []net.Addr{peerCandidate})

	if !direct.waitForWritePayloadTo(peerCandidate, discoProbePayload, 200*time.Millisecond) {
		t.Fatalf("manager did not immediately probe seeded direct candidate %v", peerCandidate)
	}
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after seeded direct candidate", mgr.PathState(), PathDirect)
	}
}

func TestManagerStartsDiscoveryWithoutWaitingForFirstTick(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000014, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	localCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 9), Port: 54321}
	controls := newFakeControlPipe()
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

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	if !controls.waitForSentCount(ControlCandidates, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send startup candidates before the first scheduled tick")
	}
	if !controls.waitForSentCount(ControlCallMeMaybe, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send startup call-me-maybe before the first scheduled tick")
	}
}

func TestManagerStopDirectWaitsForActiveDiscoveryWorker(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000016, 0))
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)
	controls := newFakeControlPipe()
	baseTimers := clock.timerCount()

	candidateSourceStarted := make(chan struct{})
	releaseCandidateSource := make(chan struct{})
	candidateSourceEntered := false
	mgr := NewManager(ManagerConfig{
		DirectConn: direct,
		CandidateSource: func(context.Context) []net.Addr {
			if !candidateSourceEntered {
				candidateSourceEntered = true
				close(candidateSourceStarted)
			}
			<-releaseCandidateSource
			return []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
		},
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

	select {
	case <-candidateSourceStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("startup discovery worker did not call CandidateSource")
	}

	stopDone := make(chan struct{})
	go func() {
		mgr.StopDirect()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("StopDirect() returned while discovery worker was still blocked")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseCandidateSource)

	select {
	case <-stopDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("StopDirect() did not return after discovery worker unblocked")
	}
}

func TestManagerStopDirectReadsLeavesDiscoveryActive(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000017, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 17), Port: 21717}
	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 2 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !direct.waitForReadAttempts(1, time.Second) {
		t.Fatal("manager did not enter the direct read loop")
	}

	mgr.StopDirectReads()

	before := direct.writeCountTo(peerCandidate)
	mgr.SeedRemoteCandidates(ctx, []net.Addr{peerCandidate})
	if !direct.waitForWriteCountTo(peerCandidate, before+1, 200*time.Millisecond) {
		t.Fatalf("manager did not probe seeded candidate after StopDirectReads(); writes before=%d after=%d", before, direct.writeCountTo(peerCandidate))
	}
}

func TestManagerReadsBatchedDirectPayloadsFromBatchConn(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000013, 0))
	direct := newFakeBatchPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	direct.useClock(clock)

	peerAddr := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 13), Port: 31313}
	mgr := NewManager(ManagerConfig{
		DirectConn:         direct,
		Clock:              clock,
		DiscoveryInterval:  time.Second,
		DirectStaleTimeout: 4 * time.Second,
	})
	mgr.mu.Lock()
	mgr.state.noteCandidates(clock.Now(), []net.Addr{peerAddr})
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerAddr.String()
	mgr.state.endpoints[peerAddr.String()] = peerAddr
	mgr.mu.Unlock()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	direct.enqueueRead([]byte("packet-1"), peerAddr)
	direct.enqueueRead([]byte("packet-2"), peerAddr)

	peerConn := mgr.PeerDatagramConn(ctx)
	defer peerConn.Close()

	payload1, _, err := peerConn.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("RecvDatagram() #1 error = %v", err)
	}
	payload2, _, err := peerConn.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("RecvDatagram() #2 error = %v", err)
	}
	if got := string(payload1); got != "packet-1" {
		t.Fatalf("RecvDatagram() #1 payload = %q, want %q", got, "packet-1")
	}
	if got := string(payload2); got != "packet-2" {
		t.Fatalf("RecvDatagram() #2 payload = %q, want %q", got, "packet-2")
	}
	peerConn.ReleaseDatagram(payload1)
	peerConn.ReleaseDatagram(payload2)
}

func TestManagerRoutesDirectSTUNPacketsToHandler(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000015, 0))
	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	direct.useClock(clock)

	stunPacket := stun.Request(stun.TxID{1, 2, 3})
	stunAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 3478}
	stunCh := make(chan struct {
		payload []byte
		addr    net.Addr
	}, 1)

	mgr := NewManager(ManagerConfig{
		DirectConn: direct,
		HandleSTUNPacket: func(payload []byte, addr net.Addr) {
			stunCh <- struct {
				payload []byte
				addr    net.Addr
			}{
				payload: append([]byte(nil), payload...),
				addr:    cloneAddr(addr),
			}
		},
		Clock:                   clock,
		DiscoveryInterval:       time.Second,
		DirectStaleTimeout:      4 * time.Second,
		DisableDirectReads:      false,
		EndpointRefreshInterval: 2 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	direct.enqueueRead(stunPacket, stunAddr)

	select {
	case got := <-stunCh:
		if !bytes.Equal(got.payload, stunPacket) {
			t.Fatalf("STUN payload = %x, want %x", got.payload, stunPacket)
		}
		if got.addr.String() != stunAddr.String() {
			t.Fatalf("STUN addr = %v, want %v", got.addr, stunAddr)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("manager did not route direct STUN packet to handler")
	}
}

func TestManagerKeepsActiveDirectPathWhenCandidateSetReplacesEndpoint(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000015, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	oldCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 31), Port: 23111}
	newCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 32), Port: 23222}
	controls := newFakeControlPipe()
	direct.enableResponder(oldCandidate)
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
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{oldCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver initial direct candidate")
	}
	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after initial direct promotion", mgr.PathState(), PathDirect)
	}

	direct.clearWrites()
	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{newCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver replacement direct candidate")
	}
	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() after candidate replacement = %v, want %v while active direct path is healthy", got, PathDirect)
	}
	if endpoint, active := mgr.DirectPath(); endpoint != oldCandidate.String() || !active {
		t.Fatalf("DirectPath() after candidate replacement = (%q, %t), want (%q, true)", endpoint, active, oldCandidate.String())
	}
	if direct.waitForWritePayloadTo(newCandidate, discoProbePayload, 200*time.Millisecond) {
		t.Fatalf("manager unexpectedly reprobed replacement candidate %v while active direct path remained healthy", newCandidate)
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

func TestManagerReturnsEMSGSIZEAndKeepsDirectPathWithoutRelayFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000025, 0))
	relay := newFakeRelayDataPipe()
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 77), Port: 34567}
	controls := newFakeControlPipe()
	controls.enablePeerCandidate(peerCandidate)
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelaySend:               relay.send,
		ReceiveRelay:            relay.receive,
		RelayAddr:               relay.remote,
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
		t.Fatalf("PathState() = %v, want %v before EMSGSIZE fallback", mgr.PathState(), PathDirect)
	}

	direct.failNextWriteTo(peerCandidate, syscall.EMSGSIZE)
	if err := mgr.sendPeerDatagram(ctx, []byte("payload")); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("sendPeerDatagram() error = %v, want %v", err, syscall.EMSGSIZE)
	}
	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() after EMSGSIZE = %v, want %v", got, PathDirect)
	}
	if sent := relay.sentCount(); sent != 0 {
		t.Fatalf("relay sent %d packets after EMSGSIZE direct write, want 0", sent)
	}
}

func TestManagerCountsDroppedPeerDatagrams(t *testing.T) {
	mgr := NewManager(ManagerConfig{})
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	for i := 0; i < cap(mgr.peerRecvCh)+3; i++ {
		mgr.enqueuePeerDatagram(addr, []byte("payload"))
	}

	if got := mgr.DroppedPeerDatagrams(); got != 3 {
		t.Fatalf("DroppedPeerDatagrams() = %d, want 3", got)
	}
	if got := mgr.MaxPeerRecvQueueDepth(); got != cap(mgr.peerRecvCh) {
		t.Fatalf("MaxPeerRecvQueueDepth() = %d, want %d", got, cap(mgr.peerRecvCh))
	}
}

func TestManagerCountsRejectedDirectDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	allowed := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 4444}
	rejected := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 5555}

	mgr := NewManager(ManagerConfig{
		DirectConn:         direct,
		DisableDirectReads: false,
		DirectStaleTimeout: time.Minute,
	})
	mgr.mu.Lock()
	mgr.state.endpoints[allowed.String()] = cloneAddr(allowed)
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = allowed.String()
	mgr.state.lastDirectAt = mgr.now()
	mgr.mu.Unlock()

	direct.enqueueRead([]byte("payload"), rejected)
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !direct.waitForReadAttempts(1, time.Second) {
		t.Fatal("manager did not read the rejected datagram")
	}
	deadline := time.Now().Add(time.Second)
	for mgr.RejectedDirectDatagrams() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := mgr.RejectedDirectDatagrams(); got != 1 {
		t.Fatalf("RejectedDirectDatagrams() = %d, want 1", got)
	}
}

func TestManagerDemotesStaleDirectPathWhenReadForSend(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000020, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 44), Port: 34567}
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
		t.Fatalf("PathState() = %v, want %v before stale demotion", mgr.PathState(), PathDirect)
	}
	if !waitForDiscoveryIdle(t, mgr, 200*time.Millisecond) {
		t.Fatal("manager did not finish direct discovery before stale demotion check")
	}
	direct.disableResponder(peerCandidate)

	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)
	probeCount := direct.writeCountTo(peerCandidate)

	clock.Advance(3 * time.Second)
	if endpoint, active := mgr.DirectPath(); endpoint != "" || active {
		t.Fatalf("DirectPath() after stale direct = (%q, %t), want (\"\", false)", endpoint, active)
	}
	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after stale direct = %v, want %v", got, PathRelay)
	}

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, callMeMaybeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not send a fresh call-me-maybe after stale direct demotion")
	}
	if !direct.waitForWriteCountTo(peerCandidate, probeCount+1, 200*time.Millisecond) {
		t.Fatal("manager did not retry direct probes after stale direct demotion")
	}
}

func TestManagerPeerDatagramConnUsesRelayThenDirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700001000, 0))
	relay := newFakeRelayDataPipe()
	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	direct.useClock(clock)
	baseTimers := clock.timerCount()
	controls := newFakeControlPipe()
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 55), Port: 45555}
	controls.enablePeerCandidate(peerCandidate)
	controls.blockSend(ControlCallMeMaybe)
	direct.enableResponder(peerCandidate)

	mgr := NewManager(ManagerConfig{
		RelaySend:               relay.send,
		ReceiveRelay:            relay.receive,
		RelayAddr:               relay.remote,
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

	conn := mgr.PeerDatagramConn(ctx)
	if err := conn.SendDatagram([]byte("relay-data")); err != nil {
		t.Fatalf("SendDatagram(relay) error = %v", err)
	}
	if !relay.waitForSentCount([]byte("relay-data"), 1, 200*time.Millisecond) {
		t.Fatal("relay send did not receive payload")
	}

	controls.unblockSend(ControlCallMeMaybe)
	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v", mgr.PathState(), PathDirect)
	}

	if err := conn.SendDatagram([]byte("direct-data")); err != nil {
		t.Fatalf("SendDatagram(direct) error = %v", err)
	}
	if !direct.waitForWritePayloadTo(peerCandidate, []byte("direct-data"), 200*time.Millisecond) {
		t.Fatal("direct path did not receive payload after upgrade")
	}
}

func TestManagerPeerDatagramConnReceivesPeerDatagrams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay := newFakeRelayDataPipe()
	mgr := NewManager(ManagerConfig{
		RelaySend:    relay.send,
		ReceiveRelay: relay.receive,
		RelayAddr:    relay.remote,
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	conn := mgr.PeerDatagramConn(ctx)
	relay.deliver([]byte("from-relay"))

	payload, addr, err := conn.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("RecvDatagram() error = %v", err)
	}
	if got := string(payload); got != "from-relay" {
		t.Fatalf("RecvDatagram() payload = %q, want %q", got, "from-relay")
	}
	if got := addr.String(); got != relay.remote.String() {
		t.Fatalf("RecvDatagram() addr = %q, want %q", got, relay.remote.String())
	}
}

func TestManagerPeerDatagramConnReceivesUnknownDirectDatagramsWhileRelayed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay := newFakeRelayDataPipe()
	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	mgr := NewManager(ManagerConfig{
		RelaySend:    relay.send,
		ReceiveRelay: relay.receive,
		RelayAddr:    relay.remote,
		DirectConn:   direct,
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	unknownDirect := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 99), Port: 49999}
	direct.enqueueRead([]byte("from-unknown-direct"), unknownDirect)

	conn := mgr.PeerDatagramConn(ctx)
	payload, addr, err := conn.RecvDatagram(ctx)
	if err != nil {
		t.Fatalf("RecvDatagram() error = %v", err)
	}
	if got := string(payload); got != "from-unknown-direct" {
		t.Fatalf("RecvDatagram() payload = %q, want %q", got, "from-unknown-direct")
	}
	if got := addr.String(); got != relay.remote.String() {
		t.Fatalf("RecvDatagram() addr = %q, want stable relay peer addr %q", got, relay.remote.String())
	}
}

func TestManagerPeerDatagramConnSurvivesPathUpgrade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700001010, 0))
	relay := newFakeRelayDataPipe()
	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	direct.useClock(clock)
	baseTimers := clock.timerCount()
	controls := newFakeControlPipe()
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 56), Port: 46666}
	controls.enablePeerCandidate(peerCandidate)
	controls.blockSend(ControlCallMeMaybe)
	direct.enableResponder(peerCandidate)

	mgr := NewManager(ManagerConfig{
		RelaySend:               relay.send,
		ReceiveRelay:            relay.receive,
		RelayAddr:               relay.remote,
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

	conn := mgr.PeerDatagramConn(ctx)
	if err := conn.SendDatagram([]byte("before-upgrade")); err != nil {
		t.Fatalf("SendDatagram(before-upgrade) error = %v", err)
	}
	if !relay.waitForSentCount([]byte("before-upgrade"), 1, 2*time.Second) {
		t.Fatal("relay send did not receive initial payload")
	}

	controls.unblockSend(ControlCallMeMaybe)
	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v", mgr.PathState(), PathDirect)
	}
	if err := conn.SendDatagram([]byte("after-upgrade")); err != nil {
		t.Fatalf("SendDatagram(after-upgrade) error = %v", err)
	}
	if !direct.waitForWritePayloadTo(peerCandidate, []byte("after-upgrade"), 200*time.Millisecond) {
		t.Fatal("direct path did not receive payload after upgrade")
	}
}

func TestManagerNoteDirectActivityKeepsCurrentDirectPathActive(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000020, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 45), Port: 35567}
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
		t.Fatalf("PathState() = %v, want %v before activity refresh", mgr.PathState(), PathDirect)
	}

	clock.Advance(2 * time.Second)
	mgr.NoteDirectActivity(peerCandidate)
	clock.Advance(2 * time.Second)

	if endpoint, active := mgr.DirectPath(); endpoint != peerCandidate.String() || !active {
		t.Fatalf("DirectPath() after refreshed activity = (%q, %t), want (%q, true)", endpoint, active, peerCandidate.String())
	}
	if got := mgr.PathState(); got != PathDirect {
		t.Fatalf("PathState() after refreshed activity = %v, want %v", got, PathDirect)
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
	if !waitForDiscoveryIdle(t, mgr, 200*time.Millisecond) {
		t.Fatal("manager did not finish startup discovery before stale rediscovery")
	}

	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)
	probeCount := direct.writeCountTo(peerCandidate)
	controls.blockSend(ControlCandidates)

	clock.Advance(3 * time.Second)
	if !controls.waitForSendAttempts(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not start the stale discovery refresh")
	}

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}

	if got := mgr.PathState(); got != PathRelay {
		t.Fatalf("PathState() after fallback = %v, want %v", got, PathRelay)
	}

	controls.unblockSend(ControlCandidates)
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
	if !controls.waitForSentCount(ControlCallMeMaybe, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send startup call-me-maybe")
	}
	if !waitForDiscoveryIdle(t, mgr, 200*time.Millisecond) {
		t.Fatal("manager did not finish startup discovery before peer candidate delivery")
	}
	callMeMaybeCount := controls.sentCount(ControlCallMeMaybe)

	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver peer candidates")
	}
	if !waitForDiscoveryIdle(t, mgr, 200*time.Millisecond) {
		t.Fatal("manager did not finish peer-candidate discovery refresh")
	}

	clock.Advance(2 * time.Second)
	if !controls.waitForSentCount(ControlCallMeMaybe, callMeMaybeCount+1, 200*time.Millisecond) {
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

func TestManagerRefreshesDiscoveryWhenPortmapChanges(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000028, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	localCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 11), Port: 64000}
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 12), Port: 64001}
	mappedCandidate := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 54321}
	controls := newFakeControlPipe()
	portmap := &fakePortmap{mapped: mappedCandidate}
	direct.enableResponder(peerCandidate)
	baseTimers := clock.timerCount()

	mgr := NewManager(ManagerConfig{
		RelayConn:               relay,
		DirectConn:              direct,
		CandidateSource:         func(context.Context) []net.Addr { return []net.Addr{localCandidate} },
		Portmap:                 portmap,
		SendControl:             controls.send,
		ReceiveControl:          controls.receive,
		Clock:                   clock,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 10 * time.Second,
		DirectStaleTimeout:      4 * time.Second,
	})

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCandidates, 1, 200*time.Millisecond) {
		t.Fatal("manager did not send the initial candidate update")
	}
	initial := controls.lastSentType(ControlCandidates)
	if initial == nil {
		t.Fatal("manager did not record the initial candidate update")
	}
	if got := initial.Candidates; len(got) != 1 || got[0] != localCandidate.String() {
		t.Fatalf("initial candidates = %#v, want %q", got, localCandidate.String())
	}

	if !controls.deliver(ControlMessage{
		Type:       ControlCandidates,
		Candidates: []string{peerCandidate.String()},
	}, 200*time.Millisecond) {
		t.Fatal("failed to deliver direct peer candidate")
	}
	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v before portmap change", mgr.PathState(), PathDirect)
	}
	if endpoint, active := mgr.DirectPath(); endpoint != peerCandidate.String() || !active {
		t.Fatalf("DirectPath() before portmap change = (%q, %t), want (%q, true)", endpoint, active, peerCandidate.String())
	}

	portmap.activate()
	clock.Advance(1 * time.Second)
	if !controls.waitForSentCount(ControlCandidates, 2, 200*time.Millisecond) {
		t.Fatal("manager did not refresh candidates after the portmap changed while direct was healthy")
	}
	refreshed := controls.lastSentType(ControlCandidates)
	if refreshed == nil {
		t.Fatal("manager did not record the refreshed candidate update")
	}
	if got := refreshed.Candidates; len(got) != 2 || got[0] != localCandidate.String() || got[1] != mappedCandidate.String() {
		t.Fatalf("refreshed candidates = %#v, want [%q %q]", got, localCandidate.String(), mappedCandidate.String())
	}
	if got, active := mgr.DirectPath(); got != peerCandidate.String() || !active {
		t.Fatalf("DirectPath() after portmap change = (%q, %t), want (%q, true)", got, active, peerCandidate.String())
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
	direct.failNextWriteTo(peerCandidate, net.ErrClosed)
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
	if got := controls.sendAttemptsCount(ControlCandidates); got != 1 {
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
	if got := controls.sendAttemptsCount(ControlCandidates); got != 1 {
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

func TestManagerWaitReturnsAfterCancelWhileDirectReadLoopIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	direct := newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	mgr := NewManager(ManagerConfig{
		DirectConn:        direct,
		DiscoveryInterval: time.Hour,
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !direct.waitForReadAttempts(1, time.Second) {
		t.Fatal("manager did not enter the direct read loop")
	}

	cancel()

	done := make(chan struct{})
	go func() {
		mgr.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Wait() did not return after cancel and direct read wakeup")
	}
}

func TestManagerWaitReturnsAfterCancelWhileDirectReadLoopKeepsReceivingPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	direct := newHotPacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	mgr := NewManager(ManagerConfig{
		DirectConn:        direct,
		DiscoveryInterval: time.Hour,
	})
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case <-direct.readStarted:
	case <-time.After(time.Second):
		t.Fatal("manager did not enter the hot direct read loop")
	}

	cancel()
	done := make(chan struct{})
	go func() {
		mgr.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		_ = direct.Close()
		<-done
		t.Fatal("Wait() did not return after cancel while direct packets kept arriving")
	}
}

func TestManagerExposesDirectPathSnapshot(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newFakeClock(time.Unix(1700000060, 0))
	relay := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	direct := newFakePacketConn(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	relay.useClock(clock)
	direct.useClock(clock)

	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 10), Port: 63000}
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

	if endpoint, active := mgr.DirectPath(); endpoint != "" || active {
		t.Fatalf("DirectPath() before Start = (%q, %t), want (\"\", false)", endpoint, active)
	}

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForManagerTimers(t, clock, baseTimers, 2)

	clock.Advance(1 * time.Second)
	if !waitForPath(t, mgr, PathDirect, 200*time.Millisecond) {
		t.Fatalf("PathState() = %v, want %v after direct promotion", mgr.PathState(), PathDirect)
	}
	if endpoint, active := mgr.DirectPath(); endpoint != peerCandidate.String() || !active {
		t.Fatalf("DirectPath() after promotion = (%q, %t), want (%q, true)", endpoint, active, peerCandidate.String())
	}

	if err := mgr.MarkDirectBroken(); err != nil {
		t.Fatalf("MarkDirectBroken() error = %v", err)
	}
	if endpoint, active := mgr.DirectPath(); endpoint != "" || active {
		t.Fatalf("DirectPath() after fallback = (%q, %t), want (\"\", false)", endpoint, active)
	}
}

func TestManagerExposesDirectAddrSnapshot(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		DirectConn: newFakePacketConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}),
	})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 77), Port: 45678}

	mgr.mu.Lock()
	mgr.state.noteCandidates(mgr.now(), []net.Addr{peerCandidate})
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerCandidate.String()
	mgr.state.lastDirectAt = mgr.now()
	mgr.mu.Unlock()

	addr, active := mgr.DirectAddr()
	if !active {
		t.Fatal("DirectAddr() active = false, want true")
	}
	got, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("DirectAddr() type = %T, want *net.UDPAddr", addr)
	}
	if got.String() != peerCandidate.String() {
		t.Fatalf("DirectAddr() = %v, want %v", got, peerCandidate)
	}
}

func TestPeerDatagramConnRecvDatagramDoesNotCopyPayload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := NewManager(ManagerConfig{})
	conn := mgr.PeerDatagramConn(ctx)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	payload := []byte("payload")

	allocs := testing.AllocsPerRun(1000, func() {
		mgr.peerRecvCh <- peerPacket{payload: payload, addr: addr}
		got, _, err := conn.RecvDatagram(ctx)
		if err != nil {
			t.Fatalf("RecvDatagram() error = %v", err)
		}
		if len(got) != len(payload) {
			t.Fatalf("RecvDatagram() len = %d, want %d", len(got), len(payload))
		}
	})
	if allocs != 0 {
		t.Fatalf("RecvDatagram() allocs/run = %v, want 0", allocs)
	}
}

func TestManagerDirectAddrDoesNotAllocate(t *testing.T) {
	clock := newFakeClock(time.Unix(1700001100, 0))
	mgr := NewManager(ManagerConfig{
		DirectConn:         benchmarkPacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
		Clock:              clock,
		DirectStaleTimeout: time.Minute,
	})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 88), Port: 48888}

	mgr.mu.Lock()
	mgr.state.noteCandidates(clock.Now(), []net.Addr{peerCandidate})
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerCandidate.String()
	mgr.state.lastDirectAt = clock.Now()
	mgr.mu.Unlock()

	allocs := testing.AllocsPerRun(1000, func() {
		addr, active := mgr.DirectAddr()
		if !active {
			t.Fatal("DirectAddr() active = false, want true")
		}
		got, ok := addr.(*net.UDPAddr)
		if !ok {
			t.Fatalf("DirectAddr() type = %T, want *net.UDPAddr", addr)
		}
		if got.Port != peerCandidate.Port || !got.IP.Equal(peerCandidate.IP) {
			t.Fatalf("DirectAddr() = %v, want %v", got, peerCandidate)
		}
	})
	if allocs != 0 {
		t.Fatalf("DirectAddr() allocs/run = %v, want 0", allocs)
	}
}

func TestManagerNoteDirectActivityDoesNotAllocate(t *testing.T) {
	clock := newFakeClock(time.Unix(1700001110, 0))
	mgr := NewManager(ManagerConfig{
		DirectConn:         benchmarkPacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
		Clock:              clock,
		DirectStaleTimeout: time.Minute,
	})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 89), Port: 48889}

	mgr.mu.Lock()
	mgr.state.noteCandidates(clock.Now(), []net.Addr{peerCandidate})
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerCandidate.String()
	mgr.state.lastDirectAt = clock.Now()
	mgr.mu.Unlock()

	allocs := testing.AllocsPerRun(1000, func() {
		mgr.NoteDirectActivity(peerCandidate)
	})
	if allocs != 0 {
		t.Fatalf("NoteDirectActivity() allocs/run = %v, want 0", allocs)
	}
}

func TestManagerShouldAcceptDirectPayloadDoesNotAllocate(t *testing.T) {
	clock := newFakeClock(time.Unix(1700001120, 0))
	mgr := NewManager(ManagerConfig{
		DirectConn:         benchmarkPacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
		Clock:              clock,
		DirectStaleTimeout: time.Minute,
	})
	peerCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 90), Port: 48890}

	mgr.mu.Lock()
	mgr.state.noteCandidates(clock.Now(), []net.Addr{peerCandidate})
	mgr.state.current = PathDirect
	mgr.state.bestEndpoint = peerCandidate.String()
	mgr.state.lastDirectAt = clock.Now()
	mgr.mu.Unlock()

	allocs := testing.AllocsPerRun(1000, func() {
		if !mgr.shouldAcceptDirectPayload(peerCandidate) {
			t.Fatal("shouldAcceptDirectPayload() = false, want true")
		}
	})
	if allocs != 0 {
		t.Fatalf("shouldAcceptDirectPayload() allocs/run = %v, want 0", allocs)
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

func waitForDiscoveryIdle(t *testing.T, mgr *Manager, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		mgr.discoveryMu.Lock()
		running := mgr.discoveryRun
		mgr.discoveryMu.Unlock()
		if !running {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

type fakePortmap struct {
	mu      sync.Mutex
	mapped  net.Addr
	have    bool
	changed bool
}

func (p *fakePortmap) Refresh(time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.changed {
		p.changed = false
		p.have = true
		return true
	}
	return false
}

func (p *fakePortmap) SnapshotAddrs() []net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.have || p.mapped == nil {
		return nil
	}
	return []net.Addr{cloneAddr(p.mapped)}
}

func (p *fakePortmap) activate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.changed = true
}

type hotPacketConn struct {
	local           net.Addr
	readStartedOnce sync.Once
	readStarted     chan struct{}
	closed          chan struct{}
}

func newHotPacketConn(local net.Addr) *hotPacketConn {
	return &hotPacketConn{
		local:       local,
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (c *hotPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readStartedOnce.Do(func() {
		close(c.readStarted)
	})
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}
	time.Sleep(time.Millisecond)
	return copy(b, discoProbePayload), &net.UDPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 12345}, nil
}

func (c *hotPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

func (c *hotPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *hotPacketConn) LocalAddr() net.Addr              { return c.local }
func (c *hotPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *hotPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *hotPacketConn) SetWriteDeadline(time.Time) error { return nil }
