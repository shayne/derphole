package transport

import (
	"net"
	"testing"
	"time"
)

func TestPathStateKeepsPrivateEndpointWhenPublicProbeArrivesSlightlyLater(t *testing.T) {
	now := time.Unix(1700000100, 0)
	state := newPathState(now, true, true)

	privateCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 20), Port: 12345}
	publicCandidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 12345}
	state.noteCandidates(now, []net.Addr{publicCandidate, privateCandidate})

	state.noteProbeSent(now, privateCandidate)
	state.noteProbeSent(now, publicCandidate)

	privateNow := now.Add(5 * time.Millisecond)
	if !state.consumeProbe(privateCandidate, time.Second, privateNow) {
		t.Fatal("consumeProbe(privateCandidate) = false, want true")
	}
	if !state.noteDirect(privateNow, privateCandidate) {
		t.Fatal("noteDirect(privateCandidate) = false, want true")
	}

	publicNow := now.Add(8 * time.Millisecond)
	if !state.consumeProbe(publicCandidate, time.Second, publicNow) {
		t.Fatal("consumeProbe(publicCandidate) = false, want true")
	}
	if changed := state.noteDirect(publicNow, publicCandidate); changed {
		t.Fatal("noteDirect(publicCandidate) changed the active path, want private endpoint to remain selected")
	}

	endpoint, active := state.directPath()
	if !active || endpoint != privateCandidate.String() {
		t.Fatalf("directPath() = (%q, %t), want (%q, true)", endpoint, active, privateCandidate.String())
	}
}

func TestPathStatePrefersCGNATEndpointOverPublicEndpointWhenLatencyIsClose(t *testing.T) {
	now := time.Unix(1700000101, 0)
	state := newPathState(now, true, true)

	publicCandidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 12400}
	cgnatCandidate := &net.UDPAddr{IP: net.IPv4(100, 100, 10, 20), Port: 12400}
	state.noteCandidates(now, []net.Addr{publicCandidate, cgnatCandidate})

	state.noteProbeSent(now, publicCandidate)
	state.noteProbeSent(now, cgnatCandidate)

	publicNow := now.Add(5 * time.Millisecond)
	if !state.consumeProbe(publicCandidate, time.Second, publicNow) {
		t.Fatal("consumeProbe(publicCandidate) = false, want true")
	}
	if !state.noteDirect(publicNow, publicCandidate) {
		t.Fatal("noteDirect(publicCandidate) = false, want true")
	}

	cgnatNow := now.Add(6 * time.Millisecond)
	if !state.consumeProbe(cgnatCandidate, time.Second, cgnatNow) {
		t.Fatal("consumeProbe(cgnatCandidate) = false, want true")
	}
	if changed := state.noteDirect(cgnatNow, cgnatCandidate); !changed {
		t.Fatal("noteDirect(cgnatCandidate) = false, want CGNAT endpoint to replace the public endpoint")
	}

	endpoint, active := state.directPath()
	if !active || endpoint != cgnatCandidate.String() {
		t.Fatalf("directPath() = (%q, %t), want (%q, true)", endpoint, active, cgnatCandidate.String())
	}
}
