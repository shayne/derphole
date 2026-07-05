// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"testing"
	"time"
)

func TestCandidateStatusString(t *testing.T) {
	tests := []struct {
		status candidateStatus
		want   string
	}{
		{status: candidatePending, want: "pending"},
		{status: candidateOpen, want: "open"},
		{status: candidateInactive, want: "inactive"},
		{status: candidateUnusable, want: "unusable"},
		{status: candidateStatus(99), want: "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Fatalf("candidateStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestPathStateInitializesCandidateLifecycle(t *testing.T) {
	state := newPathState(time.Now(), true, true)

	if state.candidateLifecycle == nil {
		t.Fatal("newPathState().candidateLifecycle = nil, want initialized map")
	}
}

func TestPathStateTracksCandidateLifecycleTransitions(t *testing.T) {
	now := time.Unix(1700000090, 0)
	state := newPathState(now, true, true)

	publicCandidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 90), Port: 19090}
	cgnatCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 90), Port: 19090}
	state.noteCandidates(now, []net.Addr{publicCandidate, cgnatCandidate})

	state.noteProbeSent(now, publicCandidate, directProbeToken{})
	publicNow := now.Add(20 * time.Millisecond)
	if !state.consumeProbe(publicCandidate, time.Second, publicNow, directProbeToken{}) {
		t.Fatal("consumeProbe(publicCandidate) = false, want true")
	}
	if !state.noteDirect(publicNow, publicCandidate) {
		t.Fatal("noteDirect(publicCandidate) = false, want true")
	}
	if got := state.candidateLifecycle[publicCandidate.String()].status; got != candidateOpen {
		t.Fatalf("public candidate status = %s, want %s", got, candidateOpen)
	}

	state.noteProbeSent(now.Add(time.Second), cgnatCandidate, directProbeToken{})
	cgnatNow := now.Add(time.Second + 19*time.Millisecond)
	if !state.consumeProbe(cgnatCandidate, time.Second, cgnatNow, directProbeToken{}) {
		t.Fatal("consumeProbe(cgnatCandidate) = false, want true")
	}
	if !state.noteDirect(cgnatNow, cgnatCandidate) {
		t.Fatal("noteDirect(cgnatCandidate) = false, want true")
	}

	if got := state.candidateLifecycle[publicCandidate.String()].status; got != candidateInactive {
		t.Fatalf("public candidate status after replacement = %s, want %s", got, candidateInactive)
	}
	if got := state.candidateLifecycle[cgnatCandidate.String()].status; got != candidateOpen {
		t.Fatalf("CGNAT candidate status after promotion = %s, want %s", got, candidateOpen)
	}
}

func TestPathStateKeepsOpenCandidateAcrossReplacement(t *testing.T) {
	now := time.Unix(1700000091, 0)
	state := newPathState(now, true, true)

	activeCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 91), Port: 19191}
	replacementCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 92), Port: 19191}
	state.noteCandidates(now, []net.Addr{activeCandidate})

	state.noteProbeSent(now, activeCandidate, directProbeToken{})
	activeNow := now.Add(10 * time.Millisecond)
	if !state.consumeProbe(activeCandidate, time.Second, activeNow, directProbeToken{}) {
		t.Fatal("consumeProbe(activeCandidate) = false, want true")
	}
	if !state.noteDirect(activeNow, activeCandidate) {
		t.Fatal("noteDirect(activeCandidate) = false, want true")
	}

	state.noteCandidates(now.Add(time.Second), []net.Addr{replacementCandidate})

	if _, ok := state.endpoints[activeCandidate.String()]; !ok {
		t.Fatal("active direct endpoint removed from endpoints after candidate replacement")
	}
	if got := state.candidateLifecycle[activeCandidate.String()].status; got != candidateOpen {
		t.Fatalf("active candidate status after replacement = %s, want %s", got, candidateOpen)
	}
}

func TestPathStateSuppressesFailedProbeTargetsBriefly(t *testing.T) {
	now := time.Unix(1700000092, 0)
	state := newPathState(now, true, true)

	candidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 93), Port: 19292}
	token := directProbeToken{}
	state.noteCandidates(now, []net.Addr{candidate})
	state.noteProbeSent(now, candidate, token)
	state.noteProbeFailed(now.Add(10*time.Millisecond), candidate, token, defaultCandidateSuppressPeriod)

	suppressedPlan := state.discoveryPlan(now.Add(time.Second), time.Minute, time.Hour, time.Second)
	if len(suppressedPlan.probeTargets) != 0 {
		t.Fatalf("probeTargets while suppressed = %d, want 0", len(suppressedPlan.probeTargets))
	}

	retryPlan := state.discoveryPlan(now.Add(10*time.Millisecond+defaultCandidateSuppressPeriod+time.Millisecond), time.Minute, time.Hour, time.Second)
	if len(retryPlan.probeTargets) != 1 || retryPlan.probeTargets[0].String() != candidate.String() {
		t.Fatalf("probeTargets after suppression = %#v, want %v", retryPlan.probeTargets, candidate)
	}
}

func TestPathStateExpiresPendingProbeAsUnusable(t *testing.T) {
	now := time.Unix(1700000093, 0)
	state := newPathState(now, true, true)

	candidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 94), Port: 19393}
	state.noteCandidates(now, []net.Addr{candidate})
	state.noteProbeSent(now, candidate, directProbeToken{})

	plan := state.discoveryPlan(now.Add(2*time.Second), time.Minute, time.Hour, time.Second)
	if len(plan.probeTargets) != 0 {
		t.Fatalf("probeTargets after pending expiry = %d, want 0", len(plan.probeTargets))
	}
	if got := state.candidateLifecycle[candidate.String()].status; got != candidateUnusable {
		t.Fatalf("candidate status after pending expiry = %s, want %s", got, candidateUnusable)
	}
}

func TestPathStatePrunesUnusableBeforePendingAndKeepsActiveDirect(t *testing.T) {
	now := time.Unix(1700000094, 0)
	state := newPathState(now, true, true)

	activeCandidate := transportStateTestCandidate(999)
	state.noteCandidates(now, []net.Addr{activeCandidate})
	state.noteProbeSent(now, activeCandidate, directProbeToken{})
	activeNow := now.Add(10 * time.Millisecond)
	if !state.consumeProbe(activeCandidate, time.Second, activeNow, directProbeToken{}) {
		t.Fatal("consumeProbe(activeCandidate) = false, want true")
	}
	if !state.noteDirect(activeNow, activeCandidate) {
		t.Fatal("noteDirect(activeCandidate) = false, want true")
	}

	candidates := make([]net.Addr, 0, maxTrackedNonRelayCandidates)
	for i := 0; i < maxTrackedNonRelayCandidates; i++ {
		candidates = append(candidates, transportStateTestCandidate(i))
	}
	state.noteCandidates(now.Add(time.Second), candidates)
	for i := 0; i < 5; i++ {
		state.markCandidateUnusable(now.Add(2*time.Second), candidates[i].String(), defaultCandidateSuppressPeriod)
	}
	for i := 0; i < 5; i++ {
		extra := transportStateTestCandidate(maxTrackedNonRelayCandidates + i)
		key := extra.String()
		state.endpoints[key] = cloneAddr(extra)
		state.noteCandidateSeen(now.Add(3*time.Second), key, extra)
	}

	state.pruneEndpointState(now.Add(4 * time.Second))

	if _, ok := state.endpoints[activeCandidate.String()]; !ok {
		t.Fatal("active direct endpoint removed during pruning")
	}
	for i := 0; i < 5; i++ {
		key := candidates[i].String()
		if _, ok := state.candidateLifecycle[key]; ok {
			t.Fatalf("unusable candidate %q remained in lifecycle after pruning", key)
		}
		if _, ok := state.endpoints[key]; ok {
			t.Fatalf("unusable candidate %q remained in endpoints after pruning", key)
		}
	}
	nonActive := len(state.candidateLifecycle)
	if _, ok := state.candidateLifecycle[activeCandidate.String()]; ok {
		nonActive--
	}
	if nonActive > maxTrackedNonRelayCandidates {
		t.Fatalf("tracked non-active candidates = %d, want <= %d", nonActive, maxTrackedNonRelayCandidates)
	}
}

func TestPathStatePruneKeepsRecentInactiveCandidates(t *testing.T) {
	now := time.Unix(1700000095, 0)
	state := newPathState(now, true, true)

	candidates := make([]net.Addr, 0, maxInactiveNonRelayCandidates+3)
	for i := 0; i < maxInactiveNonRelayCandidates+3; i++ {
		candidates = append(candidates, transportStateTestCandidate(100+i))
	}
	state.noteCandidates(now, candidates)
	for i, candidate := range candidates {
		state.markCandidateInactive(now.Add(time.Duration(i)*time.Millisecond), candidate.String())
	}

	state.pruneEndpointState(now.Add(time.Second))

	inactive := 0
	for _, candidate := range candidates {
		if state.candidateLifecycle[candidate.String()].status == candidateInactive {
			inactive++
		}
	}
	if inactive != maxInactiveNonRelayCandidates {
		t.Fatalf("inactive candidates after pruning = %d, want %d", inactive, maxInactiveNonRelayCandidates)
	}
	for i := 0; i < 3; i++ {
		if _, ok := state.candidateLifecycle[candidates[i].String()]; ok {
			t.Fatalf("old inactive candidate %q remained after pruning", candidates[i])
		}
	}
	for i := 3; i < len(candidates); i++ {
		if got := state.candidateLifecycle[candidates[i].String()].status; got != candidateInactive {
			t.Fatalf("recent inactive candidate %q status = %s, want %s", candidates[i], got, candidateInactive)
		}
	}
}

func TestPathStateKeepsPrivateEndpointWhenPublicProbeArrivesSlightlyLater(t *testing.T) {
	now := time.Unix(1700000100, 0)
	state := newPathState(now, true, true)

	privateCandidate := &net.UDPAddr{IP: net.IPv4(100, 64, 0, 20), Port: 12345}
	publicCandidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 12345}
	state.noteCandidates(now, []net.Addr{publicCandidate, privateCandidate})

	state.noteProbeSent(now, privateCandidate, directProbeToken{})
	state.noteProbeSent(now, publicCandidate, directProbeToken{})

	privateNow := now.Add(5 * time.Millisecond)
	if !state.consumeProbe(privateCandidate, time.Second, privateNow, directProbeToken{}) {
		t.Fatal("consumeProbe(privateCandidate) = false, want true")
	}
	if !state.noteDirect(privateNow, privateCandidate) {
		t.Fatal("noteDirect(privateCandidate) = false, want true")
	}

	publicNow := now.Add(8 * time.Millisecond)
	if !state.consumeProbe(publicCandidate, time.Second, publicNow, directProbeToken{}) {
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

	state.noteProbeSent(now, publicCandidate, directProbeToken{})
	state.noteProbeSent(now, cgnatCandidate, directProbeToken{})

	publicNow := now.Add(5 * time.Millisecond)
	if !state.consumeProbe(publicCandidate, time.Second, publicNow, directProbeToken{}) {
		t.Fatal("consumeProbe(publicCandidate) = false, want true")
	}
	if !state.noteDirect(publicNow, publicCandidate) {
		t.Fatal("noteDirect(publicCandidate) = false, want true")
	}

	cgnatNow := now.Add(6 * time.Millisecond)
	if !state.consumeProbe(cgnatCandidate, time.Second, cgnatNow, directProbeToken{}) {
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

func TestPathStateKeepsCurrentDirectEndpointWhenRTTImprovementIsBelowHysteresis(t *testing.T) {
	now := time.Unix(1700000102, 0)
	state := newPathState(now, true, true)

	current := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 12600}
	candidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 61), Port: 12600}
	state.noteCandidates(now, []net.Addr{current, candidate})

	state.noteProbeSent(now, current, directProbeToken{})
	currentNow := now.Add(20 * time.Millisecond)
	if !state.consumeProbe(current, time.Second, currentNow, directProbeToken{}) {
		t.Fatal("consumeProbe(current) = false, want true")
	}
	if !state.noteDirect(currentNow, current) {
		t.Fatal("noteDirect(current) = false, want true")
	}

	candidateSentAt := now.Add(time.Second)
	state.noteProbeSent(candidateSentAt, candidate, directProbeToken{})
	candidateNow := candidateSentAt.Add(16 * time.Millisecond)
	if !state.consumeProbe(candidate, time.Second, candidateNow, directProbeToken{}) {
		t.Fatal("consumeProbe(candidate) = false, want true")
	}
	if changed := state.noteDirect(candidateNow, candidate); changed {
		t.Fatal("noteDirect(candidate) changed the active path, want current endpoint to remain selected")
	}

	endpoint, active := state.directPath()
	if !active || endpoint != current.String() {
		t.Fatalf("directPath() = (%q, %t), want (%q, true)", endpoint, active, current.String())
	}
}

func TestPathStateSwitchesDirectEndpointWhenRTTImprovementMeetsHysteresis(t *testing.T) {
	now := time.Unix(1700000103, 0)
	state := newPathState(now, true, true)

	current := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 70), Port: 12700}
	candidate := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 71), Port: 12700}
	state.noteCandidates(now, []net.Addr{current, candidate})

	state.noteProbeSent(now, current, directProbeToken{})
	currentNow := now.Add(20 * time.Millisecond)
	if !state.consumeProbe(current, time.Second, currentNow, directProbeToken{}) {
		t.Fatal("consumeProbe(current) = false, want true")
	}
	if !state.noteDirect(currentNow, current) {
		t.Fatal("noteDirect(current) = false, want true")
	}

	candidateSentAt := now.Add(time.Second)
	state.noteProbeSent(candidateSentAt, candidate, directProbeToken{})
	candidateNow := candidateSentAt.Add(15 * time.Millisecond)
	if !state.consumeProbe(candidate, time.Second, candidateNow, directProbeToken{}) {
		t.Fatal("consumeProbe(candidate) = false, want true")
	}
	if changed := state.noteDirect(candidateNow, candidate); !changed {
		t.Fatal("noteDirect(candidate) = false, want candidate endpoint to replace current")
	}

	endpoint, active := state.directPath()
	if !active || endpoint != candidate.String() {
		t.Fatalf("directPath() = (%q, %t), want (%q, true)", endpoint, active, candidate.String())
	}
}

func transportStateTestCandidate(i int) net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(100, 64, byte(i/250), byte(i%250+1)),
		Port: 20000 + i,
	}
}
