// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestExternalV2DataPacketCandidateKeepsSetMappedLanesIsolated(t *testing.T) {
	prevRoute := externalDirectUDPRouteCandidate
	externalDirectUDPRouteCandidate = func(_ net.PacketConn, _ string) bool {
		return true
	}
	t.Cleanup(func() { externalDirectUDPRouteCandidate = prevRoute })

	selected := []string{"", ""}
	fallback := []string{"", "203.0.113.20:20000"}
	if got := selectExternalV2DataPacketCandidate(nil, 0, selected, fallback, false); got != "" {
		t.Fatalf("set-mapped candidate = %q, want empty when this lane has no candidate", got)
	}
	if got, want := selectExternalV2DataPacketCandidate(nil, 0, selected, fallback, true), "203.0.113.20:20000"; got != want {
		t.Fatalf("pooled candidate = %q, want %q", got, want)
	}
}

func TestExternalV2DataPacketSelectionRequiresObservedPunchByDefault(t *testing.T) {
	if externalV2DataPacketSelectionObserved(context.Background(), []string{"", ""}, nil) {
		t.Fatal("selection observed with no selected addresses, want false")
	}
	if !externalV2DataPacketSelectionObserved(context.Background(), []string{"198.51.100.10:10000", ""}, nil) {
		t.Fatal("selection not observed with one selected address, want true")
	}
	if !externalV2DataPacketSelectionObserved(withExternalDirectUDPAllowUnverifiedFallback(context.Background()), []string{"", ""}, nil) {
		t.Fatal("selection not allowed with unverified fallback context, want true")
	}
}

func TestExternalV2DataPlaneReadyPhaseMatchesOnlyExpectedPhase(t *testing.T) {
	if !externalV2DataPlaneReadyPhaseMatches(externalV2DataPlanePhaseCandidates, externalV2DataPlanePhaseCandidates) {
		t.Fatal("candidate phase did not match itself")
	}
	if !externalV2DataPlaneReadyPhaseMatches("", externalV2DataPlanePhaseCandidates) {
		t.Fatal("legacy empty phase did not match candidate phase")
	}
	if externalV2DataPlaneReadyPhaseMatches(externalV2DataPlanePhaseCandidates, externalV2DataPlanePhaseSelection) {
		t.Fatal("candidate phase matched selection phase")
	}
	if externalV2DataPlaneReadyPhaseMatches("", externalV2DataPlanePhaseSelection) {
		t.Fatal("legacy empty phase matched selection phase")
	}
}

func TestFormatExternalV2SelectedAddrsReportsNoneForEmptyLaneSelections(t *testing.T) {
	if got := formatExternalV2SelectedAddrs([]string{"", "", ""}); got != "none" {
		t.Fatalf("formatted selected addrs = %q, want none", got)
	}
	if got, want := formatExternalV2SelectedAddrs([]string{"", "203.0.113.10:1234", ""}), "203.0.113.10:1234"; got != want {
		t.Fatalf("formatted selected addrs = %q, want %q", got, want)
	}
}

func TestSelectExternalV2DataPacketAddrsUsesObservedFlatCandidates(t *testing.T) {
	conns := listenUDPConnsForExternalV2DataPacketTest(t, 2)
	observed := parseCandidateStrings([]string{"127.0.0.1:41001", "127.0.0.1:41002"})
	peerCandidates := parseCandidateStrings([]string{"127.0.0.1:42001", "127.0.0.1:42002"})

	prevObserve := externalDirectUDPObservePunchAddrsByConn
	externalDirectUDPObservePunchAddrsByConn = func(context.Context, []net.PacketConn, time.Duration) [][]net.Addr {
		return [][]net.Addr{{observed[0]}, {observed[1]}}
	}
	t.Cleanup(func() { externalDirectUDPObservePunchAddrsByConn = prevObserve })

	prevRoute := externalDirectUDPRouteCandidate
	externalDirectUDPRouteCandidate = func(net.PacketConn, string) bool {
		return true
	}
	t.Cleanup(func() { externalDirectUDPRouteCandidate = prevRoute })

	got := selectExternalV2DataPacketAddrs(context.Background(), conns, nil, peerCandidates, nil, 0)
	if len(got) != 2 {
		t.Fatalf("selected addrs len = %d, want 2 (%v)", len(got), got)
	}
	if got[0].String() != "127.0.0.1:41001" || got[1].String() != "127.0.0.1:41002" {
		t.Fatalf("selected addrs = %v, want observed addresses", got)
	}
}

func TestSelectExternalV2DataPacketAddrsKeepsCandidateSetsLaneMapped(t *testing.T) {
	conns := listenUDPConnsForExternalV2DataPacketTest(t, 2)
	observed := parseCandidateStrings([]string{"127.0.0.1:43001", "127.0.0.1:43002"})
	peerCandidateSets := [][]string{
		{"127.0.0.1:44001"},
		{"127.0.0.1:44002"},
	}

	prevObserve := externalDirectUDPObservePunchAddrsByConn
	externalDirectUDPObservePunchAddrsByConn = func(context.Context, []net.PacketConn, time.Duration) [][]net.Addr {
		return [][]net.Addr{{observed[0]}, {observed[1]}}
	}
	t.Cleanup(func() { externalDirectUDPObservePunchAddrsByConn = prevObserve })

	prevRoute := externalDirectUDPRouteCandidate
	externalDirectUDPRouteCandidate = func(net.PacketConn, string) bool {
		return true
	}
	t.Cleanup(func() { externalDirectUDPRouteCandidate = prevRoute })

	got := selectExternalV2DataPacketAddrs(context.Background(), conns, peerCandidateSets, nil, nil, 0)
	if len(got) != 2 {
		t.Fatalf("selected addrs len = %d, want 2 (%v)", len(got), got)
	}
	if got[0].String() != "127.0.0.1:43001" || got[1].String() != "127.0.0.1:43002" {
		t.Fatalf("selected addrs = %v, want lane-mapped observed addresses", got)
	}
}

func TestSelectExternalV2DataPacketAddrsFiltersObservedTailscaleInInternetOnlyMode(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")
	conns := listenUDPConnsForExternalV2DataPacketTest(t, 1)
	observed := parseCandidateStrings([]string{"100.125.235.82:60438"})
	peerCandidates := parseCandidateStrings([]string{"100.125.235.82:60438", "108.18.210.122:60438"})

	prevObserve := externalDirectUDPObservePunchAddrsByConn
	externalDirectUDPObservePunchAddrsByConn = func(context.Context, []net.PacketConn, time.Duration) [][]net.Addr {
		return [][]net.Addr{{observed[0]}}
	}
	t.Cleanup(func() { externalDirectUDPObservePunchAddrsByConn = prevObserve })

	prevRoute := externalDirectUDPRouteCandidate
	externalDirectUDPRouteCandidate = func(net.PacketConn, string) bool {
		return true
	}
	t.Cleanup(func() { externalDirectUDPRouteCandidate = prevRoute })

	if got := selectExternalV2DataPacketAddrs(context.Background(), conns, nil, peerCandidates, nil, 0); len(got) != 0 {
		t.Fatalf("selected addrs = %v, want no raw-direct promotion from Tailscale observation in internet-only mode", got)
	}
}

func TestSelectExternalV2DataPacketAddrsBySetFiltersObservedTailscaleInInternetOnlyMode(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")
	conns := listenUDPConnsForExternalV2DataPacketTest(t, 1)
	observed := parseCandidateStrings([]string{"100.125.235.82:60438"})
	peerCandidateSets := [][]string{{"100.125.235.82:60438", "108.18.210.122:60438"}}

	prevObserve := externalDirectUDPObservePunchAddrsByConn
	externalDirectUDPObservePunchAddrsByConn = func(context.Context, []net.PacketConn, time.Duration) [][]net.Addr {
		return [][]net.Addr{{observed[0]}}
	}
	t.Cleanup(func() { externalDirectUDPObservePunchAddrsByConn = prevObserve })

	prevRoute := externalDirectUDPRouteCandidate
	externalDirectUDPRouteCandidate = func(net.PacketConn, string) bool {
		return true
	}
	t.Cleanup(func() { externalDirectUDPRouteCandidate = prevRoute })

	if got := selectExternalV2DataPacketAddrs(context.Background(), conns, peerCandidateSets, nil, nil, 0); len(got) != 0 {
		t.Fatalf("selected addrs = %v, want no raw-direct promotion from set-mapped Tailscale observation in internet-only mode", got)
	}
}

func TestFinalizeExternalV2RawDirectPathRequiresPeerRawSelection(t *testing.T) {
	closed := false
	path := externalV2DirectPacketPath{
		raw: true,
		cleanup: func() {
			closed = true
		},
	}

	got := finalizeExternalV2RawDirectPath(path, false, nil)
	if got.raw {
		t.Fatal("finalized path uses raw-direct when peer selected manager, want manager fallback")
	}
	if !closed {
		t.Fatal("raw-direct resources were not closed after peer selected manager")
	}
}

func TestStartExternalV2DataPacketPunchingHonorsDelay(t *testing.T) {
	local := listenUDPConnsForExternalV2DataPacketTest(t, 1)
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	remoteAddr, err := net.ResolveUDPAddr("udp", receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startExternalV2DataPacketPunching(ctx, local, []net.Addr{remoteAddr}, 100*time.Millisecond)

	if err := receiver.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	if _, _, err := receiver.ReadFrom(buf); err == nil {
		t.Fatal("received punch before configured delay")
	}

	if err := receiver.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("did not receive punch after configured delay: %v", err)
	}
	if got := string(buf[:n]); got != "derphole-punch" {
		t.Fatalf("punch payload = %q, want derphole-punch", got)
	}
}

func listenUDPConnsForExternalV2DataPacketTest(t *testing.T, count int) []net.PacketConn {
	t.Helper()
	conns := make([]net.PacketConn, 0, count)
	for range count {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket() error = %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		conns = append(conns, conn)
	}
	return conns
}

func TestExternalV2RawDirectEnabledDefaultsOnAndCanBeDisabled(t *testing.T) {
	t.Setenv("DERPHOLE_V2_RAW_DIRECT", "")
	if !externalV2RawDirectEnabled() {
		t.Fatal("externalV2RawDirectEnabled() = false with empty env, want true")
	}

	for _, value := range []string{"0", "false", "off", "no"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DERPHOLE_V2_RAW_DIRECT", value)
			if externalV2RawDirectEnabled() {
				t.Fatalf("externalV2RawDirectEnabled() = true with %q, want false", value)
			}
		})
	}

	t.Setenv("DERPHOLE_V2_RAW_DIRECT", "1")
	if !externalV2RawDirectEnabled() {
		t.Fatal("externalV2RawDirectEnabled() = false with 1, want true")
	}
}
