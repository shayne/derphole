// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
)

const externalDirectUDPPunchWait = 1200 * time.Millisecond

type externalDirectUDPAllowUnverifiedFallbackContextKey struct{}

var externalDirectUDPProbeCandidates = publicProbeCandidates
var externalDirectUDPObservePunchAddrsByConn = probe.ObservePunchAddrsByConn
var externalDirectUDPRouteCandidate = externalDirectUDPDefaultRouteCandidate

var externalDirectUDPRouteProbePayload = []byte("derphole-direct-udp-route-check-v1")

func withExternalDirectUDPAllowUnverifiedFallback(ctx context.Context) context.Context {
	return context.WithValue(ctx, externalDirectUDPAllowUnverifiedFallbackContextKey{}, true)
}

func externalDirectUDPAllowUnverifiedFallback(ctx context.Context) bool {
	allow, _ := ctx.Value(externalDirectUDPAllowUnverifiedFallbackContextKey{}).(bool)
	return allow
}

func externalDirectUDPActivateDirectPath(pathEmitter *transportPathEmitter, transportManager *transport.Manager, punchCancel context.CancelFunc) {
	if pathEmitter != nil {
		pathEmitter.SuppressRelayRegression()
		pathEmitter.Emit(StateTryingDirect)
	}
	if transportManager != nil {
		transportManager.StopDirectReads()
	}
	externalDirectUDPStopPunchingForBlast(punchCancel)
}

func externalDirectUDPStopPunchingForBlast(cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
}

func externalDirectUDPCandidateSetsWithTimeout(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap, wait time.Duration) [][]string {
	sets := make([][]string, len(conns))
	var wg sync.WaitGroup
	wg.Add(len(conns))
	for i := range conns {
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, wait)
			defer cancel()
			var pm publicPortmap
			if i < len(portmaps) {
				pm = portmaps[i]
			}
			sets[i] = externalDirectUDPOrderCandidateStrings(externalDirectUDPProbeCandidates(probeCtx, conns[i], dm, pm))
		}()
	}
	wg.Wait()
	return sets
}

func externalDirectUDPOrderCandidateStrings(candidates []string) []string {
	if fakeTransportEnabled() {
		return externalDirectUDPPreferLoopbackStrings(candidates)
	}
	return externalDirectUDPPreferWANStrings(candidates)
}

func externalDirectUDPInferWANPerPort(sets [][]string) [][]string {
	wan, ok := externalDirectUDPFirstWANCandidateAddr(sets)
	if !ok {
		return sets
	}
	out := make([][]string, len(sets))
	for i, candidates := range sets {
		out[i] = append([]string(nil), candidates...)
		port, ok := externalDirectUDPPrivatePortForWANInference(candidates)
		if !ok {
			continue
		}
		inferred := netip.AddrPortFrom(wan, port).String()
		out[i] = append([]string{inferred}, out[i]...)
	}
	return out
}

func externalDirectUDPFirstWANCandidateAddr(sets [][]string) (netip.Addr, bool) {
	for _, candidates := range sets {
		for _, candidate := range candidates {
			addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
			if ok && externalDirectUDPCandidateRank(candidate) == 0 {
				return addrPort.Addr(), true
			}
		}
	}
	return netip.Addr{}, false
}

func externalDirectUDPPrivatePortForWANInference(candidates []string) (uint16, bool) {
	var port uint16
	for _, candidate := range candidates {
		addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
		if !ok {
			continue
		}
		if externalDirectUDPCandidateRank(candidate) == 0 {
			return 0, false
		}
		if port == 0 && addrPort.Addr().IsPrivate() {
			port = addrPort.Port()
		}
	}
	return port, port != 0
}

func externalDirectUDPStartPunching(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr) {
	if len(remoteCandidates) == 0 {
		return
	}
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		go probe.PunchAddrs(ctx, conn, remoteCandidates, nil, 0)
	}
}

func externalDirectUDPFormatObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, strconv.Itoa(i)+"="+strings.Join(externalDirectUDPParallelCandidateStrings(observed, len(observed)), "|"))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPSelectRemoteAddrsByConn(observedByConn [][]net.Addr, conns []net.PacketConn, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = len(observedByConn)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	selectCandidate := func(i int, candidate string) bool {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			return false
		}
		if !externalDirectUDPCanRouteSelectedCandidate(conns, i, candidate) {
			return false
		}
		out[i] = candidate
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		return true
	}
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range externalDirectUDPParallelCandidateStringsForPeer(observedByConn[i], len(observedByConn[i]), peer) {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	return out
}

func externalDirectUDPCanRouteSelectedCandidate(conns []net.PacketConn, i int, candidate string) bool {
	if i < 0 || i >= len(conns) || conns[i] == nil {
		return true
	}
	return externalDirectUDPRouteCandidate(conns[i], candidate)
}

func externalDirectUDPDefaultRouteCandidate(conn net.PacketConn, candidate string) bool {
	addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
	if conn == nil || !ok {
		return false
	}
	_, err := conn.WriteTo(externalDirectUDPRouteProbePayload, net.UDPAddrFromAddrPort(addrPort))
	return err == nil
}

func externalDirectUDPSelectedAddrCount(addrs []string) int {
	count := 0
	for _, addr := range addrs {
		if addr != "" {
			count++
		}
	}
	return count
}

func externalDirectUDPFilterFallbackAddrsForSelectedScope(selected []string, fallback []string) []string {
	selectedRank := externalDirectUDPBestCandidateRank(selected)
	if selectedRank == -1 {
		selectedRank = externalDirectUDPBestCandidateRank(fallback)
		if selectedRank == -1 {
			return fallback
		}
	}

	filtered := make([]string, 0, len(fallback))
	for _, candidate := range fallback {
		if candidate == "" || externalDirectUDPCandidateRank(candidate) != selectedRank {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func externalDirectUDPBestCandidateRank(candidates []string) int {
	bestRank := -1
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		rank := externalDirectUDPCandidateRank(candidate)
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
		}
	}
	return bestRank
}

func externalDirectUDPParallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	return externalDirectUDPParallelCandidateStringsForPeer(candidates, parallel, nil)
}

func externalDirectUDPParallelCandidateStringsForPeer(candidates []net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := externalDirectUDPOrderedCandidateStringsForPeer(candidates, peer)
	out, seen := externalDirectUDPAppendUniqueEndpointCandidates(nil, ordered, parallel)
	out, _ = externalDirectUDPAppendUniqueCandidates(out, seen, ordered, parallel)
	return out
}

func externalDirectUDPOrderedCandidateStringsForPeer(candidates []net.Addr, peer net.Addr) []string {
	ordered := externalDirectUDPAppendPeerCandidate(probe.CandidateStringsInOrder(candidates), peer)
	if fakeTransportEnabled() {
		return externalDirectUDPPreferLoopbackStrings(ordered)
	}
	return externalDirectUDPPreferPeerAddrStrings(ordered, peer)
}

func externalDirectUDPAppendPeerCandidate(ordered []string, peer net.Addr) []string {
	peerAddr, ok := externalDirectUDPAddrPort(peer)
	if !ok {
		return ordered
	}
	peerCandidate := peerAddr.String()
	if slices.Contains(ordered, peerCandidate) {
		return ordered
	}
	return append(ordered, peerCandidate)
}

func externalDirectUDPAppendUniqueEndpointCandidates(out []string, candidates []string, limit int) ([]string, map[string]bool) {
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	if len(out) >= limit {
		return out, seen
	}
	for _, candidate := range candidates {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		if len(out) >= limit {
			return out, seen
		}
	}
	return out, seen
}

func externalDirectUDPAppendUniqueCandidates(out []string, seen map[string]bool, candidates []string, limit int) ([]string, map[string]bool) {
	if len(out) >= limit {
		return out, seen
	}
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) >= limit {
			return out, seen
		}
	}
	return out, seen
}

func externalDirectUDPPreferPeerAddrStrings(candidates []string, peer net.Addr) []string {
	out := externalDirectUDPPreferWANStrings(candidates)
	peerAddr, ok := externalDirectUDPAddrPort(peer)
	if !ok {
		return out
	}
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromotePeerCandidate(candidate, out[j], peerAddr.Addr()) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromotePeerCandidate(candidate string, existing string, peer netip.Addr) bool {
	candidatePeer := externalDirectUDPMatchesPeerAddr(candidate, peer)
	existingPeer := externalDirectUDPMatchesPeerAddr(existing, peer)
	if candidatePeer != existingPeer {
		return candidatePeer
	}
	return candidatePeer && externalDirectUDPShouldPromoteCandidate(candidate, existing)
}

func externalDirectUDPMatchesPeerAddr(candidate string, peer netip.Addr) bool {
	candidateAddr, err := netip.ParseAddrPort(candidate)
	return err == nil && candidateAddr.Addr() == peer
}

func externalDirectUDPAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalDirectUDPPreferLoopbackStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteLoopbackCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteLoopbackCandidate(candidate string, existing string) bool {
	candidateLoopback := externalDirectUDPCandidateRank(candidate) == 5
	existingLoopback := externalDirectUDPCandidateRank(existing) == 5
	if candidateLoopback != existingLoopback {
		return candidateLoopback
	}
	if candidateLoopback {
		return externalDirectUDPShouldPromoteCandidate(candidate, existing)
	}
	return false
}

func externalDirectUDPPreferWANStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return externalDirectUDPEndpointKey(candidate) == externalDirectUDPEndpointKey(existing) && externalDirectUDPBetterCandidate(candidate, existing)
}

func externalDirectUDPBetterCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return candidate < existing
}

func externalDirectUDPCandidateRank(candidate string) int {
	addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
	if !ok {
		return 6
	}
	return externalDirectUDPAddrCandidateRank(addrPort.Addr())
}

func externalDirectUDPParsedCandidateAddrPort(candidate string) (netip.AddrPort, bool) {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return netip.AddrPort{}, false
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalDirectUDPAddrCandidateRank(addr netip.Addr) int {
	if !addr.IsValid() || addr.IsUnspecified() {
		return 6
	}
	if addr.IsLoopback() {
		return 5
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return 4
	}
	if publicProbeTailscaleCGNATPrefix.Contains(addr) || publicProbeTailscaleULAPrefix.Contains(addr) {
		return 3
	}
	if addr.IsPrivate() {
		return 2
	}
	if addr.IsGlobalUnicast() {
		return 0
	}
	return 1
}

func externalDirectUDPEndpointKey(candidate string) string {
	_, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return candidate
	}
	return port
}

func externalDirectUDPDedupeAndFill(selected []string, fallback []string) []string {
	out := append([]string(nil), selected...)
	seenEndpoint := make(map[string]int)
	for i, candidate := range out {
		if candidate == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if existingIndex, ok := seenEndpoint[endpoint]; ok {
			if externalDirectUDPBetterCandidate(candidate, out[existingIndex]) {
				out[existingIndex] = ""
				seenEndpoint[endpoint] = i
				continue
			}
			out[i] = ""
			continue
		}
		seenEndpoint[endpoint] = i
	}
	for i, candidate := range out {
		if candidate != "" {
			continue
		}
		for _, replacement := range externalDirectUDPPreferWANStrings(fallback) {
			endpoint := externalDirectUDPEndpointKey(replacement)
			if replacement == "" {
				continue
			}
			if _, ok := seenEndpoint[endpoint]; ok {
				continue
			}
			out[i] = replacement
			seenEndpoint[endpoint] = i
			break
		}
	}
	return out
}
