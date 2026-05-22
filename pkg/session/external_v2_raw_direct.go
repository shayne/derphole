// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
)

const (
	externalV2RawDirectPunchWait      = 1200 * time.Millisecond
	externalV2RawDirectPunchInterval  = 25 * time.Millisecond
	externalV2RawDirectPunchReplyWait = 100 * time.Millisecond
	externalV2RawDirectObserveLinger  = 250 * time.Millisecond
	externalV2RawDirectObserveBufSize = 1500
)

type externalV2RawDirectAllowUnverifiedFallbackContextKey struct{}

var externalV2RawDirectProbeCandidates = publicProbeCandidates
var externalV2RawDirectObservePunchAddrsByConn = observeExternalV2RawDirectPunchAddrsByConn
var externalV2RawDirectRouteCandidate = externalV2RawDirectDefaultRouteCandidate

var externalV2RawDirectRouteProbePayload = []byte("derphole-raw-direct-route-check-v1")
var externalV2RawDirectPunchPayload = []byte("derphole-punch")

func withExternalV2RawDirectAllowUnverifiedFallback(ctx context.Context) context.Context {
	return context.WithValue(ctx, externalV2RawDirectAllowUnverifiedFallbackContextKey{}, true)
}

func externalV2RawDirectAllowUnverifiedFallback(ctx context.Context) bool {
	allow, _ := ctx.Value(externalV2RawDirectAllowUnverifiedFallbackContextKey{}).(bool)
	return allow
}

func externalV2RawDirectActivateDirectPath(pathEmitter *transportPathEmitter, transportManager *transport.Manager, punchCancel context.CancelFunc) {
	if pathEmitter != nil {
		pathEmitter.SuppressRelayRegression()
		pathEmitter.Emit(StateTryingDirect)
	}
	if transportManager != nil {
		transportManager.StopDirectReads()
	}
	externalV2RawDirectStopPunchingForBlast(punchCancel)
}

func externalV2RawDirectStopPunchingForBlast(cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
}

func externalV2RawDirectCandidateSetsWithTimeout(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap, wait time.Duration) [][]string {
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
			sets[i] = externalV2RawDirectOrderCandidateStrings(externalV2RawDirectProbeCandidates(probeCtx, conns[i], dm, pm))
		}()
	}
	wg.Wait()
	return sets
}

func externalV2RawDirectOrderCandidateStrings(candidates []string) []string {
	if fakeTransportEnabled() {
		return externalV2RawDirectPreferLoopbackStrings(candidates)
	}
	return externalV2RawDirectPreferWANStrings(candidates)
}

func externalV2RawDirectInferWANPerPort(sets [][]string) [][]string {
	wan, ok := externalV2RawDirectFirstWANCandidateAddr(sets)
	if !ok {
		return sets
	}
	out := make([][]string, len(sets))
	for i, candidates := range sets {
		out[i] = append([]string(nil), candidates...)
		port, ok := externalV2RawDirectPrivatePortForWANInference(candidates)
		if !ok {
			continue
		}
		inferred := netip.AddrPortFrom(wan, port).String()
		out[i] = append([]string{inferred}, out[i]...)
	}
	return out
}

func externalV2RawDirectFirstWANCandidateAddr(sets [][]string) (netip.Addr, bool) {
	for _, candidates := range sets {
		for _, candidate := range candidates {
			addrPort, ok := externalV2RawDirectParsedCandidateAddrPort(candidate)
			if ok && externalV2RawDirectCandidateRank(candidate) == 0 {
				return addrPort.Addr(), true
			}
		}
	}
	return netip.Addr{}, false
}

func externalV2RawDirectPrivatePortForWANInference(candidates []string) (uint16, bool) {
	var port uint16
	for _, candidate := range candidates {
		addrPort, ok := externalV2RawDirectParsedCandidateAddrPort(candidate)
		if !ok {
			continue
		}
		if externalV2RawDirectCandidateRank(candidate) == 0 {
			return 0, false
		}
		if port == 0 && addrPort.Addr().IsPrivate() {
			port = addrPort.Port()
		}
	}
	return port, port != 0
}

func externalV2RawDirectStartPunching(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr) {
	if len(remoteCandidates) == 0 {
		return
	}
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		go punchExternalV2RawDirectAddrs(ctx, conn, remoteCandidates)
	}
}

func punchExternalV2RawDirectAddrs(ctx context.Context, conn net.PacketConn, addrs []net.Addr) {
	send := func() {
		for _, addr := range addrs {
			if addr != nil {
				_, _ = conn.WriteTo(externalV2RawDirectPunchPayload, addr)
			}
		}
	}
	send()
	ticker := time.NewTicker(externalV2RawDirectPunchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

func observeExternalV2RawDirectPunchAddrsByConn(ctx context.Context, conns []net.PacketConn, wait time.Duration) [][]net.Addr {
	if wait <= 0 {
		wait = externalV2RawDirectPunchWait
	}
	observeCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	observed := make([][]net.Addr, len(conns))
	expected := externalV2RawDirectConnCount(conns)
	if expected == 0 {
		return observed
	}
	var wg sync.WaitGroup
	var observedConns atomicCounter
	var stopOnce sync.Once
	stopAfterAllObserved := func() {
		stopOnce.Do(func() {
			go stopExternalV2RawDirectObservationAfterLinger(observeCtx, cancel)
		})
	}
	for i, conn := range conns {
		if conn == nil {
			continue
		}
		wg.Add(1)
		go func(i int, conn net.PacketConn) {
			defer wg.Done()
			observed[i] = observeExternalV2RawDirectPunchAddrs(
				observeCtx,
				conn,
				&observedConns,
				expected,
				stopAfterAllObserved,
			)
		}(i, conn)
	}
	wg.Wait()
	return observed
}

func observeExternalV2RawDirectPunchAddrs(
	ctx context.Context,
	conn net.PacketConn,
	observedConns *atomicCounter,
	expectedConns int,
	stopAfterAllObserved func(),
) []net.Addr {
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	seen := map[string]net.Addr{}
	lastReply := map[string]time.Time{}
	buf := make([]byte, externalV2RawDirectObserveBufSize)
	for {
		addr, ok := readExternalV2RawDirectPunch(ctx, conn, buf)
		if !ok {
			break
		}
		if addr == nil {
			continue
		}
		if externalV2RawDirectShouldReplyToPunch(addr.String(), lastReply, time.Now()) {
			_, _ = conn.WriteTo(externalV2RawDirectPunchPayload, addr)
		}
		firstForConn := len(seen) == 0
		seen[addr.String()] = externalV2RawDirectCloneAddr(addr)
		if firstForConn && observedConns.Add(1) >= expectedConns {
			stopAfterAllObserved()
		}
	}
	return externalV2RawDirectPreferredAddrs(seen)
}

func readExternalV2RawDirectPunch(ctx context.Context, conn net.PacketConn, buf []byte) (net.Addr, bool) {
	if err := conn.SetReadDeadline(externalV2RawDirectObserveReadDeadline(ctx)); err != nil {
		return nil, false
	}
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, externalV2RawDirectContinueObservation(ctx, err)
	}
	if addr == nil || !bytes.Equal(buf[:n], externalV2RawDirectPunchPayload) {
		return nil, true
	}
	return addr, true
}

func externalV2RawDirectContinueObservation(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	return externalV2RawDirectNetTimeout(err)
}

func stopExternalV2RawDirectObservationAfterLinger(ctx context.Context, cancel context.CancelFunc) {
	timer := time.NewTimer(externalV2RawDirectObserveLinger)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
		cancel()
	}
}

func externalV2RawDirectConnCount(conns []net.PacketConn) int {
	count := 0
	for _, conn := range conns {
		if conn != nil {
			count++
		}
	}
	return count
}

func externalV2RawDirectObserveReadDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(50 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func externalV2RawDirectShouldReplyToPunch(addr string, lastReply map[string]time.Time, now time.Time) bool {
	if addr == "" {
		return false
	}
	last, ok := lastReply[addr]
	if ok && now.Sub(last) < externalV2RawDirectPunchReplyWait {
		return false
	}
	lastReply[addr] = now
	return true
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) Add(delta int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += delta
	return c.n
}

func externalV2RawDirectNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func externalV2RawDirectCloneAddr(addr net.Addr) net.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return addr
	}
	cp := *udpAddr
	if udpAddr.IP != nil {
		cp.IP = append(net.IP(nil), udpAddr.IP...)
	}
	return &cp
}

func externalV2RawDirectPreferredAddrs(seen map[string]net.Addr) []net.Addr {
	out := make([]net.Addr, 0, len(seen))
	for _, addr := range seen {
		out = append(out, addr)
	}
	slices.SortFunc(out, func(a, b net.Addr) int {
		aRank := externalV2RawDirectAddrRank(a)
		bRank := externalV2RawDirectAddrRank(b)
		if aRank != bRank {
			return aRank - bRank
		}
		return strings.Compare(a.String(), b.String())
	})
	return out
}

func externalV2RawDirectAddrRank(addr net.Addr) int {
	addrPort, ok := externalV2RawDirectAddrPort(addr)
	if !ok {
		return 100
	}
	return externalV2RawDirectAddrCandidateRank(addrPort.Addr())
}

func externalV2RawDirectFormatObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, strconv.Itoa(i)+"="+strings.Join(externalV2RawDirectParallelCandidateStrings(observed, len(observed)), "|"))
	}
	return strings.Join(parts, ",")
}

func externalV2RawDirectSelectRemoteAddrsByConn(observedByConn [][]net.Addr, conns []net.PacketConn, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = len(observedByConn)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	selectCandidate := func(i int, candidate string) bool {
		endpoint := externalV2RawDirectEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			return false
		}
		if !externalV2RawDirectCanRouteSelectedCandidate(conns, i, candidate) {
			return false
		}
		out[i] = candidate
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		return true
	}
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range externalV2RawDirectParallelCandidateStringsForPeer(observedByConn[i], len(observedByConn[i]), peer) {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	return out
}

func externalV2RawDirectCanRouteSelectedCandidate(conns []net.PacketConn, i int, candidate string) bool {
	if i < 0 || i >= len(conns) || conns[i] == nil {
		return true
	}
	return externalV2RawDirectRouteCandidate(conns[i], candidate)
}

func externalV2RawDirectDefaultRouteCandidate(conn net.PacketConn, candidate string) bool {
	addrPort, ok := externalV2RawDirectParsedCandidateAddrPort(candidate)
	if conn == nil || !ok {
		return false
	}
	_, err := conn.WriteTo(externalV2RawDirectRouteProbePayload, net.UDPAddrFromAddrPort(addrPort))
	return err == nil
}

func externalV2RawDirectSelectedAddrCount(addrs []string) int {
	count := 0
	for _, addr := range addrs {
		if addr != "" {
			count++
		}
	}
	return count
}

func externalV2RawDirectFilterFallbackAddrsForSelectedScope(selected []string, fallback []string) []string {
	selectedRank := externalV2RawDirectBestCandidateRank(selected)
	if selectedRank == -1 {
		selectedRank = externalV2RawDirectBestCandidateRank(fallback)
		if selectedRank == -1 {
			return fallback
		}
	}

	filtered := make([]string, 0, len(fallback))
	for _, candidate := range fallback {
		if candidate == "" || externalV2RawDirectCandidateRank(candidate) != selectedRank {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func externalV2RawDirectBestCandidateRank(candidates []string) int {
	bestRank := -1
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		rank := externalV2RawDirectCandidateRank(candidate)
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
		}
	}
	return bestRank
}

func externalV2RawDirectParallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	return externalV2RawDirectParallelCandidateStringsForPeer(candidates, parallel, nil)
}

func externalV2RawDirectParallelCandidateStringsForPeer(candidates []net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := externalV2RawDirectOrderedCandidateStringsForPeer(candidates, peer)
	out, seen := externalV2RawDirectAppendUniqueEndpointCandidates(nil, ordered, parallel)
	out, _ = externalV2RawDirectAppendUniqueCandidates(out, seen, ordered, parallel)
	return out
}

func externalV2RawDirectOrderedCandidateStringsForPeer(candidates []net.Addr, peer net.Addr) []string {
	ordered := externalV2RawDirectAppendPeerCandidate(externalV2RawDirectCandidateStringsInOrder(candidates), peer)
	if fakeTransportEnabled() {
		return externalV2RawDirectPreferLoopbackStrings(ordered)
	}
	return externalV2RawDirectPreferPeerAddrStrings(ordered, peer)
}

func externalV2RawDirectCandidateStringsInOrder(candidates []net.Addr) []string {
	out := make([]string, 0, len(candidates))
	seen := make(map[string]bool)
	for _, addr := range candidates {
		if addr == nil {
			continue
		}
		candidate := addr.String()
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
	}
	return out
}

func externalV2RawDirectAppendPeerCandidate(ordered []string, peer net.Addr) []string {
	peerAddr, ok := externalV2RawDirectAddrPort(peer)
	if !ok {
		return ordered
	}
	peerCandidate := peerAddr.String()
	if slices.Contains(ordered, peerCandidate) {
		return ordered
	}
	return append(ordered, peerCandidate)
}

func externalV2RawDirectAppendUniqueEndpointCandidates(out []string, candidates []string, limit int) ([]string, map[string]bool) {
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	if len(out) >= limit {
		return out, seen
	}
	for _, candidate := range candidates {
		endpoint := externalV2RawDirectEndpointKey(candidate)
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

func externalV2RawDirectAppendUniqueCandidates(out []string, seen map[string]bool, candidates []string, limit int) ([]string, map[string]bool) {
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

func externalV2RawDirectPreferPeerAddrStrings(candidates []string, peer net.Addr) []string {
	out := externalV2RawDirectPreferWANStrings(candidates)
	peerAddr, ok := externalV2RawDirectAddrPort(peer)
	if !ok {
		return out
	}
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalV2RawDirectShouldPromotePeerCandidate(candidate, out[j], peerAddr.Addr()) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalV2RawDirectShouldPromotePeerCandidate(candidate string, existing string, peer netip.Addr) bool {
	candidatePeer := externalV2RawDirectMatchesPeerAddr(candidate, peer)
	existingPeer := externalV2RawDirectMatchesPeerAddr(existing, peer)
	if candidatePeer != existingPeer {
		return candidatePeer
	}
	return candidatePeer && externalV2RawDirectShouldPromoteCandidate(candidate, existing)
}

func externalV2RawDirectMatchesPeerAddr(candidate string, peer netip.Addr) bool {
	candidateAddr, err := netip.ParseAddrPort(candidate)
	return err == nil && candidateAddr.Addr() == peer
}

func externalV2RawDirectAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalV2RawDirectPreferLoopbackStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalV2RawDirectShouldPromoteLoopbackCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalV2RawDirectShouldPromoteLoopbackCandidate(candidate string, existing string) bool {
	candidateLoopback := externalV2RawDirectCandidateRank(candidate) == 5
	existingLoopback := externalV2RawDirectCandidateRank(existing) == 5
	if candidateLoopback != existingLoopback {
		return candidateLoopback
	}
	if candidateLoopback {
		return externalV2RawDirectShouldPromoteCandidate(candidate, existing)
	}
	return false
}

func externalV2RawDirectPreferWANStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalV2RawDirectShouldPromoteCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalV2RawDirectShouldPromoteCandidate(candidate string, existing string) bool {
	candidateRank := externalV2RawDirectCandidateRank(candidate)
	existingRank := externalV2RawDirectCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return externalV2RawDirectEndpointKey(candidate) == externalV2RawDirectEndpointKey(existing) && externalV2RawDirectBetterCandidate(candidate, existing)
}

func externalV2RawDirectBetterCandidate(candidate string, existing string) bool {
	candidateRank := externalV2RawDirectCandidateRank(candidate)
	existingRank := externalV2RawDirectCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return candidate < existing
}

func externalV2RawDirectCandidateRank(candidate string) int {
	addrPort, ok := externalV2RawDirectParsedCandidateAddrPort(candidate)
	if !ok {
		return 6
	}
	return externalV2RawDirectAddrCandidateRank(addrPort.Addr())
}

func externalV2RawDirectParsedCandidateAddrPort(candidate string) (netip.AddrPort, bool) {
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

func externalV2RawDirectAddrCandidateRank(addr netip.Addr) int {
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

func externalV2RawDirectEndpointKey(candidate string) string {
	_, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return candidate
	}
	return port
}

func externalV2RawDirectDedupeAndFill(selected []string, fallback []string) []string {
	out := append([]string(nil), selected...)
	seenEndpoint := make(map[string]int)
	for i, candidate := range out {
		if candidate == "" {
			continue
		}
		endpoint := externalV2RawDirectEndpointKey(candidate)
		if existingIndex, ok := seenEndpoint[endpoint]; ok {
			if externalV2RawDirectBetterCandidate(candidate, out[existingIndex]) {
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
		for _, replacement := range externalV2RawDirectPreferWANStrings(fallback) {
			endpoint := externalV2RawDirectEndpointKey(replacement)
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
