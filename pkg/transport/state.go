// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"net/netip"
	"time"
)

// Path describes the currently selected transport path.
type Path int

const (
	PathUnknown Path = iota
	PathRelay
	PathDirect
)

type pathState struct {
	current             Path
	relayConfigured     bool
	directConfigured    bool
	endpoints           map[string]net.Addr
	endpointLatency     map[string]time.Duration
	bestEndpoint        string
	lastRelayAt         time.Time
	lastDirectAt        time.Time
	lastPeerEndpointsAt time.Time
	lastRefreshAt       time.Time
	lastCallMeMaybeAt   time.Time
	pendingProbes       map[string]pendingDirectProbe
	upgrades            int
	fallbacks           int
}

type discoveryPlan struct {
	needRefresh   bool
	sendCallMe    bool
	probeTargets  []net.Addr
	shouldAttempt bool
	generation    uint64
}

type pendingDirectProbe struct {
	sentAt time.Time
	token  directProbeToken
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func newPathState(now time.Time, hasRelay, hasDirect bool) pathState {
	current := PathUnknown
	var lastRelayAt time.Time
	if hasRelay {
		current = PathRelay
		lastRelayAt = now
	}

	return pathState{
		current:          current,
		relayConfigured:  hasRelay,
		directConfigured: hasDirect,
		endpoints:        make(map[string]net.Addr),
		endpointLatency:  make(map[string]time.Duration),
		pendingProbes:    make(map[string]pendingDirectProbe),
		lastRelayAt:      lastRelayAt,
	}
}

func (s pathState) path() Path {
	return s.current
}

func (s pathState) directPath() (string, bool) {
	if s.current != PathDirect {
		return "", false
	}
	return s.bestEndpoint, s.bestEndpoint != ""
}

func (s pathState) discoveryPlan(now time.Time, refreshInterval, staleAfter time.Duration) discoveryPlan {
	if !s.directConfigured {
		return discoveryPlan{}
	}

	if !s.shouldAttemptDiscovery(now, staleAfter) {
		return discoveryPlan{}
	}

	return discoveryPlan{
		needRefresh:   s.needsEndpointRefresh(now, refreshInterval),
		sendCallMe:    s.needsCallMeMaybe(now, refreshInterval),
		probeTargets:  s.probeTargets(),
		shouldAttempt: true,
	}
}

func (s pathState) shouldAttemptDiscovery(now time.Time, staleAfter time.Duration) bool {
	return s.current != PathDirect || s.directIsStale(now, staleAfter)
}

func (s pathState) probeTargets() []net.Addr {
	targets := make([]net.Addr, 0, len(s.endpoints))
	if s.bestEndpoint != "" {
		if endpoint, ok := s.endpoints[s.bestEndpoint]; ok {
			targets = append(targets, cloneAddr(endpoint))
		}
	}
	for key, endpoint := range s.endpoints {
		if key == s.bestEndpoint {
			continue
		}
		targets = append(targets, cloneAddr(endpoint))
	}
	return targets
}

func (s pathState) needsEndpointRefresh(now time.Time, refreshInterval time.Duration) bool {
	return s.lastRefreshAt.IsZero() || now.Sub(s.lastRefreshAt) >= refreshInterval
}

func (s pathState) needsCallMeMaybe(now time.Time, refreshInterval time.Duration) bool {
	return s.relayConfigured &&
		(s.lastCallMeMaybeAt.IsZero() || now.Sub(s.lastCallMeMaybeAt) >= refreshInterval)
}

func (s pathState) directIsStale(now time.Time, staleAfter time.Duration) bool {
	if s.current != PathDirect {
		return true
	}
	if s.lastDirectAt.IsZero() {
		return true
	}
	return !now.Before(s.lastDirectAt.Add(staleAfter))
}

func (s *pathState) noteRefreshSuccess(now time.Time) {
	s.lastRefreshAt = now
}

func (s *pathState) noteCallMeMaybeSuccess(now time.Time) {
	s.lastCallMeMaybeAt = now
}

func (s *pathState) noteCandidates(now time.Time, candidates []net.Addr) bool {
	prevBest := s.bestEndpoint
	prevBestAddr := cloneAddr(s.endpoints[prevBest])
	next := candidateMap(candidates)

	if s.current == PathDirect && prevBest != "" {
		if _, ok := next[prevBest]; !ok && prevBestAddr != nil {
			next[prevBest] = prevBestAddr
		}
	}

	changed := candidateMapChanged(s.endpoints, next)
	s.endpoints = next
	s.pruneEndpointState()
	changed = s.relayIfBestEndpointLost(now) || changed
	s.lastPeerEndpointsAt = now
	return changed
}

func candidateMap(candidates []net.Addr) map[string]net.Addr {
	next := make(map[string]net.Addr, len(candidates))
	for _, candidate := range candidates {
		if candidate != nil {
			next[candidate.String()] = cloneAddr(candidate)
		}
	}
	return next
}

func candidateMapChanged(current map[string]net.Addr, next map[string]net.Addr) bool {
	if len(next) != len(current) {
		return true
	}
	for key := range next {
		if _, ok := current[key]; !ok {
			return true
		}
	}
	return false
}

func (s *pathState) pruneEndpointState() {
	pruneMissingKeys(s.pendingProbes, s.endpoints)
	pruneMissingKeys(s.endpointLatency, s.endpoints)
}

func pruneMissingKeys[T any](values map[string]T, keep map[string]net.Addr) {
	for key := range values {
		if _, ok := keep[key]; !ok {
			delete(values, key)
		}
	}
}

func (s *pathState) relayIfBestEndpointLost(now time.Time) bool {
	lostActiveDirect := s.current == PathDirect && s.bestEndpoint != ""
	if s.bestEndpoint != "" {
		if _, ok := s.endpoints[s.bestEndpoint]; !ok {
			s.bestEndpoint = ""
		}
	}
	return lostActiveDirect && s.bestEndpoint == "" && s.noteRelay(now)
}

func (s *pathState) noteDirect(now time.Time, addr net.Addr) bool {
	if !s.directConfigured || addr == nil {
		return false
	}
	key := addr.String()
	candidate, ok := s.endpoints[key]
	if !ok {
		return false
	}

	if !s.shouldSelectDirectEndpoint(key, candidate) {
		s.lastDirectAt = now
		return false
	}

	changed := s.current != PathDirect || s.bestEndpoint != key
	if s.current != PathDirect {
		s.upgrades++
	}
	s.current = PathDirect
	s.bestEndpoint = key
	s.lastDirectAt = now
	return changed
}

func (s *pathState) shouldSelectDirectEndpoint(key string, candidate net.Addr) bool {
	if s.current != PathDirect || s.bestEndpoint == "" || s.bestEndpoint == key {
		return true
	}
	best, ok := s.endpoints[s.bestEndpoint]
	if !ok {
		return true
	}
	return betterDirectAddr(candidate, s.endpointLatency[key], best, s.endpointLatency[s.bestEndpoint])
}

func (s *pathState) noteDirectActivity(now time.Time, addr net.Addr) {
	if s.current != PathDirect || addr == nil || s.bestEndpoint == "" {
		return
	}
	if !sameAddr(addr, s.endpoints[s.bestEndpoint]) {
		return
	}
	s.lastDirectAt = now
}

func (s *pathState) noteRelay(now time.Time) bool {
	next := PathUnknown
	if s.relayConfigured {
		next = PathRelay
	}

	changed := s.current != next
	if s.current == PathDirect {
		s.fallbacks++
	}
	s.current = next
	if next == PathRelay {
		s.lastRelayAt = now
	}
	s.lastRefreshAt = time.Time{}
	s.lastCallMeMaybeAt = time.Time{}
	clear(s.pendingProbes)
	return changed
}

func (s *pathState) noteProbeSent(now time.Time, addr net.Addr, token directProbeToken) {
	if addr == nil {
		return
	}
	s.pendingProbes[addr.String()] = pendingDirectProbe{sentAt: now, token: token}
}

func (s *pathState) forgetProbe(addr net.Addr, token directProbeToken) {
	if addr == nil {
		return
	}
	key := addr.String()
	pending, ok := s.pendingProbes[key]
	if !ok || pending.token != token {
		return
	}
	delete(s.pendingProbes, key)
}

func (s *pathState) consumeProbe(addr net.Addr, maxAge time.Duration, now time.Time, token directProbeToken) bool {
	if addr == nil {
		return false
	}
	key := addr.String()
	pending, ok := s.pendingProbes[key]
	if !ok {
		return false
	}
	delete(s.pendingProbes, key)
	if pending.token != token {
		return false
	}
	if pending.sentAt.Add(maxAge).Before(now) {
		return false
	}
	s.endpointLatency[key] = now.Sub(pending.sentAt)
	return true
}

func (s pathState) hasCandidate(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	for _, endpoint := range s.endpoints {
		if sameAddr(addr, endpoint) {
			return true
		}
	}
	return false
}

func cloneAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		cp := *v
		if v.IP != nil {
			cp.IP = append(net.IP(nil), v.IP...)
		}
		return &cp
	case *net.IPAddr:
		cp := *v
		if v.IP != nil {
			cp.IP = append(net.IP(nil), v.IP...)
		}
		return &cp
	default:
		return addr
	}
}

func betterDirectAddr(candidate net.Addr, candidateLatency time.Duration, current net.Addr, currentLatency time.Duration) bool {
	candidateIP, candidateOK := addrIP(candidate)
	currentIP, currentOK := addrIP(current)
	if !currentOK {
		return candidateOK
	}
	if !candidateOK {
		return false
	}

	var candidatePoints, currentPoints int
	if candidateLatency > currentLatency && candidateLatency > 0 {
		currentPoints = int(100 - ((currentLatency * 100) / candidateLatency))
	} else if currentLatency > 0 {
		candidatePoints = int(100 - ((candidateLatency * 100) / currentLatency))
	}
	candidatePoints += directAddrPreferencePoints(candidateIP)
	currentPoints += directAddrPreferencePoints(currentIP)
	if candidatePoints <= 1 && currentPoints == 0 {
		return false
	}
	return candidatePoints > currentPoints
}

func directAddrPreferencePoints(ip net.IP) int {
	switch {
	case ip.IsLoopback():
		return 50
	case ip.IsLinkLocalUnicast():
		return 30
	case ip.IsPrivate() || isCGNAT(ip):
		return 20
	default:
		return 0
	}
}

func isCGNAT(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && cgnatPrefix.Contains(addr.Unmap())
}

func addrIP(addr net.Addr) (net.IP, bool) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		if v == nil || v.IP == nil {
			return nil, false
		}
		return v.IP, true
	case *net.IPAddr:
		if v == nil || v.IP == nil {
			return nil, false
		}
		return v.IP, true
	default:
		return nil, false
	}
}

func sameAddr(a, b net.Addr) bool {
	switch av := a.(type) {
	case *net.UDPAddr:
		return sameUDPAddr(av, b)
	case *net.IPAddr:
		return sameIPAddr(av, b)
	default:
		return a == b
	}
}

func sameUDPAddr(a *net.UDPAddr, b net.Addr) bool {
	bv, ok := b.(*net.UDPAddr)
	if !ok || a == nil || bv == nil {
		return false
	}
	return a.Port == bv.Port && a.Zone == bv.Zone && a.IP.Equal(bv.IP)
}

func sameIPAddr(a *net.IPAddr, b net.Addr) bool {
	bv, ok := b.(*net.IPAddr)
	if !ok || a == nil || bv == nil {
		return false
	}
	return a.Zone == bv.Zone && a.IP.Equal(bv.IP)
}
