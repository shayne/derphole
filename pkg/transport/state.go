// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"net/netip"
	"sort"
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
	candidateLifecycle  map[string]directCandidateState
	selector            pathSelector
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
		current:            current,
		relayConfigured:    hasRelay,
		directConfigured:   hasDirect,
		endpoints:          make(map[string]net.Addr),
		endpointLatency:    make(map[string]time.Duration),
		candidateLifecycle: make(map[string]directCandidateState),
		selector:           defaultPathSelector(),
		pendingProbes:      make(map[string]pendingDirectProbe),
		lastRelayAt:        lastRelayAt,
	}
}

func (s pathState) path() Path {
	return s.current
}

func (s pathState) snapshot(now time.Time) PathSnapshot {
	snapshot := PathSnapshot{
		At:        now,
		Path:      s.current,
		Upgrades:  s.upgrades,
		Fallbacks: s.fallbacks,
	}
	if s.current == PathDirect && s.bestEndpoint != "" {
		snapshot.SelectedAddr = cloneAddr(s.endpoints[s.bestEndpoint])
		snapshot.SelectedRTT = s.endpointLatency[s.bestEndpoint]
	}

	keys := make([]string, 0, len(s.endpoints))
	for key := range s.endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	snapshot.Candidates = make([]PathCandidateSnapshot, 0, len(keys))
	for _, key := range keys {
		candidate := PathCandidateSnapshot{
			Addr:     cloneAddr(s.endpoints[key]),
			RTT:      s.endpointLatency[key],
			Selected: s.current == PathDirect && key == s.bestEndpoint,
		}
		if pending, ok := s.pendingProbes[key]; ok {
			candidate.ProbePending = true
			candidate.ProbeSentAt = pending.sentAt
		}
		snapshot.Candidates = append(snapshot.Candidates, candidate)
	}

	return snapshot
}

func (s pathState) directPath() (string, bool) {
	if s.current != PathDirect {
		return "", false
	}
	return s.bestEndpoint, s.bestEndpoint != ""
}

func (s *pathState) discoveryPlan(now time.Time, refreshInterval, staleAfter, probeTimeout time.Duration) discoveryPlan {
	if !s.directConfigured {
		return discoveryPlan{}
	}

	s.expirePendingProbes(now, probeTimeout, defaultCandidateSuppressPeriod)
	if !s.shouldAttemptDiscovery(now, staleAfter) {
		return discoveryPlan{}
	}

	return discoveryPlan{
		needRefresh:   s.needsEndpointRefresh(now, refreshInterval),
		sendCallMe:    s.needsCallMeMaybe(now, refreshInterval),
		probeTargets:  s.probeTargets(now),
		shouldAttempt: true,
	}
}

func (s pathState) shouldAttemptDiscovery(now time.Time, staleAfter time.Duration) bool {
	return s.current != PathDirect || s.directIsStale(now, staleAfter)
}

func (s pathState) probeTargets(now time.Time) []net.Addr {
	targets := make([]net.Addr, 0, len(s.endpoints))
	if s.bestEndpoint != "" {
		if endpoint, ok := s.endpoints[s.bestEndpoint]; ok {
			if s.shouldProbeEndpoint(now, s.bestEndpoint) {
				targets = append(targets, cloneAddr(endpoint))
			}
		}
	}
	for key, endpoint := range s.endpoints {
		if key == s.bestEndpoint {
			continue
		}
		if !s.shouldProbeEndpoint(now, key) {
			continue
		}
		targets = append(targets, cloneAddr(endpoint))
	}
	return targets
}

func (s pathState) shouldProbeEndpoint(now time.Time, key string) bool {
	if _, ok := s.pendingProbes[key]; ok {
		return false
	}
	if state, ok := s.candidateLifecycle[key]; ok && state.suppressed(now) {
		return false
	}
	return true
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
	for key, candidate := range next {
		s.noteCandidateSeen(now, key, candidate)
	}

	if s.current == PathDirect && prevBest != "" {
		if _, ok := next[prevBest]; !ok && prevBestAddr != nil {
			next[prevBest] = prevBestAddr
			s.markCandidateOpen(now, prevBest, prevBestAddr)
		}
	}

	changed := candidateMapChanged(s.endpoints, next)
	s.endpoints = next
	s.pruneEndpointState(now)
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

func (s *pathState) pruneEndpointState(now time.Time) {
	pruneMissingKeys(s.pendingProbes, s.endpoints)
	pruneMissingKeys(s.endpointLatency, s.endpoints)
	s.pruneTrackedCandidates(now)
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
	key, candidate, ok := s.directCandidate(addr)
	if !ok {
		return false
	}
	if !s.shouldSelectDirectCandidate(key, candidate) {
		s.markCandidateInactive(now, key)
		s.lastDirectAt = now
		return false
	}

	prevBest := s.bestEndpoint
	changed := s.current != PathDirect || s.bestEndpoint != key
	if s.current != PathDirect {
		s.upgrades++
	}
	s.current = PathDirect
	s.bestEndpoint = key
	s.lastDirectAt = now
	if changed && prevBest != "" && prevBest != key {
		s.markCandidateInactive(now, prevBest)
	}
	s.markCandidateOpen(now, key, candidate)
	return changed
}

func (s pathState) directCandidate(addr net.Addr) (string, net.Addr, bool) {
	if !s.directConfigured || addr == nil {
		return "", nil, false
	}
	key := addr.String()
	candidate, ok := s.endpoints[key]
	return key, candidate, ok
}

func (s pathState) shouldSelectDirectCandidate(key string, candidate net.Addr) bool {
	selected, ok := s.selector.selectPath(s.currentSelectablePath(), s.hasCurrentSelectablePath(), []selectablePath{{
		path: PathDirect,
		key:  key,
		addr: candidate,
		rtt:  s.endpointLatency[key],
	}})
	return ok && selected.path == PathDirect && selected.key == key
}

func (s pathState) currentSelectablePath() selectablePath {
	switch s.current {
	case PathDirect:
		if s.bestEndpoint == "" {
			return selectablePath{}
		}
		addr, ok := s.endpoints[s.bestEndpoint]
		if !ok {
			return selectablePath{}
		}
		return selectablePath{
			path: PathDirect,
			key:  s.bestEndpoint,
			addr: addr,
			rtt:  s.endpointLatency[s.bestEndpoint],
		}
	case PathRelay:
		return selectablePath{path: PathRelay}
	default:
		return selectablePath{}
	}
}

func (s pathState) hasCurrentSelectablePath() bool {
	return s.currentSelectablePath().selectable()
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
	key := addr.String()
	s.pendingProbes[key] = pendingDirectProbe{sentAt: now, token: token}
	s.noteCandidateSeen(now, key, addr)
	state := s.candidateLifecycle[key]
	state.status = candidatePending
	state.lastProbeAt = now
	state.suppressUntil = time.Time{}
	s.candidateLifecycle[key] = state
}

func (s *pathState) noteProbeFailed(now time.Time, addr net.Addr, token directProbeToken, suppressFor time.Duration) {
	if addr == nil {
		return
	}
	key := addr.String()
	pending, ok := s.pendingProbes[key]
	if !ok || pending.token != token {
		return
	}
	delete(s.pendingProbes, key)
	s.markCandidateUnusable(now, key, suppressFor)
}

func (s *pathState) expirePendingProbes(now time.Time, maxAge, suppressFor time.Duration) {
	for key, pending := range s.pendingProbes {
		if !now.After(pending.sentAt.Add(maxAge)) {
			continue
		}
		delete(s.pendingProbes, key)
		s.markCandidateUnusable(now, key, suppressFor)
	}
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
