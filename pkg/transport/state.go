package transport

import (
	"net"
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
	bestEndpoint        string
	lastRelayAt         time.Time
	lastDirectAt        time.Time
	lastPeerEndpointsAt time.Time
	lastRefreshAt       time.Time
	lastCallMeMaybeAt   time.Time
	pendingProbes       map[string]time.Time
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
		pendingProbes:    make(map[string]time.Time),
		lastRelayAt:      lastRelayAt,
	}
}

func (s pathState) path() Path {
	return s.current
}

func (s pathState) discoveryPlan(now time.Time, refreshInterval, staleAfter time.Duration) discoveryPlan {
	if !s.directConfigured {
		return discoveryPlan{}
	}

	shouldAttempt := s.current != PathDirect || s.directIsStale(now, staleAfter)
	if !shouldAttempt {
		return discoveryPlan{}
	}

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

	needRefresh := s.lastRefreshAt.IsZero() || now.Sub(s.lastRefreshAt) >= refreshInterval
	sendCallMe := s.relayConfigured && (s.lastCallMeMaybeAt.IsZero() || now.Sub(s.lastCallMeMaybeAt) >= refreshInterval)
	return discoveryPlan{
		needRefresh:   needRefresh,
		sendCallMe:    sendCallMe,
		probeTargets:  targets,
		shouldAttempt: true,
	}
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
	next := make(map[string]net.Addr, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		next[candidate.String()] = cloneAddr(candidate)
	}

	changed := len(next) != len(s.endpoints)
	if !changed {
		for key := range next {
			if _, ok := s.endpoints[key]; !ok {
				changed = true
				break
			}
		}
	}

	s.endpoints = next
	for key := range s.pendingProbes {
		if _, ok := s.endpoints[key]; !ok {
			delete(s.pendingProbes, key)
		}
	}
	if s.bestEndpoint != "" {
		if _, ok := s.endpoints[s.bestEndpoint]; !ok {
			s.bestEndpoint = ""
		}
	}
	s.lastPeerEndpointsAt = now
	return changed
}

func (s *pathState) noteDirect(now time.Time, addr net.Addr) bool {
	if !s.directConfigured || addr == nil {
		return false
	}
	key := addr.String()
	if _, ok := s.endpoints[key]; !ok {
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

func (s *pathState) noteProbeSent(now time.Time, addr net.Addr) {
	if addr == nil {
		return
	}
	s.pendingProbes[addr.String()] = now
}

func (s *pathState) consumeProbe(addr net.Addr, maxAge time.Duration, now time.Time) bool {
	if addr == nil {
		return false
	}
	key := addr.String()
	sentAt, ok := s.pendingProbes[key]
	if !ok {
		return false
	}
	delete(s.pendingProbes, key)
	return !sentAt.Add(maxAge).Before(now)
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
