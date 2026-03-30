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
	current          Path
	relayConfigured  bool
	directConfigured bool
	endpoints        map[string]net.Addr
	bestEndpoint     string
	lastRelayAt      time.Time
	lastDirectAt     time.Time
	lastEndpointsAt  time.Time
	upgrades         int
	fallbacks        int
}

type discoveryPlan struct {
	needRefresh   bool
	sendCallMe    bool
	probeTargets  []net.Addr
	shouldAttempt bool
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

	needRefresh := s.lastEndpointsAt.IsZero() || now.Sub(s.lastEndpointsAt) >= refreshInterval
	return discoveryPlan{
		needRefresh:   needRefresh,
		sendCallMe:    s.relayConfigured && needRefresh,
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

func (s *pathState) noteEndpointRefresh(now time.Time) {
	s.lastEndpointsAt = now
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
	if s.bestEndpoint != "" {
		if _, ok := s.endpoints[s.bestEndpoint]; !ok {
			s.bestEndpoint = ""
		}
	}
	s.lastEndpointsAt = now
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
	return changed
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
