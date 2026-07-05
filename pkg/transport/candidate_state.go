// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"sort"
	"time"
)

const (
	maxTrackedNonRelayCandidates   = maxControlCandidates
	maxInactiveNonRelayCandidates  = 10
	defaultCandidateSuppressPeriod = 5 * time.Second
)

type candidateStatus uint8

const (
	candidatePending candidateStatus = iota
	candidateOpen
	candidateInactive
	candidateUnusable
)

type directCandidateState struct {
	addr          net.Addr
	status        candidateStatus
	firstSeenAt   time.Time
	lastSeenAt    time.Time
	lastProbeAt   time.Time
	lastOpenedAt  time.Time
	lastClosedAt  time.Time
	suppressUntil time.Time
}

func (s candidateStatus) String() string {
	switch s {
	case candidatePending:
		return "pending"
	case candidateOpen:
		return "open"
	case candidateInactive:
		return "inactive"
	case candidateUnusable:
		return "unusable"
	default:
		return "unknown"
	}
}

func newDirectCandidateState(now time.Time, addr net.Addr) directCandidateState {
	return directCandidateState{
		addr:        cloneAddr(addr),
		status:      candidatePending,
		firstSeenAt: now,
		lastSeenAt:  now,
	}
}

func (s directCandidateState) suppressed(now time.Time) bool {
	return !s.suppressUntil.IsZero() && now.Before(s.suppressUntil)
}

func (s *pathState) noteCandidateSeen(now time.Time, key string, addr net.Addr) {
	if key == "" || addr == nil {
		return
	}
	state, ok := s.candidateLifecycle[key]
	if !ok {
		s.candidateLifecycle[key] = newDirectCandidateState(now, addr)
		return
	}
	if state.addr == nil || !sameAddr(addr, state.addr) {
		state.addr = cloneAddr(addr)
	}
	state.lastSeenAt = now
	s.candidateLifecycle[key] = state
}

func (s *pathState) markCandidateOpen(now time.Time, key string, addr net.Addr) {
	if key == "" || addr == nil {
		return
	}
	state, ok := s.candidateLifecycle[key]
	if !ok {
		state = newDirectCandidateState(now, addr)
	}
	state.addr = cloneAddr(addr)
	state.status = candidateOpen
	state.lastSeenAt = now
	state.lastOpenedAt = now
	state.suppressUntil = time.Time{}
	s.candidateLifecycle[key] = state
}

func (s *pathState) markCandidateInactive(now time.Time, key string) {
	if key == "" {
		return
	}
	state, ok := s.candidateLifecycle[key]
	if !ok {
		return
	}
	state.status = candidateInactive
	state.lastClosedAt = now
	s.candidateLifecycle[key] = state
}

func (s *pathState) markCandidateUnusable(now time.Time, key string, suppressFor time.Duration) {
	if key == "" {
		return
	}
	state, ok := s.candidateLifecycle[key]
	if !ok {
		return
	}
	state.status = candidateUnusable
	state.lastClosedAt = now
	if suppressFor > 0 {
		state.suppressUntil = now.Add(suppressFor)
	} else {
		state.suppressUntil = time.Time{}
	}
	s.candidateLifecycle[key] = state
}

func (s *pathState) pruneTrackedCandidates(time.Time) {
	activeKey := ""
	if s.current == PathDirect {
		activeKey = s.bestEndpoint
	}

	for key := range s.candidateLifecycle {
		if key == activeKey {
			continue
		}
		if _, ok := s.endpoints[key]; !ok {
			s.deleteTrackedCandidate(key)
		}
	}

	s.pruneInactiveCandidates(activeKey)
	for {
		entries := s.prunableCandidateEntries(activeKey)
		if len(entries) <= maxTrackedNonRelayCandidates {
			return
		}
		sort.SliceStable(entries, func(i, j int) bool {
			return candidatePruneLess(entries[i], entries[j])
		})
		s.deleteTrackedCandidate(entries[0].key)
	}
}

type candidatePruneEntry struct {
	key   string
	state directCandidateState
}

func (s *pathState) pruneInactiveCandidates(activeKey string) {
	inactive := make([]candidatePruneEntry, 0, len(s.candidateLifecycle))
	for key, state := range s.candidateLifecycle {
		if key == activeKey || state.status != candidateInactive {
			continue
		}
		inactive = append(inactive, candidatePruneEntry{key: key, state: state})
	}
	if len(inactive) <= maxInactiveNonRelayCandidates {
		return
	}
	sort.SliceStable(inactive, func(i, j int) bool {
		return candidateTimeLess(inactive[i], inactive[j])
	})
	for len(inactive) > maxInactiveNonRelayCandidates {
		s.deleteTrackedCandidate(inactive[0].key)
		inactive = inactive[1:]
	}
}

func (s *pathState) prunableCandidateEntries(activeKey string) []candidatePruneEntry {
	entries := make([]candidatePruneEntry, 0, len(s.candidateLifecycle))
	for key, state := range s.candidateLifecycle {
		if key == activeKey {
			continue
		}
		entries = append(entries, candidatePruneEntry{key: key, state: state})
	}
	return entries
}

func (s *pathState) deleteTrackedCandidate(key string) {
	delete(s.endpoints, key)
	delete(s.endpointLatency, key)
	delete(s.pendingProbes, key)
	delete(s.candidateLifecycle, key)
}

func candidatePruneLess(a, b candidatePruneEntry) bool {
	if ap, bp := candidatePrunePriority(a.state.status), candidatePrunePriority(b.state.status); ap != bp {
		return ap < bp
	}
	return candidateTimeLess(a, b)
}

func candidatePrunePriority(status candidateStatus) int {
	switch status {
	case candidateUnusable:
		return 0
	case candidatePending:
		return 1
	case candidateInactive:
		return 2
	case candidateOpen:
		return 3
	default:
		return 4
	}
}

func candidateTimeLess(a, b candidatePruneEntry) bool {
	at := candidatePruneTime(a.state)
	bt := candidatePruneTime(b.state)
	if !at.Equal(bt) {
		return at.Before(bt)
	}
	return a.key < b.key
}

func candidatePruneTime(state directCandidateState) time.Time {
	switch state.status {
	case candidateOpen:
		if !state.lastOpenedAt.IsZero() {
			return state.lastOpenedAt
		}
	case candidateInactive, candidateUnusable:
		if !state.lastClosedAt.IsZero() {
			return state.lastClosedAt
		}
	case candidatePending:
		if !state.lastProbeAt.IsZero() {
			return state.lastProbeAt
		}
	}
	if !state.lastSeenAt.IsZero() {
		return state.lastSeenAt
	}
	return state.firstSeenAt
}
