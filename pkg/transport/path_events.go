// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"time"
)

type PathEventType string
type PathEventReason string
type PathEventSource string

const (
	PathEventCandidatesChanged PathEventType = "candidates-changed"
	PathEventProbeSent         PathEventType = "probe-sent"
	PathEventProbeFailed       PathEventType = "probe-failed"
	PathEventProbeSucceeded    PathEventType = "probe-succeeded"
	PathEventSelected          PathEventType = "selected"
	PathEventFallback          PathEventType = "fallback"
	PathEventLagged            PathEventType = "lagged"
)

const (
	PathEventReasonProbeAck         PathEventReason = "probe-ack"
	PathEventReasonDirectBroken     PathEventReason = "direct-broken"
	PathEventReasonDirectStale      PathEventReason = "direct-stale"
	PathEventReasonCandidateLost    PathEventReason = "candidate-lost"
	PathEventReasonStopDirect       PathEventReason = "stop-direct"
	PathEventReasonProbeWriteFailed PathEventReason = "probe-write-failed"
)

const (
	PathEventSourceDirectProbe   PathEventSource = "direct-probe"
	PathEventSourceDiscovery     PathEventSource = "discovery"
	PathEventSourceManual        PathEventSource = "manual"
	PathEventSourceRemoteControl PathEventSource = "remote-control"
	PathEventSourceSeed          PathEventSource = "seed"
	PathEventSourceStaleCheck    PathEventSource = "stale-check"
	PathEventSourceStopDirect    PathEventSource = "stop-direct"
)

type PathCandidateSnapshot struct {
	Addr         net.Addr
	RTT          time.Duration
	Selected     bool
	ProbePending bool
	ProbeSentAt  time.Time
}

type PathSnapshot struct {
	At           time.Time
	Path         Path
	SelectedAddr net.Addr
	SelectedRTT  time.Duration
	Candidates   []PathCandidateSnapshot
	Upgrades     int
	Fallbacks    int
}

type PathEvent struct {
	At           time.Time
	Type         PathEventType
	Reason       PathEventReason
	Source       PathEventSource
	Path         Path
	PreviousPath Path
	SelectedAddr net.Addr
	PreviousAddr net.Addr
	TargetAddr   net.Addr
	RTT          time.Duration
	Snapshot     PathSnapshot
}

func clonePathEvent(event PathEvent) PathEvent {
	event.SelectedAddr = cloneAddr(event.SelectedAddr)
	event.PreviousAddr = cloneAddr(event.PreviousAddr)
	event.TargetAddr = cloneAddr(event.TargetAddr)
	event.Snapshot = clonePathSnapshot(event.Snapshot)
	return event
}

func clonePathSnapshot(snapshot PathSnapshot) PathSnapshot {
	snapshot.SelectedAddr = cloneAddr(snapshot.SelectedAddr)
	if len(snapshot.Candidates) > 0 {
		candidates := make([]PathCandidateSnapshot, len(snapshot.Candidates))
		for i, candidate := range snapshot.Candidates {
			candidate.Addr = cloneAddr(candidate.Addr)
			candidates[i] = candidate
		}
		snapshot.Candidates = candidates
	}
	return snapshot
}
