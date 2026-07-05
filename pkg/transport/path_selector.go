// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"net"
	"time"
)

const defaultPathSwitchHysteresis = 5 * time.Millisecond

type selectablePath struct {
	path Path
	key  string
	addr net.Addr
	rtt  time.Duration
}

type pathSelection struct {
	path Path
	key  string
}

type pathSelector struct {
	switchHysteresis time.Duration
}

func defaultPathSelector() pathSelector {
	return pathSelector{switchHysteresis: defaultPathSwitchHysteresis}
}

func (s pathSelector) selectPath(current selectablePath, hasCurrent bool, candidates []selectablePath) (pathSelection, bool) {
	best := current
	hasBest := hasCurrent
	bestIsCurrent := hasCurrent

	for _, candidate := range candidates {
		if !candidate.selectable() {
			continue
		}
		if !hasBest || s.better(candidate, best, bestIsCurrent) {
			best = candidate
			hasBest = true
			bestIsCurrent = false
		}
	}

	if !hasBest {
		return pathSelection{}, false
	}
	return pathSelection{path: best.path, key: best.key}, true
}

func (p selectablePath) selectable() bool {
	switch p.path {
	case PathDirect:
		return p.key != "" && p.addr != nil
	case PathRelay:
		return true
	default:
		return false
	}
}

func (s pathSelector) better(candidate, current selectablePath, currentIsSelected bool) bool {
	candidateTier := pathTier(candidate.path)
	currentTier := pathTier(current.path)
	if candidateTier != currentTier {
		return candidateTier > currentTier
	}
	if candidate.path == current.path && candidate.key == current.key {
		return false
	}

	candidateRTT := biasedRTT(candidate)
	currentRTT := biasedRTT(current)
	if currentIsSelected {
		return candidateRTT+s.switchHysteresis <= currentRTT
	}
	return candidateRTT < currentRTT
}

func pathTier(path Path) int {
	switch path {
	case PathDirect:
		return 2
	case PathRelay:
		return 1
	default:
		return 0
	}
}

func biasedRTT(path selectablePath) time.Duration {
	if path.path != PathDirect {
		return path.rtt
	}
	return path.rtt - directAddrRTTBias(path.addr)
}

func directAddrRTTBias(addr net.Addr) time.Duration {
	ip, ok := addrIP(addr)
	if !ok {
		return 0
	}
	switch {
	case ip.IsLoopback():
		return 50 * time.Millisecond
	case ip.IsLinkLocalUnicast():
		return 30 * time.Millisecond
	case ip.IsPrivate() || isCGNAT(ip):
		return 20 * time.Millisecond
	default:
		return 0
	}
}
