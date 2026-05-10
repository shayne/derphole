// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultParallelInitial     = 4
	MaxParallelStripes         = 16
	AutoParallelSamplePeriod   = 500 * time.Millisecond
	AutoParallelGrowthStep     = 2
	AutoParallelTargetFloor    = 8
	AutoParallelHoldSamples    = 4
	AutoParallelMinGainMbps    = 50
	AutoParallelMinGainPercent = 10
)

type ParallelMode string

const (
	ParallelModeFixed ParallelMode = "fixed"
	ParallelModeAuto  ParallelMode = "auto"
)

type ParallelPolicy struct {
	Mode    ParallelMode
	Initial int
	Cap     int
}

func DefaultParallelPolicy() ParallelPolicy {
	if raw := os.Getenv("DERPHOLE_NATIVE_QUIC_CONNS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= MaxParallelStripes {
			return FixedParallelPolicy(n)
		}
	}
	return FixedParallelPolicy(DefaultParallelInitial)
}

func FixedParallelPolicy(n int) ParallelPolicy {
	return ParallelPolicy{
		Mode:    ParallelModeFixed,
		Initial: n,
		Cap:     n,
	}
}

func AutoParallelPolicy() ParallelPolicy {
	return ParallelPolicy{
		Mode:    ParallelModeAuto,
		Initial: DefaultParallelInitial,
		Cap:     MaxParallelStripes,
	}
}

func ParseParallelPolicy(raw string) (ParallelPolicy, error) {
	if strings.EqualFold(raw, string(ParallelModeAuto)) {
		return AutoParallelPolicy(), nil
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxParallelStripes {
		return ParallelPolicy{}, fmt.Errorf("parallel must be 1-%d or auto", MaxParallelStripes)
	}
	return FixedParallelPolicy(n), nil
}

func (p ParallelPolicy) normalized() ParallelPolicy {
	switch p.Mode {
	case ParallelModeFixed:
		if p.Initial < 1 {
			return DefaultParallelPolicy()
		}
		if p.Initial > MaxParallelStripes {
			p.Initial = MaxParallelStripes
		}
		p.Cap = p.Initial
		return p
	case ParallelModeAuto:
		if p.Initial < 1 {
			p.Initial = DefaultParallelInitial
		}
		if p.Initial > MaxParallelStripes {
			p.Initial = MaxParallelStripes
		}
		if p.Cap < p.Initial {
			p.Cap = MaxParallelStripes
		}
		if p.Cap > MaxParallelStripes {
			p.Cap = MaxParallelStripes
		}
		return p
	default:
		return DefaultParallelPolicy()
	}
}

type parallelWindow struct {
	Target             int
	BacklogLimited     bool
	ThroughputMbps     float64
	PreviousThroughput float64
}

type parallelDecision struct {
	NextTarget int
	StopReason string
}

type parallelAutoController struct {
	policy      ParallelPolicy
	holdSamples int
	lastApplied int
	stopped     bool
}

func newParallelAutoController(policy ParallelPolicy) *parallelAutoController {
	policy = policy.normalized()
	return &parallelAutoController{policy: policy}
}

func (c *parallelAutoController) Observe(w parallelWindow) parallelDecision {
	if c == nil || c.policy.Mode != ParallelModeAuto || c.stopped {
		return parallelDecision{}
	}
	if !w.BacklogLimited || w.Target >= c.policy.Cap {
		return parallelDecision{}
	}
	if c.holdSamples > 0 {
		c.holdSamples--
		return parallelDecision{}
	}
	floorTarget := min(c.policy.Cap, AutoParallelTargetFloor)
	nextTarget := min(w.Target+AutoParallelGrowthStep, c.policy.Cap)
	if nextTarget <= w.Target {
		return parallelDecision{}
	}
	if w.Target < floorTarget {
		nextTarget = floorTarget
		c.lastApplied = nextTarget
		c.holdSamples = AutoParallelHoldSamples
		return parallelDecision{NextTarget: nextTarget}
	}
	if c.lastApplied == 0 {
		c.lastApplied = nextTarget
		c.holdSamples = AutoParallelHoldSamples
		return parallelDecision{NextTarget: nextTarget}
	}
	if w.PreviousThroughput <= 0 {
		c.lastApplied = nextTarget
		c.holdSamples = AutoParallelHoldSamples
		return parallelDecision{NextTarget: nextTarget}
	}
	gainMbps := w.ThroughputMbps - w.PreviousThroughput
	gainPct := (gainMbps / w.PreviousThroughput) * 100
	if gainMbps < AutoParallelMinGainMbps || gainPct < AutoParallelMinGainPercent {
		c.stopped = true
		return parallelDecision{StopReason: "diminishing-return"}
	}
	c.lastApplied = nextTarget
	c.holdSamples = AutoParallelHoldSamples
	return parallelDecision{NextTarget: nextTarget}
}
