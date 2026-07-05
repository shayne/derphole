// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && toposim

package toposim

import (
	"context"
	"testing"

	"github.com/shayne/derphole/pkg/candidate"
)

func TestTopologyNATToNATPromotesDirect(t *testing.T) {
	runCatalogScenario(t, "nat-to-nat-direct")
}

func TestTopologyRelayFallbackWhenNoStableMapping(t *testing.T) {
	runCatalogScenario(t, "relay-fallback")
}

func TestTopologyFasterPathAppears(t *testing.T) {
	runCatalogScenario(t, "faster-path-appears")
}

func TestTopologyLinkOutageFallsBackThenReplugPromotes(t *testing.T) {
	runCatalogScenario(t, "link-outage-replug")
}

func TestTopologyManyLocalAddressesCapsCandidatesAndPromotes(t *testing.T) {
	result := runCatalogScenario(t, "many-local-addresses")
	if !result.CandidateCountAtMost("left", candidate.MaxCount) {
		t.Fatalf("left candidate count = %d, want <= %d", result.CandidateCounts["left"], candidate.MaxCount)
	}
	if !result.CandidateCountAtMost("right", candidate.MaxCount) {
		t.Fatalf("right candidate count = %d, want <= %d", result.CandidateCounts["right"], candidate.MaxCount)
	}
}

func TestTopologyDualStackPrefersReachableLowerLatencyFamily(t *testing.T) {
	runCatalogScenario(t, "dual-stack-preference")
}

func TestTopologyPortmapChangeRefreshesCandidates(t *testing.T) {
	runCatalogScenario(t, "portmap-change")
}

func runCatalogScenario(t *testing.T, name string) Result {
	t.Helper()

	scenario, ok := FindScenario(name)
	if !ok {
		t.Fatalf("FindScenario(%q) ok = false", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), scenario.Timeout)
	defer cancel()

	result, err := RunLinuxScenario(ctx, scenario)
	if err != nil {
		t.Fatalf("RunLinuxScenario(%q) error = %v", name, err)
	}
	for _, expect := range scenario.Expect {
		if !result.Saw(expect) {
			t.Fatalf("RunLinuxScenario(%q) did not see %#v; transitions=%#v", name, expect, result.Transitions)
		}
	}
	return result
}
