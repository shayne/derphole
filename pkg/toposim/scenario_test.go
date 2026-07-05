// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import "testing"

func TestScenarioCatalogCoversBacklogItemOne(t *testing.T) {
	t.Parallel()

	got := make(map[string]bool)
	for _, scenario := range Catalog() {
		got[scenario.Name] = true
	}

	for _, name := range []string{
		"nat-to-nat-direct",
		"relay-fallback",
		"faster-path-appears",
		"link-outage-replug",
		"many-local-addresses",
		"dual-stack-preference",
		"portmap-change",
	} {
		if !got[name] {
			t.Fatalf("Catalog() missing scenario %q", name)
		}
	}
}

func TestCatalogScenariosHaveConcreteAssertions(t *testing.T) {
	t.Parallel()

	for _, scenario := range Catalog() {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()

			if len(scenario.Nodes) != 2 {
				t.Fatalf("scenario %q has %d nodes, want 2", scenario.Name, len(scenario.Nodes))
			}
			if scenario.Timeout <= 0 {
				t.Fatalf("scenario %q timeout = %s, want positive", scenario.Name, scenario.Timeout)
			}
			if scenario.Timeout >= 90_000_000_000 {
				t.Fatalf("scenario %q timeout = %s, want under 90s", scenario.Name, scenario.Timeout)
			}

			hasTransition := false
			for _, transition := range scenario.Expect {
				if transition.Path == PathRelayName || transition.Path == PathDirectName {
					hasTransition = true
					break
				}
			}
			if !hasTransition {
				t.Fatalf("scenario %q has no expected relay/direct transition", scenario.Name)
			}
		})
	}
}

func TestResultCandidateCountAtMost(t *testing.T) {
	t.Parallel()

	result := Result{CandidateCounts: map[string]int{"left": 32, "right": 33}}
	if !result.CandidateCountAtMost("left", 32) {
		t.Fatal("CandidateCountAtMost(left, 32) = false, want true")
	}
	if result.CandidateCountAtMost("right", 32) {
		t.Fatal("CandidateCountAtMost(right, 32) = true, want false")
	}
	if result.CandidateCountAtMost("missing", 32) {
		t.Fatal("CandidateCountAtMost(missing, 32) = true, want false")
	}
}
