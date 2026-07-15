// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"reflect"
	"testing"
)

type sccFixture struct {
	Candidates []string    `json:"candidates"`
	Edges      [][2]string `json:"edges"`
	Expected   []string    `json:"expected"`
}

func TestSCCPeakFrontierPreservesCyclesAndRejectsIncomingComponents(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"scc-cycle-frontier.json", "scc-incoming-component.json"} {
		fixture := loadFixtureTwice[sccFixture](t, name)
		edges := make([]MaterialEdge, 0, len(fixture.Edges))
		for _, edge := range fixture.Edges {
			edges = append(edges, MaterialEdge{From: edge[0], To: edge[1]})
		}
		if got := PeakFrontier(fixture.Candidates, edges); !reflect.DeepEqual(got, fixture.Expected) {
			t.Fatalf("%s frontier = %v, want %v", name, got, fixture.Expected)
		}
	}
}

func TestSCCPeakFrontierIsDeterministicUnderInputPermutations(t *testing.T) {
	t.Parallel()

	fixture := loadFixtureTwice[sccFixture](t, "scc-incoming-component.json")
	var edges []MaterialEdge
	for index := len(fixture.Edges) - 1; index >= 0; index-- {
		edge := fixture.Edges[index]
		edges = append(edges, MaterialEdge{From: edge[0], To: edge[1]})
	}
	candidates := append([]string(nil), fixture.Candidates...)
	for left, right := 0, len(candidates)-1; left < right; left, right = left+1, right-1 {
		candidates[left], candidates[right] = candidates[right], candidates[left]
	}
	if got := PeakFrontier(candidates, edges); !reflect.DeepEqual(got, fixture.Expected) {
		t.Fatalf("permuted frontier = %v, want %v", got, fixture.Expected)
	}
}
