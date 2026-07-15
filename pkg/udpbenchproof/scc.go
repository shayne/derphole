// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import "sort"

// PeakFrontier returns every member of each zero-incoming SCC.
func PeakFrontier(candidateIDs []string, edges []MaterialEdge) []string {
	candidates := uniqueSortedCandidates(candidateIDs)
	adjacency := materialAdjacency(candidates, edges)
	components, componentByCandidate := stronglyConnectedComponents(candidates, adjacency)
	incoming := componentIncoming(components, componentByCandidate, adjacency)
	return zeroIncomingCandidates(components, incoming)
}

func materialAdjacency(candidates []string, edges []MaterialEdge) map[string][]string {
	known := make(map[string]bool, len(candidates))
	adjacency := make(map[string][]string, len(candidates))
	for _, candidate := range candidates {
		known[candidate] = true
	}
	for _, edge := range edges {
		if known[edge.From] && known[edge.To] && edge.From != edge.To {
			adjacency[edge.From] = append(adjacency[edge.From], edge.To)
		}
	}
	for candidate := range adjacency {
		adjacency[candidate] = uniqueSortedCandidates(adjacency[candidate])
	}
	return adjacency
}

func componentIncoming(components [][]string, componentByCandidate map[string]int, adjacency map[string][]string) []bool {
	incoming := make([]bool, len(components))
	for from, tos := range adjacency {
		for _, to := range tos {
			fromComponent, toComponent := componentByCandidate[from], componentByCandidate[to]
			if fromComponent != toComponent {
				incoming[toComponent] = true
			}
		}
	}
	return incoming
}

func zeroIncomingCandidates(components [][]string, incoming []bool) []string {
	var frontier []string
	for index, component := range components {
		if !incoming[index] {
			frontier = append(frontier, component...)
		}
	}
	sort.Strings(frontier)
	return frontier
}

func stronglyConnectedComponents(candidates []string, adjacency map[string][]string) ([][]string, map[string]int) {
	state := tarjanState{
		adjacency: adjacency,
		indices:   make(map[string]int, len(candidates)),
		lowlink:   make(map[string]int, len(candidates)),
		onStack:   make(map[string]bool, len(candidates)),
		stack:     make([]string, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		if _, seen := state.indices[candidate]; !seen {
			state.visit(candidate)
		}
	}
	return state.components, indexComponents(candidates, state.components)
}

type tarjanState struct {
	adjacency  map[string][]string
	nextIndex  int
	indices    map[string]int
	lowlink    map[string]int
	onStack    map[string]bool
	stack      []string
	components [][]string
}

func (state *tarjanState) visit(candidate string) {
	state.indices[candidate] = state.nextIndex
	state.lowlink[candidate] = state.nextIndex
	state.nextIndex++
	state.stack = append(state.stack, candidate)
	state.onStack[candidate] = true
	for _, neighbor := range state.adjacency[candidate] {
		state.visitNeighbor(candidate, neighbor)
	}
	if state.lowlink[candidate] == state.indices[candidate] {
		state.components = append(state.components, state.popComponent(candidate))
	}
}

func (state *tarjanState) visitNeighbor(candidate, neighbor string) {
	neighborIndex, seen := state.indices[neighbor]
	if !seen {
		state.visit(neighbor)
		state.lowlink[candidate] = min(state.lowlink[candidate], state.lowlink[neighbor])
		return
	}
	if state.onStack[neighbor] {
		state.lowlink[candidate] = min(state.lowlink[candidate], neighborIndex)
	}
}

func (state *tarjanState) popComponent(root string) []string {
	var component []string
	for {
		last := state.stack[len(state.stack)-1]
		state.stack = state.stack[:len(state.stack)-1]
		state.onStack[last] = false
		component = append(component, last)
		if last == root {
			break
		}
	}
	sort.Strings(component)
	return component
}

func indexComponents(candidates []string, components [][]string) map[string]int {
	componentByCandidate := make(map[string]int, len(candidates))
	for componentIndex, component := range components {
		for _, candidate := range component {
			componentByCandidate[candidate] = componentIndex
		}
	}
	return componentByCandidate
}

func uniqueSortedCandidates(input []string) []string {
	seen := make(map[string]bool, len(input))
	result := make([]string, 0, len(input))
	for _, candidate := range input {
		if !seen[candidate] {
			seen[candidate] = true
			result = append(result, candidate)
		}
	}
	sort.Strings(result)
	return result
}
