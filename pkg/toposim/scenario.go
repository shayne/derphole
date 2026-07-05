// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toposim

import "time"

const (
	PathRelayName  = "relay"
	PathDirectName = "direct"
)

type NATKind string

const (
	NATNone       NATKind = "none"
	NATPortMapped NATKind = "port-mapped"
	NATSymmetric  NATKind = "symmetric"
)

type ActionType string

const (
	ActionSetCandidates ActionType = "set-candidates"
	ActionSetPortmap    ActionType = "set-portmap"
	ActionSetLink       ActionType = "set-link"
	ActionSendDatagram  ActionType = "send-peer-datagram"
)

type Scenario struct {
	Name        string
	Nodes       []NodeSpec
	Links       []LinkSpec
	Actions     []ScenarioAction
	Expect      []ExpectedTransition
	Timeout     time.Duration
	Description string
}

type NodeSpec struct {
	Name              string
	Namespace         string
	DirectPort        int
	InitialCandidates []string
	PortmapCandidates []string
	ManyAddressCount  int
}

type LinkSpec struct {
	Name        string
	From        string
	To          string
	IPv4CIDR    string
	IPv6CIDR    string
	Latency     time.Duration
	LossPercent int
	NAT         NATKind
}

type ScenarioAction struct {
	Type              ActionType
	Node              string
	Link              string
	After             time.Duration
	Up                bool
	Candidates        []string
	PortmapCandidates []string
	Payload           []byte
}

type ExpectedTransition struct {
	Node   string
	Path   string
	Direct string
	Within time.Duration
}

func Catalog() []Scenario {
	return []Scenario{
		{
			Name:        "nat-to-nat-direct",
			Description: "two port-mapped endpoints advertise stable candidates and promote off relay",
			Nodes:       nodePair(1, []string{"10.42.1.2:40000"}, []string{"10.42.1.3:40001"}),
			Links: []LinkSpec{
				{Name: "direct", From: "left", To: "right", IPv4CIDR: "10.42.1.0/24", Latency: 20 * time.Millisecond, NAT: NATPortMapped},
			},
			Expect:  relayThenDirect(8 * time.Second),
			Timeout: 20 * time.Second,
		},
		{
			Name:        "relay-fallback",
			Description: "symmetric NAT leaves no stable peer candidate, so relay remains selected",
			Nodes:       nodePair(2, nil, nil),
			Links: []LinkSpec{
				{Name: "blocked", From: "left", To: "right", IPv4CIDR: "10.42.2.0/24", LossPercent: 100, NAT: NATSymmetric},
			},
			Expect: []ExpectedTransition{
				{Node: "left", Path: PathRelayName, Within: 2 * time.Second},
				{Node: "right", Path: PathRelayName, Within: 2 * time.Second},
			},
			Timeout: 12 * time.Second,
		},
		{
			Name:        "faster-path-appears",
			Description: "relay starts first, then a usable direct candidate appears and is selected",
			Nodes:       nodePair(3, nil, nil),
			Links: []LinkSpec{
				{Name: "late-direct", From: "left", To: "right", IPv4CIDR: "10.42.3.0/24", Latency: 5 * time.Millisecond, NAT: NATNone},
			},
			Actions: []ScenarioAction{
				{Type: ActionSetCandidates, Node: "left", After: 500 * time.Millisecond, Candidates: []string{"10.42.3.2:40000"}},
				{Type: ActionSetCandidates, Node: "right", After: 500 * time.Millisecond, Candidates: []string{"10.42.3.3:40001"}},
			},
			Expect:  relayThenDirect(10 * time.Second),
			Timeout: 25 * time.Second,
		},
		{
			Name:        "link-outage-replug",
			Description: "direct is selected, lost during an outage, then restored after candidates return",
			Nodes:       nodePair(4, []string{"10.42.4.2:40000"}, []string{"10.42.4.3:40001"}),
			Links: []LinkSpec{
				{Name: "direct", From: "left", To: "right", IPv4CIDR: "10.42.4.0/24", Latency: 15 * time.Millisecond, NAT: NATNone},
			},
			Actions: []ScenarioAction{
				{Type: ActionSetCandidates, Node: "left", After: 1500 * time.Millisecond},
				{Type: ActionSetCandidates, Node: "right", After: 1500 * time.Millisecond},
				{Type: ActionSetCandidates, Node: "left", After: 2500 * time.Millisecond, Candidates: []string{"10.42.4.2:40000"}},
				{Type: ActionSetCandidates, Node: "right", After: 2500 * time.Millisecond, Candidates: []string{"10.42.4.3:40001"}},
			},
			Expect: []ExpectedTransition{
				{Node: "left", Path: PathRelayName, Within: 2 * time.Second},
				{Node: "left", Path: PathDirectName, Within: 8 * time.Second},
				{Node: "left", Path: PathRelayName, Within: 12 * time.Second},
				{Node: "left", Path: PathDirectName, Within: 18 * time.Second},
			},
			Timeout: 30 * time.Second,
		},
		{
			Name:        "many-local-addresses",
			Description: "candidate emission is capped while a usable direct address still promotes",
			Nodes:       nodePair(5, []string{"10.42.5.2:40000"}, []string{"10.42.5.3:40001"}),
			Links: []LinkSpec{
				{Name: "direct", From: "left", To: "right", IPv4CIDR: "10.42.5.0/24", Latency: 20 * time.Millisecond, NAT: NATPortMapped},
			},
			Expect: []ExpectedTransition{
				{Node: "left", Path: PathDirectName, Within: 12 * time.Second},
				{Node: "right", Path: PathDirectName, Within: 12 * time.Second},
			},
			Timeout: 25 * time.Second,
		},
		{
			Name:        "dual-stack-preference",
			Description: "IPv4 and IPv6 candidates are present, and a reachable lower-latency family wins",
			Nodes:       nodePair(6, []string{"10.42.6.2:40000", "[fd42:6::2]:40000"}, []string{"10.42.6.3:40001", "[fd42:6::3]:40001"}),
			Links: []LinkSpec{
				{Name: "v4", From: "left", To: "right", IPv4CIDR: "10.42.6.0/24", Latency: 40 * time.Millisecond, NAT: NATNone},
				{Name: "v6", From: "left", To: "right", IPv6CIDR: "fd42:6::/64", Latency: 5 * time.Millisecond, NAT: NATNone},
			},
			Expect: []ExpectedTransition{
				{Node: "left", Path: PathDirectName, Within: 12 * time.Second},
				{Node: "right", Path: PathDirectName, Within: 12 * time.Second},
			},
			Timeout: 25 * time.Second,
		},
		{
			Name:        "portmap-change",
			Description: "a mapped candidate changes and peers regain direct connectivity on the refreshed address",
			Nodes: []NodeSpec{
				{Name: "left", Namespace: "left", DirectPort: 40000, PortmapCandidates: []string{"10.42.7.2:41000"}},
				{Name: "right", Namespace: "right", DirectPort: 40001, InitialCandidates: []string{"10.42.7.3:40001"}},
			},
			Links: []LinkSpec{
				{Name: "direct", From: "left", To: "right", IPv4CIDR: "10.42.7.0/24", Latency: 20 * time.Millisecond, NAT: NATPortMapped},
			},
			Actions: []ScenarioAction{
				{Type: ActionSetPortmap, Node: "left", After: 1500 * time.Millisecond, PortmapCandidates: []string{"10.42.7.2:40000"}},
			},
			Expect: []ExpectedTransition{
				{Node: "left", Path: PathRelayName, Within: 2 * time.Second},
				{Node: "left", Path: PathDirectName, Within: 12 * time.Second},
			},
			Timeout: 25 * time.Second,
		},
	}
}

func FindScenario(name string) (Scenario, bool) {
	for _, scenario := range Catalog() {
		if scenario.Name == name {
			return scenario, true
		}
	}
	return Scenario{}, false
}

func nodePair(index int, leftCandidates, rightCandidates []string) []NodeSpec {
	return []NodeSpec{
		{Name: "left", Namespace: "left", DirectPort: 40000, InitialCandidates: leftCandidates, ManyAddressCount: manyAddressCount(index)},
		{Name: "right", Namespace: "right", DirectPort: 40001, InitialCandidates: rightCandidates, ManyAddressCount: manyAddressCount(index)},
	}
}

func manyAddressCount(index int) int {
	if index == 5 {
		return 48
	}
	return 0
}

func relayThenDirect(within time.Duration) []ExpectedTransition {
	return []ExpectedTransition{
		{Node: "left", Path: PathRelayName, Within: 2 * time.Second},
		{Node: "right", Path: PathRelayName, Within: 2 * time.Second},
		{Node: "left", Path: PathDirectName, Within: within},
		{Node: "right", Path: PathDirectName, Within: within},
	}
}
