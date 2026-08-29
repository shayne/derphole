// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestValidateDERPMapRejectsUnsafeStructure(t *testing.T) {
	t.Parallel()

	tests := map[string]*tailcfg.DERPMap{
		"region outside token range": validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test"}),
		"region key mismatch":        validationTestMap(2, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test"}),
		"node region mismatch":       validationTestMap(1, &tailcfg.DERPNode{RegionID: 2, HostName: "derp.example.test"}),
		"missing TLS authority":      validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, IPv4: "192.0.2.1"}),
		"malformed IPv4":             validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test", IPv4: "999.1.1.1"}),
		"IPv6 in IPv4 field":         validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test", IPv4: "2001:db8::1"}),
		"malformed IPv6":             validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test", IPv6: "not-an-ip"}),
		"invalid DERP port":          validationTestMap(1, &tailcfg.DERPNode{RegionID: 1, HostName: "derp.example.test", DERPPort: 70000}),
	}
	tests["region outside token range"] = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		70000: {RegionID: 70000, Nodes: []*tailcfg.DERPNode{{RegionID: 70000, HostName: "derp.example.test"}}},
	}}

	for name, dm := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateDERPMap(dm); err == nil {
				t.Fatal("validateDERPMap() error = nil, want structural rejection")
			}
		})
	}
}

func TestNodeForRegionSkipsNonRelayEntriesAndNeverSubstitutesRegion(t *testing.T) {
	t.Parallel()

	want := &tailcfg.DERPNode{Name: "usable", RegionID: 7, HostName: "derp7.example.test"}
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		3: {RegionID: 3, Nodes: []*tailcfg.DERPNode{{Name: "other", RegionID: 3, HostName: "derp3.example.test"}}},
		7: {RegionID: 7, Nodes: []*tailcfg.DERPNode{
			nil,
			{Name: "stun", RegionID: 7, HostName: "stun7.example.test", STUNOnly: true},
			want,
		}},
	}}

	if got := NodeForRegion(dm, 7); got != want {
		t.Fatalf("NodeForRegion(7) = %+v, want %+v", got, want)
	}
	if got := NodeForRegion(dm, 9); got != nil {
		t.Fatalf("NodeForRegion(9) = %+v, want nil without region substitution", got)
	}
	if got := FirstNode(dm); got == nil || got.RegionID != 3 {
		t.Fatalf("FirstNode() = %+v, want sorted region 3", got)
	}
}

func TestOneShotCompatibleMapUsesFrozenRegionSetAndIsolatesMutation(t *testing.T) {
	t.Parallel()

	source := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		3:  {RegionID: 3, Nodes: []*tailcfg.DERPNode{{RegionID: 3, HostName: "derp3.example.test"}}},
		99: {RegionID: 99, Nodes: []*tailcfg.DERPNode{{RegionID: 99, HostName: "derp99.example.test"}}},
	}}

	compatible, err := OneShotCompatibleMap(source)
	if err != nil {
		t.Fatalf("OneShotCompatibleMap(): %v", err)
	}
	if NodeForRegion(compatible, 3) == nil || NodeForRegion(compatible, 99) != nil {
		t.Fatalf("compatible regions = %v, want only frozen-compatible region 3", compatible.RegionIDs())
	}
	compatible.Regions[3].Nodes[0].HostName = "mutated.example.test"
	if got := source.Regions[3].Nodes[0].HostName; got != "derp3.example.test" {
		t.Fatalf("source host = %q, want mutation isolation", got)
	}

	_, err = OneShotCompatibleMap(&tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		99: source.Regions[99],
	}})
	if err == nil {
		t.Fatal("OneShotCompatibleMap(new-only map) error = nil, want compatibility failure")
	}
}

func validationTestMap(regionKey int, node *tailcfg.DERPNode) *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		regionKey: {RegionID: 1, Nodes: []*tailcfg.DERPNode{node}},
	}}
}
