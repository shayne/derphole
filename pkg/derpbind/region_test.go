// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestPickRegionSelectsMeasuredOrDeterministicRegion(t *testing.T) {
	t.Parallel()

	measurementErr := errors.New("measurement failed")
	tests := []struct {
		name       string
		dm         *tailcfg.DERPMap
		latencies  map[int]time.Duration
		measureErr error
		want       RegionSelection
		wantErr    bool
	}{
		{
			name:      "lowest positive latency wins",
			dm:        regionTestMap(1, 2, 3),
			latencies: map[int]time.Duration{1: 20 * time.Millisecond, 2: 10 * time.Millisecond, 3: 30 * time.Millisecond},
			want:      RegionSelection{RegionID: 2, Latency: 10 * time.Millisecond, Measured: true},
		},
		{
			name:      "equal latency chooses lower region",
			dm:        regionTestMap(9, 3),
			latencies: map[int]time.Duration{9: 8 * time.Millisecond, 3: 8 * time.Millisecond},
			want:      RegionSelection{RegionID: 3, Latency: 8 * time.Millisecond, Measured: true},
		},
		{
			name:      "absent regions are ignored",
			dm:        regionTestMap(4, 8),
			latencies: map[int]time.Duration{99: time.Millisecond, 8: 12 * time.Millisecond},
			want:      RegionSelection{RegionID: 8, Latency: 12 * time.Millisecond, Measured: true},
		},
		{
			name:      "non-positive latencies use sorted fallback",
			dm:        regionTestMap(7, 2),
			latencies: map[int]time.Duration{7: 0, 2: -time.Millisecond},
			want:      RegionSelection{RegionID: 2},
		},
		{
			name:       "measurement error uses sorted fallback",
			dm:         regionTestMap(12, 5),
			measureErr: measurementErr,
			want:       RegionSelection{RegionID: 5},
		},
		{
			name: "regions without relay nodes are ignored",
			dm: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
				1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{STUNOnly: true, HostName: "stun.example.test"}}},
				6: {RegionID: 6, Nodes: []*tailcfg.DERPNode{{RegionID: 6, HostName: "derp.example.test"}}},
				8: {RegionID: 8, Nodes: []*tailcfg.DERPNode{{RegionID: 8, HostName: "derp.example.test"}}},
			}},
			latencies: map[int]time.Duration{1: time.Millisecond, 6: 20 * time.Millisecond, 8: 30 * time.Millisecond},
			want:      RegionSelection{RegionID: 6, Latency: 20 * time.Millisecond, Measured: true},
		},
		{name: "nil map", wantErr: true},
		{name: "empty map", dm: &tailcfg.DERPMap{}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.dm.Clone()
			selection, err := pickRegion(context.Background(), tt.dm, func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error) {
				return tt.latencies, tt.measureErr
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("pickRegion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && selection != tt.want {
				t.Fatalf("pickRegion() = %+v, want %+v", selection, tt.want)
			}
			if !reflect.DeepEqual(tt.dm, before) {
				t.Fatalf("pickRegion() mutated input map\nbefore: %#v\nafter:  %#v", before, tt.dm)
			}
		})
	}
}

func TestPickRegionDoesNotMeasureInvalidMap(t *testing.T) {
	t.Parallel()

	called := false
	_, err := pickRegion(context.Background(), &tailcfg.DERPMap{}, func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error) {
		called = true
		return nil, nil
	})
	if err == nil {
		t.Fatal("pickRegion() error = nil, want invalid map error")
	}
	if called {
		t.Fatal("pickRegion() measured an invalid map")
	}
}

func TestPickRegionSingleUsableRegionSkipsMeasurement(t *testing.T) {
	t.Parallel()

	called := false
	selection, err := pickRegion(context.Background(), regionTestMap(7), func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error) {
		called = true
		return map[int]time.Duration{7: time.Millisecond}, nil
	})
	if err != nil {
		t.Fatalf("pickRegion() error = %v", err)
	}
	if selection != (RegionSelection{RegionID: 7}) {
		t.Fatalf("pickRegion() = %+v, want deterministic region 7", selection)
	}
	if called {
		t.Fatal("pickRegion() measured a map with only one usable region")
	}
}

func regionTestMap(regionIDs ...int) *tailcfg.DERPMap {
	dm := &tailcfg.DERPMap{Regions: make(map[int]*tailcfg.DERPRegion, len(regionIDs))}
	for _, regionID := range regionIDs {
		dm.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID: regionID,
			Nodes: []*tailcfg.DERPNode{{
				Name:     "test",
				RegionID: regionID,
				HostName: "derp.example.test",
			}},
		}
	}
	return dm
}
