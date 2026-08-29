// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"errors"
	"sort"
	"time"

	"tailscale.com/tailcfg"
)

// RegionSelection records a selected DERP region and whether it was measured.
type RegionSelection struct {
	RegionID int
	Latency  time.Duration
	Measured bool
}

type regionMeasurer func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error)

func pickRegion(ctx context.Context, dm *tailcfg.DERPMap, measure regionMeasurer) (RegionSelection, error) {
	regionIDs := usableRegionIDs(dm)
	if len(regionIDs) == 0 {
		return RegionSelection{}, errors.New("DERP map contains no usable relay regions")
	}
	fallback := RegionSelection{RegionID: regionIDs[0]}
	if len(regionIDs) == 1 || measure == nil {
		return fallback, nil
	}

	latencies, err := measure(ctx, dm)
	if err != nil {
		return fallback, nil
	}
	var best RegionSelection
	for _, regionID := range regionIDs {
		latency := latencies[regionID]
		if latency <= 0 {
			continue
		}
		if !best.Measured || latency < best.Latency {
			best = RegionSelection{
				RegionID: regionID,
				Latency:  latency,
				Measured: true,
			}
		}
	}
	if best.Measured {
		return best, nil
	}
	return fallback, nil
}

func usableRegionIDs(dm *tailcfg.DERPMap) []int {
	if dm == nil {
		return nil
	}
	regionIDs := make([]int, 0, len(dm.Regions))
	for regionID, region := range dm.Regions {
		if regionHasUsableRelay(region) {
			regionIDs = append(regionIDs, regionID)
		}
	}
	sort.Ints(regionIDs)
	return regionIDs
}

func regionHasUsableRelay(region *tailcfg.DERPRegion) bool {
	if region == nil {
		return false
	}
	for _, node := range region.Nodes {
		if usableDERPNode(node, region.RegionID) {
			return true
		}
	}
	return false
}
