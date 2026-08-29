// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js

package derpbind

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// PickRegion measures the available DERP regions and returns the nearest one.
func PickRegion(ctx context.Context, dm *tailcfg.DERPMap) (RegionSelection, error) {
	return pickRegion(ctx, dm, measureDERPRegions)
}

func measureDERPRegions(ctx context.Context, dm *tailcfg.DERPMap) (map[int]time.Duration, error) {
	standaloneCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	monitor := netmon.NewStatic()
	defer func() { _ = monitor.Close() }()
	client := &netcheck.Client{
		NetMon: monitor,
		Logf:   logger.Discard,
	}
	if err := client.Standalone(standaloneCtx, ":0"); err != nil {
		return nil, fmt.Errorf("start netcheck: %w", err)
	}
	report, err := client.GetReport(ctx, dm, &netcheck.GetReportOpts{})
	if err != nil {
		return nil, fmt.Errorf("measure DERP regions: %w", err)
	}
	return report.RegionLatency, nil
}
