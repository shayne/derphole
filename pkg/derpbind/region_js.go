// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js

package derpbind

import (
	"context"
	"time"

	"tailscale.com/tailcfg"
)

// PickRegion returns a deterministic relay region where active netcheck is unavailable.
func PickRegion(ctx context.Context, dm *tailcfg.DERPMap) (RegionSelection, error) {
	return pickRegion(ctx, dm, func(context.Context, *tailcfg.DERPMap) (map[int]time.Duration, error) {
		return nil, nil
	})
}
