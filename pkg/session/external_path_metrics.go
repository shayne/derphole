// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"time"

	"github.com/shayne/derphole/pkg/transport"
)

func watchExternalDirectPath(ctx context.Context, manager *transport.Manager, metrics *externalTransferMetrics) func() {
	if manager == nil || metrics == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go func() {
		if manager.PathState() == transport.PathDirect {
			metrics.MarkDirectValidated(time.Now())
			return
		}
		for update := range manager.Updates(watchCtx) {
			if update.Path == transport.PathDirect {
				metrics.MarkDirectValidated(time.Now())
				return
			}
		}
	}()
	return cancel
}
