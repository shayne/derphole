// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"

	"github.com/shayne/derphole/pkg/transport"
)

func watchExternalDirectPath(ctx context.Context, manager *transport.Manager, metrics *externalTransferMetrics) func() {
	if manager == nil || metrics == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go func() {
		events := manager.PathEvents(watchCtx)
		snapshot := manager.PathSnapshot()
		metrics.RecordTransportPathSnapshot(snapshot)
		if snapshot.Path == transport.PathDirect {
			cancel()
			return
		}
		for event := range events {
			metrics.RecordTransportPathEvent(event)
			if event.Type == transport.PathEventSelected && event.Path == transport.PathDirect {
				cancel()
				return
			}
		}
	}()
	return cancel
}
