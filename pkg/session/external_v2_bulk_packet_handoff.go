// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	externalV2BulkPacketHandoffQuietWindow = 10 * time.Millisecond
	externalV2BulkPacketHandoffHardTimeout = 500 * time.Millisecond
)

type externalV2BulkPacketHandoffDrainResult struct {
	Lanes     int
	Datagrams uint64
	Duration  time.Duration
}

type externalV2BulkPacketHandoffDrainDeps struct {
	quietWindow  time.Duration
	hardTimeout  time.Duration
	newBatchConn func(net.PacketConn) externalV2BulkPacketBatchConn
}

type externalV2BulkPacketHandoffLaneResult struct {
	datagrams uint64
	err       error
}

var externalV2BulkPacketDrainForHandoff = drainExternalV2BulkPacketHandoff

func drainExternalV2BulkPacketHandoff(ctx context.Context, path externalV2BulkPacketPath) (externalV2BulkPacketHandoffDrainResult, error) {
	return drainExternalV2BulkPacketHandoffWithDeps(ctx, path, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  externalV2BulkPacketHandoffQuietWindow,
		hardTimeout:  externalV2BulkPacketHandoffHardTimeout,
		newBatchConn: newExternalV2BulkPacketBatchConn,
	})
}

func drainExternalV2BulkPacketHandoffWithDeps(
	ctx context.Context,
	path externalV2BulkPacketPath,
	deps externalV2BulkPacketHandoffDrainDeps,
) (externalV2BulkPacketHandoffDrainResult, error) {
	started := time.Now()
	result := externalV2BulkPacketHandoffDrainResult{Lanes: len(path.Conns)}
	if len(path.Conns) == 0 {
		result.Duration = time.Since(started)
		return result, errors.New("bulk packet handoff drain has no lanes")
	}
	if deps.quietWindow <= 0 {
		result.Duration = time.Since(started)
		return result, errors.New("bulk packet handoff drain quiet window must be positive")
	}
	if deps.hardTimeout <= 0 {
		result.Duration = time.Since(started)
		return result, errors.New("bulk packet handoff drain hard timeout must be positive")
	}
	if deps.newBatchConn == nil {
		result.Duration = time.Since(started)
		return result, errors.New("bulk packet handoff drain batch connection factory is nil")
	}

	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deps.hardTimeout)
	defer cancel()

	results := make(chan externalV2BulkPacketHandoffLaneResult, len(path.Conns))
	for lane, conn := range path.Conns {
		lane, conn := lane, conn
		go func() {
			count, err := drainExternalV2BulkPacketHandoffLane(drainCtx, deps.quietWindow, deps.newBatchConn(conn))
			if err != nil {
				err = fmt.Errorf("bulk packet handoff lane %d: %w", lane, err)
			}
			results <- externalV2BulkPacketHandoffLaneResult{datagrams: count, err: err}
		}()
	}

	var errs []error
	for range path.Conns {
		laneResult := <-results
		result.Datagrams += laneResult.datagrams
		errs = append(errs, laneResult.err)
	}
	if err := clearExternalV2BulkPacketDeadlines(path); err != nil {
		errs = append(errs, fmt.Errorf("restore deadlines: %w", err))
	}
	result.Duration = time.Since(started)
	return result, errors.Join(errs...)
}

func drainExternalV2BulkPacketHandoffLane(
	drainCtx context.Context,
	quietWindow time.Duration,
	conn externalV2BulkPacketBatchConn,
) (uint64, error) {
	var datagrams uint64
	for {
		if err := drainCtx.Err(); err != nil {
			return datagrams, fmt.Errorf("hard deadline: %w", err)
		}

		quietCtx, cancel := context.WithTimeout(drainCtx, quietWindow)
		messages := newExternalV2BulkPacketReadMessages()
		count, err := conn.ReadBatch(quietCtx, messages)
		cancel()
		if count < 0 || count > len(messages) {
			return datagrams, fmt.Errorf("read queued datagrams: invalid bulk packet batch read count %d for %d messages", count, len(messages))
		}
		datagrams += uint64(count)

		if drainErr := drainCtx.Err(); drainErr != nil {
			return datagrams, fmt.Errorf("hard deadline: %w", drainErr)
		}
		if count == 0 && errors.Is(err, context.DeadlineExceeded) {
			return datagrams, nil
		}
		if err != nil {
			return datagrams, fmt.Errorf("read queued datagrams: %w", err)
		}
		if count == 0 {
			return datagrams, fmt.Errorf("read queued datagrams: %w", io.ErrNoProgress)
		}
	}
}
