// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"fmt"
	"time"
)

const (
	externalV2BulkPhaseProbeEnd    = "probe-end"
	externalV2BulkPhaseProbeResult = "probe-result"
)

type externalV2BulkProbeControl struct {
	Train    int    `json:"train"`
	RateMbps int    `json:"rate_mbps"`
	Sent     uint32 `json:"sent"`
	Received uint32 `json:"received"`
	Pressure bool   `json:"pressure"`
	Final    bool   `json:"final"`
}

func externalV2BulkControlIsProbe(message externalV2BulkControl) bool {
	return message.Phase == externalV2BulkPhaseProbeEnd || message.Phase == externalV2BulkPhaseProbeResult
}

func externalV2BulkControlsEqual(a, b externalV2BulkControl) bool {
	if a.Protocol != b.Protocol || a.Phase != b.Phase || a.ProbeRunID != b.ProbeRunID ||
		a.Mode != b.Mode || a.SelectedMbps != b.SelectedMbps || a.Reason != b.Reason {
		return false
	}
	if a.Probe == nil || b.Probe == nil {
		return a.Probe == nil && b.Probe == nil
	}
	return *a.Probe == *b.Probe
}

func externalV2BulkProbeControlValid(message externalV2BulkControl) bool {
	probe := message.Probe
	if probe == nil || !externalV2BulkProbeMessageEnvelopeValid(message) || !externalV2BulkProbeTrainValid(probe) {
		return false
	}
	expected := externalV2BulkPacketProbeDatagramCount(probe.RateMbps)
	if probe.Sent > expected || (!probe.Pressure && probe.Sent != expected) {
		return false
	}
	last := probe.Train == len(externalV2BulkPacketProbeRatesMbps)-1
	return externalV2BulkProbePhaseValid(message.Phase, probe, last)
}

func externalV2BulkProbePhaseValid(phase string, probe *externalV2BulkProbeControl, last bool) bool {
	switch phase {
	case externalV2BulkPhaseProbeEnd:
		return probe.Received == 0 && probe.Final == (probe.Pressure || last)
	case externalV2BulkPhaseProbeResult:
		dirty := probe.Sent == 0 || uint64(probe.Received)*100 < uint64(probe.Sent)*95
		return probe.Final == (probe.Pressure || dirty || last)
	default:
		return false
	}
}

func externalV2BulkProbeMessageEnvelopeValid(message externalV2BulkControl) bool {
	return message.ProbeRunID != 0 && message.Mode == externalV2BulkModeBulk &&
		message.SelectedMbps == 0 && message.Reason == ""
}

func externalV2BulkProbeTrainValid(probe *externalV2BulkProbeControl) bool {
	if probe.Train < 0 || probe.Train >= len(externalV2BulkPacketProbeRatesMbps) {
		return false
	}
	return probe.RateMbps == externalV2BulkPacketProbeRatesMbps[probe.Train] && probe.Received <= probe.Sent
}

func (c *externalV2BulkDecisionCoordinator) probeControlEvents() <-chan externalV2BulkControlEvent {
	return c.probeEvents
}

func (c *externalV2BulkDecisionCoordinator) sendProbeResult(ctx context.Context, result externalV2BulkControl) error {
	if result.Phase != externalV2BulkPhaseProbeResult {
		return fmt.Errorf("%w: expected probe result, got %s", errExternalV2BulkDecisionProtocol, result.Phase)
	}
	if err := validateExternalV2BulkControl(result); err != nil {
		return err
	}
	return c.send(ctx, result)
}

func (c *externalV2BulkDecisionCoordinator) sendProbeEndAndWaitResult(
	ctx context.Context,
	end externalV2BulkControl,
) (externalV2BulkControl, error) {
	if end.Phase != externalV2BulkPhaseProbeEnd {
		return externalV2BulkControl{}, fmt.Errorf("%w: expected probe end, got %s", errExternalV2BulkDecisionProtocol, end.Phase)
	}
	if err := validateExternalV2BulkControl(end); err != nil {
		return externalV2BulkControl{}, err
	}
	if err := c.send(ctx, end); err != nil {
		return externalV2BulkControl{}, err
	}
	ticker := time.NewTicker(c.retry)
	defer ticker.Stop()
	for {
		message, matched, err := c.waitForProbeResultStep(ctx, ticker.C, end)
		if err != nil {
			return externalV2BulkControl{}, err
		}
		if matched {
			return message, nil
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) waitForProbeResultStep(
	ctx context.Context,
	retry <-chan time.Time,
	end externalV2BulkControl,
) (externalV2BulkControl, bool, error) {
	select {
	case <-ctx.Done():
		return externalV2BulkControl{}, false, externalV2BulkContextError(ctx)
	case <-c.agreementCtx.Done():
		return externalV2BulkControl{}, false, externalV2BulkContextError(c.agreementCtx)
	case <-retry:
		return externalV2BulkControl{}, false, c.send(ctx, end)
	case event, ok := <-c.probeEvents:
		message, err := externalV2BulkControlFromEvent(event, ok)
		if err != nil {
			return externalV2BulkControl{}, false, err
		}
		matched, err := c.acceptProbeResult(end, message)
		return message, matched, err
	}
}

func (c *externalV2BulkDecisionCoordinator) acceptProbeResult(end, result externalV2BulkControl) (bool, error) {
	if result.Phase != externalV2BulkPhaseProbeResult || result.Probe == nil {
		return false, fmt.Errorf("%w: expected probe result", errExternalV2BulkDecisionProtocol)
	}
	want := end.Probe
	got := result.Probe
	if result.ProbeRunID != end.ProbeRunID {
		return false, fmt.Errorf("%w: probe result run ID %d does not match %d", errExternalV2BulkDecisionProtocol, result.ProbeRunID, end.ProbeRunID)
	}
	if got.Train < want.Train {
		return c.acceptPriorProbeResult(result)
	}
	if !externalV2BulkProbeResultMatchesBoundary(want, got) {
		return false, fmt.Errorf("%w: probe result does not match train boundary", errExternalV2BulkDecisionProtocol)
	}
	if c.probeResultContradictsPrevious(result) {
		return false, fmt.Errorf("%w: contradictory probe result for train %d", errExternalV2BulkDecisionProtocol, got.Train)
	}
	c.probeResults[got.Train] = result
	return true, nil
}

func (c *externalV2BulkDecisionCoordinator) acceptPriorProbeResult(result externalV2BulkControl) (bool, error) {
	previous, ok := c.probeResults[result.Probe.Train]
	if !ok || !externalV2BulkControlsEqual(previous, result) {
		return false, fmt.Errorf("%w: contradictory probe result for train %d", errExternalV2BulkDecisionProtocol, result.Probe.Train)
	}
	return false, nil
}

func externalV2BulkProbeResultMatchesBoundary(want, got *externalV2BulkProbeControl) bool {
	return got.Train == want.Train && got.RateMbps == want.RateMbps &&
		got.Sent == want.Sent && got.Pressure == want.Pressure
}

func (c *externalV2BulkDecisionCoordinator) probeResultContradictsPrevious(result externalV2BulkControl) bool {
	previous, ok := c.probeResults[result.Probe.Train]
	return ok && !externalV2BulkControlsEqual(previous, result)
}

func (c *externalV2BulkDecisionCoordinator) respondToDuplicateProbeEnds(end, result externalV2BulkControl) {
	go func() {
		for {
			select {
			case <-c.agreementCtx.Done():
				return
			case event, ok := <-c.probeEvents:
				message, err := externalV2BulkControlFromEvent(event, ok)
				if err != nil {
					c.fail(err)
					return
				}
				if !externalV2BulkControlsEqual(message, end) {
					c.fail(fmt.Errorf("%w: probe boundary changed after final result", errExternalV2BulkDecisionProtocol))
					return
				}
				if err := c.sendProbeResult(c.agreementCtx, result); err != nil {
					if c.agreementCtx.Err() == nil {
						c.fail(err)
					}
					return
				}
			}
		}
	}()
}
