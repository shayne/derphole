// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/types/key"
)

const (
	externalV2BulkPhaseReady                  = "ready"
	externalV2BulkPhaseDecision               = "decision"
	externalV2BulkPhaseAck                    = "ack"
	externalV2BulkModeBulk                    = externalV2TransferModeBulkPackets
	externalV2BulkModeQUIC                    = "quic"
	externalV2BulkReasonProbeAccepted         = "probe-accepted"
	externalV2BulkReasonSenderProbeRejected   = "sender-probe-rejected"
	externalV2BulkReasonReceiverProbeRejected = "receiver-probe-rejected"
	externalV2BulkReasonReadinessTimeout      = "receiver-readiness-timeout"
	externalV2BulkReasonBothAccepted          = "both-probes-accepted"
)

const (
	externalV2BulkDecisionReadyWait = 5 * time.Second
	externalV2BulkDecisionRetry     = 250 * time.Millisecond
)

var externalV2BulkDecisionBarrierWait = 10 * time.Second

var errExternalV2BulkDecisionProtocol = errors.New("bulk decision protocol error")

type externalV2BulkControl struct {
	Protocol     string                      `json:"protocol"`
	Phase        string                      `json:"phase"`
	ProbeRunID   uint64                      `json:"probe_run_id"`
	Mode         string                      `json:"mode"`
	SelectedMbps int                         `json:"selected_mbps,omitempty"`
	Reason       string                      `json:"reason,omitempty"`
	Probe        *externalV2BulkProbeControl `json:"probe,omitempty"`
}

type externalV2BulkDecision struct {
	Mode         string
	ProbeRunID   uint64
	SelectedMbps int
	Reason       string
}

type externalV2BulkControlEvent struct {
	Control externalV2BulkControl
	Err     error
}

type externalV2BulkControlWire interface {
	Send(context.Context, externalV2BulkControl) error
	Events() <-chan externalV2BulkControlEvent
	Close()
}

type externalV2BulkDERPControlWire struct {
	ctx         context.Context
	cancel      context.CancelFunc
	client      *derpbind.Client
	peerDERP    key.NodePublic
	auth        externalPeerControlAuth
	events      chan externalV2BulkControlEvent
	unsubscribe func()
	closeOnce   sync.Once
}

func newExternalV2BulkDERPControlWire(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	auth externalPeerControlAuth,
) externalV2BulkControlWire {
	wireCtx, cancel := context.WithCancel(ctx)
	packets, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isV2BulkControlPayload(pkt.Payload)
	})
	wire := &externalV2BulkDERPControlWire{
		ctx: wireCtx, cancel: cancel, client: client, peerDERP: peerDERP, auth: auth,
		events: make(chan externalV2BulkControlEvent, 16), unsubscribe: unsubscribe,
	}
	go wire.readLoop(packets)
	return wire
}

func (w *externalV2BulkDERPControlWire) Send(ctx context.Context, message externalV2BulkControl) error {
	if err := ctx.Err(); err != nil {
		return externalV2BulkContextError(ctx)
	}
	return sendAuthenticatedEnvelope(ctx, w.client, w.peerDERP, envelope{Type: envelopeV2BulkControl, V2BulkControl: &message}, w.auth)
}

func (w *externalV2BulkDERPControlWire) Events() <-chan externalV2BulkControlEvent {
	return w.events
}

func (w *externalV2BulkDERPControlWire) Close() {
	w.closeOnce.Do(func() {
		w.cancel()
		w.unsubscribe()
	})
}

func (w *externalV2BulkDERPControlWire) readLoop(packets <-chan derpbind.Packet) {
	for {
		select {
		case <-w.ctx.Done():
			return
		case pkt, ok := <-packets:
			if !ok {
				if w.ctx.Err() != nil {
					return
				}
				w.reportTerminal(ErrPeerDisconnected)
				return
			}
			message, ok, err := externalV2BulkControlFromPayload(pkt.Payload, w.auth)
			if err != nil {
				w.reportTerminal(err)
				return
			}
			if !ok {
				continue
			}
			select {
			case w.events <- externalV2BulkControlEvent{Control: message}:
			case <-w.ctx.Done():
				return
			}
		}
	}
}

func (w *externalV2BulkDERPControlWire) reportTerminal(err error) {
	event := externalV2BulkControlEvent{Err: err}
	for {
		select {
		case w.events <- event:
			return
		case <-w.events:
		case <-w.ctx.Done():
			return
		}
	}
}

type externalV2BulkDecisionCoordinator struct {
	ctx             context.Context
	agreementCtx    context.Context
	cancel          context.CancelCauseFunc
	agreementCancel context.CancelFunc
	wire            externalV2BulkControlWire
	emitter         *telemetry.Emitter
	retry           time.Duration
	readyWait       time.Duration
	probeEvents     chan externalV2BulkControlEvent
	decisionEvents  chan externalV2BulkControlEvent
	probeResults    map[int]externalV2BulkControl
	closeOnce       sync.Once
	wireCloseOnce   sync.Once
}

func newExternalV2BulkDecisionCoordinator(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth, emitter *telemetry.Emitter) *externalV2BulkDecisionCoordinator {
	transferCtx, agreementCtx, cancel, agreementCancel := newExternalV2BulkDecisionContexts(ctx, externalV2BulkDecisionBarrierWait)
	c := &externalV2BulkDecisionCoordinator{
		ctx: transferCtx, agreementCtx: agreementCtx, cancel: cancel, agreementCancel: agreementCancel,
		wire:    newExternalV2BulkDERPControlWire(agreementCtx, client, peerDERP, auth),
		emitter: emitter, retry: externalV2BulkDecisionRetry,
		readyWait: externalV2BulkDecisionReadyWait,
	}
	c.startControlRouter()
	c.closeWireWhenDone(agreementCtx)
	return c
}

func newExternalV2BulkDecisionCoordinatorWithWireAndBarrier(ctx context.Context, wire externalV2BulkControlWire, emitter *telemetry.Emitter, barrierWait time.Duration) *externalV2BulkDecisionCoordinator {
	transferCtx, agreementCtx, cancel, agreementCancel := newExternalV2BulkDecisionContexts(ctx, barrierWait)
	c := &externalV2BulkDecisionCoordinator{
		ctx: transferCtx, agreementCtx: agreementCtx, cancel: cancel, agreementCancel: agreementCancel,
		wire: wire, emitter: emitter,
		retry: externalV2BulkDecisionRetry, readyWait: externalV2BulkDecisionReadyWait,
	}
	c.startControlRouter()
	c.closeWireWhenDone(agreementCtx)
	return c
}

func newExternalV2BulkDecisionContexts(ctx context.Context, barrierWait time.Duration) (context.Context, context.Context, context.CancelCauseFunc, context.CancelFunc) {
	transferCtx, cancel := context.WithCancelCause(ctx)
	agreementCtx, agreementCancel := context.WithTimeoutCause(transferCtx, barrierWait, context.DeadlineExceeded)
	return transferCtx, agreementCtx, cancel, agreementCancel
}

func (c *externalV2BulkDecisionCoordinator) Context() context.Context {
	return c.ctx
}

func (c *externalV2BulkDecisionCoordinator) Close() {
	c.closeOnce.Do(func() {
		c.cancel(context.Canceled)
		c.agreementCancel()
		c.closeWire()
	})
}

func (c *externalV2BulkDecisionCoordinator) closeWireWhenDone(ctx context.Context) {
	context.AfterFunc(ctx, c.closeWire)
}

func (c *externalV2BulkDecisionCoordinator) closeWire() {
	c.wireCloseOnce.Do(c.wire.Close)
}

func (c *externalV2BulkDecisionCoordinator) startControlRouter() {
	c.probeEvents = make(chan externalV2BulkControlEvent, 64)
	c.decisionEvents = make(chan externalV2BulkControlEvent, 16)
	c.probeResults = make(map[int]externalV2BulkControl, len(externalV2BulkPacketProbeRatesMbps))
	go c.routeControlEvents()
}

func (c *externalV2BulkDecisionCoordinator) routeControlEvents() {
	for {
		select {
		case <-c.agreementCtx.Done():
			return
		case event, ok := <-c.wire.Events():
			if !ok {
				c.deliverControlTerminal(externalV2BulkControlEvent{Err: ErrPeerDisconnected})
				return
			}
			if event.Err != nil {
				c.deliverControlTerminal(event)
				return
			}
			if err := validateExternalV2BulkControl(event.Control); err != nil {
				c.deliverControlTerminal(externalV2BulkControlEvent{Err: err})
				return
			}
			target := c.decisionEvents
			if externalV2BulkControlIsProbe(event.Control) {
				target = c.probeEvents
			}
			select {
			case target <- event:
			case <-c.agreementCtx.Done():
				return
			}
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) deliverControlTerminal(event externalV2BulkControlEvent) {
	for _, target := range []chan externalV2BulkControlEvent{c.probeEvents, c.decisionEvents} {
		select {
		case target <- event:
		case <-c.agreementCtx.Done():
			return
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) ResolveSender(
	ctx context.Context,
	runID uint64,
	probeResult externalV2BulkPacketProbeResult,
	probeErr error,
) (externalV2BulkDecision, error) {
	if err := validateExternalV2BulkSenderProbe(runID, probeResult, probeErr); err != nil {
		return externalV2BulkDecision{}, err
	}
	if probeFailure := externalV2BulkPacketProbeDecisionFailure(probeErr, false); probeFailure != nil {
		return externalV2BulkDecision{}, probeFailure
	}
	roleCtx, cancel := c.roleContext(ctx)
	defer cancel()

	decision, readiness, err := c.selectSenderDecision(roleCtx, runID, probeResult.SelectedMbps, probeErr)
	if err != nil {
		return externalV2BulkDecision{}, err
	}
	if err := validateExternalV2BulkControl(decision.control(externalV2BulkPhaseDecision)); err != nil {
		return externalV2BulkDecision{}, err
	}
	emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseDecision, decision.control(externalV2BulkPhaseDecision))
	return c.publishDecision(roleCtx, decision, readiness)
}

func validateExternalV2BulkSenderProbe(runID uint64, probeResult externalV2BulkPacketProbeResult, probeErr error) error {
	if runID == 0 {
		return fmt.Errorf("%w: zero sender run ID", errExternalV2BulkDecisionProtocol)
	}
	if probeErr == nil && probeResult.RunID != runID {
		return fmt.Errorf("%w: sender probe run ID %d does not match %d", errExternalV2BulkDecisionProtocol, probeResult.RunID, runID)
	}
	return nil
}

func (c *externalV2BulkDecisionCoordinator) selectSenderDecision(
	ctx context.Context,
	runID uint64,
	selectedMbps int,
	probeErr error,
) (externalV2BulkDecision, *externalV2BulkControl, error) {
	if probeErr != nil {
		return externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: runID, Reason: externalV2BulkReasonSenderProbeRejected}, nil, nil
	}
	ready, timedOut, err := c.waitForReadiness(ctx, runID)
	if err != nil {
		return externalV2BulkDecision{}, nil, err
	}
	decision := externalV2BulkSenderDecisionFromReadiness(runID, selectedMbps, ready, timedOut)
	if timedOut {
		return decision, nil, nil
	}
	return decision, &ready, nil
}

func externalV2BulkSenderDecisionFromReadiness(runID uint64, selectedMbps int, ready externalV2BulkControl, timedOut bool) externalV2BulkDecision {
	switch {
	case timedOut:
		return externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: runID, Reason: externalV2BulkReasonReadinessTimeout}
	case ready.Mode == externalV2BulkModeQUIC:
		return externalV2BulkDecision{Mode: externalV2BulkModeQUIC, ProbeRunID: runID, Reason: externalV2BulkReasonReceiverProbeRejected}
	default:
		return externalV2BulkDecision{
			Mode: externalV2BulkModeBulk, ProbeRunID: runID,
			SelectedMbps: min(selectedMbps, ready.SelectedMbps),
			Reason:       externalV2BulkReasonBothAccepted,
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) waitForReadiness(ctx context.Context, runID uint64) (externalV2BulkControl, bool, error) {
	timer := time.NewTimer(c.readyWait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return externalV2BulkControl{}, false, externalV2BulkContextError(ctx)
		case <-timer.C:
			return externalV2BulkControl{}, true, nil
		case event, ok := <-c.decisionEvents:
			message, err := externalV2BulkControlFromEvent(event, ok)
			if err != nil {
				return externalV2BulkControl{}, false, err
			}
			if message.Phase != externalV2BulkPhaseReady {
				return externalV2BulkControl{}, false, fmt.Errorf("%w: expected readiness, got %s", errExternalV2BulkDecisionProtocol, message.Phase)
			}
			if message.ProbeRunID != 0 && message.ProbeRunID != runID {
				return externalV2BulkControl{}, false, fmt.Errorf("%w: readiness run ID %d does not match %d", errExternalV2BulkDecisionProtocol, message.ProbeRunID, runID)
			}
			emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseReady, message)
			return message, false, nil
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) publishDecision(ctx context.Context, decision externalV2BulkDecision, readiness *externalV2BulkControl) (externalV2BulkDecision, error) {
	message := decision.control(externalV2BulkPhaseDecision)
	wantAck := decision.control(externalV2BulkPhaseAck)
	if err := c.send(ctx, message); err != nil {
		return externalV2BulkDecision{}, err
	}
	ticker := time.NewTicker(c.retry)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return externalV2BulkDecision{}, externalV2BulkContextError(ctx)
		case <-ticker.C:
			if err := c.send(ctx, message); err != nil {
				return externalV2BulkDecision{}, err
			}
		case event, ok := <-c.decisionEvents:
			acknowledged, nextReadiness, err := c.consumePublishedDecisionEvent(event, ok, decision, wantAck, readiness)
			if err != nil {
				return externalV2BulkDecision{}, err
			}
			if acknowledged {
				return decision, nil
			}
			readiness = nextReadiness
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) consumePublishedDecisionEvent(
	event externalV2BulkControlEvent,
	ok bool,
	decision externalV2BulkDecision,
	wantAck externalV2BulkControl,
	readiness *externalV2BulkControl,
) (bool, *externalV2BulkControl, error) {
	control, err := externalV2BulkControlFromEvent(event, ok)
	if err != nil {
		return false, readiness, err
	}
	switch control.Phase {
	case externalV2BulkPhaseAck:
		if control != wantAck {
			return false, readiness, fmt.Errorf("%w: acknowledgement does not match decision", errExternalV2BulkDecisionProtocol)
		}
		emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseAck, control)
		return true, readiness, nil
	case externalV2BulkPhaseReady:
		nextReadiness, err := c.acceptPublishedDecisionReadiness(control, decision, readiness)
		return false, nextReadiness, err
	default:
		return false, readiness, fmt.Errorf("%w: expected acknowledgement, got %s", errExternalV2BulkDecisionProtocol, control.Phase)
	}
}

func (c *externalV2BulkDecisionCoordinator) acceptPublishedDecisionReadiness(
	control externalV2BulkControl,
	decision externalV2BulkDecision,
	readiness *externalV2BulkControl,
) (*externalV2BulkControl, error) {
	if control.ProbeRunID != 0 && control.ProbeRunID != decision.ProbeRunID {
		return readiness, fmt.Errorf("%w: readiness run ID %d does not match decision", errExternalV2BulkDecisionProtocol, control.ProbeRunID)
	}
	if readiness != nil && control != *readiness {
		return readiness, fmt.Errorf("%w: contradictory readiness", errExternalV2BulkDecisionProtocol)
	}
	if readiness == nil {
		emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseReady, control)
		return &control, nil
	}
	return readiness, nil
}

type externalV2BulkProbeOutcome struct {
	result externalV2BulkPacketProbeResult
	err    error
}

func externalV2BulkPacketProbeDecisionFailure(err error, allowCanceled bool) error {
	if err == nil || externalV2BulkPacketProbeOrdinaryRejection(err) {
		return nil
	}
	if allowCanceled && externalV2BulkPacketProbeCoordinatorCancellation(err) {
		return nil
	}
	return err
}

func externalV2BulkPacketProbeCoordinatorCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	errs := joined.Unwrap()
	return len(errs) == 2 && errs[0] == errExternalV2BulkPacketProbeRejected && errs[1] == context.Canceled
}

func (c *externalV2BulkDecisionCoordinator) ResolveReceiver(
	ctx context.Context,
	probe func(context.Context) (externalV2BulkPacketProbeResult, error),
) (probeResult externalV2BulkPacketProbeResult, decision externalV2BulkDecision, probeCleanupErr, decisionErr error) {
	roleCtx, cancel := c.roleContext(ctx)
	defer cancel()
	probeCtx, cancelProbe := context.WithCancel(roleCtx)
	probeCh := make(chan externalV2BulkProbeOutcome, 1)
	go func() {
		result, err := probe(probeCtx)
		probeCh <- externalV2BulkProbeOutcome{result: result, err: err}
	}()

	outcome, earlyDecision, err := c.awaitReceiverProbe(roleCtx, probeCh, cancelProbe)
	probeCleanupErr = externalV2BulkPacketProbeCleanupFailure(outcome.err)
	if err != nil {
		return outcome.result, externalV2BulkDecision{}, probeCleanupErr, err
	}
	if earlyDecision != nil {
		return outcome.result, *earlyDecision, probeCleanupErr, nil
	}
	return c.resolveReceiverAfterProbe(roleCtx, outcome)
}

func (c *externalV2BulkDecisionCoordinator) awaitReceiverProbe(
	roleCtx context.Context,
	probeCh <-chan externalV2BulkProbeOutcome,
	cancelProbe context.CancelFunc,
) (externalV2BulkProbeOutcome, *externalV2BulkDecision, error) {
	var outcome externalV2BulkProbeOutcome
	for {
		select {
		case <-roleCtx.Done():
			cancelProbe()
			outcome = <-probeCh
			return outcome, nil, externalV2BulkContextError(roleCtx)
		case outcome = <-probeCh:
			cancelProbe()
			return outcome, nil, nil
		case event, ok := <-c.decisionEvents:
			return c.resolveReceiverDecisionDuringProbe(roleCtx, event, ok, probeCh, cancelProbe)
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) resolveReceiverDecisionDuringProbe(
	roleCtx context.Context,
	event externalV2BulkControlEvent,
	ok bool,
	probeCh <-chan externalV2BulkProbeOutcome,
	cancelProbe context.CancelFunc,
) (externalV2BulkProbeOutcome, *externalV2BulkDecision, error) {
	message, err := externalV2BulkControlFromEvent(event, ok)
	if err != nil {
		cancelProbe()
		return <-probeCh, nil, err
	}
	if message.Phase != externalV2BulkPhaseDecision || message.Mode != externalV2BulkModeQUIC {
		cancelProbe()
		return <-probeCh, nil, fmt.Errorf("%w: only QUIC decision is valid while probing", errExternalV2BulkDecisionProtocol)
	}
	cancelProbe()
	outcome := <-probeCh
	if probeFailure := externalV2BulkPacketProbeDecisionFailure(outcome.err, true); probeFailure != nil {
		return outcome, nil, probeFailure
	}
	if outcome.result.RunID != 0 && outcome.result.RunID != message.ProbeRunID {
		return outcome, nil, fmt.Errorf("%w: probe run ID %d does not match decision %d", errExternalV2BulkDecisionProtocol, outcome.result.RunID, message.ProbeRunID)
	}
	decision := externalV2BulkDecisionFromControl(message)
	emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseDecision, message)
	if err := c.acknowledgeDecision(roleCtx, decision); err != nil {
		return outcome, nil, err
	}
	return outcome, &decision, nil
}

func (c *externalV2BulkDecisionCoordinator) resolveReceiverAfterProbe(
	roleCtx context.Context,
	outcome externalV2BulkProbeOutcome,
) (externalV2BulkPacketProbeResult, externalV2BulkDecision, error, error) {
	probeCleanupErr := externalV2BulkPacketProbeCleanupFailure(outcome.err)
	if probeFailure := externalV2BulkPacketProbeDecisionFailure(outcome.err, false); probeFailure != nil {
		return outcome.result, externalV2BulkDecision{}, probeCleanupErr, probeFailure
	}
	readiness := externalV2BulkControl{
		Protocol: externalV2Protocol, Phase: externalV2BulkPhaseReady,
		ProbeRunID: outcome.result.RunID, Mode: externalV2BulkModeBulk,
		SelectedMbps: outcome.result.SelectedMbps, Reason: externalV2BulkReasonProbeAccepted,
	}
	if outcome.err != nil {
		readiness.Mode = externalV2BulkModeQUIC
		readiness.SelectedMbps = 0
		readiness.Reason = externalV2BulkReasonReceiverProbeRejected
	}
	if err := validateExternalV2BulkControl(readiness); err != nil {
		return outcome.result, externalV2BulkDecision{}, probeCleanupErr, err
	}
	emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseReady, readiness)
	if err := c.send(roleCtx, readiness); err != nil {
		return outcome.result, externalV2BulkDecision{}, probeCleanupErr, err
	}
	decision, err := c.waitForReceiverDecision(roleCtx, readiness)
	return outcome.result, decision, probeCleanupErr, err
}

func (c *externalV2BulkDecisionCoordinator) waitForReceiverDecision(
	roleCtx context.Context,
	readiness externalV2BulkControl,
) (externalV2BulkDecision, error) {
	ticker := time.NewTicker(c.retry)
	defer ticker.Stop()
	for {
		select {
		case <-roleCtx.Done():
			return externalV2BulkDecision{}, externalV2BulkContextError(roleCtx)
		case <-ticker.C:
			if err := c.send(roleCtx, readiness); err != nil {
				return externalV2BulkDecision{}, err
			}
		case event, ok := <-c.decisionEvents:
			message, err := externalV2BulkControlFromEvent(event, ok)
			if err != nil {
				return externalV2BulkDecision{}, err
			}
			if err := validateExternalV2BulkReceiverDecision(readiness, message); err != nil {
				return externalV2BulkDecision{}, err
			}
			decision := externalV2BulkDecisionFromControl(message)
			emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseDecision, message)
			if err := c.acknowledgeDecision(roleCtx, decision); err != nil {
				return externalV2BulkDecision{}, err
			}
			return decision, nil
		}
	}
}

func validateExternalV2BulkReceiverDecision(readiness, message externalV2BulkControl) error {
	if message.Phase != externalV2BulkPhaseDecision {
		return fmt.Errorf("%w: expected decision, got %s", errExternalV2BulkDecisionProtocol, message.Phase)
	}
	if readiness.ProbeRunID != 0 && message.ProbeRunID != readiness.ProbeRunID {
		return fmt.Errorf("%w: readiness run ID %d does not match decision %d", errExternalV2BulkDecisionProtocol, readiness.ProbeRunID, message.ProbeRunID)
	}
	if message.Mode == externalV2BulkModeBulk && (readiness.Mode != externalV2BulkModeBulk || readiness.ProbeRunID == 0 || message.ProbeRunID != readiness.ProbeRunID) {
		return fmt.Errorf("%w: bulk decision without matching bulk readiness", errExternalV2BulkDecisionProtocol)
	}
	return nil
}

func (c *externalV2BulkDecisionCoordinator) acknowledgeDecision(ctx context.Context, decision externalV2BulkDecision) error {
	ack := decision.control(externalV2BulkPhaseAck)
	if err := c.send(ctx, ack); err != nil {
		return err
	}
	emitExternalV2BulkTransition(c.emitter, externalV2BulkPhaseAck, ack)
	want := decision.control(externalV2BulkPhaseDecision)
	for {
		select {
		case event, ok := <-c.decisionEvents:
			message, err := externalV2BulkControlFromEvent(event, ok)
			if err != nil {
				return err
			}
			if message != want {
				return fmt.Errorf("%w: second decision differs from first", errExternalV2BulkDecisionProtocol)
			}
			if err := c.send(ctx, ack); err != nil {
				return err
			}
		default:
			go c.respondToDuplicateDecisions(decision)
			return nil
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) respondToDuplicateDecisions(decision externalV2BulkDecision) {
	ctx := c.agreementCtx
	want := decision.control(externalV2BulkPhaseDecision)
	ack := decision.control(externalV2BulkPhaseAck)
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-c.decisionEvents:
			if ctx.Err() != nil {
				return
			}
			message, err := externalV2BulkControlFromEvent(event, ok)
			if err != nil {
				c.fail(err)
				return
			}
			if message != want {
				c.fail(fmt.Errorf("%w: second decision differs from first", errExternalV2BulkDecisionProtocol))
				return
			}
			if err := c.send(ctx, ack); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.fail(err)
				return
			}
		}
	}
}

func (c *externalV2BulkDecisionCoordinator) roleContext(ctx context.Context) (context.Context, context.CancelFunc) {
	roleCtx, cancelCause := context.WithCancelCause(c.agreementCtx)
	stop := context.AfterFunc(ctx, func() {
		cancelCause(context.Cause(ctx))
	})
	return roleCtx, func() {
		stop()
		cancelCause(context.Canceled)
	}
}

func (c *externalV2BulkDecisionCoordinator) send(ctx context.Context, message externalV2BulkControl) error {
	if err := ctx.Err(); err != nil {
		return externalV2BulkContextError(ctx)
	}
	return c.wire.Send(ctx, message)
}

func (c *externalV2BulkDecisionCoordinator) fail(err error) {
	if err == nil {
		err = context.Canceled
	}
	c.cancel(err)
	c.agreementCancel()
}

func externalV2BulkContextError(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func externalV2BulkControlFromEvent(event externalV2BulkControlEvent, ok bool) (externalV2BulkControl, error) {
	if !ok {
		return externalV2BulkControl{}, ErrPeerDisconnected
	}
	if event.Err != nil {
		return externalV2BulkControl{}, event.Err
	}
	if err := validateExternalV2BulkControl(event.Control); err != nil {
		return externalV2BulkControl{}, err
	}
	return event.Control, nil
}

func externalV2BulkDecisionFromControl(message externalV2BulkControl) externalV2BulkDecision {
	return externalV2BulkDecision{
		Mode: message.Mode, ProbeRunID: message.ProbeRunID,
		SelectedMbps: message.SelectedMbps, Reason: message.Reason,
	}
}

func emitExternalV2BulkTransition(emitter *telemetry.Emitter, phase string, message externalV2BulkControl) {
	transition := phase
	if phase == externalV2BulkPhaseAck {
		transition = "decision-ack"
	}
	emitExternalV2Debug(emitter, fmt.Sprintf(
		"v2-bulk-%s=mode:%s run_id:%d selected_mbps:%d reason:%s",
		transition, message.Mode, message.ProbeRunID, message.SelectedMbps, message.Reason,
	))
}

func (d externalV2BulkDecision) control(phase string) externalV2BulkControl {
	return externalV2BulkControl{Protocol: externalV2Protocol, Phase: phase, ProbeRunID: d.ProbeRunID, Mode: d.Mode, SelectedMbps: d.SelectedMbps, Reason: d.Reason}
}

func validateExternalV2BulkControl(message externalV2BulkControl) error {
	if err := validateExternalV2BulkControlHeader(message); err != nil {
		return err
	}
	if externalV2BulkControlIsProbe(message) {
		if !externalV2BulkProbeControlValid(message) {
			return fmt.Errorf("%w: invalid probe control", errExternalV2BulkDecisionProtocol)
		}
		return nil
	}
	if message.Probe != nil {
		return fmt.Errorf("%w: probe fields on %s", errExternalV2BulkDecisionProtocol, message.Phase)
	}
	if err := validateExternalV2BulkControlMode(message); err != nil {
		return err
	}
	return validateExternalV2BulkControlReason(message)
}

func validateExternalV2BulkControlHeader(message externalV2BulkControl) error {
	if message.Protocol != externalV2Protocol {
		return fmt.Errorf("%w: protocol %q", errExternalV2BulkDecisionProtocol, message.Protocol)
	}
	if !externalV2BulkControlPhaseValid(message.Phase) {
		return fmt.Errorf("%w: phase %q", errExternalV2BulkDecisionProtocol, message.Phase)
	}
	if !externalV2BulkControlModeValid(message.Mode) {
		return fmt.Errorf("%w: mode %q", errExternalV2BulkDecisionProtocol, message.Mode)
	}
	if message.Phase != externalV2BulkPhaseReady && message.ProbeRunID == 0 {
		return fmt.Errorf("%w: zero run ID", errExternalV2BulkDecisionProtocol)
	}
	return nil
}

func externalV2BulkControlPhaseValid(phase string) bool {
	switch phase {
	case externalV2BulkPhaseReady, externalV2BulkPhaseDecision, externalV2BulkPhaseAck,
		externalV2BulkPhaseProbeEnd, externalV2BulkPhaseProbeResult:
		return true
	default:
		return false
	}
}

func externalV2BulkControlModeValid(mode string) bool {
	return mode == externalV2BulkModeBulk || mode == externalV2BulkModeQUIC
}

func validateExternalV2BulkControlMode(message externalV2BulkControl) error {
	if message.Mode == externalV2BulkModeBulk {
		if message.ProbeRunID == 0 || message.SelectedMbps < externalV2BulkPacketMinimumWireMbps || message.SelectedMbps > externalV2BulkPacketCeilingWireMbps {
			return fmt.Errorf("%w: invalid bulk run/rate", errExternalV2BulkDecisionProtocol)
		}
	} else if message.SelectedMbps != 0 {
		return fmt.Errorf("%w: QUIC rate %d", errExternalV2BulkDecisionProtocol, message.SelectedMbps)
	}
	return nil
}

func validateExternalV2BulkControlReason(message externalV2BulkControl) error {
	if message.Phase == externalV2BulkPhaseReady {
		valid := message.Mode == externalV2BulkModeBulk && message.Reason == externalV2BulkReasonProbeAccepted ||
			message.Mode == externalV2BulkModeQUIC && message.Reason == externalV2BulkReasonReceiverProbeRejected
		if !valid {
			return fmt.Errorf("%w: readiness reason %q", errExternalV2BulkDecisionProtocol, message.Reason)
		}
		return nil
	}
	phase := "decision"
	if message.Phase == externalV2BulkPhaseAck {
		phase = "acknowledgement"
	}
	if !externalV2BulkDecisionReasonValid(message.Mode, message.Reason) {
		return fmt.Errorf("%w: %s reason %q is invalid for %s", errExternalV2BulkDecisionProtocol, phase, message.Reason, message.Mode)
	}
	return nil
}

func externalV2BulkDecisionReasonValid(mode, reason string) bool {
	if mode == externalV2BulkModeBulk {
		return reason == externalV2BulkReasonBothAccepted
	}
	return reason == externalV2BulkReasonSenderProbeRejected ||
		reason == externalV2BulkReasonReceiverProbeRejected ||
		reason == externalV2BulkReasonReadinessTimeout
}

func externalV2BulkControlFromPayload(payload []byte, auth externalPeerControlAuth) (externalV2BulkControl, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeV2BulkControl || env.V2BulkControl == nil {
		return externalV2BulkControl{}, false, err
	}
	if err := validateExternalV2BulkControl(*env.V2BulkControl); err != nil {
		return externalV2BulkControl{}, false, err
	}
	return *env.V2BulkControl, true, nil
}
