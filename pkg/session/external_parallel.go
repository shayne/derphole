//lint:file-ignore U1000 Retired public QUIC auto-growth helpers pending deletion after the WG cutover settles.
package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/telemetry"
	"tailscale.com/types/key"
)

const (
	externalParallelTailBytes          = 4 * externalCopyBufferSize
	externalParallelAutoBootstrapBytes = externalHandoffMaxUnackedBytes
)

func externalParallelAutoBootstrapReady(snapshot externalHandoffSpoolSnapshot) bool {
	return snapshot.AckedWatermark >= externalParallelAutoBootstrapBytes
}

func startParallelAutoGrowthLoop(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	session *externalNativeQUICStripedSession,
	runtime *externalHandoffCarrierRuntime,
	spool *externalHandoffSpool,
	policy ParallelPolicy,
	emitter *telemetry.Emitter,
) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		controller := newParallelAutoController(policy)
		if controller == nil || controller.policy.Mode != ParallelModeAuto {
			return
		}
		sampleTicker := time.NewTicker(AutoParallelSamplePeriod)
		defer sampleTicker.Stop()
		doneTicker := time.NewTicker(100 * time.Millisecond)
		defer doneTicker.Stop()

		previousAcked := spool.AckedWatermark()
		previousThroughput := 0.0
		for {
			select {
			case <-ctx.Done():
				return
			case <-doneTicker.C:
				if spool.Done() {
					return
				}
			case <-sampleTicker.C:
			}

			snapshot := spool.Snapshot()
			if externalParallelTail(snapshot) {
				if emitter != nil {
					emitter.Debug("parallel-auto-stop=tail")
				}
				return
			}

			deltaBytes := snapshot.AckedWatermark - previousAcked
			throughputMbps := (float64(deltaBytes) * 8) / AutoParallelSamplePeriod.Seconds() / 1_000_000
			if !externalParallelAutoBootstrapReady(snapshot) {
				previousAcked = snapshot.AckedWatermark
				previousThroughput = throughputMbps
				continue
			}
			currentTarget := session.StripeCount()
			decision := controller.Observe(parallelWindow{
				Target:             currentTarget,
				BacklogLimited:     externalParallelBacklogLimited(snapshot),
				ThroughputMbps:     throughputMbps,
				PreviousThroughput: previousThroughput,
			})
			previousAcked = snapshot.AckedWatermark
			previousThroughput = throughputMbps

			if decision.StopReason != "" {
				if emitter != nil {
					emitter.Debug("parallel-auto-stop=" + decision.StopReason)
				}
				return
			}
			if decision.NextTarget <= currentTarget {
				continue
			}

			growCtx, growCancel := context.WithTimeout(ctx, externalNativeQUICWait)
			growWatchDone := make(chan struct{})
			go func() {
				defer close(growWatchDone)
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-growCtx.Done():
						return
					case <-ticker.C:
						snapshot := spool.Snapshot()
						if snapshot.EOF && snapshot.AckedWatermark >= snapshot.SourceOffset {
							growCancel()
							return
						}
						if externalParallelTail(snapshot) {
							growCancel()
							return
						}
					}
				}
			}()
			streams, applied, err := requestExternalNativeQUICGrowth(growCtx, client, peerDERP, session, decision.NextTarget, emitter)
			<-growWatchDone
			growCancel()
			if err != nil {
				snapshot := spool.Snapshot()
				stopReason := externalParallelGrowthStopReason(snapshot, err)
				if emitter != nil {
					emitter.Debug("parallel-auto-stop=" + stopReason)
				}
				return
			}
			if applied <= currentTarget || len(streams) == 0 {
				if emitter != nil {
					emitter.Debug("parallel-auto-stop=no-growth")
				}
				return
			}
			for _, stream := range streams {
				if addErr := runtime.Add(stream); addErr != nil {
					if emitter != nil {
						emitter.Debug("parallel-auto-stop=runtime-closed")
					}
					return
				}
			}
			if emitter != nil {
				emitter.Debug("parallel-auto-applied=" + itoa(applied))
			}
		}
	}()
	return done
}

func startParallelGrowthRequestHandler(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	session *externalNativeQUICStripedSession,
	runtime *externalHandoffCarrierRuntime,
	emitter *telemetry.Emitter,
) <-chan struct{} {
	done := make(chan struct{})
	reqCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isParallelGrowRequestPayload(pkt.Payload)
	})
	resultCh, unsubscribeResult := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isParallelGrowResultPayload(pkt.Payload)
	})
	go func() {
		defer close(done)
		defer unsubscribe()
		defer unsubscribeResult()
		for {
			req, err := receiveParallelGrowRequest(ctx, reqCh)
			if err != nil {
				if ctx.Err() != nil || err == net.ErrClosed {
					return
				}
				if emitter != nil {
					emitter.Debug("parallel-grow-handler-stop err=" + err.Error())
				}
				return
			}

			growCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
			plan, planErr := session.PrepareGrowth(growCtx, req.Target)
			externalTransferTracef("parallel-grow-handler-request target=%d planErr=%v", req.Target, planErr)
			ack := parallelGrowAck{Target: req.Target, Ready: planErr == nil && plan != nil}
			if plan != nil {
				ack.CandidateSets = plan.candidateSets
			}
			externalTransferTracef("parallel-grow-handler-ack-send target=%d ready=%v", ack.Target, ack.Ready)
			if sendErr := sendEnvelope(growCtx, client, peerDERP, envelope{
				Type:            envelopeParallelGrowAck,
				ParallelGrowAck: &ack,
			}); sendErr != nil {
				closeExternalNativeQUICGrowthPlan(plan)
				cancel()
				return
			}
			if !ack.Ready {
				closeExternalNativeQUICGrowthPlan(plan)
				cancel()
				continue
			}

			growth, growErr := session.OpenGrowth(growCtx, plan, req.CandidateSets)
			externalTransferTracef("parallel-grow-handler-open target=%d growErr=%v", req.Target, growErr)
			ready := growErr == nil && growth != nil
			applied := 0
			if ready {
				applied = plan.target
			}
			externalTransferTracef("parallel-grow-handler-result-send target=%d ready=%v applied=%d", req.Target, ready, applied)
			if sendErr := sendEnvelope(growCtx, client, peerDERP, envelope{
				Type: envelopeParallelGrowResult,
				ParallelGrowResult: &parallelGrowResult{
					Target:  req.Target,
					Ready:   ready,
					Applied: applied,
				},
			}); sendErr != nil {
				if growth != nil {
					closeExternalNativeQUICGrowthResult(growth)
				} else {
					closeExternalNativeQUICGrowthPlan(plan)
				}
				cancel()
				return
			}
			peerResult, recvErr := receiveParallelGrowResult(growCtx, resultCh, req.Target)
			cancel()
			if recvErr != nil || !ready || !peerResult.Ready {
				if growth != nil {
					closeExternalNativeQUICGrowthResult(growth)
				} else {
					closeExternalNativeQUICGrowthPlan(plan)
				}
				continue
			}
			externalTransferTracef("parallel-grow-handler-result-recv target=%d ready=%v applied=%d", peerResult.Target, peerResult.Ready, peerResult.Applied)
			applied = session.CommitGrowth(growth)
			if emitter != nil {
				emitter.Debug("native-quic-stripes=" + itoa(applied))
			}
			for _, stream := range growth.streams {
				if addErr := runtime.Add(stream); addErr != nil {
					return
				}
			}
		}
	}()
	return done
}

func requestExternalNativeQUICGrowth(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	session *externalNativeQUICStripedSession,
	target int,
	emitter *telemetry.Emitter,
) ([]io.ReadWriteCloser, int, error) {
	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isParallelGrowAckPayload(pkt.Payload)
	})
	resultCh, unsubscribeResult := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isParallelGrowResultPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	defer unsubscribeResult()

	plan, err := session.PrepareGrowth(ctx, target)
	if err != nil || plan == nil {
		externalTransferTracef("parallel-grow-request-prepare target=%d err=%v ready=%v", target, err, plan != nil)
		return nil, session.StripeCount(), err
	}
	externalTransferTracef("parallel-grow-request-send target=%d", target)
	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeParallelGrowReq,
		ParallelGrowReq: &parallelGrowRequest{
			Target:        target,
			CandidateSets: plan.candidateSets,
		},
	}); err != nil {
		return nil, session.StripeCount(), err
	}
	ack, err := receiveParallelGrowAck(ctx, ackCh, target)
	if err != nil {
		closeExternalNativeQUICGrowthPlan(plan)
		return nil, session.StripeCount(), err
	}
	externalTransferTracef("parallel-grow-ack-recv target=%d ready=%v", ack.Target, ack.Ready)
	if !ack.Ready {
		closeExternalNativeQUICGrowthPlan(plan)
		return nil, session.StripeCount(), nil
	}
	growth, err := session.OpenGrowth(ctx, plan, ack.CandidateSets)
	externalTransferTracef("parallel-grow-open target=%d err=%v", target, err)
	ready := err == nil && growth != nil
	applied := 0
	if ready {
		applied = target
	}
	externalTransferTracef("parallel-grow-result-send target=%d ready=%v applied=%d", target, ready, applied)
	if sendErr := sendEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeParallelGrowResult,
		ParallelGrowResult: &parallelGrowResult{
			Target:  target,
			Ready:   ready,
			Applied: applied,
		},
	}); sendErr != nil {
		if growth != nil {
			closeExternalNativeQUICGrowthResult(growth)
		} else {
			closeExternalNativeQUICGrowthPlan(plan)
		}
		return nil, session.StripeCount(), sendErr
	}
	peerResult, err := receiveParallelGrowResult(ctx, resultCh, target)
	if err != nil || !ready || !peerResult.Ready {
		externalTransferTracef("parallel-grow-result-recv target=%d err=%v peerReady=%v peerApplied=%d", target, err, peerResult.Ready, peerResult.Applied)
		if growth != nil {
			closeExternalNativeQUICGrowthResult(growth)
		} else {
			closeExternalNativeQUICGrowthPlan(plan)
		}
		return nil, session.StripeCount(), err
	}
	externalTransferTracef("parallel-grow-result-recv target=%d err=%v peerReady=%v peerApplied=%d", target, err, peerResult.Ready, peerResult.Applied)
	applied = session.CommitGrowth(growth)
	if emitter != nil {
		emitter.Debug("native-quic-stripes=" + itoa(applied))
	}
	return growth.streams, applied, nil
}

func receiveParallelGrowRequest(ctx context.Context, ch <-chan derpbind.Packet) (parallelGrowRequest, error) {
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return parallelGrowRequest{}, net.ErrClosed
			}
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeParallelGrowReq || env.ParallelGrowReq == nil {
				continue
			}
			return *env.ParallelGrowReq, nil
		case <-ctx.Done():
			return parallelGrowRequest{}, ctx.Err()
		}
	}
}

func receiveParallelGrowAck(ctx context.Context, ch <-chan derpbind.Packet, target int) (parallelGrowAck, error) {
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return parallelGrowAck{}, net.ErrClosed
			}
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeParallelGrowAck || env.ParallelGrowAck == nil {
				continue
			}
			if env.ParallelGrowAck.Target != target {
				continue
			}
			return *env.ParallelGrowAck, nil
		case <-ctx.Done():
			return parallelGrowAck{}, ctx.Err()
		}
	}
}

func receiveParallelGrowResult(ctx context.Context, ch <-chan derpbind.Packet, target int) (parallelGrowResult, error) {
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return parallelGrowResult{}, net.ErrClosed
			}
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeParallelGrowResult || env.ParallelGrowResult == nil {
				continue
			}
			if env.ParallelGrowResult.Target != target {
				continue
			}
			return *env.ParallelGrowResult, nil
		case <-ctx.Done():
			return parallelGrowResult{}, ctx.Err()
		}
	}
}

func externalParallelBacklogLimited(snapshot externalHandoffSpoolSnapshot) bool {
	if snapshot.SourceOffset <= snapshot.AckedWatermark {
		return false
	}
	if !snapshot.EOF {
		return true
	}
	return snapshot.SourceOffset-snapshot.AckedWatermark > int64(externalCopyBufferSize)
}

func externalParallelTail(snapshot externalHandoffSpoolSnapshot) bool {
	return snapshot.EOF && snapshot.SourceOffset-snapshot.AckedWatermark <= externalParallelTailBytes
}

func externalParallelGrowthStopReason(snapshot externalHandoffSpoolSnapshot, err error) string {
	if snapshot.EOF && snapshot.AckedWatermark >= snapshot.SourceOffset {
		return "done"
	}
	if externalParallelTail(snapshot) {
		return "tail"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	return "grow-error err=" + err.Error()
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
