// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"go4.org/mem"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const externalV2CopyBufferSize = externalCopyBufferSize
const externalV2AbortNotifyWait = 2 * time.Second
const externalV2AbortDrainWait = time.Second
const externalV2AbortSignalDrainWait = 150 * time.Millisecond
const externalV2CompleteWait = 5 * time.Second
const externalV2StreamOpenWait = 2 * time.Second
const externalV2DirectNudgeInterval = 250 * time.Millisecond
const externalV2DirectNudgeDuration = 2 * time.Second

type externalV2SendRuntime struct {
	cfg          SendConfig
	tok          token.Token
	listenerDERP key.NodePublic
	dm           *tailcfg.DERPMap
	derp         *derpbind.Client
	probeConn    net.PacketConn
	pm           publicPortmap
	identity     quicpath.SessionIdentity
	auth         externalPeerControlAuth
	candidates   []string
	directTCP    *externalV2DirectTCPListener

	acceptCh            <-chan derpbind.Packet
	completeCh          <-chan derpbind.Packet
	abortCh             <-chan derpbind.Packet
	progressCh          <-chan derpbind.Packet
	unsubscribeAccept   func()
	unsubscribeComplete func()
	unsubscribeAbort    func()
	unsubscribeProgress func()
}

type externalV2ListenRuntime struct {
	cfg       ListenConfig
	tok       string
	auth      externalPeerControlAuth
	session   *relaySession
	directTCP *externalV2DirectTCPListener

	claimCh           <-chan derpbind.Packet
	unsubscribeClaims func()
}

type externalV2AcceptedClaim struct {
	peerDERP key.NodePublic
	claim    externalV2Claim
}

type externalV2ListenTransport struct {
	ctx               context.Context
	manager           *transport.Manager
	localCandidates   []string
	relayOnly         bool
	activateRawDirect func()
	cleanup           func()
}

func (tr externalV2ListenTransport) ActivateRawDirect() {
	if tr.activateRawDirect != nil {
		tr.activateRawDirect()
	}
}

func (tr externalV2ListenTransport) Close() {
	if tr.cleanup != nil {
		tr.cleanup()
	}
}

func sendExternalViaV2(ctx context.Context, cfg SendConfig) error {
	rt, err := newExternalV2SendRuntime(ctx, sendConfigWithInferredExpectedBytes(cfg))
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run(ctx)
}

func newExternalV2SendRuntime(ctx context.Context, cfg SendConfig) (*externalV2SendRuntime, error) {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return nil, err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return nil, ErrUnknownSession
	}
	if err := validateExternalV2SendToken(tok); err != nil {
		return nil, err
	}
	rt := &externalV2SendRuntime{
		cfg:          cfg,
		tok:          tok,
		listenerDERP: key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:])),
		auth:         externalPeerControlAuthForToken(tok),
	}
	if rt.listenerDERP.IsZero() {
		return nil, ErrUnknownSession
	}
	if err := rt.openDERP(ctx); err != nil {
		rt.Close()
		return nil, err
	}
	if err := rt.openProbeConn(); err != nil {
		rt.Close()
		return nil, err
	}
	if rt.identity, err = quicpath.GenerateSessionIdentity(); err != nil {
		rt.Close()
		return nil, err
	}
	rt.subscribe()
	return rt, nil
}

func (rt *externalV2SendRuntime) openDERP(ctx context.Context) error {
	bootstrap, err := resolveDERPBootstrap(ctx, rt.tok.DERPRoute, int(rt.tok.BootstrapRegion), "no bootstrap DERP node available")
	if err != nil {
		return err
	}
	client, err := openSessionDERPClient(ctx, bootstrap, rt.cfg.Emitter)
	if err != nil {
		return err
	}
	rt.dm = bootstrap.dm
	rt.derp = client
	return nil
}

func (rt *externalV2SendRuntime) openProbeConn() error {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	rt.probeConn = conn
	rt.pm = newBoundPublicPortmap(conn, nil)
	return nil
}

func (rt *externalV2SendRuntime) subscribe() {
	rt.acceptCh, rt.unsubscribeAccept = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isV2AcceptPayload(pkt.Payload)
	})
	rt.completeCh, rt.unsubscribeComplete = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isV2CompletePayload(pkt.Payload)
	})
	rt.abortCh, rt.unsubscribeAbort = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isAbortPayload(pkt.Payload)
	})
	rt.progressCh, rt.unsubscribeProgress = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isProgressPayload(pkt.Payload)
	})
}

func (rt *externalV2SendRuntime) Close() {
	if rt.directTCP != nil {
		rt.directTCP.Close()
	}
	if rt.unsubscribeAccept != nil {
		rt.unsubscribeAccept()
	}
	if rt.unsubscribeComplete != nil {
		rt.unsubscribeComplete()
	}
	if rt.unsubscribeAbort != nil {
		rt.unsubscribeAbort()
	}
	if rt.unsubscribeProgress != nil {
		rt.unsubscribeProgress()
	}
	if rt.derp != nil {
		_ = rt.derp.Close()
	}
	if rt.pm != nil {
		_ = rt.pm.Close()
	}
	if rt.probeConn != nil {
		_ = rt.probeConn.Close()
	}
}

func (rt *externalV2SendRuntime) run(ctx context.Context) (retErr error) {
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleSend)
	defer func() {
		if retErr != nil {
			metrics.SetError(retErr)
		}
	}()
	ctx = withExternalTransferMetrics(ctx, metrics)
	bytesTransferred := func() int64 {
		return metrics.RelayBytes() + metrics.DirectBytes()
	}
	stopLocalCancelAbort := watchExternalV2LocalCancelAbort(ctx, rt.derp, rt.listenerDERP, bytesTransferred, rt.auth)
	defer stopLocalCancelAbort()
	// Register the drain before the notification defers so LIFO execution keeps
	// the DERP connection open briefly after its final abort frame is flushed.
	defer drainExternalV2SenderAbortOnExit(&retErr, ctx)
	defer notifyPeerAbortOnError(&retErr, ctx, rt.derp, rt.listenerDERP, bytesTransferred, rt.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, rt.derp, rt.listenerDERP, bytesTransferred, rt.auth)

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	metrics.SetPhase(transfertrace.PhaseClaim, string(StateWaiting))
	if err := rt.sendClaim(ctx); err != nil {
		return err
	}
	pathEmitter.Emit(StateClaimed)

	tr, accept, err := rt.acceptAndStartTransport(ctx, pathEmitter, metrics)
	if err != nil {
		return err
	}
	defer tr.Close()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	if !externalV2UsesDirectTCPFileTransfer(accept.TransferMode) && rt.directTCP != nil {
		rt.directTCP.Close()
		rt.directTCP = nil
	}
	policy := externalV2ParallelPolicy(accept)
	managerConnections := externalV2ManagerConnectionCount(accept, policy)
	rawDirectBudget := externalV2AcceptedRawDirectStartupBudget(accept)
	progressState := &externalV2PeerProgressState{}
	stopPeerProgress := startPeerProgressWatcher(ctx, rt.progressCh, rt.auth, metrics, recordExternalV2PeerProgress(progressState, rt.cfg.Progress), rt.cfg.Emitter)
	defer stopPeerProgress()
	if handled, err := rt.sendSelectedDirectTCP(ctx, &accept, tr, metrics, progressState, pathEmitter); err != nil || handled {
		return err
	}
	if err := rt.sendStream(ctx, accept, tr, metrics, externalV2StreamCount(policy), managerConnections, rawDirectBudget, progressState); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func (rt *externalV2SendRuntime) sendSelectedDirectTCP(ctx context.Context, accept *externalV2Accept, tr externalV2ListenTransport, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter) (bool, error) {
	if accept == nil || !externalV2UsesDirectTCPFileTransfer(accept.TransferMode) {
		return false, nil
	}
	rt.cfg.BlockSource.ChunkSize = accept.BlockChunkSize
	used, err := rt.sendDirectTCPBlock(ctx, *accept, tr, metrics, progress, pathEmitter)
	if err != nil || used {
		return true, err
	}
	accept.TransferMode = externalV2TransferModeBlocks
	if rt.directTCP != nil {
		rt.directTCP.Close()
		rt.directTCP = nil
	}
	return false, nil
}

func (rt *externalV2SendRuntime) acceptAndStartTransport(ctx context.Context, pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) (externalV2ListenTransport, externalV2Accept, error) {
	accept, err := rt.receiveAccept(ctx)
	if err != nil {
		return externalV2ListenTransport{}, externalV2Accept{}, err
	}
	if err := validateExternalV2Accept(accept); err != nil {
		return externalV2ListenTransport{}, externalV2Accept{}, err
	}
	transferCtx, cancel := context.WithCancel(ctx)
	relayOnly := !externalV2DirectEnabled(rt.cfg.ForceRelay, accept.RelayCapable)
	manager, cleanup, err := startExternalTransportManager(transferCtx, rt.tok, rt.probeConn, rt.dm, rt.derp, rt.listenerDERP, parseCandidateStrings(rt.candidates), rt.pm, relayOnly)
	if err != nil {
		cancel()
		return externalV2ListenTransport{}, externalV2Accept{}, err
	}
	pathEmitter.Watch(transferCtx, manager)
	pathEmitter.Flush(manager)
	if !relayOnly {
		pathEmitter.Emit(StateTryingDirect)
	}
	stopDirectMetrics := watchExternalDirectPath(transferCtx, manager, metrics)
	remoteCandidates := parseRemoteCandidateStrings(accept.Candidates)
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-remote-candidates=%d", len(remoteCandidates)))
	if len(remoteCandidates) > 0 {
		manager.SeedRemoteCandidates(transferCtx, remoteCandidates)
	}
	reseedCancel := externalV2StartRemoteCandidateReseeds(transferCtx, manager, remoteCandidates, relayOnly)
	nudgeCancel := externalV2StartDirectNudges(transferCtx, rt.derp, rt.listenerDERP, rt.auth, rt.candidates, relayOnly)
	punchCancel := externalV2StartPunching(transferCtx, []net.PacketConn{rt.probeConn}, remoteCandidates, relayOnly)
	return externalV2ListenTransport{
		ctx:               transferCtx,
		manager:           manager,
		localCandidates:   rt.candidates,
		relayOnly:         relayOnly,
		activateRawDirect: newExternalV2RawDirectActivation(pathEmitter, manager, punchCancel, nudgeCancel, reseedCancel),
		cleanup: func() {
			punchCancel()
			nudgeCancel()
			reseedCancel()
			stopDirectMetrics()
			cleanup()
			cancel()
		},
	}, accept, nil
}

func (rt *externalV2SendRuntime) sendStream(ctx context.Context, accept externalV2Accept, tr externalV2ListenTransport, metrics *externalTransferMetrics, streamCount int, managerConnections int, rawDirectBudget time.Duration, progress *externalV2PeerProgressState) error {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	path, err := negotiateExternalV2DirectPacketPath(streamCtx, rt.derp, rt.listenerDERP, tr.manager, rt.dm, rt.auth, rt.cfg.Emitter, streamCount, externalV2DataPlaneSenderPunchDelay, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return err
	}
	defer path.Close()
	if path.raw {
		tr.ActivateRawDirect()
	}
	if path.raw && externalV2UsesBulkPacketTransfer(accept.TransferMode) {
		emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=bulk-packets")
		batchNative := accept.BlockPacketBatchCapable && externalV2BulkPacketBatchCapability()
		grouped := batchNative && externalV2GroupedBulk(accept.BlockPacketGroupCapable, externalV2BulkPacketGroupCapability())
		emitExternalV2BulkPacketRecordMode(rt.cfg.Emitter, grouped)
		abortErrCh, stopAbortWatch := rt.watchAbort(ctx, cancelStream)
		err := rt.sendBulkPacketBlock(
			streamCtx,
			ctx,
			path,
			batchNative,
			grouped,
			metrics,
			abortErrCh,
			progress,
		)
		stopAbortWatch()
		if !errors.Is(err, errExternalV2BulkPacketProbeRejected) {
			return err
		}
		emitExternalV2Debug(rt.cfg.Emitter, "v2-bulk-probe=fallback-before-payload")
	}
	client := rt.newExternalV2SendClient(tr.manager, path, managerConnections)
	return rt.copySendStreamWithClient(streamCtx, ctx, accept, path.raw, streamCount, client, cancelStream, metrics, progress)
}

func (rt *externalV2SendRuntime) newExternalV2SendClient(manager *transport.Manager, path externalV2DirectPacketPath, managerConnections int) *dataplane.QUICClient {
	if path.raw {
		client := dataplane.NewQUICClientOnPacketConns(path.conns, path.addrs, rt.identity, rt.tok.QUICPublic)
		client.SetManagerConnectionCount(managerConnections)
		return client
	}
	client := dataplane.NewQUICClient(manager, rt.identity, rt.tok.QUICPublic)
	client.SetManagerConnectionCount(managerConnections)
	return client
}

func (rt *externalV2SendRuntime) copySendStreamWithClient(streamCtx context.Context, ctx context.Context, accept externalV2Accept, boundedOpen bool, streamCount int, client *dataplane.QUICClient, cancelStream context.CancelFunc, metrics *externalTransferMetrics, progress *externalV2PeerProgressState) error {
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, func() {
		cancelStream()
		_ = client.CloseWithError(1, "peer aborted transfer")
	})
	defer stopAbortWatch()
	openCtx := streamCtx
	cancelOpen := func() {}
	if boundedOpen {
		openCtx, cancelOpen = context.WithTimeout(streamCtx, externalV2StreamOpenWait)
	}
	streams, err := client.OpenStreams(openCtx, streamCount)
	cancelOpen()
	if err != nil {
		err = externalV2PreferPeerAbort(ctx, abortErrCh, err)
		if boundedOpen {
			err = externalV2StreamOpenFailure(err)
		}
		return err
	}
	if err := rt.copyAcceptedSendStreams(streamCtx, ctx, accept, streams, metrics); err != nil {
		return externalV2SendQUICStreamError(ctx, client, abortErrCh, err)
	}
	complete, err := rt.receiveComplete(ctx, abortErrCh, rt.cfg.StdioExpectedBytes, progress)
	if err != nil {
		_ = client.CloseWithError(1, err.Error())
		return err
	}
	if err := recordExternalV2Completion(ctx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout); err != nil {
		_ = client.CloseWithError(1, err.Error())
		return err
	}
	if err := client.CloseWithError(0, "complete"); err != nil {
		return err
	}
	return nil
}

func (rt *externalV2SendRuntime) sendBulkPacketBlock(streamCtx context.Context, completeCtx context.Context, path externalV2DirectPacketPath, batchNative, grouped bool, metrics *externalTransferMetrics, abortErrCh <-chan error, progress *externalV2PeerProgressState) error {
	auth, err := externalV2BulkPacketAuthForToken(rt.tok, rt.derp.PublicKey(), rt.listenerDERP)
	if err != nil {
		return err
	}
	auth = auth.withGrouped(grouped)
	stats, err := sendExternalV2BulkBlockPacketsWithProbe(streamCtx, rt.cfg.BlockSource, externalV2BulkPacketPathFromRaw(path), auth, metrics, batchNative)
	metrics.SetDirectStats(stats)
	if err != nil {
		return externalV2PreferPeerAbort(completeCtx, abortErrCh, err)
	}
	complete, err := rt.receiveComplete(completeCtx, abortErrCh, rt.cfg.StdioExpectedBytes, progress)
	if err != nil {
		return err
	}
	return recordExternalV2Completion(completeCtx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout)
}

func (rt *externalV2SendRuntime) copyAcceptedSendStreams(streamCtx context.Context, openCtx context.Context, accept externalV2Accept, streams []io.WriteCloser, metrics *externalTransferMetrics) error {
	if externalV2AcceptsBlockTransfer(accept) {
		return copyExternalV2SendBlockStreams(streamCtx, rt.cfg.BlockSource, streams, metrics)
	}
	src, err := openSendSource(openCtx, rt.cfg)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	return copyExternalV2SendStreams(streamCtx, src, streams, metrics)
}

func externalV2SendQUICStreamError(ctx context.Context, client *dataplane.QUICClient, abortErrCh <-chan error, err error) error {
	_ = client.CloseWithError(1, err.Error())
	return externalV2PreferPeerAbort(ctx, abortErrCh, err)
}

func externalV2PreferPeerAbort(ctx context.Context, abortErrCh <-chan error, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return err
	}
	if abortErr := waitExternalV2Abort(abortErrCh); abortErr != nil {
		return abortErr
	}
	return err
}

func externalV2StreamOpenFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrPeerDisconnected
	}
	return err
}

func drainExternalV2AbortSignal() {
	timer := time.NewTimer(externalV2AbortSignalDrainWait)
	defer timer.Stop()
	<-timer.C
}

func drainExternalV2SenderAbortOnExit(errp *error, ctx context.Context) {
	if errp == nil {
		return
	}
	err := normalizePeerAbortError(ctx, *errp)
	if !errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) &&
		!peerAbortErrorShouldNotify(err) {
		return
	}
	drainExternalV2AbortSignal()
}

func (rt *externalV2SendRuntime) watchAbort(ctx context.Context, onAbort func()) (<-chan error, func()) {
	watchCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		err := rt.receiveAbort(watchCtx)
		if err == nil {
			return
		}
		if onAbort != nil {
			onAbort()
		}
		select {
		case errCh <- err:
		default:
		}
	}()
	return errCh, cancel
}

func (rt *externalV2SendRuntime) sendClaim(ctx context.Context) error {
	rt.candidates = externalV2ProbeCandidates(ctx, rt.cfg.ForceRelay, rt.probeConn, rt.dm, rt.pm)
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-claim-candidates=%d", len(rt.candidates)))
	claim := externalV2Claim{
		Protocol:     externalV2Protocol,
		QUICPublic:   rt.identity.Public,
		Candidates:   rt.candidates,
		RelayCapable: !rt.cfg.ForceRelay,
	}
	claim.ParallelMode, claim.ParallelInitial, claim.ParallelCap = externalV2SetParallelPolicy(rt.cfg.ParallelPolicy)
	externalV2BlockSourceClaim(rt.cfg.BlockSource, &claim)
	claim.DirectTCPFileCapable = validExternalV2BlockSource(rt.cfg.BlockSource) && !rt.cfg.ForceRelay
	if claim.DirectTCPFileCapable && claim.BlockSize >= externalV2DirectTCPMinFileSize {
		rt.directTCP = openConfiguredExternalV2DirectTCPListener(rt.cfg.DirectTCPPort, rt.candidates, rt.cfg.Emitter)
		if rt.directTCP != nil {
			ad := rt.directTCP.ad
			claim.DirectTCPFile = &ad
		}
	}
	return sendAuthenticatedEnvelope(ctx, rt.derp, rt.listenerDERP, envelope{
		Type:    envelopeV2Claim,
		V2Claim: &claim,
	}, rt.auth)
}

func (rt *externalV2SendRuntime) receiveAccept(ctx context.Context) (externalV2Accept, error) {
	for {
		select {
		case pkt, ok := <-rt.acceptCh:
			if !ok {
				return externalV2Accept{}, ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return externalV2Accept{}, err
			}
			if env.Type == envelopeV2Accept && env.V2Accept != nil {
				return *env.V2Accept, nil
			}
		case <-ctx.Done():
			return externalV2Accept{}, ctx.Err()
		}
	}
}

func (rt *externalV2SendRuntime) receiveAbort(ctx context.Context) error {
	for {
		select {
		case pkt, ok := <-rt.abortCh:
			if !ok {
				return ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return err
			}
			if env.Type == envelopeAbort && env.Abort != nil {
				return externalV2AbortError(env.Abort)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func externalV2AbortError(abort *peerAbort) error {
	if abort == nil || abort.Reason == "" {
		return ErrPeerAborted
	}
	return fmt.Errorf("%w: %s", ErrPeerAborted, abort.Reason)
}

func waitExternalV2Abort(ch <-chan error) error {
	timer := time.NewTimer(externalV2AbortDrainWait)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-timer.C:
		return nil
	}
}

func (rt *externalV2SendRuntime) receiveComplete(ctx context.Context, abortErrCh <-chan error, expectedBytes int64, progress *externalV2PeerProgressState) (externalV2Complete, error) {
	return receiveExternalV2Complete(ctx, rt.completeCh, abortErrCh, rt.auth, expectedBytes, progress, externalV2CompleteWait)
}

func receiveExternalV2Complete(ctx context.Context, completeCh <-chan derpbind.Packet, abortErrCh <-chan error, auth externalPeerControlAuth, expectedBytes int64, progress *externalV2PeerProgressState, wait time.Duration) (externalV2Complete, error) {
	timeout, stopTimer := externalV2CompleteTimeout(wait)
	defer stopTimer()
	for {
		complete, ok, timedOut, err := nextExternalV2Complete(ctx, completeCh, abortErrCh, auth, timeout)
		if err != nil || ok {
			return complete, err
		}
		if timedOut {
			return externalV2CompleteFromProgress(expectedBytes, progress)
		}
	}
}

func externalV2CompleteTimeout(wait time.Duration) (<-chan time.Time, func()) {
	if wait <= 0 {
		return nil, func() {}
	}
	timer := time.NewTimer(wait)
	return timer.C, func() { timer.Stop() }
}

func nextExternalV2Complete(ctx context.Context, completeCh <-chan derpbind.Packet, abortErrCh <-chan error, auth externalPeerControlAuth, timeout <-chan time.Time) (externalV2Complete, bool, bool, error) {
	select {
	case pkt, ok := <-completeCh:
		complete, handled, err := externalV2CompleteFromPacket(pkt, ok, auth)
		return complete, handled, false, err
	case err := <-abortErrCh:
		return externalV2Complete{}, false, false, err
	case <-ctx.Done():
		return externalV2Complete{}, false, false, ctx.Err()
	case <-timeout:
		return externalV2Complete{}, false, true, nil
	}
}

func externalV2CompleteFromPacket(pkt derpbind.Packet, channelOK bool, auth externalPeerControlAuth) (externalV2Complete, bool, error) {
	if !channelOK {
		return externalV2Complete{}, false, ErrPeerDisconnected
	}
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if err != nil {
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			return externalV2Complete{}, false, nil
		}
		return externalV2Complete{}, false, err
	}
	if env.Type != envelopeV2Complete || env.V2Complete == nil {
		return externalV2Complete{}, false, nil
	}
	return *env.V2Complete, true, nil
}

func externalV2CompleteFromProgress(expectedBytes int64, progress *externalV2PeerProgressState) (externalV2Complete, error) {
	if expectedBytes <= 0 || progress == nil {
		return externalV2Complete{}, ErrPeerDisconnected
	}
	bytesReceived := progress.BytesReceived()
	if bytesReceived < expectedBytes {
		return externalV2Complete{}, ErrPeerDisconnected
	}
	return externalV2Complete{
		Protocol:      externalV2Protocol,
		BytesReceived: bytesReceived,
	}, nil
}

func listenExternalViaV2(ctx context.Context, cfg ListenConfig) (string, error) {
	rt, err := newExternalV2ListenRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.run(ctx)
}

func newExternalV2ListenRuntime(ctx context.Context, cfg ListenConfig) (*externalV2ListenRuntime, error) {
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityTransferV2, cfg.Emitter)
	if err != nil {
		return nil, err
	}
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isV2ClaimPayload(pkt.Payload)
	})
	rt := &externalV2ListenRuntime{
		cfg:               cfg,
		tok:               tok,
		session:           session,
		auth:              externalPeerControlAuthForToken(session.token),
		claimCh:           claimCh,
		unsubscribeClaims: unsubscribeClaims,
	}
	emitStatus(cfg.Emitter, StateWaiting)
	return rt, nil
}

func (rt *externalV2ListenRuntime) Close() {
	if rt.directTCP != nil {
		rt.directTCP.Close()
	}
	if rt.unsubscribeClaims != nil {
		rt.unsubscribeClaims()
	}
	closePublicSessionTransport(rt.session)
	if rt.session != nil && rt.session.derp != nil {
		_ = rt.session.derp.Close()
	}
}

func (rt *externalV2ListenRuntime) publishToken(ctx context.Context) error {
	return emitListenToken(ctx, rt.cfg.TokenSink, rt.tok)
}

func (rt *externalV2ListenRuntime) run(ctx context.Context) (string, error) {
	for {
		accepted, ok, err := rt.nextClaim(ctx)
		if err != nil {
			return rt.tok, err
		}
		if !ok {
			continue
		}
		if err := rt.receive(ctx, accepted); err != nil {
			return rt.tok, err
		}
		return rt.tok, nil
	}
}

func (rt *externalV2ListenRuntime) nextClaim(ctx context.Context) (externalV2AcceptedClaim, bool, error) {
	for {
		select {
		case pkt, ok := <-rt.claimCh:
			if !ok {
				return externalV2AcceptedClaim{}, false, ErrPeerDisconnected
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
			if err != nil {
				if ignoreAuthenticatedEnvelopeError(err, rt.auth) {
					continue
				}
				return externalV2AcceptedClaim{}, false, err
			}
			if env.Type != envelopeV2Claim || env.V2Claim == nil {
				continue
			}
			if err := validateExternalV2Claim(*env.V2Claim); err != nil {
				return externalV2AcceptedClaim{}, false, err
			}
			return externalV2AcceptedClaim{peerDERP: pkt.From, claim: *env.V2Claim}, true, nil
		case <-ctx.Done():
			return externalV2AcceptedClaim{}, false, ctx.Err()
		}
	}
}

func (rt *externalV2ListenRuntime) receive(ctx context.Context, accepted externalV2AcceptedClaim) (retErr error) {
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleReceive)
	defer func() {
		if retErr != nil {
			metrics.SetError(retErr)
		}
	}()
	ctx = withExternalTransferMetrics(ctx, metrics)

	target, err := rt.openReceiveTarget(ctx, accepted.claim, metrics)
	if err != nil {
		return err
	}
	defer target.Close()

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	tr, err := rt.startReceiveTransport(ctx, accepted, metrics, pathEmitter)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			rt.notifyAbort(accepted.peerDERP, retErr)
			drainExternalV2AbortSignal()
		}
		tr.Close()
	}()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))

	policy := externalV2ParallelPolicy(accepted.claim)
	accept, err := rt.sendAccept(ctx, accepted.peerDERP, tr.localCandidates, policy, accepted.claim, target.useBlock)
	if err != nil {
		return err
	}
	if !externalV2UsesDirectTCPFileTransfer(accept.TransferMode) && rt.directTCP != nil {
		rt.directTCP.Close()
		rt.directTCP = nil
	}

	managerConnections := externalV2ManagerConnectionCount(accept, policy)
	rawDirectBudget := externalV2AcceptedRawDirectStartupBudget(accept)
	return rt.receiveTarget(ctx, accepted, &accept, tr, policy, managerConnections, rawDirectBudget, target, metrics, pathEmitter)
}

type externalV2ListenReceiveTarget struct {
	useBlock bool
	block    *countingBlockReceiveSink
	blockCfg externalV2BlockReceiveConfig
	stream   *byteCountingWriteCloser
}

func (target externalV2ListenReceiveTarget) Close() {
	if target.block != nil {
		_ = target.block.Close()
	}
	if target.stream != nil {
		_ = target.stream.Close()
	}
}

func (rt *externalV2ListenRuntime) openReceiveTarget(ctx context.Context, claim externalV2Claim, metrics *externalTransferMetrics) (externalV2ListenReceiveTarget, error) {
	if externalV2ClaimRequestsBlockTransfer(claim) && rt.cfg.BlockReceiver != nil {
		block, blockCfg, err := rt.openBlockReceive(ctx, claim)
		if err != nil {
			return externalV2ListenReceiveTarget{}, err
		}
		metrics.SetDirectAppProgressBase(blockCfg.HeaderBytes)
		return externalV2ListenReceiveTarget{useBlock: true, block: block, blockCfg: blockCfg}, nil
	}
	dst, err := openListenSink(ctx, rt.cfg)
	if err != nil {
		return externalV2ListenReceiveTarget{}, err
	}
	return externalV2ListenReceiveTarget{stream: newByteCountingWriteCloser(dst)}, nil
}

func (rt *externalV2ListenRuntime) receiveTarget(ctx context.Context, accepted externalV2AcceptedClaim, accept *externalV2Accept, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, target externalV2ListenReceiveTarget, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	if target.useBlock {
		return rt.receiveBlockTarget(ctx, accepted, accept, tr, policy, managerConnections, rawDirectBudget, target, metrics, pathEmitter)
	}
	progressSender := startExternalV2PeerProgressSender(ctx, rt.session.derp, accepted.peerDERP, target.stream.Count, target.stream.FirstByteAt, rt.auth)
	defer progressSender.Stop()
	return rt.receiveQUIC(ctx, accepted, tr, policy, managerConnections, rawDirectBudget, target.stream, progressSender, metrics, pathEmitter)
}

func (rt *externalV2ListenRuntime) receiveBlockTarget(ctx context.Context, accepted externalV2AcceptedClaim, accept *externalV2Accept, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, target externalV2ListenReceiveTarget, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	progressSender := startExternalV2PeerProgressSender(ctx, rt.session.derp, accepted.peerDERP, target.block.Count, target.block.FirstByteAt, rt.auth)
	defer progressSender.Stop()
	if externalV2UsesDirectTCPFileTransfer(accept.TransferMode) {
		target.blockCfg.ChunkSize = accept.BlockChunkSize
		used, err := rt.receiveDirectTCPBlock(ctx, accepted, tr, target.block, target.blockCfg, progressSender, metrics, pathEmitter)
		if err != nil || used {
			return err
		}
		accept.TransferMode = externalV2TransferModeBlocks
		if rt.directTCP != nil {
			rt.directTCP.Close()
			rt.directTCP = nil
		}
	}
	return rt.receiveQUICBlock(ctx, accepted, accept.TransferMode, tr, policy, managerConnections, rawDirectBudget, target.block, target.blockCfg, progressSender, metrics, pathEmitter)
}

func (rt *externalV2ListenRuntime) receiveQUIC(ctx context.Context, accepted externalV2AcceptedClaim, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, dst *byteCountingWriteCloser, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	server := dataplane.NewQUICServer(tr.manager, rt.session.quicIdentity, accepted.claim.QUICPublic)
	server.SetManagerConnectionCount(managerConnections)
	streamCount := externalV2StreamCount(policy)
	rawPath, err := negotiateExternalV2DirectPacketPath(streamCtx, rt.session.derp, accepted.peerDERP, tr.manager, rt.session.derpMap, rt.auth, rt.cfg.Emitter, streamCount, 0, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return err
	}
	defer rawPath.Close()
	if rawPath.raw {
		tr.ActivateRawDirect()
	}
	if rawPath.raw {
		server = dataplane.NewQUICServerOnPacketConns(rawPath.conns, rt.session.quicIdentity, accepted.claim.QUICPublic)
		server.SetManagerConnectionCount(managerConnections)
	}
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, func() {
		cancelStream()
		_ = server.CloseWithError(1, "peer aborted transfer")
	})
	defer stopAbortWatch()
	openCtx := streamCtx
	cancelOpen := func() {}
	boundedOpen := rawPath.raw
	if rawPath.raw {
		openCtx, cancelOpen = context.WithTimeout(streamCtx, externalV2StreamOpenWait)
	}
	streams, err := server.AcceptStreamsWithReady(openCtx, streamCount, nil)
	cancelOpen()
	if err != nil {
		err = externalV2PreferPeerAbort(ctx, abortErrCh, err)
		if boundedOpen {
			err = externalV2StreamOpenFailure(err)
		}
		return err
	}
	bytesReceived, err := copyExternalV2ReceiveStreams(streamCtx, dst, streams, metrics)
	if err != nil {
		_ = server.CloseWithError(1, err.Error())
		return externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	if err := rt.sendComplete(ctx, accepted.peerDERP, bytesReceived, progressSender); err != nil {
		_ = server.CloseWithError(1, err.Error())
		return err
	}
	if err := server.CloseWithError(0, "complete"); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func watchExternalV2LocalCancelAbort(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesTransferred func() int64, auth externalPeerControlAuth) context.CancelFunc {
	watchCtx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
			err := normalizePeerAbortError(ctx, ctx.Err())
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				return
			}
			var bytes int64
			if bytesTransferred != nil {
				bytes = bytesTransferred()
			}
			sendPeerAbortBestEffort(client, peerDERP, peerAbortReason(err), bytes, auth)
		case <-watchCtx.Done():
		}
	}()
	return cancel
}

func (rt *externalV2ListenRuntime) watchAbort(ctx context.Context, peerDERP key.NodePublic, onAbort func()) (<-chan error, func()) {
	abortCh, unsubscribe := rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isAbortPayload(pkt.Payload)
	})
	watchCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		err := receiveExternalV2Abort(watchCtx, abortCh, rt.auth)
		if err == nil {
			return
		}
		if onAbort != nil {
			onAbort()
		}
		select {
		case errCh <- err:
		default:
		}
	}()
	return errCh, func() {
		cancel()
		unsubscribe()
	}
}

func receiveExternalV2Abort(ctx context.Context, abortCh <-chan derpbind.Packet, auth externalPeerControlAuth) error {
	for {
		select {
		case pkt, ok := <-abortCh:
			if !ok {
				return ErrPeerDisconnected
			}
			abortErr, ok, err := externalV2AbortFromPayload(pkt.Payload, auth)
			if err != nil {
				return err
			}
			if ok {
				return abortErr
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (rt *externalV2ListenRuntime) startReceiveTransport(ctx context.Context, accepted externalV2AcceptedClaim, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (externalV2ListenTransport, error) {
	transferCtx, cancel := context.WithCancel(ctx)
	localCandidates := externalV2ProbeCandidates(ctx, rt.cfg.ForceRelay, rt.session.probeConn, rt.session.derpMap, publicSessionPortmap(rt.session))
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-accept-candidates=%d", len(localCandidates)))
	relayOnly := !externalV2DirectEnabled(rt.cfg.ForceRelay, accepted.claim.RelayCapable)
	manager, cleanup, err := startExternalTransportManager(transferCtx, rt.session.token, rt.session.probeConn, rt.session.derpMap, rt.session.derp, accepted.peerDERP, parseCandidateStrings(localCandidates), publicSessionPortmap(rt.session), relayOnly)
	if err != nil {
		cancel()
		return externalV2ListenTransport{}, err
	}
	pathEmitter.Watch(transferCtx, manager)
	pathEmitter.Flush(manager)
	if !relayOnly {
		pathEmitter.Emit(StateTryingDirect)
	}
	stopDirectMetrics := watchExternalDirectPath(transferCtx, manager, metrics)
	remoteCandidates := parseRemoteCandidateStrings(accepted.claim.Candidates)
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-remote-candidates=%d", len(remoteCandidates)))
	if len(remoteCandidates) > 0 {
		manager.SeedRemoteCandidates(transferCtx, remoteCandidates)
	}
	reseedCancel := externalV2StartRemoteCandidateReseeds(transferCtx, manager, remoteCandidates, relayOnly)
	nudgeCancel := externalV2StartDirectNudges(transferCtx, rt.session.derp, accepted.peerDERP, rt.auth, localCandidates, relayOnly)
	punchCancel := externalV2StartPunching(transferCtx, []net.PacketConn{rt.session.probeConn}, remoteCandidates, relayOnly)
	return externalV2ListenTransport{
		ctx:               transferCtx,
		manager:           manager,
		localCandidates:   localCandidates,
		relayOnly:         relayOnly,
		activateRawDirect: newExternalV2RawDirectActivation(pathEmitter, manager, punchCancel, nudgeCancel, reseedCancel),
		cleanup: func() {
			punchCancel()
			nudgeCancel()
			reseedCancel()
			stopDirectMetrics()
			cleanup()
			cancel()
		},
	}, nil
}

func (rt *externalV2ListenRuntime) notifyAbort(peerDERP key.NodePublic, err error) {
	if rt.session == nil || rt.session.derp == nil {
		return
	}
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	abortCtx, cancel := context.WithTimeout(context.Background(), externalV2AbortNotifyWait)
	defer cancel()
	_ = sendAuthenticatedEnvelope(abortCtx, rt.session.derp, peerDERP, envelope{
		Type:  envelopeAbort,
		Abort: newPeerAbort(reason, 0),
	}, rt.auth)
}

func (rt *externalV2ListenRuntime) sendAccept(ctx context.Context, peerDERP key.NodePublic, candidates []string, policy ParallelPolicy, claim externalV2Claim, blockTransfer bool) (externalV2Accept, error) {
	accept := externalV2Accept{
		Protocol:     externalV2Protocol,
		Accepted:     true,
		Candidates:   candidates,
		RelayCapable: !rt.cfg.ForceRelay,
	}
	accept.ParallelMode, accept.ParallelInitial, accept.ParallelCap = externalV2SetParallelPolicy(policy)
	accept.ManagerConnections = externalV2SetManagerConnectionCount(policy)
	accept.RawDirectBudgetMS = externalV2SetRawDirectStartupBudgetMS()
	if blockTransfer {
		batchCapable := externalV2BulkPacketBatchCapability()
		accept.BlockPacketBatchCapable = batchCapable
		accept.BlockPacketGroupCapable = batchCapable && externalV2BulkPacketGroupCapability()
		policy := externalV2AcceptedBlockTransferPolicy(claim, true, accept.BlockPacketBatchCapable, candidates)
		accept.DirectTCPFileCapable = !rt.cfg.ForceRelay
		if policy.Mode == externalV2TransferModeBlocks && claim.BlockSize >= externalV2DirectTCPMinFileSize && claim.DirectTCPFileCapable && accept.DirectTCPFileCapable {
			rt.directTCP = openConfiguredExternalV2DirectTCPListener(rt.cfg.DirectTCPPort, candidates, rt.cfg.Emitter)
			if rt.directTCP != nil {
				ad := rt.directTCP.ad
				accept.DirectTCPFile = &ad
			}
		}
		accept.TransferMode = externalV2SelectOptimizedFileTransferMode(policy.Mode, claim.BlockSize, claim.BlockPacketBatchCapable, accept.BlockPacketBatchCapable)
		accept.TransferMode = externalV2SelectFileTransferMode(accept.TransferMode, claim.BlockSize, claim.DirectTCPFileCapable, accept.DirectTCPFileCapable, claim.DirectTCPFile, accept.DirectTCPFile)
		if externalV2UsesDirectTCPFileTransfer(accept.TransferMode) {
			accept.BlockChunkSize = externalV2DirectTCPChunkSize
		}
		emitExternalV2BlockTransferPolicy(rt.cfg.Emitter, policy)
		emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-file-transfer-selection=policy:%s size:%d claim_batch:%t accept_batch:%t claim_tcp:%t accept_tcp:%t claim_listener:%t accept_listener:%t selected:%s", policy.Mode, claim.BlockSize, claim.BlockPacketBatchCapable, accept.BlockPacketBatchCapable, claim.DirectTCPFileCapable, accept.DirectTCPFileCapable, externalV2DirectTCPAdvertisementUsable(claim.DirectTCPFile), externalV2DirectTCPAdvertisementUsable(accept.DirectTCPFile), accept.TransferMode))
	}
	err := sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:     envelopeV2Accept,
		V2Accept: &accept,
	}, rt.auth)
	return accept, err
}

func (rt *externalV2ListenRuntime) sendComplete(ctx context.Context, peerDERP key.NodePublic, bytesReceived int64, progressSender *externalV2PeerProgressSender) error {
	if err := progressSender.Complete(ctx, bytesReceived); err != nil {
		return err
	}
	complete := externalV2Complete{
		Protocol:      externalV2Protocol,
		BytesReceived: bytesReceived,
	}
	return sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:       envelopeV2Complete,
		V2Complete: &complete,
	}, rt.auth)
}

func copyExternalV2SendStreams(ctx context.Context, src io.Reader, streams []io.WriteCloser, metrics *externalTransferMetrics) error {
	if len(streams) == 1 {
		dst := io.Writer(streams[0])
		if metrics != nil {
			dst = externalTransferMetricsWriter{w: dst, record: metrics.RecordDirectPathSend}
		}
		writer := bufio.NewWriterSize(dst, externalV2CopyBufferSize)
		buf := make([]byte, externalV2CopyBufferSize)
		if _, err := io.CopyBuffer(writer, src, buf); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
		return streams[0].Close()
	}
	writers := make([]io.WriteCloser, 0, len(streams))
	for _, stream := range streams {
		writer := io.WriteCloser(stream)
		if metrics != nil {
			writer = externalTransferMetricsWriteCloser{
				WriteCloser: writer,
				record:      metrics.RecordDirectPathSend,
			}
		}
		writers = append(writers, writer)
	}
	return sendExternalStripedCopyWithObserver(ctx, src, writers, externalV2CopyBufferSize, externalV2StripedObserver(metrics))
}

func copyExternalV2ReceiveStreams(ctx context.Context, dst io.Writer, streams []io.ReadCloser, metrics *externalTransferMetrics) (int64, error) {
	countingDst := &byteCountingWriter{w: dst}
	recordDst := io.Writer(countingDst)
	if metrics != nil {
		recordDst = externalTransferMetricsWriter{w: recordDst, record: metrics.RecordDirectPathReceive}
	}
	if len(streams) == 1 {
		buf := make([]byte, externalV2CopyBufferSize)
		_, err := io.CopyBuffer(recordDst, streams[0], buf)
		_ = streams[0].Close()
		return countingDst.n, err
	}
	err := receiveExternalStripedCopyWithObserver(ctx, recordDst, streams, externalV2CopyBufferSize, externalV2StripedObserver(metrics))
	return countingDst.n, err
}

func externalV2StripedObserver(metrics *externalTransferMetrics) externalStripedCopyObserver {
	if metrics == nil || metrics.trace == nil {
		return externalStripedCopyObserver{}
	}
	return externalStripedCopyObserver{
		SendBlocked: func(d time.Duration) {
			metrics.RecordStripedSendBlocked(d, time.Now())
		},
		ReceiveBacklog: func(chunks int, bytes int64) {
			metrics.RecordStripedReceiveBacklog(chunks, bytes, time.Now())
		},
	}
}

type externalTransferMetricsWriteCloser struct {
	io.WriteCloser
	record func(int64, time.Time)
}

func (w externalTransferMetricsWriteCloser) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	if n > 0 && w.record != nil {
		w.record(int64(n), time.Now())
	}
	return n, err
}

type byteCountingWriter struct {
	w io.Writer
	n int64
}

func (w *byteCountingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.n += int64(n)
	}
	return n, err
}

func externalV2DirectEnabled(forceRelay bool, peerRelayCapable bool) bool {
	return !forceRelay && peerRelayCapable
}

func externalV2ProbeCandidates(ctx context.Context, forceRelay bool, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap) []string {
	if forceRelay || conn == nil {
		return nil
	}
	return publicProbeCandidates(ctx, conn, dm, pm)
}

func externalV2StartPunching(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr, relayOnly bool) context.CancelFunc {
	if relayOnly || len(remoteCandidates) == 0 {
		return func() {}
	}
	punchCtx, cancel := context.WithCancel(ctx)
	externalV2RawDirectStartPunching(punchCtx, conns, remoteCandidates)
	return cancel
}

func externalV2StartDirectNudges(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth, candidates []string, relayOnly bool) context.CancelFunc {
	if relayOnly || client == nil || peerDERP.IsZero() {
		return func() {}
	}
	nudgeCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		deadline := time.NewTimer(externalV2DirectNudgeDuration)
		defer deadline.Stop()
		ticker := time.NewTicker(externalV2DirectNudgeInterval)
		defer ticker.Stop()

		sendExternalV2DirectNudge(nudgeCtx, client, peerDERP, auth, candidates)
		for {
			select {
			case <-nudgeCtx.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				sendExternalV2DirectNudge(nudgeCtx, client, peerDERP, auth, candidates)
			}
		}
	}()
	return cancel
}

func externalV2StartRemoteCandidateReseeds(ctx context.Context, manager *transport.Manager, remoteCandidates []net.Addr, relayOnly bool) context.CancelFunc {
	if relayOnly || manager == nil || len(remoteCandidates) == 0 {
		return func() {}
	}
	reseedCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		deadline := time.NewTimer(externalV2DirectNudgeDuration)
		defer deadline.Stop()
		ticker := time.NewTicker(externalV2DirectNudgeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-reseedCtx.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				if manager.PathState() == transport.PathDirect {
					return
				}
				manager.SeedRemoteCandidates(reseedCtx, remoteCandidates)
			}
		}
	}()
	return cancel
}

func sendExternalV2DirectNudge(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth, candidates []string) {
	if len(candidates) > 0 {
		_ = sendTransportControl(ctx, client, peerDERP, transport.ControlMessage{
			Type:       transport.ControlCandidates,
			Candidates: candidates,
		}, auth)
	}
	_ = sendTransportControl(ctx, client, peerDERP, transport.ControlMessage{
		Type: transport.ControlCallMeMaybe,
	}, auth)
}

func emitExternalV2Debug(emitter *telemetry.Emitter, msg string) {
	if emitter != nil {
		emitter.Debug(msg)
	}
}
