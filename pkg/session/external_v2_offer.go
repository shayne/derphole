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
	"sync"
	"time"

	"go4.org/mem"

	"github.com/shayne/derphole/pkg/dataplane"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type externalV2OfferRuntime struct {
	cfg       OfferConfig
	tok       string
	auth      externalPeerControlAuth
	session   *relaySession
	directTCP *externalV2DirectTCPListener

	claimCh             <-chan derpbind.Packet
	completeCh          <-chan derpbind.Packet
	abortCh             <-chan derpbind.Packet
	progressCh          <-chan derpbind.Packet
	unsubscribeClaims   func()
	unsubscribeComplete func()
	unsubscribeAbort    func()
	unsubscribeProgress func()
}

type externalV2OfferReceiveRuntime struct {
	cfg          ReceiveConfig
	tok          token.Token
	listenerDERP key.NodePublic
	dm           *tailcfg.DERPMap
	derp         *derpbind.Client
	probeConn    net.PacketConn
	pm           publicPortmap
	identity     quicpath.SessionIdentity
	auth         externalPeerControlAuth
	candidates   []string
	countedDst   *byteCountingWriteCloser
	directTCP    *externalV2DirectTCPListener

	acceptCh          <-chan derpbind.Packet
	abortCh           <-chan derpbind.Packet
	unsubscribeAccept func()
	unsubscribeAbort  func()
}

type externalV2AcceptEvent struct {
	accept externalV2Accept
	abort  error
	ok     bool
}

func externalOfferTokenUsesV2(rawToken string) bool {
	tok, err := token.Decode(rawToken, time.Now())
	return err == nil &&
		tok.Capabilities&token.CapabilityStdioOffer != 0 &&
		tok.Capabilities&token.CapabilityTransferV2 != 0
}

func offerExternalViaV2(ctx context.Context, cfg OfferConfig) (string, error) {
	rt, err := newExternalV2OfferRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.tok, rt.run(ctx)
}

func newExternalV2OfferRuntime(ctx context.Context, cfg OfferConfig) (*externalV2OfferRuntime, error) {
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdioOffer|token.CapabilityTransferV2, cfg.Emitter)
	if err != nil {
		return nil, err
	}
	rt := &externalV2OfferRuntime{
		cfg:     cfg,
		tok:     tok,
		session: session,
		auth:    externalPeerControlAuthForToken(session.token),
	}
	rt.subscribe()
	emitStatus(cfg.Emitter, StateWaiting)
	return rt, nil
}

func (rt *externalV2OfferRuntime) subscribe() {
	rt.claimCh, rt.unsubscribeClaims = rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isV2ClaimPayload(pkt.Payload)
	})
	rt.completeCh, rt.unsubscribeComplete = rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isV2CompletePayload(pkt.Payload)
	})
	rt.abortCh, rt.unsubscribeAbort = rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isAbortPayload(pkt.Payload)
	})
	rt.progressCh, rt.unsubscribeProgress = rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isProgressPayload(pkt.Payload)
	})
}

func (rt *externalV2OfferRuntime) Close() {
	if rt.directTCP != nil {
		rt.directTCP.Close()
	}
	if rt.unsubscribeClaims != nil {
		rt.unsubscribeClaims()
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
	closePublicSessionTransport(rt.session)
	if rt.session != nil && rt.session.derp != nil {
		_ = rt.session.derp.Close()
	}
}

func (rt *externalV2OfferRuntime) publishToken(ctx context.Context) error {
	if err := emitListenToken(ctx, rt.cfg.TokenSink, rt.tok); err != nil {
		return err
	}
	emitExternalV2Debug(rt.cfg.Emitter, "v2-offer-derp-public="+rt.session.derp.PublicKey().String())
	return nil
}

func (rt *externalV2OfferRuntime) run(ctx context.Context) (retErr error) {
	for {
		accepted, ok, err := rt.nextClaim(ctx)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		return rt.send(ctx, accepted)
	}
}

func (rt *externalV2OfferRuntime) nextClaim(ctx context.Context) (externalV2AcceptedClaim, bool, error) {
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

func externalOfferCountedSrcCount(countedSrc *byteCountingReadCloser) int64 {
	if countedSrc == nil {
		return 0
	}
	return countedSrc.Count()
}

func openExternalOfferCountedSource(ctx context.Context, cfg OfferConfig) (*byteCountingReadCloser, error) {
	src, err := openOfferSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return newByteCountingReadCloser(src), nil
}

func (rt *externalV2OfferRuntime) send(ctx context.Context, accepted externalV2AcceptedClaim) (retErr error) {
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleSend)
	var countedSrc *byteCountingReadCloser
	defer func() {
		if retErr != nil {
			metrics.SetError(retErr)
			rt.notifyAbort(accepted.peerDERP, retErr, externalOfferCountedSrcCount(countedSrc))
		}
	}()
	ctx = withExternalTransferMetrics(ctx, metrics)

	var err error
	countedSrc, err = openExternalOfferCountedSource(ctx, rt.cfg)
	if err != nil {
		return err
	}
	defer func() { _ = countedSrc.Close() }()

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	transferCtx, cancelTransfer := context.WithCancel(ctx)
	defer cancelTransfer()
	var endpointMu sync.Mutex
	var activeEndpoint externalV2QUICEndpoint
	setEndpoint := func(endpoint externalV2QUICEndpoint) {
		endpointMu.Lock()
		activeEndpoint = endpoint
		endpointMu.Unlock()
	}
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, func() {
		cancelTransfer()
		endpointMu.Lock()
		endpoint := activeEndpoint
		endpointMu.Unlock()
		if endpoint != nil {
			_ = endpoint.CloseWithError(1, "peer aborted transfer")
		}
	})
	defer stopAbortWatch()

	tr, err := rt.startSendTransport(transferCtx, accepted, metrics, pathEmitter)
	if err != nil {
		return externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	defer tr.Close()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))

	progressState := &externalV2PeerProgressState{}
	progressStop := startPeerProgressWatcher(ctx, rt.progressCh, rt.auth, metrics, recordExternalV2PeerProgress(progressState, rt.cfg.Progress), rt.cfg.Emitter)
	defer progressStop()

	policy := rt.cfg.ParallelPolicy.normalized()
	accept, err := rt.sendAccept(transferCtx, accepted.peerDERP, tr.localCandidates, policy, accepted.claim)
	if err != nil {
		return externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}

	managerConnections := externalV2ManagerConnectionCount(accept, policy)
	rawDirectBudget := externalV2AcceptedRawDirectStartupBudget(accept)
	if externalV2UsesDirectTCPFileTransfer(accept.TransferMode) {
		rt.cfg.BlockSource.ChunkSize = accept.BlockChunkSize
		used, err := rt.sendDirectTCPBlock(ctx, transferCtx, accepted, tr, metrics, progressState, pathEmitter, abortErrCh)
		if err != nil || used {
			return err
		}
		accept.TransferMode = externalV2TransferModeBlocks
	}
	return rt.sendQUIC(ctx, transferCtx, accepted, accept, tr, policy, managerConnections, rawDirectBudget, countedSrc, metrics, progressState, pathEmitter, abortErrCh, setEndpoint)
}

func (rt *externalV2OfferRuntime) sendQUIC(preferenceCtx context.Context, ctx context.Context, accepted externalV2AcceptedClaim, accept externalV2Accept, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, countedSrc *byteCountingReadCloser, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter, abortErrCh <-chan error, setEndpoint func(externalV2QUICEndpoint)) error {
	streamCount := externalV2StreamCount(policy)
	rawPath, err := negotiateExternalV2DirectPacketPath(ctx, rt.session.derp, accepted.peerDERP, tr.manager, rt.session.derpMap, rt.auth, rt.cfg.Emitter, streamCount, externalV2DataPlaneSenderPunchDelay, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return externalV2PreferPeerAbort(preferenceCtx, abortErrCh, err)
	}
	defer rawPath.Close()
	if rawPath.raw {
		tr.ActivateRawDirect()
	}
	var endpoint externalV2QUICEndpoint
	var streams []io.WriteCloser
	if rawPath.raw {
		if externalV2UsesBulkPacketTransfer(accept.TransferMode) {
			emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=bulk-packets")
			return rt.sendBulkPacketBlock(ctx, accepted, rawPath, metrics, progress, pathEmitter, tr.manager, abortErrCh)
		}
		client := dataplane.NewQUICClientOnPacketConns(rawPath.conns, rawPath.addrs, rt.session.quicIdentity, accepted.claim.QUICPublic)
		client.SetManagerConnectionCount(managerConnections)
		endpoint = client
		setEndpoint(endpoint)
		openCtx, cancelOpen := context.WithTimeout(ctx, externalV2StreamOpenWait)
		streams, err = client.OpenStreams(openCtx, streamCount)
		cancelOpen()
		if err != nil {
			return externalV2StreamOpenFailure(externalV2PreferPeerAbort(preferenceCtx, abortErrCh, err))
		}
		return rt.sendQUICStreams(ctx, accepted, accept, countedSrc, streams, endpoint, abortErrCh, metrics, progress, pathEmitter, tr.manager)
	}
	server := dataplane.NewQUICServer(tr.manager, rt.session.quicIdentity, accepted.claim.QUICPublic)
	server.SetManagerConnectionCount(managerConnections)
	endpoint = server
	setEndpoint(endpoint)
	streams, err = server.OpenStreamsWithReady(ctx, streamCount, nil)
	if err != nil {
		return externalV2PreferPeerAbort(preferenceCtx, abortErrCh, err)
	}
	return rt.sendQUICStreams(ctx, accepted, accept, countedSrc, streams, endpoint, abortErrCh, metrics, progress, pathEmitter, tr.manager)
}

func (rt *externalV2OfferRuntime) sendBulkPacketBlock(ctx context.Context, accepted externalV2AcceptedClaim, path externalV2DirectPacketPath, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter, manager *transport.Manager, abortErrCh <-chan error) error {
	auth, err := externalV2BulkPacketAuthForToken(rt.session.token, rt.session.derp.PublicKey(), accepted.peerDERP)
	if err != nil {
		return err
	}
	stats, err := sendExternalV2BulkBlockPackets(ctx, rt.cfg.BlockSource, externalV2BulkPacketPathFromRaw(path), auth, metrics)
	metrics.SetDirectStats(stats)
	if err != nil {
		return externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	complete, err := rt.receiveComplete(ctx, accepted.peerDERP, abortErrCh)
	if err != nil {
		return err
	}
	if err := recordExternalV2Completion(ctx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(manager)
	return nil
}

type externalV2QUICEndpoint interface {
	CloseWithError(code uint64, reason string) error
	Stats() dataplane.Stats
}

func (rt *externalV2OfferRuntime) sendQUICStreams(ctx context.Context, accepted externalV2AcceptedClaim, accept externalV2Accept, countedSrc *byteCountingReadCloser, streams []io.WriteCloser, endpoint externalV2QUICEndpoint, abortErrCh <-chan error, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter, manager *transport.Manager) error {
	if err := rt.sendStreamData(ctx, accept, countedSrc, streams, endpoint, abortErrCh, metrics); err != nil {
		return err
	}
	complete, err := rt.receiveComplete(ctx, accepted.peerDERP, abortErrCh)
	if err != nil {
		_ = endpoint.CloseWithError(1, err.Error())
		return err
	}
	if err := rt.finishSendStream(ctx, endpoint, complete, metrics, progress); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(manager)
	return nil
}

func (rt *externalV2OfferRuntime) sendStreamData(ctx context.Context, accept externalV2Accept, src *byteCountingReadCloser, streams []io.WriteCloser, endpoint externalV2QUICEndpoint, abortErrCh <-chan error, metrics *externalTransferMetrics) error {
	if externalV2AcceptCarriesBlockTransfer(accept) {
		if err := copyExternalV2SendBlockStreams(ctx, rt.cfg.BlockSource, streams, metrics); err != nil {
			return externalV2SendStreamError(endpoint, abortErrCh, err)
		}
	} else if err := copyExternalV2SendStreams(ctx, src, streams, metrics); err != nil {
		return externalV2SendStreamError(endpoint, abortErrCh, err)
	}
	return nil
}

func externalV2SendStreamError(endpoint externalV2QUICEndpoint, abortErrCh <-chan error, err error) error {
	_ = endpoint.CloseWithError(1, err.Error())
	if abortErr := waitExternalV2Abort(abortErrCh); abortErr != nil {
		return abortErr
	}
	return err
}

func (rt *externalV2OfferRuntime) finishSendStream(ctx context.Context, endpoint externalV2QUICEndpoint, complete externalV2Complete, metrics *externalTransferMetrics, progress *externalV2PeerProgressState) error {
	if err := recordExternalV2Completion(ctx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout); err != nil {
		_ = endpoint.CloseWithError(1, err.Error())
		return err
	}
	return endpoint.CloseWithError(0, "complete")
}

func (rt *externalV2OfferRuntime) startSendTransport(ctx context.Context, accepted externalV2AcceptedClaim, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (externalV2ListenTransport, error) {
	transferCtx, cancel := context.WithCancel(ctx)
	localCandidates := externalV2ProbeCandidates(ctx, rt.cfg.ForceRelay, rt.session.probeConn, rt.session.derpMap, publicSessionPortmap(rt.session))
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-accept-candidates=%d", len(localCandidates)))
	relayOnly := !externalV2DirectEnabled(rt.cfg.ForceRelay, accepted.claim.RelayCapable)
	manager, cleanup, err := startExternalTransportManager(transferCtx, rt.session.token, rt.session.probeConn, rt.session.derpMap, rt.session.derp, accepted.peerDERP, parseCandidateStrings(localCandidates), publicSessionPortmap(rt.session), relayOnly)
	if err != nil {
		cancel()
		return externalV2ListenTransport{}, err
	}
	emitStatus(rt.cfg.Emitter, StateClaimed)
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

func (rt *externalV2OfferRuntime) sendAccept(ctx context.Context, peerDERP key.NodePublic, candidates []string, policy ParallelPolicy, claim externalV2Claim) (externalV2Accept, error) {
	accept := externalV2Accept{
		Protocol:     externalV2Protocol,
		Accepted:     true,
		Candidates:   candidates,
		RelayCapable: !rt.cfg.ForceRelay,
	}
	accept.ParallelMode, accept.ParallelInitial, accept.ParallelCap = externalV2SetParallelPolicy(policy)
	accept.ManagerConnections = externalV2SetManagerConnectionCount(policy)
	accept.RawDirectBudgetMS = externalV2SetRawDirectStartupBudgetMS()
	if claim.BlockCapable {
		externalV2BlockSourceAccept(rt.cfg.BlockSource, &accept)
		policy := externalV2AcceptedBlockTransferPolicy(claim, validExternalV2BlockSource(rt.cfg.BlockSource), candidates)
		accept.DirectTCPFileCapable = validExternalV2BlockSource(rt.cfg.BlockSource) && !rt.cfg.ForceRelay
		if policy.Mode == externalV2TransferModeBlocks && accept.BlockSize >= externalV2DirectTCPMinFileSize && claim.DirectTCPFileCapable && accept.DirectTCPFileCapable && !externalV2DirectTCPAdvertisementUsable(claim.DirectTCPFile) {
			rt.directTCP = openConfiguredExternalV2DirectTCPListener(rt.cfg.DirectTCPPort, candidates, rt.cfg.Emitter)
			if rt.directTCP != nil {
				ad := rt.directTCP.ad
				accept.DirectTCPFile = &ad
			}
		}
		accept.TransferMode = externalV2SelectFileTransferMode(policy.Mode, accept.BlockSize, claim.DirectTCPFileCapable, accept.DirectTCPFileCapable, claim.DirectTCPFile, accept.DirectTCPFile)
		if externalV2UsesDirectTCPFileTransfer(accept.TransferMode) {
			accept.BlockChunkSize = externalV2DirectTCPChunkSize
		}
		emitExternalV2BlockTransferPolicy(rt.cfg.Emitter, policy)
		emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-file-transfer-selection=policy:%s size:%d claim_tcp:%t accept_tcp:%t claim_listener:%t accept_listener:%t selected:%s", policy.Mode, accept.BlockSize, claim.DirectTCPFileCapable, accept.DirectTCPFileCapable, externalV2DirectTCPAdvertisementUsable(claim.DirectTCPFile), externalV2DirectTCPAdvertisementUsable(accept.DirectTCPFile), accept.TransferMode))
	}
	err := sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:     envelopeV2Accept,
		V2Accept: &accept,
	}, rt.auth)
	return accept, err
}

func (rt *externalV2OfferRuntime) receiveComplete(ctx context.Context, peerDERP key.NodePublic, abortErrCh <-chan error) (externalV2Complete, error) {
	for {
		complete, ok, err := rt.nextComplete(ctx, peerDERP, abortErrCh)
		if err != nil {
			return externalV2Complete{}, err
		}
		if ok {
			return complete, nil
		}
	}
}

func (rt *externalV2OfferRuntime) nextComplete(ctx context.Context, peerDERP key.NodePublic, abortErrCh <-chan error) (externalV2Complete, bool, error) {
	select {
	case pkt, ok := <-rt.completeCh:
		return externalV2CompleteFromPeerPacket(pkt, ok, peerDERP, rt.auth)
	case err := <-abortErrCh:
		return externalV2Complete{}, false, err
	case <-ctx.Done():
		return externalV2Complete{}, false, ctx.Err()
	}
}

func externalV2CompleteFromPeerPacket(pkt derpbind.Packet, channelOK bool, peerDERP key.NodePublic, auth externalPeerControlAuth) (externalV2Complete, bool, error) {
	if !channelOK {
		return externalV2Complete{}, false, ErrPeerDisconnected
	}
	if pkt.From != peerDERP {
		return externalV2Complete{}, false, nil
	}
	return externalV2CompleteFromPayload(pkt.Payload, auth)
}

func externalV2CompleteFromPayload(payload []byte, auth externalPeerControlAuth) (externalV2Complete, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeV2Complete || env.V2Complete == nil {
		return externalV2Complete{}, false, err
	}
	return *env.V2Complete, true, nil
}

func (rt *externalV2OfferRuntime) watchAbort(ctx context.Context, peerDERP key.NodePublic, onAbort func()) (<-chan error, func()) {
	watchCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		err := rt.receiveAbort(watchCtx, peerDERP)
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

func (rt *externalV2OfferRuntime) receiveAbort(ctx context.Context, peerDERP key.NodePublic) error {
	for {
		abortErr, ok, err := rt.nextAbort(ctx, peerDERP)
		if err != nil {
			return err
		}
		if ok {
			return abortErr
		}
	}
}

func (rt *externalV2OfferRuntime) nextAbort(ctx context.Context, peerDERP key.NodePublic) (error, bool, error) {
	select {
	case pkt, ok := <-rt.abortCh:
		return externalV2AbortFromPeerPacket(pkt, ok, peerDERP, rt.auth)
	case <-ctx.Done():
		return nil, true, nil
	}
}

func externalV2AbortFromPeerPacket(pkt derpbind.Packet, channelOK bool, peerDERP key.NodePublic, auth externalPeerControlAuth) (error, bool, error) {
	if !channelOK {
		return nil, false, ErrPeerDisconnected
	}
	if pkt.From != peerDERP {
		return nil, false, nil
	}
	return externalV2AbortFromPayload(pkt.Payload, auth)
}

func (rt *externalV2OfferRuntime) notifyAbort(peerDERP key.NodePublic, err error, bytesTransferred int64) {
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
		Abort: newPeerAbort(reason, bytesTransferred),
	}, rt.auth)
}

func receiveExternalOfferViaV2(ctx context.Context, cfg ReceiveConfig) error {
	rt, err := newExternalV2OfferReceiveRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run(ctx)
}

func newExternalV2OfferReceiveRuntime(ctx context.Context, cfg ReceiveConfig) (*externalV2OfferReceiveRuntime, error) {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return nil, err
	}
	if tok.Capabilities&token.CapabilityStdioOffer == 0 {
		return nil, ErrUnknownSession
	}
	if err := validateExternalV2SendToken(tok); err != nil {
		return nil, err
	}
	rt := &externalV2OfferReceiveRuntime{
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

func (rt *externalV2OfferReceiveRuntime) openDERP(ctx context.Context) error {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(rt.tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	client, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	emitDERPProxyDebug(rt.cfg.Emitter, client)
	rt.dm = dm
	rt.derp = client
	return nil
}

func (rt *externalV2OfferReceiveRuntime) openProbeConn() error {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	rt.probeConn = conn
	rt.pm = newBoundPublicPortmap(conn, nil)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) subscribe() {
	rt.acceptCh, rt.unsubscribeAccept = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isV2AcceptPayload(pkt.Payload)
	})
	rt.abortCh, rt.unsubscribeAbort = rt.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isAbortPayload(pkt.Payload)
	})
}

func (rt *externalV2OfferReceiveRuntime) Close() {
	if rt.directTCP != nil {
		rt.directTCP.Close()
	}
	if rt.unsubscribeAccept != nil {
		rt.unsubscribeAccept()
	}
	if rt.unsubscribeAbort != nil {
		rt.unsubscribeAbort()
	}
	if rt.countedDst != nil {
		_ = rt.countedDst.Close()
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

func (rt *externalV2OfferReceiveRuntime) run(ctx context.Context) (retErr error) {
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleReceive)
	defer func() {
		if retErr != nil {
			metrics.SetError(retErr)
		}
	}()
	ctx = withExternalTransferMetrics(ctx, metrics)

	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	if err := rt.sendClaim(ctx); err != nil {
		return err
	}
	tr, accept, err := rt.acceptAndStartTransport(ctx, pathEmitter, metrics)
	if err != nil {
		rt.notifyAbort(err)
		drainExternalV2AbortSignal()
		return err
	}
	defer func() {
		if retErr != nil {
			rt.notifyAbort(retErr)
			drainExternalV2AbortSignal()
		}
		tr.Close()
	}()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	if !externalV2UsesDirectTCPFileTransfer(accept.TransferMode) && rt.directTCP != nil {
		rt.directTCP.Close()
		rt.directTCP = nil
	}

	sink, err := rt.openAcceptedReceiveSink(ctx, accept, metrics)
	if err != nil {
		return err
	}
	defer sink.Close()

	progressSender := rt.startAcceptedPeerProgress(ctx, sink)
	defer progressSender.Stop()

	policy := externalV2ParallelPolicy(accept)
	managerConnections := externalV2ManagerConnectionCount(accept, policy)
	rawDirectBudget := externalV2AcceptedRawDirectStartupBudget(accept)
	if handled, err := rt.receiveSelectedDirectTCP(ctx, accept, tr, &sink, progressSender, metrics, pathEmitter); err != nil || handled {
		return err
	}
	return rt.receiveAcceptedQUIC(ctx, tr, policy, managerConnections, rawDirectBudget, sink, progressSender, metrics, pathEmitter)
}

func (rt *externalV2OfferReceiveRuntime) receiveSelectedDirectTCP(ctx context.Context, accept externalV2Accept, tr externalV2ListenTransport, sink *externalV2OfferReceiveSink, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (bool, error) {
	if sink == nil || !sink.useBlock || !externalV2UsesDirectTCPFileTransfer(sink.transferMode) {
		return false, nil
	}
	used, err := rt.receiveDirectTCPBlock(ctx, accept, tr, sink.block, sink.blockCfg, progressSender, metrics, pathEmitter)
	if err != nil || used {
		return true, err
	}
	sink.transferMode = externalV2TransferModeBlocks
	return false, nil
}

type externalV2OfferReceiveSink struct {
	useBlock     bool
	transferMode string
	block        *countingBlockReceiveSink
	blockCfg     externalV2BlockReceiveConfig
}

func (s externalV2OfferReceiveSink) Close() {
	if s.block != nil {
		_ = s.block.Close()
	}
}

func (rt *externalV2OfferReceiveRuntime) openAcceptedReceiveSink(ctx context.Context, accept externalV2Accept, metrics *externalTransferMetrics) (externalV2OfferReceiveSink, error) {
	if externalV2AcceptCarriesBlockTransfer(accept) && rt.cfg.BlockReceiver != nil {
		blockSink, blockCfg, err := rt.openBlockReceive(ctx, accept)
		if err != nil {
			return externalV2OfferReceiveSink{}, err
		}
		metrics.SetDirectAppProgressBase(blockCfg.HeaderBytes)
		return externalV2OfferReceiveSink{useBlock: true, transferMode: accept.TransferMode, block: blockSink, blockCfg: blockCfg}, nil
	}
	if err := rt.openReceiveSink(ctx); err != nil {
		return externalV2OfferReceiveSink{}, err
	}
	return externalV2OfferReceiveSink{}, nil
}

func (rt *externalV2OfferReceiveRuntime) startAcceptedPeerProgress(ctx context.Context, sink externalV2OfferReceiveSink) *externalV2PeerProgressSender {
	if sink.useBlock {
		return startExternalV2PeerProgressSender(ctx, rt.derp, rt.listenerDERP, sink.block.Count, sink.block.FirstByteAt, rt.auth)
	}
	return startExternalV2PeerProgressSender(ctx, rt.derp, rt.listenerDERP, rt.countedDst.Count, rt.countedDst.FirstByteAt, rt.auth)
}

func (rt *externalV2OfferReceiveRuntime) receiveAcceptedQUIC(ctx context.Context, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, sink externalV2OfferReceiveSink, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	if sink.useBlock {
		return rt.receiveQUICBlock(ctx, tr, policy, managerConnections, rawDirectBudget, sink.transferMode, sink.block, sink.blockCfg, progressSender, metrics, pathEmitter)
	}
	return rt.receiveQUIC(ctx, tr, policy, managerConnections, rawDirectBudget, progressSender, metrics, pathEmitter)
}

func (rt *externalV2OfferReceiveRuntime) receiveQUIC(ctx context.Context, tr externalV2ListenTransport, policy ParallelPolicy, managerConnections int, rawDirectBudget time.Duration, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	endpoint, streams, rawPath, err := rt.acceptReceiveStreams(tr, externalV2StreamCount(policy), managerConnections, rawDirectBudget)
	if err != nil {
		return err
	}
	defer rawPath.Close()
	bytesReceived, err := rt.receiveStreamData(ctx, endpoint, streams, metrics)
	if err != nil {
		return err
	}
	if err := rt.finishReceiveStream(ctx, endpoint, bytesReceived, progressSender); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) acceptReceiveStreams(tr externalV2ListenTransport, streamCount int, managerConnections int, rawDirectBudget time.Duration) (externalV2QUICEndpoint, []io.ReadCloser, externalV2DirectPacketPath, error) {
	client := dataplane.NewQUICClient(tr.manager, rt.identity, rt.tok.QUICPublic)
	client.SetManagerConnectionCount(managerConnections)
	rawPath, err := negotiateExternalV2DirectPacketPath(tr.ctx, rt.derp, rt.listenerDERP, tr.manager, rt.dm, rt.auth, rt.cfg.Emitter, streamCount, 0, rawDirectBudget, tr.relayOnly)
	if err != nil {
		return nil, nil, externalV2DirectPacketPath{}, err
	}
	if rawPath.raw {
		tr.ActivateRawDirect()
	}
	if rawPath.raw {
		server := dataplane.NewQUICServerOnPacketConns(rawPath.conns, rt.identity, rt.tok.QUICPublic)
		server.SetManagerConnectionCount(managerConnections)
		openCtx, cancelOpen := context.WithTimeout(tr.ctx, externalV2StreamOpenWait)
		streams, err := server.AcceptStreamsWithReady(openCtx, streamCount, nil)
		cancelOpen()
		if err != nil {
			rawPath.Close()
			return nil, nil, externalV2DirectPacketPath{}, externalV2StreamOpenFailure(err)
		}
		return server, streams, rawPath, nil
	}
	streams, err := client.AcceptStreams(tr.ctx, streamCount)
	if err != nil {
		rawPath.Close()
		return nil, nil, externalV2DirectPacketPath{}, err
	}
	return client, streams, rawPath, nil
}

func (rt *externalV2OfferReceiveRuntime) receiveStreamData(ctx context.Context, endpoint externalV2QUICEndpoint, streams []io.ReadCloser, metrics *externalTransferMetrics) (int64, error) {
	bytesReceived, err := copyExternalV2ReceiveStreams(ctx, rt.countedDst, streams, metrics)
	if err != nil {
		return 0, rt.receiveStreamError(endpoint, err)
	}
	return bytesReceived, nil
}

func (rt *externalV2OfferReceiveRuntime) receiveStreamError(endpoint externalV2QUICEndpoint, err error) error {
	_ = endpoint.CloseWithError(1, err.Error())
	if abortErr := rt.pollAbort(); abortErr != nil {
		return abortErr
	}
	return err
}

func (rt *externalV2OfferReceiveRuntime) finishReceiveStream(ctx context.Context, endpoint externalV2QUICEndpoint, bytesReceived int64, progressSender *externalV2PeerProgressSender) error {
	if err := rt.sendComplete(ctx, bytesReceived, progressSender); err != nil {
		_ = endpoint.CloseWithError(1, err.Error())
		return err
	}
	return endpoint.CloseWithError(0, "complete")
}

func (rt *externalV2OfferReceiveRuntime) openReceiveSink(ctx context.Context) error {
	dst, err := openReceiveSink(ctx, rt.cfg)
	if err != nil {
		return err
	}
	rt.countedDst = newByteCountingWriteCloser(dst)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) sendClaim(ctx context.Context) error {
	rt.candidates = externalV2ProbeCandidates(ctx, rt.cfg.ForceRelay, rt.probeConn, rt.dm, rt.pm)
	emitExternalV2Debug(rt.cfg.Emitter, fmt.Sprintf("v2-claim-candidates=%d", len(rt.candidates)))
	claim := externalV2Claim{
		Protocol:             externalV2Protocol,
		QUICPublic:           rt.identity.Public,
		Candidates:           rt.candidates,
		RelayCapable:         !rt.cfg.ForceRelay,
		BlockCapable:         rt.cfg.BlockReceiver != nil,
		BlockPacketCapable:   rt.cfg.BlockReceiver != nil,
		DirectTCPFileCapable: rt.cfg.BlockReceiver != nil && !rt.cfg.ForceRelay,
	}
	if claim.DirectTCPFileCapable {
		rt.directTCP = openConfiguredExternalV2DirectTCPListener(rt.cfg.DirectTCPPort, rt.candidates, rt.cfg.Emitter)
		if rt.directTCP != nil {
			ad := rt.directTCP.ad
			claim.DirectTCPFile = &ad
		}
	}
	claim.ParallelMode, claim.ParallelInitial, claim.ParallelCap = externalV2SetParallelPolicy(DefaultParallelPolicy())
	return sendAuthenticatedEnvelope(ctx, rt.derp, rt.listenerDERP, envelope{
		Type:    envelopeV2Claim,
		V2Claim: &claim,
	}, rt.auth)
}

func (rt *externalV2OfferReceiveRuntime) acceptAndStartTransport(ctx context.Context, pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) (externalV2ListenTransport, externalV2Accept, error) {
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

func (rt *externalV2OfferReceiveRuntime) receiveAccept(ctx context.Context) (externalV2Accept, error) {
	for {
		event, err := rt.nextAcceptEvent(ctx)
		if err != nil {
			return externalV2Accept{}, err
		}
		if !event.ok {
			continue
		}
		if event.abort != nil {
			return externalV2Accept{}, event.abort
		}
		return event.accept, nil
	}
}

func (rt *externalV2OfferReceiveRuntime) nextAcceptEvent(ctx context.Context) (externalV2AcceptEvent, error) {
	select {
	case pkt, ok := <-rt.acceptCh:
		return externalV2AcceptEventFromPacket(pkt.Payload, ok, rt.auth)
	case pkt, ok := <-rt.abortCh:
		return externalV2AbortEventFromPacket(pkt.Payload, ok, rt.auth)
	case <-ctx.Done():
		return externalV2AcceptEvent{}, ctx.Err()
	}
}

func externalV2AcceptEventFromPacket(payload []byte, channelOK bool, auth externalPeerControlAuth) (externalV2AcceptEvent, error) {
	if !channelOK {
		return externalV2AcceptEvent{}, ErrPeerDisconnected
	}
	accept, ok, err := externalV2AcceptFromPayload(payload, auth)
	return externalV2AcceptEvent{accept: accept, ok: ok}, err
}

func externalV2AbortEventFromPacket(payload []byte, channelOK bool, auth externalPeerControlAuth) (externalV2AcceptEvent, error) {
	if !channelOK {
		return externalV2AcceptEvent{}, ErrPeerDisconnected
	}
	abortErr, ok, err := externalV2AbortFromPayload(payload, auth)
	return externalV2AcceptEvent{abort: abortErr, ok: ok}, err
}

func externalV2AcceptFromPayload(payload []byte, auth externalPeerControlAuth) (externalV2Accept, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeV2Accept || env.V2Accept == nil {
		return externalV2Accept{}, false, err
	}
	return *env.V2Accept, true, nil
}

func externalV2AbortFromPayload(payload []byte, auth externalPeerControlAuth) (error, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeAbort || env.Abort == nil {
		return nil, false, err
	}
	return externalV2AbortError(env.Abort), true, nil
}

func externalV2EnvelopeFromPayload(payload []byte, auth externalPeerControlAuth) (envelope, bool, error) {
	env, err := decodeAuthenticatedEnvelope(payload, auth)
	if err == nil {
		return env, true, nil
	}
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return envelope{}, false, nil
	}
	return envelope{}, false, err
}

func (rt *externalV2OfferReceiveRuntime) sendComplete(ctx context.Context, bytesReceived int64, progressSender *externalV2PeerProgressSender) error {
	if err := progressSender.Complete(ctx, bytesReceived); err != nil {
		return err
	}
	complete := externalV2Complete{
		Protocol:      externalV2Protocol,
		BytesReceived: bytesReceived,
	}
	return sendAuthenticatedEnvelope(ctx, rt.derp, rt.listenerDERP, envelope{
		Type:       envelopeV2Complete,
		V2Complete: &complete,
	}, rt.auth)
}

func (rt *externalV2OfferReceiveRuntime) pollAbort() error {
	select {
	case pkt, ok := <-rt.abortCh:
		if !ok {
			return ErrPeerDisconnected
		}
		abortErr, ok, err := externalV2AbortFromPayload(pkt.Payload, rt.auth)
		if err != nil {
			return nil
		}
		if ok {
			return abortErr
		}
	default:
	}
	return nil
}

func (rt *externalV2OfferReceiveRuntime) notifyAbort(err error) {
	if rt.derp == nil {
		return
	}
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	bytesReceived := int64(0)
	if rt.countedDst != nil {
		bytesReceived = rt.countedDst.Count()
	}
	abortCtx, cancel := context.WithTimeout(context.Background(), externalV2AbortNotifyWait)
	defer cancel()
	if err := sendAuthenticatedEnvelope(abortCtx, rt.derp, rt.listenerDERP, envelope{
		Type:  envelopeAbort,
		Abort: newPeerAbort(reason, bytesReceived),
	}, rt.auth); err != nil {
		emitExternalV2Debug(rt.cfg.Emitter, "v2-abort-notify-error="+err.Error())
	}
}
