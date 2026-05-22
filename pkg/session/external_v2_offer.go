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
	cfg     OfferConfig
	tok     string
	auth    externalPeerControlAuth
	session *relaySession

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
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdioOffer|token.CapabilityTransferV2)
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
	rt.abortCh, rt.unsubscribeAbort = rt.session.derp.Subscribe(func(pkt derpbind.Packet) bool {
		return isAbortPayload(pkt.Payload)
	})
	rt.progressCh, rt.unsubscribeProgress = rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isProgressPayload(pkt.Payload)
	})
}

func (rt *externalV2OfferRuntime) Close() {
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
	tr, err := rt.startSendTransport(ctx, accepted, metrics, pathEmitter)
	if err != nil {
		return err
	}
	defer tr.Close()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))

	progressStop := startPeerProgressWatcher(ctx, rt.progressCh, rt.auth, metrics, rt.cfg.Progress, rt.cfg.Emitter)
	defer progressStop()

	policy := rt.cfg.ParallelPolicy.normalized()
	if err := rt.sendAccept(ctx, accepted.peerDERP, tr.localCandidates, policy); err != nil {
		return err
	}

	return rt.sendQUIC(ctx, accepted, tr, policy, countedSrc, metrics, pathEmitter)
}

func (rt *externalV2OfferRuntime) sendQUIC(ctx context.Context, accepted externalV2AcceptedClaim, tr externalV2ListenTransport, policy ParallelPolicy, countedSrc *byteCountingReadCloser, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	streamCount := externalV2StreamCount(policy)
	rawPath, err := negotiateExternalV2DirectPacketPath(ctx, rt.session.derp, accepted.peerDERP, tr.manager, rt.session.derpMap, rt.auth, rt.cfg.Emitter, streamCount, externalV2DataPlaneSenderPunchDelay, tr.relayOnly)
	if err != nil {
		return err
	}
	defer rawPath.Close()
	var endpoint externalV2QUICEndpoint
	var streams []io.WriteCloser
	if rawPath.raw {
		client := dataplane.NewQUICClientOnPacketConns(rawPath.conns, rawPath.addrs, rt.session.quicIdentity, accepted.claim.QUICPublic)
		endpoint = client
		abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, func() {
			_ = endpoint.CloseWithError(1, "peer aborted transfer")
		})
		defer stopAbortWatch()
		streams, err = client.OpenStreams(tr.ctx, streamCount)
		if err != nil {
			return err
		}
		return rt.sendQUICStreams(ctx, accepted, countedSrc, streams, endpoint, abortErrCh, metrics, pathEmitter, tr.manager)
	}
	server := dataplane.NewQUICServer(tr.manager, rt.session.quicIdentity, accepted.claim.QUICPublic)
	endpoint = server
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, func() {
		_ = endpoint.CloseWithError(1, "peer aborted transfer")
	})
	defer stopAbortWatch()
	streams, err = server.OpenStreamsWithReady(tr.ctx, streamCount, nil)
	if err != nil {
		return err
	}
	return rt.sendQUICStreams(ctx, accepted, countedSrc, streams, endpoint, abortErrCh, metrics, pathEmitter, tr.manager)
}

type externalV2QUICEndpoint interface {
	CloseWithError(code uint64, reason string) error
	Stats() dataplane.Stats
}

func (rt *externalV2OfferRuntime) sendQUICStreams(ctx context.Context, accepted externalV2AcceptedClaim, countedSrc *byteCountingReadCloser, streams []io.WriteCloser, endpoint externalV2QUICEndpoint, abortErrCh <-chan error, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter, manager *transport.Manager) error {
	if err := rt.sendStreamData(ctx, countedSrc, streams, endpoint, abortErrCh, metrics); err != nil {
		return err
	}
	complete, err := rt.receiveComplete(ctx, accepted.peerDERP, abortErrCh)
	if err != nil {
		_ = endpoint.CloseWithError(1, err.Error())
		return err
	}
	if err := rt.finishSendStream(endpoint, complete, metrics); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(manager)
	return nil
}

func (rt *externalV2OfferRuntime) sendStreamData(ctx context.Context, src *byteCountingReadCloser, streams []io.WriteCloser, endpoint externalV2QUICEndpoint, abortErrCh <-chan error, metrics *externalTransferMetrics) error {
	if err := copyExternalV2SendStreams(ctx, src, streams, metrics); err != nil {
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

func (rt *externalV2OfferRuntime) finishSendStream(endpoint externalV2QUICEndpoint, complete externalV2Complete, metrics *externalTransferMetrics) error {
	metrics.RecordPeerProgress(complete.BytesReceived, 0, time.Now())
	if rt.cfg.Progress != nil {
		rt.cfg.Progress(complete.BytesReceived, 0)
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
		ctx:             transferCtx,
		manager:         manager,
		localCandidates: localCandidates,
		relayOnly:       relayOnly,
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

func (rt *externalV2OfferRuntime) sendAccept(ctx context.Context, peerDERP key.NodePublic, candidates []string, policy ParallelPolicy) error {
	accept := externalV2Accept{
		Protocol:     externalV2Protocol,
		Accepted:     true,
		Candidates:   candidates,
		RelayCapable: !rt.cfg.ForceRelay,
	}
	accept.ParallelMode, accept.ParallelInitial, accept.ParallelCap = externalV2SetParallelPolicy(policy)
	return sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{
		Type:     envelopeV2Accept,
		V2Accept: &accept,
	}, rt.auth)
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
	rt.abortCh, rt.unsubscribeAbort = rt.derp.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.listenerDERP && isAbortPayload(pkt.Payload)
	})
}

func (rt *externalV2OfferReceiveRuntime) Close() {
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
			rt.notifyAbort(retErr)
		}
	}()
	ctx = withExternalTransferMetrics(ctx, metrics)

	if err := rt.openReceiveSink(ctx); err != nil {
		return err
	}
	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	if err := rt.sendClaim(ctx); err != nil {
		return err
	}
	tr, accept, err := rt.acceptAndStartTransport(ctx, pathEmitter, metrics)
	if err != nil {
		return err
	}
	defer tr.Close()
	metrics.SetTransportManager(tr.manager)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))

	progressCtx, stopPeerProgress := context.WithCancel(ctx)
	defer stopPeerProgress()
	go sendPeerProgressLoop(progressCtx, rt.derp, rt.listenerDERP, rt.countedDst.Count, rt.countedDst.FirstByteAt, rt.auth)

	policy := externalV2ParallelPolicy(accept)

	return rt.receiveQUIC(ctx, tr, policy, metrics, pathEmitter)
}

func (rt *externalV2OfferReceiveRuntime) receiveQUIC(ctx context.Context, tr externalV2ListenTransport, policy ParallelPolicy, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) error {
	endpoint, streams, rawPath, err := rt.acceptReceiveStreams(tr, externalV2StreamCount(policy))
	if err != nil {
		return err
	}
	defer rawPath.Close()
	bytesReceived, err := rt.receiveStreamData(ctx, endpoint, streams, metrics)
	if err != nil {
		return err
	}
	if err := rt.finishReceiveStream(ctx, endpoint, bytesReceived); err != nil {
		return err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

func (rt *externalV2OfferReceiveRuntime) acceptReceiveStreams(tr externalV2ListenTransport, streamCount int) (externalV2QUICEndpoint, []io.ReadCloser, externalV2DirectPacketPath, error) {
	client := dataplane.NewQUICClient(tr.manager, rt.identity, rt.tok.QUICPublic)
	rawPath, err := negotiateExternalV2DirectPacketPath(tr.ctx, rt.derp, rt.listenerDERP, tr.manager, rt.dm, rt.auth, rt.cfg.Emitter, streamCount, 0, tr.relayOnly)
	if err != nil {
		return nil, nil, externalV2DirectPacketPath{}, err
	}
	if rawPath.raw {
		server := dataplane.NewQUICServerOnPacketConns(rawPath.conns, rt.identity, rt.tok.QUICPublic)
		streams, err := server.AcceptStreamsWithReady(tr.ctx, streamCount, nil)
		if err != nil {
			rawPath.Close()
			return nil, nil, externalV2DirectPacketPath{}, err
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

func (rt *externalV2OfferReceiveRuntime) finishReceiveStream(ctx context.Context, endpoint externalV2QUICEndpoint, bytesReceived int64) error {
	if err := rt.sendComplete(ctx, bytesReceived); err != nil {
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
		Protocol:     externalV2Protocol,
		QUICPublic:   rt.identity.Public,
		Candidates:   rt.candidates,
		RelayCapable: !rt.cfg.ForceRelay,
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
		ctx:             transferCtx,
		manager:         manager,
		localCandidates: rt.candidates,
		relayOnly:       relayOnly,
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

func (rt *externalV2OfferReceiveRuntime) sendComplete(ctx context.Context, bytesReceived int64) error {
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
	_ = sendAuthenticatedEnvelope(abortCtx, rt.derp, rt.listenerDERP, envelope{
		Type:  envelopeAbort,
		Abort: newPeerAbort(reason, bytesReceived),
	}, rt.auth)
}
