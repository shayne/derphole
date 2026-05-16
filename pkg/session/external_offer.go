// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func offerExternal(ctx context.Context, cfg OfferConfig) (retTok string, retErr error) {
	tok, session, err := issuePublicSessionWithCapabilities(ctx, token.CapabilityStdioOffer)
	if err != nil {
		return "", err
	}
	defer closePublicSessionTransport(session)
	defer func() { _ = session.derp.Close() }()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()
	auth := externalPeerControlAuthForToken(session.token)

	if err := sendExternalOfferToken(ctx, cfg.TokenSink, tok); err != nil {
		return tok, err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("offer-derp-public=" + session.derp.PublicKey().String())
	}

	return tok, serveExternalOfferClaims(ctx, session, claimCh, auth, pathEmitter, cfg, &retErr)
}

func sendExternalOfferToken(ctx context.Context, tokenSink chan<- string, tok string) error {
	if tokenSink == nil {
		return nil
	}
	select {
	case tokenSink <- tok:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func serveExternalOfferClaims(ctx context.Context, session *relaySession, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg OfferConfig, retErr *error) error {
	for {
		claim, err := receiveExternalOfferClaim(ctx, claimCh, auth)
		if err != nil {
			return err
		}
		if claim == nil {
			continue
		}
		done, err := handleExternalOfferClaim(ctx, session, *claim, auth, pathEmitter, cfg, retErr)
		if done || err != nil {
			return err
		}
	}
}

type externalOfferDirectRuntime struct {
	decision         rendezvous.Decision
	relayOnly        bool
	probeConn        net.PacketConn
	probeConns       []net.PacketConn
	portmaps         []publicPortmap
	pm               publicPortmap
	localCandidates  []net.Addr
	remoteCandidates []net.Addr
	cleanup          func()
}

type externalOfferPeerChannels struct {
	ackCh       <-chan derpbind.Packet
	readyAckCh  <-chan derpbind.Packet
	startAckCh  <-chan derpbind.Packet
	rateProbeCh <-chan derpbind.Packet
	progressCh  <-chan derpbind.Packet
	cleanup     func()
}

type externalOfferTransportRuntime struct {
	ctx              context.Context
	cancel           context.CancelFunc
	manager          *transport.Manager
	cleanup          func()
	punchCancel      context.CancelFunc
	remoteCandidates []net.Addr
}

func receiveExternalOfferClaim(ctx context.Context, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth) (*rendezvous.Claim, error) {
	pkt, err := receiveSubscribedPacket(ctx, claimCh)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return nil, nil
	}
	if err != nil || env.Type != envelopeClaim || env.Claim == nil {
		return nil, nil
	}
	return env.Claim, nil
}

func handleExternalOfferClaim(ctx context.Context, session *relaySession, claim rendezvous.Claim, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg OfferConfig, retErr *error) (bool, error) {
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("offer-claim-received candidate_count=" + strconv.Itoa(len(claim.Candidates)))
	}
	peerDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
	decision, _ := session.gate.Accept(time.Now(), claim)
	if !decision.Accepted {
		emitExternalOfferDebug(cfg, "offer-decision-send accepted=false")
		err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth)
		return false, err
	}
	if decision.Accept == nil {
		return true, errors.New("accepted decision missing accept payload")
	}
	return true, sendExternalAcceptedOffer(ctx, session, claim, decision, peerDERP, auth, pathEmitter, cfg, retErr)
}

func sendExternalAcceptedOffer(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, peerDERP key.NodePublic, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg OfferConfig, callerRetErr *error) (retErr error) {
	var countedSrc *byteCountingReadCloser
	abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalOfferPeerControl(session, peerDERP)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)
	defer stopPeerAbort()
	defer func() {
		if callerRetErr != nil {
			*callerRetErr = retErr
		}
	}()
	defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalOfferCountedSrcCount(countedSrc)
	}, auth)

	direct, err := prepareExternalOfferDirectRuntime(ctx, session, claim, decision, cfg)
	if err != nil {
		return err
	}
	defer direct.cleanup()
	channels := subscribeExternalOfferPeerChannels(session, peerDERP)
	defer channels.cleanup()
	transportRuntime, err := startExternalOfferTransport(ctx, session, claim, peerDERP, direct, pathEmitter)
	if err != nil {
		return err
	}
	defer transportRuntime.Close()

	countedSrc, err = openExternalOfferCountedSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = countedSrc.Close() }()
	metrics := newExternalTransferMetricsWithTrace(time.Now(), cfg.Trace, transfertrace.RoleSend)
	metrics.DeferSendCompleteUntilPeerAck()
	ctx = withExternalTransferMetrics(ctx, metrics)

	if err := sendExternalOfferDecision(ctx, session, peerDERP, direct.decision, auth, cfg); err != nil {
		metrics.SetError(err)
		return err
	}
	if err := sendExternalOfferPayload(ctx, session, countedSrc, direct, channels, transportRuntime, peerDERP, pathEmitter, cfg); err != nil {
		metrics.SetError(err)
		return err
	}
	if err := waitForPeerAckWithTimeout(ctx, channels.ackCh, countedSrc.Count(), externalDirectUDPAckWait, auth); err != nil {
		metrics.SetError(err)
		return err
	}
	completeExternalSendMetricsAfterPeerAck(metrics, countedSrc.Count(), time.Now())
	pathEmitter.Complete(transportRuntime.manager)
	return nil
}

func subscribeExternalOfferPeerControl(session *relaySession, peerDERP key.NodePublic) (<-chan derpbind.Packet, <-chan derpbind.Packet, func()) {
	abortCh, unsubscribeAbort := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isAbortPayload(pkt.Payload)
	})
	heartbeatCh, unsubscribeHeartbeat := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isHeartbeatPayload(pkt.Payload)
	})
	return abortCh, heartbeatCh, func() {
		unsubscribeAbort()
		unsubscribeHeartbeat()
	}
}

func externalOfferCountedSrcCount(countedSrc *byteCountingReadCloser) int64 {
	if countedSrc == nil {
		return 0
	}
	return countedSrc.Count()
}

func prepareExternalOfferDirectRuntime(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, cfg OfferConfig) (externalOfferDirectRuntime, error) {
	direct := externalOfferDirectRuntime{
		decision:   decision,
		relayOnly:  cfg.ForceRelay || externalClaimRelayOnly(claim),
		probeConn:  session.probeConn,
		probeConns: []net.PacketConn{session.probeConn},
		portmaps:   []publicPortmap{publicSessionPortmap(session)},
		cleanup:    func() {},
	}
	if !direct.relayOnly {
		probeConn, probeConns, portmaps, cleanup, err := externalAcceptedDirectUDPSet(session.probeConn, publicSessionPortmap(session), cfg.Emitter)
		if err != nil {
			return direct, err
		}
		direct.probeConn = probeConn
		direct.probeConns = probeConns
		direct.portmaps = portmaps
		direct.cleanup = cleanup
	}
	direct.pm = direct.portmaps[0]
	applyExternalOfferDecisionCandidates(ctx, session, &direct)
	direct.localCandidates = parseCandidateStrings(direct.decision.Accept.Candidates)
	direct.remoteCandidates = parseRemoteCandidateStrings(claim.Candidates)
	return direct, nil
}

func applyExternalOfferDecisionCandidates(ctx context.Context, session *relaySession, direct *externalOfferDirectRuntime) {
	if direct.relayOnly {
		direct.decision.Accept.Parallel = 0
		direct.decision.Accept.Candidates = nil
		return
	}
	direct.decision.Accept.Parallel = len(direct.probeConns)
	direct.decision.Accept.Candidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, direct.probeConns, session.derpMap, direct.portmaps))
}

func subscribeExternalOfferPeerChannels(session *relaySession, peerDERP key.NodePublic) externalOfferPeerChannels {
	ackCh, unsubscribeAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isAckOrAbortPayload(pkt.Payload)
	})
	readyAckCh, unsubscribeReadyAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
	})
	startAckCh, unsubscribeStartAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isDirectUDPStartAckPayload(pkt.Payload)
	})
	rateProbeCh, unsubscribeRateProbe := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isDirectUDPRateProbePayload(pkt.Payload)
	})
	progressCh, unsubscribeProgress := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isProgressPayload(pkt.Payload)
	})
	return externalOfferPeerChannels{
		ackCh:       ackCh,
		readyAckCh:  readyAckCh,
		startAckCh:  startAckCh,
		rateProbeCh: rateProbeCh,
		progressCh:  progressCh,
		cleanup: func() {
			unsubscribeAck()
			unsubscribeReadyAck()
			unsubscribeStartAck()
			unsubscribeRateProbe()
			unsubscribeProgress()
		},
	}
}

func startExternalOfferTransport(ctx context.Context, session *relaySession, claim rendezvous.Claim, peerDERP key.NodePublic, direct externalOfferDirectRuntime, pathEmitter *transportPathEmitter) (*externalOfferTransportRuntime, error) {
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.token, direct.probeConn, session.derpMap, session.derp, peerDERP, direct.localCandidates, direct.pm, direct.relayOnly)
	if err != nil {
		transportCancel()
		return nil, err
	}
	pathEmitter.Emit(StateClaimed)
	pathEmitter.SuppressWatcherDirect()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	if !direct.relayOnly {
		externalDirectUDPStartPunching(punchCtx, direct.probeConns, direct.remoteCandidates)
	}
	return &externalOfferTransportRuntime{
		ctx:              transportCtx,
		cancel:           transportCancel,
		manager:          transportManager,
		cleanup:          transportCleanup,
		punchCancel:      punchCancel,
		remoteCandidates: direct.remoteCandidates,
	}, nil
}

func (r *externalOfferTransportRuntime) Close() {
	if r == nil {
		return
	}
	if r.punchCancel != nil {
		r.punchCancel()
	}
	if r.cleanup != nil {
		r.cleanup()
	}
	if r.cancel != nil {
		r.cancel()
	}
}

func openExternalOfferCountedSource(ctx context.Context, cfg OfferConfig) (*byteCountingReadCloser, error) {
	src, err := openOfferSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return newByteCountingReadCloser(src), nil
}

func sendExternalOfferDecision(ctx context.Context, session *relaySession, peerDERP key.NodePublic, decision rendezvous.Decision, auth externalPeerControlAuth, cfg OfferConfig) error {
	if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
		return err
	}
	emitExternalOfferDebug(cfg, "offer-decision-send accepted=true candidate_count="+strconv.Itoa(len(decision.Accept.Candidates)))
	return nil
}

func sendExternalOfferPayload(ctx context.Context, session *relaySession, countedSrc *byteCountingReadCloser, direct externalOfferDirectRuntime, channels externalOfferPeerChannels, transportRuntime *externalOfferTransportRuntime, peerDERP key.NodePublic, pathEmitter *transportPathEmitter, cfg OfferConfig) error {
	if direct.relayOnly {
		return sendExternalRelayUDPWithPeerProgress(ctx, countedSrc, transportRuntime.manager, session.token, channels.progressCh, externalOfferSendConfig(cfg))
	}
	return sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
		src:              countedSrc,
		tok:              session.token,
		decision:         direct.decision,
		derpClient:       session.derp,
		listenerDERP:     peerDERP,
		transportCtx:     transportRuntime.ctx,
		transportManager: transportRuntime.manager,
		pathEmitter:      pathEmitter,
		punchCancel:      transportRuntime.punchCancel,
		probeConn:        direct.probeConn,
		probeConns:       direct.probeConns,
		remoteCandidates: transportRuntime.remoteCandidates,
		readyAckCh:       channels.readyAckCh,
		startAckCh:       channels.startAckCh,
		rateProbeCh:      channels.rateProbeCh,
		progressCh:       channels.progressCh,
		cfg:              externalOfferSendConfig(cfg),
	})
}

func externalOfferSendConfig(cfg OfferConfig) SendConfig {
	return SendConfig{
		Emitter:            cfg.Emitter,
		StdioIn:            cfg.StdioIn,
		StdioExpectedBytes: cfg.StdioExpectedBytes,
		ForceRelay:         cfg.ForceRelay,
		UsePublicDERP:      cfg.UsePublicDERP,
		ParallelPolicy:     cfg.ParallelPolicy,
		Trace:              cfg.Trace,
		Progress:           cfg.Progress,
	}
}

func emitExternalOfferDebug(cfg OfferConfig, msg string) {
	if cfg.Emitter != nil {
		cfg.Emitter.Debug(msg)
	}
}

type externalOfferReceiveChannels struct {
	relayPrefixPackets <-chan derpbind.Packet
	readyCh            <-chan derpbind.Packet
	startCh            <-chan derpbind.Packet
	cleanup            func()
}

type externalOfferReceiveRuntime struct {
	tok               token.Token
	listenerDERP      key.NodePublic
	dm                *tailcfg.DERPMap
	derpClient        *derpbind.Client
	channels          externalOfferReceiveChannels
	probeConns        []net.PacketConn
	portmaps          []publicPortmap
	cleanupProbeConns func()
	probeConn         net.PacketConn
	pm                publicPortmap
	localCandidates   []string
	remoteCandidates  []net.Addr
	claim             rendezvous.Claim
	decision          rendezvous.Decision
	auth              externalPeerControlAuth
	relayOnly         bool
	countedDst        *byteCountingWriteCloser
}

func (r *externalOfferReceiveRuntime) Close() {
	if r == nil {
		return
	}
	if r.countedDst != nil {
		_ = r.countedDst.Close()
	}
	if r.cleanupProbeConns != nil {
		r.cleanupProbeConns()
	}
	if r.channels.cleanup != nil {
		r.channels.cleanup()
	}
	if r.derpClient != nil {
		_ = r.derpClient.Close()
	}
}

func receiveExternal(ctx context.Context, cfg ReceiveConfig) (retErr error) {
	runtime, err := newExternalOfferReceiveRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()

	abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalOfferReceivePeerControl(runtime)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, runtime.derpClient, runtime.listenerDERP, abortCh, heartbeatCh, runtime.countedDstCount, runtime.auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedDstCount, runtime.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedDstCount, runtime.auth)

	return receiveExternalAcceptedOffer(ctx, cfg, runtime)
}

func newExternalOfferReceiveRuntime(ctx context.Context, cfg ReceiveConfig) (_ *externalOfferReceiveRuntime, err error) {
	runtime := &externalOfferReceiveRuntime{cleanupProbeConns: func() {}}
	defer func() {
		if err != nil {
			runtime.Close()
		}
	}()
	runtime.tok, err = decodeExternalOfferReceiveToken(cfg.Token)
	if err != nil {
		return nil, err
	}
	runtime.listenerDERP, err = externalWGListenerDERP(runtime.tok)
	if err != nil {
		return nil, err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-listener-derp-public=" + runtime.listenerDERP.String())
	}
	runtime.dm, runtime.derpClient, err = openExternalWGDERPClient(ctx, runtime.tok)
	if err != nil {
		return nil, err
	}
	runtime.channels = subscribeExternalOfferReceiveChannels(runtime.derpClient, runtime.listenerDERP, cfg.ForceRelay)
	if err := runtime.openProbeConns(cfg); err != nil {
		return nil, err
	}
	if err := runtime.buildClaim(ctx, cfg); err != nil {
		return nil, err
	}
	if err := runtime.sendClaim(ctx, cfg); err != nil {
		return nil, err
	}
	runtime.relayOnly = cfg.ForceRelay || externalDecisionRelayOnly(runtime.decision)
	runtime.remoteCandidates = parseRemoteCandidateStrings(runtime.decision.Accept.Candidates)
	return runtime, nil
}

func decodeExternalOfferReceiveToken(rawToken string) (token.Token, error) {
	tok, err := token.Decode(rawToken, time.Now())
	if err != nil {
		return token.Token{}, err
	}
	if tok.Capabilities&token.CapabilityStdioOffer == 0 {
		return token.Token{}, ErrUnknownSession
	}
	return tok, nil
}

func subscribeExternalOfferReceiveChannels(derpClient *derpbind.Client, listenerDERP key.NodePublic, forceRelay bool) externalOfferReceiveChannels {
	if forceRelay {
		return externalOfferReceiveChannels{cleanup: func() {}}
	}
	relayPrefixPackets, unsubscribeRelayPrefix := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	readyCh, unsubscribeReady := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyPayload(pkt.Payload)
	})
	startCh, unsubscribeStart := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartPayload(pkt.Payload)
	})
	return externalOfferReceiveChannels{
		relayPrefixPackets: relayPrefixPackets,
		readyCh:            readyCh,
		startCh:            startCh,
		cleanup: func() {
			unsubscribeRelayPrefix()
			unsubscribeReady()
			unsubscribeStart()
		},
	}
}

func (r *externalOfferReceiveRuntime) openProbeConns(cfg ReceiveConfig) error {
	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConnsFn(nil, nil, externalDirectUDPParallelism, cfg.Emitter)
	if err != nil {
		return err
	}
	r.probeConns = probeConns
	r.portmaps = portmaps
	r.cleanupProbeConns = cleanupProbeConns
	r.probeConn = probeConns[0]
	r.pm = portmaps[0]
	return nil
}

func (r *externalOfferReceiveRuntime) buildClaim(ctx context.Context, cfg ReceiveConfig) error {
	claimIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return err
	}
	r.localCandidates = externalOfferReceiveCandidates(ctx, cfg, r)
	claimParallel := len(r.probeConns)
	if cfg.ForceRelay {
		claimParallel = 0
	}
	r.claim = rendezvous.Claim{
		Version:      r.tok.Version,
		SessionID:    r.tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(r.derpClient.PublicKey()),
		QUICPublic:   claimIdentity.Public,
		Parallel:     claimParallel,
		Candidates:   r.localCandidates,
		Capabilities: r.tok.Capabilities,
	}
	r.claim.BearerMAC = rendezvous.ComputeBearerMAC(r.tok.BearerSecret, r.claim)
	r.auth = externalPeerControlAuthForToken(r.tok)
	return nil
}

func externalOfferReceiveCandidates(ctx context.Context, cfg ReceiveConfig, runtime *externalOfferReceiveRuntime) []string {
	if cfg.ForceRelay {
		return nil
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-direct-candidate-gather-start")
	}
	candidateStart := time.Now()
	localCandidates := externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, runtime.probeConns, runtime.dm, runtime.portmaps))
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-direct-candidate-gather-finish count=" + strconv.Itoa(len(localCandidates)) + " elapsed_ms=" + strconv.FormatInt(time.Since(candidateStart).Milliseconds(), 10))
	}
	return localCandidates
}

func (r *externalOfferReceiveRuntime) sendClaim(ctx context.Context, cfg ReceiveConfig) error {
	if cfg.Emitter != nil {
		if payload, err := json.Marshal(envelope{Type: envelopeClaim, Claim: &r.claim}); err == nil {
			cfg.Emitter.Debug("receive-claim-bytes=" + strconv.Itoa(len(payload)))
		}
		cfg.Emitter.Debug("receive-claim-start")
	}
	decision, err := sendClaimAndReceiveDecisionWithTelemetry(ctx, r.derpClient, r.listenerDERP, r.claim, cfg.Emitter, "receive-", r.auth)
	if err != nil {
		return err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-claim-finish")
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}
	if decision.Accept == nil {
		return errors.New("accepted decision missing accept payload")
	}
	r.decision = decision
	return nil
}

func subscribeExternalOfferReceivePeerControl(runtime *externalOfferReceiveRuntime) (<-chan derpbind.Packet, <-chan derpbind.Packet, func()) {
	abortCh, unsubscribeAbort := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == runtime.listenerDERP && isAbortPayload(pkt.Payload)
	})
	heartbeatCh, unsubscribeHeartbeat := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == runtime.listenerDERP && isHeartbeatPayload(pkt.Payload)
	})
	return abortCh, heartbeatCh, func() {
		unsubscribeAbort()
		unsubscribeHeartbeat()
	}
}

func (r *externalOfferReceiveRuntime) countedDstCount() int64 {
	if r.countedDst == nil {
		return 0
	}
	return r.countedDst.Count()
}

func receiveExternalAcceptedOffer(ctx context.Context, cfg ReceiveConfig, runtime *externalOfferReceiveRuntime) error {
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)

	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		runtime.tok,
		runtime.probeConn,
		runtime.dm,
		runtime.derpClient,
		runtime.listenerDERP,
		parseCandidateStrings(runtime.localCandidates),
		runtime.pm,
		runtime.relayOnly,
	)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.SuppressWatcherDirect()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, runtime.decision)

	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !runtime.relayOnly {
		externalDirectUDPStartPunching(punchCtx, runtime.probeConns, runtime.remoteCandidates)
	}

	if err := runtime.openReceiveSink(ctx, cfg); err != nil {
		return err
	}
	progressCtx, stopPeerProgress := context.WithCancel(ctx)
	defer stopPeerProgress()
	go sendPeerProgressLoop(progressCtx, runtime.derpClient, runtime.listenerDERP, runtime.countedDst.Count, runtime.countedDst.FirstByteAt, runtime.auth)
	if err := receiveExternalOfferPayload(ctx, cfg, runtime, transportManager, pathEmitter, punchCancel); err != nil {
		return err
	}
	if err := sendPeerAck(ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedDst.Count(), runtime.auth); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

func (r *externalOfferReceiveRuntime) openReceiveSink(ctx context.Context, cfg ReceiveConfig) error {
	dst, err := openReceiveSink(ctx, cfg)
	if err != nil {
		return err
	}
	r.countedDst = newByteCountingWriteCloser(dst)
	return nil
}

func receiveExternalOfferPayload(ctx context.Context, cfg ReceiveConfig, runtime *externalOfferReceiveRuntime, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc) error {
	if runtime.relayOnly {
		return receiveExternalRelayUDP(ctx, runtime.countedDst, transportManager, runtime.tok, cfg.Emitter)
	}
	return receiveExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixReceiveConfig{
		dst:              runtime.countedDst,
		tok:              runtime.tok,
		derpClient:       runtime.derpClient,
		peerDERP:         runtime.listenerDERP,
		transportManager: transportManager,
		pathEmitter:      pathEmitter,
		punchCancel:      punchCancel,
		probeConn:        runtime.probeConn,
		probeConns:       runtime.probeConns,
		remoteCandidates: runtime.remoteCandidates,
		decision:         runtime.decision,
		readyCh:          runtime.channels.readyCh,
		startCh:          runtime.channels.startCh,
		relayPackets:     runtime.channels.relayPrefixPackets,
		cfg: ListenConfig{
			Emitter:       cfg.Emitter,
			StdioOut:      cfg.StdioOut,
			ForceRelay:    cfg.ForceRelay,
			UsePublicDERP: cfg.UsePublicDERP,
			Trace:         cfg.Trace,
		},
	})
}
