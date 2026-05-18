// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
)

var (
	errExternalDirectQUICTokenRequiresQUIC = errors.New("direct QUIC token requires DERPHOLE_DIRECT_TRANSPORT=quic")
	errExternalDirectQUICTokenUnsupported  = errors.New("token does not support direct QUIC")
)

const externalDirectQUICCopyBufferSize = 1 << 20

func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) (retErr error) {
	rt, err := newExternalDirectQUICSendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	ctx, stopPeerAbort := rt.withPeerControl(ctx)
	defer stopPeerAbort()
	defer rt.notifyPeerAbortOnError(&retErr, ctx)
	defer rt.notifyPeerAbortOnLocalCancel(&retErr, ctx)
	return rt.runQUIC(ctx)
}

func (rt *externalDirectUDPSendRuntime) runQUIC(ctx context.Context) error {
	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	tr, err := rt.startTransport(ctx, pathEmitter)
	if err != nil {
		return err
	}
	defer tr.Close()
	if !tr.relayOnly {
		pathEmitter.Emit(StateTryingDirect)
	}

	stopPeerProgress := startPeerProgressWatcher(ctx, rt.subs.progressCh, rt.auth, nil, rt.cfg.Progress, rt.cfg.Emitter)
	defer stopPeerProgress()

	if err := externalDirectQUICSendOverManagerAndThen(tr.ctx, rt.countedSrc, tr.manager, rt.quicIdentity, rt.tok.QUICPublic, func() error {
		return waitForPeerAckWithTimeout(ctx, rt.subs.ackCh, rt.countedSrc.Count(), externalDirectUDPAckWait, rt.auth)
	}); err != nil {
		return err
	}
	pathEmitter.Complete(tr.manager)
	return nil
}

func listenExternalViaDirectQUIC(ctx context.Context, cfg ListenConfig) (retTok string, retErr error) {
	rt, err := newExternalDirectQUICListenRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.runQUIC(ctx)
}

func newExternalDirectQUICListenRuntime(ctx context.Context, cfg ListenConfig) (*externalDirectUDPListenRuntime, error) {
	tok, session, err := issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityDirectQUIC)
	if err != nil {
		return nil, err
	}
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	return &externalDirectUDPListenRuntime{
		cfg:               cfg,
		tok:               tok,
		session:           session,
		pathEmitter:       pathEmitter,
		claimCh:           claimCh,
		unsubscribeClaims: unsubscribeClaims,
		auth:              externalPeerControlAuthForToken(session.token),
	}, nil
}

func (rt *externalDirectUDPListenRuntime) runQUIC(ctx context.Context) (string, error) {
	for {
		accepted, ok, err := rt.nextAcceptedClaim(ctx)
		if err != nil {
			return rt.tok, err
		}
		if !ok {
			continue
		}
		if err := rt.receiveAcceptedQUIC(ctx, accepted); err != nil {
			return rt.tok, err
		}
		return rt.tok, nil
	}
}

func (rt *externalDirectUDPListenRuntime) receiveAcceptedQUIC(ctx context.Context, accepted externalDirectUDPAcceptedClaim) (retErr error) {
	peerSubs := rt.subscribePeer(accepted.peerDERP)
	defer peerSubs.Close()
	var countedDst *byteCountingWriteCloser
	ctx, stopPeerAbort := withPeerControlContext(ctx, rt.session.derp, accepted.peerDERP, peerSubs.abortCh, peerSubs.heartbeatCh, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, rt.session.derp, accepted.peerDERP, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)
	defer notifyPeerAbortOnLocalCancel(&retErr, ctx, rt.session.derp, accepted.peerDERP, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)

	emitExternalDirectUDPClaimAccepted(rt.cfg.Emitter)
	tr, decision, err := rt.prepareQUICTransfer(ctx, accepted)
	if err != nil {
		return err
	}
	accepted.decision = decision
	defer tr.Close()
	countedDst, err = rt.openCountedSink(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = countedDst.Close() }()
	if !tr.relayOnly {
		rt.pathEmitter.Emit(StateTryingDirect)
	}

	progressCtx, stopPeerProgress := context.WithCancel(ctx)
	defer stopPeerProgress()
	go sendPeerProgressLoop(progressCtx, rt.session.derp, accepted.peerDERP, countedDst.Count, countedDst.FirstByteAt, rt.auth)

	if err := externalDirectQUICReceiveOverManagerAfterListen(tr.transportCtx, countedDst, tr.transportManager, rt.session.quicIdentity, accepted.env.Claim.QUICPublic, func() error {
		if err := rt.sendDecision(ctx, accepted.peerDERP, accepted.decision); err != nil {
			return err
		}
		emitExternalDirectUDPDecisionSent(rt.cfg.Emitter)
		return nil
	}); err != nil {
		return err
	}
	if err := sendPeerAck(ctx, rt.session.derp, accepted.peerDERP, countedDst.Count(), rt.auth); err != nil {
		return err
	}
	rt.pathEmitter.Complete(tr.transportManager)
	return nil
}

func (rt *externalDirectUDPListenRuntime) prepareQUICTransfer(ctx context.Context, accepted externalDirectUDPAcceptedClaim) (externalDirectUDPListenTransfer, rendezvous.Decision, error) {
	tr, err := rt.prepareProbeSet(accepted)
	if err != nil {
		return externalDirectUDPListenTransfer{}, accepted.decision, err
	}
	rt.applyDecisionCandidates(ctx, &accepted.decision, tr)
	localCandidates := parseCandidateStrings(accepted.decision.Accept.Candidates)
	tr.transportCtx, tr.transportCancel = context.WithCancel(ctx)
	tr.transportManager, tr.transportCleanup, err = startExternalTransportManager(tr.transportCtx, rt.session.token, tr.probeConn, rt.session.derpMap, rt.session.derp, accepted.peerDERP, localCandidates, tr.portmaps[0], tr.relayOnly)
	if err != nil {
		tr.Close()
		return externalDirectUDPListenTransfer{}, accepted.decision, err
	}
	rt.startQUICTransferTransport(accepted, &tr)
	return tr, accepted.decision, nil
}

func (rt *externalDirectUDPListenRuntime) startQUICTransferTransport(accepted externalDirectUDPAcceptedClaim, tr *externalDirectUDPListenTransfer) {
	rt.pathEmitter.Watch(tr.transportCtx, tr.transportManager)
	rt.pathEmitter.Flush(tr.transportManager)
	seedAcceptedClaimCandidates(tr.transportCtx, tr.transportManager, *accepted.env.Claim)
	tr.remoteCandidates = parseRemoteCandidateStrings(accepted.env.Claim.Candidates)
	if !tr.relayOnly {
		punchCtx, punchCancel := context.WithCancel(tr.transportCtx)
		tr.punchCancel = punchCancel
		externalDirectUDPStartPunching(punchCtx, tr.probeConns, tr.remoteCandidates)
	}
}

func externalDirectQUICSendOverManager(ctx context.Context, src io.Reader, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	return externalDirectQUICSendOverManagerAndThen(ctx, src, manager, identity, peer, nil)
}

func externalDirectQUICSendOverManagerAndThen(ctx context.Context, src io.Reader, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte, afterStreamClosed func() error) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()

	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer func() { _ = endpoint.Close() }()

	before := endpoint.Stats().BytesSent
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(stream, externalDirectQUICCopyBufferSize)
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	if _, err := io.CopyBuffer(writer, src, buf); err != nil {
		_ = stream.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Close()
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if endpoint.Stats().BytesSent > before {
		if err := externalDirectQUICWaitForCommittedBytes(ctx, func() int64 {
			return endpoint.Stats().BytesSent
		}, before); err != nil {
			return err
		}
	}
	if afterStreamClosed != nil {
		if err := afterStreamClosed(); err != nil {
			return err
		}
	}
	return nil
}

func externalDirectQUICReceiveOverManager(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()

	endpoint, err := directquic.Listen(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer func() { _ = endpoint.Close() }()

	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	_, copyErr := io.CopyBuffer(dst, stream, buf)
	closeErr := stream.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func externalDirectQUICReceiveOverManagerAfterListen(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte, afterListen func() error) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()

	endpoint, err := directquic.ListenWithReady(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   identity,
		PeerPublic: peer,
	}, afterListen)
	if err != nil {
		return err
	}
	defer func() { _ = endpoint.Close() }()

	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	_, err = io.CopyBuffer(dst, stream, buf)
	return err
}

func externalDirectQUICWaitForCommittedBytes(ctx context.Context, committed func() int64, before int64) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if committed() > before {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
