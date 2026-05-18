// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/types/key"
)

var (
	errExternalDirectQUICTokenRequiresQUIC = errors.New("direct QUIC token requires DERPHOLE_DIRECT_TRANSPORT=quic")
	errExternalDirectQUICTokenUnsupported  = errors.New("token does not support direct QUIC")
)

const externalDirectQUICCopyBufferSize = 1 << 20
const externalDirectQUICAckType = "derphole-direct-quic-ack-v1"
const externalDirectQUICAckMaxBytes = 4096
const externalDirectQUICAckCloseWait = 5 * time.Second

var externalDirectQUICModeWait = externalNativeQUICWait

type externalDirectQUICAck struct {
	Type  string `json:"type"`
	Bytes int64  `json:"bytes"`
}

var externalOfferRequestDirectQUICModeFn = requestExternalDirectQUICMode
var externalOfferAcceptDirectQUICModeFn = acceptExternalDirectQUICMode

func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) (retErr error) {
	rt, err := newExternalDirectQUICSendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	ctx, stopPeerAbort := rt.withPeerControlNoHeartbeatWatch(ctx)
	defer stopPeerAbort()
	defer rt.notifyPeerAbortOnError(&retErr, ctx)
	defer rt.notifyPeerAbortOnLocalCancel(&retErr, ctx)
	return rt.runQUIC(ctx)
}

func (rt *externalDirectUDPSendRuntime) runQUIC(ctx context.Context) error {
	rt.metrics = newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleSend)
	rt.metrics.DeferSendCompleteUntilPeerAck()
	ctx = withExternalTransferMetrics(ctx, rt.metrics)
	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	tr, err := rt.startTransport(ctx, pathEmitter)
	if err != nil {
		rt.metrics.SetError(err)
		return err
	}
	defer tr.Close()
	rt.metrics.SetTransportManager(tr.manager)
	rt.metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-direct-quic")
	stopDirectMetrics := externalDirectQUICWatchDirectPath(tr.ctx, tr.manager, rt.metrics)
	defer stopDirectMetrics()
	if !tr.relayOnly {
		pathEmitter.Emit(StateTryingDirect)
	}

	stopPeerProgress := startPeerProgressWatcher(ctx, rt.subs.progressCh, rt.auth, nil, rt.cfg.Progress, rt.cfg.Emitter)
	defer stopPeerProgress()

	if err := externalDirectQUICSendOverManagerAndThenFn(tr.ctx, rt.countedSrc, tr.manager, rt.quicIdentity, rt.tok.QUICPublic, nil); err != nil {
		rt.metrics.SetError(err)
		return err
	}
	completeExternalSendMetricsAfterPeerAck(rt.metrics, rt.countedSrc.Count(), time.Now())
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
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleReceive)
	ctx = withExternalTransferMetrics(ctx, metrics)
	peerSubs := rt.subscribePeer(accepted.peerDERP)
	defer peerSubs.Close()
	var countedDst *byteCountingWriteCloser
	ctx, stopPeerAbort := withPeerControlContext(ctx, rt.session.derp, accepted.peerDERP, peerSubs.abortCh, nil, func() int64 {
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
		metrics.SetError(err)
		return err
	}
	accepted.decision = decision
	defer tr.Close()
	metrics.SetTransportManager(tr.transportManager)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "connected-direct-quic")
	stopDirectMetrics := externalDirectQUICWatchDirectPath(tr.transportCtx, tr.transportManager, metrics)
	defer stopDirectMetrics()
	countedDst, err = rt.openCountedSink(ctx)
	if err != nil {
		metrics.SetError(err)
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
		metrics.SetError(err)
		return err
	}
	if err := sendPeerAck(ctx, rt.session.derp, accepted.peerDERP, countedDst.Count(), rt.auth); err != nil {
		metrics.SetError(err)
		return err
	}
	metrics.Complete(time.Now())
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
	return externalDirectQUICSendOverManagerAndThenFn(ctx, src, manager, identity, peer, nil)
}

var externalDirectQUICSendOverManagerAndThenFn = externalDirectQUICSendOverManagerAndThen

func externalDirectQUICSendOverManagerAndThen(ctx context.Context, src io.Reader, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte, afterStreamClosed func() error) error {
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.MarkDirectQUIC(time.Now())
	endpoint, closeEndpoint, err := externalDirectQUICDialEndpoint(ctx, manager, identity, peer)
	if err != nil {
		return err
	}
	defer func() {
		closeEndpoint()
		metrics.SetDirectQUICStats(endpoint.Stats())
	}()
	metrics.SetDirectQUICStats(endpoint.Stats())

	if err := externalDirectQUICCopySendStream(ctx, src, endpoint, metrics); err != nil {
		return err
	}
	if err := externalDirectQUICWaitForAck(ctx, endpoint, endpoint.Stats().BytesSent); err != nil {
		return err
	}
	return runExternalDirectQUICAfterStreamClosed(afterStreamClosed)
}

func externalDirectQUICDialEndpoint(ctx context.Context, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) (*directquic.Endpoint, func(), error) {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return endpoint, func() {
		_ = endpoint.Close()
		_ = adapter.Close()
	}, nil
}

func externalDirectQUICCopySendStream(ctx context.Context, src io.Reader, endpoint *directquic.Endpoint, metrics *externalTransferMetrics) error {
	before := endpoint.Stats().BytesSent
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		return err
	}
	if err := externalDirectQUICWriteSendStream(src, stream, metrics); err != nil {
		return err
	}
	metrics.SetDirectQUICStats(endpoint.Stats())
	if err := stream.Close(); err != nil {
		return err
	}
	metrics.SetDirectQUICStats(endpoint.Stats())
	return externalDirectQUICWaitForCommittedBytesIfNeeded(ctx, endpoint, before)
}

func externalDirectQUICWriteSendStream(src io.Reader, stream io.WriteCloser, metrics *externalTransferMetrics) error {
	meteredStream := externalTransferMetricsWriter{
		w:      stream,
		record: metrics.RecordDirectQUICSend,
	}
	writer := bufio.NewWriterSize(meteredStream, externalDirectQUICCopyBufferSize)
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	if _, err := io.CopyBuffer(writer, src, buf); err != nil {
		_ = stream.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Close()
		return err
	}
	return nil
}

func externalDirectQUICWaitForCommittedBytesIfNeeded(ctx context.Context, endpoint *directquic.Endpoint, before int64) error {
	if endpoint.Stats().BytesSent > before {
		return externalDirectQUICWaitForCommittedBytes(ctx, func() int64 {
			return endpoint.Stats().BytesSent
		}, before)
	}
	return nil
}

func runExternalDirectQUICAfterStreamClosed(afterStreamClosed func() error) error {
	if afterStreamClosed == nil {
		return nil
	}
	return afterStreamClosed()
}

func externalDirectQUICReceiveOverManager(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	return externalDirectQUICReceiveOverManagerFn(ctx, dst, manager, identity, peer)
}

var externalDirectQUICReceiveOverManagerFn = externalDirectQUICReceiveOverManagerImpl

func externalDirectQUICReceiveOverManagerImpl(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.MarkDirectQUIC(time.Now())
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
	defer func() {
		_ = endpoint.Close()
		metrics.SetDirectQUICStats(endpoint.Stats())
	}()
	metrics.SetDirectQUICStats(endpoint.Stats())

	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	meteredDst := externalTransferMetricsWriter{
		w:      dst,
		record: metrics.RecordDirectQUICReceive,
	}
	n, copyErr := io.CopyBuffer(meteredDst, stream, buf)
	metrics.SetDirectQUICStats(endpoint.Stats())
	closeErr := stream.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return externalDirectQUICSendAck(ctx, endpoint, n)
}

func externalDirectQUICReceiveOverManagerAfterListen(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte, afterListen func() error) error {
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.MarkDirectQUIC(time.Now())
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
	defer func() {
		_ = endpoint.Close()
		metrics.SetDirectQUICStats(endpoint.Stats())
	}()
	metrics.SetDirectQUICStats(endpoint.Stats())

	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	meteredDst := externalTransferMetricsWriter{
		w:      dst,
		record: metrics.RecordDirectQUICReceive,
	}
	n, err := io.CopyBuffer(meteredDst, stream, buf)
	metrics.SetDirectQUICStats(endpoint.Stats())
	if err != nil {
		return err
	}
	return externalDirectQUICSendAck(ctx, endpoint, n)
}

func externalDirectQUICWatchDirectPath(ctx context.Context, manager *transport.Manager, metrics *externalTransferMetrics) func() {
	if manager == nil || metrics == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go func() {
		if manager.PathState() == transport.PathDirect {
			metrics.MarkDirectValidated(time.Now())
			return
		}
		for update := range manager.Updates(watchCtx) {
			if update.Path == transport.PathDirect {
				metrics.MarkDirectValidated(time.Now())
				return
			}
		}
	}()
	return cancel
}

func requestExternalDirectQUICMode(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, respCh <-chan derpbind.Packet, readyCh <-chan derpbind.Packet, auth externalPeerControlAuth) (bool, error) {
	if client == nil || manager == nil {
		return false, nil
	}
	if err := sendExternalDirectQUICModeRequest(ctx, client, peerDERP, auth); err != nil {
		return false, err
	}
	modeCtx, cancel := context.WithTimeout(ctx, externalDirectQUICModeWait)
	defer cancel()

	resp, err := receiveExternalDirectQUICModeResponse(modeCtx, respCh, auth)
	if err != nil {
		return false, externalDirectQUICModeOptionalError(ctx, err)
	}
	if !resp.NativeDirect {
		return false, nil
	}
	if !requestExternalDirectQUICHasLocalDirect(modeCtx, manager) {
		_ = sendExternalDirectQUICModeAck(ctx, client, peerDERP, false, auth)
		return false, nil
	}
	return requestExternalDirectQUICReady(ctx, modeCtx, client, peerDERP, readyCh, auth)
}

func sendExternalDirectQUICModeRequest(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth) error {
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:        envelopeQUICModeReq,
		QUICModeReq: &quicModeRequest{NativeDirect: true},
	}, auth)
}

func receiveExternalDirectQUICModeResponse(ctx context.Context, respCh <-chan derpbind.Packet, auth externalPeerControlAuth) (quicModeResponse, error) {
	return receiveQUICModeResponse(ctx, respCh, auth)
}

func requestExternalDirectQUICHasLocalDirect(ctx context.Context, manager *transport.Manager) bool {
	_, ok := waitForExternalDirectAddr(ctx, manager, externalDirectQUICModeWait)
	return ok
}

func requestExternalDirectQUICReady(ctx context.Context, modeCtx context.Context, client *derpbind.Client, peerDERP key.NodePublic, readyCh <-chan derpbind.Packet, auth externalPeerControlAuth) (bool, error) {
	ackEnv := externalDirectQUICModeAckEnvelope(true)
	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, ackEnv, auth); err != nil {
		return false, err
	}
	ready, err := receiveQUICModeReadyWithAckRetry(modeCtx, readyCh, func(ctx context.Context) error {
		return sendAuthenticatedEnvelope(ctx, client, peerDERP, ackEnv, auth)
	}, auth)
	if err != nil {
		return false, externalDirectQUICModeOptionalError(ctx, err)
	}
	return ready.NativeDirect, nil
}

func acceptExternalDirectQUICMode(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, reqCh <-chan derpbind.Packet, ackCh <-chan derpbind.Packet, auth externalPeerControlAuth) (bool, error) {
	if client == nil || manager == nil {
		return false, nil
	}
	modeCtx, cancel := context.WithTimeout(ctx, externalDirectQUICModeWait)
	defer cancel()

	req, err := receiveExternalDirectQUICModeRequest(modeCtx, reqCh, auth)
	if err != nil {
		return false, externalDirectQUICModeOptionalError(ctx, err)
	}
	if !req.NativeDirect {
		return false, nil
	}
	directAddr, ok, err := acceptExternalDirectQUICWaitForDirect(modeCtx, ctx, client, peerDERP, manager, ackCh, auth)
	if err != nil || !ok {
		return false, err
	}
	return acceptExternalDirectQUICReady(ctx, client, peerDERP, manager, ackCh, directAddr, auth)
}

func receiveExternalDirectQUICModeRequest(ctx context.Context, reqCh <-chan derpbind.Packet, auth externalPeerControlAuth) (quicModeRequest, error) {
	return receiveQUICModeRequest(ctx, reqCh, auth)
}

func acceptExternalDirectQUICWaitForDirect(modeCtx context.Context, ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, ackCh <-chan derpbind.Packet, auth externalPeerControlAuth) (net.Addr, bool, error) {
	directAddr, ok, aborted := waitForExternalDirectAddrOrModeAbort(modeCtx, manager, ackCh, externalDirectQUICModeWait, auth)
	if aborted {
		return nil, false, nil
	}
	if !ok {
		if err := sendExternalDirectQUICModeResponse(ctx, client, peerDERP, false, nil, auth); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	return directAddr, true, nil
}

func acceptExternalDirectQUICReady(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, ackCh <-chan derpbind.Packet, directAddr net.Addr, auth externalPeerControlAuth) (bool, error) {
	if err := sendExternalDirectQUICModeResponse(ctx, client, peerDERP, true, directAddr, auth); err != nil {
		return false, err
	}
	ack, ok := receiveExternalQUICModeAcceptAck(ctx, ackCh, auth)
	if !ok || !ack.NativeDirect {
		return false, nil
	}
	if _, err := sendExternalQUICModeReady(ctx, client, peerDERP, manager, directAddr, auth); err != nil {
		return false, err
	}
	return true, nil
}

func externalDirectQUICModeAckEnvelope(nativeDirect bool) envelope {
	return envelope{
		Type:        envelopeQUICModeAck,
		QUICModeAck: &quicModeAck{NativeDirect: nativeDirect},
	}
}

func externalDirectQUICModeOptionalError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func sendExternalDirectQUICModeResponse(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, nativeDirect bool, directAddr net.Addr, auth externalPeerControlAuth) error {
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeResp,
		QUICModeResp: &quicModeResponse{
			NativeDirect: nativeDirect,
			DirectAddr:   quicModeDirectAddrString(directAddr),
		},
	}, auth)
}

func sendExternalDirectQUICModeAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, nativeDirect bool, auth externalPeerControlAuth) error {
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, externalDirectQUICModeAckEnvelope(nativeDirect), auth)
}

func externalDirectQUICSendAck(ctx context.Context, endpoint *directquic.Endpoint, bytesReceived int64) error {
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		return err
	}
	ack := externalDirectQUICAck{Type: externalDirectQUICAckType, Bytes: bytesReceived}
	if err := json.NewEncoder(stream).Encode(ack); err != nil {
		_ = stream.Close()
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectQUICAckCloseWait)
	defer cancel()
	_ = endpoint.WaitClosed(waitCtx)
	return nil
}

func externalDirectQUICWaitForAck(ctx context.Context, endpoint *directquic.Endpoint, bytesSent int64) error {
	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	payload, err := io.ReadAll(io.LimitReader(stream, externalDirectQUICAckMaxBytes))
	if err != nil {
		return err
	}
	var ack externalDirectQUICAck
	if err := json.Unmarshal(payload, &ack); err != nil {
		return err
	}
	if ack.Type != externalDirectQUICAckType {
		return fmt.Errorf("unexpected direct QUIC ack type %q", ack.Type)
	}
	if ack.Bytes != bytesSent {
		return fmt.Errorf("direct QUIC peer received %d bytes, sent %d", ack.Bytes, bytesSent)
	}
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.RecordPeerProgressFromFirstByte(ack.Bytes, time.Now())
	return nil
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
