// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/stream"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func issuePublicShareSession(ctx context.Context, cfg ShareConfig) (string, *relaySession, error) {
	_ = cfg
	return issuePublicQUICSession(ctx, token.CapabilityShare)
}

func shareExternal(ctx context.Context, cfg ShareConfig) (string, error) {
	tok, session, err := issuePublicShareSession(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = session.derp.Close() }()
	defer closePublicSessionTransport(session)
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()
	auth := externalPeerControlAuthForToken(session.token)

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	if err := sendExternalShareToken(ctx, cfg, tok); err != nil {
		return tok, err
	}

	for {
		claim, peerDERP, ok, err := receiveExternalAttachClaim(ctx, claimCh, auth)
		if err != nil {
			if ctx.Err() != nil {
				return tok, ctx.Err()
			}
			return tok, err
		}
		if !ok {
			continue
		}
		decision, _ := session.gate.Accept(time.Now(), claim)
		if rejected, err := rejectExternalAttachClaim(ctx, session, peerDERP, decision, auth); err != nil {
			return tok, err
		} else if rejected {
			continue
		}
		return acceptExternalShareClaim(ctx, cfg, session, pathEmitter, claimCh, auth, claim, peerDERP, decision, tok)
	}
}

func sendExternalShareToken(ctx context.Context, cfg ShareConfig, tok string) error {
	if cfg.TokenSink == nil {
		return nil
	}
	select {
	case cfg.TokenSink <- tok:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func acceptExternalShareClaim(ctx context.Context, cfg ShareConfig, session *relaySession, pathEmitter *transportPathEmitter, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth, claim rendezvous.Claim, peerDERP key.NodePublic, decision rendezvous.Decision, tok string) (string, error) {
	localCandidates := shareAcceptedCandidates(ctx, cfg, session, &decision)
	pathEmitter.Emit(StateClaimed)
	transportCtx, transportCancel, transportManager, transportCleanup, err := startExternalShareTransport(ctx, cfg, session, peerDERP, localCandidates)
	if err != nil {
		return tok, err
	}
	defer transportCancel()
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)
	adapter, quicListener, err := listenExternalShareQUIC(transportCtx, session, transportManager, claim)
	if err != nil {
		return tok, err
	}
	defer func() { _ = adapter.Close() }()
	defer func() { _ = quicListener.Close() }()
	if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
		return tok, err
	}
	claimErrCh := rejectAdditionalShareClaims(ctx, session.derp, session.gate, claimCh, auth)
	quicConn, err := quicListener.Accept(ctx)
	if err != nil {
		return tok, err
	}
	defer func() { _ = quicConn.CloseWithError(0, "") }()
	return tok, serveQUICListenerWithClaimRejections(ctx, quicConn, cfg.TargetAddr, cfg.Emitter, claimErrCh)
}

func shareAcceptedCandidates(ctx context.Context, cfg ShareConfig, session *relaySession, decision *rendezvous.Decision) []net.Addr {
	if decision.Accept != nil && !cfg.ForceRelay {
		decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap, publicSessionPortmap(session))
	}
	if decision.Accept == nil {
		return parseCandidateStrings(nil)
	}
	return parseCandidateStrings(decision.Accept.Candidates)
}

func startExternalShareTransport(ctx context.Context, cfg ShareConfig, session *relaySession, peerDERP key.NodePublic, localCandidates []net.Addr) (context.Context, context.CancelFunc, *transport.Manager, func(), error) {
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.token, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay)
	if err != nil {
		transportCancel()
		return nil, nil, nil, nil, err
	}
	return transportCtx, transportCancel, transportManager, transportCleanup, nil
}

func listenExternalShareQUIC(transportCtx context.Context, session *relaySession, transportManager *transport.Manager, claim rendezvous.Claim) (*quicpath.Adapter, *quic.Listener, error) {
	adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
	quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(session.quicIdentity, claim.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return adapter, quicListener, nil
}

func openExternal(ctx context.Context, cfg OpenConfig, tok token.Token) error {
	runtime, err := newOpenExternalRuntime(ctx, cfg, tok)
	if err != nil {
		return err
	}
	defer runtime.close()
	claim := runtime.claim()
	decision, err := runtime.sendClaim(ctx, claim)
	if err != nil {
		return err
	}
	if err := derptunClaimDecisionErr(decision); err != nil {
		return err
	}
	return runtime.open(ctx, cfg, decision)
}

type openExternalRuntime struct {
	tok             token.Token
	listenerDERP    key.NodePublic
	dm              *tailcfg.DERPMap
	derpClient      *derpbind.Client
	probeConn       net.PacketConn
	pm              publicPortmap
	clientIdentity  quicpath.SessionIdentity
	localCandidates []string
}

func newOpenExternalRuntime(ctx context.Context, cfg OpenConfig, tok token.Token) (*openExternalRuntime, error) {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return nil, ErrUnknownSession
	}
	dm, derpClient, err := openDerptunDialDERP(ctx, tok)
	if err != nil {
		return nil, err
	}
	runtime := &openExternalRuntime{tok: tok, listenerDERP: listenerDERP, dm: dm, derpClient: derpClient}
	if err := runtime.openProbe(ctx, cfg); err != nil {
		runtime.close()
		return nil, err
	}
	return runtime, nil
}

func (r *openExternalRuntime) openProbe(ctx context.Context, cfg OpenConfig) error {
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		_ = probeConn.Close()
		return err
	}
	r.probeConn = probeConn
	r.pm = newBoundPublicPortmap(probeConn, cfg.Emitter)
	r.clientIdentity = clientIdentity
	if !cfg.ForceRelay {
		r.localCandidates = publicProbeCandidates(ctx, probeConn, r.dm, r.pm)
	}
	return nil
}

func (r *openExternalRuntime) close() {
	if r.pm != nil {
		_ = r.pm.Close()
	}
	if r.probeConn != nil {
		_ = r.probeConn.Close()
	}
	if r.derpClient != nil {
		_ = r.derpClient.Close()
	}
}

func (r *openExternalRuntime) claim() rendezvous.Claim {
	claim := rendezvous.Claim{
		Version:      r.tok.Version,
		SessionID:    r.tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(r.derpClient.PublicKey()),
		QUICPublic:   r.clientIdentity.Public,
		Candidates:   r.localCandidates,
		Capabilities: r.tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(r.tok.BearerSecret, claim)
	return claim
}

func (r *openExternalRuntime) sendClaim(ctx context.Context, claim rendezvous.Claim) (rendezvous.Decision, error) {
	return sendClaimAndReceiveDecision(ctx, r.derpClient, r.listenerDERP, claim, externalPeerControlAuthForToken(r.tok))
}

func (r *openExternalRuntime) open(ctx context.Context, cfg OpenConfig, decision rendezvous.Decision) error {
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, r.tok, r.probeConn, r.dm, r.derpClient, r.listenerDERP, parseCandidateStrings(r.localCandidates), r.pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	transportCleanupFn := transportCleanup
	defer func() {
		transportCleanupFn()
	}()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(r.clientIdentity, r.tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer func() { _ = quicConn.CloseWithError(0, "") }()

	listener, err := openLocalListener(cfg, r.tok)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		streamConn, err := quicConn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return quicpath.WrapStream(quicConn, streamConn), nil
	}, cfg.Emitter)
}

func serveQUICListener(ctx context.Context, conn *quic.Conn, targetAddr string, emitter *telemetry.Emitter) error {
	var wg sync.WaitGroup
	slots := make(chan struct{}, quicpath.MaxIncomingStreams)
	defer wg.Wait()

	for {
		overlayConn, err := acceptQUICOverlayStream(ctx, conn)
		if err != nil {
			return err
		}
		if overlayConn == nil {
			return nil
		}
		if !reserveQUICStreamSlot(slots, overlayConn, emitter) {
			continue
		}
		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			releaseFailedQUICBackend(slots, overlayConn, emitter)
			continue
		}
		bridgeQUICOverlayStream(ctx, &wg, slots, overlayConn, backendConn)
	}
}

func acceptQUICOverlayStream(ctx context.Context, conn *quic.Conn) (net.Conn, error) {
	streamConn, err := conn.AcceptStream(ctx)
	if err == nil {
		return quicpath.WrapStream(conn, streamConn), nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil, nil
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
		return nil, nil
	}
	return nil, err
}

func reserveQUICStreamSlot(slots chan struct{}, overlayConn net.Conn, emitter *telemetry.Emitter) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		if emitter != nil {
			emitter.Debug("stream-limit-reached")
		}
		_ = overlayConn.Close()
		return false
	}
}

func releaseFailedQUICBackend(slots chan struct{}, overlayConn net.Conn, emitter *telemetry.Emitter) {
	if emitter != nil {
		emitter.Debug("backend-dial-failed")
	}
	<-slots
	_ = overlayConn.Close()
}

func bridgeQUICOverlayStream(ctx context.Context, wg *sync.WaitGroup, slots chan struct{}, overlayConn net.Conn, backendConn net.Conn) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-slots }()
		defer func() { _ = overlayConn.Close() }()
		defer func() { _ = backendConn.Close() }()
		_ = stream.Bridge(ctx, overlayConn, backendConn)
	}()
}

func serveQUICListenerWithClaimRejections(
	ctx context.Context,
	conn *quic.Conn,
	targetAddr string,
	emitter *telemetry.Emitter,
	claimErrCh <-chan error,
) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	connErrCh := make(chan error, 1)
	go func() {
		connErrCh <- serveQUICListener(serveCtx, conn, targetAddr, emitter)
	}()

	for {
		select {
		case err := <-connErrCh:
			return err
		case err, ok := <-claimErrCh:
			if !ok {
				claimErrCh = nil
				continue
			}
			if err != nil {
				cancel()
				_ = conn.CloseWithError(1, "claim rejection loop failed")
				<-connErrCh
				return err
			}
		}
	}
}

func rejectAdditionalShareClaims(
	ctx context.Context,
	client *derpbind.Client,
	gate *rendezvous.Gate,
	claimCh <-chan derpbind.Packet,
	auth externalPeerControlAuth,
) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		for {
			claim, peerDERP, ok, err := receiveExternalAttachClaim(ctx, claimCh, auth)
			if err != nil {
				sendAdditionalClaimLoopErr(ctx, errCh, err)
				return
			}
			if !ok {
				continue
			}
			decision, _ := gate.Accept(time.Now(), claim)
			if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
				if ctx.Err() == nil {
					errCh <- err
				}
				return
			}
		}
	}()
	return errCh
}

func sendAdditionalClaimLoopErr(ctx context.Context, errCh chan<- error, err error) {
	if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		errCh <- err
	}
}

func receiveSubscribedPacket(ctx context.Context, ch <-chan derpbind.Packet) (derpbind.Packet, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return derpbind.Packet{}, net.ErrClosed
		}
		return pkt, nil
	case <-ctx.Done():
		return derpbind.Packet{}, ctx.Err()
	}
}
