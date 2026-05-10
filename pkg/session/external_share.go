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
	"go4.org/mem"
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
	defer session.derp.Close()
	defer closePublicSessionTransport(session)
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()
	auth := externalPeerControlAuthForToken(session.token)

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	if cfg.TokenSink != nil {
		select {
		case cfg.TokenSink <- tok:
		case <-ctx.Done():
			return tok, ctx.Err()
		}
	}

	for {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			if ctx.Err() != nil {
				return tok, ctx.Err()
			}
			return tok, err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			continue
		}

		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := session.gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
				return tok, err
			}
			continue
		}

		if decision.Accept != nil && !cfg.ForceRelay {
			decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap, publicSessionPortmap(session))
		}
		localCandidates := parseCandidateStrings(nil)
		if decision.Accept != nil {
			localCandidates = parseCandidateStrings(decision.Accept.Candidates)
		}
		pathEmitter.Emit(StateClaimed)
		transportCtx, transportCancel := context.WithCancel(ctx)
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.token, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay)
		if err != nil {
			transportCancel()
			return tok, err
		}
		defer transportCancel()
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
		defer adapter.Close()
		quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic), quicpath.DefaultQUICConfig())
		if err != nil {
			return tok, err
		}
		defer quicListener.Close()

		if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
			return tok, err
		}
		claimErrCh := rejectAdditionalShareClaims(ctx, session.derp, session.gate, claimCh, auth)
		quicConn, err := quicListener.Accept(ctx)
		if err != nil {
			return tok, err
		}
		defer quicConn.CloseWithError(0, "")
		return tok, serveQUICListenerWithClaimRejections(ctx, quicConn, cfg.TargetAddr, cfg.Emitter, claimErrCh)
	}
}

func openExternal(ctx context.Context, cfg OpenConfig, tok token.Token) error {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return ErrUnknownSession
	}

	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	defer derpClient.Close()

	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer probeConn.Close()
	pm := newBoundPublicPortmap(probeConn, cfg.Emitter)
	defer pm.Close()

	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return err
	}

	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = publicProbeCandidates(ctx, probeConn, dm, pm)
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   clientIdentity.Public,
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	auth := externalPeerControlAuthForToken(tok)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim, auth)
	if err != nil {
		return err
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, tok, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
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
	defer adapter.Close()
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer quicConn.CloseWithError(0, "")

	listener, err := openLocalListener(cfg, tok)
	if err != nil {
		return err
	}
	defer listener.Close()
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
		streamConn, err := conn.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
				return nil
			}
			return err
		}
		overlayConn := quicpath.WrapStream(conn, streamConn)
		select {
		case slots <- struct{}{}:
		default:
			if emitter != nil {
				emitter.Debug("stream-limit-reached")
			}
			_ = overlayConn.Close()
			continue
		}

		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			if emitter != nil {
				emitter.Debug("backend-dial-failed")
			}
			<-slots
			_ = overlayConn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer overlayConn.Close()
			defer backendConn.Close()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
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
			pkt, err := receiveSubscribedPacket(ctx, claimCh)
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					errCh <- err
				}
				return
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err != nil || env.Type != envelopeClaim || env.Claim == nil {
				continue
			}

			peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
			decision, _ := gate.Accept(time.Now(), *env.Claim)
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
