package session

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/stream"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/wg"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func issuePublicShareSession(ctx context.Context, cfg ShareConfig) (string, *relaySession, error) {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return "", nil, err
	}
	node := firstDERPNode(dm, 0)
	if node == nil {
		return "", nil, errors.New("no DERP node available")
	}

	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return "", nil, err
	}

	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}
	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}
	wgPrivate, wgPublic, err := wg.GenerateKeypair()
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}
	_, discoPublic, err := wg.GenerateKeypair()
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}

	tokValue := token.Token{
		Version:         token.SupportedVersion,
		SessionID:       sessionID,
		ExpiresUnix:     time.Now().Add(10 * time.Minute).Unix(),
		BootstrapRegion: uint16(node.RegionID),
		DERPPublic:      derpPublicKeyRaw32(derpClient.PublicKey()),
		WGPublic:        wgPublic,
		DiscoPublic:     discoPublic,
		BearerSecret:    bearerSecret,
		Capabilities:    token.CapabilityShare,
		ShareTargetAddr: cfg.TargetAddr,
		DefaultBindHost: "127.0.0.1",
		DefaultBindPort: 0,
	}
	tok, err := token.Encode(tokValue)
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}

	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}

	session := &relaySession{
		probeConn: probeConn,
		derp:      derpClient,
		token:     tokValue,
		gate:      rendezvous.NewGate(tokValue),
		derpMap:   dm,
		wgPrivate: wgPrivate,
	}
	return tok, session, nil
}

func shareExternal(ctx context.Context, cfg ShareConfig) (string, error) {
	tok, session, err := issuePublicShareSession(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer session.derp.Close()
	defer session.probeConn.Close()
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

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
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			continue
		}

		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := session.gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
				return tok, err
			}
			continue
		}

		if decision.Accept != nil {
			decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap)
		}
		pathEmitter.Emit(StateClaimed)
		transportCtx, transportCancel := context.WithCancel(ctx)
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, cfg.ForceRelay)
		if err != nil {
			transportCancel()
			return tok, err
		}
		defer transportCancel()
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		cert, err := quicpath.GenerateSelfSignedCertificate()
		if err != nil {
			return tok, err
		}
		adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
		defer adapter.Close()
		quicListener, err := quic.Listen(adapter, quicpath.DefaultTLSConfig(cert, quicpath.ServerName), quicpath.DefaultQUICConfig())
		if err != nil {
			return tok, err
		}
		defer quicListener.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		claimErrCh := rejectAdditionalShareClaims(ctx, session.derp, session.gate, claimCh)
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

	_, senderPublic, err := wg.GenerateKeypair()
	if err != nil {
		return err
	}
	_, senderDisco, err := wg.GenerateKeypair()
	if err != nil {
		return err
	}

	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		WGPublic:     senderPublic,
		DiscoPublic:  senderDisco,
		Candidates:   publicProbeCandidates(ctx, probeConn, dm),
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeClaim, Claim: &claim}); err != nil {
		return err
	}

	decision, err := receiveDecision(ctx, derpClient, listenerDERP)
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
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	defer adapter.Close()
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
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

		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			if emitter != nil {
				emitter.Debug("backend-dial-failed")
			}
			_ = overlayConn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
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
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeClaim || env.Claim == nil {
				continue
			}

			peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
			decision, _ := gate.Accept(time.Now(), *env.Claim)
			if err := sendEnvelope(ctx, client, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
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
