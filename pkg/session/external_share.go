package session

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/stream"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/wg"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func issuePublicShareSession(ctx context.Context, cfg ShareConfig) (string, *relaySession, error) {
	dm, err := derpbind.FetchMap(ctx, derpbind.PublicDERPMapURL)
	if err != nil {
		return "", nil, err
	}
	node := firstDERPNode(dm, 0)
	if node == nil {
		return "", nil, errors.New("no DERP node available")
	}

	derpClient, err := derpbind.NewClient(ctx, node, derpServerURL(node))
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
		pkt, err := session.derp.Receive(ctx)
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

		_, listenerAddr, senderAddr := wg.DeriveAddresses(session.token.SessionID)
		sessionNode, err := wg.NewNode(wg.Config{
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.WGPublic,
			LocalAddr:     listenerAddr,
			PeerAddr:      senderAddr,
			PacketConn:    session.probeConn,
			DERPClient:    session.derp,
			PeerDERP:      peerDERP,
			PathSelector:  transportManager,
		})
		if err != nil {
			return tok, err
		}
		defer sessionNode.Close()

		ln, err := sessionNode.ListenTCP(overlayPort)
		if err != nil {
			return tok, err
		}
		defer ln.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		return tok, serveOverlayListener(ctx, ln, cfg.TargetAddr, cfg.Emitter)
	}
}

func openExternal(ctx context.Context, cfg OpenConfig, tok token.Token) error {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return ErrUnknownSession
	}

	dm, err := derpbind.FetchMap(ctx, derpbind.PublicDERPMapURL)
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, derpServerURL(node))
	if err != nil {
		return err
	}
	defer derpClient.Close()

	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer probeConn.Close()

	senderPrivate, senderPublic, err := wg.GenerateKeypair()
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

	_, listenerAddr, senderAddr := wg.DeriveAddresses(tok.SessionID)
	sessionNode, err := wg.NewNode(wg.Config{
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.WGPublic,
		LocalAddr:     senderAddr,
		PeerAddr:      listenerAddr,
		PacketConn:    probeConn,
		DERPClient:    derpClient,
		PeerDERP:      listenerDERP,
		PathSelector:  transportManager,
	})
	if err != nil {
		return err
	}
	defer sessionNode.Close()

	listener, err := openLocalListener(cfg, tok)
	if err != nil {
		return err
	}
	defer listener.Close()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		return dialOverlay(ctx, sessionNode, netip.AddrPortFrom(listenerAddr, overlayPort))
	}, cfg.Emitter)
}

func serveOverlayListener(ctx context.Context, listener net.Listener, targetAddr string, emitter *telemetry.Emitter) error {
	for {
		overlayConn, err := acceptOverlay(ctx, listener)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			if emitter != nil {
				emitter.Debug("backend-dial-failed")
			}
			_ = overlayConn.Close()
			continue
		}

		go func() {
			defer overlayConn.Close()
			defer backendConn.Close()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
}
