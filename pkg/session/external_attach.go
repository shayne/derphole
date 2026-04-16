package session

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/types/key"
)

type externalAttachConn struct {
	net.Conn
	stream           *quic.Stream
	cleanupRequested chan struct{}
	closeOnce        sync.Once
	once             sync.Once
	cleanup          func()
}

// Give the peer a brief window to drain the final stream bytes and FIN before
// tearing down the underlying QUIC transport.
const externalAttachCloseGrace = 2 * time.Second

func wrapExternalAttachConn(quicConn *quic.Conn, streamConn *quic.Stream, cleanup func()) net.Conn {
	conn := &externalAttachConn{
		Conn:             quicpath.WrapStream(quicConn, streamConn),
		stream:           streamConn,
		cleanupRequested: make(chan struct{}),
		cleanup:          cleanup,
	}
	go func() {
		select {
		case <-quicConn.Context().Done():
		case <-conn.cleanupRequested:
			timer := time.NewTimer(externalAttachCloseGrace)
			defer timer.Stop()
			select {
			case <-quicConn.Context().Done():
			case <-timer.C:
			}
		}
		conn.once.Do(func() {
			if conn.cleanup != nil {
				conn.cleanup()
			}
		})
	}()
	return conn
}

func (c *externalAttachConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.cleanupRequested)
	})
	if c.stream != nil {
		c.stream.CancelRead(0)
		return c.stream.Close()
	}
	return c.Conn.Close()
}

func issuePublicQUICSession(ctx context.Context, capabilities uint32) (string, *relaySession, error) {
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
	quicIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}

	tokValue := token.Token{
		Version:         token.SupportedVersion,
		SessionID:       sessionID,
		ExpiresUnix:     time.Now().Add(time.Hour).Unix(),
		BootstrapRegion: uint16(node.RegionID),
		DERPPublic:      derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:      quicIdentity.Public,
		BearerSecret:    bearerSecret,
		Capabilities:    capabilities,
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
		probeConn:    probeConn,
		derp:         derpClient,
		token:        tokValue,
		gate:         rendezvous.NewGate(tokValue),
		derpMap:      dm,
		quicIdentity: quicIdentity,
	}
	attachPublicPortmap(session, newBoundPublicPortmap(probeConn, nil))
	return tok, session, nil
}

func issuePublicAttachSession(ctx context.Context) (string, *relaySession, error) {
	return issuePublicQUICSession(ctx, token.CapabilityAttach)
}

func listenAttachExternal(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	tok, session, err := issuePublicAttachSession(ctx)
	if err != nil {
		return nil, err
	}

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)

	var cleanupOnce sync.Once
	cleanupSession := func() {
		cleanupOnce.Do(func() {
			_ = session.derp.Close()
			closePublicSessionTransport(session)
		})
	}

	listener := &AttachListener{Token: tok}
	listener.accept = func(ctx context.Context) (net.Conn, error) {
		return acceptExternalAttachConn(ctx, cfg, session, pathEmitter, cleanupSession)
	}
	listener.close = func() error {
		cleanupSession()
		return nil
	}
	return listener, nil
}

func acceptExternalAttachConn(
	ctx context.Context,
	cfg AttachListenConfig,
	session *relaySession,
	pathEmitter *transportPathEmitter,
	cleanupSession func(),
) (net.Conn, error) {
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	for {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			cleanupSession()
			return nil, err
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			continue
		}

		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := session.gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
				cleanupSession()
				return nil, err
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
		transportManager, transportCleanup, err := startExternalTransportManager(
			transportCtx,
			session.probeConn,
			session.derpMap,
			session.derp,
			peerDERP,
			localCandidates,
			publicSessionPortmap(session),
			cfg.ForceRelay,
		)
		if err != nil {
			transportCancel()
			cleanupSession()
			return nil, err
		}
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)

		adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
		quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic), quicpath.DefaultQUICConfig())
		if err != nil {
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			cleanupSession()
			return nil, err
		}

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			cleanupSession()
			return nil, err
		}

		quicConn, err := quicListener.Accept(ctx)
		if err != nil {
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			cleanupSession()
			return nil, err
		}
		streamConn, err := openExternalNativeQUICStreamForConn(ctx, quicConn, false)
		if err != nil {
			_ = quicConn.CloseWithError(1, "accept attach stream failed")
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			cleanupSession()
			return nil, err
		}

		activeClaimCh, unsubscribeActiveClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return isClaimPayload(pkt.Payload)
		})
		claimErrCh := rejectAdditionalShareClaims(transportCtx, session.derp, session.gate, activeClaimCh)

		var cleanupConnOnce sync.Once
		cleanupConn := func() {
			cleanupConnOnce.Do(func() {
				unsubscribeActiveClaims()
				pathEmitter.Complete(transportManager)
				_ = quicConn.CloseWithError(0, "")
				_ = quicListener.Close()
				_ = adapter.Close()
				transportCleanup()
				transportCancel()
				cleanupSession()
			})
		}
		go func() {
			for err := range claimErrCh {
				if err != nil {
					cleanupConn()
					return
				}
			}
		}()

		return wrapExternalAttachConn(quicConn, streamConn, cleanupConn), nil
	}
}

func dialAttachExternal(ctx context.Context, cfg AttachDialConfig, tok token.Token) (net.Conn, error) {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return nil, ErrUnknownSession
	}

	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return nil, errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, err
	}

	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		_ = derpClient.Close()
		return nil, err
	}
	pm := newBoundPublicPortmap(probeConn, cfg.Emitter)

	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, err
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

	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, err
	}
	if !decision.Accepted {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		if decision.Reject != nil {
			return nil, errors.New(decision.Reject.Reason)
		}
		return nil, errors.New("claim rejected")
	}

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)

	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		probeConn,
		dm,
		derpClient,
		listenerDERP,
		parseCandidateStrings(localCandidates),
		pm,
		cfg.ForceRelay,
	)
	if err != nil {
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, err
	}
	streamConn, err := openExternalNativeQUICStreamForConn(ctx, quicConn, true)
	if err != nil {
		_ = quicConn.CloseWithError(1, "open attach stream failed")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, err
	}

	return wrapExternalAttachConn(quicConn, streamConn, func() {
		pathEmitter.Complete(transportManager)
		_ = quicConn.CloseWithError(0, "")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
	}), nil
}
