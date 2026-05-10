// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
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
	auth := externalPeerControlAuthForToken(session.token)

	for {
		claim, peerDERP, ok, err := receiveExternalAttachClaim(ctx, claimCh, auth)
		if err != nil {
			cleanupSession()
			return nil, err
		}
		if !ok {
			continue
		}
		decision, _ := session.gate.Accept(time.Now(), claim)
		if rejected, err := rejectExternalAttachClaim(ctx, session, peerDERP, decision, auth); err != nil {
			cleanupSession()
			return nil, err
		} else if rejected {
			continue
		}

		return acceptExternalAttachClaim(ctx, cfg, session, pathEmitter, cleanupSession, claim, peerDERP, decision, auth)
	}
}

func receiveExternalAttachClaim(ctx context.Context, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth) (rendezvous.Claim, key.NodePublic, bool, error) {
	pkt, err := receiveSubscribedPacket(ctx, claimCh)
	if err != nil {
		return rendezvous.Claim{}, key.NodePublic{}, false, err
	}
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return rendezvous.Claim{}, key.NodePublic{}, false, nil
	}
	if err != nil || env.Type != envelopeClaim || env.Claim == nil {
		return rendezvous.Claim{}, key.NodePublic{}, false, nil
	}
	peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
	return *env.Claim, peerDERP, true, nil
}

func rejectExternalAttachClaim(ctx context.Context, session *relaySession, peerDERP key.NodePublic, decision rendezvous.Decision, auth externalPeerControlAuth) (bool, error) {
	if decision.Accepted {
		return false, nil
	}
	err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth)
	return true, err
}

func acceptExternalAttachClaim(
	ctx context.Context,
	cfg AttachListenConfig,
	session *relaySession,
	pathEmitter *transportPathEmitter,
	cleanupSession func(),
	claim rendezvous.Claim,
	peerDERP key.NodePublic,
	decision rendezvous.Decision,
	auth externalPeerControlAuth,
) (net.Conn, error) {
	localCandidates := attachAcceptedCandidates(ctx, cfg, session, &decision)
	pathEmitter.Emit(StateClaimed)
	transportCtx, transportCancel, transportManager, transportCleanup, err := startExternalAttachTransport(ctx, cfg, session, peerDERP, localCandidates)
	if err != nil {
		cleanupSession()
		return nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)

	adapter, quicListener, err := listenExternalAttachQUIC(transportCtx, session, transportManager, claim)
	if err != nil {
		cleanupExternalAttachTransport(transportCleanup, transportCancel)
		cleanupSession()
		return nil, err
	}
	return acceptExternalAttachQUICConn(ctx, session, pathEmitter, cleanupSession, peerDERP, auth, decision, transportCtx, transportCancel, transportManager, transportCleanup, adapter, quicListener)
}

func attachAcceptedCandidates(ctx context.Context, cfg AttachListenConfig, session *relaySession, decision *rendezvous.Decision) []net.Addr {
	if decision.Accept != nil && !cfg.ForceRelay {
		decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap, publicSessionPortmap(session))
	}
	if decision.Accept == nil {
		return parseCandidateStrings(nil)
	}
	return parseCandidateStrings(decision.Accept.Candidates)
}

func startExternalAttachTransport(ctx context.Context, cfg AttachListenConfig, session *relaySession, peerDERP key.NodePublic, localCandidates []net.Addr) (context.Context, context.CancelFunc, *transport.Manager, func(), error) {
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		session.token,
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
		return nil, nil, nil, nil, err
	}
	return transportCtx, transportCancel, transportManager, transportCleanup, nil
}

func listenExternalAttachQUIC(transportCtx context.Context, session *relaySession, transportManager *transport.Manager, claim rendezvous.Claim) (*quicpath.Adapter, *quic.Listener, error) {
	adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
	quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(session.quicIdentity, claim.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return adapter, quicListener, nil
}

func cleanupExternalAttachTransport(transportCleanup func(), transportCancel context.CancelFunc) {
	if transportCleanup != nil {
		transportCleanup()
	}
	if transportCancel != nil {
		transportCancel()
	}
}

func acceptExternalAttachQUICConn(
	ctx context.Context,
	session *relaySession,
	pathEmitter *transportPathEmitter,
	cleanupSession func(),
	peerDERP key.NodePublic,
	auth externalPeerControlAuth,
	decision rendezvous.Decision,
	transportCtx context.Context,
	transportCancel context.CancelFunc,
	transportManager *transport.Manager,
	transportCleanup func(),
	adapter *quicpath.Adapter,
	quicListener *quic.Listener,
) (net.Conn, error) {
	if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
		cleanupExternalAttachListener(quicListener, adapter)
		cleanupExternalAttachTransport(transportCleanup, transportCancel)
		cleanupSession()
		return nil, err
	}
	quicConn, err := quicListener.Accept(ctx)
	if err != nil {
		cleanupExternalAttachListener(quicListener, adapter)
		cleanupExternalAttachTransport(transportCleanup, transportCancel)
		cleanupSession()
		return nil, err
	}
	streamConn, err := openExternalNativeQUICStreamForConn(ctx, quicConn, false)
	if err != nil {
		_ = quicConn.CloseWithError(1, "accept attach stream failed")
		cleanupExternalAttachListener(quicListener, adapter)
		cleanupExternalAttachTransport(transportCleanup, transportCancel)
		cleanupSession()
		return nil, err
	}
	var unsubscribeActiveClaims func()
	cleanupConn := newExternalAttachCleanup(session, pathEmitter, cleanupSession, quicConn, quicListener, adapter, transportManager, transportCleanup, transportCancel, func() {
		if unsubscribeActiveClaims != nil {
			unsubscribeActiveClaims()
		}
	})
	unsubscribeActiveClaims = watchExternalAttachClaims(transportCtx, session, cleanupConn, auth)
	return wrapExternalAttachConn(quicConn, streamConn, cleanupConn), nil
}

func cleanupExternalAttachListener(quicListener *quic.Listener, adapter *quicpath.Adapter) {
	if quicListener != nil {
		_ = quicListener.Close()
	}
	if adapter != nil {
		_ = adapter.Close()
	}
}

func newExternalAttachCleanup(
	session *relaySession,
	pathEmitter *transportPathEmitter,
	cleanupSession func(),
	quicConn *quic.Conn,
	quicListener *quic.Listener,
	adapter *quicpath.Adapter,
	transportManager *transport.Manager,
	transportCleanup func(),
	transportCancel context.CancelFunc,
	unsubscribeActiveClaims func(),
) func() {
	var cleanupConnOnce sync.Once
	return func() {
		cleanupConnOnce.Do(func() {
			if unsubscribeActiveClaims != nil {
				unsubscribeActiveClaims()
			}
			pathEmitter.Complete(transportManager)
			_ = quicConn.CloseWithError(0, "")
			cleanupExternalAttachListener(quicListener, adapter)
			cleanupExternalAttachTransport(transportCleanup, transportCancel)
			cleanupSession()
		})
	}
}

func watchExternalAttachClaims(transportCtx context.Context, session *relaySession, cleanupConn func(), auth externalPeerControlAuth) func() {
	activeClaimCh, unsubscribeActiveClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	claimErrCh := rejectAdditionalShareClaims(transportCtx, session.derp, session.gate, activeClaimCh, auth)
	go func() {
		for err := range claimErrCh {
			if err != nil {
				cleanupConn()
				return
			}
		}
	}()
	return unsubscribeActiveClaims
}

func dialAttachExternal(ctx context.Context, cfg AttachDialConfig, tok token.Token) (net.Conn, error) {
	runtime, err := newAttachDialRuntime(ctx, cfg, tok)
	if err != nil {
		return nil, err
	}
	claim := runtime.claim()
	decision, err := runtime.sendClaim(ctx, claim)
	if err != nil {
		runtime.close()
		return nil, err
	}
	if err := derptunClaimDecisionErr(decision); err != nil {
		runtime.close()
		return nil, err
	}
	conn, err := runtime.dial(ctx, cfg, decision)
	if err != nil {
		runtime.close()
		return nil, err
	}
	return conn, nil
}

type attachDialRuntime struct {
	tok             token.Token
	listenerDERP    key.NodePublic
	dm              *tailcfg.DERPMap
	derpClient      *derpbind.Client
	probeConn       net.PacketConn
	pm              publicPortmap
	clientIdentity  quicpath.SessionIdentity
	localCandidates []string
}

func newAttachDialRuntime(ctx context.Context, cfg AttachDialConfig, tok token.Token) (*attachDialRuntime, error) {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return nil, ErrUnknownSession
	}
	dm, derpClient, err := openDerptunDialDERP(ctx, tok)
	if err != nil {
		return nil, err
	}
	runtime := &attachDialRuntime{tok: tok, listenerDERP: listenerDERP, dm: dm, derpClient: derpClient}
	if err := runtime.openProbe(ctx, cfg); err != nil {
		runtime.close()
		return nil, err
	}
	return runtime, nil
}

func (r *attachDialRuntime) openProbe(ctx context.Context, cfg AttachDialConfig) error {
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

func (r *attachDialRuntime) close() {
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

func (r *attachDialRuntime) claim() rendezvous.Claim {
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

func (r *attachDialRuntime) sendClaim(ctx context.Context, claim rendezvous.Claim) (rendezvous.Decision, error) {
	return sendClaimAndReceiveDecision(ctx, r.derpClient, r.listenerDERP, claim, externalPeerControlAuthForToken(r.tok))
}

func (r *attachDialRuntime) dial(ctx context.Context, cfg AttachDialConfig, decision rendezvous.Decision) (net.Conn, error) {
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)

	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		r.tok,
		r.probeConn,
		r.dm,
		r.derpClient,
		r.listenerDERP,
		parseCandidateStrings(r.localCandidates),
		r.pm,
		cfg.ForceRelay,
	)
	if err != nil {
		transportCancel()
		return nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(r.clientIdentity, r.tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		return nil, err
	}
	streamConn, err := openExternalNativeQUICStreamForConn(ctx, quicConn, true)
	if err != nil {
		_ = quicConn.CloseWithError(1, "open attach stream failed")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		return nil, err
	}

	return wrapExternalAttachConn(quicConn, streamConn, func() {
		pathEmitter.Complete(transportManager)
		_ = quicConn.CloseWithError(0, "")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		r.close()
	}), nil
}
