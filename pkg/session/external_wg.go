// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"github.com/shayne/derphole/pkg/traversal"
	wgtransport "github.com/shayne/derphole/pkg/wg"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type externalWGRole uint8

const (
	externalWGRoleListener externalWGRole = iota + 1
	externalWGRoleSender
)

const (
	externalWGTransportLabel = "batched"
	externalWGStdioPort      = 7000
)

type externalWGTunnelConfig struct {
	SessionID      [16]byte
	Role           externalWGRole
	PacketConn     net.PacketConn
	Transport      string
	DERPClient     *derpbind.Client
	PeerDERP       key.NodePublic
	PathSelector   wgtransport.PathSelector
	DirectEndpoint string
	PrivateKey     [32]byte
	PeerPublicKey  [32]byte
}

type externalWGTunnel struct {
	node      *wgtransport.Node
	localAddr netip.Addr
	peerAddr  netip.Addr
}

func newExternalWGTunnel(cfg externalWGTunnelConfig) (*externalWGTunnel, error) {
	if cfg.Role != externalWGRoleListener && cfg.Role != externalWGRoleSender {
		return nil, errors.New("invalid external wg role")
	}

	_, listenerAddr, senderAddr := wgtransport.DeriveAddresses(cfg.SessionID)
	localAddr := listenerAddr
	peerAddr := senderAddr
	if cfg.Role == externalWGRoleSender {
		localAddr = senderAddr
		peerAddr = listenerAddr
	}

	node, err := wgtransport.NewNode(wgtransport.Config{
		PrivateKey:     cfg.PrivateKey,
		PeerPublicKey:  cfg.PeerPublicKey,
		LocalAddr:      localAddr,
		PeerAddr:       peerAddr,
		PacketConn:     cfg.PacketConn,
		Transport:      cfg.Transport,
		DERPClient:     cfg.DERPClient,
		PeerDERP:       cfg.PeerDERP,
		PathSelector:   cfg.PathSelector,
		DirectEndpoint: cfg.DirectEndpoint,
	})
	if err != nil {
		return nil, err
	}

	return &externalWGTunnel{
		node:      node,
		localAddr: localAddr,
		peerAddr:  peerAddr,
	}, nil
}

func (t *externalWGTunnel) Close() error {
	if t == nil || t.node == nil {
		return nil
	}
	return t.node.Close()
}

func (t *externalWGTunnel) ListenTCP(port uint16) (net.Listener, error) {
	if t == nil || t.node == nil {
		return nil, net.ErrClosed
	}
	return t.node.ListenTCP(port)
}

func (t *externalWGTunnel) DialTCP(ctx context.Context, port uint16) (net.Conn, error) {
	if t == nil || t.node == nil {
		return nil, net.ErrClosed
	}
	return t.node.DialTCP(ctx, netip.AddrPortFrom(t.peerAddr, port))
}

func clampExternalWGParallel(n int) int {
	if n < 1 {
		return 1
	}
	if n > MaxParallelStripes {
		return MaxParallelStripes
	}
	return n
}

func startExternalWGTransportManager(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
	localCandidates []net.Addr,
	pm publicPortmap,
	forceRelay bool,
	authOpt ...externalPeerControlAuth,
) (*transport.Manager, func(), error) {
	auth := optionalPeerControlAuth(authOpt)
	controlCh, unsubscribe := derpClient.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportControlPayload(pkt.Payload)
	})

	cfg := transport.ManagerConfig{
		RelayAddr:               relayTransportAddr(),
		DirectConn:              nil,
		DisableDirectReads:      true,
		Portmap:                 pm,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 1 * time.Second,
		DirectStaleTimeout:      10 * time.Second,
		SendControl: func(ctx context.Context, msg transport.ControlMessage) error {
			return sendTransportControl(ctx, derpClient, peerDERP, msg, auth)
		},
		ReceiveControl: func(ctx context.Context) (transport.ControlMessage, error) {
			return receiveTransportControl(ctx, controlCh, auth)
		},
	}
	if !forceRelay {
		stunPackets := make(chan traversal.STUNPacket, 256)
		cfg.DirectConn = conn
		cfg.DirectBatchConn = publicDirectBatchConn(conn)
		cfg.HandleSTUNPacket = func(payload []byte, addr net.Addr) {
			packet, ok := publicSTUNPacket(payload, addr)
			if !ok {
				return
			}
			select {
			case stunPackets <- packet:
			default:
			}
		}
		cfg.CandidateSource = publicCandidateSource(conn, dm, pm, localCandidates, stunPackets)
	}

	manager := newTransportManager(cfg)
	if err := manager.Start(ctx); err != nil {
		unsubscribe()
		return nil, nil, err
	}
	return manager, func() {
		unsubscribe()
	}, nil
}

func dialExternalWGConns(ctx context.Context, tunnel *externalWGTunnel, port uint16, count int) ([]net.Conn, error) {
	count = clampExternalWGParallel(count)
	conns := make([]net.Conn, 0, count)
	for i := 0; i < count; i++ {
		conn, err := tunnel.DialTCP(ctx, port)
		if err != nil {
			closeExternalNativeTCPConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func acceptExternalWGConns(ctx context.Context, ln net.Listener, count int) ([]net.Conn, error) {
	count = clampExternalWGParallel(count)
	conns := make([]net.Conn, 0, count)
	for i := 0; i < count; i++ {
		conn, err := acceptNetListener(ctx, ln)
		if err != nil {
			closeExternalNativeTCPConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

type externalWGSendRuntime struct {
	tok             token.Token
	countedSrc      *byteCountingReadCloser
	listenerDERP    key.NodePublic
	dm              *tailcfg.DERPMap
	derpClient      *derpbind.Client
	probeConn       net.PacketConn
	pm              publicPortmap
	senderPrivate   [32]byte
	senderPublic    [32]byte
	localCandidates []string
	decision        rendezvous.Decision
	auth            externalPeerControlAuth
}

func (r *externalWGSendRuntime) Close() {
	if r == nil {
		return
	}
	if r.countedSrc != nil {
		_ = r.countedSrc.Close()
	}
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

func sendExternalViaWGTunnel(ctx context.Context, cfg SendConfig) (retErr error) {
	runtime, err := newExternalWGSendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()

	ackCh, abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalWGSendPeer(runtime)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, runtime.derpClient, runtime.listenerDERP, abortCh, heartbeatCh, runtime.countedSrc.Count, runtime.auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, runtime.derpClient, runtime.listenerDERP, runtime.countedSrc.Count, runtime.auth)

	return sendExternalWGRuntime(ctx, cfg, runtime, ackCh)
}

func newExternalWGSendRuntime(ctx context.Context, cfg SendConfig) (_ *externalWGSendRuntime, err error) {
	runtime := &externalWGSendRuntime{}
	defer func() {
		if err != nil {
			runtime.Close()
		}
	}()
	runtime.tok, err = decodeExternalWGSendToken(cfg.Token)
	if err != nil {
		return nil, err
	}
	runtime.countedSrc, err = openExternalWGSendSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	runtime.listenerDERP, err = externalWGListenerDERP(runtime.tok)
	if err != nil {
		return nil, err
	}
	runtime.dm, runtime.derpClient, err = openExternalWGDERPClient(ctx, runtime.tok)
	if err != nil {
		return nil, err
	}
	runtime.probeConn, runtime.pm, err = openExternalWGProbeConn(cfg.Emitter)
	if err != nil {
		return nil, err
	}
	runtime.senderPrivate, runtime.senderPublic, err = wgtransport.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	runtime.localCandidates = externalWGSendCandidates(ctx, cfg, runtime)
	runtime.auth = externalPeerControlAuthForToken(runtime.tok)
	runtime.decision, err = sendExternalWGClaim(ctx, cfg, runtime)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func decodeExternalWGSendToken(rawToken string) (token.Token, error) {
	tok, err := token.Decode(rawToken, time.Now())
	if err != nil {
		return token.Token{}, err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return token.Token{}, ErrUnknownSession
	}
	return tok, nil
}

func openExternalWGSendSource(ctx context.Context, cfg SendConfig) (*byteCountingReadCloser, error) {
	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return newByteCountingReadCloser(src), nil
}

func externalWGListenerDERP(tok token.Token) (key.NodePublic, error) {
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return key.NodePublic{}, ErrUnknownSession
	}
	return listenerDERP, nil
}

func openExternalWGDERPClient(ctx context.Context, tok token.Token) (*tailcfg.DERPMap, *derpbind.Client, error) {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, nil, err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return nil, nil, errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, nil, err
	}
	return dm, derpClient, nil
}

func openExternalWGProbeConn(emitter *telemetry.Emitter) (net.PacketConn, publicPortmap, error) {
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, nil, err
	}
	pm := newBoundPublicPortmap(probeConn, emitter)
	return probeConn, pm, nil
}

func externalWGSendCandidates(ctx context.Context, cfg SendConfig, runtime *externalWGSendRuntime) []string {
	if cfg.ForceRelay {
		return nil
	}
	return publicProbeCandidates(ctx, runtime.probeConn, runtime.dm, runtime.pm)
}

func sendExternalWGClaim(ctx context.Context, cfg SendConfig, runtime *externalWGSendRuntime) (rendezvous.Decision, error) {
	parallel := clampExternalWGParallel(externalParallelTCPConnCount(cfg.ParallelPolicy))
	claim := rendezvous.Claim{
		Version:      runtime.tok.Version,
		SessionID:    runtime.tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(runtime.derpClient.PublicKey()),
		QUICPublic:   runtime.senderPublic,
		Parallel:     parallel,
		Candidates:   runtime.localCandidates,
		Capabilities: runtime.tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(runtime.tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, runtime.derpClient, runtime.listenerDERP, claim, runtime.auth)
	if err != nil {
		return rendezvous.Decision{}, err
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return rendezvous.Decision{}, errors.New(decision.Reject.Reason)
		}
		return rendezvous.Decision{}, errors.New("claim rejected")
	}
	if decision.Accept == nil {
		return rendezvous.Decision{}, errors.New("accepted decision missing accept payload")
	}
	return decision, nil
}

func subscribeExternalWGSendPeer(runtime *externalWGSendRuntime) (<-chan derpbind.Packet, <-chan derpbind.Packet, <-chan derpbind.Packet, func()) {
	ackCh, unsubscribeAck := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == runtime.listenerDERP && isAckOrAbortPayload(pkt.Payload)
	})
	abortCh, unsubscribeAbort := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == runtime.listenerDERP && isAbortPayload(pkt.Payload)
	})
	heartbeatCh, unsubscribeHeartbeat := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == runtime.listenerDERP && isHeartbeatPayload(pkt.Payload)
	})
	return ackCh, abortCh, heartbeatCh, func() {
		unsubscribeAck()
		unsubscribeAbort()
		unsubscribeHeartbeat()
	}
}

func sendExternalWGRuntime(ctx context.Context, cfg SendConfig, runtime *externalWGSendRuntime, ackCh <-chan derpbind.Packet) error {
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalWGTransportManager(
		transportCtx,
		runtime.probeConn,
		runtime.dm,
		runtime.derpClient,
		runtime.listenerDERP,
		parseCandidateStrings(runtime.localCandidates),
		runtime.pm,
		cfg.ForceRelay,
		runtime.auth,
	)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, runtime.decision)

	tunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     runtime.tok.SessionID,
		Role:          externalWGRoleSender,
		PacketConn:    runtime.probeConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    runtime.derpClient,
		PeerDERP:      runtime.listenerDERP,
		PathSelector:  transportManager,
		PrivateKey:    runtime.senderPrivate,
		PeerPublicKey: runtime.tok.QUICPublic,
	})
	if err != nil {
		return err
	}
	defer func() { _ = tunnel.Close() }()

	conns, err := dialExternalWGConns(ctx, tunnel, externalWGStdioPort, runtime.decision.Accept.Parallel)
	if err != nil {
		return err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("wg-stripes=" + strconv.Itoa(len(conns)))
	}
	if err := sendExternalNativeTCPDirect(ctx, runtime.countedSrc, conns); err != nil {
		return err
	}
	if err := waitForPeerAck(ctx, ackCh, runtime.countedSrc.Count(), runtime.auth); err != nil {
		return err
	}
	return nil
}

func listenExternalViaWGTunnel(ctx context.Context, cfg ListenConfig) (retTok string, retErr error) {
	tok, session, err := issuePublicSession(ctx)
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, session)
	defer closePublicSessionTransport(session)
	defer func() { _ = session.derp.Close() }()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()
	auth := externalPeerControlAuthForToken(session.token)

	if err := sendExternalWGListenToken(ctx, cfg.TokenSink, tok); err != nil {
		return tok, err
	}

	return tok, serveExternalWGClaims(ctx, session, claimCh, auth, pathEmitter, cfg, &retErr)
}

func sendExternalWGListenToken(ctx context.Context, tokenSink chan<- string, tok string) error {
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

func serveExternalWGClaims(ctx context.Context, session *relaySession, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg ListenConfig, retErr *error) error {
	for {
		claim, err := receiveExternalWGClaim(ctx, claimCh, auth)
		if err != nil {
			return err
		}
		if claim == nil {
			continue
		}
		done, err := handleExternalWGClaim(ctx, session, *claim, auth, pathEmitter, cfg, retErr)
		if done || err != nil {
			return err
		}
	}
}

func receiveExternalWGClaim(ctx context.Context, claimCh <-chan derpbind.Packet, auth externalPeerControlAuth) (*rendezvous.Claim, error) {
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

func handleExternalWGClaim(ctx context.Context, session *relaySession, claim rendezvous.Claim, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg ListenConfig, retErr *error) (bool, error) {
	peerDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
	decision, _ := session.gate.Accept(time.Now(), claim)
	if !decision.Accepted {
		err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth)
		return false, err
	}
	if decision.Accept == nil {
		return true, errors.New("accepted decision missing accept payload")
	}
	decision.Accept.Parallel = clampExternalWGParallel(claim.Parallel)
	decision.Accept.Candidates = publicInitialProbeCandidates(session.probeConn, publicSessionPortmap(session))
	emitExternalWGDebug(cfg.Emitter, "claim-accepted")
	return true, receiveExternalWGAcceptedClaim(ctx, session, claim, decision, peerDERP, auth, pathEmitter, cfg, retErr)
}

func receiveExternalWGAcceptedClaim(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, peerDERP key.NodePublic, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg ListenConfig, retErr *error) error {
	var countedDst *byteCountingWriteCloser
	abortCh, heartbeatCh, cleanupPeerSubs := subscribeExternalWGListenPeer(session, peerDERP)
	defer cleanupPeerSubs()
	ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
		return externalWGCountedDstCount(countedDst)
	}, auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(retErr, ctx, session.derp, peerDERP, func() int64 {
		return externalWGCountedDstCount(countedDst)
	}, auth)

	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalWGListenTransport(transportCtx, session, peerDERP, decision, claim, auth, pathEmitter, cfg)
	if err != nil {
		return err
	}
	defer transportCleanup()

	countedDst, err = openExternalWGListenSink(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = countedDst.Close() }()

	return receiveExternalWGAcceptedClaimData(ctx, session, claim, decision, peerDERP, transportManager, countedDst, auth, cfg)
}

func subscribeExternalWGListenPeer(session *relaySession, peerDERP key.NodePublic) (<-chan derpbind.Packet, <-chan derpbind.Packet, func()) {
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

func externalWGCountedDstCount(countedDst *byteCountingWriteCloser) int64 {
	if countedDst == nil {
		return 0
	}
	return countedDst.Count()
}

func startExternalWGListenTransport(transportCtx context.Context, session *relaySession, peerDERP key.NodePublic, decision rendezvous.Decision, claim rendezvous.Claim, auth externalPeerControlAuth, pathEmitter *transportPathEmitter, cfg ListenConfig) (*transport.Manager, func(), error) {
	localCandidates := parseCandidateStrings(decision.Accept.Candidates)
	transportManager, transportCleanup, err := startExternalWGTransportManager(
		transportCtx,
		session.probeConn,
		session.derpMap,
		session.derp,
		peerDERP,
		localCandidates,
		publicSessionPortmap(session),
		cfg.ForceRelay,
		auth,
	)
	if err != nil {
		return nil, nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)
	return transportManager, transportCleanup, nil
}

func openExternalWGListenSink(ctx context.Context, cfg ListenConfig) (*byteCountingWriteCloser, error) {
	dst, err := openListenSink(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return newByteCountingWriteCloser(dst), nil
}

func receiveExternalWGAcceptedClaimData(ctx context.Context, session *relaySession, claim rendezvous.Claim, decision rendezvous.Decision, peerDERP key.NodePublic, transportManager *transport.Manager, countedDst *byteCountingWriteCloser, auth externalPeerControlAuth, cfg ListenConfig) error {
	tunnel, err := newExternalWGListenTunnel(session, claim, peerDERP, transportManager)
	if err != nil {
		return err
	}
	defer func() { _ = tunnel.Close() }()
	ln, err := tunnel.ListenTCP(externalWGStdioPort)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
		return err
	}
	emitExternalWGDebug(cfg.Emitter, "decision-sent")

	conns, err := acceptExternalWGConns(ctx, ln, decision.Accept.Parallel)
	if err != nil {
		return err
	}
	emitExternalWGDebug(cfg.Emitter, "wg-stripes="+strconv.Itoa(len(conns)))
	if err := receiveExternalNativeTCPDirect(ctx, countedDst, conns); err != nil {
		return err
	}
	return sendPeerAck(ctx, session.derp, peerDERP, countedDst.Count(), auth)
}

func newExternalWGListenTunnel(session *relaySession, claim rendezvous.Claim, peerDERP key.NodePublic, transportManager *transport.Manager) (*externalWGTunnel, error) {
	return newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     session.token.SessionID,
		Role:          externalWGRoleListener,
		PacketConn:    session.probeConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    session.derp,
		PeerDERP:      peerDERP,
		PathSelector:  transportManager,
		PrivateKey:    session.wgPrivate,
		PeerPublicKey: claim.QUICPublic,
	})
}

func emitExternalWGDebug(emitter *telemetry.Emitter, msg string) {
	if emitter != nil {
		emitter.Debug(msg)
	}
}
