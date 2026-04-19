package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/rendezvous"
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

func sendExternalViaWGTunnel(ctx context.Context, cfg SendConfig) (retErr error) {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return ErrUnknownSession
	}
	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	countedSrc := newByteCountingReadCloser(src)
	defer countedSrc.Close()

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

	senderPrivate, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		return err
	}

	parallel := clampExternalWGParallel(externalParallelTCPConnCount(cfg.ParallelPolicy))
	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = publicProbeCandidates(ctx, probeConn, dm, pm)
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     parallel,
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		return err
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}
	ackCh, unsubscribeAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAckOrAbortPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	abortCh, unsubscribeAbort := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAbortPayload(pkt.Payload)
	})
	defer unsubscribeAbort()
	heartbeatCh, unsubscribeHeartbeat := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isHeartbeatPayload(pkt.Payload)
	})
	defer unsubscribeHeartbeat()
	auth := externalPeerControlAuthForToken(tok)
	ctx, stopPeerAbort := withPeerControlContext(ctx, derpClient, listenerDERP, abortCh, heartbeatCh, func() int64 {
		return countedSrc.Count()
	}, auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, derpClient, listenerDERP, func() int64 {
		return countedSrc.Count()
	}, auth)

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalWGTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay, auth)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	tunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
		SessionID:     tok.SessionID,
		Role:          externalWGRoleSender,
		PacketConn:    probeConn,
		Transport:     externalWGTransportLabel,
		DERPClient:    derpClient,
		PeerDERP:      listenerDERP,
		PathSelector:  transportManager,
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.QUICPublic,
	})
	if err != nil {
		return err
	}
	defer tunnel.Close()

	conns, err := dialExternalWGConns(ctx, tunnel, externalWGStdioPort, decision.Accept.Parallel)
	if err != nil {
		return err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("wg-stripes=" + itoa(len(conns)))
	}
	if err := sendExternalNativeTCPDirect(ctx, countedSrc, conns); err != nil {
		return err
	}
	if err := waitForPeerAck(ctx, ackCh, countedSrc.Count(), auth); err != nil {
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
	defer session.derp.Close()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)

	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

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
		if decision.Accept == nil {
			return tok, errors.New("accepted decision missing accept payload")
		}
		abortCh, unsubscribeAbort := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isAbortPayload(pkt.Payload)
		})
		defer unsubscribeAbort()
		var countedDst *byteCountingWriteCloser
		heartbeatCh, unsubscribeHeartbeat := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isHeartbeatPayload(pkt.Payload)
		})
		defer unsubscribeHeartbeat()
		ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
			if countedDst == nil {
				return 0
			}
			return countedDst.Count()
		}, externalPeerControlAuthForToken(session.token))
		defer stopPeerAbort()
		defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
			if countedDst == nil {
				return 0
			}
			return countedDst.Count()
		})
		decision.Accept.Parallel = clampExternalWGParallel(env.Claim.Parallel)

		decision.Accept.Candidates = publicInitialProbeCandidates(session.probeConn, publicSessionPortmap(session))
		localCandidates := parseCandidateStrings(decision.Accept.Candidates)
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("claim-accepted")
		}

		transportCtx, transportCancel := context.WithCancel(ctx)
		defer transportCancel()
		auth := externalPeerControlAuthForToken(session.token)
		transportManager, transportCleanup, err := startExternalWGTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay, auth)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		countedDst = newByteCountingWriteCloser(dst)
		defer countedDst.Close()

		tunnel, err := newExternalWGTunnel(externalWGTunnelConfig{
			SessionID:     session.token.SessionID,
			Role:          externalWGRoleListener,
			PacketConn:    session.probeConn,
			Transport:     externalWGTransportLabel,
			DERPClient:    session.derp,
			PeerDERP:      peerDERP,
			PathSelector:  transportManager,
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.QUICPublic,
		})
		if err != nil {
			return tok, err
		}
		defer tunnel.Close()

		ln, err := tunnel.ListenTCP(externalWGStdioPort)
		if err != nil {
			return tok, err
		}
		defer ln.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
		}

		conns, err := acceptExternalWGConns(ctx, ln, decision.Accept.Parallel)
		if err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("wg-stripes=" + itoa(len(conns)))
		}
		if err := receiveExternalNativeTCPDirect(ctx, countedDst, conns); err != nil {
			return tok, err
		}
		if err := sendPeerAck(ctx, session.derp, peerDERP, countedDst.Count(), auth); err != nil {
			return tok, err
		}
		return tok, nil
	}
}
