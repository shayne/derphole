package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"go4.org/mem"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/portmap"
	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/transport"
	"github.com/shayne/derpcat/pkg/traversal"
	"tailscale.com/net/batching"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	envelopeClaim        = "claim"
	envelopeDecision     = "decision"
	envelopeControl      = "control"
	envelopeAck          = "ack"
	envelopeQUICModeReq  = "quic_mode_request"
	envelopeQUICModeResp = "quic_mode_response"
	envelopeQUICModeAck  = "quic_mode_ack"
	maxEnvelopeBytes     = 16 << 10
)

const externalNativeQUICWait = 5 * time.Second
const externalCopyBufferSize = 256 << 10
const defaultExternalNativeQUICConns = 4

var (
	publicProbeTailscaleCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	publicProbeTailscaleULAPrefix   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

var gatherTraversalCandidates = traversal.GatherCandidates
var publicSessionPortmaps sync.Map
var newPublicPortmap = func(emitter *telemetry.Emitter) publicPortmap {
	return portmap.New(emitter)
}
var newTransportManager = transport.NewManager

type publicPortmap interface {
	transport.Portmap
	SetLocalPort(uint16)
	Snapshot() (netip.AddrPort, bool)
	Close() error
}

type envelope struct {
	Type         string                    `json:"type"`
	Claim        *rendezvous.Claim         `json:"claim,omitempty"`
	Decision     *rendezvous.Decision      `json:"decision,omitempty"`
	Control      *transport.ControlMessage `json:"control,omitempty"`
	QUICModeReq  *quicModeRequest          `json:"quic_mode_request,omitempty"`
	QUICModeResp *quicModeResponse         `json:"quic_mode_response,omitempty"`
	QUICModeAck  *quicModeAck              `json:"quic_mode_ack,omitempty"`
}

type quicModeRequest struct {
	NativeDirect bool `json:"native_direct"`
}

type quicModeResponse struct {
	NativeDirect bool   `json:"native_direct"`
	DirectAddr   string `json:"direct_addr,omitempty"`
}

type quicModeAck struct {
	NativeDirect bool `json:"native_direct"`
}

type remoteCandidateSeeder interface {
	SeedRemoteCandidates(context.Context, []net.Addr)
}

func derpPublicKeyRaw32(pub key.NodePublic) [32]byte {
	var raw [32]byte
	copy(raw[:], pub.AppendTo(raw[:0]))
	return raw
}

func issuePublicSession(ctx context.Context) (string, *relaySession, error) {
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
		Capabilities:    token.CapabilityStdio,
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
		mailbox:      make(chan relayMessage),
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

func sendExternal(ctx context.Context, cfg SendConfig) error {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return ErrUnknownSession
	}
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

	localCandidates := publicProbeCandidates(ctx, probeConn, dm, pm)
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   clientIdentity.Public,
		Candidates:   localCandidates,
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
	ackCh, unsubscribeAck := derpClient.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("claim-accepted")
	}
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	transportCleanupFn := transportCleanup
	defer func() {
		if transportCleanupFn != nil {
			transportCleanupFn()
		}
	}()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	nativeQUIC, nativeQUICAddr, err := requestExternalQUICMode(ctx, derpClient, listenerDERP, transportManager, cfg.ForceRelay)
	if err != nil {
		return err
	}
	if nativeQUIC {
		pathEmitter.Emit(StateDirect)
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("sender-quic-direct")
			cfg.Emitter.Debug("dialing-quic")
		}
		transportCancel()
		transportCleanupFn()
		transportCleanupFn = nil
		probeConn, err = prepareProbeConnForNativeQUIC(transportManager, probeConn, nativeQUICAddr)
		if err != nil {
			return err
		}
		nativeSession, err := dialExternalNativeQUICStripedConns(
			ctx,
			probeConn,
			nativeQUICAddr,
			dm,
			cfg.Emitter,
			quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic),
			quicpath.ServerTLSConfig(clientIdentity, tok.QUICPublic),
			externalNativeQUICConnCount(),
		)
		if err != nil {
			return err
		}
		defer nativeSession.Close()
		return runExternalSendStripedStreams(ctx, cfg, nativeSession, ackCh, pathEmitter, transportManager)
	}

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	defer adapter.Close()
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("sender-quic-ready")
		cfg.Emitter.Debug("dialing-quic")
	}
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("quic-connected")
	}

	return runExternalSendStream(ctx, cfg, quicConn, ackCh, pathEmitter, transportManager)
}

func runExternalSendStream(
	ctx context.Context,
	cfg SendConfig,
	quicConn *quic.Conn,
	ackCh <-chan derpbind.Packet,
	pathEmitter *transportPathEmitter,
	transportManager *transport.Manager,
) error {
	defer quicConn.CloseWithError(0, "")

	streamConn, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer streamConn.Close()

	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	if _, err := io.CopyBuffer(streamConn, src, make([]byte, externalCopyBufferSize)); err != nil {
		return err
	}
	if err := streamConn.Close(); err != nil {
		return err
	}
	if err := waitForPeerAck(ctx, ackCh); err != nil {
		return err
	}
	if err := quicConn.CloseWithError(0, ""); err != nil {
		return err
	}

	pathEmitter.Complete(transportManager)
	return nil
}

func runExternalSendStripedStreams(
	ctx context.Context,
	cfg SendConfig,
	nativeSession *externalNativeQUICStripedSession,
	ackCh <-chan derpbind.Packet,
	pathEmitter *transportPathEmitter,
	transportManager *transport.Manager,
) error {
	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	writers, err := nativeSession.OpenStreams(ctx)
	if err != nil {
		return err
	}

	if err := sendExternalStripedCopy(ctx, src, writers, externalCopyBufferSize); err != nil {
		return err
	}
	if err := waitForPeerAck(ctx, ackCh); err != nil {
		return err
	}

	pathEmitter.Complete(transportManager)
	return nil
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	tok, session, err := issuePublicSession(ctx)
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, session)
	defer closePublicSessionTransport(session)
	defer session.derp.Close()

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
			decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap, publicSessionPortmap(session))
		}
		localCandidates := parseCandidateStrings(nil)
		if decision.Accept != nil {
			localCandidates = parseCandidateStrings(decision.Accept.Candidates)
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("claim-accepted")
		}
		modeCh, unsubscribeMode := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isQUICModeRequestPayload(pkt.Payload)
		})
		defer unsubscribeMode()
		transportCtx, transportCancel := context.WithCancel(ctx)
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay)
		if err != nil {
			transportCancel()
			return tok, err
		}
		defer transportCancel()
		transportCleanupFn := transportCleanup
		defer func() {
			if transportCleanupFn != nil {
				transportCleanupFn()
			}
		}()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
		}

		nativeQUIC, err := acceptExternalQUICMode(ctx, session.derp, modeCh, peerDERP, transportManager, localCandidates, cfg.ForceRelay)
		if err != nil {
			return tok, err
		}
		var quicPacketConn net.PacketConn
		if nativeQUIC {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-quic-direct")
			}
			transportCancel()
			transportCleanupFn()
			transportCleanupFn = nil
			nativeQUICAddr, ok := transportManager.DirectAddr()
			if !ok || nativeQUICAddr == nil {
				return tok, errors.New("native direct path unavailable")
			}
			nativeQUICConn, err := prepareProbeConnForNativeQUIC(transportManager, session.probeConn, nativeQUICAddr)
			if err != nil {
				return tok, err
			}
			nativeSession, streamConns, err := acceptExternalNativeQUICStripedConns(
				ctx,
				nativeQUICConn,
				cloneSessionAddr(nativeQUICAddr),
				session.derpMap,
				cfg.Emitter,
				quicpath.ClientTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
				quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
				externalNativeQUICConnCount(),
			)
			if err != nil {
				return tok, err
			}
			defer nativeSession.Close()
			defer closeExternalNativeQUICStreams(streamConns)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("quic-accepted")
			}

			dst, err := openListenSink(ctx, cfg)
			if err != nil {
				return tok, err
			}
			defer dst.Close()

			readers := make([]io.ReadCloser, 0, len(streamConns))
			for _, streamConn := range streamConns {
				readers = append(readers, streamConn)
			}
			if err := receiveExternalStripedCopy(ctx, dst, readers, externalCopyBufferSize); err != nil {
				return tok, err
			}
			if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeAck}); err != nil {
				return tok, err
			}

			pathEmitter.Complete(transportManager)
			return tok, nil
		} else {
			adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
			defer adapter.Close()
			quicPacketConn = adapter
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-quic-ready")
			}
		}
		quicListener, err := quic.Listen(quicPacketConn, quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic), quicpath.DefaultQUICConfig())
		if err != nil {
			return tok, err
		}
		defer quicListener.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("quic-listening")
			cfg.Emitter.Debug("accepting-quic")
		}

		quicConn, err := quicListener.Accept(ctx)
		if err != nil {
			return tok, err
		}
		defer quicConn.CloseWithError(0, "")
		streamConn, err := quicConn.AcceptStream(ctx)
		if err != nil {
			return tok, err
		}
		defer streamConn.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("quic-accepted")
		}

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		defer dst.Close()

		if _, err := io.CopyBuffer(dst, streamConn, make([]byte, externalCopyBufferSize)); err != nil {
			return tok, err
		}
		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeAck}); err != nil {
			return tok, err
		}

		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func startExternalTransportManager(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
	localCandidates []net.Addr,
	pm publicPortmap,
	forceRelay bool,
) (*transport.Manager, func(), error) {
	controlCh, unsubscribe := derpClient.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportControlPayload(pkt.Payload)
	})
	payloadCh, unsubscribePayload := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportDataPayload(pkt.Payload)
	})

	cfg := transport.ManagerConfig{
		RelayConn: conn,
		RelaySend: func(ctx context.Context, payload []byte) error {
			return derpClient.Send(ctx, peerDERP, payload)
		},
		ReceiveRelay: func(ctx context.Context) ([]byte, error) {
			select {
			case pkt, ok := <-payloadCh:
				if !ok {
					return nil, net.ErrClosed
				}
				return append([]byte(nil), pkt.Payload...), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		RelayAddr:               relayTransportAddr(),
		DirectConn:              nil,
		DisableDirectReads:      false,
		Portmap:                 pm,
		DiscoveryInterval:       1 * time.Second,
		EndpointRefreshInterval: 1 * time.Second,
		DirectStaleTimeout:      10 * time.Second,
		SendControl: func(ctx context.Context, msg transport.ControlMessage) error {
			return sendTransportControl(ctx, derpClient, peerDERP, msg)
		},
		ReceiveControl: func(ctx context.Context) (transport.ControlMessage, error) {
			return receiveTransportControl(ctx, controlCh)
		},
	}
	if !forceRelay {
		cfg.DirectConn = conn
		cfg.DirectBatchConn = publicDirectBatchConn(conn)
		cfg.CandidateSource = publicCandidateSource(conn, dm, pm, localCandidates)
	}

	manager := newTransportManager(cfg)
	if err := manager.Start(ctx); err != nil {
		unsubscribe()
		unsubscribePayload()
		return nil, nil, err
	}
	return manager, func() {
		unsubscribe()
		unsubscribePayload()
	}, nil
}

func publicDirectBatchConn(conn net.PacketConn) transport.DirectBatchConn {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		if batchConn, ok := conn.(transport.DirectBatchConn); ok {
			return batchConn
		}
		return nil
	}
	batchConn := batching.TryUpgradeToConn(udpConn, "udp4", batching.IdealBatchSize)
	directBatchConn, _ := batchConn.(transport.DirectBatchConn)
	return directBatchConn
}

func requestExternalQUICMode(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	forceRelay bool,
) (bool, net.Addr, error) {
	if forceRelay || manager == nil {
		return false, nil, nil
	}

	modeCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeResponsePayload(pkt.Payload)
	})
	defer unsubscribe()

	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type:        envelopeQUICModeReq,
		QUICModeReq: &quicModeRequest{NativeDirect: true},
	}); err != nil {
		return false, nil, err
	}

	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()
	resp, err := receiveQUICModeResponse(modeCtx, modeCh)
	if err != nil || !resp.NativeDirect {
		return false, nil, nil
	}

	var addr net.Addr
	ok := false
	if parsed := parseCandidateStrings([]string{resp.DirectAddr}); len(parsed) == 1 {
		addr = parsed[0]
		ok = true
	}
	if !ok || addr == nil {
		addr, ok = manager.DirectAddr()
	}
	if !ok || addr == nil {
		addr, ok = waitForExternalDirectAddr(ctx, manager, externalNativeQUICWait)
	}
	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type:        envelopeQUICModeAck,
		QUICModeAck: &quicModeAck{NativeDirect: ok && addr != nil},
	}); err != nil {
		return false, nil, err
	}
	if !ok || addr == nil {
		return false, nil, nil
	}
	return true, cloneSessionAddr(addr), nil
}

func acceptExternalQUICMode(
	ctx context.Context,
	client *derpbind.Client,
	modeCh <-chan derpbind.Packet,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	localCandidates []net.Addr,
	forceRelay bool,
) (bool, error) {
	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()

	req, err := receiveQUICModeRequest(modeCtx, modeCh)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
			return false, nil
		}
		if errors.Is(err, context.Canceled) {
			return false, ctx.Err()
		}
		return false, nil
	}

	nativeQUIC := false
	var nativeQUICAddr net.Addr
	if req.NativeDirect && !forceRelay {
		peerDirectAddr, ok := waitForExternalDirectAddr(ctx, manager, externalNativeQUICWait)
		if ok {
			nativeQUIC = true
			nativeQUICAddr = selectExternalQUICModeResponseAddr(peerDirectAddr, localCandidates)
		}
	}
	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeResp,
		QUICModeResp: &quicModeResponse{
			NativeDirect: nativeQUIC,
			DirectAddr:   quicModeDirectAddrString(nativeQUICAddr),
		},
	}); err != nil {
		return false, err
	}
	if !nativeQUIC {
		return false, nil
	}
	ackCtx, ackCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer ackCancel()
	ack, err := receiveQUICModeAck(ackCtx, ackCh)
	if err != nil || !ack.NativeDirect {
		return false, nil
	}
	return nativeQUIC, nil
}

func selectExternalQUICModeResponseAddr(peerAddr net.Addr, localCandidates []net.Addr) net.Addr {
	for _, candidate := range localCandidates {
		if externalNativeQUICStripeCanUseLocalAddrCandidate(candidate, peerAddr) {
			return cloneSessionAddr(candidate)
		}
	}
	for _, candidate := range localCandidates {
		udpAddr, ok := candidate.(*net.UDPAddr)
		if !ok || udpAddr == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip) {
			continue
		}
		if ip.IsGlobalUnicast() {
			return cloneSessionAddr(candidate)
		}
	}
	if len(localCandidates) > 0 {
		return cloneSessionAddr(localCandidates[0])
	}
	return nil
}

func quicModeDirectAddrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func receiveQUICModeRequest(ctx context.Context, ch <-chan derpbind.Packet) (quicModeRequest, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return quicModeRequest{}, net.ErrClosed
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeQUICModeReq || env.QUICModeReq == nil {
			return quicModeRequest{}, errors.New("unexpected quic mode request")
		}
		return *env.QUICModeReq, nil
	case <-ctx.Done():
		return quicModeRequest{}, ctx.Err()
	}
}

func receiveQUICModeResponse(ctx context.Context, ch <-chan derpbind.Packet) (quicModeResponse, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return quicModeResponse{}, net.ErrClosed
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeQUICModeResp || env.QUICModeResp == nil {
			return quicModeResponse{}, errors.New("unexpected quic mode response")
		}
		return *env.QUICModeResp, nil
	case <-ctx.Done():
		return quicModeResponse{}, ctx.Err()
	}
}

func receiveQUICModeAck(ctx context.Context, ch <-chan derpbind.Packet) (quicModeAck, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return quicModeAck{}, net.ErrClosed
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeQUICModeAck || env.QUICModeAck == nil {
			return quicModeAck{}, errors.New("unexpected quic mode ack")
		}
		return *env.QUICModeAck, nil
	case <-ctx.Done():
		return quicModeAck{}, ctx.Err()
	}
}

func waitForExternalDirectAddr(ctx context.Context, manager *transport.Manager, timeout time.Duration) (net.Addr, bool) {
	if manager == nil {
		return nil, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if addr, ok := manager.DirectAddr(); ok && addr != nil {
			return cloneSessionAddr(addr), true
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-timer.C:
			return nil, false
		case <-ticker.C:
		}
	}
}

func prepareProbeConnForNativeQUIC(manager *transport.Manager, conn net.PacketConn, _ net.Addr) (net.PacketConn, error) {
	if conn == nil {
		return nil, nil
	}
	_ = conn.SetReadDeadline(time.Now())
	if manager != nil {
		manager.Wait()
	}
	_ = disablePublicNativeQUICReceiveOffload(conn)
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func waitForPeerAck(ctx context.Context, ch <-chan derpbind.Packet) error {
	select {
	case _, ok := <-ch:
		if !ok {
			return net.ErrClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func firstDERPNode(dm *tailcfg.DERPMap, regionID int) *tailcfg.DERPNode {
	if dm == nil || len(dm.Regions) == 0 {
		return nil
	}
	if regionID != 0 {
		if region := dm.Regions[regionID]; region != nil && len(region.Nodes) > 0 {
			return region.Nodes[0]
		}
	}
	for _, regionID := range dm.RegionIDs() {
		region := dm.Regions[regionID]
		if region != nil && len(region.Nodes) > 0 {
			return region.Nodes[0]
		}
	}
	return nil
}

func derpServerURL(node *tailcfg.DERPNode) string {
	if node == nil {
		return ""
	}
	host := node.HostName
	port := node.DERPPort
	if port != 0 && port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "https://" + host + "/derp"
}

func publicDERPMapURL() string {
	if override := os.Getenv("DERPCAT_TEST_DERP_MAP_URL"); override != "" {
		return override
	}
	return derpbind.PublicDERPMapURL
}

func publicDERPServerURL(node *tailcfg.DERPNode) string {
	if override := os.Getenv("DERPCAT_TEST_DERP_SERVER_URL"); override != "" {
		return override
	}
	return derpServerURL(node)
}

func receiveDecision(ctx context.Context, client *derpbind.Client, from key.NodePublic) (rendezvous.Decision, error) {
	for {
		pkt, err := client.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return rendezvous.Decision{}, ctx.Err()
			}
			return rendezvous.Decision{}, err
		}
		if pkt.From != from {
			continue
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeDecision || env.Decision == nil {
			continue
		}
		return *env.Decision, nil
	}
}

func sendTransportControl(ctx context.Context, client *derpbind.Client, dst key.NodePublic, msg transport.ControlMessage) error {
	return sendEnvelope(ctx, client, dst, envelope{Type: envelopeControl, Control: &msg})
}

func receiveTransportControl(ctx context.Context, ch <-chan derpbind.Packet) (transport.ControlMessage, error) {
	select {
	case pkt, ok := <-ch:
		if !ok {
			return transport.ControlMessage{}, net.ErrClosed
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeControl || env.Control == nil {
			return transport.ControlMessage{}, errors.New("unexpected control payload")
		}
		return *env.Control, nil
	case <-ctx.Done():
		return transport.ControlMessage{}, ctx.Err()
	}
}

func sendEnvelope(ctx context.Context, client *derpbind.Client, dst key.NodePublic, env envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return client.Send(ctx, dst, payload)
}

func decodeEnvelope(payload []byte) (envelope, error) {
	var env envelope
	if len(payload) == 0 || len(payload) > maxEnvelopeBytes {
		return env, errors.New("invalid envelope size")
	}
	err := json.Unmarshal(payload, &env)
	return env, err
}

func publicProbeCandidates(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap) []string {
	if fakeTransportCandidatesBlocked() {
		return nil
	}
	if conn == nil {
		return nil
	}
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	port := udpAddr.Port
	seen := map[string]struct{}{}
	add := func(ip netip.Addr) {
		if !publicProbeCandidateAllowed(ip) {
			return
		}
		candidate := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		seen[candidate] = struct{}{}
	}

	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsGlobalUnicast() {
			add(ip)
		}
	}

	if dm != nil {
		var mapped func() (netip.AddrPort, bool)
		if pm != nil {
			mapped = pm.Snapshot
		}
		if gathered, err := gatherTraversalCandidates(ctx, conn, dm, mapped); err == nil {
			for _, candidate := range gathered {
				if addrPort, err := netip.ParseAddrPort(candidate); err == nil {
					if !publicProbeCandidateAllowed(addrPort.Addr()) {
						continue
					}
					seen[addrPort.String()] = struct{}{}
				}
			}
		}
	}

	candidates := make([]string, 0, len(seen))
	for candidate := range seen {
		candidates = append(candidates, candidate)
	}
	slices.Sort(candidates)
	if len(candidates) > rendezvous.MaxClaimCandidates {
		candidates = candidates[:rendezvous.MaxClaimCandidates]
	}
	return candidates
}

func publicProbeCandidateAllowed(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() {
		return false
	}
	if os.Getenv("DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES") != "1" {
		return true
	}
	return !publicProbeTailscaleCGNATPrefix.Contains(ip) && !publicProbeTailscaleULAPrefix.Contains(ip)
}

func publicProbeAddrs(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap) []net.Addr {
	raw := publicProbeCandidates(ctx, conn, dm, pm)
	return parseCandidateStrings(raw)
}

func publicCandidateSource(conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap, localCandidates []net.Addr) func(context.Context) []net.Addr {
	if fakeTransportEnabled() {
		return func(ctx context.Context) []net.Addr {
			_ = dm
			_ = pm
			return publicProbeAddrs(ctx, conn, nil, nil)
		}
	}
	return func(context.Context) []net.Addr {
		return slices.Clone(localCandidates)
	}
}

func newBoundPublicPortmap(conn net.PacketConn, emitter *telemetry.Emitter) publicPortmap {
	pm := newPublicPortmap(emitter)
	if pm == nil || conn == nil {
		return pm
	}
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		pm.SetLocalPort(uint16(udpAddr.Port))
	}
	return pm
}

func attachPublicPortmap(session *relaySession, pm publicPortmap) {
	if session == nil || pm == nil {
		return
	}
	publicSessionPortmaps.Store(session, pm)
}

func publicSessionPortmap(session *relaySession) publicPortmap {
	if session == nil {
		return nil
	}
	if pm, ok := publicSessionPortmaps.Load(session); ok {
		if client, ok := pm.(publicPortmap); ok {
			return client
		}
	}
	return nil
}

func closePublicSessionTransport(session *relaySession) {
	if session == nil {
		return
	}
	if pm, ok := publicSessionPortmaps.LoadAndDelete(session); ok {
		if client, ok := pm.(publicPortmap); ok {
			_ = client.Close()
		}
	}
	if session.probeConn != nil {
		_ = session.probeConn.Close()
	}
}

func parseCandidateStrings(raw []string) []net.Addr {
	addrs := make([]net.Addr, 0, len(raw))
	for _, candidate := range raw {
		addrPort, err := netip.ParseAddrPort(candidate)
		if err != nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   append(net.IP(nil), addrPort.Addr().AsSlice()...),
			Port: int(addrPort.Port()),
			Zone: addrPort.Addr().Zone(),
		})
	}
	return addrs
}

func cloneSessionAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		cp := *v
		if v.IP != nil {
			cp.IP = append(net.IP(nil), v.IP...)
		}
		return &cp
	default:
		return addr
	}
}

func seedAcceptedDecisionCandidates(ctx context.Context, seeder remoteCandidateSeeder, decision rendezvous.Decision) {
	if seeder == nil || decision.Accept == nil || len(decision.Accept.Candidates) == 0 {
		return
	}
	seeder.SeedRemoteCandidates(ctx, parseCandidateStrings(decision.Accept.Candidates))
}

func seedAcceptedClaimCandidates(ctx context.Context, seeder remoteCandidateSeeder, claim rendezvous.Claim) {
	if seeder == nil || len(claim.Candidates) == 0 {
		return
	}
	seeder.SeedRemoteCandidates(ctx, parseCandidateStrings(claim.Candidates))
}

func isTransportControlPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeControl && env.Control != nil
}

func isClaimPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeClaim && env.Claim != nil
}

func isAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeAck
}

func isQUICModeRequestPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeQUICModeReq && env.QUICModeReq != nil
}

func isQUICModeResponsePayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeQUICModeResp && env.QUICModeResp != nil
}

func isQUICModeAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeQUICModeAck && env.QUICModeAck != nil
}

func isDecisionPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDecision && env.Decision != nil
}

func isTransportDataPayload(payload []byte) bool {
	return !isTransportControlPayload(payload) &&
		!isAckPayload(payload) &&
		!isClaimPayload(payload) &&
		!isDecisionPayload(payload) &&
		!isQUICModeRequestPayload(payload) &&
		!isQUICModeResponsePayload(payload) &&
		!isQUICModeAckPayload(payload)
}

func relayTransportAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func fakeTransportCandidatesBlocked() bool {
	if !fakeTransportEnabled() {
		return false
	}
	raw := os.Getenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT")
	if raw == "" {
		return false
	}
	enableAt, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(0, enableAt))
}

func fakeTransportEnabled() bool {
	return os.Getenv("DERPCAT_FAKE_TRANSPORT") == "1"
}

func externalNativeQUICConnCount() int {
	if fakeTransportEnabled() {
		return 1
	}
	return defaultExternalNativeQUICConns
}
