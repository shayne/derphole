package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
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
	envelopeClaim         = "claim"
	envelopeDecision      = "decision"
	envelopeControl       = "control"
	envelopeAck           = "ack"
	envelopeQUICModeReq   = "quic_mode_request"
	envelopeQUICModeResp  = "quic_mode_response"
	envelopeQUICModeAck   = "quic_mode_ack"
	envelopeQUICModeReady = "quic_mode_ready"
	maxEnvelopeBytes      = 16 << 10
)

const externalNativeQUICWait = 5 * time.Second
const externalNativeQUICConnectWait = externalNativeQUICWait
const externalNativeQUICAckRetryInterval = 250 * time.Millisecond
const externalNativeQUICNackWait = 1 * time.Second
const externalNativeQUICSetupGraceWait = 0
const externalNativeQUICSetupSkipRelayTailBytes = 256 << 10
const externalNativeQUICRelayTailPeerAckWait = 250 * time.Millisecond
const externalPublicCandidateRefreshWait = 250 * time.Millisecond
const externalCopyBufferSize = 256 << 10
const defaultExternalNativeQUICConns = 4
const externalClaimRetryInterval = 250 * time.Millisecond

var (
	publicProbeTailscaleCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	publicProbeTailscaleULAPrefix   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

var gatherTraversalCandidates = traversal.GatherCandidates
var gatherTraversalCandidatesFromSTUNPackets = traversal.GatherCandidatesFromSTUNPackets
var publicInterfaceAddrs = net.InterfaceAddrs
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
	Type          string                    `json:"type"`
	Claim         *rendezvous.Claim         `json:"claim,omitempty"`
	Decision      *rendezvous.Decision      `json:"decision,omitempty"`
	Control       *transport.ControlMessage `json:"control,omitempty"`
	QUICModeReq   *quicModeRequest          `json:"quic_mode_request,omitempty"`
	QUICModeResp  *quicModeResponse         `json:"quic_mode_response,omitempty"`
	QUICModeAck   *quicModeAck              `json:"quic_mode_ack,omitempty"`
	QUICModeReady *quicModeReady            `json:"quic_mode_ready,omitempty"`
}

type quicModeRequest struct {
	NativeDirect   bool   `json:"native_direct"`
	NativeTCP      bool   `json:"native_tcp,omitempty"`
	DirectAddr     string `json:"direct_addr,omitempty"`
	NativeTCPConns int    `json:"native_tcp_conns,omitempty"`
}

type quicModeResponse struct {
	NativeDirect   bool   `json:"native_direct"`
	NativeTCP      bool   `json:"native_tcp,omitempty"`
	DirectAddr     string `json:"direct_addr,omitempty"`
	NativeTCPConns int    `json:"native_tcp_conns,omitempty"`
}

type quicModeAck struct {
	NativeDirect bool `json:"native_direct"`
	NativeTCP    bool `json:"native_tcp,omitempty"`
}

type quicModeReady struct {
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

	localCandidates := publicInitialProbeCandidates(probeConn, pm)
	parsedLocalCandidates := parseCandidateStrings(localCandidates)
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
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parsedLocalCandidates, pm, cfg.ForceRelay)
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

	nativeDirectModeCtx, nativeDirectModeCancel := context.WithCancel(ctx)
	defer nativeDirectModeCancel()
	nativeDirectModeCh := requestExternalDirectModeAsync(
		nativeDirectModeCtx,
		derpClient,
		listenerDERP,
		transportManager,
		parsedLocalCandidates,
		dm,
		probeConn,
		cfg.Emitter,
		quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic),
		quicpath.ServerTLSConfig(clientIdentity, tok.QUICPublic),
		externalNativeTCPAuth{
			Enabled:      true,
			SessionID:    tok.SessionID,
			BearerSecret: tok.BearerSecret,
			LocalPublic:  clientIdentity.Public,
			PeerPublic:   tok.QUICPublic,
		},
		cfg.ForceRelay,
	)

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

	return runExternalSendStream(
		ctx,
		cfg,
		quicConn,
		ackCh,
		pathEmitter,
		transportManager,
		transportCancel,
		probeConn,
		dm,
		quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic),
		quicpath.ServerTLSConfig(clientIdentity, tok.QUICPublic),
		nativeDirectModeCh,
		nativeDirectModeCancel,
	)
}

func runExternalSendStream(
	ctx context.Context,
	cfg SendConfig,
	quicConn *quic.Conn,
	ackCh <-chan derpbind.Packet,
	pathEmitter *transportPathEmitter,
	transportManager *transport.Manager,
	transportCancel context.CancelFunc,
	probeConn net.PacketConn,
	dm *tailcfg.DERPMap,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeDirectModeCh <-chan externalNativeDirectModeResult,
	nativeDirectModeCancel context.CancelFunc,
) error {
	defer quicConn.CloseWithError(0, "")

	externalTransferTracef("sender-open-relay-stream-start")
	streamConn, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer streamConn.Close()
	externalTransferTracef("sender-open-relay-stream-complete")

	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()
	externalTransferTracef("sender-source-ready src=%T", src)

	spool, err := newExternalHandoffSpool(src, externalCopyBufferSize, externalHandoffMaxUnackedBytes)
	if err != nil {
		return err
	}
	defer spool.Close()
	externalTransferTracef("sender-spool-ready")

	relayStopCh := make(chan struct{})
	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- sendExternalHandoffCarrier(ctx, streamConn, spool, relayStopCh)
	}()
	externalTransferTracef("sender-relay-carrier-launched")

	select {
	case modeResult := <-nativeDirectModeCh:
		externalTransferTracef(
			"sender-native-mode-result err=%v nativeTCP=%d nativeQUIC=%v acked=%d relayDone=%v",
			modeResult.err,
			len(modeResult.nativeTCPConns),
			modeResult.nativeQUIC && modeResult.nativeQUICAddr != nil,
			spool.AckedWatermark(),
			spool.Done(),
		)
		if modeResult.err != nil {
			close(relayStopCh)
			relayErr := <-relayErrCh
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			if relayErr != nil {
				return relayErr
			}
			return modeResult.err
		}
		if len(modeResult.nativeTCPConns) == 0 && (!modeResult.nativeQUIC || modeResult.nativeQUICAddr == nil) {
			if err := <-relayErrCh; err != nil {
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

		if len(modeResult.nativeTCPConns) > 0 {
			close(relayStopCh)
			if err := <-relayErrCh; err != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return err
			}
			externalTransferTracef("sender-relay-carrier-stopped acked=%d", spool.AckedWatermark())
			if spool.Done() {
				externalTransferTracef("sender-native-tcp-skip relay-complete acked=%d", spool.AckedWatermark())
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				break
			}
			if err := spool.RewindTo(spool.AckedWatermark()); err != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return err
			}

			pathEmitter.Emit(StateDirect)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("sender-tcp-direct")
				cfg.Emitter.Debug("tcp-connected")
			}

			externalTransferTracef("sender-native-tcp-copy-start conns=%d acked=%d", len(modeResult.nativeTCPConns), spool.AckedWatermark())
			if err := sendExternalHandoffNativeTCPConns(ctx, modeResult.nativeTCPConns, spool); err != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return err
			}
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			externalTransferTracef("sender-native-tcp-copy-complete")
			break
		}

		if externalNativeQUICSetupShouldSkipForSpool(spool) {
			externalTransferTracef("sender-native-quic-setup-skip short-relay-tail acked=%d", spool.AckedWatermark())
			transportManager.StopDirect()
			if err := <-relayErrCh; err != nil {
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

		if relayErr, relayDone := waitExternalNativeQUICSetupGrace(relayErrCh, externalNativeQUICSetupGraceWaitForSpool(spool)); relayDone {
			externalTransferTracef("sender-native-quic-setup-skip relay-complete err=%v acked=%d", relayErr, spool.AckedWatermark())
			if relayErr != nil {
				return relayErr
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

		transportManager.StopDirect()
		_ = probeConn.SetDeadline(time.Time{})
		externalTransferTracef("sender-keep-relay-quic-during-native-setup")

		nativeQUICSetupCtx, nativeQUICSetupCancel := context.WithCancel(ctx)
		nativeQUICSetupCh := make(chan externalNativeQUICSendSetupResult, 1)
		go func() {
			nativeQUICSession, err := dialExternalNativeQUICStripedConns(
				nativeQUICSetupCtx,
				probeConn,
				modeResult.nativeQUICAddr,
				dm,
				cfg.Emitter,
				clientTLSConfig,
				serverTLSConfig,
				externalNativeQUICConnCount(),
			)
			if err != nil || nativeQUICSession == nil || nativeQUICSession.setupFallback {
				nativeQUICSetupCh <- externalNativeQUICSendSetupResult{
					session: nativeQUICSession,
					err:     err,
				}
				return
			}

			nativeQUICStreams, err := nativeQUICSession.OpenReadWriteStreams(nativeQUICSetupCtx)
			if err != nil {
				nativeQUICSetupCh <- externalNativeQUICSendSetupResult{
					session: nativeQUICSession,
					err:     err,
				}
				return
			}
			if err := waitExternalNativeQUICReceiverReady(
				nativeQUICSetupCtx,
				nativeQUICStreams,
				externalNativeQUICStreamRole(nativeQUICSession.openStreams, 0),
			); err != nil {
				nativeQUICSetupCh <- externalNativeQUICSendSetupResult{
					session: nativeQUICSession,
					streams: nativeQUICStreams,
					err:     err,
				}
				return
			}
			nativeQUICSetupCh <- externalNativeQUICSendSetupResult{
				session: nativeQUICSession,
				streams: nativeQUICStreams,
			}
		}()

		var nativeQUICSetup externalNativeQUICSendSetupResult
		nativeQUICSetupReady := false
		select {
		case nativeQUICSetup = <-nativeQUICSetupCh:
			nativeQUICSetupReady = nativeQUICSetup.err == nil && nativeQUICSetup.session != nil && !nativeQUICSetup.session.setupFallback
		case relayErr := <-relayErrCh:
			nativeQUICSetupCancel()
			closeExternalNativeQUICSendSetupResultAsync(nativeQUICSetupCh)
			if relayErr != nil {
				return relayErr
			}
			if err := waitForPeerAck(ctx, ackCh); err != nil {
				return err
			}
			if err := quicConn.CloseWithError(0, ""); err != nil {
				return err
			}
			externalTransferTracef("sender-close-relay-quic-complete")
			externalTransferTracef("sender-transport-cancel")
			transportCancel()
			externalTransferTracef("sender-transport-wait-start")
			transportManager.Wait()
			externalTransferTracef("sender-transport-wait-complete")
			pathEmitter.Complete(transportManager)
			return nil
		}
		nativeQUICSetupCancel()

		if !nativeQUICSetupReady {
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			if cfg.Emitter != nil {
				if nativeQUICSetup.err != nil {
					cfg.Emitter.Debug("sender-native-quic-setup-fallback err=" + nativeQUICSetup.err.Error())
				} else {
					cfg.Emitter.Debug("sender-native-quic-setup-fallback=primary-only")
				}
			}
			if err := <-relayErrCh; err != nil {
				return err
			}
			if err := waitForPeerAck(ctx, ackCh); err != nil {
				return err
			}
			if err := quicConn.CloseWithError(0, ""); err != nil {
				return err
			}
			externalTransferTracef("sender-close-relay-quic-complete")
			externalTransferTracef("sender-transport-cancel")
			transportCancel()
			externalTransferTracef("sender-transport-wait-start")
			transportManager.Wait()
			externalTransferTracef("sender-transport-wait-complete")
			pathEmitter.Complete(transportManager)
			return nil
		}
		close(relayStopCh)
		if err := <-relayErrCh; err != nil {
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			return err
		}
		externalTransferTracef("sender-relay-carrier-stopped acked=%d", spool.AckedWatermark())
		if relayComplete, err := waitExternalNativeQUICRelayTailPeerAck(ctx, spool, ackCh); err != nil {
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			return err
		} else if relayComplete {
			externalTransferTracef("sender-native-quic-skip relay-peer-ack-complete acked=%d", spool.AckedWatermark())
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			if err := quicConn.CloseWithError(0, ""); err != nil {
				return err
			}
			externalTransferTracef("sender-close-relay-quic-complete")
			externalTransferTracef("sender-transport-cancel")
			transportCancel()
			externalTransferTracef("sender-transport-wait-start")
			transportManager.Wait()
			externalTransferTracef("sender-transport-wait-complete")
			pathEmitter.Complete(transportManager)
			return nil
		}
		if spool.Done() {
			externalTransferTracef("sender-native-quic-skip relay-complete acked=%d", spool.AckedWatermark())
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			break
		}
		if err := spool.RewindTo(spool.AckedWatermark()); err != nil {
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			return err
		}
		pathEmitter.Emit(StateDirect)
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("sender-quic-direct")
		}
		externalTransferTracef("sender-native-quic-copy-start conns=%d acked=%d", len(nativeQUICSetup.streams), spool.AckedWatermark())
		if err := sendExternalHandoffCarriers(ctx, nativeQUICSetup.streams, spool); err != nil {
			closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
			return err
		}
		externalTransferTracef("sender-native-quic-copy-complete")
		closeExternalNativeQUICSendSetupResult(nativeQUICSetup)

		if err := quicConn.CloseWithError(0, ""); err != nil {
			return err
		}
		externalTransferTracef("sender-close-relay-quic-complete")
		externalTransferTracef("sender-transport-cancel")
		transportCancel()
		externalTransferTracef("sender-transport-wait-start")
		transportManager.Wait()
		externalTransferTracef("sender-transport-wait-complete")
	case err := <-relayErrCh:
		externalTransferTracef("sender-relay-carrier-complete err=%v", err)
		nativeDirectModeCancel()
		externalTransferTracef("sender-native-mode-drain-after-relay-start")
		closeExternalNativeTCPConns(waitExternalNativeDirectModeResult(nativeDirectModeCh).nativeTCPConns)
		externalTransferTracef("sender-native-mode-drain-after-relay-complete")
		if err != nil {
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

	if err := waitForPeerAck(ctx, ackCh); err != nil {
		return err
	}
	if err := quicConn.CloseWithError(0, ""); err != nil {
		return err
	}

	pathEmitter.Complete(transportManager)
	return nil
}

func runExternalListenStream(
	ctx context.Context,
	cfg ListenConfig,
	streamConn *quic.Stream,
	relayConn *quic.Conn,
	closeRelayQUIC func(),
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
	pathEmitter *transportPathEmitter,
	transportManager *transport.Manager,
	transportCancel context.CancelFunc,
	probeConn net.PacketConn,
	dm *tailcfg.DERPMap,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeDirectModeCh <-chan externalNativeDirectModeResult,
	nativeDirectModeCancel context.CancelFunc,
) error {
	dst, err := openListenSink(ctx, cfg)
	if err != nil {
		return err
	}
	defer dst.Close()
	externalTransferTracef("listener-sink-ready dst=%T", dst)

	rx := newExternalHandoffReceiver(dst, externalHandoffMaxUnackedBytes)
	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- receiveExternalHandoffCarrier(ctx, streamConn, rx, externalCopyBufferSize)
	}()
	externalTransferTracef("listener-relay-carrier-launched")

	select {
	case modeResult := <-nativeDirectModeCh:
		externalTransferTracef(
			"listener-native-mode-result err=%v nativeTCP=%d nativeQUIC=%v watermark=%d",
			modeResult.err,
			len(modeResult.nativeTCPConns),
			modeResult.nativeQUIC && modeResult.nativeQUICAddr != nil,
			rx.Watermark(),
		)
		switch {
		case modeResult.err != nil:
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			if err := <-relayErrCh; err != nil {
				return err
			}
		case len(modeResult.nativeTCPConns) == 0 && (!modeResult.nativeQUIC || modeResult.nativeQUICAddr == nil):
			if err := <-relayErrCh; err != nil {
				return err
			}
		case len(modeResult.nativeTCPConns) > 0:
			relayErr := <-relayErrCh
			if relayErr != nil && !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return relayErr
			}
			if relayErr == nil {
				externalTransferTracef("listener-native-tcp-skip relay-complete watermark=%d", rx.Watermark())
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				break
			}
			externalTransferTracef("listener-relay-carrier-stopped watermark=%d", rx.Watermark())
			pathEmitter.Emit(StateDirect)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-tcp-direct")
				cfg.Emitter.Debug("tcp-accepted")
			}
			externalTransferTracef("listener-native-tcp-copy-start conns=%d watermark=%d", len(modeResult.nativeTCPConns), rx.Watermark())
			if err := receiveExternalHandoffNativeTCPConns(ctx, modeResult.nativeTCPConns, rx); err != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return err
			}
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			externalTransferTracef("listener-native-tcp-copy-complete watermark=%d", rx.Watermark())
		default:
			relayErrReady := false
			var relayErr error
			if relayErr, relayErrReady = waitExternalNativeQUICSetupGrace(relayErrCh, externalNativeQUICSetupGraceWait); relayErrReady {
				if relayErr != nil && !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
					return relayErr
				}
				if relayErr == nil {
					externalTransferTracef("listener-native-quic-setup-skip relay-complete watermark=%d", rx.Watermark())
					break
				}
			}

			transportManager.StopDirect()
			_ = probeConn.SetDeadline(time.Time{})
			nativeQUICSetupCtx, nativeQUICSetupCancel := context.WithCancel(ctx)
			nativeQUICSetupCh := make(chan externalNativeQUICListenSetupResult, 1)
			go func() {
				nativeQUICSession, nativeQUICStreams, err := acceptExternalNativeQUICStripedConns(
					nativeQUICSetupCtx,
					probeConn,
					modeResult.nativeQUICAddr,
					dm,
					cfg.Emitter,
					clientTLSConfig,
					serverTLSConfig,
					externalNativeQUICConnCount(),
				)
				if err == nil && nativeQUICSession != nil && !nativeQUICSession.setupFallback {
					err = signalExternalNativeQUICReceiverReady(
						nativeQUICSetupCtx,
						nativeQUICStreams,
						externalNativeQUICStreamRole(nativeQUICSession.openStreams, 0),
					)
				}
				nativeQUICSetupCh <- externalNativeQUICListenSetupResult{
					session: nativeQUICSession,
					streams: nativeQUICStreams,
					err:     err,
				}
			}()

			var nativeQUICSetup externalNativeQUICListenSetupResult
			nativeQUICSetupReady := false
			if !relayErrReady {
				select {
				case nativeQUICSetup = <-nativeQUICSetupCh:
					nativeQUICSetupReady = nativeQUICSetup.err == nil && nativeQUICSetup.session != nil && !nativeQUICSetup.session.setupFallback
				case relayErr = <-relayErrCh:
					relayErrReady = true
				}
			}
			if relayErrReady && relayErr == nil {
				nativeQUICSetupCancel()
				closeExternalNativeQUICListenSetupResultAsync(nativeQUICSetupCh)
				break
			}
			if relayErrReady && errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
				select {
				case nativeQUICSetup = <-nativeQUICSetupCh:
					nativeQUICSetupReady = nativeQUICSetup.err == nil && nativeQUICSetup.session != nil && !nativeQUICSetup.session.setupFallback
				case <-time.After(externalNativeQUICWait):
					nativeQUICSetupCancel()
					closeExternalNativeQUICListenSetupResult(<-nativeQUICSetupCh)
				}
			}
			nativeQUICSetupCancel()

			if !nativeQUICSetupReady {
				closeExternalNativeQUICListenSetupResult(nativeQUICSetup)
				if cfg.Emitter != nil {
					if nativeQUICSetup.err != nil {
						cfg.Emitter.Debug("listener-native-quic-setup-fallback err=" + nativeQUICSetup.err.Error())
					} else {
						cfg.Emitter.Debug("listener-native-quic-setup-fallback=primary-only")
					}
				}
				if !relayErrReady {
					relayErr = <-relayErrCh
					relayErrReady = true
				}
				if relayErr != nil && !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
					return relayErr
				}
				break
			}
			defer nativeQUICSetup.session.Close()
			defer closeExternalNativeQUICStreams(nativeQUICSetup.streams)

			if !relayErrReady {
				relayErr = <-relayErrCh
				relayErrReady = true
			}
			if relayErr != nil && !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
				return relayErr
			}
			if relayErr == nil {
				externalTransferTracef("listener-native-quic-skip relay-complete watermark=%d", rx.Watermark())
				break
			}
			externalTransferTracef("listener-relay-carrier-stopped watermark=%d", rx.Watermark())
			if relayConn != nil {
				externalTransferTracef("listener-close-relay-quic-start")
				_ = relayConn.CloseWithError(0, "")
				externalTransferTracef("listener-close-relay-quic-complete")
			}
			if closeRelayQUIC != nil {
				closeRelayQUIC()
			}
			externalTransferTracef("listener-transport-cancel")
			transportCancel()
			externalTransferTracef("listener-transport-wait-start")
			transportManager.Wait()
			externalTransferTracef("listener-transport-wait-complete")
			_ = probeConn.SetDeadline(time.Time{})

			pathEmitter.Emit(StateDirect)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-quic-direct")
			}
			externalTransferTracef("listener-native-quic-copy-start conns=%d watermark=%d", len(nativeQUICSetup.streams), rx.Watermark())
			if err := receiveExternalHandoffNativeQUICStreams(ctx, nativeQUICSetup.streams, rx); err != nil {
				return err
			}
			externalTransferTracef("listener-native-quic-copy-complete watermark=%d", rx.Watermark())
		}
	case err := <-relayErrCh:
		externalTransferTracef("listener-relay-carrier-complete err=%v watermark=%d", err, rx.Watermark())
		if err != nil && !errors.Is(err, errExternalHandoffCarrierHandoff) {
			nativeDirectModeCancel()
			externalTransferTracef("listener-native-mode-drain-after-relay-error-start")
			closeExternalNativeTCPConns(waitExternalNativeDirectModeResult(nativeDirectModeCh).nativeTCPConns)
			externalTransferTracef("listener-native-mode-drain-after-relay-error-complete")
			return err
		}
		if !errors.Is(err, errExternalHandoffCarrierHandoff) {
			nativeDirectModeCancel()
			externalTransferTracef("listener-native-mode-drain-after-relay-start")
			closeExternalNativeTCPConns(waitExternalNativeDirectModeResult(nativeDirectModeCh).nativeTCPConns)
			externalTransferTracef("listener-native-mode-drain-after-relay-complete")
			break
		}
		modeResult := waitExternalNativeDirectModeResult(nativeDirectModeCh)
		if modeResult.err != nil {
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			return modeResult.err
		}
		if len(modeResult.nativeTCPConns) > 0 {
			pathEmitter.Emit(StateDirect)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-tcp-direct")
				cfg.Emitter.Debug("tcp-accepted")
			}
			externalTransferTracef("listener-native-tcp-copy-start conns=%d watermark=%d", len(modeResult.nativeTCPConns), rx.Watermark())
			if err := receiveExternalHandoffNativeTCPConns(ctx, modeResult.nativeTCPConns, rx); err != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return err
			}
			closeExternalNativeTCPConns(modeResult.nativeTCPConns)
			externalTransferTracef("listener-native-tcp-copy-complete watermark=%d", rx.Watermark())
			break
		}
		if modeResult.nativeQUIC && modeResult.nativeQUICAddr != nil {
			if relayConn != nil {
				externalTransferTracef("listener-close-relay-quic-start")
				_ = relayConn.CloseWithError(0, "")
				externalTransferTracef("listener-close-relay-quic-complete")
			}
			if closeRelayQUIC != nil {
				closeRelayQUIC()
			}
			externalTransferTracef("listener-transport-cancel")
			transportCancel()
			externalTransferTracef("listener-transport-wait-start")
			transportManager.Wait()
			externalTransferTracef("listener-transport-wait-complete")
			_ = probeConn.SetDeadline(time.Time{})

			nativeQUICSession, nativeQUICStreams, err := acceptExternalNativeQUICStripedConns(
				ctx,
				probeConn,
				modeResult.nativeQUICAddr,
				dm,
				cfg.Emitter,
				clientTLSConfig,
				serverTLSConfig,
				externalNativeQUICConnCount(),
			)
			if err != nil {
				return err
			}
			defer nativeQUICSession.Close()
			defer closeExternalNativeQUICStreams(nativeQUICStreams)

			pathEmitter.Emit(StateDirect)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("listener-quic-direct")
			}
			externalTransferTracef("listener-native-quic-copy-start conns=%d watermark=%d", len(nativeQUICStreams), rx.Watermark())
			if err := receiveExternalHandoffNativeQUICStreams(ctx, nativeQUICStreams, rx); err != nil {
				return err
			}
			externalTransferTracef("listener-native-quic-copy-complete watermark=%d", rx.Watermark())
		}
	}

	if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeAck}); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

type externalNativeDirectModeResult struct {
	nativeQUIC     bool
	nativeQUICAddr net.Addr
	nativeTCPConns []net.Conn
	err            error
}

type externalNativeQUICSendSetupResult struct {
	session *externalNativeQUICStripedSession
	streams []io.ReadWriteCloser
	err     error
}

func closeExternalNativeQUICSendSetupResult(result externalNativeQUICSendSetupResult) {
	for _, stream := range result.streams {
		_ = stream.Close()
	}
	if result.session != nil {
		result.session.Close()
	}
}

func closeExternalNativeQUICSendSetupResultAsync(resultCh <-chan externalNativeQUICSendSetupResult) {
	if resultCh == nil {
		return
	}
	go func() {
		closeExternalNativeQUICSendSetupResult(<-resultCh)
	}()
}

type externalNativeQUICListenSetupResult struct {
	session *externalNativeQUICStripedSession
	streams []*quic.Stream
	err     error
}

const externalNativeQUICReceiverReadyByte = byte(1)

func closeExternalNativeQUICListenSetupResult(result externalNativeQUICListenSetupResult) {
	closeExternalNativeQUICStreams(result.streams)
	if result.session != nil {
		result.session.Close()
	}
}

func closeExternalNativeQUICListenSetupResultAsync(resultCh <-chan externalNativeQUICListenSetupResult) {
	if resultCh == nil {
		return
	}
	go func() {
		closeExternalNativeQUICListenSetupResult(<-resultCh)
	}()
}

func waitExternalNativeQUICReceiverReady(ctx context.Context, streams []io.ReadWriteCloser, localOpenedStream bool) error {
	if len(streams) == 0 {
		return errors.New("native QUIC setup has no streams")
	}
	externalTransferTracef("native-quic-wait-receiver-ready-start local-opened=%v stream=%T", localOpenedStream, streams[0])
	if deadlineCarrier, ok := streams[0].(interface{ SetDeadline(time.Time) error }); ok {
		cancelDeadline := cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx, deadlineCarrier)
		defer cancelDeadline()
	}

	if localOpenedStream {
		externalTransferTracef("native-quic-wait-receiver-ready-write local-opened=%v", localOpenedStream)
		if _, err := streams[0].Write([]byte{externalNativeQUICReceiverReadyByte}); err != nil {
			return err
		}
	}
	var ready [1]byte
	externalTransferTracef("native-quic-wait-receiver-ready-read local-opened=%v", localOpenedStream)
	if _, err := io.ReadFull(streams[0], ready[:]); err != nil {
		return err
	}
	if ready[0] != externalNativeQUICReceiverReadyByte {
		return fmt.Errorf("native QUIC setup ready byte = %d, want %d", ready[0], externalNativeQUICReceiverReadyByte)
	}
	externalTransferTracef("native-quic-wait-receiver-ready-complete local-opened=%v", localOpenedStream)
	return nil
}

func signalExternalNativeQUICReceiverReady(ctx context.Context, streams []*quic.Stream, localOpenedStream bool) error {
	if len(streams) == 0 {
		return errors.New("native QUIC setup has no streams")
	}
	externalTransferTracef("native-quic-signal-receiver-ready-start local-opened=%v stream=%T", localOpenedStream, streams[0])
	cancelDeadline := cancelExternalNativeQUICCarrierDeadlineOnContextDone(ctx, streams[0])
	defer cancelDeadline()

	if !localOpenedStream {
		externalTransferTracef("native-quic-signal-receiver-ready-read local-opened=%v", localOpenedStream)
		var ready [1]byte
		if _, err := io.ReadFull(streams[0], ready[:]); err != nil {
			return err
		}
		if ready[0] != externalNativeQUICReceiverReadyByte {
			return fmt.Errorf("native QUIC setup ready byte = %d, want %d", ready[0], externalNativeQUICReceiverReadyByte)
		}
	}
	externalTransferTracef("native-quic-signal-receiver-ready-write local-opened=%v", localOpenedStream)
	_, err := streams[0].Write([]byte{externalNativeQUICReceiverReadyByte})
	if err == nil {
		externalTransferTracef("native-quic-signal-receiver-ready-complete local-opened=%v", localOpenedStream)
	}
	return err
}

func requestExternalDirectModeAsync(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	localCandidates []net.Addr,
	dm *tailcfg.DERPMap,
	probeConn net.PacketConn,
	emitter *telemetry.Emitter,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeTCPAuth externalNativeTCPAuth,
	forceRelay bool,
) <-chan externalNativeDirectModeResult {
	_ = dm
	_ = probeConn
	resultCh := make(chan externalNativeDirectModeResult, 1)
	go func() {
		nativeQUIC, nativeTCPConns, nativeQUICAddr, err := requestExternalQUICMode(ctx, client, peerDERP, manager, localCandidates, emitter, clientTLSConfig, serverTLSConfig, nativeTCPAuth, forceRelay)
		resultCh <- externalNativeDirectModeResult{
			nativeQUIC:     nativeQUIC,
			nativeQUICAddr: nativeQUICAddr,
			nativeTCPConns: nativeTCPConns,
			err:            err,
		}
	}()
	return resultCh
}

func acceptExternalDirectModeAsync(
	ctx context.Context,
	client *derpbind.Client,
	modeCh <-chan derpbind.Packet,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	localCandidates []net.Addr,
	forceRelay bool,
	emitter *telemetry.Emitter,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeTCPAuth externalNativeTCPAuth,
) <-chan externalNativeDirectModeResult {
	resultCh := make(chan externalNativeDirectModeResult, 1)
	go func() {
		nativeQUIC, nativeTCPConns, nativeQUICAddr, err := acceptExternalQUICMode(
			ctx,
			client,
			modeCh,
			peerDERP,
			manager,
			localCandidates,
			forceRelay,
			emitter,
			clientTLSConfig,
			serverTLSConfig,
			nativeTCPAuth,
		)
		resultCh <- externalNativeDirectModeResult{
			nativeQUIC:     nativeQUIC,
			nativeQUICAddr: nativeQUICAddr,
			nativeTCPConns: nativeTCPConns,
			err:            err,
		}
	}()
	return resultCh
}

func waitExternalNativeDirectModeResult(resultCh <-chan externalNativeDirectModeResult) externalNativeDirectModeResult {
	if resultCh == nil {
		return externalNativeDirectModeResult{}
	}
	return <-resultCh
}

func sendExternalHandoffCarriers(ctx context.Context, carriers []io.ReadWriteCloser, spool *externalHandoffSpool) error {
	if len(carriers) == 0 {
		return nil
	}
	errCh := make(chan error, len(carriers))
	var wg sync.WaitGroup
	for _, carrier := range carriers {
		wg.Add(1)
		go func(carrier io.ReadWriteCloser) {
			defer wg.Done()
			errCh <- sendExternalHandoffCarrier(ctx, carrier, spool, nil)
		}(carrier)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func sendExternalHandoffNativeTCPConns(ctx context.Context, conns []net.Conn, spool *externalHandoffSpool) error {
	carriers := make([]io.ReadWriteCloser, 0, len(conns))
	for _, conn := range conns {
		carriers = append(carriers, conn)
	}
	return sendExternalHandoffCarriers(ctx, carriers, spool)
}

func receiveExternalHandoffNativeTCPConns(ctx context.Context, conns []net.Conn, rx *externalHandoffReceiver) error {
	carriers := make([]io.ReadWriteCloser, 0, len(conns))
	for _, conn := range conns {
		carriers = append(carriers, conn)
	}
	return receiveExternalHandoffCarriers(ctx, carriers, rx)
}

func receiveExternalHandoffNativeQUICStreams(ctx context.Context, streams []*quic.Stream, rx *externalHandoffReceiver) error {
	carriers := make([]io.ReadWriteCloser, 0, len(streams))
	for _, stream := range streams {
		carriers = append(carriers, stream)
	}
	return receiveExternalHandoffCarriers(ctx, carriers, rx)
}

func receiveExternalHandoffCarriers(ctx context.Context, carriers []io.ReadWriteCloser, rx *externalHandoffReceiver) error {
	if len(carriers) == 0 {
		return nil
	}
	errCh := make(chan error, len(carriers))
	var wg sync.WaitGroup
	for _, carrier := range carriers {
		wg.Add(1)
		go func(carrier io.ReadWriteCloser) {
			defer wg.Done()
			errCh <- receiveExternalHandoffCarrier(ctx, carrier, rx, externalCopyBufferSize)
		}(carrier)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
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
			decision.Accept.Candidates = publicInitialProbeCandidates(session.probeConn, publicSessionPortmap(session))
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

		nativeDirectModeCtx, nativeDirectModeCancel := context.WithCancel(ctx)
		defer nativeDirectModeCancel()
		nativeDirectModeCh := acceptExternalDirectModeAsync(
			nativeDirectModeCtx,
			session.derp,
			modeCh,
			peerDERP,
			transportManager,
			localCandidates,
			cfg.ForceRelay,
			cfg.Emitter,
			quicpath.ClientTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
			quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
			externalNativeTCPAuth{
				Enabled:      true,
				SessionID:    session.token.SessionID,
				BearerSecret: session.token.BearerSecret,
				LocalPublic:  session.quicIdentity.Public,
				PeerPublic:   env.Claim.QUICPublic,
			},
		)
		adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
		defer adapter.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("listener-quic-ready")
		}
		quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic), quicpath.DefaultQUICConfig())
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
		if err := runExternalListenStream(
			ctx,
			cfg,
			streamConn,
			quicConn,
			func() {
				_ = quicListener.Close()
			},
			session.derp,
			peerDERP,
			pathEmitter,
			transportManager,
			transportCancel,
			session.probeConn,
			session.derpMap,
			quicpath.ClientTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
			quicpath.ServerTLSConfig(session.quicIdentity, env.Claim.QUICPublic),
			nativeDirectModeCh,
			nativeDirectModeCancel,
		); err != nil {
			return tok, err
		}
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
	localCandidates []net.Addr,
	emitter *telemetry.Emitter,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeTCPAuth externalNativeTCPAuth,
	forceRelay bool,
) (bool, []net.Conn, net.Addr, error) {
	if forceRelay || manager == nil {
		return false, nil, nil, nil
	}

	var localTCPListener net.Listener
	localTCPAddr := ""
	if ln, ok := listenExternalNativeTCPOnCandidates(localCandidates, serverTLSConfig); ok {
		localTCPListener = ln
		localTCPAddr = quicModeDirectAddrString(localTCPListener.Addr())
		defer func() {
			if localTCPListener != nil {
				_ = localTCPListener.Close()
			}
		}()
	}
	if emitter != nil {
		emitter.Debug("sender-tcp-offer=" + strconv.FormatBool(localTCPListener != nil) + " addr=" + localTCPAddr)
	}

	modeCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeResponsePayload(pkt.Payload)
	})
	defer unsubscribe()
	readyCh, unsubscribeReady := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeReadyPayload(pkt.Payload)
	})
	defer unsubscribeReady()

	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeReq,
		QUICModeReq: &quicModeRequest{
			NativeDirect:   true,
			NativeTCP:      localTCPListener != nil,
			DirectAddr:     localTCPAddr,
			NativeTCPConns: externalNativeTCPConnCount(),
		},
	}); err != nil {
		return false, nil, nil, err
	}

	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()
	resp, err := receiveQUICModeResponse(modeCtx, modeCh)
	if err != nil || (!resp.NativeDirect && !resp.NativeTCP) {
		if errors.Is(err, context.Canceled) {
			nackCtx, nackCancel := context.WithTimeout(context.Background(), externalNativeQUICNackWait)
			_ = sendEnvelope(nackCtx, client, peerDERP, envelope{
				Type: envelopeQUICModeAck,
				QUICModeAck: &quicModeAck{
					NativeDirect: false,
					NativeTCP:    false,
				},
			})
			nackCancel()
		}
		if emitter != nil {
			emitter.Debug("sender-tcp-response=none")
		}
		return false, nil, nil, nil
	}
	if emitter != nil {
		emitter.Debug("sender-tcp-response=" + strconv.FormatBool(resp.NativeTCP) + " addr=" + resp.DirectAddr)
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
	var nativeTCPConns []net.Conn
	nativeTCP := resp.NativeTCP && localTCPListener != nil && addr != nil && externalNativeTCPAddrAllowed(addr)
	if nativeTCP {
		tcpTLSConfig := clientTLSConfig
		if externalNativeTCPUseBearerAuth(localTCPListener.Addr(), addr) {
			tcpTLSConfig = nil
		}
		connCount := externalNativeTCPHandshakeConnCount(resp.NativeTCPConns, externalNativeTCPConnCount())
		if connCount > 1 {
			nativeTCPConns, err = connectExternalNativeTCPConns(modeCtx, localTCPListener, addr, tcpTLSConfig, nativeTCPAuth, 0, connCount)
			if err == nil && emitter != nil {
				emitter.Debug("native-tcp-stripes=" + strconv.Itoa(len(nativeTCPConns)))
			}
		} else {
			nativeTCPConn, connectErr := connectExternalNativeTCPSender(modeCtx, localTCPListener, addr, tcpTLSConfig, nativeTCPAuth)
			err = connectErr
			if nativeTCPConn != nil {
				nativeTCPConns = []net.Conn{nativeTCPConn}
			}
		}
		if err != nil {
			if emitter != nil {
				emitter.Debug("sender-tcp-connect-failed=" + err.Error())
			}
			nativeTCP = false
			nativeTCPConns = nil
		}
	}
	ackEnv := envelope{
		Type: envelopeQUICModeAck,
		QUICModeAck: &quicModeAck{
			NativeDirect: resp.NativeDirect && ok && addr != nil,
			NativeTCP:    nativeTCP && len(nativeTCPConns) > 0,
		},
	}
	if err := sendEnvelope(ctx, client, peerDERP, ackEnv); err != nil {
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, err
	}
	if !resp.NativeDirect || !ok || addr == nil {
		if len(nativeTCPConns) > 0 {
			localTCPListener = nil
			return false, nativeTCPConns, nil, nil
		}
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, nil
	}
	if len(nativeTCPConns) > 0 {
		localTCPListener = nil
		return true, nativeTCPConns, cloneSessionAddr(addr), nil
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer readyCancel()
	ready, err := receiveQUICModeReadyWithAckRetry(readyCtx, readyCh, func(ctx context.Context) error {
		return sendEnvelope(ctx, client, peerDERP, ackEnv)
	})
	if err != nil || !ready.NativeDirect {
		closeExternalNativeTCPConns(nativeTCPConns)
		if errors.Is(err, context.Canceled) {
			return false, nil, nil, ctx.Err()
		}
		return false, nil, nil, nil
	}
	return true, nativeTCPConns, cloneSessionAddr(addr), nil
}

func acceptExternalQUICMode(
	ctx context.Context,
	client *derpbind.Client,
	modeCh <-chan derpbind.Packet,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	localCandidates []net.Addr,
	forceRelay bool,
	emitter *telemetry.Emitter,
	clientTLSConfig *tls.Config,
	serverTLSConfig *tls.Config,
	nativeTCPAuth externalNativeTCPAuth,
) (bool, []net.Conn, net.Addr, error) {
	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()

	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	modeAbortCh, unsubscribeModeAbort := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAbortAckPayload(pkt.Payload)
	})
	defer unsubscribeModeAbort()

	req, err := receiveQUICModeRequest(modeCtx, modeCh)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
			return false, nil, nil, nil
		}
		if errors.Is(err, context.Canceled) {
			return false, nil, nil, ctx.Err()
		}
		return false, nil, nil, nil
	}
	if emitter != nil {
		emitter.Debug("listener-tcp-request=" + strconv.FormatBool(req.NativeTCP) + " addr=" + req.DirectAddr)
	}

	nativeQUIC := false
	var nativeQUICAddr net.Addr
	var nativeQUICPeerAddr net.Addr
	var nativeTCPListener net.Listener
	var nativeTCPPeerAddr net.Addr
	var nativeTCPAddr net.Addr
	if (req.NativeDirect || req.NativeTCP) && !forceRelay {
		if req.NativeTCP {
			if parsed := parseCandidateStrings([]string{req.DirectAddr}); len(parsed) == 1 && externalNativeTCPAddrAllowed(parsed[0]) {
				nativeTCPPeerAddr = parsed[0]
				nativeTCPAddr = selectExternalNativeTCPResponseAddr(nativeTCPPeerAddr, nil, localCandidates)
			} else if emitter != nil {
				emitter.Debug("listener-tcp-peer-rejected")
			}
		}
		if nativeTCPPeerAddr != nil && nativeTCPAddr != nil && externalNativeTCPAddrAllowed(nativeTCPAddr) {
			tcpTLSConfig := serverTLSConfig
			if externalNativeTCPUseBearerAuth(nativeTCPAddr, nativeTCPPeerAddr) {
				tcpTLSConfig = nil
			}
			nativeTCPListener, err = listenExternalNativeTCP(nativeTCPAddr, tcpTLSConfig)
			if err != nil {
				if emitter != nil {
					emitter.Debug("listener-tcp-listen-failed=" + err.Error())
				}
				nativeTCPPeerAddr = nil
				nativeTCPAddr = nil
				nativeTCPListener = nil
			}
		} else if req.NativeTCP && emitter != nil {
			emitter.Debug("listener-tcp-offer-rejected")
		}
	}
	if req.NativeDirect && !forceRelay && nativeTCPListener == nil {
		peerDirectAddr, ok, aborted := waitForExternalDirectAddrOrModeAbort(ctx, manager, modeAbortCh, externalNativeQUICWait)
		if aborted {
			return false, nil, nil, nil
		}
		if ok {
			nativeQUIC = true
			nativeQUICPeerAddr = cloneSessionAddr(peerDirectAddr)
			nativeQUICAddr = selectExternalQUICModeResponseAddr(peerDirectAddr, localCandidates)
			if nativeTCPPeerAddr != nil {
				nativeTCPAddr = selectExternalNativeTCPResponseAddr(nativeTCPPeerAddr, peerDirectAddr, localCandidates)
			}
			if emitter != nil {
				emitter.Debug("listener-tcp-selected=" + quicModeDirectAddrString(nativeTCPAddr))
			}
			if nativeTCPPeerAddr != nil && nativeTCPAddr != nil && externalNativeTCPAddrAllowed(nativeTCPAddr) {
				tcpTLSConfig := serverTLSConfig
				if externalNativeTCPUseBearerAuth(nativeTCPAddr, nativeTCPPeerAddr) {
					tcpTLSConfig = nil
				}
				nativeTCPListener, err = listenExternalNativeTCP(nativeTCPAddr, tcpTLSConfig)
				if err != nil {
					if emitter != nil {
						emitter.Debug("listener-tcp-listen-failed=" + err.Error())
					}
					nativeTCPPeerAddr = nil
					nativeTCPListener = nil
				}
			} else if req.NativeTCP && emitter != nil {
				emitter.Debug("listener-tcp-offer-rejected")
			}
		}
	}
	if emitter != nil && nativeTCPListener != nil && !nativeQUIC {
		emitter.Debug("listener-tcp-selected=" + quicModeDirectAddrString(nativeTCPAddr))
	}
	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeResp,
		QUICModeResp: &quicModeResponse{
			NativeDirect:   nativeQUIC,
			NativeTCP:      nativeTCPListener != nil && nativeTCPPeerAddr != nil,
			DirectAddr:     quicModeDirectAddrString(nativeQUICModeResponseAddr(nativeQUICAddr, nativeTCPAddr, nativeTCPListener != nil && nativeTCPPeerAddr != nil)),
			NativeTCPConns: externalNativeTCPHandshakeConnCount(req.NativeTCPConns, externalNativeTCPConnCount()),
		},
	}); err != nil {
		if nativeTCPListener != nil {
			_ = nativeTCPListener.Close()
		}
		return false, nil, nil, err
	}
	if !nativeQUIC && nativeTCPListener == nil {
		return false, nil, nil, nil
	}

	type nativeTCPResult struct {
		conns []net.Conn
		err   error
	}
	var (
		nativeTCPConnCh chan nativeTCPResult
		nativeTCPCancel context.CancelFunc
	)
	nativeTCPConnCount := externalNativeTCPHandshakeConnCount(req.NativeTCPConns, externalNativeTCPConnCount())
	if nativeTCPListener != nil && nativeTCPPeerAddr != nil {
		nativeTCPCtx, cancel := context.WithCancel(ctx)
		nativeTCPCancel = cancel
		nativeTCPConnCh = make(chan nativeTCPResult, 1)
		tcpTLSConfig := clientTLSConfig
		if externalNativeTCPUseBearerAuth(nativeTCPListener.Addr(), nativeTCPPeerAddr) {
			tcpTLSConfig = nil
		}
		go func() {
			connCount := nativeTCPConnCount
			if connCount > 1 {
				conns, err := connectExternalNativeTCPConns(nativeTCPCtx, nativeTCPListener, nativeTCPPeerAddr, tcpTLSConfig, nativeTCPAuth, externalNativeTCPDialFallbackDelay, connCount)
				if err == nil && emitter != nil {
					emitter.Debug("native-tcp-stripes=" + strconv.Itoa(len(conns)))
				}
				nativeTCPConnCh <- nativeTCPResult{conns: conns, err: err}
				return
			}
			conn, err := connectExternalNativeTCPListener(nativeTCPCtx, nativeTCPListener, nativeTCPPeerAddr, tcpTLSConfig, nativeTCPAuth)
			if conn == nil {
				nativeTCPConnCh <- nativeTCPResult{err: err}
				return
			}
			nativeTCPConnCh <- nativeTCPResult{conns: []net.Conn{conn}, err: err}
		}()
	}
	ackCtx, ackCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer ackCancel()
	ack, err := receiveQUICModeAck(ackCtx, ackCh)
	if err != nil || (!ack.NativeDirect && !ack.NativeTCP) {
		if nativeTCPCancel != nil {
			nativeTCPCancel()
		}
		if nativeTCPConnCh != nil {
			result := <-nativeTCPConnCh
			closeExternalNativeTCPConns(result.conns)
		}
		return false, nil, nil, nil
	}
	if nativeTCPListener != nil && (!ack.NativeTCP || nativeTCPPeerAddr == nil) {
		if emitter != nil {
			emitter.Debug("listener-tcp-ack-rejected")
		}
		if nativeTCPCancel != nil {
			nativeTCPCancel()
		}
		if nativeTCPConnCh != nil {
			result := <-nativeTCPConnCh
			closeExternalNativeTCPConns(result.conns)
		}
		if !nativeQUIC {
			return false, nil, nil, nil
		}
		if _, err := sendExternalQUICModeReady(ctx, client, peerDERP, manager, nativeQUICAddr); err != nil {
			return false, nil, nil, err
		}
		return nativeQUIC, nil, cloneSessionAddr(nativeQUICPeerAddr), nil
	}
	if nativeTCPListener == nil {
		if !nativeQUIC {
			return false, nil, nil, nil
		}
		if _, err := sendExternalQUICModeReady(ctx, client, peerDERP, manager, nativeQUICAddr); err != nil {
			return false, nil, nil, err
		}
		return nativeQUIC, nil, cloneSessionAddr(nativeQUICPeerAddr), nil
	}
	result := <-nativeTCPConnCh
	if result.err != nil {
		return false, nil, nil, result.err
	}
	return nativeQUIC, result.conns, cloneSessionAddr(nativeQUICPeerAddr), nil
}

func sendExternalQUICModeReady(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	nativeQUICAddr net.Addr,
) (net.Addr, error) {
	readyAddr := cloneSessionAddr(nativeQUICAddr)
	if manager != nil {
		if readyAddr == nil {
			readyAddr, _ = manager.DirectAddr()
		}
	}
	if err := sendEnvelope(ctx, client, peerDERP, envelope{
		Type:          envelopeQUICModeReady,
		QUICModeReady: &quicModeReady{NativeDirect: true},
	}); err != nil {
		return nil, err
	}
	externalTransferTracef("listener-native-quic-ready-sent addr=%v", readyAddr)
	return cloneSessionAddr(readyAddr), nil
}

func waitExternalNativeQUICSetupGrace(relayErrCh <-chan error, graceWait time.Duration) (error, bool) {
	if graceWait <= 0 {
		return nil, false
	}
	graceTimer := time.NewTimer(graceWait)
	defer graceTimer.Stop()
	select {
	case relayErr := <-relayErrCh:
		return relayErr, true
	case <-graceTimer.C:
		return nil, false
	}
}

func externalNativeQUICSetupGraceWaitForSpool(spool *externalHandoffSpool) time.Duration {
	return 0
}

func externalNativeQUICSetupShouldSkipForSpool(spool *externalHandoffSpool) bool {
	if spool == nil {
		return false
	}

	spool.mu.Lock()
	defer spool.mu.Unlock()

	if !spool.eof {
		externalTransferTracef(
			"sender-native-quic-setup-skip-check eof=%v source=%d read=%d acked=%d tail=%d cutoff=%d skip=false",
			spool.eof,
			spool.sourceOffset,
			spool.readOffset,
			spool.ackedWatermark,
			spool.sourceOffset-spool.ackedWatermark,
			externalNativeQUICSetupSkipRelayTailBytes,
		)
		return false
	}
	tail := spool.sourceOffset - spool.ackedWatermark
	skip := tail <= externalNativeQUICSetupSkipRelayTailBytes
	externalTransferTracef(
		"sender-native-quic-setup-skip-check eof=%v source=%d read=%d acked=%d tail=%d cutoff=%d skip=%v",
		spool.eof,
		spool.sourceOffset,
		spool.readOffset,
		spool.ackedWatermark,
		tail,
		externalNativeQUICSetupSkipRelayTailBytes,
		skip,
	)
	return skip
}

func waitExternalNativeQUICRelayTailPeerAck(ctx context.Context, spool *externalHandoffSpool, ackCh <-chan derpbind.Packet) (bool, error) {
	if !externalNativeQUICSetupShouldSkipForSpool(spool) {
		return false, nil
	}

	ackCtx, cancel := context.WithTimeout(ctx, externalNativeQUICRelayTailPeerAckWait)
	defer cancel()

	if err := waitForPeerAck(ackCtx, ackCh); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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
	return nil
}

func nativeQUICModeResponseAddr(nativeQUICAddr, nativeTCPAddr net.Addr, nativeTCP bool) net.Addr {
	if nativeTCP && nativeTCPAddr != nil {
		return nativeTCPAddr
	}
	return nativeQUICAddr
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

func receiveQUICModeReadyWithAckRetry(
	ctx context.Context,
	readyCh <-chan derpbind.Packet,
	sendAck func(context.Context) error,
) (quicModeReady, error) {
	retry := time.NewTicker(externalNativeQUICAckRetryInterval)
	defer retry.Stop()

	for {
		select {
		case pkt, ok := <-readyCh:
			if !ok {
				return quicModeReady{}, net.ErrClosed
			}
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeQUICModeReady || env.QUICModeReady == nil {
				return quicModeReady{}, errors.New("unexpected quic mode ready")
			}
			return *env.QUICModeReady, nil
		case <-retry.C:
			if sendAck != nil {
				if err := sendAck(ctx); err != nil {
					return quicModeReady{}, err
				}
			}
		case <-ctx.Done():
			return quicModeReady{}, ctx.Err()
		}
	}
}

func waitForExternalDirectAddr(ctx context.Context, manager *transport.Manager, timeout time.Duration) (net.Addr, bool) {
	addr, ok, _ := waitForExternalDirectAddrOrModeAbort(ctx, manager, nil, timeout)
	return addr, ok
}

func waitForExternalDirectAddrOrModeAbort(
	ctx context.Context,
	manager *transport.Manager,
	modeAckCh <-chan derpbind.Packet,
	timeout time.Duration,
) (net.Addr, bool, bool) {
	if manager == nil {
		return nil, false, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if addr, ok := manager.DirectAddr(); ok && addr != nil {
			externalTransferTracef("wait-direct-addr-ready path=%v addr=%v", manager.PathState(), addr)
			return cloneSessionAddr(addr), true, false
		}
		externalTransferTracef("wait-direct-addr-pending path=%v", manager.PathState())
		select {
		case <-ctx.Done():
			externalTransferTracef("wait-direct-addr-context-done err=%v", ctx.Err())
			return nil, false, false
		case pkt, ok := <-modeAckCh:
			if !ok {
				externalTransferTracef("wait-direct-addr-mode-ack-closed")
				return nil, false, true
			}
			ackEnv, err := decodeEnvelope(pkt.Payload)
			if err == nil &&
				ackEnv.Type == envelopeQUICModeAck &&
				ackEnv.QUICModeAck != nil &&
				!ackEnv.QUICModeAck.NativeDirect &&
				!ackEnv.QUICModeAck.NativeTCP {
				externalTransferTracef("wait-direct-addr-mode-abort")
				return nil, false, true
			}
		case <-timer.C:
			externalTransferTracef("wait-direct-addr-timeout")
			return nil, false, false
		case <-ticker.C:
		}
	}
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

func sendClaimAndReceiveDecision(
	ctx context.Context,
	client *derpbind.Client,
	dst key.NodePublic,
	claim rendezvous.Claim,
) (rendezvous.Decision, error) {
	decisionCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == dst && isDecisionPayload(pkt.Payload)
	})
	defer unsubscribe()

	if err := sendEnvelope(ctx, client, dst, envelope{Type: envelopeClaim, Claim: &claim}); err != nil {
		return rendezvous.Decision{}, fmt.Errorf("send claim: %w", err)
	}

	retry := time.NewTicker(externalClaimRetryInterval)
	defer retry.Stop()

	for {
		select {
		case pkt, ok := <-decisionCh:
			if !ok {
				return rendezvous.Decision{}, net.ErrClosed
			}
			env, err := decodeEnvelope(pkt.Payload)
			if err != nil || env.Type != envelopeDecision || env.Decision == nil {
				continue
			}
			return *env.Decision, nil
		case <-retry.C:
			if err := sendEnvelope(ctx, client, dst, envelope{Type: envelopeClaim, Claim: &claim}); err != nil {
				return rendezvous.Decision{}, fmt.Errorf("resend claim: %w", err)
			}
		case <-ctx.Done():
			return rendezvous.Decision{}, ctx.Err()
		}
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
	return publicProbeCandidatesFromSTUNPackets(ctx, conn, dm, pm, nil)
}

func publicProbeCandidatesFromSTUNPackets(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	pm publicPortmap,
	stunPackets <-chan traversal.STUNPacket,
) []string {
	candidates := publicInitialProbeCandidates(conn, pm)
	if fakeTransportCandidatesBlocked() {
		return nil
	}
	if conn == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		seen[candidate] = struct{}{}
	}

	if dm != nil {
		var mapped func() (netip.AddrPort, bool)
		if pm != nil {
			mapped = pm.Snapshot
		}
		var gathered []string
		var err error
		if stunPackets != nil {
			gathered, err = gatherTraversalCandidatesFromSTUNPackets(ctx, conn, dm, mapped, stunPackets)
		} else {
			gathered, err = gatherTraversalCandidates(ctx, conn, dm, mapped)
		}
		if err == nil {
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

	candidates = candidates[:0]
	for candidate := range seen {
		candidates = append(candidates, candidate)
	}
	slices.Sort(candidates)
	if len(candidates) > rendezvous.MaxClaimCandidates {
		candidates = candidates[:rendezvous.MaxClaimCandidates]
	}
	return candidates
}

func publicInitialProbeCandidates(conn net.PacketConn, pm publicPortmap) []string {
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
	add := func(ip netip.Addr, port int) {
		if !publicProbeCandidateAllowed(ip) {
			return
		}
		candidate := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		seen[candidate] = struct{}{}
	}

	addrs, _ := publicInterfaceAddrs()
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsGlobalUnicast() {
			add(ip, port)
		}
	}

	if pm != nil {
		if mapped, ok := pm.Snapshot(); ok && mapped.IsValid() {
			add(mapped.Addr(), int(mapped.Port()))
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
	if !publicProbeTailscaleCGNATPrefix.Contains(ip) && !publicProbeTailscaleULAPrefix.Contains(ip) {
		return true
	}
	if os.Getenv("DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES") == "1" {
		return false
	}
	return os.Getenv("DERPCAT_ENABLE_TAILSCALE_CANDIDATES") == "1"
}

func publicProbeAddrs(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap) []net.Addr {
	raw := publicProbeCandidates(ctx, conn, dm, pm)
	return parseCandidateStrings(raw)
}

func publicCandidateSource(
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	pm publicPortmap,
	localCandidates []net.Addr,
	stunPackets <-chan traversal.STUNPacket,
) func(context.Context) []net.Addr {
	if fakeTransportEnabled() {
		return func(ctx context.Context) []net.Addr {
			_ = dm
			_ = pm
			return publicProbeAddrs(ctx, conn, nil, nil)
		}
	}
	return func(ctx context.Context) []net.Addr {
		probeCtx, cancel := context.WithTimeout(ctx, externalPublicCandidateRefreshWait)
		defer cancel()

		candidates := publicProbeAddrsFromSTUNPackets(probeCtx, conn, dm, pm, stunPackets)
		if len(candidates) > 0 {
			return candidates
		}
		return slices.Clone(localCandidates)
	}
}

func publicProbeAddrsFromSTUNPackets(
	ctx context.Context,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	pm publicPortmap,
	stunPackets <-chan traversal.STUNPacket,
) []net.Addr {
	raw := publicProbeCandidatesFromSTUNPackets(ctx, conn, dm, pm, stunPackets)
	return parseCandidateStrings(raw)
}

func publicSTUNPacket(payload []byte, addr net.Addr) (traversal.STUNPacket, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return traversal.STUNPacket{}, false
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return traversal.STUNPacket{}, false
	}
	return traversal.STUNPacket{
		Payload: payload,
		Addr:    netip.AddrPortFrom(ip.Unmap(), uint16(udpAddr.Port)),
	}, true
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

func isQUICModeAbortAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil &&
		env.Type == envelopeQUICModeAck &&
		env.QUICModeAck != nil &&
		!env.QUICModeAck.NativeDirect &&
		!env.QUICModeAck.NativeTCP
}

func isQUICModeReadyPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeQUICModeReady && env.QUICModeReady != nil
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
		!isQUICModeAckPayload(payload) &&
		!isQUICModeReadyPayload(payload)
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
	if raw := os.Getenv("DERPCAT_NATIVE_QUIC_CONNS"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err == nil && count > 0 {
			return count
		}
	}
	return defaultExternalNativeQUICConns
}
