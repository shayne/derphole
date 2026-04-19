//lint:file-ignore U1000 Retired public QUIC handoff helpers pending deletion after the WG cutover settles.
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

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/candidate"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/portmap"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"github.com/shayne/derphole/pkg/traversal"
	wgtransport "github.com/shayne/derphole/pkg/wg"
	"tailscale.com/net/batching"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	envelopeClaim              = "claim"
	envelopeDecision           = "decision"
	envelopeControl            = "control"
	envelopeAck                = "ack"
	envelopeAbort              = "abort"
	envelopeHeartbeat          = "heartbeat"
	envelopeDirectUDPReady     = "direct_udp_ready"
	envelopeDirectUDPReadyAck  = "direct_udp_ready_ack"
	envelopeDirectUDPStart     = "direct_udp_start"
	envelopeDirectUDPStartAck  = "direct_udp_start_ack"
	envelopeDirectUDPRateProbe = "direct_udp_rate_probe"
	envelopeQUICModeReq        = "quic_mode_request"
	envelopeQUICModeResp       = "quic_mode_response"
	envelopeQUICModeAck        = "quic_mode_ack"
	envelopeQUICModeReady      = "quic_mode_ready"
	envelopeParallelGrowReq    = "parallel_grow_request"
	envelopeParallelGrowAck    = "parallel_grow_ack"
	envelopeParallelGrowResult = "parallel_grow_result"
	maxEnvelopeBytes           = 16 << 10
)

const externalNativeQUICWait = 5 * time.Second
const externalNativeQUICConnectWait = externalNativeQUICWait
const externalNativeTCPDirectStartWait = 750 * time.Millisecond
const externalNativeQUICAckRetryInterval = 250 * time.Millisecond
const externalNativeQUICNackWait = 1 * time.Second
const externalNativeQUICSetupGraceWait = 0
const externalNativeQUICSetupSkipRelayTailBytes = 256 << 10
const externalNativeQUICRelayTailPeerAckWait = 250 * time.Millisecond
const externalPublicCandidateRefreshWait = 750 * time.Millisecond
const externalDirectUDPCandidateGatherWait = 250 * time.Millisecond
const externalCopyBufferSize = 256 << 10
const defaultExternalNativeQUICConns = 4
const externalClaimRetryInterval = 250 * time.Millisecond

var peerHeartbeatInterval = 2 * time.Second
var peerHeartbeatTimeout = 30 * time.Second

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
	Type               string                    `json:"type"`
	MAC                string                    `json:"mac,omitempty"`
	Claim              *rendezvous.Claim         `json:"claim,omitempty"`
	Decision           *rendezvous.Decision      `json:"decision,omitempty"`
	Control            *transport.ControlMessage `json:"control,omitempty"`
	Ack                *peerAck                  `json:"ack,omitempty"`
	Abort              *peerAbort                `json:"abort,omitempty"`
	Heartbeat          *peerHeartbeat            `json:"heartbeat,omitempty"`
	DirectUDPReadyAck  *directUDPReadyAck        `json:"direct_udp_ready_ack,omitempty"`
	DirectUDPStart     *directUDPStart           `json:"direct_udp_start,omitempty"`
	DirectUDPRateProbe *directUDPRateProbeResult `json:"direct_udp_rate_probe,omitempty"`
	QUICModeReq        *quicModeRequest          `json:"quic_mode_request,omitempty"`
	QUICModeResp       *quicModeResponse         `json:"quic_mode_response,omitempty"`
	QUICModeAck        *quicModeAck              `json:"quic_mode_ack,omitempty"`
	QUICModeReady      *quicModeReady            `json:"quic_mode_ready,omitempty"`
	ParallelGrowReq    *parallelGrowRequest      `json:"parallel_grow_request,omitempty"`
	ParallelGrowAck    *parallelGrowAck          `json:"parallel_grow_ack,omitempty"`
	ParallelGrowResult *parallelGrowResult       `json:"parallel_grow_result,omitempty"`
}

type peerAck struct {
	BytesReceived *int64 `json:"bytes_received,omitempty"`
}

func newPeerAck(bytesReceived int64) *peerAck {
	return &peerAck{BytesReceived: &bytesReceived}
}

type peerAbort struct {
	Reason           string `json:"reason,omitempty"`
	BytesTransferred *int64 `json:"bytes_transferred,omitempty"`
}

func newPeerAbort(reason string, bytesTransferred int64) *peerAbort {
	return &peerAbort{
		Reason:           reason,
		BytesTransferred: &bytesTransferred,
	}
}

type peerHeartbeat struct {
	BytesTransferred *int64 `json:"bytes_transferred,omitempty"`
	Sequence         uint64 `json:"sequence,omitempty"`
	MAC              string `json:"mac,omitempty"`
}

func newPeerHeartbeat(bytesTransferred int64) *peerHeartbeat {
	return &peerHeartbeat{BytesTransferred: &bytesTransferred}
}

type directUDPReadyAck struct {
	FastDiscard bool `json:"fast_discard,omitempty"`
}

type directUDPStart struct {
	ExpectedBytes int64    `json:"expected_bytes,omitempty"`
	SectionSizes  []int64  `json:"section_sizes,omitempty"`
	SectionAddrs  []string `json:"section_addrs,omitempty"`
	ProbeRates    []int    `json:"probe_rates,omitempty"`
	ProbeNonce    string   `json:"probe_nonce,omitempty"`
	Stream        bool     `json:"stream,omitempty"`
	StripedBlast  bool     `json:"striped_blast,omitempty"`
}

type directUDPRateProbeResult struct {
	Samples []directUDPRateProbeSample `json:"samples,omitempty"`
}

type directUDPRateProbeSample struct {
	RateMbps       int   `json:"rate_mbps,omitempty"`
	BytesSent      int64 `json:"bytes_sent,omitempty"`
	BytesReceived  int64 `json:"bytes_received,omitempty"`
	DurationMillis int64 `json:"duration_millis,omitempty"`
}

type quicModeRequest struct {
	NativeDirect    bool   `json:"native_direct"`
	NativeTCP       bool   `json:"native_tcp,omitempty"`
	DirectAddr      string `json:"direct_addr,omitempty"`
	NativeTCPConns  int    `json:"native_tcp_conns,omitempty"`
	ParallelMode    string `json:"parallel_mode,omitempty"`
	ParallelInitial int    `json:"parallel_initial,omitempty"`
	ParallelCap     int    `json:"parallel_cap,omitempty"`
}

type quicModeResponse struct {
	NativeDirect    bool   `json:"native_direct"`
	NativeTCP       bool   `json:"native_tcp,omitempty"`
	DirectAddr      string `json:"direct_addr,omitempty"`
	NativeTCPConns  int    `json:"native_tcp_conns,omitempty"`
	ParallelMode    string `json:"parallel_mode,omitempty"`
	ParallelInitial int    `json:"parallel_initial,omitempty"`
	ParallelCap     int    `json:"parallel_cap,omitempty"`
}

type quicModeAck struct {
	NativeDirect bool `json:"native_direct"`
	NativeTCP    bool `json:"native_tcp,omitempty"`
}

type quicModeReady struct {
	NativeDirect bool `json:"native_direct"`
}

type parallelGrowRequest struct {
	Target        int        `json:"target"`
	CandidateSets [][]string `json:"candidate_sets,omitempty"`
}

type parallelGrowAck struct {
	Target        int        `json:"target"`
	Ready         bool       `json:"ready"`
	CandidateSets [][]string `json:"candidate_sets,omitempty"`
}

type parallelGrowResult struct {
	Target  int  `json:"target"`
	Ready   bool `json:"ready"`
	Applied int  `json:"applied,omitempty"`
}

type remoteCandidateSeeder interface {
	SeedRemoteCandidates(context.Context, []net.Addr)
}

func derpPublicKeyRaw32(pub key.NodePublic) [32]byte {
	var raw [32]byte
	copy(raw[:], pub.AppendTo(raw[:0]))
	return raw
}

func issuePublicSessionWithCapabilities(ctx context.Context, capabilities uint32) (string, *relaySession, error) {
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
	wgPrivate, wgPublic, err := wgtransport.GenerateKeypair()
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
		QUICPublic:      wgPublic,
		BearerSecret:    bearerSecret,
		Capabilities:    capabilities,
	}
	if bootstrapAddr, ok := externalNativeTCPTokenBootstrapAddr(); ok {
		tokValue.SetNativeTCPBootstrapAddr(bootstrapAddr)
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
		wgPrivate:    wgPrivate,
		wgPublic:     wgPublic,
	}
	attachPublicPortmap(session, newBoundPublicPortmap(probeConn, nil))
	return tok, session, nil
}

func issuePublicSession(ctx context.Context) (string, *relaySession, error) {
	return issuePublicSessionWithCapabilities(ctx, token.CapabilityStdio)
}

func sendExternal(ctx context.Context, cfg SendConfig) error {
	return sendExternalViaDirectUDP(ctx, cfg)
}

func runExternalSendStream(
	ctx context.Context,
	cfg SendConfig,
	src io.ReadCloser,
	quicConn *quic.Conn,
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
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
	countedSrc := newByteCountingReadCloser(src)

	externalTransferTracef("sender-open-relay-stream-start")
	streamConn, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer streamConn.Close()
	externalTransferTracef("sender-open-relay-stream-complete")

	spool, err := newExternalHandoffSpool(countedSrc, externalCopyBufferSize, externalHandoffMaxUnackedBytes)
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
			if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
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
			copyErr := sendExternalHandoffNativeTCPConns(ctx, modeResult.nativeTCPConns, spool)
			if copyErr != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return copyErr
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
			if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
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
			if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
				return err
			}
			if err := quicConn.CloseWithError(0, ""); err != nil {
				return err
			}
			pathEmitter.Complete(transportManager)
			return nil
		}

		pathEmitter.SuppressRelayRegression()
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
				externalParallelQUICConnCount(modeResult.parallelPolicy),
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
			if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
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
			pathEmitter.ResumeRelayRegression()
			pathEmitter.Flush(transportManager)
			if err := <-relayErrCh; err != nil {
				return err
			}
			if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
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
		runtime := newExternalHandoffSendRuntime(ctx, spool)
		for _, stream := range nativeQUICSetup.streams {
			if err := runtime.Add(stream); err != nil {
				closeExternalNativeQUICSendSetupResult(nativeQUICSetup)
				return err
			}
		}
		var growthDone <-chan struct{}
		if modeResult.parallelPolicy.Mode == ParallelModeAuto {
			growthDone = startParallelAutoGrowthLoop(ctx, derpClient, peerDERP, nativeQUICSetup.session, runtime, spool, modeResult.parallelPolicy, cfg.Emitter)
		}
		if growthDone != nil {
			<-growthDone
		}
		if err := runtime.CloseAndWait(); err != nil {
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
		if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
			return err
		}
		if err := quicConn.CloseWithError(0, ""); err != nil {
			return err
		}
		pathEmitter.Complete(transportManager)
		return nil
	}

	if err := waitForPeerAck(ctx, ackCh, countedSrc.Count()); err != nil {
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
	dst io.WriteCloser,
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
			copyErr := receiveExternalHandoffNativeTCPConns(ctx, modeResult.nativeTCPConns, rx)
			if copyErr != nil {
				closeExternalNativeTCPConns(modeResult.nativeTCPConns)
				return copyErr
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

			pathEmitter.SuppressRelayRegression()
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
					externalParallelQUICConnCount(modeResult.parallelPolicy),
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
				pathEmitter.ResumeRelayRegression()
				pathEmitter.Flush(transportManager)
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
			runtime := newExternalHandoffReceiveRuntime(ctx, rx)
			for _, stream := range nativeQUICSetup.streams {
				if err := runtime.Add(stream); err != nil {
					return err
				}
			}
			growthCtx, growthCancel := context.WithCancel(ctx)
			var growthDone <-chan struct{}
			if modeResult.parallelPolicy.Mode == ParallelModeAuto {
				growthDone = startParallelGrowthRequestHandler(growthCtx, derpClient, peerDERP, nativeQUICSetup.session, runtime, cfg.Emitter)
			}
			err := runtime.Wait()
			growthCancel()
			if growthDone != nil {
				<-growthDone
			}
			runtime.Close()
			if err != nil {
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
				externalParallelQUICConnCount(modeResult.parallelPolicy),
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
			runtime := newExternalHandoffReceiveRuntime(ctx, rx)
			for _, stream := range nativeQUICStreams {
				if err := runtime.Add(stream); err != nil {
					return err
				}
			}
			growthCtx, growthCancel := context.WithCancel(ctx)
			var growthDone <-chan struct{}
			if modeResult.parallelPolicy.Mode == ParallelModeAuto {
				growthDone = startParallelGrowthRequestHandler(growthCtx, derpClient, peerDERP, nativeQUICSession, runtime, cfg.Emitter)
			}
			err = runtime.Wait()
			growthCancel()
			if growthDone != nil {
				<-growthDone
			}
			runtime.Close()
			if err != nil {
				return err
			}
			externalTransferTracef("listener-native-quic-copy-complete watermark=%d", rx.Watermark())
		}
	}

	if err := sendPeerAck(ctx, derpClient, peerDERP, rx.Watermark()); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

type externalNativeDirectModeResult struct {
	nativeQUIC     bool
	nativeQUICAddr net.Addr
	nativeTCPConns []net.Conn
	parallelPolicy ParallelPolicy
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
	parallelPolicy ParallelPolicy,
	forceRelay bool,
) <-chan externalNativeDirectModeResult {
	_ = dm
	_ = probeConn
	resultCh := make(chan externalNativeDirectModeResult, 1)
	go func() {
		nativeQUIC, nativeTCPConns, nativeQUICAddr, resolvedPolicy, err := requestExternalQUICMode(ctx, client, peerDERP, manager, localCandidates, emitter, clientTLSConfig, serverTLSConfig, nativeTCPAuth, parallelPolicy, forceRelay)
		resultCh <- externalNativeDirectModeResult{
			nativeQUIC:     nativeQUIC,
			nativeQUICAddr: nativeQUICAddr,
			nativeTCPConns: nativeTCPConns,
			parallelPolicy: resolvedPolicy,
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
		nativeQUIC, nativeTCPConns, nativeQUICAddr, resolvedPolicy, err := acceptExternalQUICMode(
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
			parallelPolicy: resolvedPolicy,
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
	return listenExternalViaDirectUDP(ctx, cfg)
}

func sendExternalNativeTCPDirect(ctx context.Context, src io.Reader, conns []net.Conn) error {
	defer closeExternalNativeTCPConns(conns)
	writers := newExternalStripedBufferedWriteClosers(conns, externalNativeTCPCopyChunkSize())
	copyErr := sendExternalStripedCopy(ctx, src, writers, externalNativeTCPCopyChunkSize())
	if copyErr != nil {
		closeExternalNativeTCPConns(conns)
		return copyErr
	}
	return nil
}

func receiveExternalNativeTCPDirect(ctx context.Context, dst io.WriteCloser, conns []net.Conn) error {
	defer closeExternalNativeTCPConns(conns)
	readers := newExternalStripedBufferedReadClosers(conns, externalNativeTCPCopyChunkSize())
	copyErr := receiveExternalStripedCopy(ctx, dst, readers, externalNativeTCPCopyChunkSize())
	if copyErr != nil {
		closeExternalNativeTCPConns(conns)
		return copyErr
	}
	return nil
}

func startExternalTransportManager(
	ctx context.Context,
	tok token.Token,
	conn net.PacketConn,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
	localCandidates []net.Addr,
	pm publicPortmap,
	forceRelay bool,
) (*transport.Manager, func(), error) {
	auth := externalPeerControlAuthForToken(tok)
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
		DiscoveryKey:            externalTransportDiscoveryKey(tok, derpClient.PublicKey(), peerDERP),
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
	parallelPolicy ParallelPolicy,
	forceRelay bool,
	authOpt ...externalPeerControlAuth,
) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	if forceRelay || manager == nil {
		return false, nil, nil, ParallelPolicy{}, nil
	}
	auth := optionalPeerControlAuth(authOpt)
	parallelPolicy = parallelPolicy.normalized()

	var localTCPListener net.Listener
	localTCPAddr := ""
	nativeTCPRequested := false
	if ln, ok := listenExternalNativeTCPOnCandidates(localCandidates, serverTLSConfig); ok {
		localTCPListener = ln
		localTCPAddr = quicModeDirectAddrString(externalNativeTCPAdvertiseAddr(localTCPListener.Addr(), nil))
		nativeTCPRequested = true
		defer func() {
			if localTCPListener != nil {
				_ = localTCPListener.Close()
			}
		}()
	}
	if emitter != nil {
		emitter.Debug("sender-tcp-offer=" + strconv.FormatBool(nativeTCPRequested) + " addr=" + localTCPAddr)
	}

	modeCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeResponsePayload(pkt.Payload)
	})
	defer unsubscribe()
	readyCh, unsubscribeReady := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeReadyPayload(pkt.Payload)
	})
	defer unsubscribeReady()

	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeReq,
		QUICModeReq: &quicModeRequest{
			NativeDirect:    true,
			NativeTCP:       nativeTCPRequested,
			DirectAddr:      localTCPAddr,
			NativeTCPConns:  externalParallelTCPConnCount(parallelPolicy),
			ParallelMode:    string(parallelPolicy.Mode),
			ParallelInitial: parallelPolicy.Initial,
			ParallelCap:     parallelPolicy.Cap,
		},
	}, auth); err != nil {
		return false, nil, nil, ParallelPolicy{}, err
	}

	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()
	resp, err := receiveQUICModeResponse(modeCtx, modeCh, auth)
	if err != nil || (!resp.NativeDirect && !resp.NativeTCP) {
		if errors.Is(err, context.Canceled) {
			nackCtx, nackCancel := context.WithTimeout(context.Background(), externalNativeQUICNackWait)
			_ = sendAuthenticatedEnvelope(nackCtx, client, peerDERP, envelope{
				Type: envelopeQUICModeAck,
				QUICModeAck: &quicModeAck{
					NativeDirect: false,
					NativeTCP:    false,
				},
			}, auth)
			nackCancel()
		}
		if emitter != nil {
			emitter.Debug("sender-tcp-response=none")
		}
		return false, nil, nil, ParallelPolicy{}, nil
	}
	if emitter != nil {
		emitter.Debug("sender-tcp-response=" + strconv.FormatBool(resp.NativeTCP) + " addr=" + resp.DirectAddr)
	}

	resolvedPolicy := quicModeParallelPolicy(resp)
	if resolvedPolicy.Mode == "" {
		resolvedPolicy = parallelPolicy
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
	nativeTCP := resp.NativeTCP && addr != nil && externalNativeTCPAddrAllowed(addr)
	if nativeTCP {
		tcpTLSConfig := clientTLSConfig
		connCount := externalNativeTCPHandshakeConnCount(resp.NativeTCPConns, externalParallelTCPConnCount(parallelPolicy))
		if localTCPListener != nil {
			if externalNativeTCPUseBearerAuth(localTCPListener.Addr(), addr) {
				tcpTLSConfig = nil
			}
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
		} else {
			if connCount > 1 {
				nativeTCPConns, err = dialExternalNativeTCPConns(modeCtx, addr, tcpTLSConfig, nativeTCPAuth, connCount)
				if err == nil && emitter != nil {
					emitter.Debug("native-tcp-stripes=" + strconv.Itoa(len(nativeTCPConns)))
				}
			} else {
				nativeTCPConn, connectErr := dialExternalNativeTCP(modeCtx, addr, tcpTLSConfig, nativeTCPAuth)
				err = connectErr
				if nativeTCPConn != nil {
					nativeTCPConns = []net.Conn{nativeTCPConn}
				}
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
	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, ackEnv, auth); err != nil {
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, resolvedPolicy, err
	}
	if !resp.NativeDirect || !ok || addr == nil {
		if len(nativeTCPConns) > 0 {
			localTCPListener = nil
			return false, nativeTCPConns, nil, resolvedPolicy, nil
		}
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, resolvedPolicy, nil
	}
	if len(nativeTCPConns) > 0 {
		localTCPListener = nil
		return true, nativeTCPConns, cloneSessionAddr(addr), resolvedPolicy, nil
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer readyCancel()
	ready, err := receiveQUICModeReadyWithAckRetry(readyCtx, readyCh, func(ctx context.Context) error {
		return sendAuthenticatedEnvelope(ctx, client, peerDERP, ackEnv, auth)
	}, auth)
	if err != nil || !ready.NativeDirect {
		closeExternalNativeTCPConns(nativeTCPConns)
		if errors.Is(err, context.Canceled) {
			return false, nil, nil, resolvedPolicy, ctx.Err()
		}
		return false, nil, nil, resolvedPolicy, nil
	}
	return true, nativeTCPConns, cloneSessionAddr(addr), resolvedPolicy, nil
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
	authOpt ...externalPeerControlAuth,
) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)

	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	modeAbortCh, unsubscribeModeAbort := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAbortAckPayload(pkt.Payload)
	})
	defer unsubscribeModeAbort()

	req, err := receiveQUICModeRequest(modeCtx, modeCh, auth)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
			return false, nil, nil, ParallelPolicy{}, nil
		}
		if errors.Is(err, context.Canceled) {
			return false, nil, nil, ParallelPolicy{}, ctx.Err()
		}
		return false, nil, nil, ParallelPolicy{}, nil
	}
	requestedPolicy := quicModeParallelPolicy(req)
	if requestedPolicy.Mode == "" {
		requestedPolicy = DefaultParallelPolicy()
	}
	if emitter != nil {
		emitter.Debug("listener-tcp-request=" + strconv.FormatBool(req.NativeTCP) + " addr=" + req.DirectAddr)
	}

	nativeQUIC := false
	var nativeQUICAddr net.Addr
	var nativeQUICPeerAddr net.Addr
	var nativeTCPListener net.Listener
	var nativeTCPPeerAddr net.Addr
	var nativeTCPBindAddr net.Addr
	var nativeTCPAddr net.Addr
	if (req.NativeDirect || req.NativeTCP) && !forceRelay {
		if req.NativeTCP {
			if parsed := parseCandidateStrings([]string{req.DirectAddr}); len(parsed) == 1 && externalNativeTCPAddrAllowed(parsed[0]) {
				peerCandidate := parsed[0]
				bindAddr := selectExternalNativeTCPResponseAddr(peerCandidate, nil, localCandidates)
				if bindAddr != nil {
					nativeTCPPeerAddr = peerCandidate
					nativeTCPBindAddr = bindAddr
					nativeTCPAddr = externalNativeTCPAdvertiseAddr(nativeTCPBindAddr, nativeTCPPeerAddr)
				} else {
					nativeTCPBindAddr = selectExternalNativeTCPOfferAddr(localCandidates)
					nativeTCPAddr = externalNativeTCPAdvertiseAddr(nativeTCPBindAddr, nil)
				}
			} else {
				nativeTCPBindAddr = selectExternalNativeTCPOfferAddr(localCandidates)
				nativeTCPAddr = externalNativeTCPAdvertiseAddr(nativeTCPBindAddr, nil)
				if nativeTCPBindAddr == nil && emitter != nil {
					emitter.Debug("listener-tcp-peer-rejected")
				}
			}
		}
		if nativeTCPBindAddr != nil && externalNativeTCPAddrAllowed(nativeTCPBindAddr) {
			tcpTLSConfig := serverTLSConfig
			if externalNativeTCPUseBearerAuth(nativeTCPBindAddr, nativeTCPPeerAddr) {
				tcpTLSConfig = nil
			}
			nativeTCPListener, err = listenExternalNativeTCP(nativeTCPBindAddr, tcpTLSConfig)
			if err != nil {
				if emitter != nil {
					emitter.Debug("listener-tcp-listen-failed=" + err.Error())
				}
				nativeTCPPeerAddr = nil
				nativeTCPBindAddr = nil
				nativeTCPAddr = nil
				nativeTCPListener = nil
			}
		} else if req.NativeTCP && emitter != nil {
			emitter.Debug("listener-tcp-offer-rejected")
		}
	}
	if req.NativeDirect && !forceRelay && nativeTCPListener == nil {
		peerDirectAddr, ok, aborted := waitForExternalDirectAddrOrModeAbort(ctx, manager, modeAbortCh, externalNativeQUICWait, auth)
		if aborted {
			return false, nil, nil, ParallelPolicy{}, nil
		}
		if ok {
			nativeQUIC = true
			nativeQUICPeerAddr = cloneSessionAddr(peerDirectAddr)
			nativeQUICAddr = selectExternalQUICModeResponseAddr(peerDirectAddr, localCandidates)
			if nativeTCPPeerAddr != nil {
				nativeTCPBindAddr = selectExternalNativeTCPResponseAddr(nativeTCPPeerAddr, peerDirectAddr, localCandidates)
				nativeTCPAddr = externalNativeTCPAdvertiseAddr(nativeTCPBindAddr, nativeTCPPeerAddr)
			}
			if emitter != nil {
				emitter.Debug("listener-tcp-selected=" + quicModeDirectAddrString(nativeTCPAddr))
			}
			if nativeTCPBindAddr != nil && externalNativeTCPAddrAllowed(nativeTCPBindAddr) {
				tcpTLSConfig := serverTLSConfig
				if externalNativeTCPUseBearerAuth(nativeTCPBindAddr, nativeTCPPeerAddr) {
					tcpTLSConfig = nil
				}
				nativeTCPListener, err = listenExternalNativeTCP(nativeTCPBindAddr, tcpTLSConfig)
				if err != nil {
					if emitter != nil {
						emitter.Debug("listener-tcp-listen-failed=" + err.Error())
					}
					nativeTCPPeerAddr = nil
					nativeTCPBindAddr = nil
					nativeTCPAddr = nil
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
	resolvedPolicy := requestedPolicy
	if nativeQUIC && nativeQUICPeerAddr != nil {
		resolvedPolicy.Initial = externalNativeQUICConnCountForPeer(nativeQUICPeerAddr, resolvedPolicy.Initial)
		resolvedPolicy.Cap = externalNativeQUICConnCountForPeer(nativeQUICPeerAddr, resolvedPolicy.Cap)
		if resolvedPolicy.Cap < resolvedPolicy.Initial {
			resolvedPolicy.Cap = resolvedPolicy.Initial
		}
	}
	nativeTCPOffered := nativeTCPListener != nil
	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeResp,
		QUICModeResp: &quicModeResponse{
			NativeDirect:    nativeQUIC,
			NativeTCP:       nativeTCPOffered,
			DirectAddr:      quicModeDirectAddrString(nativeQUICModeResponseAddr(nativeQUICAddr, nativeTCPAddr, nativeTCPOffered)),
			NativeTCPConns:  externalNativeTCPPassiveConnCount(req.NativeTCPConns),
			ParallelMode:    string(resolvedPolicy.Mode),
			ParallelInitial: resolvedPolicy.Initial,
			ParallelCap:     resolvedPolicy.Cap,
		},
	}, auth); err != nil {
		if nativeTCPListener != nil {
			_ = nativeTCPListener.Close()
		}
		return false, nil, nil, resolvedPolicy, err
	}
	if !nativeQUIC && nativeTCPListener == nil {
		return false, nil, nil, resolvedPolicy, nil
	}

	type nativeTCPResult struct {
		conns []net.Conn
		err   error
	}
	var (
		nativeTCPConnCh chan nativeTCPResult
		nativeTCPCancel context.CancelFunc
	)
	nativeTCPConnCount := externalNativeTCPPassiveConnCount(req.NativeTCPConns)
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
	} else if nativeTCPListener != nil {
		nativeTCPCtx, cancel := context.WithCancel(ctx)
		nativeTCPCancel = cancel
		nativeTCPConnCh = make(chan nativeTCPResult, 1)
		go func() {
			if nativeTCPConnCount > 1 {
				conns, err := acceptExternalNativeTCPConns(nativeTCPCtx, nativeTCPListener, nativeTCPAuth, nativeTCPConnCount)
				if err == nil && emitter != nil {
					emitter.Debug("native-tcp-stripes=" + strconv.Itoa(len(conns)))
				}
				nativeTCPConnCh <- nativeTCPResult{conns: conns, err: err}
				return
			}
			conn, err := acceptExternalNativeTCP(nativeTCPCtx, nativeTCPListener, nativeTCPAuth)
			if conn == nil {
				nativeTCPConnCh <- nativeTCPResult{err: err}
				return
			}
			nativeTCPConnCh <- nativeTCPResult{conns: []net.Conn{conn}, err: err}
		}()
	}
	ackCtx, ackCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer ackCancel()
	ack, err := receiveQUICModeAck(ackCtx, ackCh, auth)
	if err != nil || (!ack.NativeDirect && !ack.NativeTCP) {
		if nativeTCPCancel != nil {
			nativeTCPCancel()
		}
		if nativeTCPConnCh != nil {
			result := <-nativeTCPConnCh
			closeExternalNativeTCPConns(result.conns)
		}
		return false, nil, nil, resolvedPolicy, nil
	}
	if nativeTCPListener != nil && !ack.NativeTCP {
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
			return false, nil, nil, resolvedPolicy, nil
		}
		if _, err := sendExternalQUICModeReady(ctx, client, peerDERP, manager, nativeQUICAddr, auth); err != nil {
			return false, nil, nil, resolvedPolicy, err
		}
		return nativeQUIC, nil, cloneSessionAddr(nativeQUICPeerAddr), resolvedPolicy, nil
	}
	if nativeTCPListener == nil {
		if !nativeQUIC {
			return false, nil, nil, resolvedPolicy, nil
		}
		if _, err := sendExternalQUICModeReady(ctx, client, peerDERP, manager, nativeQUICAddr, auth); err != nil {
			return false, nil, nil, resolvedPolicy, err
		}
		return nativeQUIC, nil, cloneSessionAddr(nativeQUICPeerAddr), resolvedPolicy, nil
	}
	result := <-nativeTCPConnCh
	if result.err != nil {
		return false, nil, nil, resolvedPolicy, result.err
	}
	return nativeQUIC, result.conns, cloneSessionAddr(nativeQUICPeerAddr), resolvedPolicy, nil
}

func sendExternalQUICModeReady(
	ctx context.Context,
	client *derpbind.Client,
	peerDERP key.NodePublic,
	manager *transport.Manager,
	nativeQUICAddr net.Addr,
	authOpt ...externalPeerControlAuth,
) (net.Addr, error) {
	auth := optionalPeerControlAuth(authOpt)
	readyAddr := cloneSessionAddr(nativeQUICAddr)
	if manager != nil {
		if readyAddr == nil {
			readyAddr, _ = manager.DirectAddr()
		}
	}
	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:          envelopeQUICModeReady,
		QUICModeReady: &quicModeReady{NativeDirect: true},
	}, auth); err != nil {
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

	if err := waitForPeerAck(ackCtx, ackCh, spool.sourceOffset); err != nil {
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

func receiveQUICModeRequest(ctx context.Context, ch <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (quicModeRequest, error) {
	auth := optionalPeerControlAuth(authOpt)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return quicModeRequest{}, net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err != nil || env.Type != envelopeQUICModeReq || env.QUICModeReq == nil {
				return quicModeRequest{}, errors.New("unexpected quic mode request")
			}
			return *env.QUICModeReq, nil
		case <-ctx.Done():
			return quicModeRequest{}, ctx.Err()
		}
	}
}

func receiveQUICModeResponse(ctx context.Context, ch <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (quicModeResponse, error) {
	auth := optionalPeerControlAuth(authOpt)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return quicModeResponse{}, net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err != nil || env.Type != envelopeQUICModeResp || env.QUICModeResp == nil {
				return quicModeResponse{}, errors.New("unexpected quic mode response")
			}
			return *env.QUICModeResp, nil
		case <-ctx.Done():
			return quicModeResponse{}, ctx.Err()
		}
	}
}

func receiveQUICModeAck(ctx context.Context, ch <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (quicModeAck, error) {
	auth := optionalPeerControlAuth(authOpt)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return quicModeAck{}, net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err != nil || env.Type != envelopeQUICModeAck || env.QUICModeAck == nil {
				return quicModeAck{}, errors.New("unexpected quic mode ack")
			}
			return *env.QUICModeAck, nil
		case <-ctx.Done():
			return quicModeAck{}, ctx.Err()
		}
	}
}

func receiveQUICModeReadyWithAckRetry(
	ctx context.Context,
	readyCh <-chan derpbind.Packet,
	sendAck func(context.Context) error,
	authOpt ...externalPeerControlAuth,
) (quicModeReady, error) {
	auth := optionalPeerControlAuth(authOpt)
	retry := time.NewTicker(externalNativeQUICAckRetryInterval)
	defer retry.Stop()

	for {
		select {
		case pkt, ok := <-readyCh:
			if !ok {
				return quicModeReady{}, net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
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
	authOpt ...externalPeerControlAuth,
) (net.Addr, bool, bool) {
	if manager == nil {
		return nil, false, false
	}
	auth := optionalPeerControlAuth(authOpt)
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
			ackEnv, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
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

func sendPeerAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived int64, authOpt ...externalPeerControlAuth) error {
	auth := optionalPeerControlAuth(authOpt)
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{Type: envelopeAck, Ack: newPeerAck(bytesReceived)}, auth)
}

func sendPeerAbortBestEffort(client *derpbind.Client, peerDERP key.NodePublic, reason string, bytesTransferred int64, authOpt ...externalPeerControlAuth) {
	if client == nil || peerDERP.IsZero() {
		return
	}
	if reason == "" {
		reason = "aborted"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	_ = sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:  envelopeAbort,
		Abort: newPeerAbort(reason, bytesTransferred),
	}, auth)
}

func sendPeerHeartbeat(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesTransferred int64, sequence uint64, auth externalPeerControlAuth) error {
	if client == nil || peerDERP.IsZero() {
		return nil
	}
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:      envelopeHeartbeat,
		Heartbeat: newAuthenticatedPeerHeartbeat(bytesTransferred, sequence, auth),
	}, auth)
}

func withPeerControlContext(parent context.Context, client *derpbind.Client, peerDERP key.NodePublic, abortCh <-chan derpbind.Packet, heartbeatCh <-chan derpbind.Packet, bytesTransferred func() int64, auth externalPeerControlAuth) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	var stopOnce sync.Once
	stopCh := make(chan struct{})
	stop := func() {
		stopOnce.Do(func() {
			close(stopCh)
			cancel(context.Canceled)
		})
	}
	currentBytes := func() int64 {
		if bytesTransferred == nil {
			return 0
		}
		return bytesTransferred()
	}

	if abortCh != nil || heartbeatCh != nil {
		go func() {
			var timer *time.Timer
			var timerC <-chan time.Time
			if heartbeatCh != nil {
				timeout := peerHeartbeatTimeout
				if timeout <= 0 {
					timeout = 30 * time.Second
				}
				timer = time.NewTimer(timeout)
				timerC = timer.C
				defer timer.Stop()
			}
			resetHeartbeatTimer := func() {
				if timer == nil {
					return
				}
				timeout := peerHeartbeatTimeout
				if timeout <= 0 {
					timeout = 30 * time.Second
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(timeout)
			}
			var lastHeartbeatSequence uint64
			for {
				select {
				case pkt, ok := <-abortCh:
					if !ok {
						abortCh = nil
						continue
					}
					env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
					if ignoreAuthenticatedEnvelopeError(err, auth) {
						continue
					}
					if err == nil && env.Type == envelopeAbort {
						cancel(ErrPeerAborted)
						return
					}
				case pkt, ok := <-heartbeatCh:
					if !ok {
						heartbeatCh = nil
						timerC = nil
						continue
					}
					env, err := decodeEnvelope(pkt.Payload)
					if err != nil || env.Type != envelopeHeartbeat {
						continue
					}
					if !verifyPeerHeartbeat(env.Heartbeat, auth, &lastHeartbeatSequence) {
						continue
					}
					resetHeartbeatTimer()
				case <-timerC:
					cancel(ErrPeerDisconnected)
					return
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				}
				if abortCh == nil && heartbeatCh == nil {
					return
				}
			}
		}()
	}

	if client != nil && !peerDERP.IsZero() {
		go func() {
			interval := peerHeartbeatInterval
			if interval <= 0 {
				interval = 2 * time.Second
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var heartbeatSequence uint64
			for {
				heartbeatSequence++
				_ = sendPeerHeartbeat(ctx, client, peerDERP, currentBytes(), heartbeatSequence, auth)
				select {
				case <-ticker.C:
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				}
			}
		}()
	}

	return ctx, stop
}

func normalizePeerAbortError(ctx context.Context, err error) error {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, ErrPeerAborted):
		return ErrPeerAborted
	case errors.Is(cause, ErrPeerDisconnected):
		return ErrPeerDisconnected
	}
	return err
}

func notifyPeerAbortOnError(errp *error, ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesTransferred func() int64, authOpt ...externalPeerControlAuth) {
	if errp == nil {
		return
	}
	*errp = normalizePeerAbortError(ctx, *errp)
	if *errp == nil || errors.Is(*errp, ErrPeerAborted) || errors.Is(*errp, ErrPeerDisconnected) {
		return
	}
	var bytes int64
	if bytesTransferred != nil {
		bytes = bytesTransferred()
	}
	sendPeerAbortBestEffort(client, peerDERP, peerAbortReason(*errp), bytes, optionalPeerControlAuth(authOpt))
}

func peerAbortReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return err.Error()
	}
}

func waitForPeerAck(ctx context.Context, ch <-chan derpbind.Packet, bytesSent int64, authOpt ...externalPeerControlAuth) error {
	auth := optionalPeerControlAuth(authOpt)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err == nil && env.Type == envelopeAbort {
				return ErrPeerAborted
			}
			if err != nil || env.Type != envelopeAck {
				return errors.New("unexpected peer ack payload")
			}
			if env.Ack == nil || env.Ack.BytesReceived == nil {
				return errors.New("peer ack missing bytes_received")
			}
			if *env.Ack.BytesReceived != bytesSent {
				return fmt.Errorf("peer received %d bytes, sent %d", *env.Ack.BytesReceived, bytesSent)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func waitForPeerAckWithTimeout(ctx context.Context, ch <-chan derpbind.Packet, bytesSent int64, timeout time.Duration, authOpt ...externalPeerControlAuth) error {
	if timeout <= 0 {
		return waitForPeerAck(ctx, ch, bytesSent, authOpt...)
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return waitForPeerAck(waitCtx, ch, bytesSent, authOpt...)
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
	if override := os.Getenv("DERPHOLE_TEST_DERP_MAP_URL"); override != "" {
		return override
	}
	return derpbind.PublicDERPMapURL
}

func publicDERPServerURL(node *tailcfg.DERPNode) string {
	if override := os.Getenv("DERPHOLE_TEST_DERP_SERVER_URL"); override != "" {
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
	return sendClaimAndReceiveDecisionWithTelemetry(ctx, client, dst, claim, nil, "")
}

func sendClaimAndReceiveDecisionWithTelemetry(
	ctx context.Context,
	client *derpbind.Client,
	dst key.NodePublic,
	claim rendezvous.Claim,
	emitter *telemetry.Emitter,
	prefix string,
) (rendezvous.Decision, error) {
	decisionCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == dst && isDecisionOrAbortPayload(pkt.Payload)
	})
	defer unsubscribe()

	attempt := 1
	if emitter != nil {
		emitter.Debug(prefix + "claim-send-attempt=" + strconv.Itoa(attempt))
	}
	if err := sendEnvelope(ctx, client, dst, envelope{Type: envelopeClaim, Claim: &claim}); err != nil {
		return rendezvous.Decision{}, fmt.Errorf("send claim: %w", err)
	}
	if emitter != nil {
		emitter.Debug(prefix + "claim-send-complete=" + strconv.Itoa(attempt))
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
			if err != nil {
				continue
			}
			if env.Type == envelopeAbort {
				return rendezvous.Decision{}, ErrPeerAborted
			}
			if env.Type != envelopeDecision || env.Decision == nil {
				continue
			}
			if emitter != nil {
				emitter.Debug(prefix + "decision-received")
			}
			return *env.Decision, nil
		case <-retry.C:
			attempt++
			if emitter != nil {
				emitter.Debug(prefix + "claim-send-attempt=" + strconv.Itoa(attempt))
			}
			if err := sendEnvelope(ctx, client, dst, envelope{Type: envelopeClaim, Claim: &claim}); err != nil {
				return rendezvous.Decision{}, fmt.Errorf("resend claim: %w", err)
			}
			if emitter != nil {
				emitter.Debug(prefix + "claim-send-complete=" + strconv.Itoa(attempt))
			}
		case <-ctx.Done():
			return rendezvous.Decision{}, ctx.Err()
		}
	}
}

func sendTransportControl(ctx context.Context, client *derpbind.Client, dst key.NodePublic, msg transport.ControlMessage, authOpt ...externalPeerControlAuth) error {
	return sendAuthenticatedEnvelope(ctx, client, dst, envelope{Type: envelopeControl, Control: &msg}, optionalPeerControlAuth(authOpt))
}

func quicModeParallelPolicy(msg interface {
	getParallelMode() string
	getParallelInitial() int
	getParallelCap() int
}) ParallelPolicy {
	return parallelPolicyFromFields(msg.getParallelMode(), msg.getParallelInitial(), msg.getParallelCap())
}

func parallelPolicyFromFields(mode string, initial, cap int) ParallelPolicy {
	switch ParallelMode(mode) {
	case ParallelModeFixed:
		return FixedParallelPolicy(initial).normalized()
	case ParallelModeAuto:
		policy := AutoParallelPolicy()
		if initial > 0 {
			policy.Initial = initial
		}
		if cap > 0 {
			policy.Cap = cap
		}
		return policy.normalized()
	default:
		return ParallelPolicy{}
	}
}

func (m quicModeRequest) getParallelMode() string  { return m.ParallelMode }
func (m quicModeRequest) getParallelInitial() int  { return m.ParallelInitial }
func (m quicModeRequest) getParallelCap() int      { return m.ParallelCap }
func (m quicModeResponse) getParallelMode() string { return m.ParallelMode }
func (m quicModeResponse) getParallelInitial() int { return m.ParallelInitial }
func (m quicModeResponse) getParallelCap() int     { return m.ParallelCap }

func externalParallelQUICConnCount(policy ParallelPolicy) int {
	policy = policy.normalized()
	return policy.Initial
}

func externalParallelTCPConnCount(policy ParallelPolicy) int {
	policy = policy.normalized()
	return policy.Initial
}

func waitInitialExternalNativeDirectMode(
	ctx context.Context,
	ch <-chan externalNativeDirectModeResult,
	wait time.Duration,
) (externalNativeDirectModeResult, bool) {
	if os.Getenv("DERPHOLE_NATIVE_TCP_DIRECT_START") != "1" {
		return externalNativeDirectModeResult{}, false
	}
	if wait <= 0 {
		return externalNativeDirectModeResult{}, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case result := <-ch:
		return result, true
	case <-timer.C:
		return externalNativeDirectModeResult{}, false
	case <-ctx.Done():
		return externalNativeDirectModeResult{}, false
	}
}

func singleExternalNativeDirectModeResult(result externalNativeDirectModeResult) <-chan externalNativeDirectModeResult {
	ch := make(chan externalNativeDirectModeResult, 1)
	ch <- result
	return ch
}

func receiveTransportControl(ctx context.Context, ch <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (transport.ControlMessage, error) {
	auth := optionalPeerControlAuth(authOpt)
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return transport.ControlMessage{}, net.ErrClosed
			}
			env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
			if ignoreAuthenticatedEnvelopeError(err, auth) {
				continue
			}
			if err != nil || env.Type != envelopeControl || env.Control == nil {
				return transport.ControlMessage{}, errors.New("unexpected control payload")
			}
			return *env.Control, nil
		case <-ctx.Done():
			return transport.ControlMessage{}, ctx.Err()
		}
	}
}

func sendEnvelope(ctx context.Context, client *derpbind.Client, dst key.NodePublic, env envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return client.Send(ctx, dst, payload)
}

func sendAuthenticatedEnvelope(ctx context.Context, client *derpbind.Client, dst key.NodePublic, env envelope, auth externalPeerControlAuth) error {
	payload, err := marshalAuthenticatedEnvelope(env, auth)
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
		// Preserve private and link-local interface candidates so same-LAN
		// peers can still converge on their best direct path. Loopback
		// remains fake-transport-only so direct-upgrade tests still model the
		// real transport state machine without exposing loopback in production.
		if !ip.IsValid() || ip.IsUnspecified() {
			continue
		}
		if ip.IsLoopback() && !fakeTransportEnabled() {
			continue
		}
		add(ip, port)
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
	if os.Getenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES") == "1" {
		return false
	}
	return os.Getenv("DERPHOLE_ENABLE_TAILSCALE_CANDIDATES") == "1"
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
	return candidate.ParseLocalAddrs(raw)
}

func parseRemoteCandidateStrings(raw []string) []net.Addr {
	if fakeTransportEnabled() {
		return candidate.ParsePeerAddrs(raw, candidate.AllowLoopback())
	}
	return candidate.ParsePeerAddrs(raw)
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
	seeder.SeedRemoteCandidates(ctx, parseRemoteCandidateStrings(decision.Accept.Candidates))
}

func seedAcceptedClaimCandidates(ctx context.Context, seeder remoteCandidateSeeder, claim rendezvous.Claim) {
	if seeder == nil || len(claim.Candidates) == 0 {
		return
	}
	seeder.SeedRemoteCandidates(ctx, parseRemoteCandidateStrings(claim.Candidates))
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

func isAckOrAbortPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && (env.Type == envelopeAck || env.Type == envelopeAbort)
}

func isAbortPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeAbort
}

func isHeartbeatPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeHeartbeat
}

func isDirectUDPReadyAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPReadyAck
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

func isParallelGrowRequestPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeParallelGrowReq && env.ParallelGrowReq != nil
}

func isParallelGrowAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeParallelGrowAck && env.ParallelGrowAck != nil
}

func isParallelGrowResultPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeParallelGrowResult && env.ParallelGrowResult != nil
}

func isDecisionPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDecision && env.Decision != nil
}

func isDecisionOrAbortPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && (env.Type == envelopeDecision || env.Type == envelopeAbort)
}

func isTransportDataPayload(payload []byte) bool {
	return !isTransportControlPayload(payload) &&
		externalRelayPrefixDERPFrameKindOf(payload) == 0 &&
		!isAckPayload(payload) &&
		!isAbortPayload(payload) &&
		!isHeartbeatPayload(payload) &&
		!isDirectUDPReadyAckPayload(payload) &&
		!isDirectUDPRateProbePayload(payload) &&
		!isClaimPayload(payload) &&
		!isDecisionPayload(payload) &&
		!isQUICModeRequestPayload(payload) &&
		!isQUICModeResponsePayload(payload) &&
		!isQUICModeAckPayload(payload) &&
		!isQUICModeReadyPayload(payload) &&
		!isParallelGrowRequestPayload(payload) &&
		!isParallelGrowAckPayload(payload) &&
		!isParallelGrowResultPayload(payload)
}

func relayTransportAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func fakeTransportCandidatesBlocked() bool {
	if !fakeTransportEnabled() {
		return false
	}
	raw := os.Getenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT")
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
	return os.Getenv("DERPHOLE_FAKE_TRANSPORT") == "1"
}

func externalNativeQUICConnCount() int {
	if fakeTransportEnabled() {
		return 1
	}
	if raw := os.Getenv("DERPHOLE_NATIVE_QUIC_CONNS"); raw != "" {
		count, err := strconv.Atoi(raw)
		if err == nil && count > 0 {
			return count
		}
	}
	return defaultExternalNativeQUICConns
}
