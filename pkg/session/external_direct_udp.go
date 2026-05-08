package session

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	externalDirectUDPTransportLabel                = "batched"
	externalDirectUDPParallelism                   = 8
	externalDirectUDPChunkSize                     = 1384 // 52-byte probe header + 16-byte GCM tag keeps UDP payload at 1452 bytes.
	externalDirectUDPMaxRateMbps                   = 10_000
	externalDirectUDPInitialProbeFallbackMbps      = 150
	externalDirectUDPWait                          = 5 * time.Second
	externalDirectUDPPunchWait                     = 1200 * time.Millisecond
	externalDirectUDPHandshakeWait                 = 1500 * time.Millisecond
	externalDirectUDPStartWait                     = 30 * time.Second
	externalDirectUDPAckWait                       = 60 * time.Second
	externalDirectUDPBufferSize                    = 4 << 20
	externalDirectUDPRepairPayloads                = true
	externalDirectUDPTailReplayBytes               = 32 << 20
	externalDirectUDPStreamReplayBytes             = 256 << 20
	externalDirectUDPFECGroupSize                  = 32
	externalDirectUDPStreamFECGroupSize            = 0
	externalDirectUDPStripedBlast                  = true
	externalDirectUDPDiscardQueue                  = 32
	externalDirectUDPRateProbeMinBytes             = 256 << 20
	externalDirectUDPRateProbeDuration             = 200 * time.Millisecond
	externalDirectUDPRateProbeHighDuration         = 500 * time.Millisecond
	externalDirectUDPRateProbeGrace                = 300 * time.Millisecond
	externalDirectUDPRateProbeMinMbps              = 1
	externalDirectUDPRateProbeHighShare            = 0.79
	externalDirectUDPRateProbeHighGain             = 1.40
	externalDirectUDPRateProbeClean                = 0.98
	externalDirectUDPRateProbeDefaultMaxMbps       = 2250
	externalDirectUDPRateProbeNearClean            = 0.90
	externalDirectUDPRateProbeEfficient            = 0.75
	externalDirectUDPRateProbeCeilingEfficient     = 0.90
	externalDirectUDPRateProbeCeilingDelivery      = 0.75
	externalDirectUDPRateProbeHeadroomDelivery     = 0.25
	externalDirectUDPRateProbeSentGrowth           = 1.03
	externalDirectUDPRateProbeCeilingFloor         = 0.60
	externalDirectUDPRateProbeCeilingFloorMin      = 300.0
	externalDirectUDPRateProbeLossyGain            = 1.05
	externalDirectUDPRateProbeMaterialGain         = 1.35
	externalDirectUDPRateProbeModerateGain         = 1.34
	externalDirectUDPRateProbeSenderLimitGain      = 1.25
	externalDirectUDPRateProbeLossyDelivery        = 0.40
	externalDirectUDPRateProbeLossySelect          = 0.80
	externalDirectUDPRateProbeBufferedCollapse     = 0.70
	externalDirectUDPRateProbeConfirmMinMbps       = 1800
	externalDirectUDPRateProbeKneeHeadroom         = 0.75
	externalDirectUDPRateProbeHighHeadroom         = 0.50
	externalDirectUDPRateProbeHighHeadroomMin      = 700
	externalDirectUDPRateProbeCollapseMinMbps      = 1000
	externalDirectUDPDataStartMaxMbps              = 350
	externalDirectUDPDataStartHighMinMbps          = 1200
	externalDirectUDPDataStartHighMbps             = 1200
	externalDirectUDPDataExplorationDefaultMaxMbps = 2100
	externalDirectUDPCeilingHeadroomMinMbps        = 500
	externalDirectUDPActiveLaneOneMaxMbps          = 350
	externalDirectUDPActiveLaneTwoMaxMbps          = 700
	externalDirectUDPActiveLaneFourMaxMbps         = 2250
	externalDirectUDPBatchOnlyCleanStartShare      = 0.83
	externalDirectUDPBatchOnlyLossyStartShare      = 1.00
	externalDirectUDPBatchOnlyProbeRoundMbps       = 50
	externalDirectUDPConstrainedReceiverBuffer     = 8 << 20
	externalDirectUDPConstrainedReceiverStartMbps  = 100
	externalDirectUDPConstrainedReceiverLaneMax    = 2
	externalRelayPrefixSkipDirectTail              = 256 << 10
	externalRelayPrefixDERPChunkSize               = 32 << 10
	externalRelayPrefixDERPMaxUnacked              = 512 << 10
	externalRelayPrefixDERPSustainedMax            = 64 << 10
	externalRelayPrefixDERPStartupBytes            = 4 << 20
	externalRelayPrefixDERPHandoffAckWait          = 5 * time.Second
	externalRelayPrefixDirectPrepStallWait         = 250 * time.Millisecond
	externalRelayPrefixNoProbeStartMbps            = 100
	externalRelayPrefixNoProbeCeilingMbps          = externalDirectUDPRateProbeDefaultMaxMbps
	externalRelayPrefixNoProbeLaneBasisMbps        = externalDirectUDPActiveLaneTwoMaxMbps
)

var externalDirectUDPRateProbeMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'r', 'a', 't', 'e', 'v', '1'}
var externalRelayPrefixDERPMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'p', 'r', 'e', 'f', 'v', '1'}

const (
	externalDirectUDPRateProbeIndexOffset = len(externalDirectUDPRateProbeMagic)
	externalDirectUDPRateProbeNonceOffset = externalDirectUDPRateProbeIndexOffset + 4
	externalDirectUDPRateProbeMACOffset   = externalDirectUDPRateProbeNonceOffset + 16
	externalDirectUDPRateProbeHeaderSize  = externalDirectUDPRateProbeMACOffset + sha256.Size
	externalRelayPrefixDERPHeaderSize     = 25
)

type externalDirectUDPRateProbeAuth struct {
	Key   [32]byte
	Nonce [16]byte
}

func (auth externalDirectUDPRateProbeAuth) enabled() bool {
	return auth.Key != [32]byte{} && auth.Nonce != [16]byte{}
}

type externalRelayPrefixDERPFrameKind byte

const (
	externalRelayPrefixDERPFrameData externalRelayPrefixDERPFrameKind = iota + 1
	externalRelayPrefixDERPFrameAck
	externalRelayPrefixDERPFrameEOF
	externalRelayPrefixDERPFrameHandoff
	externalRelayPrefixDERPFrameHandoffAck
)

var externalDirectUDPPreviewTransportCaps = probe.PreviewTransportCaps
var externalDirectUDPProbeCandidates = publicProbeCandidates
var externalDirectUDPProbeSendFn = probe.Send
var externalRelayUDPProbeReceiveToWriterFn = func(ctx context.Context, conn net.PacketConn, dst io.Writer, cfg probe.ReceiveConfig) (probe.TransferStats, error) {
	return probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{conn}, dst, cfg, 0)
}
var externalSendDirectUDPOnlyFn = sendExternalViaDirectUDPOnly
var externalPrepareDirectUDPSendFn = externalPrepareDirectUDPSend
var externalExecutePreparedDirectUDPSendFn = externalExecutePreparedDirectUDPSend
var externalPrepareDirectUDPReceiveFn = externalPrepareDirectUDPReceive
var externalExecutePreparedDirectUDPReceiveFn = externalExecutePreparedDirectUDPReceive
var externalDirectUDPWaitReadyFn = waitForDirectUDPReady
var externalDirectUDPWaitReadyAckFn = waitForDirectUDPReadyAck
var externalDirectUDPWaitStartFn = waitForDirectUDPStart
var externalDirectUDPWaitStartAckFn = waitForDirectUDPStartAck
var externalDirectUDPWaitRateProbeFn = waitForDirectUDPRateProbe
var externalDirectUDPSendRateProbesParallelFn = externalDirectUDPSendRateProbesParallel
var externalDirectUDPReceiveRateProbesFn = externalDirectUDPReceiveRateProbes
var externalDirectUDPConnsFn = externalDirectUDPConns
var externalSendExternalHandoffDERPFn = sendExternalHandoffDERP
var externalReceiveExternalHandoffDERPFn = receiveExternalHandoffDERP
var externalSessionPacketAEADDomain = []byte("derphole-session-packet-aead-v1")
var externalRelayPrefixDERPDataNonceDomain = []byte("derphole-relay-prefix-derp-data-nonce-v1")
var externalDirectUDPObservePunchAddrsByConn = probe.ObservePunchAddrsByConn

type externalDirectUDPSendPlan struct {
	probeConns           []net.PacketConn
	remoteAddrs          []string
	sendCfg              probe.SendConfig
	selectedRateMbps     int
	startRateMbps        int
	rateCeilingMbps      int
	probeRates           []int
	sentProbeSamples     []directUDPRateProbeSample
	receivedProbeSamples []directUDPRateProbeSample
}

type externalDirectUDPSenderProbeRateLimitResult struct {
	StartMbps     int
	CeilingMbps   int
	StartOverride bool
}

type externalDirectUDPHandoffReadyContextKey struct{}
type externalDirectUDPHandoffProceedContextKey struct{}
type externalDirectUDPHandoffRelayPauseContextKey struct{}
type externalDirectUDPDirectReadyContextKey struct{}

type externalDirectUDPHandoffReadySignal struct {
	ch   chan struct{}
	once sync.Once
}

type externalDirectUDPHandoffProceedSignal struct {
	ch           chan struct{}
	once         sync.Once
	mu           sync.Mutex
	watermark    int64
	hasWatermark bool
}

type externalDirectUDPHandoffRelayPauseControl struct {
	mu     sync.Mutex
	paused bool
	resume chan struct{}
}

type externalDirectUDPDirectReadySignal struct {
	ch   chan struct{}
	once sync.Once
}

func withExternalDirectUDPHandoffReadySignal(ctx context.Context) (context.Context, <-chan struct{}) {
	signal := &externalDirectUDPHandoffReadySignal{ch: make(chan struct{})}
	return context.WithValue(ctx, externalDirectUDPHandoffReadyContextKey{}, signal), signal.ch
}

func signalExternalDirectUDPHandoffReady(ctx context.Context) {
	signal, _ := ctx.Value(externalDirectUDPHandoffReadyContextKey{}).(*externalDirectUDPHandoffReadySignal)
	if signal == nil {
		return
	}
	signal.once.Do(func() {
		close(signal.ch)
	})
}

func withExternalDirectUDPHandoffProceedSignal(ctx context.Context) (context.Context, func()) {
	signal := &externalDirectUDPHandoffProceedSignal{ch: make(chan struct{})}
	return context.WithValue(ctx, externalDirectUDPHandoffProceedContextKey{}, signal), func() {
		signal.once.Do(func() {
			close(signal.ch)
		})
	}
}

func recordExternalDirectUDPHandoffProceedWatermark(ctx context.Context, watermark int64) {
	signal, _ := ctx.Value(externalDirectUDPHandoffProceedContextKey{}).(*externalDirectUDPHandoffProceedSignal)
	if signal == nil {
		return
	}
	signal.mu.Lock()
	defer signal.mu.Unlock()
	signal.watermark = watermark
	signal.hasWatermark = true
}

func externalDirectUDPHandoffProceedWatermark(ctx context.Context) (int64, bool) {
	signal, _ := ctx.Value(externalDirectUDPHandoffProceedContextKey{}).(*externalDirectUDPHandoffProceedSignal)
	if signal == nil {
		return 0, false
	}
	signal.mu.Lock()
	defer signal.mu.Unlock()
	return signal.watermark, signal.hasWatermark
}

func waitExternalDirectUDPHandoffProceed(ctx context.Context) error {
	signal, _ := ctx.Value(externalDirectUDPHandoffProceedContextKey{}).(*externalDirectUDPHandoffProceedSignal)
	if signal == nil {
		return nil
	}
	select {
	case <-signal.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func withExternalDirectUDPHandoffRelayPauseControl(ctx context.Context) (context.Context, *externalDirectUDPHandoffRelayPauseControl) {
	control := &externalDirectUDPHandoffRelayPauseControl{}
	return context.WithValue(ctx, externalDirectUDPHandoffRelayPauseContextKey{}, control), control
}

func externalDirectUDPHandoffRelayPauseFromContext(ctx context.Context) *externalDirectUDPHandoffRelayPauseControl {
	control, _ := ctx.Value(externalDirectUDPHandoffRelayPauseContextKey{}).(*externalDirectUDPHandoffRelayPauseControl)
	return control
}

func (c *externalDirectUDPHandoffRelayPauseControl) Pause() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return
	}
	c.paused = true
	c.resume = make(chan struct{})
}

func (c *externalDirectUDPHandoffRelayPauseControl) Resume() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		return
	}
	c.paused = false
	close(c.resume)
	c.resume = nil
}

func externalDirectUDPHandoffRelayPauseWait(ctx context.Context, stop <-chan struct{}) error {
	control := externalDirectUDPHandoffRelayPauseFromContext(ctx)
	if control == nil {
		return nil
	}
	for {
		control.mu.Lock()
		if !control.paused {
			control.mu.Unlock()
			return nil
		}
		resume := control.resume
		control.mu.Unlock()

		select {
		case <-resume:
		case <-ctx.Done():
			return ctx.Err()
		case <-stop:
			return nil
		}
	}
}

func withExternalDirectUDPDirectReadySignal(ctx context.Context) (context.Context, <-chan struct{}) {
	signal := &externalDirectUDPDirectReadySignal{ch: make(chan struct{})}
	return context.WithValue(ctx, externalDirectUDPDirectReadyContextKey{}, signal), signal.ch
}

func signalExternalDirectUDPDirectReady(ctx context.Context) {
	signal, _ := ctx.Value(externalDirectUDPDirectReadyContextKey{}).(*externalDirectUDPDirectReadySignal)
	if signal == nil {
		return
	}
	signal.once.Do(func() {
		close(signal.ch)
	})
}

type externalDirectUDPBudget struct {
	RateMbps          int
	ActiveLanes       int
	ReplayWindowBytes uint64
}

type externalDirectUDPReceivePlan struct {
	probeConns  []net.PacketConn
	remoteAddrs []string
	receiveDst  io.Writer
	flushDst    func() error
	receiveCfg  probe.ReceiveConfig
	fastDiscard bool
	start       directUDPStart
	decision    rendezvous.Decision
	peerAddr    net.Addr
}

var waitExternalDirectUDPAddr = waitExternalDirectUDPAddrDefault

func externalSessionPacketAEAD(tok token.Token) (cipher.AEAD, error) {
	hash := sha256.New()
	_, _ = hash.Write(externalSessionPacketAEADDomain)
	_, _ = hash.Write(tok.SessionID[:])
	_, _ = hash.Write(tok.BearerSecret[:])
	block, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sendExternalViaDirectUDP(ctx context.Context, cfg SendConfig) (retErr error) {
	cfg = sendConfigWithInferredExpectedBytes(cfg)
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

	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConnsFn(nil, nil, externalDirectUDPParallelism, cfg.Emitter)
	if err != nil {
		return err
	}
	defer cleanupProbeConns()
	probeConn := probeConns[0]
	pm := portmaps[0]

	claimIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return err
	}

	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, dm, portmaps))
	}
	claimParallel := len(probeConns)
	if cfg.ForceRelay {
		claimParallel = 0
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   claimIdentity.Public,
		Parallel:     claimParallel,
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
	if decision.Accept == nil {
		return errors.New("accepted decision missing accept payload")
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
	ctx, stopPeerAbort := withPeerControlContext(ctx, derpClient, listenerDERP, abortCh, heartbeatCh, func() int64 {
		return countedSrc.Count()
	}, auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, derpClient, listenerDERP, func() int64 {
		return countedSrc.Count()
	}, auth)
	readyAckCh, unsubscribeReadyAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
	})
	defer unsubscribeReadyAck()
	startAckCh, unsubscribeStartAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartAckPayload(pkt.Payload)
	})
	defer unsubscribeStartAck()
	rateProbeCh, unsubscribeRateProbe := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPRateProbePayload(pkt.Payload)
	})
	defer unsubscribeRateProbe()
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	pathEmitter.SuppressWatcherDirect()
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	remoteRelayOnly := externalDecisionRelayOnly(decision)
	relayOnly := cfg.ForceRelay || remoteRelayOnly
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, tok, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, relayOnly)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	remoteCandidates := parseRemoteCandidateStrings(decision.Accept.Candidates)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !relayOnly {
		externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
	}

	var sendErr error
	if relayOnly {
		sendErr = sendExternalRelayUDP(ctx, countedSrc, transportManager, tok, cfg.Emitter)
	} else {
		sendErr = sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
			src:              countedSrc,
			tok:              tok,
			decision:         decision,
			derpClient:       derpClient,
			listenerDERP:     listenerDERP,
			transportCtx:     transportCtx,
			transportManager: transportManager,
			pathEmitter:      pathEmitter,
			punchCancel:      punchCancel,
			probeConn:        probeConn,
			probeConns:       probeConns,
			remoteCandidates: remoteCandidates,
			readyAckCh:       readyAckCh,
			startAckCh:       startAckCh,
			rateProbeCh:      rateProbeCh,
			cfg:              cfg,
		})
	}
	if sendErr != nil {
		return sendErr
	}
	if err := waitForPeerAckWithTimeout(ctx, ackCh, countedSrc.Count(), externalDirectUDPAckWait, auth); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

func externalDirectUDPActivateDirectPath(pathEmitter *transportPathEmitter, transportManager *transport.Manager, punchCancel context.CancelFunc) {
	if pathEmitter != nil {
		pathEmitter.ResumeWatcherDirect()
		pathEmitter.SuppressRelayRegression()
		pathEmitter.Emit(StateDirect)
	}
	if transportManager != nil {
		transportManager.StopDirectReads()
	}
	externalDirectUDPStopPunchingForBlast(punchCancel)
}

func externalPrepareDirectUDPSend(ctx context.Context, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, cfg SendConfig) (externalDirectUDPSendPlan, error) {
	plan := externalDirectUDPSendPlan{}
	auth := externalPeerControlAuthForToken(tok)
	externalTransferTracef("direct-udp-send-ready-send addr=%v", peerAddr)
	if err := sendAuthenticatedEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeDirectUDPReady}, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-send-ready-wait-ack addr=%v", peerAddr)
	readyAck, err := externalDirectUDPWaitReadyAckFn(ctx, readyAckCh, auth)
	if err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-send-ready-ack addr=%v fast-discard=%v", peerAddr, readyAck.FastDiscard)

	externalTransferTracef("direct-udp-send-remote-addrs-start addr=%v candidates=%d conns=%d", peerAddr, len(remoteCandidates), len(probeConns))
	remoteAddrs := externalDirectUDPSelectRemoteAddrs(ctx, probeConns, remoteCandidates, peerAddr, cfg.Emitter)
	externalTransferTracef("direct-udp-send-remote-addrs-done addr=%v selected=%d", peerAddr, len(remoteAddrs))
	probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
	if len(probeConns) == 0 {
		return plan, errors.New("direct UDP established without usable remote addresses")
	}
	localTransportCaps := externalDirectUDPPreviewTransportCaps(probeConns[0], externalDirectUDPTransportLabel)
	effectiveTransportCaps := externalDirectUDPEffectiveSenderCaps(localTransportCaps, readyAck)
	receiverConstrained := externalDirectUDPConstrainedReceiver(readyAck)

	maxRateMbps := externalDirectUDPMaxRateMbps
	activeRateMbps := externalDirectUDPInitialProbeFallbackMbps
	rateCeilingMbps := maxRateMbps
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-blast=true")
		cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
		cfg.Emitter.Debug("udp-rate-max-mbps=" + strconv.Itoa(maxRateMbps))
		cfg.Emitter.Debug("udp-adaptive-rate=true")
		cfg.Emitter.Debug("udp-repair-payloads=" + strconv.FormatBool(externalDirectUDPRepairPayloads))
		cfg.Emitter.Debug("udp-tail-replay-bytes=" + strconv.Itoa(externalDirectUDPTailReplayBytes))
		cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPStreamFECGroupSize))
		cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(readyAck.FastDiscard))
		if receiverConstrained {
			cfg.Emitter.Debug("udp-receiver-constrained=true")
		}
		if peerAddr != nil {
			cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
		}
		cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
	}
	externalTransferTracef("direct-udp-send-handoff-ready-signal addr=%v", peerAddr)
	signalExternalDirectUDPHandoffReady(ctx)
	externalTransferTracef("direct-udp-send-handoff-proceed-wait addr=%v", peerAddr)
	if err := waitExternalDirectUDPHandoffProceed(ctx); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-send-handoff-proceed addr=%v", peerAddr)
	handoffWatermark := int64(0)
	if watermark, ok := externalDirectUDPHandoffProceedWatermark(ctx); ok {
		handoffWatermark = watermark
	}
	directExpectedBytes := externalDirectUDPRemainingExpectedBytes(cfg.StdioExpectedBytes, handoffWatermark)
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return plan, err
	}
	policyActiveLaneCap := externalDirectUDPActiveLaneCapForPolicy(cfg.ParallelPolicy, len(probeConns))
	policyActiveLaneCap = externalDirectUDPConstrainedReceiverLaneCap(readyAck, policyActiveLaneCap, len(probeConns))
	stripedDecisionLanes := len(probeConns)
	if policyActiveLaneCap > 0 && policyActiveLaneCap < stripedDecisionLanes {
		stripedDecisionLanes = policyActiveLaneCap
	}
	sendCfg := probe.SendConfig{
		Blast:                    true,
		Transport:                externalDirectUDPTransportLabel,
		ChunkSize:                externalDirectUDPChunkSize,
		RateMbps:                 activeRateMbps,
		RateCeilingMbps:          maxRateMbps,
		RunID:                    tok.SessionID,
		RepairPayloads:           externalDirectUDPRepairPayloads,
		TailReplayBytes:          externalDirectUDPTailReplayBytes,
		StreamReplayWindowBytes:  externalDirectUDPStreamReplayBytes,
		FECGroupSize:             externalDirectUDPStreamFECGroupSize,
		StripedBlast:             externalDirectUDPShouldUseStripedBlast(stripedDecisionLanes, readyAck.FastDiscard),
		PacketAEAD:               packetAEAD,
		AllowPartialParallel:     true,
		ParallelHandshakeTimeout: externalDirectUDPHandshakeWait,
		MaxActiveLanes:           policyActiveLaneCap,
		MinActiveLanes:           externalDirectUDPConstrainedReceiverMinActiveLanes(readyAck, len(probeConns)),
	}
	emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, directExpectedBytes)
	start := externalDirectUDPStreamStart(maxRateMbps, directExpectedBytes)
	probeRates := append([]int(nil), start.ProbeRates...)
	useRelayPrefixNoProbePath := externalDirectUDPUseRelayPrefixNoProbePath(ctx, cfg.skipDirectUDPRateProbes, probeRates)
	if useRelayPrefixNoProbePath {
		start.ProbeRates = nil
		probeRates = nil
		reason := "relay-prefix-upgrade"
		if !cfg.skipDirectUDPRateProbes {
			reason = "relay-prefix-small-remaining"
		}
		externalTransferTracef("direct-udp-send-rate-probe-skipped reason=%s", reason)
	}
	var rateProbeAuth externalDirectUDPRateProbeAuth
	if len(probeRates) > 0 {
		rateProbeAuth, start.ProbeNonce, err = newExternalDirectUDPRateProbeAuth(tok)
		if err != nil {
			return plan, err
		}
	}
	start.StripedBlast = sendCfg.StripedBlast
	externalTransferTracef("direct-udp-send-start-send addr=%v", peerAddr)
	if err := sendAuthenticatedEnvelope(ctx, derpClient, listenerDERP, envelope{
		Type:           envelopeDirectUDPStart,
		DirectUDPStart: &start,
	}, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-send-start-wait-ack addr=%v", peerAddr)
	if err := externalDirectUDPWaitStartAckFn(ctx, startAckCh, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-send-start-ack addr=%v", peerAddr)
	signalExternalDirectUDPDirectReady(ctx)

	selectedRateMbps := activeRateMbps
	var sentProbeSamples []directUDPRateProbeSample
	var probeResult directUDPRateProbeResult
	if len(probeRates) > 0 {
		externalTransferTracef("direct-udp-send-rate-probe-start rates=%s", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(probeRates)), ","), "[]"))
		sentProbeSamples, err = externalDirectUDPSendRateProbesParallelFn(ctx, probeConns, remoteAddrs, probeRates, rateProbeAuth)
		if err != nil {
			externalTransferTracef("direct-udp-send-rate-probe-done err=%v", err)
			return plan, err
		}
		probeResult, err = externalDirectUDPWaitRateProbeFn(ctx, rateProbeCh, auth)
		if err != nil {
			externalTransferTracef("direct-udp-send-rate-probe-done err=%v", err)
			return plan, err
		}
		externalTransferTracef("direct-udp-send-rate-probe-done err=<nil> samples=%d", len(probeResult.Samples))
		selectedRateMbps = externalDirectUDPSelectInitialRateMbps(maxRateMbps, sentProbeSamples, probeResult.Samples)
		rateCeilingMbps = externalDirectUDPSelectRateCeilingMbps(maxRateMbps, selectedRateMbps, sentProbeSamples, probeResult.Samples)
		probeLimit := externalDirectUDPSenderProbeRateLimit(effectiveTransportCaps, sentProbeSamples, probeResult.Samples)
		rateCeilingMbps = externalDirectUDPSenderRateCeilingCap(effectiveTransportCaps, rateCeilingMbps)
		if probeLimit.CeilingMbps > 0 && (rateCeilingMbps <= 0 || probeLimit.CeilingMbps < rateCeilingMbps) {
			rateCeilingMbps = probeLimit.CeilingMbps
		}
		if rateCeilingMbps > 0 && selectedRateMbps > rateCeilingMbps {
			selectedRateMbps = rateCeilingMbps
		}
		activeRateMbps = externalDirectUDPDataStartRateMbpsForProbeSamples(selectedRateMbps, rateCeilingMbps, sentProbeSamples, probeResult.Samples)
		activeRateMbps = externalDirectUDPClampDataStartRate(selectedRateMbps, activeRateMbps, rateCeilingMbps, len(probeConns), sendCfg.StripedBlast)
		activeRateMbps = externalDirectUDPSenderStartRateCap(effectiveTransportCaps, selectedRateMbps, activeRateMbps)
		activeRateMbps = externalDirectUDPSenderApplyProbeRateLimit(activeRateMbps, probeLimit)
		activeRateMbps = externalDirectUDPConstrainedReceiverStartRate(readyAck, activeRateMbps)
		sendCfg.RateMbps = activeRateMbps
		sendCfg.RateCeilingMbps = rateCeilingMbps
		sendCfg.RateExplorationCeilingMbps = externalDirectUDPDataExplorationCeilingMbpsForProbeSamples(maxRateMbps, selectedRateMbps, rateCeilingMbps, sentProbeSamples, probeResult.Samples)
		sendCfg.RateExplorationCeilingMbps = externalDirectUDPSenderExplorationCeilingCap(effectiveTransportCaps, sendCfg.RateExplorationCeilingMbps)
		if probeLimit.CeilingMbps > 0 && sendCfg.RateExplorationCeilingMbps > probeLimit.CeilingMbps {
			sendCfg.RateExplorationCeilingMbps = probeLimit.CeilingMbps
		}
		sendCfg.StreamReplayWindowBytes = externalDirectUDPDataPathBudget(selectedRateMbps, activeRateMbps, rateCeilingMbps, len(probeConns), sendCfg.StripedBlast).ReplayWindowBytes
	} else if useRelayPrefixNoProbePath {
		rateCeilingMbps = externalDirectUDPRelayPrefixNoProbeRateCeilingMbps(maxRateMbps)
		selectedRateMbps = externalRelayPrefixNoProbeStartMbps
		if rateCeilingMbps > 0 && selectedRateMbps > rateCeilingMbps {
			selectedRateMbps = rateCeilingMbps
		}
		activeRateMbps = selectedRateMbps
		activeRateMbps = externalDirectUDPConstrainedReceiverStartRate(readyAck, activeRateMbps)
		laneBasisMbps := externalDirectUDPNoProbeLaneBasisMbps(activeRateMbps, rateCeilingMbps)
		sendCfg.RateMbps = activeRateMbps
		sendCfg.RateCeilingMbps = rateCeilingMbps
		sendCfg.StreamReplayWindowBytes = externalDirectUDPReplayWindowBytesForRate(laneBasisMbps)
	}

	var retainedLanes int
	if len(sentProbeSamples) > 0 || len(probeResult.Samples) > 0 {
		retainedLanes = externalDirectUDPDataPathBudget(selectedRateMbps, activeRateMbps, rateCeilingMbps, len(probeConns), sendCfg.StripedBlast).ActiveLanes
	} else {
		laneRateBasisMbps := externalDirectUDPDataLaneRateBasisMbps(activeRateMbps, rateCeilingMbps, probeRates)
		retainedLanes = externalDirectUDPRetainedLanesForRate(laneRateBasisMbps, len(probeConns), sendCfg.StripedBlast)
	}
	if useRelayPrefixNoProbePath {
		noProbeLanes := externalDirectUDPNoProbeActiveLanes(activeRateMbps, rateCeilingMbps, len(probeConns))
		if noProbeLanes > 0 && (retainedLanes == 0 || noProbeLanes < retainedLanes) {
			retainedLanes = noProbeLanes
		}
	}
	if policyActiveLaneCap > 0 && (retainedLanes == 0 || policyActiveLaneCap < retainedLanes) {
		retainedLanes = policyActiveLaneCap
	}
	retainedLanes = externalDirectUDPSenderRetainedLaneCap(effectiveTransportCaps, selectedRateMbps, activeRateMbps, rateCeilingMbps, retainedLanes)
	if retainedLanes == 0 {
		return plan, errors.New("direct UDP established without active send lanes")
	}
	if retainedLanes < len(probeConns) {
		probeConns = probeConns[:retainedLanes]
		remoteAddrs = remoteAddrs[:retainedLanes]
	}
	rateCeilingMbps = externalDirectUDPDataRateCeilingMbps(rateCeilingMbps, activeRateMbps, len(probeConns))
	sendCfg.RateCeilingMbps = rateCeilingMbps
	if sendCfg.RateExplorationCeilingMbps > 0 {
		sendCfg.RateExplorationCeilingMbps = externalDirectUDPDataRateCeilingMbps(sendCfg.RateExplorationCeilingMbps, activeRateMbps, len(probeConns))
		if sendCfg.RateExplorationCeilingMbps < rateCeilingMbps {
			sendCfg.RateExplorationCeilingMbps = rateCeilingMbps
		}
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-striped-available-lanes=" + strconv.Itoa(len(probeConns)))
		cfg.Emitter.Debug("udp-striped-decision=" + strconv.FormatBool(sendCfg.StripedBlast))
		cfg.Emitter.Debug("udp-striped-blast=" + strconv.FormatBool(sendCfg.StripedBlast))
		cfg.Emitter.Debug("udp-rate-ceiling-mbps=" + strconv.Itoa(rateCeilingMbps))
		if sendCfg.RateExplorationCeilingMbps > rateCeilingMbps {
			cfg.Emitter.Debug("udp-rate-exploration-ceiling-mbps=" + strconv.Itoa(sendCfg.RateExplorationCeilingMbps))
		}
		if len(probeRates) > 0 {
			cfg.Emitter.Debug("udp-rate-probe-rates=" + strings.Trim(strings.Join(strings.Fields(fmt.Sprint(probeRates)), ","), "[]"))
			cfg.Emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(sentProbeSamples, probeResult.Samples))
		}
		cfg.Emitter.Debug("udp-rate-selected-mbps=" + strconv.Itoa(selectedRateMbps))
		cfg.Emitter.Debug("udp-rate-start-mbps=" + strconv.Itoa(activeRateMbps))
		cfg.Emitter.Debug("udp-active-lanes-selected=" + strconv.Itoa(len(probeConns)))
		if sendCfg.MaxActiveLanes > 0 {
			cfg.Emitter.Debug("udp-active-lane-cap=" + strconv.Itoa(sendCfg.MaxActiveLanes))
		}
		if sendCfg.MinActiveLanes > 0 {
			cfg.Emitter.Debug("udp-active-lane-min=" + strconv.Itoa(sendCfg.MinActiveLanes))
		}
		cfg.Emitter.Debug("udp-rate-mbps=" + strconv.Itoa(activeRateMbps))
		cfg.Emitter.Debug("udp-stream=true")
		cfg.Emitter.Debug("udp-stream-replay-window-bytes=" + strconv.FormatUint(sendCfg.StreamReplayWindowBytes, 10))
	}

	plan.probeConns = probeConns
	plan.remoteAddrs = remoteAddrs
	plan.sendCfg = sendCfg
	plan.selectedRateMbps = selectedRateMbps
	plan.startRateMbps = activeRateMbps
	plan.rateCeilingMbps = rateCeilingMbps
	plan.probeRates = probeRates
	plan.sentProbeSamples = sentProbeSamples
	plan.receivedProbeSamples = probeResult.Samples
	return plan, nil
}

func externalExecutePreparedDirectUDPSend(ctx context.Context, src io.Reader, plan externalDirectUDPSendPlan, cfg SendConfig, metrics *externalTransferMetrics) error {
	if metrics == nil {
		metrics = externalTransferMetricsFromContext(ctx)
	}
	if metrics == nil {
		metrics = newExternalTransferMetrics(time.Now())
	}
	externalTransferTracef("direct-udp-send-execute-start lanes=%d addrs=%s rate=%d ceiling=%d", len(plan.probeConns), strings.Join(plan.remoteAddrs, ","), plan.sendCfg.RateMbps, plan.sendCfg.RateCeilingMbps)
	stats, err := probe.SendBlastParallel(ctx, plan.probeConns, plan.remoteAddrs, externalDirectUDPBufferedReader(src), plan.sendCfg)
	externalTransferTracef("direct-udp-send-execute-done err=%v bytes=%d lanes=%d first-byte-zero=%v complete-zero=%v", err, stats.BytesSent, stats.Lanes, stats.FirstByteAt.IsZero(), stats.CompletedAt.IsZero())
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-send-transport=" + stats.Transport.Summary())
		cfg.Emitter.Debug("udp-send-active-lanes=" + strconv.Itoa(stats.Lanes))
		cfg.Emitter.Debug("udp-send-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
		emitExternalDirectUDPSendReplayStats(cfg.Emitter, stats)
		emitExternalDirectUDPStats(cfg.Emitter, "udp-send", stats.BytesSent, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
	}
	if stats.BytesSent > 0 {
		directFirstByteAt := stats.FirstByteAt
		if directFirstByteAt.IsZero() {
			directFirstByteAt = stats.StartedAt
		}
		metrics.RecordDirectWrite(stats.BytesSent, directFirstByteAt)
	}
	emitExternalTransferMetricsComplete(metrics, cfg.Emitter, "udp-send", stats, stats.CompletedAt)
	return err
}

func externalPrepareDirectUDPReceive(ctx context.Context, dst io.Writer, tok token.Token, derpClient *derpbind.Client, peerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, decision rendezvous.Decision, readyCh <-chan derpbind.Packet, startCh <-chan derpbind.Packet, cfg ListenConfig) (externalDirectUDPReceivePlan, error) {
	plan := externalDirectUDPReceivePlan{decision: decision, peerAddr: peerAddr}
	auth := externalPeerControlAuthForToken(tok)
	externalTransferTracef("direct-udp-recv-ready-wait addr=%v", peerAddr)
	if err := externalDirectUDPWaitReadyFn(ctx, readyCh, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-recv-ready addr=%v", peerAddr)
	remoteAddrs := externalDirectUDPParallelCandidateStringsForPeer(remoteCandidates, len(probeConns), peerAddr)
	if len(remoteAddrs) > 0 {
		probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
	}
	if len(probeConns) == 0 {
		return plan, errors.New("direct UDP ready without usable receive sockets")
	}
	localTransportCaps := externalDirectUDPPreviewTransportCaps(probeConns[0], externalDirectUDPTransportLabel)

	receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
	fastDiscard := receiveDst == io.Discard
	if !fastDiscard {
		receiveDst, flushDst = externalDirectUDPSectionWriterForTarget(dst, receiveDst, flushDst)
	}
	if err := sendAuthenticatedEnvelope(ctx, derpClient, peerDERP, envelope{
		Type: envelopeDirectUDPReadyAck,
		DirectUDPReadyAck: &directUDPReadyAck{
			FastDiscard:               fastDiscard,
			TransportKind:             localTransportCaps.Kind,
			TransportBatchSize:        localTransportCaps.BatchSize,
			TransportReadBufferBytes:  localTransportCaps.ReadBufferBytes,
			TransportWriteBufferBytes: localTransportCaps.WriteBufferBytes,
			TransportTXOffload:        localTransportCaps.TXOffload,
			TransportRXQOverflow:      localTransportCaps.RXQOverflow,
		},
	}, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-recv-ready-ack-send addr=%v fast-discard=%v", peerAddr, fastDiscard)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-blast=true")
		cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
		cfg.Emitter.Debug("udp-require-complete=" + strconv.FormatBool(!fastDiscard))
		cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPStreamFECGroupSize))
		cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(fastDiscard))
		if peerAddr != nil {
			cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
		}
		cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
	}
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return plan, err
	}
	receiveCfg := externalDirectUDPFastDiscardReceiveConfig()
	receiveCfg.PacketAEAD = packetAEAD
	externalTransferTracef("direct-udp-recv-start-wait addr=%v", peerAddr)
	start, err := externalDirectUDPWaitStartFn(ctx, startCh, auth)
	if err != nil {
		return plan, err
	}
	rateProbeAuth, err := externalDirectUDPRateProbeAuthFromStart(tok, start)
	if err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-recv-start addr=%v stream=%v", peerAddr, start.Stream)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-stream=" + strconv.FormatBool(start.Stream))
		cfg.Emitter.Debug("udp-striped-blast=" + strconv.FormatBool(start.StripedBlast))
	}
	emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, start.ExpectedBytes)
	if err := sendAuthenticatedEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDirectUDPStartAck}, auth); err != nil {
		return plan, err
	}
	externalTransferTracef("direct-udp-recv-start-ack-send addr=%v", peerAddr)
	signalExternalDirectUDPDirectReady(ctx)
	if len(start.ProbeRates) > 0 {
		probeSamples, probeErr := externalDirectUDPReceiveRateProbesFn(ctx, probeConns, remoteAddrs, start.ProbeRates, rateProbeAuth)
		if probeErr != nil {
			return plan, probeErr
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(nil, probeSamples))
		}
		if err := sendAuthenticatedEnvelope(ctx, derpClient, peerDERP, envelope{
			Type: envelopeDirectUDPRateProbe,
			DirectUDPRateProbe: &directUDPRateProbeResult{
				Samples: probeSamples,
			},
		}, auth); err != nil {
			return plan, err
		}
	}
	plan.probeConns = probeConns
	plan.remoteAddrs = remoteAddrs
	plan.receiveDst = receiveDst
	plan.flushDst = flushDst
	plan.receiveCfg = receiveCfg
	plan.fastDiscard = fastDiscard
	plan.start = start
	return plan, nil
}

func externalExecutePreparedDirectUDPReceive(ctx context.Context, plan externalDirectUDPReceivePlan, tok token.Token, cfg ListenConfig, metrics *externalTransferMetrics) error {
	if metrics == nil {
		metrics = externalTransferMetricsFromContext(ctx)
	}
	if metrics == nil {
		metrics = newExternalTransferMetrics(time.Now())
	}
	receiveCfg := plan.receiveCfg
	var (
		stats probe.TransferStats
		err   error
	)
	if plan.start.Stream {
		receiveCfg.RequireComplete = true
		receiveCfg.FECGroupSize = externalDirectUDPStreamFECGroupSize
		receiveCfg.ExpectedRunID = tok.SessionID
		externalTransferTracef("direct-udp-recv-execute-start stream=true lanes=%d expected=%d", len(plan.probeConns), plan.start.ExpectedBytes)
		stats, err = probe.ReceiveBlastStreamParallelToWriter(ctx, plan.probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes)
	} else if plan.fastDiscard {
		externalTransferTracef("direct-udp-recv-execute-start fast-discard=true lanes=%d expected=%d", len(plan.probeConns), plan.start.ExpectedBytes)
		stats, err = probe.ReceiveBlastParallelToWriter(ctx, plan.probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes)
	} else {
		receiveCfg.RequireComplete = true
		probeConns, orderErr := externalDirectUDPOrderConnsForSections(plan.probeConns, plan.decision.Accept.Candidates, plan.start.SectionAddrs)
		if orderErr != nil {
			return orderErr
		}
		receiveCfg.ExpectedRunIDs = externalDirectUDPLaneRunIDs(tok.SessionID, len(probeConns))
		externalTransferTracef("direct-udp-recv-execute-start sections=true lanes=%d expected=%d", len(probeConns), plan.start.ExpectedBytes)
		stats, err = externalDirectUDPReceiveSectionSpoolParallel(ctx, probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes, plan.start.SectionSizes)
	}
	externalTransferTracef("direct-udp-recv-execute-done err=%v bytes=%d lanes=%d first-byte-zero=%v complete-zero=%v", err, stats.BytesReceived, stats.Lanes, stats.FirstByteAt.IsZero(), stats.CompletedAt.IsZero())
	emitExternalDirectUDPReceiveResultDebug(cfg.Emitter, stats, err)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-receive-transport=" + stats.Transport.Summary())
		if stats.Lanes > 0 {
			cfg.Emitter.Debug("udp-receive-active-lanes=" + strconv.Itoa(stats.Lanes))
		}
		cfg.Emitter.Debug("udp-receive-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
		emitExternalDirectUDPStats(cfg.Emitter, "udp-receive", stats.BytesReceived, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
	}
	if err == nil {
		err = plan.flushDst()
	}
	completedAt := time.Now()
	if stats.BytesReceived > 0 {
		directFirstByteAt := stats.FirstByteAt
		if directFirstByteAt.IsZero() {
			directFirstByteAt = stats.StartedAt
		}
		metrics.RecordDirectWrite(stats.BytesReceived, directFirstByteAt)
	}
	emitExternalTransferMetricsComplete(metrics, cfg.Emitter, "udp-receive", stats, completedAt)
	return err
}

func sendExternalViaDirectUDPOnly(ctx context.Context, src io.Reader, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc, probeConn net.PacketConn, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, cfg SendConfig) error {
	ctx = withExternalTransferMetrics(ctx, newExternalTransferMetrics(time.Now()))
	var peerAddr net.Addr
	if transportManager != nil {
		peerAddr, _ = transportManager.DirectAddr()
	}
	plan, err := externalPrepareDirectUDPSendFn(ctx, tok, derpClient, listenerDERP, peerAddr, probeConns, remoteCandidates, readyAckCh, startAckCh, rateProbeCh, cfg)
	if err != nil {
		if externalDirectUDPWaitCanFallback(ctx, err) {
			return sendExternalRelayUDP(ctx, src, transportManager, tok, cfg.Emitter)
		}
		return err
	}
	externalDirectUDPActivateDirectPath(pathEmitter, transportManager, punchCancel)
	metrics := externalTransferMetricsFromContext(ctx)
	return externalExecutePreparedDirectUDPSendFn(ctx, src, plan, cfg, metrics)
}

func listenExternalViaDirectUDP(ctx context.Context, cfg ListenConfig) (retTok string, retErr error) {
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
	auth := externalPeerControlAuthForToken(session.token)

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
		}, auth)
		defer stopPeerAbort()
		defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
			if countedDst == nil {
				return 0
			}
			return countedDst.Count()
		}, auth)
		probeConn := session.probeConn
		probeConns := []net.PacketConn{session.probeConn}
		portmaps := []publicPortmap{publicSessionPortmap(session)}
		cleanupProbeConns := func() {}
		peerRelayOnly := externalClaimRelayOnly(*env.Claim)
		relayOnly := cfg.ForceRelay || peerRelayOnly
		if !relayOnly {
			probeConn, probeConns, portmaps, cleanupProbeConns, err = externalAcceptedDirectUDPSet(session.probeConn, publicSessionPortmap(session), cfg.Emitter)
			if err != nil {
				return tok, err
			}
		}
		defer cleanupProbeConns()
		pm := portmaps[0]
		if !relayOnly {
			decision.Accept.Parallel = len(probeConns)
			decision.Accept.Candidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, session.derpMap, portmaps))
		} else {
			decision.Accept.Parallel = 0
			decision.Accept.Candidates = nil
		}
		localCandidates := parseCandidateStrings(decision.Accept.Candidates)
		readyCh, unsubscribeReady := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPReadyPayload(pkt.Payload)
		})
		defer unsubscribeReady()
		startCh, unsubscribeStart := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPStartPayload(pkt.Payload)
		})
		defer unsubscribeStart()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("claim-accepted")
		}

		transportCtx, transportCancel := context.WithCancel(ctx)
		defer transportCancel()
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.token, probeConn, session.derpMap, session.derp, peerDERP, localCandidates, pm, relayOnly)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.SuppressWatcherDirect()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		remoteCandidates := parseRemoteCandidateStrings(env.Claim.Candidates)
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		defer punchCancel()
		if !relayOnly {
			externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
		}

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		countedDst = newByteCountingWriteCloser(dst)
		defer countedDst.Close()
		var relayPrefixPackets <-chan derpbind.Packet
		if !relayOnly {
			var unsubscribeRelayPrefix func()
			relayPrefixPackets, unsubscribeRelayPrefix = session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
				return pkt.From == peerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
			})
			defer unsubscribeRelayPrefix()
		}

		if err := sendAuthenticatedEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
		}

		var receiveErr error
		if relayOnly {
			receiveErr = receiveExternalRelayUDP(ctx, countedDst, transportManager, session.token, cfg.Emitter)
		} else {
			receiveErr = receiveExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixReceiveConfig{
				dst:              countedDst,
				tok:              session.token,
				derpClient:       session.derp,
				peerDERP:         peerDERP,
				transportManager: transportManager,
				pathEmitter:      pathEmitter,
				punchCancel:      punchCancel,
				probeConn:        probeConn,
				probeConns:       probeConns,
				remoteCandidates: remoteCandidates,
				decision:         decision,
				readyCh:          readyCh,
				startCh:          startCh,
				relayPackets:     relayPrefixPackets,
				cfg:              cfg,
			})
		}
		if receiveErr != nil {
			return tok, receiveErr
		}
		if err := sendPeerAck(ctx, session.derp, peerDERP, countedDst.Count(), auth); err != nil {
			return tok, err
		}
		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func receiveExternalViaDirectUDPOnly(ctx context.Context, dst io.Writer, tok token.Token, derpClient *derpbind.Client, peerDERP key.NodePublic, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc, probeConn net.PacketConn, probeConns []net.PacketConn, remoteCandidates []net.Addr, decision rendezvous.Decision, readyCh <-chan derpbind.Packet, startCh <-chan derpbind.Packet, cfg ListenConfig) error {
	ctx = withExternalTransferMetrics(ctx, newExternalTransferMetrics(time.Now()))
	peerAddr, _ := transportManager.DirectAddr()
	plan, err := externalPrepareDirectUDPReceiveFn(ctx, dst, tok, derpClient, peerDERP, peerAddr, probeConns, remoteCandidates, decision, readyCh, startCh, cfg)
	if err != nil {
		if externalDirectUDPWaitCanFallback(ctx, err) {
			return receiveExternalRelayUDP(ctx, dst, transportManager, tok, cfg.Emitter)
		}
		return err
	}
	externalDirectUDPActivateDirectPath(pathEmitter, transportManager, punchCancel)
	metrics := externalTransferMetricsFromContext(ctx)
	return externalExecutePreparedDirectUDPReceiveFn(ctx, plan, tok, cfg, metrics)
}

type externalRelayPrefixSendConfig struct {
	src              io.Reader
	tok              token.Token
	decision         rendezvous.Decision
	derpClient       *derpbind.Client
	listenerDERP     key.NodePublic
	transportCtx     context.Context
	transportManager *transport.Manager
	pathEmitter      *transportPathEmitter
	punchCancel      context.CancelFunc
	probeConn        net.PacketConn
	probeConns       []net.PacketConn
	remoteCandidates []net.Addr
	readyAckCh       <-chan derpbind.Packet
	startAckCh       <-chan derpbind.Packet
	rateProbeCh      <-chan derpbind.Packet
	cfg              SendConfig
}

func sendExternalViaRelayPrefixThenDirectUDP(ctx context.Context, rcfg externalRelayPrefixSendConfig) error {
	if rcfg.decision.Accept == nil {
		return externalSendDirectUDPOnlyFn(ctx, rcfg.src, rcfg.tok, rcfg.derpClient, rcfg.listenerDERP, rcfg.transportManager, rcfg.pathEmitter, rcfg.punchCancel, rcfg.probeConn, rcfg.probeConns, rcfg.remoteCandidates, rcfg.readyAckCh, rcfg.startAckCh, rcfg.rateProbeCh, rcfg.cfg)
	}
	metrics := newExternalTransferMetrics(time.Now())
	ctx = withExternalTransferMetrics(ctx, metrics)
	packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
	if err != nil {
		return err
	}
	spool, err := newExternalHandoffSpool(rcfg.src, externalRelayPrefixDERPChunkSize, externalRelayPrefixDERPMaxUnacked)
	if err != nil {
		return err
	}
	defer spool.Close()
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	defer keepaliveCancel()
	go externalRelayPrefixTransportKeepalive(keepaliveCtx, rcfg.transportManager)

	relayStopCh := make(chan struct{})
	var relayStopOnce sync.Once
	stopRelay := func() {
		relayStopOnce.Do(func() {
			close(relayStopCh)
		})
	}
	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- externalSendExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.listenerDERP, spool, relayStopCh, metrics, packetAEAD)
	}()

	waitRelayErr := func() error {
		select {
		case err := <-relayErrCh:
			return err
		case <-ctx.Done():
			stopRelay()
			return normalizePeerAbortError(ctx, ctx.Err())
		}
	}

	handoffRelay := func() (bool, int64, error) {
		stopRelay()
		if err := waitRelayErr(); err != nil {
			return false, 0, err
		}
		watermark := spool.AckedWatermark()
		if spool.Done() {
			if rcfg.cfg.Emitter != nil {
				rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
			}
			emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-send", probe.TransferStats{}, time.Now())
			return true, watermark, nil
		}
		return false, watermark, spool.RewindTo(watermark)
	}

	prepCtx, prepCancel := context.WithCancel(ctx)
	defer prepCancel()
	prepCtx, handoffReadyCh := withExternalDirectUDPHandoffReadySignal(prepCtx)
	prepCtx, signalHandoffProceed := withExternalDirectUDPHandoffProceedSignal(prepCtx)
	prepCtx, directReadyCh := withExternalDirectUDPDirectReadySignal(prepCtx)
	type sendPrepResult struct {
		plan externalDirectUDPSendPlan
		err  error
	}
	prepCh := make(chan sendPrepResult, 1)
	var peerAddr net.Addr
	if rcfg.transportManager != nil {
		peerAddr, _ = rcfg.transportManager.DirectAddr()
	}
	go func() {
		sendCfg := rcfg.cfg
		sendCfg.skipDirectUDPRateProbes = externalRelayPrefixShouldSkipDirectUDPRateProbes(sendCfg.StdioExpectedBytes)
		plan, err := externalPrepareDirectUDPSendFn(prepCtx, rcfg.tok, rcfg.derpClient, rcfg.listenerDERP, peerAddr, rcfg.probeConns, rcfg.remoteCandidates, rcfg.readyAckCh, rcfg.startAckCh, rcfg.rateProbeCh, sendCfg)
		prepCh <- sendPrepResult{plan: plan, err: err}
	}()
	stallTimer := time.NewTimer(externalRelayPrefixDirectPrepStallWait)
	defer stallTimer.Stop()
	stallFired := false
	handoffReady := false
	directActivated := false
	activateDirect := func() {
		if directActivated {
			return
		}
		externalDirectUDPActivateDirectPath(rcfg.pathEmitter, rcfg.transportManager, rcfg.punchCancel)
		directActivated = true
	}
	postHandoff := func() error {
		externalTransferTracef("relay-prefix-send-post-handoff-start")
		done, watermark, err := handoffRelay()
		if err != nil {
			return err
		}
		if done {
			externalTransferTracef("relay-prefix-send-post-handoff-done-on-relay")
			return nil
		}
		externalTransferTracef("relay-prefix-send-post-handoff-proceed")
		recordExternalDirectUDPHandoffProceedWatermark(prepCtx, watermark)
		signalHandoffProceed()
		for {
			if directReadyCh != nil {
				select {
				case <-directReadyCh:
					directReadyCh = nil
					activateDirect()
					continue
				default:
				}
			}
			select {
			case <-directReadyCh:
				directReadyCh = nil
				externalTransferTracef("relay-prefix-send-post-handoff-direct-ready")
				activateDirect()
			case prep := <-prepCh:
				if prep.err != nil {
					return prep.err
				}
				externalTransferTracef("relay-prefix-send-post-handoff-prepared")
				activateDirect()
				return externalExecutePreparedDirectUDPSendFn(ctx, newExternalHandoffSpoolReader(spool), prep.plan, rcfg.cfg, metrics)
			case <-ctx.Done():
				prepCancel()
				stopRelay()
				return normalizePeerAbortError(ctx, ctx.Err())
			}
		}
	}

	for {
		if directReadyCh != nil {
			select {
			case <-directReadyCh:
				directReadyCh = nil
				activateDirect()
				continue
			default:
			}
		}
		select {
		case relayErr := <-relayErrCh:
			prepCancel()
			if relayErr != nil {
				return relayErr
			}
			if rcfg.cfg.Emitter != nil {
				rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
			}
			emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-send", probe.TransferStats{}, time.Now())
			return nil
		case prep := <-prepCh:
			if prep.err != nil {
				if rcfg.cfg.Emitter != nil {
					rcfg.cfg.Emitter.Debug("udp-handoff-send-prepare-error=" + prep.err.Error())
				}
				if ctx.Err() != nil || errors.Is(prep.err, context.Canceled) {
					stopRelay()
					return normalizePeerAbortError(ctx, prep.err)
				}
				relayErr := waitRelayErr()
				if relayErr != nil {
					return relayErr
				}
				if rcfg.cfg.Emitter != nil {
					rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
				}
				emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-send", probe.TransferStats{}, time.Now())
				return nil
			}
			if externalRelayPrefixShouldFinishRelay(spool) {
				relayErr := waitRelayErr()
				if relayErr != nil {
					return relayErr
				}
				if rcfg.cfg.Emitter != nil {
					rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
				}
				emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-send", probe.TransferStats{}, time.Now())
				return nil
			}
			externalTransferTracef("relay-prefix-send-prepare-complete")
			done, watermark, err := handoffRelay()
			if err != nil {
				return err
			}
			if done {
				externalTransferTracef("relay-prefix-send-prepare-complete-done-on-relay")
				return nil
			}
			recordExternalDirectUDPHandoffProceedWatermark(prepCtx, watermark)
			externalDirectUDPActivateDirectPath(rcfg.pathEmitter, rcfg.transportManager, rcfg.punchCancel)
			return externalExecutePreparedDirectUDPSendFn(ctx, newExternalHandoffSpoolReader(spool), prep.plan, rcfg.cfg, metrics)
		case <-stallTimer.C:
			stallFired = true
			externalTransferTracef("relay-prefix-send-stall-timer handoff-ready=%v", handoffReady)
			if handoffReady {
				return postHandoff()
			}
		case <-handoffReadyCh:
			handoffReady = true
			handoffReadyCh = nil
			externalTransferTracef("relay-prefix-send-handoff-ready stall-fired=%v", stallFired)
			if stallFired {
				return postHandoff()
			}
		case <-directReadyCh:
			directReadyCh = nil
			externalTransferTracef("relay-prefix-send-direct-ready-pre-prepare")
			activateDirect()
		case <-ctx.Done():
			prepCancel()
			stopRelay()
			return normalizePeerAbortError(ctx, ctx.Err())
		}
	}
}

type externalRelayPrefixReceiveConfig struct {
	dst              io.Writer
	tok              token.Token
	derpClient       *derpbind.Client
	peerDERP         key.NodePublic
	transportManager *transport.Manager
	pathEmitter      *transportPathEmitter
	punchCancel      context.CancelFunc
	probeConn        net.PacketConn
	probeConns       []net.PacketConn
	remoteCandidates []net.Addr
	decision         rendezvous.Decision
	readyCh          <-chan derpbind.Packet
	startCh          <-chan derpbind.Packet
	relayPackets     <-chan derpbind.Packet
	cfg              ListenConfig
}

func receiveExternalViaRelayPrefixThenDirectUDP(ctx context.Context, rcfg externalRelayPrefixReceiveConfig) error {
	metrics := newExternalTransferMetrics(time.Now())
	ctx = withExternalTransferMetrics(ctx, metrics)
	packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
	if err != nil {
		return err
	}
	rx := newExternalHandoffReceiver(externalTransferMetricsWriter{w: rcfg.dst, record: metrics.RecordRelayWrite}, externalHandoffMaxUnackedBytes)
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	defer keepaliveCancel()
	go externalRelayPrefixTransportKeepalive(keepaliveCtx, rcfg.transportManager)
	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- externalReceiveExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.peerDERP, rx, rcfg.relayPackets, nil, packetAEAD)
	}()

	waitRelayOrReturnDirectError := func(directErr error) error {
		relayErr := <-relayErrCh
		switch {
		case relayErr == nil:
			if rcfg.cfg.Emitter != nil {
				rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
			}
			emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-receive", probe.TransferStats{}, time.Now())
			return nil
		case errors.Is(relayErr, errExternalHandoffCarrierHandoff):
			return directErr
		default:
			return relayErr
		}
	}

	prepCtx, prepCancel := context.WithCancel(ctx)
	defer prepCancel()
	prepCtx, directReadyCh := withExternalDirectUDPDirectReadySignal(prepCtx)
	type receivePrepResult struct {
		plan externalDirectUDPReceivePlan
		err  error
	}
	prepCh := make(chan receivePrepResult, 1)
	var peerAddr net.Addr
	if rcfg.transportManager != nil {
		peerAddr, _ = rcfg.transportManager.DirectAddr()
	}
	go func() {
		plan, err := externalPrepareDirectUDPReceiveFn(prepCtx, rcfg.dst, rcfg.tok, rcfg.derpClient, rcfg.peerDERP, peerAddr, rcfg.probeConns, rcfg.remoteCandidates, rcfg.decision, rcfg.readyCh, rcfg.startCh, rcfg.cfg)
		prepCh <- receivePrepResult{plan: plan, err: err}
	}()
	directActivated := false
	relayHandedOff := false
	activateDirect := func() {
		if directActivated {
			return
		}
		externalDirectUDPActivateDirectPath(rcfg.pathEmitter, rcfg.transportManager, rcfg.punchCancel)
		directActivated = true
	}

	for {
		if directReadyCh != nil {
			select {
			case <-directReadyCh:
				directReadyCh = nil
				activateDirect()
				continue
			default:
			}
		}
		select {
		case relayErr := <-relayErrCh:
			if relayErr == nil {
				prepCancel()
				if rcfg.cfg.Emitter != nil {
					rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
				}
				emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-receive", probe.TransferStats{}, time.Now())
				return nil
			}
			if !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
				prepCancel()
				return relayErr
			}
			relayErrCh = nil
			relayHandedOff = true
		case <-directReadyCh:
			directReadyCh = nil
			activateDirect()
		case prep := <-prepCh:
			if prep.err != nil {
				if rcfg.cfg.Emitter != nil {
					rcfg.cfg.Emitter.Debug("udp-handoff-receive-prepare-error=" + prep.err.Error())
				}
				if relayHandedOff {
					return prep.err
				}
				return waitRelayOrReturnDirectError(prep.err)
			}
			if !relayHandedOff {
				relayErr := <-relayErrCh
				if relayErr == nil {
					if rcfg.cfg.Emitter != nil {
						rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
					}
					emitExternalTransferMetricsComplete(metrics, rcfg.cfg.Emitter, "udp-receive", probe.TransferStats{}, time.Now())
					return nil
				}
				if !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
					return relayErr
				}
				relayHandedOff = true
			}
			activateDirect()
			return externalExecutePreparedDirectUDPReceiveFn(ctx, prep.plan, rcfg.tok, rcfg.cfg, metrics)
		}
	}
}

func externalRelayPrefixTransportKeepalive(ctx context.Context, manager *transport.Manager) {
	if manager == nil {
		return
	}
	peerConn := manager.PeerDatagramConn(ctx)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	payload := []byte("prefix-keepalive")
	for {
		_ = peerConn.SendDatagram(payload)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func externalRelayPrefixShouldSkipDirectUDPRateProbes(expectedBytes int64) bool {
	return expectedBytes <= 0 || expectedBytes < externalDirectUDPRateProbeMinBytes
}

func externalDirectUDPUseRelayPrefixNoProbePath(ctx context.Context, skipRateProbes bool, probeRates []int) bool {
	if skipRateProbes {
		return true
	}
	if len(probeRates) > 0 {
		return false
	}
	_, ok := externalDirectUDPHandoffProceedWatermark(ctx)
	return ok
}

func externalDirectUDPSenderRetainedLaneCap(caps probe.TransportCaps, selectedRateMbps int, activeRateMbps int, rateCeilingMbps int, retainedLanes int) int {
	if retainedLanes <= 2 {
		return retainedLanes
	}
	if caps.Kind != "legacy" && caps.Kind != "batched" {
		return retainedLanes
	}
	if caps.Kind == "legacy" &&
		selectedRateMbps < externalDirectUDPActiveLaneTwoMaxMbps &&
		activeRateMbps < externalDirectUDPActiveLaneTwoMaxMbps {
		return retainedLanes
	}
	if caps.Kind == "batched" &&
		(caps.TXOffload || caps.RXQOverflow ||
			(rateCeilingMbps > 0 && retainedLanes > 0 && rateCeilingMbps/retainedLanes <= externalDirectUDPActiveLaneOneMaxMbps) ||
			(rateCeilingMbps > 0 && rateCeilingMbps <= externalDirectUDPDataStartHighMbps) ||
			(selectedRateMbps < externalDirectUDPActiveLaneTwoMaxMbps && activeRateMbps < externalDirectUDPActiveLaneTwoMaxMbps)) {
		return retainedLanes
	}
	return 2
}

func externalDirectUDPEffectiveSenderCaps(localCaps probe.TransportCaps, readyAck directUDPReadyAck) probe.TransportCaps {
	if readyAck.TransportKind == "legacy" {
		localCaps.Kind = "legacy"
	}
	if readyAck.TransportKind == "batched" &&
		readyAck.TransportBatchSize > 0 &&
		!readyAck.TransportTXOffload &&
		!readyAck.TransportRXQOverflow {
		localCaps.Kind = "batched"
		localCaps.TXOffload = false
		localCaps.RXQOverflow = false
		if localCaps.BatchSize == 0 {
			localCaps.BatchSize = readyAck.TransportBatchSize
		}
	}
	return localCaps
}

func externalDirectUDPConstrainedReceiver(readyAck directUDPReadyAck) bool {
	return readyAck.TransportKind == "batched" &&
		readyAck.TransportRXQOverflow &&
		readyAck.TransportReadBufferBytes > 0 &&
		readyAck.TransportReadBufferBytes <= externalDirectUDPConstrainedReceiverBuffer
}

func externalDirectUDPConstrainedReceiverStartRate(readyAck directUDPReadyAck, activeRateMbps int) int {
	if !externalDirectUDPConstrainedReceiver(readyAck) || activeRateMbps <= 0 || activeRateMbps <= externalDirectUDPConstrainedReceiverStartMbps {
		return activeRateMbps
	}
	return externalDirectUDPConstrainedReceiverStartMbps
}

func externalDirectUDPConstrainedReceiverLaneCap(readyAck directUDPReadyAck, currentCap int, available int) int {
	if !externalDirectUDPConstrainedReceiver(readyAck) {
		return currentCap
	}
	cap := externalDirectUDPConstrainedReceiverLaneMax
	if available > 0 && cap > available {
		cap = available
	}
	if currentCap > 0 && currentCap < cap {
		return currentCap
	}
	return cap
}

func externalDirectUDPConstrainedReceiverMinActiveLanes(readyAck directUDPReadyAck, available int) int {
	if !externalDirectUDPConstrainedReceiver(readyAck) || available <= 1 {
		return 0
	}
	if available < externalDirectUDPConstrainedReceiverLaneMax {
		return available
	}
	return externalDirectUDPConstrainedReceiverLaneMax
}

func externalDirectUDPSenderProbeRateLimit(caps probe.TransportCaps, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) externalDirectUDPSenderProbeRateLimitResult {
	if caps.Kind != "batched" || caps.TXOffload || caps.RXQOverflow || len(sent) == 0 || len(received) == 0 {
		return externalDirectUDPSenderProbeRateLimitResult{}
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	cleanLimit := externalDirectUDPSenderProbeRateLimitResult{}
	lossyLimit := externalDirectUDPSenderProbeRateLimitResult{}
	lossyScore := 0
	lowCleanLimit := externalDirectUDPSenderProbeRateLimitResult{}
	for _, sample := range received {
		if sample.RateMbps < externalDirectUDPActiveLaneTwoMaxMbps {
			continue
		}
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || goodput <= 0 {
			continue
		}
		if delivery >= externalDirectUDPRateProbeClean {
			limit := externalDirectUDPBatchOnlyCleanProbeRateLimit(sample.RateMbps)
			if sample.RateMbps >= externalDirectUDPRateProbeCollapseMinMbps {
				if sample.RateMbps > cleanLimit.CeilingMbps {
					cleanLimit = limit
				}
				continue
			}
			if sample.RateMbps > lowCleanLimit.CeilingMbps {
				lowCleanLimit = limit
			}
			continue
		}
		if sample.RateMbps < externalDirectUDPRateProbeCollapseMinMbps ||
			delivery < externalDirectUDPRateProbeBufferedCollapse ||
			goodput < externalDirectUDPRateProbeHighHeadroomMin {
			continue
		}
		limit := externalDirectUDPBatchOnlyLossyProbeRateLimit(sample.RateMbps, goodput, delivery)
		if limit.StartMbps <= lossyScore {
			continue
		}
		lossyScore = limit.StartMbps
		lossyLimit = limit
	}
	switch {
	case cleanLimit.CeilingMbps > 0:
		return cleanLimit
	case lossyLimit.CeilingMbps > 0 && lowCleanLimit.CeilingMbps > 0 && lowCleanLimit.StartMbps >= lossyLimit.StartMbps:
		return lowCleanLimit
	case lossyLimit.CeilingMbps > 0:
		return lossyLimit
	case lowCleanLimit.CeilingMbps > 0:
		return lowCleanLimit
	default:
		return externalDirectUDPSenderProbeRateLimitResult{}
	}
}

func externalDirectUDPSenderApplyProbeRateLimit(activeRateMbps int, limit externalDirectUDPSenderProbeRateLimitResult) int {
	if limit.StartMbps <= 0 {
		return activeRateMbps
	}
	if limit.StartOverride {
		return limit.StartMbps
	}
	if activeRateMbps > limit.StartMbps {
		return limit.StartMbps
	}
	return activeRateMbps
}

func externalDirectUDPBatchOnlyCleanProbeRateLimit(rateMbps int) externalDirectUDPSenderProbeRateLimitResult {
	startMbps := rateMbps
	if rateMbps > externalDirectUDPRateProbeCollapseMinMbps {
		startMbps = externalDirectUDPRoundBatchOnlyProbeMbps(float64(rateMbps) * externalDirectUDPBatchOnlyCleanStartShare)
	}
	limit := externalDirectUDPNormalizeBatchOnlyProbeRateLimit(startMbps, rateMbps)
	if rateMbps >= externalDirectUDPRateProbeCollapseMinMbps {
		limit.CeilingMbps = limit.StartMbps
	}
	return limit
}

func externalDirectUDPBatchOnlyLossyProbeRateLimit(rateMbps int, goodputMbps float64, delivery float64) externalDirectUDPSenderProbeRateLimitResult {
	startMbps := externalDirectUDPRoundBatchOnlyProbeMbps(goodputMbps * delivery * delivery * externalDirectUDPBatchOnlyLossyStartShare)
	limit := externalDirectUDPNormalizeBatchOnlyProbeRateLimit(startMbps, rateMbps)
	if limit.StartMbps > externalDirectUDPRateProbeCollapseMinMbps {
		limit.StartMbps = externalDirectUDPRateProbeCollapseMinMbps
	}
	limit.CeilingMbps = limit.StartMbps
	limit.StartOverride = false
	return limit
}

func externalDirectUDPNormalizeBatchOnlyProbeRateLimit(startMbps int, ceilingMbps int) externalDirectUDPSenderProbeRateLimitResult {
	if ceilingMbps <= 0 {
		return externalDirectUDPSenderProbeRateLimitResult{}
	}
	if startMbps <= 0 {
		startMbps = ceilingMbps
	}
	if startMbps > ceilingMbps {
		startMbps = ceilingMbps
	}
	return externalDirectUDPSenderProbeRateLimitResult{
		StartMbps:     startMbps,
		CeilingMbps:   ceilingMbps,
		StartOverride: true,
	}
}

func externalDirectUDPRoundBatchOnlyProbeMbps(rateMbps float64) int {
	if rateMbps <= 0 {
		return 0
	}
	round := externalDirectUDPBatchOnlyProbeRoundMbps
	if round <= 0 {
		return int(rateMbps + 0.5)
	}
	return int(rateMbps/float64(round)+0.5) * round
}

func externalDirectUDPSenderStartRateCap(caps probe.TransportCaps, selectedRateMbps int, activeRateMbps int) int {
	maxRateMbps := externalDirectUDPStaticSenderRateMaxMbps(caps)
	if maxRateMbps == 0 || selectedRateMbps < maxRateMbps {
		return activeRateMbps
	}
	if activeRateMbps == maxRateMbps {
		return activeRateMbps
	}
	return maxRateMbps
}

func externalDirectUDPSenderRateCeilingCap(caps probe.TransportCaps, rateCeilingMbps int) int {
	maxRateMbps := externalDirectUDPStaticSenderRateMaxMbps(caps)
	if maxRateMbps == 0 || rateCeilingMbps <= maxRateMbps {
		return rateCeilingMbps
	}
	return maxRateMbps
}

func externalDirectUDPSenderExplorationCeilingCap(caps probe.TransportCaps, explorationCeilingMbps int) int {
	maxRateMbps := externalDirectUDPStaticSenderRateMaxMbps(caps)
	if maxRateMbps == 0 || explorationCeilingMbps <= maxRateMbps {
		return explorationCeilingMbps
	}
	return maxRateMbps
}

func externalDirectUDPStaticSenderRateMaxMbps(caps probe.TransportCaps) int {
	if caps.Kind == "legacy" {
		return externalDirectUDPActiveLaneTwoMaxMbps
	}
	return 0
}

func sendExternalHandoffDERP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, spool *externalHandoffSpool, stop <-chan struct{}, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error {
	externalTransferTracef("sender-derp-prefix-start")
	if client == nil {
		return errors.New("nil DERP client")
	}
	if spool == nil {
		return errors.New("nil external handoff spool")
	}
	if stop != nil {
		stopWatchDone := make(chan struct{})
		defer close(stopWatchDone)
		go func() {
			select {
			case <-stop:
				select {
				case <-stopWatchDone:
					return
				default:
				}
				spool.InterruptPendingRead()
			case <-stopWatchDone:
			}
		}()
	}

	ackPackets, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		kind := externalRelayPrefixDERPFrameKindOf(pkt.Payload)
		return pkt.From == peerDERP && (kind == externalRelayPrefixDERPFrameAck || kind == externalRelayPrefixDERPFrameHandoffAck)
	})
	defer unsubscribe()

	ackEvents := make(chan int64, 128)
	handoffAckEvents := make(chan int64, 16)
	ackErrCh := make(chan error, 1)
	go func() {
		for {
			pkt, err := receiveSubscribedPacket(ctx, ackPackets)
			if err != nil {
				ackErrCh <- err
				return
			}
			watermark, err := externalRelayPrefixDERPDecodeAck(pkt.Payload)
			if err != nil {
				ackErrCh <- err
				return
			}
			if err := spool.AckTo(watermark); err != nil {
				ackErrCh <- err
				return
			}
			kind := externalRelayPrefixDERPFrameKindOf(pkt.Payload)
			if kind == externalRelayPrefixDERPFrameHandoffAck {
				externalTransferTracef("sender-derp-prefix-handoff-ack watermark=%d", watermark)
				select {
				case handoffAckEvents <- watermark:
				default:
				}
			} else {
				externalTransferTracef("sender-derp-prefix-ack watermark=%d", watermark)
				select {
				case ackEvents <- watermark:
				default:
				}
			}
			if spool.Done() {
				ackErrCh <- nil
				return
			}
		}
	}()

	waitForAnyAck := func() error {
		select {
		case err := <-ackErrCh:
			return err
		case <-ackEvents:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	drainAckEvents := func() {
		for {
			select {
			case <-ackEvents:
			case <-handoffAckEvents:
			default:
				return
			}
		}
	}

	waitForHandoffAck := func(boundary int64) error {
		timer := time.NewTimer(externalRelayPrefixDERPHandoffAckWait)
		defer timer.Stop()
		for {
			if spool.AckedWatermark() >= boundary {
				return nil
			}
			select {
			case err := <-ackErrCh:
				return err
			case <-handoffAckEvents:
				return nil
			case <-ackEvents:
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return ErrPeerDisconnected
			}
		}
	}

	sendHandoffAndWaitForAck := func(boundary int64) error {
		drainAckEvents()
		if err := externalRelayPrefixDERPSendHandoff(ctx, client, peerDERP, boundary); err != nil {
			return err
		}
		if spool.AckedWatermark() >= boundary {
			return nil
		}
		return waitForHandoffAck(boundary)
	}

	waitForCompleteAck := func() error {
		for {
			if spool.Done() {
				return nil
			}
			if err := waitForAnyAck(); err != nil {
				return err
			}
		}
	}

	handoffBoundary := func() (int64, bool) {
		snapshot := spool.Snapshot()
		return snapshot.ReadOffset, snapshot.ReadOffset > 0
	}

	for {
		if stop != nil {
			select {
			case <-stop:
				if !spool.Done() {
					if boundary, ready := handoffBoundary(); ready {
						externalTransferTracef("sender-derp-prefix-handoff-fast boundary=%d acked=%d", boundary, spool.AckedWatermark())
						return sendHandoffAndWaitForAck(boundary)
					}
				} else {
					return nil
				}
			default:
			}
		}
		if err := externalDirectUDPHandoffRelayPauseWait(ctx, stop); err != nil {
			return err
		}

		if spool.Snapshot().ReadOffset >= externalRelayPrefixDERPStartupBytes {
			spool.SetMaxUnacked(externalRelayPrefixDERPSustainedMax)
		}

		chunk, err := spool.NextChunk()
		switch {
		case err == nil:
			externalTransferTracef("sender-derp-prefix-data offset=%d bytes=%d", chunk.Offset, len(chunk.Payload))
			if err := externalRelayPrefixDERPSendChunk(ctx, client, peerDERP, chunk, packetAEAD); err != nil {
				return err
			}
			if metrics != nil {
				metrics.RecordRelayWrite(int64(len(chunk.Payload)), time.Now())
			}
		case errors.Is(err, io.EOF):
			finalOffset := spool.Snapshot().SourceOffset
			externalTransferTracef("sender-derp-prefix-eof final=%d acked=%d", finalOffset, spool.AckedWatermark())
			if err := externalRelayPrefixDERPSendEOF(ctx, client, peerDERP, finalOffset); err != nil {
				return err
			}
			return waitForCompleteAck()
		case errors.Is(err, errExternalHandoffUnackedWindowFull), errors.Is(err, errExternalHandoffSourcePending):
			select {
			case <-stop:
				if !spool.Done() {
					if boundary, ready := handoffBoundary(); ready {
						externalTransferTracef("sender-derp-prefix-handoff boundary=%d acked=%d", boundary, spool.AckedWatermark())
						return sendHandoffAndWaitForAck(boundary)
					}
					continue
				}
				return nil
			case err := <-ackErrCh:
				return err
			case <-ackEvents:
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		default:
			return err
		}
	}
}

func receiveExternalHandoffDERP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, rx *externalHandoffReceiver, packets <-chan derpbind.Packet, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error {
	externalTransferTracef("listener-derp-prefix-start")
	if client == nil {
		return errors.New("nil DERP client")
	}
	if rx == nil {
		return errors.New("nil external handoff receiver")
	}

	if packets == nil {
		var unsubscribe func()
		packets, unsubscribe = client.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
		})
		defer unsubscribe()
	}

	eofOffset := int64(-1)
	finishIfBoundaryReached := func() (bool, error) {
		watermark := rx.Watermark()
		if eofOffset >= 0 && watermark >= eofOffset {
			if err := externalRelayPrefixDERPSendAck(ctx, client, peerDERP, watermark); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, nil
	}

	for {
		pkt, err := receiveSubscribedPacket(ctx, packets)
		if err != nil {
			return err
		}
		kind := externalRelayPrefixDERPFrameKindOf(pkt.Payload)
		externalTransferTracef("listener-derp-prefix-frame kind=%d bytes=%d watermark=%d", kind, len(pkt.Payload), rx.Watermark())
		switch kind {
		case externalRelayPrefixDERPFrameData:
			chunk, err := externalRelayPrefixDERPDecodeChunk(pkt.Payload, packetAEAD)
			if err != nil {
				return err
			}
			prevWatermark := rx.Watermark()
			if err := rx.AcceptChunk(chunk); err != nil {
				return err
			}
			if metrics != nil {
				if delivered := rx.Watermark() - prevWatermark; delivered > 0 {
					metrics.RecordRelayWrite(delivered, time.Now())
				}
			}
			if err := externalRelayPrefixDERPSendAck(ctx, client, peerDERP, rx.Watermark()); err != nil {
				return err
			}
			done, err := finishIfBoundaryReached()
			if done || err != nil {
				return err
			}
		case externalRelayPrefixDERPFrameEOF:
			offset, err := externalRelayPrefixDERPDecodeOffset(pkt.Payload)
			if err != nil {
				return err
			}
			eofOffset = offset
			done, err := finishIfBoundaryReached()
			if done || err != nil {
				return err
			}
		case externalRelayPrefixDERPFrameHandoff:
			offset, err := externalRelayPrefixDERPDecodeOffset(pkt.Payload)
			if err != nil {
				return err
			}
			externalTransferTracef("listener-derp-prefix-handoff boundary=%d watermark=%d", offset, rx.Watermark())
			if err := externalRelayPrefixDERPSendHandoffAck(ctx, client, peerDERP, rx.Watermark()); err != nil {
				return err
			}
			return errExternalHandoffCarrierHandoff
		case externalRelayPrefixDERPFrameAck:
			continue
		default:
			return errors.New("unexpected relay-prefix DERP frame")
		}
	}
}

func externalRelayPrefixDERPFrameKindOf(payload []byte) externalRelayPrefixDERPFrameKind {
	if len(payload) < externalRelayPrefixDERPHeaderSize || !mem.B(payload[:16]).Equal(mem.B(externalRelayPrefixDERPMagic[:])) {
		return 0
	}
	kind := externalRelayPrefixDERPFrameKind(payload[16])
	switch kind {
	case externalRelayPrefixDERPFrameData, externalRelayPrefixDERPFrameAck, externalRelayPrefixDERPFrameEOF, externalRelayPrefixDERPFrameHandoff, externalRelayPrefixDERPFrameHandoffAck:
		return kind
	default:
		return 0
	}
}

const externalTestRelayPlaintextMarkerEnv = "DERPHOLE_TEST_RELAY_PLAINTEXT_MARKER"

func externalAssertNoPlaintextRelayMarker(payload []byte) error {
	marker := os.Getenv(externalTestRelayPlaintextMarkerEnv)
	if marker == "" {
		return nil
	}
	if strings.Contains(string(payload), marker) {
		return errors.New("relay payload contains plaintext marker")
	}
	return nil
}

func externalRelayPrefixDERPHeader(kind externalRelayPrefixDERPFrameKind, offset int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("negative relay-prefix DERP offset %d", offset)
	}
	out := make([]byte, externalRelayPrefixDERPHeaderSize)
	copy(out[:16], externalRelayPrefixDERPMagic[:])
	out[16] = byte(kind)
	binary.BigEndian.PutUint64(out[17:25], uint64(offset))
	return out, nil
}

func externalRelayPrefixDERPDataNonce(header []byte) ([12]byte, error) {
	var nonce [12]byte
	if len(header) != externalRelayPrefixDERPHeaderSize {
		return nonce, fmt.Errorf("relay-prefix DERP header length = %d, want %d", len(header), externalRelayPrefixDERPHeaderSize)
	}
	hash := sha256.New()
	_, _ = hash.Write(externalRelayPrefixDERPDataNonceDomain)
	_, _ = hash.Write(header)
	sum := hash.Sum(nil)
	copy(nonce[:], sum[:len(nonce)])
	return nonce, nil
}

func externalRelayPrefixDERPPayload(kind externalRelayPrefixDERPFrameKind, offset int64, payload []byte, packetAEAD cipher.AEAD) ([]byte, error) {
	header, err := externalRelayPrefixDERPHeader(kind, offset)
	if err != nil {
		return nil, err
	}
	if kind != externalRelayPrefixDERPFrameData {
		if len(payload) != 0 {
			return nil, errors.New("relay-prefix DERP control frame cannot carry payload")
		}
		return header, nil
	}
	if packetAEAD == nil {
		return nil, errors.New("nil relay-prefix DERP data AEAD")
	}
	if packetAEAD.NonceSize() != 12 {
		return nil, errors.New("unsupported relay-prefix DERP data AEAD nonce size")
	}
	nonce, err := externalRelayPrefixDERPDataNonce(header)
	if err != nil {
		return nil, err
	}
	return packetAEAD.Seal(header, nonce[:], payload, header), nil
}

func externalRelayPrefixDERPSendChunk(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, chunk externalHandoffChunk, packetAEAD cipher.AEAD) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameData, chunk.Offset, chunk.Payload, packetAEAD)
	if err != nil {
		return err
	}
	if err := externalAssertNoPlaintextRelayMarker(payload); err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}

func externalRelayPrefixDERPSendAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, watermark int64) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameAck, watermark, nil, nil)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}

func externalRelayPrefixDERPSendEOF(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, finalOffset int64) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameEOF, finalOffset, nil, nil)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}

func externalRelayPrefixDERPSendHandoff(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, watermark int64) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameHandoff, watermark, nil, nil)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}

func externalRelayPrefixDERPSendHandoffAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, watermark int64) error {
	payload, err := externalRelayPrefixDERPPayload(externalRelayPrefixDERPFrameHandoffAck, watermark, nil, nil)
	if err != nil {
		return err
	}
	return client.Send(ctx, peerDERP, payload)
}

func externalRelayPrefixDERPDecodeOffset(payload []byte) (int64, error) {
	kind := externalRelayPrefixDERPFrameKindOf(payload)
	if kind == 0 {
		return 0, errors.New("invalid relay-prefix DERP frame")
	}
	if kind != externalRelayPrefixDERPFrameData && len(payload) != externalRelayPrefixDERPHeaderSize {
		return 0, errors.New("relay-prefix DERP control frame cannot carry payload")
	}
	offset := binary.BigEndian.Uint64(payload[17:25])
	if offset > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("relay-prefix DERP offset %d overflows int64", offset)
	}
	return int64(offset), nil
}

func externalRelayPrefixDERPDecodeAck(payload []byte) (int64, error) {
	kind := externalRelayPrefixDERPFrameKindOf(payload)
	if kind != externalRelayPrefixDERPFrameAck && kind != externalRelayPrefixDERPFrameHandoffAck {
		return 0, errors.New("unexpected relay-prefix DERP ack frame")
	}
	return externalRelayPrefixDERPDecodeOffset(payload)
}

func externalRelayPrefixDERPDecodeChunk(payload []byte, packetAEAD cipher.AEAD) (externalHandoffChunk, error) {
	if externalRelayPrefixDERPFrameKindOf(payload) != externalRelayPrefixDERPFrameData {
		return externalHandoffChunk{}, errors.New("unexpected relay-prefix DERP data frame")
	}
	offset, err := externalRelayPrefixDERPDecodeOffset(payload)
	if err != nil {
		return externalHandoffChunk{}, err
	}
	if packetAEAD == nil {
		return externalHandoffChunk{}, errors.New("nil relay-prefix DERP data AEAD")
	}
	if packetAEAD.NonceSize() != 12 {
		return externalHandoffChunk{}, errors.New("unsupported relay-prefix DERP data AEAD nonce size")
	}
	header := payload[:externalRelayPrefixDERPHeaderSize]
	nonce, err := externalRelayPrefixDERPDataNonce(header)
	if err != nil {
		return externalHandoffChunk{}, err
	}
	cleartext, err := packetAEAD.Open(nil, nonce[:], payload[externalRelayPrefixDERPHeaderSize:], header)
	if err != nil {
		return externalHandoffChunk{}, fmt.Errorf("decrypt relay-prefix DERP data: %w", err)
	}
	return externalHandoffChunk{Offset: offset, Payload: cleartext}, nil
}

func externalRelayPrefixShouldFinishRelay(spool *externalHandoffSpool) bool {
	if spool == nil {
		return false
	}

	spool.mu.Lock()
	defer spool.mu.Unlock()

	if !spool.eof {
		return false
	}
	return spool.sourceOffset-spool.ackedWatermark <= externalRelayPrefixSkipDirectTail
}

func externalDirectUDPConns(_ net.PacketConn, _ publicPortmap, parallel int, emitter *telemetry.Emitter) ([]net.PacketConn, []publicPortmap, func(), error) {
	if parallel <= 0 {
		parallel = 1
	}
	conns := make([]net.PacketConn, 0, parallel)
	portmaps := make([]publicPortmap, 0, parallel)
	owned := make([]net.PacketConn, 0, parallel)
	ownedPMs := make([]publicPortmap, 0, parallel)
	network, address := "udp", ":0"
	if fakeTransportEnabled() {
		network, address = "udp4", "127.0.0.1:0"
	}
	for len(conns) < parallel {
		conn, err := net.ListenPacket(network, address)
		if err != nil {
			for _, ownedConn := range owned {
				_ = ownedConn.Close()
			}
			for _, pm := range ownedPMs {
				if pm != nil {
					_ = pm.Close()
				}
			}
			return nil, nil, nil, err
		}
		externalDirectUDPPreviewTransportCaps(conn, externalDirectUDPTransportLabel)
		pm := newBoundPublicPortmap(conn, emitter)
		conns = append(conns, conn)
		portmaps = append(portmaps, pm)
		owned = append(owned, conn)
		if pm != nil {
			ownedPMs = append(ownedPMs, pm)
		}
	}
	cleanup := func() {
		for _, pm := range ownedPMs {
			_ = pm.Close()
		}
		for _, conn := range owned {
			_ = conn.Close()
		}
	}
	return conns, portmaps, cleanup, nil
}

func externalAcceptedDirectUDPSet(baseConn net.PacketConn, basePM publicPortmap, emitter *telemetry.Emitter) (net.PacketConn, []net.PacketConn, []publicPortmap, func(), error) {
	if baseConn == nil {
		probeConns, portmaps, cleanup, err := externalDirectUDPConnsFn(nil, nil, externalDirectUDPParallelism, emitter)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if len(probeConns) == 0 || len(portmaps) == 0 {
			cleanup()
			return nil, nil, nil, nil, errors.New("direct UDP acceptor sockets unavailable")
		}
		return probeConns[0], probeConns, portmaps, cleanup, nil
	}

	extraParallel := externalDirectUDPParallelism - 1
	probeConns := []net.PacketConn{baseConn}
	portmaps := []publicPortmap{basePM}
	cleanup := func() {}
	if extraParallel <= 0 {
		return baseConn, probeConns, portmaps, cleanup, nil
	}

	extraConns, extraPMs, extraCleanup, err := externalDirectUDPConnsFn(nil, nil, extraParallel, emitter)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(extraConns) == 0 {
		extraCleanup()
		return nil, nil, nil, nil, errors.New("direct UDP acceptor sockets unavailable")
	}
	probeConns = append(probeConns, extraConns...)
	portmaps = append(portmaps, extraPMs...)
	cleanup = extraCleanup
	return baseConn, probeConns, portmaps, cleanup, nil
}

func externalDirectUDPFlattenCandidateSets(sets [][]string) []string {
	out := make([]string, 0, rendezvous.MaxClaimCandidates)
	seen := make(map[string]bool)
	add := func(candidate string) bool {
		if candidate == "" || seen[candidate] {
			return false
		}
		out = append(out, candidate)
		seen[candidate] = true
		return len(out) == rendezvous.MaxClaimCandidates
	}
	for depth := 0; ; depth++ {
		progressed := false
		for _, candidates := range sets {
			if depth >= len(candidates) {
				continue
			}
			progressed = true
			if add(candidates[depth]) {
				return out
			}
		}
		if !progressed {
			return out
		}
	}
}

func externalDirectUDPCandidateSets(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap) [][]string {
	sets := externalDirectUDPCandidateSetsWithTimeout(ctx, conns, dm, portmaps, externalDirectUDPCandidateGatherWait)
	if fakeTransportEnabled() || externalDirectUDPHasGlobalCandidate(sets) {
		return externalDirectUDPInferWANPerPort(sets)
	}
	if len(conns) == 0 || conns[0] == nil {
		return externalDirectUDPInferWANPerPort(sets)
	}
	var pm publicPortmap
	if len(portmaps) > 0 {
		pm = portmaps[0]
	}
	retryCtx, cancel := context.WithTimeout(ctx, externalPublicCandidateRefreshWait)
	defer cancel()
	confirmed := externalDirectUDPProbeCandidates(retryCtx, conns[0], dm, pm)
	if len(confirmed) > 0 {
		sets[0] = externalDirectUDPOrderCandidateStrings(confirmed)
	}
	return externalDirectUDPInferWANPerPort(sets)
}

func externalDirectUDPCandidateSetsWithTimeout(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap, wait time.Duration) [][]string {
	sets := make([][]string, len(conns))
	var wg sync.WaitGroup
	wg.Add(len(conns))
	for i := range conns {
		go func() {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, wait)
			defer cancel()
			var pm publicPortmap
			if i < len(portmaps) {
				pm = portmaps[i]
			}
			sets[i] = externalDirectUDPOrderCandidateStrings(externalDirectUDPProbeCandidates(probeCtx, conns[i], dm, pm))
		}()
	}
	wg.Wait()
	return sets
}

func externalDirectUDPOrderCandidateStrings(candidates []string) []string {
	if fakeTransportEnabled() {
		return externalDirectUDPPreferLoopbackStrings(candidates)
	}
	return externalDirectUDPPreferWANStrings(candidates)
}

func externalDirectUDPHasGlobalCandidate(sets [][]string) bool {
	for _, candidates := range sets {
		for _, candidate := range candidates {
			if externalDirectUDPCandidateRank(candidate) == 0 {
				return true
			}
		}
	}
	return false
}

func externalDirectUDPInferWANPerPort(sets [][]string) [][]string {
	var wan netip.Addr
	for _, candidates := range sets {
		for _, candidate := range candidates {
			addrPort, err := netip.ParseAddrPort(candidate)
			if err != nil {
				continue
			}
			if externalDirectUDPCandidateRank(candidate) == 0 {
				wan = addrPort.Addr()
				break
			}
		}
		if wan.IsValid() {
			break
		}
	}
	if !wan.IsValid() {
		return sets
	}
	out := make([][]string, len(sets))
	for i, candidates := range sets {
		out[i] = append([]string(nil), candidates...)
		hasWAN := false
		var port uint16
		for _, candidate := range candidates {
			addrPort, err := netip.ParseAddrPort(candidate)
			if err != nil {
				continue
			}
			if externalDirectUDPCandidateRank(candidate) == 0 {
				hasWAN = true
				break
			}
			if port == 0 && addrPort.Addr().IsPrivate() {
				port = addrPort.Port()
			}
		}
		if hasWAN || port == 0 {
			continue
		}
		inferred := netip.AddrPortFrom(wan, port).String()
		out[i] = append([]string{inferred}, out[i]...)
	}
	return out
}

func externalDirectUDPStartPunching(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr) {
	if len(remoteCandidates) == 0 {
		return
	}
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		go probe.PunchAddrs(ctx, conn, remoteCandidates, nil, 0)
	}
}

func externalDirectUDPSelectRemoteAddrs(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr, peer net.Addr, emitter *telemetry.Emitter) []string {
	fallback := externalDirectUDPParallelCandidateStringsForPeer(remoteCandidates, len(conns), peer)
	if fakeTransportEnabled() {
		return fallback
	}
	if emitter != nil {
		emitter.Debug("udp-remote-fallback-addrs=" + strings.Join(fallback, ","))
	}
	fallback = externalDirectUDPFilterFallbackAddrsForSelectedScope(nil, fallback)
	if emitter != nil {
		emitter.Debug("udp-filtered-fallback-addrs=" + strings.Join(fallback, ","))
	}
	observedByConn := externalDirectUDPObservePunchAddrsByConn(ctx, conns, externalDirectUDPPunchWait)
	if emitter != nil {
		emitter.Debug("udp-observed-addrs-by-conn=" + externalDirectUDPFormatObservedAddrsByConn(observedByConn))
	}
	selected := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, len(conns), nil)
	if emitter != nil {
		emitter.Debug("udp-selected-addrs=" + strings.Join(selected, ","))
	}
	if externalDirectUDPSelectedAddrCount(selected) == 0 && peer == nil {
		if emitter != nil {
			emitter.Debug("udp-final-addrs=" + strings.Join(selected, ","))
		}
		return selected
	}
	final := externalDirectUDPFillMissingSelectedAddrs(selected, fallback)
	if emitter != nil {
		emitter.Debug("udp-final-addrs=" + strings.Join(final, ","))
	}
	return final
}

func externalDirectUDPFormatObservedAddrsByConn(observedByConn [][]net.Addr) string {
	parts := make([]string, 0, len(observedByConn))
	for i, observed := range observedByConn {
		parts = append(parts, strconv.Itoa(i)+"="+strings.Join(externalDirectUDPParallelCandidateStrings(observed, len(observed)), "|"))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPSelectRemoteAddrsByConn(observedByConn [][]net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = len(observedByConn)
	}
	out := make([]string, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	selectCandidate := func(i int, candidate string) bool {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			return false
		}
		out[i] = candidate
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		return true
	}
	for i := 0; i < parallel && i < len(observedByConn); i++ {
		for _, candidate := range externalDirectUDPParallelCandidateStringsForPeer(observedByConn[i], len(observedByConn[i]), peer) {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	return out
}

func externalDirectUDPSelectedAddrCount(addrs []string) int {
	count := 0
	for _, addr := range addrs {
		if addr != "" {
			count++
		}
	}
	return count
}

func externalDirectUDPFillMissingSelectedAddrs(selected []string, fallback []string) []string {
	if externalDirectUDPSelectedAddrCount(selected) == len(selected) {
		return selected
	}
	fallback = externalDirectUDPFilterFallbackAddrsForSelectedScope(selected, fallback)
	if externalDirectUDPSelectedAddrCount(selected) == 0 {
		return externalDirectUDPDedupeAndFill(make([]string, len(selected)), fallback)
	}
	return externalDirectUDPDedupeAndFill(selected, fallback)
}

func externalDirectUDPFilterFallbackAddrsForSelectedScope(selected []string, fallback []string) []string {
	selectedRank := externalDirectUDPBestCandidateRank(selected)
	if selectedRank == -1 {
		selectedRank = externalDirectUDPBestCandidateRank(fallback)
		if selectedRank == -1 {
			return fallback
		}
	}

	filtered := make([]string, 0, len(fallback))
	for _, candidate := range fallback {
		if candidate == "" || externalDirectUDPCandidateRank(candidate) != selectedRank {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func externalDirectUDPBestCandidateRank(candidates []string) int {
	bestRank := -1
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		rank := externalDirectUDPCandidateRank(candidate)
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
		}
	}
	return bestRank
}

func externalDirectUDPParallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	return externalDirectUDPParallelCandidateStringsForPeer(candidates, parallel, nil)
}

func externalDirectUDPParallelCandidateStringsForPeer(candidates []net.Addr, parallel int, peer net.Addr) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := probe.CandidateStringsInOrder(candidates)
	if peerAddr, ok := externalDirectUDPAddrPort(peer); ok {
		peerCandidate := peerAddr.String()
		if !slices.Contains(ordered, peerCandidate) {
			ordered = append(ordered, peerCandidate)
		}
	}
	if fakeTransportEnabled() {
		ordered = externalDirectUDPPreferLoopbackStrings(ordered)
	} else {
		ordered = externalDirectUDPPreferPeerAddrStrings(ordered, peer)
	}
	out := make([]string, 0, parallel)
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	for _, candidate := range ordered {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		if len(out) == parallel {
			return out
		}
	}
	for _, candidate := range ordered {
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) == parallel {
			return out
		}
	}
	return out
}

func externalDirectUDPPreferPeerAddrStrings(candidates []string, peer net.Addr) []string {
	out := externalDirectUDPPreferWANStrings(candidates)
	peerAddr, ok := externalDirectUDPAddrPort(peer)
	if !ok {
		return out
	}
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromotePeerCandidate(candidate, out[j], peerAddr.Addr()) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromotePeerCandidate(candidate string, existing string, peer netip.Addr) bool {
	candidatePeer := externalDirectUDPMatchesPeerAddr(candidate, peer)
	existingPeer := externalDirectUDPMatchesPeerAddr(existing, peer)
	if candidatePeer != existingPeer {
		return candidatePeer
	}
	return candidatePeer && externalDirectUDPShouldPromoteCandidate(candidate, existing)
}

func externalDirectUDPMatchesPeerAddr(candidate string, peer netip.Addr) bool {
	candidateAddr, err := netip.ParseAddrPort(candidate)
	return err == nil && candidateAddr.Addr() == peer
}

func externalDirectUDPAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalDirectUDPPreferLoopbackStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteLoopbackCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteLoopbackCandidate(candidate string, existing string) bool {
	candidateLoopback := externalDirectUDPCandidateRank(candidate) == 5
	existingLoopback := externalDirectUDPCandidateRank(existing) == 5
	if candidateLoopback != existingLoopback {
		return candidateLoopback
	}
	if candidateLoopback {
		return externalDirectUDPShouldPromoteCandidate(candidate, existing)
	}
	return false
}

func externalDirectUDPPreferWANStrings(candidates []string) []string {
	out := append([]string(nil), candidates...)
	for i := 1; i < len(out); i++ {
		candidate := out[i]
		j := i - 1
		for j >= 0 && externalDirectUDPShouldPromoteCandidate(candidate, out[j]) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = candidate
	}
	return out
}

func externalDirectUDPShouldPromoteCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return externalDirectUDPEndpointKey(candidate) == externalDirectUDPEndpointKey(existing) && externalDirectUDPBetterCandidate(candidate, existing)
}

func externalDirectUDPBetterCandidate(candidate string, existing string) bool {
	candidateRank := externalDirectUDPCandidateRank(candidate)
	existingRank := externalDirectUDPCandidateRank(existing)
	if candidateRank != existingRank {
		return candidateRank < existingRank
	}
	return candidate < existing
}

func externalDirectUDPCandidateRank(candidate string) int {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return 6
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		return 6
	}
	if addr.IsLoopback() {
		return 5
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return 4
	}
	if publicProbeTailscaleCGNATPrefix.Contains(addr) || publicProbeTailscaleULAPrefix.Contains(addr) {
		return 3
	}
	if addr.IsPrivate() {
		return 2
	}
	if addr.IsGlobalUnicast() {
		return 0
	}
	return 1
}

func externalDirectUDPEndpointKey(candidate string) string {
	_, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return candidate
	}
	return port
}

func externalDirectUDPDedupeAndFill(selected []string, fallback []string) []string {
	out := append([]string(nil), selected...)
	seenEndpoint := make(map[string]int)
	for i, candidate := range out {
		if candidate == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if existingIndex, ok := seenEndpoint[endpoint]; ok {
			if externalDirectUDPBetterCandidate(candidate, out[existingIndex]) {
				out[existingIndex] = ""
				seenEndpoint[endpoint] = i
				continue
			}
			out[i] = ""
			continue
		}
		seenEndpoint[endpoint] = i
	}
	for i, candidate := range out {
		if candidate != "" {
			continue
		}
		for _, replacement := range externalDirectUDPPreferWANStrings(fallback) {
			endpoint := externalDirectUDPEndpointKey(replacement)
			if replacement == "" {
				continue
			}
			if _, ok := seenEndpoint[endpoint]; ok {
				continue
			}
			out[i] = replacement
			seenEndpoint[endpoint] = i
			break
		}
	}
	return out
}

func externalDirectUDPPairs(conns []net.PacketConn, remoteAddrs []string) ([]net.PacketConn, []string) {
	limit := len(conns)
	if len(remoteAddrs) < limit {
		limit = len(remoteAddrs)
	}
	outConns := make([]net.PacketConn, 0, limit)
	outAddrs := make([]string, 0, limit)
	seenEndpoint := make(map[string]bool)
	for i := 0; i < limit; i++ {
		if conns[i] == nil || remoteAddrs[i] == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(remoteAddrs[i])
		if seenEndpoint[endpoint] {
			continue
		}
		seenEndpoint[endpoint] = true
		outConns = append(outConns, conns[i])
		outAddrs = append(outAddrs, remoteAddrs[i])
	}
	return outConns, outAddrs
}

func externalDirectUDPRateProbeRates(maxRateMbps int, totalBytes int64) []int {
	if maxRateMbps <= 0 {
		return nil
	}
	if totalBytes >= 0 && totalBytes < externalDirectUDPRateProbeMinBytes {
		return nil
	}
	probeMaxMbps := maxRateMbps
	if probeMaxMbps > externalDirectUDPRateProbeDefaultMaxMbps {
		probeMaxMbps = externalDirectUDPRateProbeDefaultMaxMbps
	}
	bases := []int{8, 25, 75, 150, 350, 700, 1000, 1200, 1800, 2000, 2250}
	out := make([]int, 0, len(bases))
	seen := make(map[int]bool)
	for _, rate := range bases {
		if rate < externalDirectUDPRateProbeMinMbps || rate > probeMaxMbps || seen[rate] {
			continue
		}
		out = append(out, rate)
		seen[rate] = true
	}
	if probeMaxMbps >= externalDirectUDPRateProbeMinMbps && !seen[probeMaxMbps] {
		out = append(out, probeMaxMbps)
		seen[probeMaxMbps] = true
	}
	if len(out) == 0 {
		out = append(out, probeMaxMbps)
	}
	return out
}

func externalDirectUDPStreamStart(maxRateMbps int, totalBytes int64) directUDPStart {
	start := directUDPStart{
		Stream:        true,
		ExpectedBytes: 0,
		ProbeRates:    externalDirectUDPRateProbeRates(maxRateMbps, totalBytes),
	}
	if totalBytes > 0 {
		start.ExpectedBytes = totalBytes
	}
	return start
}

func externalDirectUDPRemainingExpectedBytes(totalBytes int64, alreadyDelivered int64) int64 {
	if totalBytes <= 0 {
		return -1
	}
	if alreadyDelivered < 0 {
		alreadyDelivered = 0
	}
	if alreadyDelivered >= totalBytes {
		return 0
	}
	return totalBytes - alreadyDelivered
}

func newExternalDirectUDPRateProbeAuth(tok token.Token) (externalDirectUDPRateProbeAuth, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return externalDirectUDPRateProbeAuth{}, "", err
	}
	auth := externalDirectUDPRateProbeAuthForToken(tok, nonce)
	return auth, base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func externalDirectUDPRateProbeAuthForToken(tok token.Token, nonce [16]byte) externalDirectUDPRateProbeAuth {
	return externalDirectUDPRateProbeAuth{
		Key:   externalSessionSubkey(tok, "derphole-direct-udp-rate-probe-v1"),
		Nonce: nonce,
	}
}

func externalDirectUDPRateProbeAuthFromStart(tok token.Token, start directUDPStart) (externalDirectUDPRateProbeAuth, error) {
	if len(start.ProbeRates) == 0 {
		return externalDirectUDPRateProbeAuth{}, nil
	}
	if start.ProbeNonce == "" {
		return externalDirectUDPRateProbeAuth{}, errors.New("direct UDP rate probe nonce missing")
	}
	raw, err := base64.RawURLEncoding.DecodeString(start.ProbeNonce)
	if err != nil {
		return externalDirectUDPRateProbeAuth{}, err
	}
	if len(raw) != 16 {
		return externalDirectUDPRateProbeAuth{}, fmt.Errorf("direct UDP rate probe nonce length %d", len(raw))
	}
	var nonce [16]byte
	copy(nonce[:], raw)
	return externalDirectUDPRateProbeAuthForToken(tok, nonce), nil
}

func externalDirectUDPRateProbePayload(index int, size int, auth externalDirectUDPRateProbeAuth) ([]byte, error) {
	if index < 0 {
		return nil, fmt.Errorf("negative rate probe index %d", index)
	}
	if !auth.enabled() {
		return nil, errors.New("rate probe auth missing")
	}
	if size < externalDirectUDPRateProbeHeaderSize {
		size = externalDirectUDPRateProbeHeaderSize
	}
	payload := make([]byte, size)
	copy(payload[:externalDirectUDPRateProbeIndexOffset], externalDirectUDPRateProbeMagic[:])
	binary.BigEndian.PutUint32(payload[externalDirectUDPRateProbeIndexOffset:externalDirectUDPRateProbeNonceOffset], uint32(index))
	copy(payload[externalDirectUDPRateProbeNonceOffset:externalDirectUDPRateProbeMACOffset], auth.Nonce[:])
	copy(payload[externalDirectUDPRateProbeMACOffset:externalDirectUDPRateProbeHeaderSize], externalDirectUDPRateProbeMAC(auth, payload))
	return payload, nil
}

func externalDirectUDPRateProbeMAC(auth externalDirectUDPRateProbeAuth, packet []byte) []byte {
	mac := hmac.New(sha256.New, auth.Key[:])
	mac.Write(packet[:externalDirectUDPRateProbeMACOffset])
	if len(packet) > externalDirectUDPRateProbeHeaderSize {
		mac.Write(packet[externalDirectUDPRateProbeHeaderSize:])
	}
	return mac.Sum(nil)
}

func externalDirectUDPSendRateProbes(ctx context.Context, conn net.PacketConn, remoteAddr string, rates []int, auth externalDirectUDPRateProbeAuth) ([]directUDPRateProbeSample, error) {
	return externalDirectUDPSendRateProbesParallel(ctx, []net.PacketConn{conn}, []string{remoteAddr}, rates, auth)
}

func externalDirectUDPSendRateProbesParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, rates []int, auth externalDirectUDPRateProbeAuth) ([]directUDPRateProbeSample, error) {
	if len(rates) == 0 {
		return nil, nil
	}
	if !auth.enabled() {
		return nil, errors.New("rate probe auth missing")
	}
	if len(conns) == 0 {
		return nil, errors.New("no rate probe conns")
	}
	if len(conns) != len(remoteAddrs) {
		return nil, errors.New("rate probe conns and addrs length mismatch")
	}
	remotes := make([]*net.UDPAddr, len(remoteAddrs))
	for i, conn := range conns {
		if conn == nil {
			return nil, errors.New("nil rate probe conn")
		}
		if remoteAddrs[i] == "" {
			return nil, errors.New("empty rate probe remote addr")
		}
		remote, err := net.ResolveUDPAddr("udp", remoteAddrs[i])
		if err != nil {
			return nil, err
		}
		remotes[i] = remote
	}
	samples := make([]directUDPRateProbeSample, len(rates))
	for i, rate := range rates {
		if rate <= 0 {
			return nil, fmt.Errorf("invalid rate probe rate %d", rate)
		}
		payload, err := externalDirectUDPRateProbePayload(i, externalDirectUDPChunkSize, auth)
		if err != nil {
			return samples, err
		}
		samples[i].RateMbps = rate
		duration := externalDirectUDPRateProbeDurationForRate(rate)
		samples[i].DurationMillis = duration.Milliseconds()
		tierStart := time.Now()
		deadline := tierStart.Add(duration)
		activeLanes := externalDirectUDPRateProbeActiveLanes(rate, len(conns))
		laneRate := externalDirectUDPPerLaneRateMbps(rate, activeLanes)
		sentByLane := make([]int64, len(conns))
		errCh := make(chan error, activeLanes)
		tierCtx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		for lane := 0; lane < activeLanes; lane++ {
			wg.Add(1)
			go func(lane int) {
				defer wg.Done()
				var sent int64
				defer func() {
					sentByLane[lane] = sent
				}()
				for time.Now().Before(deadline) {
					if err := tierCtx.Err(); err != nil {
						if errors.Is(err, context.Canceled) && ctx.Err() == nil {
							return
						}
						errCh <- err
						return
					}
					n, err := conns[lane].WriteTo(payload, remotes[lane])
					if err != nil {
						if errors.Is(err, syscall.ENOBUFS) {
							if err := sleepWithContext(tierCtx, 250*time.Microsecond); err != nil {
								if errors.Is(err, context.Canceled) && ctx.Err() == nil {
									return
								}
								errCh <- err
								cancel()
								return
							}
							continue
						}
						errCh <- err
						cancel()
						return
					}
					sent += int64(n)
					elapsed := time.Since(tierStart)
					target := int64(float64(laneRate*1000*1000)/8.0*elapsed.Seconds() + 0.5)
					if sent <= target {
						continue
					}
					sleepFor := time.Duration(float64(sent-target) * 8.0 / float64(laneRate*1000*1000) * float64(time.Second))
					if sleepFor <= 0 {
						continue
					}
					if untilDeadline := time.Until(deadline); sleepFor > untilDeadline {
						sleepFor = untilDeadline
					}
					if err := sleepWithContext(tierCtx, sleepFor); err != nil {
						if errors.Is(err, context.Canceled) && ctx.Err() == nil {
							return
						}
						errCh <- err
						cancel()
						return
					}
				}
			}(lane)
		}
		wg.Wait()
		cancel()
		select {
		case err := <-errCh:
			return samples, err
		default:
		}
		var sent int64
		for _, laneSent := range sentByLane {
			sent += laneSent
		}
		samples[i].BytesSent = sent
		if i > 0 && i+1 < len(rates) && externalDirectUDPRateProbeShouldStopAfterSent(samples[i-1], samples[i]) {
			return samples[:i+1], nil
		}
	}
	return samples, nil
}

func externalDirectUDPRateProbeActiveLanes(rateMbps int, maxLanes int) int {
	if maxLanes <= 0 {
		return 0
	}
	switch {
	case rateMbps <= externalDirectUDPActiveLaneOneMaxMbps:
		if maxLanes < 1 {
			return maxLanes
		}
		return 1
	case rateMbps <= externalDirectUDPActiveLaneTwoMaxMbps:
		if maxLanes < 2 {
			return maxLanes
		}
		return 2
	case rateMbps <= externalDirectUDPDataStartHighMbps:
		if maxLanes < 4 {
			return maxLanes
		}
		return 4
	default:
		return maxLanes
	}
}

func externalDirectUDPRateProbeShouldStopAfterSent(prev directUDPRateProbeSample, current directUDPRateProbeSample) bool {
	return false
}

func externalDirectUDPRateProbeDurationForRate(rateMbps int) time.Duration {
	if rateMbps >= 1800 {
		return externalDirectUDPRateProbeHighDuration
	}
	return externalDirectUDPRateProbeDuration
}

func externalDirectUDPRateProbeWindow(rates []int) time.Duration {
	var window time.Duration
	for _, rate := range rates {
		window += externalDirectUDPRateProbeDurationForRate(rate)
	}
	return window
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func externalDirectUDPReceiveRateProbes(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, rates []int, auth externalDirectUDPRateProbeAuth) ([]directUDPRateProbeSample, error) {
	if len(rates) == 0 {
		return nil, nil
	}
	if !auth.enabled() {
		return nil, errors.New("rate probe auth missing")
	}
	samples := make([]directUDPRateProbeSample, len(rates))
	for i, rate := range rates {
		samples[i] = directUDPRateProbeSample{
			RateMbps:       rate,
			DurationMillis: externalDirectUDPRateProbeDurationForRate(rate).Milliseconds(),
		}
	}
	if len(conns) == 0 {
		return samples, errors.New("no packet conns")
	}
	allowedSources, err := externalDirectUDPRateProbeAllowedSources(remoteAddrs)
	if err != nil {
		return samples, err
	}
	deadline := time.Now().Add(externalDirectUDPRateProbeWindow(rates) + externalDirectUDPRateProbeGrace)
	var mu sync.Mutex
	errCh := make(chan error, len(conns))
	var wg sync.WaitGroup
	for _, conn := range conns {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return samples, err
		}
		wg.Add(1)
		go func(conn net.PacketConn) {
			defer wg.Done()
			defer conn.SetReadDeadline(time.Time{})
			buf := make([]byte, externalDirectUDPChunkSize)
			for {
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if externalDirectUDPIsNetTimeout(err) {
						return
					}
					if ctx.Err() != nil {
						errCh <- ctx.Err()
						return
					}
					errCh <- err
					return
				}
				if !externalDirectUDPRateProbeSourceAllowed(addr, allowedSources) {
					continue
				}
				index, ok := externalDirectUDPRateProbeIndex(buf[:n], len(samples), auth)
				if !ok {
					continue
				}
				mu.Lock()
				samples[index].BytesReceived += int64(n)
				mu.Unlock()
			}
		}(conn)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return samples, err
	default:
	}
	return samples, nil
}

func externalDirectUDPRateProbeAllowedSources(remoteAddrs []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(remoteAddrs))
	for _, raw := range remoteAddrs {
		if raw == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", raw)
		if err != nil {
			return nil, err
		}
		allowed[addr.String()] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no rate probe remote addrs")
	}
	return allowed, nil
}

func externalDirectUDPRateProbeSourceAllowed(addr net.Addr, allowed map[string]struct{}) bool {
	if addr == nil || len(allowed) == 0 {
		return false
	}
	_, ok := allowed[addr.String()]
	return ok
}

func externalDirectUDPRateProbeIndex(packet []byte, samples int, auth externalDirectUDPRateProbeAuth) (int, bool) {
	if len(packet) < externalDirectUDPRateProbeHeaderSize || samples <= 0 || !auth.enabled() {
		return 0, false
	}
	if string(packet[:externalDirectUDPRateProbeIndexOffset]) != string(externalDirectUDPRateProbeMagic[:]) {
		return 0, false
	}
	if !hmac.Equal(packet[externalDirectUDPRateProbeNonceOffset:externalDirectUDPRateProbeMACOffset], auth.Nonce[:]) {
		return 0, false
	}
	wantMAC := externalDirectUDPRateProbeMAC(auth, packet)
	if !hmac.Equal(packet[externalDirectUDPRateProbeMACOffset:externalDirectUDPRateProbeHeaderSize], wantMAC) {
		return 0, false
	}
	index := int(binary.BigEndian.Uint32(packet[externalDirectUDPRateProbeIndexOffset:externalDirectUDPRateProbeNonceOffset]))
	if index < 0 || index >= samples {
		return 0, false
	}
	return index, true
}

func externalDirectUDPIsNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func externalDirectUDPSelectRateFromProbeSamples(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if maxRateMbps <= 0 || len(sent) == 0 || len(received) == 0 {
		return 0
	}
	if !externalDirectUDPHasPositiveProbeProgress(received) {
		return 0
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	type candidate struct {
		rate     int
		goodput  float64
		delivery float64
		score    float64
	}
	candidates := make([]candidate, 0, len(received))
	bestRate := 0
	bestGoodput := 0.0
	bestScore := 0.0
	bestDelivery := 0.0
	for _, sample := range received {
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		delivery := 0.0
		if sentSample, ok := sentByRate[sample.RateMbps]; ok && sentSample.BytesSent > 0 {
			delivery = float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		}
		score := goodput
		if delivery > 0 && delivery < 0.90 {
			score *= delivery / 0.90
		}
		candidates = append(candidates, candidate{
			rate:     sample.RateMbps,
			goodput:  goodput,
			delivery: delivery,
			score:    score,
		})
		if score <= bestScore {
			continue
		}
		bestScore = score
		bestGoodput = goodput
		bestRate = sample.RateMbps
		bestDelivery = delivery
	}
	if bestRate <= 0 || bestGoodput <= 0 {
		return maxRateMbps
	}
	trimmedLeadingZeroCandidates := false
	for len(candidates) > 0 && candidates[0].goodput <= 0 && candidates[0].delivery <= 0 {
		trimmedLeadingZeroCandidates = true
		candidates = candidates[1:]
	}
	if len(candidates) == 0 {
		return 0
	}
	capSenderLimitedProbeRate := func(rate int) int {
		if rate < externalDirectUDPRateProbeCollapseMinMbps {
			return rate
		}
		var selected candidate
		selectedOK := false
		var previous candidate
		previousOK := false
		bestEfficient := candidate{}
		bestEfficientOK := false
		for _, probe := range candidates {
			if probe.rate == rate {
				selected = probe
				selectedOK = true
			}
			if probe.rate > rate {
				break
			}
			if probe.rate < rate {
				previous = probe
				previousOK = true
			}
			efficiency := 0.0
			if probe.rate > 0 {
				efficiency = probe.goodput / float64(probe.rate)
			}
			if probe.delivery >= externalDirectUDPRateProbeClean && efficiency >= externalDirectUDPRateProbeEfficient && (!bestEfficientOK || probe.goodput > bestEfficient.goodput) {
				bestEfficient = probe
				bestEfficientOK = true
			}
		}
		if !selectedOK || !bestEfficientOK || bestEfficient.rate >= rate {
			return rate
		}
		selectedEfficiency := 0.0
		if selected.rate > 0 {
			selectedEfficiency = selected.goodput / float64(selected.rate)
		}
		if selected.delivery < externalDirectUDPRateProbeClean || selectedEfficiency >= externalDirectUDPRateProbeEfficient {
			return rate
		}
		if previousOK && previous.goodput > 0 && selected.goodput >= previous.goodput*externalDirectUDPRateProbeModerateGain {
			return rate
		}
		if selected.goodput >= bestEfficient.goodput*externalDirectUDPRateProbeMaterialGain {
			return rate
		}
		return bestEfficient.rate
	}
	if trimmedLeadingZeroCandidates && len(candidates) >= 2 && candidates[0].goodput > 0 && candidates[0].rate < externalDirectUDPRateProbeCollapseMinMbps {
		base := candidates[0]
		for i := 1; i < len(candidates); i++ {
			current := candidates[i]
			if current.rate < externalDirectUDPRateProbeCollapseMinMbps {
				continue
			}
			if current.delivery < externalDirectUDPRateProbeLossyDelivery {
				continue
			}
			if current.goodput < base.goodput*externalDirectUDPRateProbeMaterialGain {
				continue
			}
			return capSenderLimitedProbeRate(current.rate)
		}
	}
	highestProbeRate := candidates[len(candidates)-1].rate
	for i := 1; i < len(candidates); i++ {
		prev := candidates[i-1]
		current := candidates[i]
		efficiency := 0.0
		if current.rate > 0 {
			efficiency = current.goodput / float64(current.rate)
		}
		prevEfficiency := 0.0
		if prev.rate > 0 {
			prevEfficiency = prev.goodput / float64(prev.rate)
		}
		topProbe := i == len(candidates)-1 || current.rate == maxRateMbps
		topProbeCleanGain := topProbe && current.delivery >= externalDirectUDPRateProbeClean && current.goodput > prev.goodput && current.goodput >= bestGoodput
		if topProbeCleanGain {
			selected := int(current.goodput*1.15 + 0.5)
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		highThroughputKnee := current.delivery >= externalDirectUDPRateProbeClean && current.goodput >= float64(maxRateMbps)*externalDirectUDPRateProbeHighShare && current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain
		if current.delivery >= externalDirectUDPRateProbeClean && current.goodput >= prev.goodput*0.75 && (efficiency >= externalDirectUDPRateProbeEfficient || highThroughputKnee) {
			continue
		}
		nearCleanEfficientGain := !topProbe && current.delivery >= externalDirectUDPRateProbeNearClean && current.goodput >= prev.goodput*0.75 && efficiency >= externalDirectUDPRateProbeEfficient
		if nearCleanEfficientGain {
			continue
		}
		cleanSenderLimitedRamp := current.delivery >= externalDirectUDPRateProbeClean &&
			current.goodput >= prev.goodput &&
			(current.goodput < externalDirectUDPRateProbeHighHeadroomMin ||
				prevEfficiency < externalDirectUDPRateProbeEfficient)
		if cleanSenderLimitedRamp {
			continue
		}
		if topProbe && externalDirectUDPHighGoodputCappedTopProbe(maxRateMbps, highestProbeRate, current.rate, current.goodput, current.delivery, prev.goodput) {
			selected := int(current.goodput*1.15 + 0.5)
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > current.rate {
				selected = current.rate
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		midProbeMaterialGain := !topProbe &&
			current.rate < maxRateMbps &&
			(current.delivery >= externalDirectUDPRateProbeClean || current.delivery >= externalDirectUDPRateProbeLossySelect) &&
			current.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			current.goodput >= prev.goodput*externalDirectUDPRateProbeMaterialGain
		if midProbeMaterialGain {
			selected := current.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		midProbeModerateGain := !topProbe &&
			current.rate < maxRateMbps &&
			current.delivery >= externalDirectUDPRateProbeCeilingDelivery &&
			current.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			current.goodput >= prev.goodput*externalDirectUDPRateProbeModerateGain
		if midProbeModerateGain {
			selected := current.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		cleanSenderLimitedHighTier := !topProbe &&
			prev.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
			current.rate >= externalDirectUDPRateProbeConfirmMinMbps &&
			current.delivery >= externalDirectUDPRateProbeClean &&
			current.goodput >= externalDirectUDPRateProbeHighHeadroomMin
		if cleanSenderLimitedHighTier {
			continue
		}
		topProbeSenderLimitedBelowBest := topProbe &&
			current.delivery >= externalDirectUDPRateProbeClean &&
			bestRate > 0 &&
			bestRate < current.rate &&
			bestGoodput > prev.goodput*1.10 &&
			bestGoodput > current.goodput*1.10
		if topProbeSenderLimitedBelowBest {
			selected := bestRate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		midProbeSoftLoss := current.rate < maxRateMbps &&
			current.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
			current.delivery >= 0.70 &&
			current.delivery < externalDirectUDPRateProbeClean &&
			current.goodput >= prev.goodput
		if midProbeSoftLoss {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		cleanMidProbeSenderLimitedGain := current.rate < maxRateMbps &&
			current.rate < externalDirectUDPRateProbeConfirmMinMbps &&
			current.delivery >= externalDirectUDPRateProbeClean &&
			efficiency < externalDirectUDPRateProbeEfficient &&
			prev.rate >= externalDirectUDPActiveLaneTwoMaxMbps &&
			prevEfficiency >= externalDirectUDPRateProbeEfficient &&
			current.goodput >= prev.goodput &&
			current.goodput >= externalDirectUDPRateProbeHighHeadroomMin
		if cleanMidProbeSenderLimitedGain {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		midProbeCollapseAfterCleanTier := current.rate < maxRateMbps &&
			current.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
			prev.delivery >= 0.90 &&
			(current.delivery < externalDirectUDPRateProbeNearClean ||
				current.goodput < prev.goodput*externalDirectUDPRateProbeSentGrowth)
		if midProbeCollapseAfterCleanTier {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		topProbeCleanCollapseAfterMaterialGain := topProbe &&
			i >= 2 &&
			current.delivery >= externalDirectUDPRateProbeClean &&
			prev.delivery >= externalDirectUDPRateProbeClean &&
			current.goodput < prev.goodput*externalDirectUDPRateProbeSentGrowth &&
			prev.goodput >= candidates[i-2].goodput*1.10
		if topProbeCleanCollapseAfterMaterialGain {
			selected := prev.rate
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return capSenderLimitedProbeRate(selected)
		}
		topProbeStillGaining := topProbe && current.delivery >= externalDirectUDPRateProbeClean && current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain
		if topProbeStillGaining {
			selected := int(current.goodput*1.15 + 0.5)
			if selected < externalDirectUDPRateProbeMinMbps {
				selected = externalDirectUDPRateProbeMinMbps
			}
			if selected > maxRateMbps {
				selected = maxRateMbps
			}
			return selected
		}
		if !topProbe && current.rate < externalDirectUDPRateProbeCollapseMinMbps {
			continue
		}
		backoffIndex := i - 2
		if backoffIndex < 0 {
			backoffIndex = i - 1
		}
		selected := candidates[backoffIndex].rate
		if backoffIndex >= 0 {
			backoffCandidate := candidates[backoffIndex]
			if backoffCandidate.rate < externalDirectUDPRateProbeCollapseMinMbps &&
				bestRate > 0 &&
				bestRate < backoffCandidate.rate &&
				bestDelivery >= externalDirectUDPRateProbeCeilingDelivery &&
				backoffCandidate.delivery < externalDirectUDPRateProbeCeilingDelivery &&
				backoffCandidate.goodput < bestGoodput*externalDirectUDPRateProbeLossyGain {
				selected = bestRate
			}
		}
		if selected < externalDirectUDPRateProbeMinMbps {
			selected = externalDirectUDPRateProbeMinMbps
		}
		if selected > maxRateMbps {
			selected = maxRateMbps
		}
		return capSenderLimitedProbeRate(selected)
	}
	selected := int(bestGoodput*1.15 + 0.5)
	if bestDelivery >= 0.90 {
		selected = bestRate
	}
	if selected < externalDirectUDPRateProbeMinMbps {
		selected = externalDirectUDPRateProbeMinMbps
	}
	if selected > maxRateMbps {
		selected = maxRateMbps
	}
	return capSenderLimitedProbeRate(selected)
}

func externalDirectUDPSelectInitialRateMbps(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	selected := externalDirectUDPSelectRateFromProbeSamples(maxRateMbps, sent, received)
	if selected <= 0 || selected > maxRateMbps {
		selected = externalDirectUDPInitialProbeFallbackMbps
	}
	if !externalDirectUDPHasPositiveProbeProgress(received) {
		return selected
	}
	return externalDirectUDPAddProbeKneeHeadroom(maxRateMbps, selected, sent, received)
}

func externalDirectUDPSelectRateCeilingMbps(maxRateMbps int, selected int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if maxRateMbps <= 0 {
		return maxRateMbps
	}
	if selected <= 0 {
		selected = externalDirectUDPInitialProbeFallbackMbps
	}
	if selected > maxRateMbps {
		selected = maxRateMbps
	}
	if !externalDirectUDPHasPositiveProbeProgress(received) {
		return selected
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	ceiling := selected
	ceilingGoodput := 0.0
	ceilingDelivery := 0.0
	ceilingEfficiency := 0.0
	highestProbeRate := externalDirectUDPHighestProbeRate(sent, maxRateMbps)
	previousGoodput := 0.0
	selectedGoodput := 0.0
	selectedDelivery := 0.0
	probedPastSelectedHeadroom := false
	rejectedHigherProbe := false
	lossyImprovingCeiling := false
	for _, sample := range received {
		if sample.RateMbps <= 0 || sample.RateMbps > maxRateMbps {
			continue
		}
		sentSample, ok := sentByRate[sample.RateMbps]
		if !ok || sentSample.BytesSent <= 0 {
			continue
		}
		delivery := float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		efficiency := 0.0
		if sample.RateMbps > 0 {
			efficiency = goodput / float64(sample.RateMbps)
		}
		if sample.RateMbps < selected {
			previousGoodput = goodput
			continue
		}
		if sample.RateMbps == selected {
			selectedGoodput = goodput
			selectedDelivery = delivery
		}
		priorGoodput := ceilingGoodput
		if priorGoodput <= 0 {
			priorGoodput = previousGoodput
		}
		cappedTopHighGoodput := externalDirectUDPHighGoodputCappedTopProbe(maxRateMbps, highestProbeRate, sample.RateMbps, goodput, delivery, priorGoodput)
		highThroughputKnee := goodput >= float64(maxRateMbps)*externalDirectUDPRateProbeHighShare && (ceilingGoodput <= 0 || goodput >= ceilingGoodput*externalDirectUDPRateProbeHighGain)
		nearCleanCeiling := ceilingDelivery >= externalDirectUDPRateProbeNearClean && ceilingDelivery < externalDirectUDPRateProbeClean
		highSelectedHeadroom := selected >= externalDirectUDPRateProbeCollapseMinMbps &&
			sample.RateMbps == highestProbeRate &&
			goodput >= externalDirectUDPRateProbeCeilingFloorMin &&
			delivery >= externalDirectUDPRateProbeCeilingDelivery
		meaningfulNextTier := ceilingGoodput >= externalDirectUDPRateProbeCeilingFloorMin && sample.RateMbps > ceiling && goodput >= ceilingGoodput*externalDirectUDPRateProbeCeilingFloor && (delivery >= externalDirectUDPRateProbeCeilingDelivery || nearCleanCeiling || highSelectedHeadroom)
		allowLossyImprovingCeiling := selected < externalDirectUDPCeilingHeadroomMinMbps || (selected >= externalDirectUDPRateProbeCollapseMinMbps && sample.RateMbps == highestProbeRate)
		lossyStillImproving := allowLossyImprovingCeiling && externalDirectUDPLossyProbeStillImproving(sample.RateMbps, goodput, delivery, priorGoodput)
		boundedLossyObservedGoodputCeiling := selected >= externalDirectUDPRateProbeCollapseMinMbps &&
			sample.RateMbps == highestProbeRate &&
			delivery >= externalDirectUDPRateProbeLossyDelivery &&
			delivery < externalDirectUDPRateProbeCeilingDelivery &&
			goodput >= float64(selected)*1.10 &&
			goodput >= priorGoodput*externalDirectUDPRateProbeLossyGain
		selectedLossyGain := selected >= externalDirectUDPRateProbeHighHeadroomMin &&
			sample.RateMbps == selected &&
			delivery >= externalDirectUDPRateProbeLossySelect &&
			goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			goodput >= priorGoodput*externalDirectUDPRateProbeMaterialGain
		if selectedLossyGain {
			ceiling = sample.RateMbps
			ceilingGoodput = goodput
			ceilingDelivery = delivery
			ceilingEfficiency = efficiency
			continue
		}
		if delivery < externalDirectUDPRateProbeClean && !(delivery >= externalDirectUDPRateProbeNearClean && efficiency >= externalDirectUDPRateProbeCeilingEfficient) {
			rejectedHigherProbe = sample.RateMbps > ceiling
			if cappedTopHighGoodput {
				ceiling = sample.RateMbps
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
				break
			}
			if meaningfulNextTier {
				ceiling = sample.RateMbps
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
			}
			if boundedLossyObservedGoodputCeiling {
				ceiling = int(goodput + 0.5)
				ceilingGoodput = goodput
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
				lossyImprovingCeiling = true
			}
			if lossyStillImproving {
				ceiling = sample.RateMbps
				ceilingGoodput = goodput
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
				lossyImprovingCeiling = true
				rejectedHigherProbe = false
				continue
			}
			break
		}
		if delivery < externalDirectUDPRateProbeClean && sample.RateMbps > selected && efficiency < externalDirectUDPRateProbeCeilingEfficient && !highThroughputKnee && ceilingGoodput > 0 && goodput < ceilingGoodput*externalDirectUDPRateProbeSentGrowth {
			rejectedHigherProbe = sample.RateMbps > ceiling
			if cappedTopHighGoodput {
				ceiling = sample.RateMbps
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
				break
			}
			if meaningfulNextTier {
				ceiling = sample.RateMbps
				ceilingDelivery = delivery
				ceilingEfficiency = efficiency
			}
			break
		}
		senderLimitedHeadroomProbe := selected > externalDirectUDPActiveLaneTwoMaxMbps &&
			selected < externalDirectUDPRateProbeConfirmMinMbps &&
			sample.RateMbps > selected &&
			sample.RateMbps >= externalDirectUDPRateProbeCollapseMinMbps &&
			delivery >= externalDirectUDPRateProbeClean &&
			efficiency > 0 &&
			efficiency < externalDirectUDPRateProbeEfficient &&
			ceilingGoodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			goodput < ceilingGoodput*externalDirectUDPRateProbeMaterialGain
		if senderLimitedHeadroomProbe {
			rejectedHigherProbe = sample.RateMbps > ceiling
			break
		}
		cleanHigherThroughputCollapse := selected >= externalDirectUDPRateProbeCollapseMinMbps &&
			sample.RateMbps > selected &&
			delivery >= externalDirectUDPRateProbeClean &&
			efficiency > 0 &&
			efficiency < externalDirectUDPRateProbeEfficient &&
			ceilingGoodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			goodput < ceilingGoodput*externalDirectUDPRateProbeSentGrowth
		if cleanHigherThroughputCollapse {
			rejectedHigherProbe = sample.RateMbps > ceiling
			break
		}
		ceiling = sample.RateMbps
		ceilingGoodput = goodput
		ceilingDelivery = delivery
		ceilingEfficiency = efficiency
		if delivery < externalDirectUDPRateProbeClean && sample.RateMbps > selected && efficiency < externalDirectUDPRateProbeCeilingEfficient && !highThroughputKnee {
			if selected == externalDirectUDPProbeKneeHeadroom(sample.RateMbps) && !probedPastSelectedHeadroom {
				probedPastSelectedHeadroom = true
				continue
			}
			rejectedHigherProbe = sample.RateMbps > ceiling
			break
		}
	}
	if recoveryRate, _, recoveryDelivery, recoveryEfficiency, ok := externalDirectUDPFindLossyRecoveryProbe(selected, selectedGoodput, sentByRate, received); ok && recoveryRate > ceiling {
		ceiling = recoveryRate
		ceilingDelivery = recoveryDelivery
		ceilingEfficiency = recoveryEfficiency
	}
	if explorationRate, _, explorationDelivery, explorationEfficiency, ok := externalDirectUDPFindLossyHighSelectedExplorationCeiling(selected, selectedGoodput, selectedDelivery, sentByRate, received, maxRateMbps); ok && explorationRate > ceiling {
		ceiling = explorationRate
		ceilingDelivery = explorationDelivery
		ceilingEfficiency = explorationEfficiency
		lossyImprovingCeiling = true
	}
	if explorationRate, _, explorationDelivery, explorationEfficiency, ok := externalDirectUDPFindAdaptiveExplorationCeiling(selected, selectedGoodput, sentByRate, received, maxRateMbps); ok && explorationRate > ceiling {
		ceiling = explorationRate
		ceilingDelivery = explorationDelivery
		ceilingEfficiency = explorationEfficiency
		lossyImprovingCeiling = true
	}
	if ceiling == highestProbeRate && highestProbeRate > 0 && highestProbeRate == maxRateMbps && ceilingDelivery >= externalDirectUDPRateProbeClean && ceilingEfficiency >= externalDirectUDPRateProbeEfficient {
		return maxRateMbps
	}
	if selected < externalDirectUDPCeilingHeadroomMinMbps && ceiling > externalDirectUDPRateProbeHighHeadroomMin && rejectedHigherProbe {
		ceiling = externalDirectUDPRateProbeHighHeadroomMin
	}
	if !lossyImprovingCeiling {
		ceiling = externalDirectUDPCapBufferedMediumCeiling(selected, ceiling, ceilingDelivery, ceilingEfficiency)
	}
	if ceiling < selected {
		ceiling = selected
	}
	if ceiling > maxRateMbps {
		ceiling = maxRateMbps
	}
	return ceiling
}

func externalDirectUDPHighGoodputCappedTopProbe(maxRateMbps int, highestProbeRate int, rateMbps int, goodput float64, delivery float64, previousGoodput float64) bool {
	return maxRateMbps > rateMbps &&
		rateMbps == highestProbeRate &&
		rateMbps >= externalDirectUDPRateProbeCollapseMinMbps &&
		delivery >= externalDirectUDPRateProbeCeilingDelivery &&
		previousGoodput > 0 &&
		goodput >= previousGoodput*externalDirectUDPRateProbeHighGain
}

func externalDirectUDPProbeMetrics(sample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) (float64, float64, float64, bool) {
	sentSample, ok := sentByRate[sample.RateMbps]
	if !ok || sentSample.BytesSent <= 0 || sample.RateMbps <= 0 {
		return 0, 0, 0, false
	}
	durationMillis := sample.DurationMillis
	if durationMillis <= 0 {
		durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
	}
	goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
	delivery := float64(sample.BytesReceived) / float64(sentSample.BytesSent)
	efficiency := goodput / float64(sample.RateMbps)
	return goodput, delivery, efficiency, true
}

func externalDirectUDPFindLossyRecoveryProbe(selected int, baseGoodput float64, sentByRate map[int]directUDPRateProbeSample, received []directUDPRateProbeSample) (int, float64, float64, float64, bool) {
	if selected < externalDirectUDPActiveLaneTwoMaxMbps || baseGoodput < externalDirectUDPRateProbeCeilingFloorMin {
		return 0, 0, 0, 0, false
	}
	threshold := baseGoodput * externalDirectUDPRateProbeMaterialGain
	if threshold < externalDirectUDPRateProbeHighHeadroomMin {
		threshold = externalDirectUDPRateProbeHighHeadroomMin
	}
	bestRate := 0
	bestGoodput := 0.0
	bestDelivery := 0.0
	bestEfficiency := 0.0
	for _, sample := range received {
		if sample.RateMbps <= selected {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || delivery < externalDirectUDPRateProbeCeilingDelivery || goodput < threshold {
			continue
		}
		if goodput <= bestGoodput {
			continue
		}
		bestRate = sample.RateMbps
		bestGoodput = goodput
		bestDelivery = delivery
		bestEfficiency = efficiency
	}
	return bestRate, bestGoodput, bestDelivery, bestEfficiency, bestRate > 0
}

func externalDirectUDPHasLossyHigherGoodputProbe(selected int, baseGoodput float64, sentByRate map[int]directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	if selected < externalDirectUDPActiveLaneTwoMaxMbps || baseGoodput < externalDirectUDPRateProbeCeilingFloorMin {
		return false
	}
	threshold := baseGoodput * externalDirectUDPRateProbeMaterialGain
	if threshold < externalDirectUDPRateProbeHighHeadroomMin {
		threshold = externalDirectUDPRateProbeHighHeadroomMin
	}
	for _, sample := range received {
		if sample.RateMbps <= selected {
			continue
		}
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if ok && delivery >= externalDirectUDPRateProbeLossyDelivery && goodput >= threshold {
			return true
		}
	}
	return false
}

func externalDirectUDPFindAdaptiveExplorationCeiling(selected int, baseGoodput float64, sentByRate map[int]directUDPRateProbeSample, received []directUDPRateProbeSample, maxRateMbps int) (int, float64, float64, float64, bool) {
	if selected != externalDirectUDPActiveLaneTwoMaxMbps || baseGoodput < externalDirectUDPRateProbeCeilingFloorMin {
		return 0, 0, 0, 0, false
	}
	threshold := baseGoodput * externalDirectUDPRateProbeLossyGain
	if threshold < externalDirectUDPRateProbeHighHeadroomMin {
		threshold = externalDirectUDPRateProbeHighHeadroomMin
	}
	bestRate := 0
	bestGoodput := 0.0
	bestDelivery := 0.0
	bestEfficiency := 0.0
	highestRate := 0
	highestGoodput := 0.0
	highestDelivery := 0.0
	highestEfficiency := 0.0
	for _, sample := range received {
		if sample.RateMbps <= selected || sample.RateMbps > maxRateMbps {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if ok && sample.RateMbps >= highestRate {
			highestRate = sample.RateMbps
			highestGoodput = goodput
			highestDelivery = delivery
			highestEfficiency = efficiency
		}
		if !ok || delivery < externalDirectUDPRateProbeHeadroomDelivery || goodput < threshold {
			continue
		}
		if goodput < bestGoodput || (goodput == bestGoodput && sample.RateMbps < bestRate) {
			continue
		}
		bestRate = sample.RateMbps
		bestGoodput = goodput
		bestDelivery = delivery
		bestEfficiency = efficiency
	}
	if bestRate > 0 && highestRate > bestRate && highestDelivery >= externalDirectUDPRateProbeHeadroomDelivery && highestGoodput >= bestGoodput*externalDirectUDPRateProbeLossyGain {
		return highestRate, highestGoodput, highestDelivery, highestEfficiency, true
	}
	return bestRate, bestGoodput, bestDelivery, bestEfficiency, bestRate > 0
}

func externalDirectUDPFindLossyHighSelectedExplorationCeiling(selected int, baseGoodput float64, selectedDelivery float64, sentByRate map[int]directUDPRateProbeSample, received []directUDPRateProbeSample, maxRateMbps int) (int, float64, float64, float64, bool) {
	selectedEfficiency := 0.0
	if selected > 0 {
		selectedEfficiency = baseGoodput / float64(selected)
	}
	if selected < externalDirectUDPRateProbeCollapseMinMbps ||
		baseGoodput < externalDirectUDPRateProbeCeilingFloorMin ||
		(selectedDelivery >= externalDirectUDPRateProbeLossySelect && selectedEfficiency > externalDirectUDPRateProbeEfficient) {
		return 0, 0, 0, 0, false
	}
	threshold := baseGoodput * externalDirectUDPRateProbeLossyGain
	if threshold < externalDirectUDPRateProbeHighHeadroomMin {
		threshold = externalDirectUDPRateProbeHighHeadroomMin
	}
	bestRate := 0
	bestGoodput := 0.0
	bestDelivery := 0.0
	bestEfficiency := 0.0
	for _, sample := range received {
		if sample.RateMbps <= selected || sample.RateMbps > maxRateMbps {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || delivery < externalDirectUDPRateProbeLossyDelivery || goodput < threshold {
			continue
		}
		if goodput < bestGoodput || (goodput == bestGoodput && sample.RateMbps > bestRate) {
			continue
		}
		bestRate = sample.RateMbps
		bestGoodput = goodput
		bestDelivery = delivery
		bestEfficiency = efficiency
	}
	return bestRate, bestGoodput, bestDelivery, bestEfficiency, bestRate > 0
}

func externalDirectUDPLossyProbeStillImproving(rateMbps int, goodput float64, delivery float64, previousGoodput float64) bool {
	return rateMbps >= externalDirectUDPRateProbeHighHeadroomMin &&
		goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		delivery >= externalDirectUDPRateProbeCeilingDelivery &&
		previousGoodput > 0 &&
		goodput >= previousGoodput*externalDirectUDPRateProbeLossyGain
}

func externalDirectUDPCapBufferedMediumCeiling(selected int, ceiling int, delivery float64, efficiency float64) int {
	if selected <= 0 || ceiling <= selected || selected >= externalDirectUDPRateProbeHighHeadroomMin {
		return ceiling
	}
	if selected >= externalDirectUDPCeilingHeadroomMinMbps && efficiency > 0 && efficiency < externalDirectUDPRateProbeCeilingEfficient {
		capped := externalDirectUDPRateProbeHighHeadroomMin
		if ceiling > capped {
			return capped
		}
		return ceiling
	}
	if delivery >= externalDirectUDPRateProbeClean {
		return ceiling
	}
	if selected < externalDirectUDPCeilingHeadroomMinMbps && delivery >= externalDirectUDPRateProbeCeilingDelivery {
		return ceiling
	}
	capped := selected * 2
	if selected >= externalDirectUDPDataStartMaxMbps && selected < externalDirectUDPRateProbeHighHeadroomMin {
		capped = externalDirectUDPRateProbeHighHeadroomMin
	}
	if capped < selected {
		return ceiling
	}
	if capped < externalDirectUDPRateProbeMinMbps {
		capped = externalDirectUDPRateProbeMinMbps
	}
	if ceiling > capped {
		return capped
	}
	return ceiling
}

func externalDirectUDPHighestProbeRate(samples []directUDPRateProbeSample, maxRateMbps int) int {
	highest := 0
	for _, sample := range samples {
		if sample.RateMbps <= 0 || sample.RateMbps > maxRateMbps {
			continue
		}
		if sample.RateMbps > highest {
			highest = sample.RateMbps
		}
	}
	return highest
}

func externalDirectUDPAddProbeKneeHeadroom(maxRateMbps int, selected int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if selected <= 0 {
		return selected
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	highestProbeRate := externalDirectUDPHighestProbeRate(received, maxRateMbps)
	prevGoodput := 0.0
	prevBelowSelectedRate := 0
	selectedGoodput := 0.0
	selectedProbeViable := false
	selectedProbeClean := false
	for _, sample := range received {
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		if sample.RateMbps < selected {
			prevBelowSelectedRate = sample.RateMbps
		}
		sentSample, ok := sentByRate[sample.RateMbps]
		sampleMatchesSelectedTier := sample.RateMbps == selected ||
			(selected >= externalDirectUDPRateProbeCollapseMinMbps &&
				sample.RateMbps < selected &&
				sample.RateMbps >= externalDirectUDPRateProbeCollapseMinMbps)
		if ok && sentSample.BytesSent > 0 && sampleMatchesSelectedTier {
			delivery := float64(sample.BytesReceived) / float64(sentSample.BytesSent)
			efficiency := 0.0
			if sample.RateMbps > 0 {
				efficiency = goodput / float64(sample.RateMbps)
			}
			lossySelectedGain := sample.RateMbps >= externalDirectUDPRateProbeCollapseMinMbps &&
				delivery >= externalDirectUDPRateProbeLossyDelivery &&
				goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
				prevGoodput > 0 &&
				goodput >= prevGoodput*externalDirectUDPRateProbeMaterialGain
			selectedGoodput = goodput
			selectedProbeClean = delivery >= externalDirectUDPRateProbeClean
			selectedProbeViable = (delivery >= externalDirectUDPRateProbeNearClean && efficiency >= externalDirectUDPRateProbeEfficient) ||
				(sample.RateMbps >= externalDirectUDPRateProbeHighHeadroomMin &&
					(delivery >= externalDirectUDPRateProbeClean || delivery >= externalDirectUDPRateProbeLossySelect || delivery >= externalDirectUDPRateProbeCeilingDelivery) &&
					goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
					(goodput >= prevGoodput*externalDirectUDPRateProbeMaterialGain || goodput >= prevGoodput*externalDirectUDPRateProbeModerateGain)) ||
				(sample.RateMbps >= externalDirectUDPRateProbeCollapseMinMbps &&
					delivery >= externalDirectUDPRateProbeClean &&
					goodput >= externalDirectUDPRateProbeHighHeadroomMin) ||
				lossySelectedGain
		}
		if sample.RateMbps <= selected {
			prevGoodput = goodput
			continue
		}
		if !ok || sentSample.BytesSent <= 0 {
			continue
		}
		sentGoodput := externalDirectUDPSampleGoodputMbps(sentSample.BytesSent, durationMillis)
		sentEfficiency := 0.0
		if sample.RateMbps > 0 {
			sentEfficiency = sentGoodput / float64(sample.RateMbps)
		}
		delivery := float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		efficiency := 0.0
		if sample.RateMbps > 0 {
			efficiency = goodput / float64(sample.RateMbps)
		}
		highThroughputKnee := maxRateMbps > 0 && goodput >= float64(maxRateMbps)*externalDirectUDPRateProbeHighShare
		if delivery >= externalDirectUDPRateProbeClean {
			if efficiency < externalDirectUDPRateProbeEfficient && !highThroughputKnee {
				if selectedProbeViable &&
					selected >= externalDirectUDPRateProbeCollapseMinMbps &&
					sample.RateMbps > selected &&
					goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
					sentEfficiency < externalDirectUDPRateProbeEfficient {
					return selected
				}
				if selectedProbeViable && selected >= externalDirectUDPRateProbeCollapseMinMbps && sample.RateMbps == highestProbeRate && goodput <= prevGoodput {
					return selected
				}
				if selected >= externalDirectUDPRateProbeHighHeadroomMin &&
					goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
					goodput >= prevGoodput*externalDirectUDPRateProbeSenderLimitGain {
					return selected
				}
				if float64(selected) >= goodput && goodput > prevGoodput {
					return selected
				}
				return externalDirectUDPProbeKneeHeadroom(selected)
			}
			return selected
		}
		if delivery >= externalDirectUDPRateProbeNearClean && efficiency >= externalDirectUDPRateProbeEfficient {
			headroom := externalDirectUDPProbeKneeHeadroom(sample.RateMbps)
			if selected >= externalDirectUDPRateProbeCollapseMinMbps && headroom < selected {
				return selected
			}
			return headroom
		}
		if externalDirectUDPHighGoodputCappedTopProbe(maxRateMbps, highestProbeRate, sample.RateMbps, goodput, delivery, prevGoodput) && selected >= externalDirectUDPRateProbeHighHeadroomMin {
			return selected
		}
		if selected == externalDirectUDPActiveLaneTwoMaxMbps &&
			!selectedProbeViable &&
			sample.RateMbps >= externalDirectUDPDataStartHighMbps &&
			delivery >= externalDirectUDPRateProbeBufferedCollapse &&
			goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
			selectedGoodput > 0 &&
			goodput >= selectedGoodput*externalDirectUDPRateProbeMaterialGain {
			return sample.RateMbps
		}
		if selected >= externalDirectUDPActiveLaneTwoMaxMbps &&
			selectedProbeViable &&
			delivery >= externalDirectUDPRateProbeLossyDelivery &&
			goodput >= selectedGoodput*externalDirectUDPRateProbeLossyGain {
			if selected >= externalDirectUDPRateProbeCollapseMinMbps &&
				sample.RateMbps >= externalDirectUDPRateProbeConfirmMinMbps &&
				delivery >= externalDirectUDPRateProbeCeilingDelivery &&
				goodput >= selectedGoodput*externalDirectUDPRateProbeMaterialGain {
				return sample.RateMbps
			}
			return selected
		}
		if selected == externalDirectUDPActiveLaneTwoMaxMbps &&
			selectedProbeClean &&
			delivery < externalDirectUDPRateProbeBufferedCollapse &&
			goodput < selectedGoodput*externalDirectUDPRateProbeLossyGain {
			return selected
		}
		if selected >= externalDirectUDPRateProbeCollapseMinMbps && delivery < externalDirectUDPRateProbeBufferedCollapse && prevBelowSelectedRate > 0 {
			if selectedProbeViable &&
				selected >= externalDirectUDPRateProbeConfirmMinMbps &&
				delivery >= externalDirectUDPRateProbeLossyDelivery {
				return selected
			}
			if selectedProbeViable && sentEfficiency >= externalDirectUDPRateProbeCeilingEfficient {
				return selected
			}
			return externalDirectUDPProbeKneeHeadroom(prevBelowSelectedRate)
		}
		if selected >= externalDirectUDPActiveLaneTwoMaxMbps && selectedProbeViable && delivery < externalDirectUDPRateProbeBufferedCollapse && externalDirectUDPHasLossyHigherGoodputProbe(selected, selectedGoodput, sentByRate, received) {
			return selected
		}
		if selected >= externalDirectUDPRateProbeCollapseMinMbps && selectedProbeViable && delivery >= externalDirectUDPRateProbeBufferedCollapse && goodput >= selectedGoodput {
			return selected
		}
		if _, _, _, _, ok := externalDirectUDPFindLossyRecoveryProbe(selected, selectedGoodput, sentByRate, received); ok {
			return selected
		}
		if selected >= externalDirectUDPRateProbeCollapseMinMbps && selectedProbeViable {
			return selected
		}
		return externalDirectUDPProbeKneeHeadroom(selected)
	}
	return selected
}

func externalDirectUDPProbeKneeHeadroom(selected int) int {
	headroomMultiplier := externalDirectUDPRateProbeKneeHeadroom
	if selected >= externalDirectUDPRateProbeHighHeadroomMin {
		headroomMultiplier = externalDirectUDPRateProbeHighHeadroom
	}
	headroom := int(float64(selected)*headroomMultiplier + 0.5)
	if headroom < externalDirectUDPRateProbeMinMbps {
		headroom = externalDirectUDPRateProbeMinMbps
	}
	return headroom
}

func externalDirectUDPSampleGoodputMbps(bytes int64, durationMillis int64) float64 {
	if bytes <= 0 || durationMillis <= 0 {
		return 0
	}
	return float64(bytes*8) / float64(durationMillis) / 1000
}

func externalDirectUDPHasPositiveProbeProgress(samples []directUDPRateProbeSample) bool {
	for _, sample := range samples {
		if sample.BytesReceived > 0 {
			return true
		}
	}
	return false
}

func externalDirectUDPFormatRateProbeSamples(sent []directUDPRateProbeSample, received []directUDPRateProbeSample) string {
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	parts := make([]string, 0, len(received))
	for _, sample := range received {
		durationMillis := sample.DurationMillis
		if durationMillis <= 0 {
			durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		}
		goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
		delivery := 0.0
		if sentSample, ok := sentByRate[sample.RateMbps]; ok && sentSample.BytesSent > 0 {
			delivery = float64(sample.BytesReceived) / float64(sentSample.BytesSent)
		}
		parts = append(parts, fmt.Sprintf("%d:rx=%d:goodput=%.2f:delivery=%.2f", sample.RateMbps, sample.BytesReceived, goodput, delivery))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPOrderConnsForSections(conns []net.PacketConn, localCandidates []string, sectionAddrs []string) ([]net.PacketConn, error) {
	if len(sectionAddrs) == 0 {
		return conns, nil
	}
	endpointToConn := make(map[string]int)
	addEndpoint := func(endpoint string, index int) {
		if endpoint == "" || index < 0 || index >= len(conns) {
			return
		}
		if _, ok := endpointToConn[endpoint]; !ok {
			endpointToConn[endpoint] = index
		}
	}
	nextConn := 0
	for _, candidate := range localCandidates {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if endpoint == "" {
			continue
		}
		if _, ok := endpointToConn[endpoint]; ok {
			continue
		}
		addEndpoint(endpoint, nextConn)
		nextConn++
		if nextConn == len(conns) {
			break
		}
	}
	for i, conn := range conns {
		if conn == nil || conn.LocalAddr() == nil {
			continue
		}
		addEndpoint(externalDirectUDPEndpointKey(conn.LocalAddr().String()), i)
	}

	ordered := make([]net.PacketConn, 0, len(sectionAddrs))
	seen := make(map[int]bool)
	for _, addr := range sectionAddrs {
		endpoint := externalDirectUDPEndpointKey(addr)
		index, ok := endpointToConn[endpoint]
		if !ok {
			return nil, fmt.Errorf("direct UDP section address %q does not match a local lane", addr)
		}
		if seen[index] {
			return nil, fmt.Errorf("direct UDP section address %q duplicates local lane %d", addr, index)
		}
		seen[index] = true
		ordered = append(ordered, conns[index])
	}
	return ordered, nil
}

func externalDirectUDPFastDiscardReceiveConfig() probe.ReceiveConfig {
	return probe.ReceiveConfig{
		Blast:        true,
		Transport:    externalDirectUDPTransportLabel,
		FECGroupSize: externalDirectUDPFECGroupSize,
	}
}

func waitExternalDirectUDPAddrDefault(ctx context.Context, conn net.PacketConn, manager *transport.Manager) (net.Addr, error) {
	if manager == nil {
		return nil, errors.New("nil transport manager")
	}
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if addr, active := manager.DirectAddr(); active && addr != nil {
			return addr, nil
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			return nil, waitCtx.Err()
		}
	}
}

func externalDirectUDPWaitCanFallback(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded)
}

func emitExternalDirectUDPStats(emitter *telemetry.Emitter, prefix string, bytes int64, startedAt time.Time, firstByteAt time.Time, completedAt time.Time) {
	if emitter == nil || bytes <= 0 || startedAt.IsZero() || completedAt.IsZero() || !completedAt.After(startedAt) {
		return
	}
	duration := completedAt.Sub(startedAt)
	emitter.Debug(prefix + "-duration-ms=" + strconv.FormatInt(duration.Milliseconds(), 10))
	mbps := float64(bytes*8) / duration.Seconds() / 1_000_000
	emitter.Debug(prefix + "-goodput-mbps=" + strconv.FormatFloat(mbps, 'f', 2, 64))
	if firstByteAt.IsZero() {
		firstByteAt = startedAt
	} else if firstByteAt.Before(startedAt) || !completedAt.After(firstByteAt) {
		firstByteAt = startedAt
	}
	firstByteDelay := firstByteAt.Sub(startedAt)
	dataDuration := completedAt.Sub(firstByteAt)
	dataMbps := float64(bytes*8) / dataDuration.Seconds() / 1_000_000
	emitter.Debug(prefix + "-first-byte-ms=" + strconv.FormatInt(firstByteDelay.Milliseconds(), 10))
	emitter.Debug(prefix + "-data-duration-ms=" + strconv.FormatInt(dataDuration.Milliseconds(), 10))
	emitter.Debug(prefix + "-data-goodput-mbps=" + strconv.FormatFloat(dataMbps, 'f', 2, 64))
}

func emitExternalDirectUDPReceiveStartDebug(emitter *telemetry.Emitter, expectedBytes int64) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-fast-discard-expected-bytes=" + strconv.FormatInt(expectedBytes, 10))
}

func emitExternalDirectUDPSendReplayStats(emitter *telemetry.Emitter, stats probe.TransferStats) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-send-max-replay-bytes=" + strconv.FormatUint(stats.MaxReplayBytes, 10))
	emitter.Debug("udp-send-replay-window-full-waits=" + strconv.FormatInt(stats.ReplayWindowFullWaits, 10))
	emitter.Debug("udp-send-replay-window-full-wait-ms=" + strconv.FormatInt(stats.ReplayWindowFullWaitDuration.Milliseconds(), 10))
}

func emitExternalDirectUDPReceiveResultDebug(emitter *telemetry.Emitter, stats probe.TransferStats, err error) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-receive-bytes=" + strconv.FormatInt(stats.BytesReceived, 10))
	if err != nil {
		emitter.Debug("udp-receive-error=" + err.Error())
	}
}

func waitForDirectUDPReady(ctx context.Context, readyCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	for {
		pkt, err := receiveSubscribedPacket(waitCtx, readyCh)
		if err != nil {
			return err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeDirectUDPReady {
			return errors.New("unexpected direct UDP ready")
		}
		return nil
	}
}

func waitForDirectUDPReadyAck(ctx context.Context, readyAckCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (directUDPReadyAck, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	for {
		pkt, err := receiveSubscribedPacket(waitCtx, readyAckCh)
		if err != nil {
			return directUDPReadyAck{}, err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeDirectUDPReadyAck {
			return directUDPReadyAck{}, errors.New("unexpected direct UDP ready ack")
		}
		if env.DirectUDPReadyAck == nil {
			return directUDPReadyAck{}, nil
		}
		return *env.DirectUDPReadyAck, nil
	}
}

func waitForDirectUDPStart(ctx context.Context, startCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (directUDPStart, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	for {
		pkt, err := receiveSubscribedPacket(waitCtx, startCh)
		if err != nil {
			return directUDPStart{}, err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeDirectUDPStart {
			return directUDPStart{}, errors.New("unexpected direct UDP start")
		}
		if env.DirectUDPStart == nil {
			return directUDPStart{}, nil
		}
		return *env.DirectUDPStart, nil
	}
}

func waitForDirectUDPStartAck(ctx context.Context, startAckCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	for {
		pkt, err := receiveSubscribedPacket(waitCtx, startAckCh)
		if err != nil {
			return err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeDirectUDPStartAck {
			return errors.New("unexpected direct UDP start ack")
		}
		return nil
	}
}

func waitForDirectUDPRateProbe(ctx context.Context, rateProbeCh <-chan derpbind.Packet, authOpt ...externalPeerControlAuth) (directUDPRateProbeResult, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	auth := optionalPeerControlAuth(authOpt)
	for {
		pkt, err := receiveSubscribedPacket(waitCtx, rateProbeCh)
		if err != nil {
			return directUDPRateProbeResult{}, err
		}
		env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
		if ignoreAuthenticatedEnvelopeError(err, auth) {
			continue
		}
		if err != nil || env.Type != envelopeDirectUDPRateProbe {
			return directUDPRateProbeResult{}, errors.New("unexpected direct UDP rate probe response")
		}
		if env.DirectUDPRateProbe == nil {
			return directUDPRateProbeResult{}, errors.New("direct UDP rate probe response missing samples")
		}
		return *env.DirectUDPRateProbe, nil
	}
}

func isDirectUDPReadyPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPReady
}

func isDirectUDPStartPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPStart
}

func isDirectUDPStartAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPStartAck
}

func isDirectUDPRateProbePayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPRateProbe
}

type externalDirectUDPDiscardSendResult struct {
	stats probe.TransferStats
	err   error
}

type externalDirectUDPReceiveResult struct {
	stats probe.TransferStats
	err   error
}

type externalDirectUDPDiscardSpool struct {
	File       *os.File
	Path       string
	Offsets    []int64
	Sizes      []int64
	TotalBytes int64
}

func (s *externalDirectUDPDiscardSpool) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.File != nil {
		if err := s.File.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.Path != "" {
		if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func externalDirectUDPSpoolDiscardLanes(ctx context.Context, src io.Reader, lanes int, chunkSize int) (*externalDirectUDPDiscardSpool, error) {
	if lanes <= 0 {
		return nil, errors.New("no discard spool lanes")
	}
	if src == nil {
		return nil, errors.New("nil source reader")
	}
	if chunkSize <= 0 {
		chunkSize = externalDirectUDPChunkSize
	}
	file, err := os.CreateTemp("", "derphole-discard-spool-*")
	if err != nil {
		return nil, err
	}
	spool := &externalDirectUDPDiscardSpool{
		File:    file,
		Path:    file.Name(),
		Offsets: make([]int64, lanes),
		Sizes:   make([]int64, lanes),
	}
	buf := make([]byte, chunkSize*128)
	for {
		if err := ctx.Err(); err != nil {
			_ = spool.Close()
			return nil, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, err := spool.File.Write(buf[:n])
			if err != nil {
				_ = spool.Close()
				return nil, err
			}
			if written != n {
				_ = spool.Close()
				return nil, io.ErrShortWrite
			}
			spool.TotalBytes += int64(written)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = spool.Close()
			return nil, readErr
		}
		if n == 0 {
			select {
			case <-ctx.Done():
				_ = spool.Close()
				return nil, ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}
	base := spool.TotalBytes / int64(lanes)
	extra := spool.TotalBytes % int64(lanes)
	var offset int64
	for i := range spool.Sizes {
		size := base
		if int64(i) < extra {
			size++
		}
		spool.Offsets[i] = offset
		spool.Sizes[i] = size
		offset += size
	}
	return spool, nil
}

func externalDirectUDPSendDiscardSpoolParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, spool *externalDirectUDPDiscardSpool, cfg probe.SendConfig) (probe.TransferStats, error) {
	if spool == nil {
		return probe.TransferStats{}, errors.New("nil discard spool")
	}
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return probe.TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if spool.File == nil {
		return probe.TransferStats{}, errors.New("nil discard spool file")
	}
	if len(spool.Sizes) < len(conns) || len(spool.Offsets) < len(conns) {
		return probe.TransferStats{}, fmt.Errorf("discard spool lane count %d is less than packet conn count %d", len(spool.Sizes), len(conns))
	}
	cfg.StripedBlast = false
	cfg.Parallel = 1
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = externalDirectUDPChunkSize
	}
	laneRate := externalDirectUDPPerLaneRateMbps(cfg.RateMbps, len(conns))
	laneRateCeiling := externalDirectUDPPerLaneRateMbps(cfg.RateCeilingMbps, len(conns))
	startedAt := time.Now()
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPDiscardLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		laneCfg.RateCeilingMbps = laneRateCeiling
		src := io.NewSectionReader(spool.File, spool.Offsets[i], spool.Sizes[i])
		go func(conn net.PacketConn, remoteAddr string, src io.Reader, laneCfg probe.SendConfig) {
			stats, err := externalDirectUDPProbeSendFn(ctx, conn, remoteAddr, src, laneCfg)
			results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
		}(conn, remoteAddrs[i], src, laneCfg)
	}
	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var sendErr error
	for range conns {
		result := <-results
		if result.err != nil && sendErr == nil {
			sendErr = result.err
		}
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if sendErr != nil {
		return probe.TransferStats{}, sendErr
	}
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

type externalDirectUDPOffsetWriter struct {
	file   *os.File
	offset int64
}

func (w *externalDirectUDPOffsetWriter) Write(p []byte) (int, error) {
	if w == nil || w.file == nil {
		return 0, errors.New("nil offset writer")
	}
	n, err := w.file.WriteAt(p, w.offset)
	w.offset += int64(n)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func externalDirectUDPReceiveSectionSpoolParallel(ctx context.Context, conns []net.PacketConn, dst io.Writer, cfg probe.ReceiveConfig, totalBytes int64, sectionSizes []int64) (probe.TransferStats, error) {
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if totalBytes < 0 {
		return probe.TransferStats{}, errors.New("negative expected bytes")
	}
	sizes, offsets, err := externalDirectUDPReceiveSectionLayout(totalBytes, len(conns), sectionSizes)
	if err != nil {
		return probe.TransferStats{}, err
	}
	conns = conns[:len(sizes)]
	if dst == nil {
		dst = io.Discard
	}
	file, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(dst, totalBytes)
	if err != nil {
		return probe.TransferStats{}, err
	}
	defer cleanup()

	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan externalDirectUDPReceiveResult, len(conns))
	startedAt := time.Now()
	for i, conn := range conns {
		laneCfg := cfg
		if len(laneCfg.ExpectedRunIDs) == len(conns) {
			laneCfg.ExpectedRunID = laneCfg.ExpectedRunIDs[i]
			laneCfg.ExpectedRunIDs = nil
		} else if len(laneCfg.ExpectedRunIDs) == 0 {
			laneCfg.ExpectedRunID = [16]byte{}
		}
		laneCfg.RequireComplete = true
		writer := &externalDirectUDPOffsetWriter{file: file, offset: offsets[i]}
		go func(conn net.PacketConn, writer io.Writer, expected int64, laneCfg probe.ReceiveConfig) {
			stats, err := probe.ReceiveBlastParallelToWriter(receiveCtx, []net.PacketConn{conn}, writer, laneCfg, expected)
			if err != nil {
				cancel()
			}
			results <- externalDirectUDPReceiveResult{stats: stats, err: err}
		}(conn, writer, sizes[i], laneCfg)
	}

	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var receiveErr error
	for range conns {
		result := <-results
		receiveErr = externalDirectUDPPreferInformativeError(receiveErr, result.err)
		externalDirectUDPMergeReceiveStats(&stats, result.stats)
	}
	if receiveErr != nil {
		stats.CompletedAt = time.Now()
		if stats.FirstByteAt.IsZero() && stats.BytesReceived > 0 {
			stats.FirstByteAt = startedAt
		}
		return stats, receiveErr
	}
	if err := externalDirectUDPFinishSectionTarget(file, copyToDst, dst, totalBytes); err != nil {
		stats.CompletedAt = time.Now()
		return stats, err
	}
	stats.CompletedAt = time.Now()
	if stats.FirstByteAt.IsZero() && stats.BytesReceived > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

func externalDirectUDPReceiveSectionTarget(dst io.Writer, totalBytes int64) (*os.File, bool, func(), error) {
	if file := externalDirectUDPRegularFileWriter(dst); file != nil {
		if totalBytes > 0 {
			if err := file.Truncate(totalBytes); err != nil {
				return nil, false, nil, err
			}
		}
		return file, false, func() {}, nil
	}
	file, err := os.CreateTemp("", "derphole-receive-spool-*")
	if err != nil {
		return nil, false, nil, err
	}
	path := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	return file, true, cleanup, nil
}

func externalDirectUDPSectionWriterForTarget(dst io.Writer, buffered io.Writer, flush func() error) (io.Writer, func() error) {
	if file := externalDirectUDPRegularFileWriter(dst); file != nil {
		return file, func() error { return nil }
	}
	if buffered == nil {
		buffered = dst
	}
	if flush == nil {
		flush = func() error { return nil }
	}
	return buffered, flush
}

func externalDirectUDPRegularFileWriter(dst io.Writer) *os.File {
	file := externalDirectUDPFileWriter(dst)
	if file == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return file
}

func externalDirectUDPFileWriter(dst io.Writer) *os.File {
	switch writer := dst.(type) {
	case *os.File:
		return writer
	case nopWriteCloser:
		return externalDirectUDPFileWriter(writer.Writer)
	case *nopWriteCloser:
		if writer == nil {
			return nil
		}
		return externalDirectUDPFileWriter(writer.Writer)
	default:
		return nil
	}
}

func externalDirectUDPFinishSectionTarget(file *os.File, copyToDst bool, dst io.Writer, totalBytes int64) error {
	if file == nil || totalBytes <= 0 {
		return nil
	}
	if !copyToDst {
		_, err := file.Seek(totalBytes, io.SeekStart)
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	written, err := io.CopyN(dst, file, totalBytes)
	if err != nil {
		return err
	}
	if written != totalBytes {
		return io.ErrShortWrite
	}
	return nil
}

func externalDirectUDPReceiveSectionLayout(totalBytes int64, connCount int, sectionSizes []int64) ([]int64, []int64, error) {
	if connCount <= 0 {
		return nil, nil, errors.New("no packet conns")
	}
	if len(sectionSizes) == 0 {
		sizes, offsets := externalDirectUDPSectionSizes(totalBytes, connCount)
		return sizes, offsets, nil
	}
	if len(sectionSizes) > connCount {
		return nil, nil, fmt.Errorf("direct UDP start section count %d exceeds receiver lane count %d", len(sectionSizes), connCount)
	}
	sizes := append([]int64(nil), sectionSizes...)
	offsets := make([]int64, len(sizes))
	var offset int64
	for i, size := range sizes {
		if size < 0 {
			return nil, nil, fmt.Errorf("negative direct UDP section size at lane %d", i)
		}
		offsets[i] = offset
		offset += size
	}
	if offset != totalBytes {
		return nil, nil, fmt.Errorf("direct UDP section sizes total %d bytes, want %d", offset, totalBytes)
	}
	return sizes, offsets, nil
}

func externalDirectUDPSectionSizes(totalBytes int64, lanes int) ([]int64, []int64) {
	if lanes <= 0 {
		return nil, nil
	}
	sizes := make([]int64, lanes)
	offsets := make([]int64, lanes)
	base := totalBytes / int64(lanes)
	extra := totalBytes % int64(lanes)
	var offset int64
	for i := range sizes {
		size := base
		if int64(i) < extra {
			size++
		}
		offsets[i] = offset
		sizes[i] = size
		offset += size
	}
	return sizes, offsets
}

func externalDirectUDPSendDiscardParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, src io.Reader, cfg probe.SendConfig) (probe.TransferStats, error) {
	if len(conns) == 0 {
		return probe.TransferStats{}, errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return probe.TransferStats{}, fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if src == nil {
		return probe.TransferStats{}, errors.New("nil source reader")
	}
	cfg.StripedBlast = false
	cfg.Parallel = 1
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = externalDirectUDPChunkSize
	}
	if len(conns) == 1 {
		cfg.RunID = externalDirectUDPLaneRunID(cfg.RunID, 0)
		return externalDirectUDPProbeSendFn(ctx, conns[0], remoteAddrs[0], src, cfg)
	}

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	startedAt := time.Now()
	laneRate := externalDirectUDPPerLaneRateMbps(cfg.RateMbps, len(conns))
	laneRateCeiling := externalDirectUDPPerLaneRateMbps(cfg.RateCeilingMbps, len(conns))
	writers := make([]*io.PipeWriter, len(conns))
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		reader, writer := io.Pipe()
		writers[i] = writer
		remoteAddr := remoteAddrs[i]
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		laneCfg.RateCeilingMbps = laneRateCeiling
		go func(conn net.PacketConn, remoteAddr string, reader *io.PipeReader, laneCfg probe.SendConfig) {
			defer reader.Close()
			stats, err := externalDirectUDPProbeSendFn(sendCtx, conn, remoteAddr, reader, laneCfg)
			if err != nil {
				cancel()
			}
			results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
		}(conn, remoteAddr, reader, laneCfg)
	}

	dispatchErr := externalDirectUDPDistributeDiscardStream(sendCtx, src, writers, cfg.ChunkSize)
	for _, writer := range writers {
		if dispatchErr != nil {
			_ = writer.CloseWithError(dispatchErr)
			continue
		}
		_ = writer.Close()
	}

	stats := probe.TransferStats{StartedAt: startedAt, Lanes: len(conns)}
	var sendErr error
	for range conns {
		result := <-results
		sendErr = externalDirectUDPPreferInformativeError(sendErr, result.err)
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if dispatchErr != nil {
		return probe.TransferStats{}, externalDirectUDPPreferInformativeError(dispatchErr, sendErr)
	}
	if sendErr != nil {
		return probe.TransferStats{}, sendErr
	}
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
}

func externalDirectUDPPreferInformativeError(current, candidate error) error {
	if current == nil {
		return candidate
	}
	if candidate == nil {
		return current
	}
	if errors.Is(current, context.Canceled) || errors.Is(current, io.ErrClosedPipe) || errors.Is(current, net.ErrClosed) {
		return candidate
	}
	return current
}

func externalDirectUDPLaneRunIDs(base [16]byte, lanes int) [][16]byte {
	if lanes <= 0 {
		return nil
	}
	out := make([][16]byte, lanes)
	for i := range out {
		out[i] = externalDirectUDPLaneRunID(base, i)
	}
	return out
}

func externalDirectUDPDiscardLaneRunID(base [16]byte, lane int) [16]byte {
	if base == ([16]byte{}) {
		return base
	}
	return externalDirectUDPLaneRunID(base, lane)
}

func externalDirectUDPStopPunchingForBlast(cancel context.CancelFunc) {
	// The blast keeps NAT mappings warm. Extra keepalive punches on the data sockets can backlog receivers.
	if cancel != nil {
		cancel()
	}
}

func externalDirectUDPLaneRunID(base [16]byte, lane int) [16]byte {
	runID := base
	if lane < 0 {
		lane = 0
	}
	lane++
	runID[14] ^= byte(lane >> 8)
	runID[15] ^= byte(lane)
	return runID
}

func externalDirectUDPDistributeDiscardStream(ctx context.Context, src io.Reader, writers []*io.PipeWriter, chunkSize int) error {
	if len(writers) == 0 {
		return errors.New("no pipe writers")
	}
	if chunkSize <= 0 {
		chunkSize = externalDirectUDPChunkSize
	}
	distCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var writerErrMu sync.Mutex
	var writerErr error
	setWriterErr := func(err error) {
		if err == nil {
			return
		}
		writerErrMu.Lock()
		if writerErr == nil {
			writerErr = err
		}
		writerErrMu.Unlock()
		cancel()
	}
	currentWriterErr := func() error {
		writerErrMu.Lock()
		defer writerErrMu.Unlock()
		return writerErr
	}
	closeWritersWithError := func(err error) {
		for _, writer := range writers {
			if writer != nil {
				_ = writer.CloseWithError(err)
			}
		}
	}
	queues := make([]chan []byte, len(writers))
	writerDone := make(chan error, len(writers))
	for i, writer := range writers {
		queue := make(chan []byte, externalDirectUDPDiscardQueue)
		queues[i] = queue
		go func(writer *io.PipeWriter, queue <-chan []byte) {
			for chunk := range queue {
				if len(chunk) == 0 {
					continue
				}
				if _, err := writer.Write(chunk); err != nil {
					setWriterErr(err)
					writerDone <- err
					return
				}
			}
			writerDone <- nil
		}(writer, queue)
	}
	var closeQueuesOnce sync.Once
	closeQueues := func() {
		closeQueuesOnce.Do(func() {
			for _, queue := range queues {
				close(queue)
			}
		})
	}
	waitWriters := func() error {
		var firstErr error
		for range writers {
			if err := <-writerDone; err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return firstErr
		}
		return currentWriterErr()
	}
	fail := func(err error) error {
		closeWritersWithError(err)
		closeQueues()
		if writerWaitErr := waitWriters(); writerWaitErr != nil && err == nil {
			return writerWaitErr
		}
		return err
	}

	buf := make([]byte, chunkSize*128)
	lane := 0
	for {
		if err := distCtx.Err(); err != nil {
			if writerErr := currentWriterErr(); writerErr != nil {
				return fail(writerErr)
			}
			return fail(err)
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case queues[lane] <- chunk:
				lane = (lane + 1) % len(writers)
			case <-distCtx.Done():
				if writerErr := currentWriterErr(); writerErr != nil {
					return fail(writerErr)
				}
				return fail(distCtx.Err())
			}
		}
		if errors.Is(readErr, io.EOF) {
			closeQueues()
			return waitWriters()
		}
		if readErr != nil {
			return fail(readErr)
		}
		if n == 0 {
			select {
			case <-distCtx.Done():
				if writerErr := currentWriterErr(); writerErr != nil {
					return fail(writerErr)
				}
				return fail(distCtx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
}

func externalDirectUDPPerLaneRateMbps(totalRateMbps int, lanes int) int {
	if totalRateMbps <= 0 || lanes <= 1 {
		return totalRateMbps
	}
	rate := totalRateMbps / lanes
	if rate < 1 {
		return 1
	}
	return rate
}

func externalDirectUDPRateMbpsForLanes(maxRateMbps int, lanes int) int {
	if maxRateMbps <= 0 || lanes >= externalDirectUDPParallelism {
		return maxRateMbps
	}
	if lanes <= 0 {
		return 0
	}
	return externalDirectUDPPerLaneRateMbps(maxRateMbps, externalDirectUDPParallelism) * lanes
}

func externalDirectUDPActiveLanesForRate(rateMbps int, available int) int {
	if available <= 0 {
		return 0
	}
	target := externalDirectUDPParallelism
	switch {
	case rateMbps <= externalDirectUDPActiveLaneOneMaxMbps:
		target = 1
	case rateMbps <= externalDirectUDPActiveLaneTwoMaxMbps:
		target = 2
	case rateMbps <= externalDirectUDPDataStartHighMbps:
		target = 4
	}
	if target > available {
		return available
	}
	return target
}

func externalDirectUDPRetainedLanesForRate(rateMbps int, available int, striped bool) int {
	target := externalDirectUDPActiveLanesForRate(rateMbps, available)
	if !striped || available <= target {
		return target
	}
	// Keep a four-lane striped pool warm once probes show a material WAN path.
	// The data-plane controller still paces aggregate Mbps; this preserves enough
	// socket fan-out to recover beyond a conservative initial sample.
	if rateMbps >= externalDirectUDPActiveLaneTwoMaxMbps && target < 4 {
		target = 4
	}
	if target > available {
		return available
	}
	return target
}

func externalDirectUDPNoProbeActiveLanes(rateMbps int, rateCeilingMbps int, available int) int {
	laneBasisMbps := externalDirectUDPNoProbeLaneBasisMbps(rateMbps, rateCeilingMbps)
	return externalDirectUDPActiveLanesForRate(laneBasisMbps, available)
}

func externalDirectUDPNoProbeLaneBasisMbps(rateMbps int, rateCeilingMbps int) int {
	laneBasisMbps := rateMbps
	if rateCeilingMbps >= externalRelayPrefixNoProbeLaneBasisMbps && laneBasisMbps < externalRelayPrefixNoProbeLaneBasisMbps {
		laneBasisMbps = externalRelayPrefixNoProbeLaneBasisMbps
	}
	return laneBasisMbps
}

func externalDirectUDPActiveLaneCapForPolicy(policy ParallelPolicy, available int) int {
	if available <= 0 {
		return 0
	}
	policy = policy.normalized()
	switch policy.Mode {
	case ParallelModeFixed:
		if policy.Initial <= 0 {
			return 0
		}
		if policy.Initial > available {
			return available
		}
		return policy.Initial
	case ParallelModeAuto:
		if policy.Cap > 0 && policy.Cap < available {
			return policy.Cap
		}
	}
	return 0
}

func externalDirectUDPDataLaneRateBasisMbps(activeRateMbps int, rateCeilingMbps int, probeRates []int) int {
	basis := activeRateMbps
	if rateCeilingMbps > basis {
		if len(probeRates) > 0 {
			if rateCeilingMbps >= externalDirectUDPActiveLaneFourMaxMbps && activeRateMbps > 0 && activeRateMbps <= externalDirectUDPActiveLaneFourMaxMbps {
				return externalDirectUDPActiveLaneFourMaxMbps
			}
			if rateCeilingMbps > externalDirectUDPDataStartHighMbps && activeRateMbps > 0 && activeRateMbps < externalDirectUDPActiveLaneFourMaxMbps {
				return externalDirectUDPDataStartHighMbps
			}
		}
		basis = rateCeilingMbps
		if rateCeilingMbps > externalDirectUDPRateProbeDefaultMaxMbps {
			probeMax := 0
			for _, rate := range probeRates {
				if rate > probeMax {
					probeMax = rate
				}
			}
			if probeMax == 0 {
				basis = activeRateMbps
			} else if probeMax > basis || probeMax > activeRateMbps {
				basis = probeMax
			}
		}
	}
	return basis
}

func externalDirectUDPStartBudget(rateCeilingMbps int) externalDirectUDPBudget {
	budget := externalDirectUDPBudget{
		RateMbps:          externalDirectUDPRateProbeMinMbps,
		ActiveLanes:       1,
		ReplayWindowBytes: 16 << 20,
	}
	if rateCeilingMbps <= 0 {
		return budget
	}
	switch {
	case rateCeilingMbps <= 100:
		budget.RateMbps = rateCeilingMbps
	case rateCeilingMbps <= externalDirectUDPActiveLaneOneMaxMbps:
		budget.RateMbps = 250
		budget.ReplayWindowBytes = 32 << 20
	case rateCeilingMbps <= externalDirectUDPActiveLaneTwoMaxMbps:
		budget.RateMbps = 525
		budget.ActiveLanes = 2
		budget.ReplayWindowBytes = 64 << 20
	case rateCeilingMbps <= externalDirectUDPDataStartHighMbps:
		budget.RateMbps = 900
		budget.ActiveLanes = 2
		budget.ReplayWindowBytes = 64 << 20
	case rateCeilingMbps <= 1800:
		budget.RateMbps = externalDirectUDPDataStartHighMbps
		budget.ActiveLanes = 4
		budget.ReplayWindowBytes = 128 << 20
	default:
		budget.RateMbps = externalDirectUDPDataStartHighMbps
		budget.ActiveLanes = externalDirectUDPParallelism
		budget.ReplayWindowBytes = externalDirectUDPStreamReplayBytes
	}
	if budget.RateMbps < externalDirectUDPRateProbeMinMbps {
		budget.RateMbps = externalDirectUDPRateProbeMinMbps
	}
	if budget.RateMbps > rateCeilingMbps {
		budget.RateMbps = rateCeilingMbps
	}
	return budget
}

func externalDirectUDPReplayWindowBytesForRate(rateMbps int) uint64 {
	switch {
	case rateMbps <= 0:
		return 16 << 20
	case rateMbps <= 100:
		return 16 << 20
	case rateMbps <= externalDirectUDPActiveLaneOneMaxMbps:
		return 32 << 20
	case rateMbps < externalDirectUDPActiveLaneTwoMaxMbps:
		return 64 << 20
	case rateMbps <= externalDirectUDPDataStartHighMbps:
		return 128 << 20
	default:
		return externalDirectUDPStreamReplayBytes
	}
}

func externalDirectUDPDataPathBudget(selectedRateMbps int, activeRateMbps int, rateCeilingMbps int, availableLanes int, striped bool) externalDirectUDPBudget {
	budget := externalDirectUDPStartBudget(rateCeilingMbps)
	if activeRateMbps > 0 {
		budget.RateMbps = activeRateMbps
	}
	if availableLanes <= 0 {
		budget.ActiveLanes = 0
		return budget
	}

	laneRateBasisMbps := selectedRateMbps
	if laneRateBasisMbps <= 0 {
		laneRateBasisMbps = activeRateMbps
	}
	if laneRateBasisMbps <= 0 {
		laneRateBasisMbps = rateCeilingMbps
	}
	switch {
	case laneRateBasisMbps > externalDirectUDPDataStartHighMbps && rateCeilingMbps >= externalDirectUDPActiveLaneFourMaxMbps:
		laneRateBasisMbps = externalDirectUDPActiveLaneFourMaxMbps
	case laneRateBasisMbps >= externalDirectUDPActiveLaneTwoMaxMbps && rateCeilingMbps > externalDirectUDPDataStartHighMbps:
		laneRateBasisMbps = externalDirectUDPDataStartHighMbps
	}

	budget.ActiveLanes = externalDirectUDPRetainedLanesForRate(laneRateBasisMbps, availableLanes, striped)
	budget.ReplayWindowBytes = externalDirectUDPReplayWindowBytesForRate(laneRateBasisMbps)
	return budget
}

func externalDirectUDPClampDataStartRate(selectedRateMbps int, activeRateMbps int, rateCeilingMbps int, availableLanes int, striped bool) int {
	startBudget := externalDirectUDPStartBudget(rateCeilingMbps)
	if activeRateMbps <= 0 {
		return startBudget.RateMbps
	}
	if activeRateMbps <= startBudget.RateMbps {
		return activeRateMbps
	}
	dataBudget := externalDirectUDPDataPathBudget(selectedRateMbps, activeRateMbps, rateCeilingMbps, availableLanes, striped)
	if startBudget.ActiveLanes >= dataBudget.ActiveLanes &&
		startBudget.ReplayWindowBytes >= dataBudget.ReplayWindowBytes {
		return activeRateMbps
	}
	return startBudget.RateMbps
}

func externalDirectUDPDataStartRateMbps(selectedRateMbps int) int {
	if selectedRateMbps <= 0 || selectedRateMbps <= externalDirectUDPDataStartMaxMbps {
		return selectedRateMbps
	}
	if selectedRateMbps >= externalDirectUDPRateProbeDefaultMaxMbps {
		return externalDirectUDPRateProbeDefaultMaxMbps
	}
	if selectedRateMbps >= externalDirectUDPDataStartHighMinMbps {
		return externalDirectUDPDataStartHighMbps
	}
	if selectedRateMbps >= externalDirectUDPActiveLaneTwoMaxMbps {
		return externalDirectUDPActiveLaneTwoMaxMbps
	}
	return externalDirectUDPDataStartMaxMbps
}

func externalDirectUDPDataStartRateMbpsForCeiling(selectedRateMbps int, rateCeilingMbps int) int {
	start := externalDirectUDPDataStartRateMbps(selectedRateMbps)
	if selectedRateMbps <= 0 {
		return start
	}
	if selectedRateMbps >= externalDirectUDPDataStartHighMinMbps && rateCeilingMbps >= selectedRateMbps {
		return selectedRateMbps
	}
	return start
}

func externalDirectUDPRelayPrefixNoProbeRateCeilingMbps(maxRateMbps int) int {
	if maxRateMbps <= 0 {
		return externalRelayPrefixNoProbeCeilingMbps
	}
	if maxRateMbps < externalRelayPrefixNoProbeCeilingMbps {
		return maxRateMbps
	}
	return externalRelayPrefixNoProbeCeilingMbps
}

func externalDirectUDPDataStartRateMbpsForProbeSamples(selectedRateMbps int, rateCeilingMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	start := externalDirectUDPDataStartRateMbpsForCeiling(selectedRateMbps, rateCeilingMbps)
	if start > externalDirectUDPDataStartMaxMbps {
		if externalDirectUDPSelectedTierHasBufferedCollapse(selectedRateMbps, rateCeilingMbps, sent, received) {
			return externalDirectUDPDataStartMaxMbps
		}
		if externalDirectUDPSelectedTierNeedsConservativeHighStart(selectedRateMbps, sent, received) {
			return externalDirectUDPDataStartHighMbps
		}
	}
	return start
}

func externalDirectUDPShouldUseStripedBlast(availableLanes int, fastDiscard bool) bool {
	if fastDiscard {
		return false
	}
	return externalDirectUDPStripedBlast && availableLanes > 1
}

func externalDirectUDPSelectedTierHasBufferedCollapse(selectedRateMbps int, rateCeilingMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	if selectedRateMbps < externalDirectUDPDataStartHighMbps {
		return false
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	selectedGoodput := 0.0
	selectedDelivery := 0.0
	selectedEfficiency := 0.0
	for _, sample := range received {
		if sample.RateMbps != selectedRateMbps {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || delivery < externalDirectUDPRateProbeNearClean {
			return false
		}
		selectedGoodput = goodput
		selectedDelivery = delivery
		selectedEfficiency = efficiency
		break
	}
	if selectedGoodput <= 0 {
		return false
	}
	startBudgetRate := externalDirectUDPStartBudget(rateCeilingMbps).RateMbps
	startGoodput := 0.0
	startDelivery := 0.0
	startEfficiency := 0.0
	if startBudgetRate > externalDirectUDPDataStartMaxMbps && startBudgetRate < selectedRateMbps {
		for _, sample := range received {
			if sample.RateMbps <= 0 || sample.RateMbps > startBudgetRate {
				continue
			}
			goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
			if !ok {
				continue
			}
			startGoodput = goodput
			startDelivery = delivery
			startEfficiency = efficiency
		}
	}
	higherGoodputBeatSelected := false
	for _, sample := range received {
		if sample.RateMbps <= selectedRateMbps {
			continue
		}
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok {
			continue
		}
		if goodput >= selectedGoodput {
			higherGoodputBeatSelected = true
			continue
		}
		if selectedRateMbps <= startBudgetRate &&
			selectedDelivery >= externalDirectUDPRateProbeNearClean &&
			selectedEfficiency >= externalDirectUDPRateProbeEfficient {
			// A near-clean, efficient selected tier is already a viable data
			// start. Collapse above that point should cap further exploration, not
			// force the sender all the way back to the conservative 350 Mbps
			// start.
			if rateCeilingMbps > selectedRateMbps && higherGoodputBeatSelected {
				continue
			}
			continue
		}
		if startGoodput > 0 &&
			startDelivery >= externalDirectUDPRateProbeNearClean &&
			startEfficiency >= externalDirectUDPRateProbeEfficient &&
			delivery >= externalDirectUDPRateProbeLossyDelivery {
			continue
		}
		if selectedDelivery < externalDirectUDPRateProbeClean && delivery < externalDirectUDPRateProbeCeilingDelivery {
			return true
		}
	}
	return false
}

func externalDirectUDPSelectedTierNeedsConservativeHighStart(selectedRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	if selectedRateMbps <= externalDirectUDPDataStartHighMbps {
		return false
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	prevGoodput := 0.0
	prevDelivery := 0.0
	for _, sample := range received {
		if sample.RateMbps < selectedRateMbps {
			goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
			if ok {
				prevGoodput = goodput
				prevDelivery = delivery
			}
		}
		if sample.RateMbps != selectedRateMbps {
			continue
		}
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, sentByRate)
		if !ok || delivery < externalDirectUDPRateProbeClean {
			return false
		}
		if selectedRateMbps > externalDirectUDPRateProbeConfirmMinMbps &&
			prevGoodput > 0 &&
			prevDelivery >= externalDirectUDPRateProbeClean &&
			goodput >= prevGoodput*1.10 {
			return false
		}
		efficiency := goodput / float64(selectedRateMbps)
		return efficiency < externalDirectUDPRateProbeCeilingEfficient
	}
	return false
}

func externalDirectUDPDataExplorationCeilingMbps(maxRateMbps int, selectedRateMbps int, rateCeilingMbps int) int {
	if selectedRateMbps < externalDirectUDPActiveLaneTwoMaxMbps {
		return rateCeilingMbps
	}
	explorationCeiling := rateCeilingMbps
	target := externalDirectUDPRateProbeDefaultMaxMbps
	if selectedRateMbps < externalDirectUDPRateProbeDefaultMaxMbps {
		target = externalDirectUDPDataExplorationDefaultMaxMbps
	}
	if explorationCeiling < target {
		explorationCeiling = target
	}
	if maxRateMbps > 0 && explorationCeiling > maxRateMbps {
		explorationCeiling = maxRateMbps
	}
	if explorationCeiling < rateCeilingMbps {
		return rateCeilingMbps
	}
	return explorationCeiling
}

func externalDirectUDPDataExplorationCeilingMbpsForProbeSamples(maxRateMbps int, selectedRateMbps int, rateCeilingMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	explorationCeiling := externalDirectUDPDataExplorationCeilingMbps(maxRateMbps, selectedRateMbps, rateCeilingMbps)
	if rateCeilingMbps > selectedRateMbps ||
		selectedRateMbps < externalDirectUDPRateProbeCollapseMinMbps ||
		len(sent) == 0 ||
		len(received) == 0 {
		return explorationCeiling
	}
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	selectedSample := directUDPRateProbeSample{RateMbps: selectedRateMbps}
	foundSelected := false
	for _, sample := range received {
		if sample.RateMbps != selectedRateMbps {
			continue
		}
		selectedSample = sample
		foundSelected = true
		break
	}
	if !foundSelected {
		return rateCeilingMbps
	}
	selectedGoodput, selectedDelivery, _, ok := externalDirectUDPProbeMetrics(selectedSample, sentByRate)
	if !ok {
		return rateCeilingMbps
	}
	if selectedDelivery >= externalDirectUDPRateProbeLossySelect {
		return rateCeilingMbps
	}
	if explorationRate, _, _, _, ok := externalDirectUDPFindLossyHighSelectedExplorationCeiling(selectedRateMbps, selectedGoodput, selectedDelivery, sentByRate, received, maxRateMbps); ok && explorationRate > rateCeilingMbps {
		return explorationRate
	}
	return rateCeilingMbps
}

func externalDirectUDPDataRateCeilingMbps(probeCeilingMbps int, selectedRateMbps int, activeLanes int) int {
	if probeCeilingMbps <= 0 || selectedRateMbps <= 0 {
		return probeCeilingMbps
	}
	if activeLanes <= 1 && probeCeilingMbps > externalDirectUDPActiveLaneOneMaxMbps {
		return externalDirectUDPActiveLaneOneMaxMbps
	}
	return probeCeilingMbps
}

func externalDirectUDPMergeSendStats(dst *probe.TransferStats, src probe.TransferStats) {
	dst.BytesSent += src.BytesSent
	dst.PacketsSent += src.PacketsSent
	dst.PacketsAcked += src.PacketsAcked
	dst.Retransmits += src.Retransmits
	if !src.FirstByteAt.IsZero() && (dst.FirstByteAt.IsZero() || src.FirstByteAt.Before(dst.FirstByteAt)) {
		dst.FirstByteAt = src.FirstByteAt
	}
	if dst.Transport.Kind == "" {
		dst.Transport = src.Transport
	}
}

func externalDirectUDPMergeReceiveStats(dst *probe.TransferStats, src probe.TransferStats) {
	dst.BytesReceived += src.BytesReceived
	dst.PacketsSent += src.PacketsSent
	dst.PacketsAcked += src.PacketsAcked
	dst.Retransmits += src.Retransmits
	if !src.FirstByteAt.IsZero() && (dst.FirstByteAt.IsZero() || src.FirstByteAt.Before(dst.FirstByteAt)) {
		dst.FirstByteAt = src.FirstByteAt
	}
	if dst.Transport.Kind == "" {
		dst.Transport = src.Transport
	}
}

func sendExternalRelayUDP(ctx context.Context, src io.Reader, manager *transport.Manager, tok token.Token, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return err
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	_, err = externalDirectUDPProbeSendFn(ctx, packetConn, packetConn.remoteAddr.String(), externalDirectUDPBufferedReader(src), probe.SendConfig{
		Raw:        true,
		Blast:      true,
		Transport:  "legacy",
		ChunkSize:  externalDirectUDPChunkSize,
		WindowSize: 4096,
		RunID:      tok.SessionID,
		PacketAEAD: packetAEAD,
		// DERP is reliable per connection, but relay datagrams can still be
		// dropped by local queues during high-rate transfers. Keep the blast
		// repair path enabled for force-relay file correctness.
		RepairPayloads:          true,
		TailReplayBytes:         externalDirectUDPTailReplayBytes,
		FECGroupSize:            externalDirectUDPFECGroupSize,
		StreamReplayWindowBytes: externalDirectUDPStreamReplayBytes,
	})
	return err
}

func receiveExternalRelayUDP(ctx context.Context, dst io.Writer, manager *transport.Manager, tok token.Token, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return err
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
	_, err = externalRelayUDPProbeReceiveToWriterFn(ctx, packetConn, receiveDst, probe.ReceiveConfig{
		Raw:             true,
		Blast:           true,
		ExpectedRunID:   tok.SessionID,
		PacketAEAD:      packetAEAD,
		RequireComplete: true,
		FECGroupSize:    externalDirectUDPFECGroupSize,
		SpoolOutput:     true,
	})
	if err == nil {
		err = flushDst()
	}
	return err
}

func externalDirectUDPBufferedReader(src io.Reader) io.Reader {
	if src == nil {
		return nil
	}
	if _, ok := src.(*bufio.Reader); ok {
		return src
	}
	return bufio.NewReaderSize(src, externalDirectUDPBufferSize)
}

func externalDirectUDPBufferedWriter(dst io.Writer) (io.Writer, func() error) {
	if dst == nil {
		return io.Discard, func() error { return nil }
	}
	if externalDirectUDPWriterIsNullDevice(dst) {
		return io.Discard, func() error { return nil }
	}
	if buffered, ok := dst.(*bufio.Writer); ok {
		return buffered, buffered.Flush
	}
	buffered := bufio.NewWriterSize(dst, externalDirectUDPBufferSize)
	return buffered, buffered.Flush
}

func externalDirectUDPWriterIsNullDevice(dst io.Writer) bool {
	switch writer := dst.(type) {
	case nopWriteCloser:
		return externalDirectUDPWriterIsNullDevice(writer.Writer)
	case *nopWriteCloser:
		if writer == nil {
			return false
		}
		return externalDirectUDPWriterIsNullDevice(writer.Writer)
	case *os.File:
		return externalDirectUDPFileIsNullDevice(writer)
	default:
		return false
	}
}

func externalDirectUDPFileIsNullDevice(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return false
	}
	defer devNull.Close()
	nullInfo, err := devNull.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(info, nullInfo)
}

type externalPeerDatagramPacketConn struct {
	ctx        context.Context
	peer       transport.PeerDatagramConn
	remoteAddr net.Addr

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newExternalPeerDatagramPacketConn(ctx context.Context, peer transport.PeerDatagramConn) *externalPeerDatagramPacketConn {
	remoteAddr := peer.RemoteAddr()
	if remoteAddr == nil {
		remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	}
	return &externalPeerDatagramPacketConn{
		ctx:        ctx,
		peer:       peer,
		remoteAddr: remoteAddr,
	}
}

func (c *externalPeerDatagramPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	readCtx := c.ctx
	deadline := c.currentReadDeadline()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithDeadline(readCtx, deadline)
		defer cancel()
	}
	payload, _, err := c.peer.RecvDatagram(readCtx)
	if err != nil {
		return 0, nil, err
	}
	defer c.peer.ReleaseDatagram(payload)
	return copy(b, payload), c.remoteAddr, nil
}

func (c *externalPeerDatagramPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if deadline := c.currentWriteDeadline(); !deadline.IsZero() && time.Now().After(deadline) {
		return 0, context.DeadlineExceeded
	}
	if err := c.peer.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *externalPeerDatagramPacketConn) Close() error {
	return c.peer.Close()
}

func (c *externalPeerDatagramPacketConn) LocalAddr() net.Addr {
	return c.peer.LocalAddr()
}

func (c *externalPeerDatagramPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *externalPeerDatagramPacketConn) currentReadDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline
}

func (c *externalPeerDatagramPacketConn) currentWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline
}
