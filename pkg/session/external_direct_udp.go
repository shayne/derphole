// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"github.com/shayne/derphole/pkg/transfertrace"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	externalDirectUDPTransportLabel                = "batched"
	externalDirectUDPParallelism                   = 8
	externalDirectUDPDataWireSize                  = 1384
	externalDirectUDPPacketHeaderSize              = 52
	externalDirectUDPPacketAEADOverhead            = 16
	externalDirectUDPChunkSize                     = externalDirectUDPDataWireSize - externalDirectUDPPacketHeaderSize - externalDirectUDPPacketAEADOverhead
	externalDirectUDPMaxRateMbps                   = 10_000
	externalDirectUDPInitialProbeFallbackMbps      = 150
	externalDirectUDPWait                          = 5 * time.Second
	externalDirectUDPPunchWait                     = 1200 * time.Millisecond
	externalDirectUDPHandshakeWait                 = 1500 * time.Millisecond
	externalDirectUDPStartWait                     = 30 * time.Second
	externalDirectUDPAckWait                       = 60 * time.Second
	externalDirectUDPProgressWatcherStopWait       = time.Second
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
	externalRelayPrefixDERPMaxUnacked              = 64 << 10
	externalRelayPrefixDERPSustainedMax            = 64 << 10
	externalRelayPrefixDERPHandoffMaxUnacked       = externalRelayPrefixDERPSustainedMax
	externalRelayPrefixOverlapMaxBuffered          = 8 << 20
	externalRelayPrefixDERPStartupBytes            = 4 << 20
	externalRelayPrefixDERPHandoffAckWait          = 5 * time.Second
	externalRelayPrefixDirectPrepStallWait         = 250 * time.Millisecond
	externalRelayPrefixNoProbeStartMbps            = 100
	externalRelayPrefixNoProbeCeilingMbps          = externalDirectUDPRateProbeDefaultMaxMbps
	externalRelayPrefixNoProbeLaneBasisMbps        = externalDirectUDPActiveLaneTwoMaxMbps
)

var externalDirectUDPRateProbeMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'r', 'a', 't', 'e', 'v', '1'}
var externalRelayPrefixDERPMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'p', 'r', 'e', 'f', 'v', '1'}
var peerProgressInterval = 500 * time.Millisecond
var peerProgressFinalTimeout = 2 * time.Second

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
var externalDirectUDPReceiveBlastParallelToWriterFn = probe.ReceiveBlastParallelToWriter
var externalDirectUDPReceiveBlastStreamParallelToWriterFn = probe.ReceiveBlastStreamParallelToWriter
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

var errExternalDirectUDPNoRateProbePackets = errors.New("direct UDP rate probes received no packets")

type externalDirectUDPSendPlan struct {
	probeConns                  []net.PacketConn
	remoteAddrs                 []string
	sendCfg                     probe.SendConfig
	sendSrcRecordsDirectMetrics bool
	selectedRateMbps            int
	startRateMbps               int
	rateCeilingMbps             int
	availableLanes              int
	probeRates                  []int
	sentProbeSamples            []directUDPRateProbeSample
	receivedProbeSamples        []directUDPRateProbeSample
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
type externalDirectUDPStartWaitContextKey struct{}
type externalDirectUDPAllowUnverifiedFallbackContextKey struct{}

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

func withExternalDirectUDPStartWait(ctx context.Context, wait time.Duration) context.Context {
	return context.WithValue(ctx, externalDirectUDPStartWaitContextKey{}, wait)
}

func externalDirectUDPStartWaitOverride(ctx context.Context) (time.Duration, bool) {
	wait, ok := ctx.Value(externalDirectUDPStartWaitContextKey{}).(time.Duration)
	return wait, ok
}

func externalDirectUDPStartWaitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	wait, ok := externalDirectUDPStartWaitOverride(ctx)
	if !ok {
		return context.WithTimeout(ctx, externalDirectUDPStartWait)
	}
	if wait <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, wait)
}

func withExternalDirectUDPAllowUnverifiedFallback(ctx context.Context) context.Context {
	return context.WithValue(ctx, externalDirectUDPAllowUnverifiedFallbackContextKey{}, true)
}

func externalDirectUDPAllowUnverifiedFallback(ctx context.Context) bool {
	allow, _ := ctx.Value(externalDirectUDPAllowUnverifiedFallbackContextKey{}).(bool)
	return allow
}

type externalDirectUDPBudget struct {
	RateMbps          int
	ActiveLanes       int
	ReplayWindowBytes uint64
}

type externalDirectUDPReceivePlan struct {
	probeConns                     []net.PacketConn
	remoteAddrs                    []string
	receiveDst                     io.Writer
	flushDst                       func() error
	receiveCfg                     probe.ReceiveConfig
	receiveDstRecordsDirectMetrics bool
	fastDiscard                    bool
	start                          directUDPStart
	receivedProbeSamples           []directUDPRateProbeSample
	decision                       rendezvous.Decision
	peerAddr                       net.Addr
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
	rt, err := newExternalDirectUDPSendRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	ctx, stopPeerAbort := rt.withPeerControl(ctx)
	defer stopPeerAbort()
	defer rt.notifyPeerAbortOnError(&retErr, ctx)
	defer rt.notifyPeerAbortOnLocalCancel(&retErr, ctx)
	return rt.run(ctx)
}

type externalDirectUDPSendRuntime struct {
	cfg          SendConfig
	tok          token.Token
	countedSrc   *byteCountingReadCloser
	listenerDERP key.NodePublic
	dm           *tailcfg.DERPMap
	derpClient   *derpbind.Client
	probeConn    net.PacketConn
	probeConns   []net.PacketConn
	portmaps     []publicPortmap
	pm           publicPortmap
	auth         externalPeerControlAuth
	decision     rendezvous.Decision
	subs         externalDirectUDPSendSubscriptions
	metrics      *externalTransferMetrics
	cleanupConns func()
}

func newExternalDirectUDPSendRuntime(ctx context.Context, cfg SendConfig) (*externalDirectUDPSendRuntime, error) {
	rt := &externalDirectUDPSendRuntime{cfg: sendConfigWithInferredExpectedBytes(cfg)}
	var err error
	rt.tok, err = decodeExternalDirectUDPSendToken(rt.cfg.Token)
	if err != nil {
		return nil, err
	}
	if err := rt.openSource(ctx); err != nil {
		return nil, err
	}
	if err := rt.openDERP(ctx); err != nil {
		rt.Close()
		return nil, err
	}
	if err := rt.openProbeConns(); err != nil {
		rt.Close()
		return nil, err
	}
	if err := rt.claim(ctx); err != nil {
		rt.Close()
		return nil, err
	}
	rt.subs = subscribeExternalDirectUDPSend(rt.derpClient, rt.listenerDERP)
	return rt, nil
}

func decodeExternalDirectUDPSendToken(raw string) (token.Token, error) {
	tok, err := token.Decode(raw, time.Now())
	if err != nil {
		return token.Token{}, err
	}
	if tok.Capabilities&token.CapabilityStdio == 0 {
		return token.Token{}, ErrUnknownSession
	}
	return tok, nil
}

func (rt *externalDirectUDPSendRuntime) openSource(ctx context.Context) error {
	src, err := openSendSource(ctx, rt.cfg)
	if err != nil {
		return err
	}
	rt.countedSrc = newByteCountingReadCloser(src)
	return nil
}

func (rt *externalDirectUDPSendRuntime) openDERP(ctx context.Context) error {
	rt.listenerDERP = key.NodePublicFromRaw32(mem.B(rt.tok.DERPPublic[:]))
	if rt.listenerDERP.IsZero() {
		return ErrUnknownSession
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(rt.tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return err
	}
	rt.dm = dm
	rt.derpClient = derpClient
	return nil
}

func (rt *externalDirectUDPSendRuntime) openProbeConns() error {
	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConnsFn(nil, nil, externalDirectUDPParallelism, rt.cfg.Emitter)
	if err != nil {
		return err
	}
	rt.probeConns = probeConns
	rt.portmaps = portmaps
	rt.cleanupConns = cleanupProbeConns
	rt.probeConn = probeConns[0]
	rt.pm = portmaps[0]
	return nil
}

func (rt *externalDirectUDPSendRuntime) claim(ctx context.Context) error {
	claimIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		return err
	}
	localCandidates := externalDirectUDPSendLocalCandidates(ctx, rt.cfg, rt.probeConns, rt.dm, rt.portmaps)
	claim := externalDirectUDPSendClaim(rt.tok, rt.derpClient.PublicKey(), claimIdentity.Public, len(rt.probeConns), localCandidates, rt.cfg)
	rt.auth = externalPeerControlAuthForToken(rt.tok)
	decision, err := sendClaimAndReceiveDecision(ctx, rt.derpClient, rt.listenerDERP, claim, rt.auth)
	if err != nil {
		return err
	}
	if err := validateExternalDirectUDPDecision(decision); err != nil {
		return err
	}
	rt.decision = decision
	return nil
}

func externalDirectUDPSendLocalCandidates(ctx context.Context, cfg SendConfig, probeConns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap) []string {
	if cfg.ForceRelay {
		return nil
	}
	return externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, dm, portmaps))
}

func externalDirectUDPSendClaim(tok token.Token, derpPublic key.NodePublic, quicPublic [32]byte, parallel int, localCandidates []string, cfg SendConfig) rendezvous.Claim {
	if cfg.ForceRelay {
		parallel = 0
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpPublic),
		QUICPublic:   quicPublic,
		Parallel:     parallel,
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func validateExternalDirectUDPDecision(decision rendezvous.Decision) error {
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}
	if decision.Accept == nil {
		return errors.New("accepted decision missing accept payload")
	}
	return nil
}

type externalDirectUDPSendSubscriptions struct {
	ackCh                <-chan derpbind.Packet
	abortCh              <-chan derpbind.Packet
	heartbeatCh          <-chan derpbind.Packet
	progressCh           <-chan derpbind.Packet
	readyAckCh           <-chan derpbind.Packet
	startAckCh           <-chan derpbind.Packet
	rateProbeCh          <-chan derpbind.Packet
	unsubscribeAck       func()
	unsubscribeAbort     func()
	unsubscribeHeartbeat func()
	unsubscribeProgress  func()
	unsubscribeReadyAck  func()
	unsubscribeStartAck  func()
	unsubscribeRateProbe func()
}

func (s externalDirectUDPSendSubscriptions) Close() {
	if s.unsubscribeAck != nil {
		s.unsubscribeAck()
	}
	if s.unsubscribeAbort != nil {
		s.unsubscribeAbort()
	}
	if s.unsubscribeHeartbeat != nil {
		s.unsubscribeHeartbeat()
	}
	if s.unsubscribeProgress != nil {
		s.unsubscribeProgress()
	}
	if s.unsubscribeReadyAck != nil {
		s.unsubscribeReadyAck()
	}
	if s.unsubscribeStartAck != nil {
		s.unsubscribeStartAck()
	}
	if s.unsubscribeRateProbe != nil {
		s.unsubscribeRateProbe()
	}
}

func subscribeExternalDirectUDPSend(client *derpbind.Client, listenerDERP key.NodePublic) externalDirectUDPSendSubscriptions {
	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAckOrAbortPayload(pkt.Payload)
	})
	abortCh, unsubscribeAbort := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAbortPayload(pkt.Payload)
	})
	heartbeatCh, unsubscribeHeartbeat := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isHeartbeatPayload(pkt.Payload)
	})
	progressCh, unsubscribeProgress := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isProgressPayload(pkt.Payload)
	})
	readyAckCh, unsubscribeReadyAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
	})
	startAckCh, unsubscribeStartAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartAckPayload(pkt.Payload)
	})
	rateProbeCh, unsubscribeRateProbe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPRateProbePayload(pkt.Payload)
	})
	return externalDirectUDPSendSubscriptions{
		ackCh:                ackCh,
		abortCh:              abortCh,
		heartbeatCh:          heartbeatCh,
		progressCh:           progressCh,
		readyAckCh:           readyAckCh,
		startAckCh:           startAckCh,
		rateProbeCh:          rateProbeCh,
		unsubscribeAck:       unsubscribeAck,
		unsubscribeAbort:     unsubscribeAbort,
		unsubscribeHeartbeat: unsubscribeHeartbeat,
		unsubscribeProgress:  unsubscribeProgress,
		unsubscribeReadyAck:  unsubscribeReadyAck,
		unsubscribeStartAck:  unsubscribeStartAck,
		unsubscribeRateProbe: unsubscribeRateProbe,
	}
}

func externalPeerProgressConsumer(metrics *externalTransferMetrics, callback func(int64, int64)) func(peerProgress, time.Time) {
	return func(progress peerProgress, at time.Time) {
		if metrics != nil {
			metrics.RecordPeerProgress(progress.BytesReceived, progress.TransferElapsedMS, at)
		}
		if callback != nil {
			callback(progress.BytesReceived, progress.TransferElapsedMS)
		}
	}
}

func peerProgressForTransfer(bytesReceived int64, firstByteAt time.Time, now time.Time, sequence uint64) peerProgress {
	var elapsedMS int64
	if !firstByteAt.IsZero() && now.After(firstByteAt) {
		elapsedMS = now.Sub(firstByteAt).Milliseconds()
	}
	return *newPeerProgress(bytesReceived, elapsedMS, sequence)
}

func sendPeerProgressLoop(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth) {
	ticker := time.NewTicker(peerProgressInterval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case now := <-ticker.C:
			sequence = sendPeerProgressSnapshot(ctx, client, peerDERP, bytesReceived, firstByteAt, auth, sequence, now)
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), peerProgressFinalTimeout)
			_ = sendPeerProgressSnapshot(finalCtx, client, peerDERP, bytesReceived, firstByteAt, auth, sequence, time.Now())
			cancel()
			return
		}
	}
}

func sendPeerProgressSnapshot(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived func() int64, firstByteAt func() time.Time, auth externalPeerControlAuth, sequence uint64, now time.Time) uint64 {
	if firstByteAt == nil {
		return sequence
	}
	firstByte := firstByteAt()
	if firstByte.IsZero() {
		return sequence
	}
	sequence++
	var received int64
	if bytesReceived != nil {
		received = bytesReceived()
	}
	progress := peerProgressForTransfer(received, firstByte, now, sequence)
	_ = sendPeerProgress(ctx, client, peerDERP, progress.BytesReceived, progress.TransferElapsedMS, progress.Sequence, auth)
	return sequence
}

func watchPeerProgress(ctx context.Context, ch <-chan derpbind.Packet, auth externalPeerControlAuth, consume func(peerProgress, time.Time)) error {
	var lastSequence uint64
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return net.ErrClosed
			}
			progress, handled, err := verifyPeerProgressPacket(pkt, auth, &lastSequence)
			if handled {
				continue
			}
			if err != nil {
				return err
			}
			if consume != nil {
				consume(progress, time.Now())
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func startPeerProgressWatcher(ctx context.Context, progressCh <-chan derpbind.Packet, auth externalPeerControlAuth, metrics *externalTransferMetrics, progress func(int64, int64), emitter *telemetry.Emitter) func() {
	progressCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	consume := externalPeerProgressConsumer(metrics, progress)
	go func() {
		done <- watchPeerProgress(progressCtx, progressCh, auth, consume)
	}()
	return func() {
		cancel()
		select {
		case err := <-done:
			emitPeerProgressWatcherStopDebug(emitter, err)
		case <-time.After(externalDirectUDPProgressWatcherStopWait):
			if emitter != nil {
				emitter.Debug("udp-peer-progress-watch-stop-timeout")
			}
		}
	}
}

func emitPeerProgressWatcherStopDebug(emitter *telemetry.Emitter, err error) {
	if emitter == nil || err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	emitter.Debug("udp-peer-progress-watch-error=" + err.Error())
}

func (rt *externalDirectUDPSendRuntime) withPeerControl(ctx context.Context) (context.Context, func()) {
	return withPeerControlContext(ctx, rt.derpClient, rt.listenerDERP, rt.subs.abortCh, rt.subs.heartbeatCh, rt.countedSrc.Count, rt.auth)
}

func (rt *externalDirectUDPSendRuntime) notifyPeerAbortOnError(retErr *error, ctx context.Context) {
	notifyPeerAbortOnError(retErr, ctx, rt.derpClient, rt.listenerDERP, rt.countedSrc.Count, rt.auth)
}

func (rt *externalDirectUDPSendRuntime) notifyPeerAbortOnLocalCancel(retErr *error, ctx context.Context) {
	notifyPeerAbortOnLocalCancel(retErr, ctx, rt.derpClient, rt.listenerDERP, rt.countedSrc.Count, rt.auth)
}

func (rt *externalDirectUDPSendRuntime) run(ctx context.Context) error {
	rt.metrics = newExternalTransferMetricsWithTrace(time.Now(), rt.cfg.Trace, transfertrace.RoleSend)
	rt.metrics.DeferSendCompleteUntilPeerAck()
	ctx = withExternalTransferMetrics(ctx, rt.metrics)
	pathEmitter := newTransportPathEmitter(rt.cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	pathEmitter.SuppressWatcherDirect()
	tr, err := rt.startTransport(ctx, pathEmitter)
	if err != nil {
		rt.metrics.SetError(err)
		return err
	}
	defer tr.Close()

	sendErr := rt.send(ctx, tr)
	if sendErr != nil {
		return sendErr
	}
	if err := waitForPeerAckWithTimeout(ctx, rt.subs.ackCh, rt.countedSrc.Count(), externalDirectUDPAckWait, rt.auth); err != nil {
		rt.metrics.SetError(err)
		return err
	}
	completeExternalSendMetricsAfterPeerAck(rt.metrics, rt.countedSrc.Count(), time.Now())
	pathEmitter.Complete(tr.manager)
	return nil
}

type externalDirectUDPSendTransport struct {
	ctx              context.Context
	cancel           context.CancelFunc
	manager          *transport.Manager
	cleanup          func()
	pathEmitter      *transportPathEmitter
	relayOnly        bool
	remoteCandidates []net.Addr
	punchCancel      context.CancelFunc
}

func (rt *externalDirectUDPSendRuntime) startTransport(ctx context.Context, pathEmitter *transportPathEmitter) (externalDirectUDPSendTransport, error) {
	transportCtx, transportCancel := context.WithCancel(ctx)
	relayOnly := rt.cfg.ForceRelay || externalDecisionRelayOnly(rt.decision)
	localCandidates := parseCandidateStrings(rt.decision.Accept.Candidates)
	manager, cleanup, err := startExternalTransportManager(transportCtx, rt.tok, rt.probeConn, rt.dm, rt.derpClient, rt.listenerDERP, localCandidates, rt.pm, relayOnly)
	if err != nil {
		transportCancel()
		return externalDirectUDPSendTransport{}, err
	}
	pathEmitter.Watch(transportCtx, manager)
	pathEmitter.Flush(manager)
	seedAcceptedDecisionCandidates(transportCtx, manager, rt.decision)
	tr := externalDirectUDPSendTransport{
		ctx:              transportCtx,
		cancel:           transportCancel,
		manager:          manager,
		cleanup:          cleanup,
		pathEmitter:      pathEmitter,
		relayOnly:        relayOnly,
		remoteCandidates: parseRemoteCandidateStrings(rt.decision.Accept.Candidates),
		punchCancel:      func() {},
	}
	if !relayOnly {
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		tr.punchCancel = punchCancel
		externalDirectUDPStartPunching(punchCtx, rt.probeConns, tr.remoteCandidates)
	}
	return tr, nil
}

func (tr externalDirectUDPSendTransport) Close() {
	if tr.punchCancel != nil {
		tr.punchCancel()
	}
	if tr.cleanup != nil {
		tr.cleanup()
	}
	if tr.cancel != nil {
		tr.cancel()
	}
}

func (rt *externalDirectUDPSendRuntime) send(ctx context.Context, tr externalDirectUDPSendTransport) error {
	if tr.relayOnly {
		return sendExternalRelayUDPWithPeerProgress(ctx, rt.countedSrc, tr.manager, rt.tok, rt.subs.progressCh, rt.cfg)
	}
	return sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
		src:              rt.countedSrc,
		tok:              rt.tok,
		decision:         rt.decision,
		derpClient:       rt.derpClient,
		listenerDERP:     rt.listenerDERP,
		transportCtx:     tr.ctx,
		transportManager: tr.manager,
		pathEmitter:      tr.pathEmitter,
		punchCancel:      tr.punchCancel,
		probeConn:        rt.probeConn,
		probeConns:       rt.probeConns,
		remoteCandidates: tr.remoteCandidates,
		readyAckCh:       rt.subs.readyAckCh,
		startAckCh:       rt.subs.startAckCh,
		rateProbeCh:      rt.subs.rateProbeCh,
		progressCh:       rt.subs.progressCh,
		cfg:              rt.cfg,
	})
}

func (rt *externalDirectUDPSendRuntime) Close() {
	rt.subs.Close()
	if rt.cleanupConns != nil {
		rt.cleanupConns()
	}
	if rt.derpClient != nil {
		_ = rt.derpClient.Close()
	}
	if rt.countedSrc != nil {
		_ = rt.countedSrc.Close()
	}
}

func externalDirectUDPActivateDirectPath(pathEmitter *transportPathEmitter, transportManager *transport.Manager, punchCancel context.CancelFunc) {
	if pathEmitter != nil {
		pathEmitter.SuppressRelayRegression()
		pathEmitter.Emit(StateTryingDirect)
	}
	if transportManager != nil {
		transportManager.StopDirectReads()
	}
	externalDirectUDPStopPunchingForBlast(punchCancel)
}

func externalDirectUDPBeginTryingDirect(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) {
	if metrics != nil {
		metrics.SetPhase(transfertrace.PhaseDirectPrepare, string(StateTryingDirect))
	}
	if pathEmitter != nil {
		pathEmitter.Emit(StateTryingDirect)
	}
}

func externalDirectUDPMarkDirectValidated(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) {
	now := time.Now()
	if metrics != nil {
		metrics.MarkDirectValidated(now)
		metrics.SetPhase(transfertrace.PhaseDirectExecute, string(StateDirect))
	}
	if pathEmitter != nil {
		pathEmitter.ResumeWatcherDirect()
		pathEmitter.SuppressRelayRegression()
		pathEmitter.Emit(StateDirect)
	}
}

func externalDirectUDPValidateDirectProbe(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics, samples []directUDPRateProbeSample) {
	if externalDirectUDPHasPositiveProbeProgress(samples) {
		externalDirectUDPMarkDirectValidated(pathEmitter, metrics)
	}
}

func externalDirectUDPValidateDirectProgress(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics, stats probe.TransferStats) {
	if stats.BytesSent > 0 || stats.BytesReceived > 0 {
		externalDirectUDPMarkDirectValidated(pathEmitter, metrics)
	}
}

func externalDirectUDPInstallSendProgressValidation(plan *externalDirectUDPSendPlan, pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) {
	if plan == nil {
		return
	}
	progress := plan.sendCfg.Progress
	plan.sendCfg.Progress = func(stats probe.TransferStats) {
		if progress != nil {
			progress(stats)
		}
		externalDirectUDPValidateDirectProgress(pathEmitter, metrics, stats)
	}
}

func externalDirectUDPInstallReceiveProgressValidation(plan *externalDirectUDPReceivePlan, pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) {
	if plan == nil {
		return
	}
	progress := plan.receiveCfg.Progress
	plan.receiveCfg.Progress = func(stats probe.TransferStats) {
		if progress != nil {
			progress(stats)
		}
		externalDirectUDPValidateDirectProgress(pathEmitter, metrics, stats)
	}
}

func externalDirectUDPValidateDirectMetricsProgress(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics) {
	if metrics != nil && metrics.DirectBytes() > 0 {
		externalDirectUDPMarkDirectValidated(pathEmitter, metrics)
	}
}

func externalDirectUDPMarkDirectFallbackRelay(pathEmitter *transportPathEmitter, metrics *externalTransferMetrics, err error) {
	if err == nil {
		return
	}
	now := time.Now()
	if metrics != nil {
		metrics.SetFallbackReason(err.Error(), now)
		metrics.SetPhase(transfertrace.PhaseRelay, string(StateDirectFallbackRelay))
	}
	if pathEmitter != nil {
		pathEmitter.Emit(StateDirectFallbackRelay)
	}
}

func externalPrepareDirectUDPSend(ctx context.Context, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, cfg SendConfig) (externalDirectUDPSendPlan, error) {
	plan := externalDirectUDPSendPlan{}
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.SetPhase(transfertrace.PhaseDirectPrepare, string(StateTryingDirect))
	auth := externalPeerControlAuthForToken(tok)
	readyAck, err := externalDirectUDPSendReadyHandshake(ctx, derpClient, listenerDERP, peerAddr, readyAckCh, auth)
	if err != nil {
		return plan, err
	}
	probeConns, remoteAddrs, effectiveTransportCaps, receiverConstrained, err := externalDirectUDPSendRemoteSetup(ctx, probeConns, remoteCandidates, peerAddr, readyAck, cfg.Emitter)
	if err != nil {
		return plan, err
	}
	availableLanes := len(probeConns)
	rateState := externalDirectUDPInitialSendRateState()
	emitExternalDirectUDPSendInitialDebug(cfg.Emitter, peerAddr, remoteAddrs, len(probeConns), rateState.maxRateMbps, readyAck, receiverConstrained)
	directExpectedBytes, relayPrefixOffset, err := externalDirectUDPSendWaitHandoffExpectedBytes(ctx, peerAddr, cfg.StdioExpectedBytes)
	if err != nil {
		return plan, err
	}
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return plan, err
	}
	policyActiveLaneCap := externalDirectUDPActiveLaneCapForPolicy(cfg.ParallelPolicy, len(probeConns))
	policyActiveLaneCap = externalDirectUDPConstrainedReceiverLaneCap(readyAck, policyActiveLaneCap, len(probeConns))
	sendCfg := externalDirectUDPNewSendConfig(tok, packetAEAD, readyAck, policyActiveLaneCap, len(probeConns), rateState)
	emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, directExpectedBytes)
	start, rateProbeAuth, err := externalDirectUDPSendStart(ctx, tok, cfg, directExpectedBytes, relayPrefixOffset, sendCfg.StripedBlast, &rateState)
	if err != nil {
		return plan, err
	}
	if err := externalDirectUDPSendStartHandshake(ctx, derpClient, listenerDERP, peerAddr, startAckCh, start, auth); err != nil {
		return plan, err
	}
	setExternalTransferMetricsProbePhase(metrics, len(rateState.probeRates))
	rateState, sendCfg, err = externalDirectUDPResolveSendRates(ctx, probeConns, remoteAddrs, rateProbeCh, auth, rateProbeAuth, readyAck, effectiveTransportCaps, sendCfg, rateState)
	if err != nil {
		return plan, err
	}
	setExternalTransferMetricsProbeSummary(metrics, rateState.sentProbeSamples, rateState.probeResult.Samples)
	retainedLanes := externalDirectUDPSendRetainedLanes(rateState, sendCfg, policyActiveLaneCap, len(probeConns), effectiveTransportCaps)
	if retainedLanes == 0 {
		err := errors.New("direct UDP established without active send lanes")
		return plan, err
	}
	if retainedLanes < len(probeConns) {
		probeConns = probeConns[:retainedLanes]
		remoteAddrs = remoteAddrs[:retainedLanes]
	}
	rateState, sendCfg = externalDirectUDPFinalizeSendRates(rateState, sendCfg, len(probeConns))
	emitExternalDirectUDPSendFinalDebug(cfg.Emitter, probeConns, sendCfg, rateState)
	metrics.SetDirectPlan(rateState.selectedRateMbps, rateState.activeRateMbps, len(probeConns), availableLanes)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")

	plan.probeConns = probeConns
	plan.remoteAddrs = remoteAddrs
	plan.sendCfg = sendCfg
	plan.selectedRateMbps = rateState.selectedRateMbps
	plan.startRateMbps = rateState.activeRateMbps
	plan.rateCeilingMbps = rateState.rateCeilingMbps
	plan.availableLanes = availableLanes
	plan.probeRates = rateState.probeRates
	plan.sentProbeSamples = rateState.sentProbeSamples
	plan.receivedProbeSamples = rateState.probeResult.Samples
	return plan, nil
}

type externalDirectUDPSendRateState struct {
	maxRateMbps               int
	activeRateMbps            int
	selectedRateMbps          int
	rateCeilingMbps           int
	probeRates                []int
	useRelayPrefixNoProbePath bool
	sentProbeSamples          []directUDPRateProbeSample
	probeResult               directUDPRateProbeResult
}

func externalDirectUDPInitialSendRateState() externalDirectUDPSendRateState {
	activeRateMbps := externalDirectUDPInitialProbeFallbackMbps
	maxRateMbps := externalDirectUDPMaxRateMbps
	return externalDirectUDPSendRateState{
		maxRateMbps:      maxRateMbps,
		activeRateMbps:   activeRateMbps,
		selectedRateMbps: activeRateMbps,
		rateCeilingMbps:  maxRateMbps,
	}
}

func externalDirectUDPSendReadyHandshake(ctx context.Context, derpClient *derpbind.Client, listenerDERP key.NodePublic, peerAddr net.Addr, readyAckCh <-chan derpbind.Packet, auth externalPeerControlAuth) (directUDPReadyAck, error) {
	externalTransferTracef("direct-udp-send-ready-send addr=%v", peerAddr)
	if err := sendAuthenticatedEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeDirectUDPReady}, auth); err != nil {
		return directUDPReadyAck{}, err
	}
	externalTransferTracef("direct-udp-send-ready-wait-ack addr=%v", peerAddr)
	readyAck, err := externalDirectUDPWaitReadyAckFn(ctx, readyAckCh, auth)
	if err != nil {
		return directUDPReadyAck{}, err
	}
	externalTransferTracef("direct-udp-send-ready-ack addr=%v fast-discard=%v", peerAddr, readyAck.FastDiscard)
	return readyAck, nil
}

func externalDirectUDPSendRemoteSetup(ctx context.Context, probeConns []net.PacketConn, remoteCandidates []net.Addr, peerAddr net.Addr, readyAck directUDPReadyAck, emitter *telemetry.Emitter) ([]net.PacketConn, []string, probe.TransportCaps, bool, error) {
	externalTransferTracef("direct-udp-send-remote-addrs-start addr=%v candidates=%d conns=%d", peerAddr, len(remoteCandidates), len(probeConns))
	remoteAddrs := externalDirectUDPSelectRemoteAddrs(ctx, probeConns, remoteCandidates, peerAddr, emitter)
	externalTransferTracef("direct-udp-send-remote-addrs-done addr=%v selected=%d", peerAddr, len(remoteAddrs))
	probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
	if len(probeConns) == 0 {
		return nil, nil, probe.TransportCaps{}, false, errors.New("direct UDP established without usable remote addresses")
	}
	localTransportCaps := externalDirectUDPPreviewTransportCaps(probeConns[0], externalDirectUDPTransportLabel)
	effectiveTransportCaps := externalDirectUDPEffectiveSenderCaps(localTransportCaps, readyAck)
	return probeConns, remoteAddrs, effectiveTransportCaps, externalDirectUDPConstrainedReceiver(readyAck), nil
}

func emitExternalDirectUDPSendInitialDebug(emitter *telemetry.Emitter, peerAddr net.Addr, remoteAddrs []string, lanes int, maxRateMbps int, readyAck directUDPReadyAck, receiverConstrained bool) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-blast=true")
	emitter.Debug("udp-lanes=" + strconv.Itoa(lanes))
	emitter.Debug("udp-rate-max-mbps=" + strconv.Itoa(maxRateMbps))
	emitter.Debug("udp-adaptive-rate=true")
	emitter.Debug("udp-repair-payloads=" + strconv.FormatBool(externalDirectUDPRepairPayloads))
	emitter.Debug("udp-tail-replay-bytes=" + strconv.Itoa(externalDirectUDPTailReplayBytes))
	emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPStreamFECGroupSize))
	emitter.Debug("udp-fast-discard=" + strconv.FormatBool(readyAck.FastDiscard))
	if receiverConstrained {
		emitter.Debug("udp-receiver-constrained=true")
	}
	if peerAddr != nil {
		emitter.Debug("udp-direct-addr=" + peerAddr.String())
	}
	emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
}

func externalDirectUDPSendWaitHandoffExpectedBytes(ctx context.Context, peerAddr net.Addr, expectedBytes int64) (int64, int64, error) {
	externalTransferTracef("direct-udp-send-handoff-ready-signal addr=%v", peerAddr)
	signalExternalDirectUDPHandoffReady(ctx)
	externalTransferTracef("direct-udp-send-handoff-proceed-wait addr=%v", peerAddr)
	if err := waitExternalDirectUDPHandoffProceed(ctx); err != nil {
		return 0, 0, err
	}
	externalTransferTracef("direct-udp-send-handoff-proceed addr=%v", peerAddr)
	handoffWatermark := int64(0)
	if watermark, ok := externalDirectUDPHandoffProceedWatermark(ctx); ok {
		handoffWatermark = watermark
	}
	return externalDirectUDPRemainingExpectedBytes(expectedBytes, handoffWatermark), handoffWatermark, nil
}

func externalDirectUDPNewSendConfig(tok token.Token, packetAEAD cipher.AEAD, readyAck directUDPReadyAck, policyActiveLaneCap int, lanes int, rateState externalDirectUDPSendRateState) probe.SendConfig {
	stripedDecisionLanes := externalDirectUDPStripedDecisionLanes(lanes, policyActiveLaneCap)
	return probe.SendConfig{
		Blast:                    true,
		Transport:                externalDirectUDPTransportLabel,
		ChunkSize:                externalDirectUDPChunkSize,
		RateMbps:                 rateState.activeRateMbps,
		RateCeilingMbps:          rateState.maxRateMbps,
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
		MinActiveLanes:           externalDirectUDPConstrainedReceiverMinActiveLanes(readyAck, lanes),
	}
}

func externalDirectUDPStripedDecisionLanes(lanes int, policyActiveLaneCap int) int {
	if policyActiveLaneCap > 0 && policyActiveLaneCap < lanes {
		return policyActiveLaneCap
	}
	return lanes
}

func externalDirectUDPSendStart(ctx context.Context, tok token.Token, cfg SendConfig, directExpectedBytes int64, relayPrefixOffset int64, stripedBlast bool, rateState *externalDirectUDPSendRateState) (directUDPStart, externalDirectUDPRateProbeAuth, error) {
	start := externalDirectUDPStreamStart(rateState.maxRateMbps, directExpectedBytes)
	if relayPrefixOffset > 0 {
		start.RelayPrefixOffset = relayPrefixOffset
	}
	rateState.probeRates = append([]int(nil), start.ProbeRates...)
	rateState.useRelayPrefixNoProbePath = externalDirectUDPUseRelayPrefixNoProbePath(ctx, cfg.skipDirectUDPRateProbes, rateState.probeRates)
	if rateState.useRelayPrefixNoProbePath {
		start.ProbeRates = nil
		rateState.probeRates = nil
		externalTransferTracef("direct-udp-send-rate-probe-skipped reason=%s", externalDirectUDPSendProbeSkipReason(cfg))
	}
	rateProbeAuth, err := externalDirectUDPSendRateProbeAuth(tok, &start, rateState.probeRates)
	start.StripedBlast = stripedBlast
	return start, rateProbeAuth, err
}

func externalDirectUDPSendProbeSkipReason(cfg SendConfig) string {
	if cfg.skipDirectUDPRateProbes {
		return "relay-prefix-upgrade"
	}
	return "relay-prefix-small-remaining"
}

func externalDirectUDPSendRateProbeAuth(tok token.Token, start *directUDPStart, probeRates []int) (externalDirectUDPRateProbeAuth, error) {
	if len(probeRates) == 0 {
		return externalDirectUDPRateProbeAuth{}, nil
	}
	rateProbeAuth, nonce, err := newExternalDirectUDPRateProbeAuth(tok)
	if err != nil {
		return externalDirectUDPRateProbeAuth{}, err
	}
	start.ProbeNonce = nonce
	return rateProbeAuth, nil
}

func externalDirectUDPSendStartHandshake(ctx context.Context, derpClient *derpbind.Client, listenerDERP key.NodePublic, peerAddr net.Addr, startAckCh <-chan derpbind.Packet, start directUDPStart, auth externalPeerControlAuth) error {
	externalTransferTracef("direct-udp-send-start-send addr=%v", peerAddr)
	if err := sendAuthenticatedEnvelope(ctx, derpClient, listenerDERP, envelope{
		Type:           envelopeDirectUDPStart,
		DirectUDPStart: &start,
	}, auth); err != nil {
		return err
	}
	externalTransferTracef("direct-udp-send-start-wait-ack addr=%v", peerAddr)
	if err := externalDirectUDPWaitStartAckFn(ctx, startAckCh, auth); err != nil {
		return err
	}
	externalTransferTracef("direct-udp-send-start-ack addr=%v", peerAddr)
	signalExternalDirectUDPDirectReady(ctx)
	return nil
}

func externalDirectUDPResolveSendRates(ctx context.Context, probeConns []net.PacketConn, remoteAddrs []string, rateProbeCh <-chan derpbind.Packet, auth externalPeerControlAuth, rateProbeAuth externalDirectUDPRateProbeAuth, readyAck directUDPReadyAck, effectiveTransportCaps probe.TransportCaps, sendCfg probe.SendConfig, rateState externalDirectUDPSendRateState) (externalDirectUDPSendRateState, probe.SendConfig, error) {
	if len(rateState.probeRates) > 0 {
		return externalDirectUDPResolveProbedSendRates(ctx, probeConns, remoteAddrs, rateProbeCh, auth, rateProbeAuth, readyAck, effectiveTransportCaps, sendCfg, rateState)
	}
	if rateState.useRelayPrefixNoProbePath {
		return externalDirectUDPResolveNoProbeSendRates(readyAck, sendCfg, rateState)
	}
	return rateState, sendCfg, nil
}

func setExternalTransferMetricsProbePhase(metrics *externalTransferMetrics, probeRates int) {
	if probeRates == 0 {
		return
	}
	metrics.SetPhase(transfertrace.PhaseDirectProbe, string(StateTryingDirect))
}

func setExternalTransferMetricsProbeSummary(metrics *externalTransferMetrics, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) {
	if len(sent) == 0 && len(received) == 0 {
		return
	}
	metrics.SetProbeSummary("done", externalDirectUDPFormatRateProbeSamples(sent, received))
}

func externalDirectUDPResolveProbedSendRates(ctx context.Context, probeConns []net.PacketConn, remoteAddrs []string, rateProbeCh <-chan derpbind.Packet, auth externalPeerControlAuth, rateProbeAuth externalDirectUDPRateProbeAuth, readyAck directUDPReadyAck, effectiveTransportCaps probe.TransportCaps, sendCfg probe.SendConfig, rateState externalDirectUDPSendRateState) (externalDirectUDPSendRateState, probe.SendConfig, error) {
	sentProbeSamples, probeResult, err := externalDirectUDPSendRunRateProbes(ctx, probeConns, remoteAddrs, rateState.probeRates, rateProbeCh, auth, rateProbeAuth)
	if err != nil {
		return rateState, sendCfg, err
	}
	rateState.sentProbeSamples = sentProbeSamples
	rateState.probeResult = probeResult
	if !externalDirectUDPHasPositiveProbeProgress(probeResult.Samples) {
		return rateState, sendCfg, errExternalDirectUDPNoRateProbePackets
	}
	rateState.selectedRateMbps = externalDirectUDPSelectInitialRateMbps(rateState.maxRateMbps, sentProbeSamples, probeResult.Samples)
	rateState.rateCeilingMbps = externalDirectUDPSelectRateCeilingMbps(rateState.maxRateMbps, rateState.selectedRateMbps, sentProbeSamples, probeResult.Samples)
	probeLimit := externalDirectUDPSenderProbeRateLimit(effectiveTransportCaps, sentProbeSamples, probeResult.Samples)
	rateState.rateCeilingMbps = externalDirectUDPSendApplyProbeCeiling(effectiveTransportCaps, rateState.rateCeilingMbps, probeLimit)
	rateState.selectedRateMbps = externalDirectUDPClampSelectedRate(rateState.selectedRateMbps, rateState.rateCeilingMbps)
	rateState.activeRateMbps = externalDirectUDPDataStartRateMbpsForProbeSamples(rateState.selectedRateMbps, rateState.rateCeilingMbps, sentProbeSamples, probeResult.Samples)
	rateState.activeRateMbps = externalDirectUDPClampDataStartRate(rateState.selectedRateMbps, rateState.activeRateMbps, rateState.rateCeilingMbps, len(probeConns), sendCfg.StripedBlast)
	rateState.activeRateMbps = externalDirectUDPSenderStartRateCap(effectiveTransportCaps, rateState.selectedRateMbps, rateState.activeRateMbps)
	rateState.activeRateMbps = externalDirectUDPSenderApplyProbeRateLimit(rateState.activeRateMbps, probeLimit)
	rateState.activeRateMbps = externalDirectUDPConstrainedReceiverStartRate(readyAck, rateState.activeRateMbps)
	sendCfg.RateMbps = rateState.activeRateMbps
	sendCfg.RateCeilingMbps = rateState.rateCeilingMbps
	sendCfg.RateExplorationCeilingMbps = externalDirectUDPSendExplorationCeiling(rateState, effectiveTransportCaps, probeLimit)
	sendCfg.StreamReplayWindowBytes = externalDirectUDPDataPathBudget(rateState.selectedRateMbps, rateState.activeRateMbps, rateState.rateCeilingMbps, len(probeConns), sendCfg.StripedBlast).ReplayWindowBytes
	return rateState, sendCfg, nil
}

func externalDirectUDPSendRunRateProbes(ctx context.Context, probeConns []net.PacketConn, remoteAddrs []string, probeRates []int, rateProbeCh <-chan derpbind.Packet, auth externalPeerControlAuth, rateProbeAuth externalDirectUDPRateProbeAuth) ([]directUDPRateProbeSample, directUDPRateProbeResult, error) {
	externalTransferTracef("direct-udp-send-rate-probe-start rates=%s", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(probeRates)), ","), "[]"))
	sentProbeSamples, err := externalDirectUDPSendRateProbesParallelFn(ctx, probeConns, remoteAddrs, probeRates, rateProbeAuth)
	if err != nil {
		externalTransferTracef("direct-udp-send-rate-probe-done err=%v", err)
		return nil, directUDPRateProbeResult{}, err
	}
	probeResult, err := externalDirectUDPWaitRateProbeFn(ctx, rateProbeCh, auth)
	if err != nil {
		externalTransferTracef("direct-udp-send-rate-probe-done err=%v", err)
		return nil, directUDPRateProbeResult{}, err
	}
	externalTransferTracef("direct-udp-send-rate-probe-done err=<nil> samples=%d", len(probeResult.Samples))
	return sentProbeSamples, probeResult, nil
}

func externalDirectUDPSendApplyProbeCeiling(effectiveTransportCaps probe.TransportCaps, rateCeilingMbps int, probeLimit externalDirectUDPSenderProbeRateLimitResult) int {
	rateCeilingMbps = externalDirectUDPSenderRateCeilingCap(effectiveTransportCaps, rateCeilingMbps)
	if probeLimit.CeilingMbps > 0 && (rateCeilingMbps <= 0 || probeLimit.CeilingMbps < rateCeilingMbps) {
		return probeLimit.CeilingMbps
	}
	return rateCeilingMbps
}

func externalDirectUDPClampSelectedRate(selectedRateMbps int, rateCeilingMbps int) int {
	if rateCeilingMbps > 0 && selectedRateMbps > rateCeilingMbps {
		return rateCeilingMbps
	}
	return selectedRateMbps
}

func externalDirectUDPSendExplorationCeiling(rateState externalDirectUDPSendRateState, effectiveTransportCaps probe.TransportCaps, probeLimit externalDirectUDPSenderProbeRateLimitResult) int {
	ceiling := externalDirectUDPDataExplorationCeilingMbpsForProbeSamples(rateState.maxRateMbps, rateState.selectedRateMbps, rateState.rateCeilingMbps, rateState.sentProbeSamples, rateState.probeResult.Samples)
	ceiling = externalDirectUDPSenderExplorationCeilingCap(effectiveTransportCaps, ceiling)
	if probeLimit.CeilingMbps > 0 && ceiling > probeLimit.CeilingMbps {
		return probeLimit.CeilingMbps
	}
	return ceiling
}

func externalDirectUDPResolveNoProbeSendRates(readyAck directUDPReadyAck, sendCfg probe.SendConfig, rateState externalDirectUDPSendRateState) (externalDirectUDPSendRateState, probe.SendConfig, error) {
	rateState.rateCeilingMbps = externalDirectUDPRelayPrefixNoProbeRateCeilingMbps(rateState.maxRateMbps)
	rateState.selectedRateMbps = externalRelayPrefixNoProbeStartMbps
	rateState.selectedRateMbps = externalDirectUDPClampSelectedRate(rateState.selectedRateMbps, rateState.rateCeilingMbps)
	rateState.activeRateMbps = externalDirectUDPConstrainedReceiverStartRate(readyAck, rateState.selectedRateMbps)
	laneBasisMbps := externalDirectUDPNoProbeLaneBasisMbps(rateState.activeRateMbps, rateState.rateCeilingMbps)
	sendCfg.RateMbps = rateState.activeRateMbps
	sendCfg.RateCeilingMbps = rateState.rateCeilingMbps
	sendCfg.StreamReplayWindowBytes = externalDirectUDPReplayWindowBytesForRate(laneBasisMbps)
	return rateState, sendCfg, nil
}

func externalDirectUDPSendRetainedLanes(rateState externalDirectUDPSendRateState, sendCfg probe.SendConfig, policyActiveLaneCap int, lanes int, effectiveTransportCaps probe.TransportCaps) int {
	retainedLanes := externalDirectUDPBaseRetainedLanes(rateState, sendCfg, lanes)
	retainedLanes = externalDirectUDPApplyNoProbeRetainedLanes(retainedLanes, rateState, lanes)
	retainedLanes = externalDirectUDPApplyPolicyRetainedLanes(retainedLanes, policyActiveLaneCap)
	return externalDirectUDPSenderRetainedLaneCap(effectiveTransportCaps, rateState.selectedRateMbps, rateState.activeRateMbps, rateState.rateCeilingMbps, retainedLanes)
}

func externalDirectUDPBaseRetainedLanes(rateState externalDirectUDPSendRateState, sendCfg probe.SendConfig, lanes int) int {
	if len(rateState.sentProbeSamples) > 0 || len(rateState.probeResult.Samples) > 0 {
		return externalDirectUDPDataPathBudget(rateState.selectedRateMbps, rateState.activeRateMbps, rateState.rateCeilingMbps, lanes, sendCfg.StripedBlast).ActiveLanes
	}
	laneRateBasisMbps := externalDirectUDPDataLaneRateBasisMbps(rateState.activeRateMbps, rateState.rateCeilingMbps, rateState.probeRates)
	return externalDirectUDPRetainedLanesForRate(laneRateBasisMbps, lanes, sendCfg.StripedBlast)
}

func externalDirectUDPApplyNoProbeRetainedLanes(retainedLanes int, rateState externalDirectUDPSendRateState, lanes int) int {
	if !rateState.useRelayPrefixNoProbePath {
		return retainedLanes
	}
	noProbeLanes := externalDirectUDPNoProbeActiveLanes(rateState.activeRateMbps, rateState.rateCeilingMbps, lanes)
	if noProbeLanes > 0 && (retainedLanes == 0 || noProbeLanes < retainedLanes) {
		return noProbeLanes
	}
	return retainedLanes
}

func externalDirectUDPApplyPolicyRetainedLanes(retainedLanes int, policyActiveLaneCap int) int {
	if policyActiveLaneCap > 0 && (retainedLanes == 0 || policyActiveLaneCap < retainedLanes) {
		return policyActiveLaneCap
	}
	return retainedLanes
}

func externalDirectUDPFinalizeSendRates(rateState externalDirectUDPSendRateState, sendCfg probe.SendConfig, lanes int) (externalDirectUDPSendRateState, probe.SendConfig) {
	rateState.rateCeilingMbps = externalDirectUDPDataRateCeilingMbps(rateState.rateCeilingMbps, rateState.activeRateMbps, lanes)
	sendCfg.RateCeilingMbps = rateState.rateCeilingMbps
	if sendCfg.RateExplorationCeilingMbps > 0 {
		sendCfg.RateExplorationCeilingMbps = externalDirectUDPDataRateCeilingMbps(sendCfg.RateExplorationCeilingMbps, rateState.activeRateMbps, lanes)
		if sendCfg.RateExplorationCeilingMbps < rateState.rateCeilingMbps {
			sendCfg.RateExplorationCeilingMbps = rateState.rateCeilingMbps
		}
	}
	return rateState, sendCfg
}

func emitExternalDirectUDPSendFinalDebug(emitter *telemetry.Emitter, probeConns []net.PacketConn, sendCfg probe.SendConfig, rateState externalDirectUDPSendRateState) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-striped-available-lanes=" + strconv.Itoa(len(probeConns)))
	emitter.Debug("udp-striped-decision=" + strconv.FormatBool(sendCfg.StripedBlast))
	emitter.Debug("udp-striped-blast=" + strconv.FormatBool(sendCfg.StripedBlast))
	emitter.Debug("udp-rate-ceiling-mbps=" + strconv.Itoa(rateState.rateCeilingMbps))
	if sendCfg.RateExplorationCeilingMbps > rateState.rateCeilingMbps {
		emitter.Debug("udp-rate-exploration-ceiling-mbps=" + strconv.Itoa(sendCfg.RateExplorationCeilingMbps))
	}
	if len(rateState.probeRates) > 0 {
		emitter.Debug("udp-rate-probe-rates=" + strings.Trim(strings.Join(strings.Fields(fmt.Sprint(rateState.probeRates)), ","), "[]"))
		emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(rateState.sentProbeSamples, rateState.probeResult.Samples))
	}
	emitter.Debug("udp-rate-selected-mbps=" + strconv.Itoa(rateState.selectedRateMbps))
	emitter.Debug("udp-rate-start-mbps=" + strconv.Itoa(rateState.activeRateMbps))
	emitter.Debug("udp-active-lanes-selected=" + strconv.Itoa(len(probeConns)))
	if sendCfg.MaxActiveLanes > 0 {
		emitter.Debug("udp-active-lane-cap=" + strconv.Itoa(sendCfg.MaxActiveLanes))
	}
	if sendCfg.MinActiveLanes > 0 {
		emitter.Debug("udp-active-lane-min=" + strconv.Itoa(sendCfg.MinActiveLanes))
	}
	emitter.Debug("udp-rate-mbps=" + strconv.Itoa(rateState.activeRateMbps))
	emitter.Debug("udp-stream=true")
	emitter.Debug("udp-stream-replay-window-bytes=" + strconv.FormatUint(sendCfg.StreamReplayWindowBytes, 10))
}

func externalExecutePreparedDirectUDPSend(ctx context.Context, src io.Reader, plan externalDirectUDPSendPlan, cfg SendConfig, metrics *externalTransferMetrics) error {
	if metrics == nil {
		metrics = externalTransferMetricsFromContext(ctx)
	}
	if metrics == nil {
		metrics = newExternalTransferMetricsWithTrace(time.Now(), cfg.Trace, transfertrace.RoleSend)
	}
	availableLanes := plan.availableLanes
	if availableLanes == 0 {
		availableLanes = len(plan.probeConns)
	}
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
	metrics.SetDirectPlan(plan.selectedRateMbps, plan.startRateMbps, len(plan.probeConns), availableLanes)
	plan.sendCfg.Progress = externalDirectUDPSendProgressRecorder(plan.sendCfg.Progress, metrics, !plan.sendSrcRecordsDirectMetrics)
	externalTransferTracef("direct-udp-send-execute-start lanes=%d addrs=%s rate=%d ceiling=%d", len(plan.probeConns), strings.Join(plan.remoteAddrs, ","), plan.sendCfg.RateMbps, plan.sendCfg.RateCeilingMbps)
	stats, err := probe.SendBlastParallel(ctx, plan.probeConns, plan.remoteAddrs, externalDirectUDPBufferedReader(src), plan.sendCfg)
	externalTransferTracef("direct-udp-send-execute-done err=%v bytes=%d lanes=%d first-byte-zero=%v complete-zero=%v", err, stats.BytesSent, stats.Lanes, stats.FirstByteAt.IsZero(), stats.CompletedAt.IsZero())
	if stats.Lanes > 0 {
		metrics.SetDirectPlan(plan.selectedRateMbps, plan.startRateMbps, stats.Lanes, availableLanes)
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("udp-send-transport=" + stats.Transport.Summary())
		cfg.Emitter.Debug("udp-send-active-lanes=" + strconv.Itoa(stats.Lanes))
		cfg.Emitter.Debug("udp-send-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
		emitExternalDirectUDPSendReplayStats(cfg.Emitter, stats)
		emitExternalDirectUDPStats(cfg.Emitter, "udp-send", stats.BytesSent, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
	}
	externalDirectUDPValidateDirectProgress(nil, metrics, stats)
	externalDirectUDPSendRecordMetrics(metrics, stats, !plan.sendSrcRecordsDirectMetrics)
	if err != nil {
		metrics.SetError(err)
	} else {
		emitExternalTransferMetricsComplete(metrics, cfg.Emitter, "udp-send", stats, stats.CompletedAt)
	}
	return err
}

func externalDirectUDPSendRecordMetrics(metrics *externalTransferMetrics, stats probe.TransferStats, backfillDirectBytes bool) {
	if !backfillDirectBytes || stats.BytesSent <= 0 {
		return
	}
	directFirstByteAt := stats.FirstByteAt
	if directFirstByteAt.IsZero() {
		directFirstByteAt = stats.StartedAt
	}
	if remaining := stats.BytesSent - metrics.DirectBytes(); remaining > 0 {
		metrics.RecordDirectWrite(remaining, directFirstByteAt)
	}
}

func externalDirectUDPSendProgressRecorder(progress func(probe.TransferStats), metrics *externalTransferMetrics, updateDirectBytes bool) func(probe.TransferStats) {
	return func(stats probe.TransferStats) {
		if progress != nil {
			progress(stats)
		}
		externalDirectUDPValidateDirectProgress(nil, metrics, stats)
		if updateDirectBytes {
			metrics.SetProbeStats(stats)
			return
		}
		metrics.SetProbeStatsWithoutByteProgress(stats)
	}
}

func externalPrepareDirectUDPReceive(ctx context.Context, dst io.Writer, tok token.Token, derpClient *derpbind.Client, peerDERP key.NodePublic, peerAddr net.Addr, probeConns []net.PacketConn, remoteCandidates []net.Addr, decision rendezvous.Decision, readyCh <-chan derpbind.Packet, startCh <-chan derpbind.Packet, cfg ListenConfig) (externalDirectUDPReceivePlan, error) {
	plan := externalDirectUDPReceivePlan{decision: decision, peerAddr: peerAddr}
	metrics := externalTransferMetricsFromContext(ctx)
	metrics.SetPhase(transfertrace.PhaseDirectPrepare, string(StateTryingDirect))
	auth := externalPeerControlAuthForToken(tok)
	if err := externalDirectUDPReceiveReadyWait(ctx, peerAddr, readyCh, auth); err != nil {
		return plan, err
	}
	probeConns, remoteAddrs, err := externalDirectUDPReceiveRemotePairs(probeConns, remoteCandidates, peerAddr)
	if err != nil {
		return plan, err
	}
	availableLanes := len(probeConns)
	localTransportCaps := externalDirectUDPPreviewTransportCaps(probeConns[0], externalDirectUDPTransportLabel)
	receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
	receiveDst, flushDst, fastDiscard := externalDirectUDPReceiveWriter(dst, receiveDst, flushDst)
	if err := externalDirectUDPReceiveReadyAck(ctx, derpClient, peerDERP, peerAddr, fastDiscard, localTransportCaps, auth); err != nil {
		return plan, err
	}
	emitExternalDirectUDPReceiveInitialDebug(cfg.Emitter, peerAddr, remoteAddrs, len(probeConns), fastDiscard)
	packetAEAD, err := externalSessionPacketAEAD(tok)
	if err != nil {
		return plan, err
	}
	receiveCfg := externalDirectUDPFastDiscardReceiveConfig()
	receiveCfg.PacketAEAD = packetAEAD
	start, rateProbeAuth, err := externalDirectUDPReceiveStart(ctx, tok, peerAddr, startCh, auth)
	if err != nil {
		return plan, err
	}
	emitExternalDirectUDPReceiveStartModeDebug(cfg.Emitter, start)
	emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, start.ExpectedBytes)
	if err := externalDirectUDPReceiveStartAck(ctx, derpClient, peerDERP, peerAddr, auth); err != nil {
		return plan, err
	}
	signalExternalDirectUDPDirectReady(ctx)
	setExternalTransferMetricsProbePhase(metrics, len(start.ProbeRates))
	probeSamples, err := externalDirectUDPReceiveRateProbeResult(ctx, derpClient, peerDERP, probeConns, remoteAddrs, start, rateProbeAuth, cfg.Emitter, auth)
	if err != nil {
		return plan, err
	}
	metrics.SetDirectPlan(0, 0, len(probeConns), availableLanes)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
	plan.probeConns = probeConns
	plan.remoteAddrs = remoteAddrs
	plan.receiveDst = receiveDst
	plan.flushDst = flushDst
	plan.receiveCfg = receiveCfg
	plan.fastDiscard = fastDiscard
	plan.start = start
	plan.receivedProbeSamples = probeSamples
	return plan, nil
}

func externalDirectUDPReceiveReadyWait(ctx context.Context, peerAddr net.Addr, readyCh <-chan derpbind.Packet, auth externalPeerControlAuth) error {
	externalTransferTracef("direct-udp-recv-ready-wait addr=%v", peerAddr)
	if err := externalDirectUDPWaitReadyFn(ctx, readyCh, auth); err != nil {
		return err
	}
	externalTransferTracef("direct-udp-recv-ready addr=%v", peerAddr)
	return nil
}

func externalDirectUDPReceiveRemotePairs(probeConns []net.PacketConn, remoteCandidates []net.Addr, peerAddr net.Addr) ([]net.PacketConn, []string, error) {
	remoteAddrs := externalDirectUDPParallelCandidateStringsForPeer(remoteCandidates, len(probeConns), peerAddr)
	if len(remoteAddrs) > 0 {
		probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
	}
	if len(probeConns) == 0 {
		return nil, nil, errors.New("direct UDP ready without usable receive sockets")
	}
	return probeConns, remoteAddrs, nil
}

func externalDirectUDPReceiveWriter(dst io.Writer, receiveDst io.Writer, flushDst func() error) (io.Writer, func() error, bool) {
	fastDiscard := receiveDst == io.Discard
	if fastDiscard {
		return receiveDst, flushDst, true
	}
	receiveDst, flushDst = externalDirectUDPSectionWriterForTarget(dst, receiveDst, flushDst)
	return receiveDst, flushDst, false
}

func externalDirectUDPReceiveReadyAck(ctx context.Context, derpClient *derpbind.Client, peerDERP key.NodePublic, peerAddr net.Addr, fastDiscard bool, localTransportCaps probe.TransportCaps, auth externalPeerControlAuth) error {
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
		return err
	}
	externalTransferTracef("direct-udp-recv-ready-ack-send addr=%v fast-discard=%v", peerAddr, fastDiscard)
	return nil
}

func emitExternalDirectUDPReceiveInitialDebug(emitter *telemetry.Emitter, peerAddr net.Addr, remoteAddrs []string, lanes int, fastDiscard bool) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-blast=true")
	emitter.Debug("udp-lanes=" + strconv.Itoa(lanes))
	emitter.Debug("udp-require-complete=" + strconv.FormatBool(!fastDiscard))
	emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPStreamFECGroupSize))
	emitter.Debug("udp-fast-discard=" + strconv.FormatBool(fastDiscard))
	if peerAddr != nil {
		emitter.Debug("udp-direct-addr=" + peerAddr.String())
	}
	emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
}

func externalDirectUDPReceiveStart(ctx context.Context, tok token.Token, peerAddr net.Addr, startCh <-chan derpbind.Packet, auth externalPeerControlAuth) (directUDPStart, externalDirectUDPRateProbeAuth, error) {
	externalTransferTracef("direct-udp-recv-start-wait addr=%v", peerAddr)
	start, err := externalDirectUDPWaitStartFn(ctx, startCh, auth)
	if err != nil {
		return directUDPStart{}, externalDirectUDPRateProbeAuth{}, err
	}
	rateProbeAuth, err := externalDirectUDPRateProbeAuthFromStart(tok, start)
	if err != nil {
		return directUDPStart{}, externalDirectUDPRateProbeAuth{}, err
	}
	externalTransferTracef("direct-udp-recv-start addr=%v stream=%v", peerAddr, start.Stream)
	return start, rateProbeAuth, nil
}

func emitExternalDirectUDPReceiveStartModeDebug(emitter *telemetry.Emitter, start directUDPStart) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-stream=" + strconv.FormatBool(start.Stream))
	emitter.Debug("udp-striped-blast=" + strconv.FormatBool(start.StripedBlast))
}

func externalDirectUDPReceiveStartAck(ctx context.Context, derpClient *derpbind.Client, peerDERP key.NodePublic, peerAddr net.Addr, auth externalPeerControlAuth) error {
	if err := sendAuthenticatedEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDirectUDPStartAck}, auth); err != nil {
		return err
	}
	externalTransferTracef("direct-udp-recv-start-ack-send addr=%v", peerAddr)
	return nil
}

func externalDirectUDPReceiveRateProbeResult(ctx context.Context, derpClient *derpbind.Client, peerDERP key.NodePublic, probeConns []net.PacketConn, remoteAddrs []string, start directUDPStart, rateProbeAuth externalDirectUDPRateProbeAuth, emitter *telemetry.Emitter, auth externalPeerControlAuth) ([]directUDPRateProbeSample, error) {
	if len(start.ProbeRates) == 0 {
		return nil, nil
	}
	probeSamples, err := externalDirectUDPReceiveRateProbesFn(ctx, probeConns, remoteAddrs, start.ProbeRates, rateProbeAuth)
	if err != nil {
		return nil, err
	}
	externalTransferMetricsFromContext(ctx).SetProbeSummary("done", externalDirectUDPFormatRateProbeSamples(nil, probeSamples))
	if emitter != nil {
		emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(nil, probeSamples))
	}
	if err := sendAuthenticatedEnvelope(ctx, derpClient, peerDERP, envelope{
		Type: envelopeDirectUDPRateProbe,
		DirectUDPRateProbe: &directUDPRateProbeResult{
			Samples: probeSamples,
		},
	}, auth); err != nil {
		return nil, err
	}
	return probeSamples, nil
}

func externalExecutePreparedDirectUDPReceive(ctx context.Context, plan externalDirectUDPReceivePlan, tok token.Token, cfg ListenConfig, metrics *externalTransferMetrics) error {
	metrics = externalTransferMetricsOrNew(ctx, metrics, cfg.Trace, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseDirectExecute, "direct-execute")
	metrics.SetDirectPlan(0, 0, len(plan.probeConns), len(plan.probeConns))
	receiveCfg := plan.receiveCfg
	stats, err := externalDirectUDPExecuteReceivePlan(ctx, plan, tok, receiveCfg, metrics)
	externalTransferTracef("direct-udp-recv-execute-done err=%v bytes=%d lanes=%d first-byte-zero=%v complete-zero=%v", err, stats.BytesReceived, stats.Lanes, stats.FirstByteAt.IsZero(), stats.CompletedAt.IsZero())
	if stats.Lanes > 0 {
		metrics.SetDirectPlan(0, 0, stats.Lanes, len(plan.probeConns))
	}
	emitExternalDirectUDPReceiveDebug(cfg.Emitter, stats, err)
	err = externalDirectUDPFlushReceivePlan(plan, err)
	externalDirectUDPValidateDirectProgress(nil, metrics, stats)
	if err != nil {
		externalDirectUDPBackfillReceiveMetrics(metrics, stats, !plan.receiveDstRecordsDirectMetrics)
		metrics.SetError(err)
	} else {
		externalDirectUDPRecordReceiveMetrics(metrics, cfg.Emitter, stats, !plan.receiveDstRecordsDirectMetrics)
	}
	return err
}

func externalTransferMetricsOrNew(ctx context.Context, metrics *externalTransferMetrics, trace *transfertrace.Recorder, role transfertrace.Role) *externalTransferMetrics {
	if metrics != nil {
		return metrics
	}
	metrics = externalTransferMetricsFromContext(ctx)
	if metrics != nil {
		return metrics
	}
	return newExternalTransferMetricsWithTrace(time.Now(), trace, role)
}

func externalDirectUDPExecuteReceivePlan(ctx context.Context, plan externalDirectUDPReceivePlan, tok token.Token, receiveCfg probe.ReceiveConfig, metrics *externalTransferMetrics) (probe.TransferStats, error) {
	if metrics == nil {
		metrics = externalTransferMetricsFromContext(ctx)
	}
	if metrics != nil && !plan.receiveDstRecordsDirectMetrics {
		plan.receiveDst = externalTransferMetricsWriter{w: plan.receiveDst, record: metrics.RecordDirectWrite}
	}
	if plan.start.Stream {
		receiveCfg.RequireComplete = true
		receiveCfg.FECGroupSize = externalDirectUDPStreamFECGroupSize
		receiveCfg.ExpectedRunID = tok.SessionID
		externalTransferTracef("direct-udp-recv-execute-start stream=true lanes=%d expected=%d", len(plan.probeConns), plan.start.ExpectedBytes)
		return externalDirectUDPReceiveBlastStreamParallelToWriterFn(ctx, plan.probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes)
	}
	if plan.fastDiscard {
		externalTransferTracef("direct-udp-recv-execute-start fast-discard=true lanes=%d expected=%d", len(plan.probeConns), plan.start.ExpectedBytes)
		return externalDirectUDPReceiveBlastParallelToWriterFn(ctx, plan.probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes)
	}
	return externalDirectUDPExecuteSectionReceivePlan(ctx, plan, tok, receiveCfg)
}

func externalDirectUDPExecuteSectionReceivePlan(ctx context.Context, plan externalDirectUDPReceivePlan, tok token.Token, receiveCfg probe.ReceiveConfig) (probe.TransferStats, error) {
	receiveCfg.RequireComplete = true
	probeConns, orderErr := externalDirectUDPOrderConnsForSections(plan.probeConns, plan.decision.Accept.Candidates, plan.start.SectionAddrs)
	if orderErr != nil {
		return probe.TransferStats{}, orderErr
	}
	receiveCfg.ExpectedRunIDs = externalDirectUDPLaneRunIDs(tok.SessionID, len(probeConns))
	externalTransferTracef("direct-udp-recv-execute-start sections=true lanes=%d expected=%d", len(probeConns), plan.start.ExpectedBytes)
	return externalDirectUDPReceiveSectionSpoolParallel(ctx, probeConns, plan.receiveDst, receiveCfg, plan.start.ExpectedBytes, plan.start.SectionSizes)
}

func emitExternalDirectUDPReceiveDebug(emitter *telemetry.Emitter, stats probe.TransferStats, err error) {
	emitExternalDirectUDPReceiveResultDebug(emitter, stats, err)
	if emitter != nil {
		emitter.Debug("udp-receive-transport=" + stats.Transport.Summary())
		if stats.Lanes > 0 {
			emitter.Debug("udp-receive-active-lanes=" + strconv.Itoa(stats.Lanes))
		}
		emitter.Debug("udp-receive-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
		emitExternalDirectUDPStats(emitter, "udp-receive", stats.BytesReceived, stats.StartedAt, stats.FirstByteAt, stats.CompletedAt)
	}
}

func externalDirectUDPFlushReceivePlan(plan externalDirectUDPReceivePlan, err error) error {
	if err == nil {
		return plan.flushDst()
	}
	return err
}

func externalDirectUDPRecordReceiveMetrics(metrics *externalTransferMetrics, emitter *telemetry.Emitter, stats probe.TransferStats, backfillDirectBytes bool) {
	externalDirectUDPBackfillReceiveMetrics(metrics, stats, backfillDirectBytes)
	emitExternalTransferMetricsComplete(metrics, emitter, "udp-receive", stats, time.Now())
}

func externalDirectUDPBackfillReceiveMetrics(metrics *externalTransferMetrics, stats probe.TransferStats, backfillDirectBytes bool) {
	if backfillDirectBytes && stats.BytesReceived > 0 {
		directFirstByteAt := stats.FirstByteAt
		if directFirstByteAt.IsZero() {
			directFirstByteAt = stats.StartedAt
		}
		if remaining := stats.BytesReceived - metrics.DirectBytes(); remaining > 0 {
			metrics.RecordDirectWrite(remaining, directFirstByteAt)
		}
	}
}

func sendExternalViaDirectUDPOnly(ctx context.Context, src io.Reader, tok token.Token, derpClient *derpbind.Client, listenerDERP key.NodePublic, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc, probeConn net.PacketConn, probeConns []net.PacketConn, remoteCandidates []net.Addr, readyAckCh <-chan derpbind.Packet, startAckCh <-chan derpbind.Packet, rateProbeCh <-chan derpbind.Packet, progressCh <-chan derpbind.Packet, cfg SendConfig) error {
	metrics := externalTransferMetricsFromContext(ctx)
	if metrics == nil {
		metrics = newExternalTransferMetricsWithTrace(time.Now(), cfg.Trace, transfertrace.RoleSend)
		ctx = withExternalTransferMetrics(ctx, metrics)
	}
	stopPeerProgress := startPeerProgressWatcher(ctx, progressCh, externalPeerControlAuthForToken(tok), metrics, cfg.Progress, cfg.Emitter)
	defer stopPeerProgress()
	var peerAddr net.Addr
	if transportManager != nil {
		peerAddr, _ = transportManager.DirectAddr()
	}
	externalDirectUDPBeginTryingDirect(pathEmitter, metrics)
	plan, err := externalPrepareDirectUDPSendFn(ctx, tok, derpClient, listenerDERP, peerAddr, probeConns, remoteCandidates, readyAckCh, startAckCh, rateProbeCh, cfg)
	if err != nil {
		if externalDirectUDPWaitCanFallback(ctx, err) {
			externalDirectUDPMarkDirectFallbackRelay(pathEmitter, metrics, err)
			return sendExternalRelayUDP(ctx, src, transportManager, tok, cfg.Emitter)
		}
		metrics.SetError(err)
		return err
	}
	externalDirectUDPActivateDirectPath(pathEmitter, transportManager, punchCancel)
	externalDirectUDPValidateDirectProbe(pathEmitter, metrics, plan.receivedProbeSamples)
	externalDirectUDPInstallSendProgressValidation(&plan, pathEmitter, metrics)
	err = externalExecutePreparedDirectUDPSendFn(ctx, src, plan, cfg, metrics)
	externalDirectUDPValidateDirectMetricsProgress(pathEmitter, metrics)
	return err
}

func sendExternalRelayUDPWithPeerProgress(ctx context.Context, src io.Reader, manager *transport.Manager, tok token.Token, progressCh <-chan derpbind.Packet, cfg SendConfig) error {
	metrics := externalTransferMetricsOrNew(ctx, nil, cfg.Trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, string(StateRelay))
	stopPeerProgress := startPeerProgressWatcher(ctx, progressCh, externalPeerControlAuthForToken(tok), metrics, cfg.Progress, cfg.Emitter)
	defer stopPeerProgress()
	return sendExternalRelayUDP(ctx, src, manager, tok, cfg.Emitter)
}

func listenExternalViaDirectUDP(ctx context.Context, cfg ListenConfig) (retTok string, retErr error) {
	rt, err := newExternalDirectUDPListenRuntime(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer rt.Close()
	if err := rt.publishToken(ctx); err != nil {
		return rt.tok, err
	}
	return rt.run(ctx)
}

type externalDirectUDPListenRuntime struct {
	cfg               ListenConfig
	tok               string
	session           *relaySession
	pathEmitter       *transportPathEmitter
	claimCh           <-chan derpbind.Packet
	unsubscribeClaims func()
	auth              externalPeerControlAuth
}

func newExternalDirectUDPListenRuntime(ctx context.Context, cfg ListenConfig) (*externalDirectUDPListenRuntime, error) {
	tok, session, err := issuePublicSession(ctx)
	if err != nil {
		return nil, err
	}
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateWaiting)
	claimCh, unsubscribeClaims := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	return &externalDirectUDPListenRuntime{
		cfg:               cfg,
		tok:               tok,
		session:           session,
		pathEmitter:       pathEmitter,
		claimCh:           claimCh,
		unsubscribeClaims: unsubscribeClaims,
		auth:              externalPeerControlAuthForToken(session.token),
	}, nil
}

func (rt *externalDirectUDPListenRuntime) Close() {
	if rt.unsubscribeClaims != nil {
		rt.unsubscribeClaims()
	}
	if rt.session != nil {
		deleteRelayMailbox(rt.tok, rt.session)
		closePublicSessionTransport(rt.session)
		_ = rt.session.derp.Close()
	}
}

func (rt *externalDirectUDPListenRuntime) publishToken(ctx context.Context) error {
	if rt.cfg.TokenSink == nil {
		return nil
	}
	select {
	case rt.cfg.TokenSink <- rt.tok:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type externalDirectUDPAcceptedClaim struct {
	env      envelope
	peerDERP key.NodePublic
	decision rendezvous.Decision
}

func (rt *externalDirectUDPListenRuntime) run(ctx context.Context) (string, error) {
	for {
		accepted, ok, err := rt.nextAcceptedClaim(ctx)
		if err != nil {
			return rt.tok, err
		}
		if !ok {
			continue
		}
		if err := rt.receiveAccepted(ctx, accepted); err != nil {
			return rt.tok, err
		}
		return rt.tok, nil
	}
}

func (rt *externalDirectUDPListenRuntime) nextAcceptedClaim(ctx context.Context) (externalDirectUDPAcceptedClaim, bool, error) {
	claim, ok, err := rt.receiveClaim(ctx)
	if err != nil || !ok {
		return externalDirectUDPAcceptedClaim{}, false, err
	}
	if !claim.decision.Accepted {
		return externalDirectUDPAcceptedClaim{}, false, rt.sendDecision(ctx, claim.peerDERP, claim.decision)
	}
	if claim.decision.Accept == nil {
		return externalDirectUDPAcceptedClaim{}, false, errors.New("accepted decision missing accept payload")
	}
	return claim, true, nil
}

func (rt *externalDirectUDPListenRuntime) receiveClaim(ctx context.Context) (externalDirectUDPAcceptedClaim, bool, error) {
	pkt, err := receiveSubscribedPacket(ctx, rt.claimCh)
	if err != nil {
		if ctx.Err() != nil {
			return externalDirectUDPAcceptedClaim{}, false, ctx.Err()
		}
		return externalDirectUDPAcceptedClaim{}, false, err
	}
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, rt.auth)
	if ignoreAuthenticatedEnvelopeError(err, rt.auth) || err != nil || env.Type != envelopeClaim || env.Claim == nil {
		return externalDirectUDPAcceptedClaim{}, false, nil
	}
	peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
	decision, _ := rt.session.gate.Accept(time.Now(), *env.Claim)
	return externalDirectUDPAcceptedClaim{env: env, peerDERP: peerDERP, decision: decision}, true, nil
}

func (rt *externalDirectUDPListenRuntime) sendDecision(ctx context.Context, peerDERP key.NodePublic, decision rendezvous.Decision) error {
	return sendAuthenticatedEnvelope(ctx, rt.session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, rt.auth)
}

type externalDirectUDPListenPeerSubscriptions struct {
	abortCh              <-chan derpbind.Packet
	heartbeatCh          <-chan derpbind.Packet
	readyCh              <-chan derpbind.Packet
	startCh              <-chan derpbind.Packet
	unsubscribeAbort     func()
	unsubscribeHeartbeat func()
	unsubscribeReady     func()
	unsubscribeStart     func()
}

func (s externalDirectUDPListenPeerSubscriptions) Close() {
	if s.unsubscribeAbort != nil {
		s.unsubscribeAbort()
	}
	if s.unsubscribeHeartbeat != nil {
		s.unsubscribeHeartbeat()
	}
	if s.unsubscribeReady != nil {
		s.unsubscribeReady()
	}
	if s.unsubscribeStart != nil {
		s.unsubscribeStart()
	}
}

func (rt *externalDirectUDPListenRuntime) subscribePeer(peerDERP key.NodePublic) externalDirectUDPListenPeerSubscriptions {
	abortCh, unsubscribeAbort := rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isAbortPayload(pkt.Payload)
	})
	heartbeatCh, unsubscribeHeartbeat := rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isHeartbeatPayload(pkt.Payload)
	})
	readyCh, unsubscribeReady := rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isDirectUDPReadyPayload(pkt.Payload)
	})
	startCh, unsubscribeStart := rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isDirectUDPStartPayload(pkt.Payload)
	})
	return externalDirectUDPListenPeerSubscriptions{
		abortCh:              abortCh,
		heartbeatCh:          heartbeatCh,
		readyCh:              readyCh,
		startCh:              startCh,
		unsubscribeAbort:     unsubscribeAbort,
		unsubscribeHeartbeat: unsubscribeHeartbeat,
		unsubscribeReady:     unsubscribeReady,
		unsubscribeStart:     unsubscribeStart,
	}
}

type externalDirectUDPListenTransfer struct {
	relayOnly         bool
	probeConn         net.PacketConn
	probeConns        []net.PacketConn
	portmaps          []publicPortmap
	remoteCandidates  []net.Addr
	transportCtx      context.Context
	transportCancel   context.CancelFunc
	transportManager  *transport.Manager
	transportCleanup  func()
	punchCancel       context.CancelFunc
	cleanupProbeConns func()
}

func (tr externalDirectUDPListenTransfer) Close() {
	if tr.punchCancel != nil {
		tr.punchCancel()
	}
	if tr.transportCleanup != nil {
		tr.transportCleanup()
	}
	if tr.transportCancel != nil {
		tr.transportCancel()
	}
	if tr.cleanupProbeConns != nil {
		tr.cleanupProbeConns()
	}
}

func (rt *externalDirectUDPListenRuntime) receiveAccepted(ctx context.Context, accepted externalDirectUDPAcceptedClaim) (retErr error) {
	peerSubs := rt.subscribePeer(accepted.peerDERP)
	defer peerSubs.Close()
	var countedDst *byteCountingWriteCloser
	ctx, stopPeerAbort := withPeerControlContext(ctx, rt.session.derp, accepted.peerDERP, peerSubs.abortCh, peerSubs.heartbeatCh, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, rt.session.derp, accepted.peerDERP, func() int64 {
		return externalDirectUDPCountedDstBytes(countedDst)
	}, rt.auth)

	emitExternalDirectUDPClaimAccepted(rt.cfg.Emitter)
	tr, decision, err := rt.prepareTransfer(ctx, accepted)
	if err != nil {
		return err
	}
	accepted.decision = decision
	defer tr.Close()
	countedDst, err = rt.openCountedSink(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = countedDst.Close() }()
	relayPrefixPackets, unsubscribeRelayPrefix := rt.subscribeRelayPrefix(accepted.peerDERP, tr.relayOnly)
	defer unsubscribeRelayPrefix()

	if err := rt.sendDecision(ctx, accepted.peerDERP, accepted.decision); err != nil {
		return err
	}
	emitExternalDirectUDPDecisionSent(rt.cfg.Emitter)
	progressCtx, stopPeerProgress := context.WithCancel(ctx)
	defer stopPeerProgress()
	go sendPeerProgressLoop(progressCtx, rt.session.derp, accepted.peerDERP, countedDst.Count, countedDst.FirstByteAt, rt.auth)
	if err := rt.receivePayload(ctx, accepted, tr, countedDst, peerSubs, relayPrefixPackets); err != nil {
		return err
	}
	if err := sendPeerAck(ctx, rt.session.derp, accepted.peerDERP, countedDst.Count(), rt.auth); err != nil {
		return err
	}
	rt.pathEmitter.Complete(tr.transportManager)
	return nil
}

func externalDirectUDPCountedDstBytes(countedDst *byteCountingWriteCloser) int64 {
	if countedDst == nil {
		return 0
	}
	return countedDst.Count()
}

func emitExternalDirectUDPClaimAccepted(emitter *telemetry.Emitter) {
	if emitter != nil {
		emitter.Debug("claim-accepted")
	}
}

func (rt *externalDirectUDPListenRuntime) prepareTransfer(ctx context.Context, accepted externalDirectUDPAcceptedClaim) (externalDirectUDPListenTransfer, rendezvous.Decision, error) {
	tr, err := rt.prepareProbeSet(accepted)
	if err != nil {
		return externalDirectUDPListenTransfer{}, accepted.decision, err
	}
	rt.applyDecisionCandidates(ctx, &accepted.decision, tr)
	localCandidates := parseCandidateStrings(accepted.decision.Accept.Candidates)
	tr.transportCtx, tr.transportCancel = context.WithCancel(ctx)
	tr.transportManager, tr.transportCleanup, err = startExternalTransportManager(tr.transportCtx, rt.session.token, tr.probeConn, rt.session.derpMap, rt.session.derp, accepted.peerDERP, localCandidates, tr.portmaps[0], tr.relayOnly)
	if err != nil {
		tr.Close()
		return externalDirectUDPListenTransfer{}, accepted.decision, err
	}
	rt.startTransferTransport(accepted, &tr)
	return tr, accepted.decision, nil
}

func (rt *externalDirectUDPListenRuntime) prepareProbeSet(accepted externalDirectUDPAcceptedClaim) (externalDirectUDPListenTransfer, error) {
	tr := externalDirectUDPListenTransfer{
		relayOnly:         rt.cfg.ForceRelay || externalClaimRelayOnly(*accepted.env.Claim),
		probeConn:         rt.session.probeConn,
		probeConns:        []net.PacketConn{rt.session.probeConn},
		portmaps:          []publicPortmap{publicSessionPortmap(rt.session)},
		cleanupProbeConns: func() {},
		punchCancel:       func() {},
	}
	if tr.relayOnly {
		return tr, nil
	}
	var err error
	tr.probeConn, tr.probeConns, tr.portmaps, tr.cleanupProbeConns, err = externalAcceptedDirectUDPSet(rt.session.probeConn, publicSessionPortmap(rt.session), rt.cfg.Emitter)
	return tr, err
}

func (rt *externalDirectUDPListenRuntime) applyDecisionCandidates(ctx context.Context, decision *rendezvous.Decision, tr externalDirectUDPListenTransfer) {
	if tr.relayOnly {
		decision.Accept.Parallel = 0
		decision.Accept.Candidates = nil
		return
	}
	decision.Accept.Parallel = len(tr.probeConns)
	decision.Accept.Candidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, tr.probeConns, rt.session.derpMap, tr.portmaps))
}

func (rt *externalDirectUDPListenRuntime) startTransferTransport(accepted externalDirectUDPAcceptedClaim, tr *externalDirectUDPListenTransfer) {
	rt.pathEmitter.SuppressWatcherDirect()
	rt.pathEmitter.Watch(tr.transportCtx, tr.transportManager)
	rt.pathEmitter.Flush(tr.transportManager)
	seedAcceptedClaimCandidates(tr.transportCtx, tr.transportManager, *accepted.env.Claim)
	tr.remoteCandidates = parseRemoteCandidateStrings(accepted.env.Claim.Candidates)
	if !tr.relayOnly {
		punchCtx, punchCancel := context.WithCancel(tr.transportCtx)
		tr.punchCancel = punchCancel
		externalDirectUDPStartPunching(punchCtx, tr.probeConns, tr.remoteCandidates)
	}
}

func (rt *externalDirectUDPListenRuntime) openCountedSink(ctx context.Context) (*byteCountingWriteCloser, error) {
	dst, err := openListenSink(ctx, rt.cfg)
	if err != nil {
		return nil, err
	}
	return newByteCountingWriteCloser(dst), nil
}

func (rt *externalDirectUDPListenRuntime) subscribeRelayPrefix(peerDERP key.NodePublic, relayOnly bool) (<-chan derpbind.Packet, func()) {
	if relayOnly {
		return nil, func() {}
	}
	return rt.session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
}

func emitExternalDirectUDPDecisionSent(emitter *telemetry.Emitter) {
	if emitter != nil {
		emitter.Debug("decision-sent")
	}
}

func (rt *externalDirectUDPListenRuntime) receivePayload(ctx context.Context, accepted externalDirectUDPAcceptedClaim, tr externalDirectUDPListenTransfer, countedDst *byteCountingWriteCloser, peerSubs externalDirectUDPListenPeerSubscriptions, relayPrefixPackets <-chan derpbind.Packet) error {
	if tr.relayOnly {
		return receiveExternalRelayUDP(ctx, countedDst, tr.transportManager, rt.session.token, rt.cfg.Emitter)
	}
	return receiveExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixReceiveConfig{
		dst:              countedDst,
		tok:              rt.session.token,
		derpClient:       rt.session.derp,
		peerDERP:         accepted.peerDERP,
		transportManager: tr.transportManager,
		pathEmitter:      rt.pathEmitter,
		punchCancel:      tr.punchCancel,
		probeConn:        tr.probeConn,
		probeConns:       tr.probeConns,
		remoteCandidates: tr.remoteCandidates,
		decision:         accepted.decision,
		readyCh:          peerSubs.readyCh,
		startCh:          peerSubs.startCh,
		relayPackets:     relayPrefixPackets,
		cfg:              rt.cfg,
	})
}

func receiveExternalViaDirectUDPOnly(ctx context.Context, dst io.Writer, tok token.Token, derpClient *derpbind.Client, peerDERP key.NodePublic, transportManager *transport.Manager, pathEmitter *transportPathEmitter, punchCancel context.CancelFunc, probeConn net.PacketConn, probeConns []net.PacketConn, remoteCandidates []net.Addr, decision rendezvous.Decision, readyCh <-chan derpbind.Packet, startCh <-chan derpbind.Packet, cfg ListenConfig) error {
	ctx = withExternalTransferMetrics(ctx, newExternalTransferMetricsWithTrace(time.Now(), cfg.Trace, transfertrace.RoleReceive))
	metrics := externalTransferMetricsFromContext(ctx)
	peerAddr, _ := transportManager.DirectAddr()
	externalDirectUDPBeginTryingDirect(pathEmitter, metrics)
	plan, err := externalPrepareDirectUDPReceiveFn(ctx, dst, tok, derpClient, peerDERP, peerAddr, probeConns, remoteCandidates, decision, readyCh, startCh, cfg)
	if err != nil {
		if externalDirectUDPWaitCanFallback(ctx, err) {
			externalDirectUDPMarkDirectFallbackRelay(pathEmitter, metrics, err)
			return receiveExternalRelayUDP(ctx, dst, transportManager, tok, cfg.Emitter)
		}
		metrics.SetError(err)
		return err
	}
	externalDirectUDPActivateDirectPath(pathEmitter, transportManager, punchCancel)
	externalDirectUDPValidateDirectProbe(pathEmitter, metrics, plan.receivedProbeSamples)
	externalDirectUDPInstallReceiveProgressValidation(&plan, pathEmitter, metrics)
	err = externalExecutePreparedDirectUDPReceiveFn(ctx, plan, tok, cfg, metrics)
	externalDirectUDPValidateDirectMetricsProgress(pathEmitter, metrics)
	return err
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
	progressCh       <-chan derpbind.Packet
	cfg              SendConfig
}

func sendExternalViaRelayPrefixThenDirectUDP(ctx context.Context, rcfg externalRelayPrefixSendConfig) error {
	if rcfg.decision.Accept == nil {
		return externalSendDirectUDPOnlyFn(ctx, rcfg.src, rcfg.tok, rcfg.derpClient, rcfg.listenerDERP, rcfg.transportManager, rcfg.pathEmitter, rcfg.punchCancel, rcfg.probeConn, rcfg.probeConns, rcfg.remoteCandidates, rcfg.readyAckCh, rcfg.startAckCh, rcfg.rateProbeCh, rcfg.progressCh, rcfg.cfg)
	}
	rt, err := newExternalRelayPrefixSendRuntime(ctx, rcfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run()
}

type externalRelayPrefixSendPrepResult struct {
	plan externalDirectUDPSendPlan
	err  error
}

type externalRelayPrefixSendRuntime struct {
	ctx                  context.Context
	rcfg                 externalRelayPrefixSendConfig
	metrics              *externalTransferMetrics
	spool                *externalHandoffSpool
	keepaliveCancel      context.CancelFunc
	relayStopCh          chan struct{}
	relayStopOnce        sync.Once
	relayErrCh           chan error
	prepCtx              context.Context
	prepCancel           context.CancelFunc
	handoffReadyCh       <-chan struct{}
	signalHandoffProceed func()
	directReadyCh        <-chan struct{}
	prepCh               chan externalRelayPrefixSendPrepResult
	stallTimer           *time.Timer
	directProgressCh     chan struct{}
	directProgressOnce   sync.Once
	peerProgressStop     func()
	overlapBoundary      int64
	overlapStarted       bool
	stallFired           bool
	handoffReady         bool
	directActivated      bool
}

func newExternalRelayPrefixSendRuntime(ctx context.Context, rcfg externalRelayPrefixSendConfig) (*externalRelayPrefixSendRuntime, error) {
	metrics := externalTransferMetricsOrNew(ctx, nil, rcfg.cfg.Trace, transfertrace.RoleSend)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	ctx = withExternalTransferMetrics(ctx, metrics)
	packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
	if err != nil {
		return nil, err
	}
	spool, err := newExternalHandoffSpool(rcfg.src, externalRelayPrefixDERPChunkSize, externalRelayPrefixDERPMaxUnacked)
	if err != nil {
		return nil, err
	}
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	go externalRelayPrefixTransportKeepalive(keepaliveCtx, rcfg.transportManager)
	rt := &externalRelayPrefixSendRuntime{
		ctx:              ctx,
		rcfg:             rcfg,
		metrics:          metrics,
		spool:            spool,
		keepaliveCancel:  keepaliveCancel,
		relayStopCh:      make(chan struct{}),
		relayErrCh:       make(chan error, 1),
		stallTimer:       time.NewTimer(externalRelayPrefixDirectPrepStallWait),
		directProgressCh: make(chan struct{}),
	}
	rt.peerProgressStop = startPeerProgressWatcher(ctx, rcfg.progressCh, externalPeerControlAuthForToken(rcfg.tok), rt.metrics, rcfg.cfg.Progress, rcfg.cfg.Emitter)
	relayErrCh := make(chan error, 1)
	rt.relayErrCh = relayErrCh
	go func() {
		relayErrCh <- externalSendExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.listenerDERP, spool, rt.relayStopCh, metrics, packetAEAD)
	}()
	prepCtx, prepCancel := context.WithCancel(ctx)
	prepCtx, handoffReadyCh := withExternalDirectUDPHandoffReadySignal(prepCtx)
	prepCtx, signalHandoffProceed := withExternalDirectUDPHandoffProceedSignal(prepCtx)
	prepCtx, directReadyCh := withExternalDirectUDPDirectReadySignal(prepCtx)
	rt.prepCtx = prepCtx
	rt.prepCancel = prepCancel
	rt.handoffReadyCh = handoffReadyCh
	rt.signalHandoffProceed = signalHandoffProceed
	rt.directReadyCh = directReadyCh
	rt.prepCh = make(chan externalRelayPrefixSendPrepResult, 1)
	rt.startPrepare()
	return rt, nil
}

func (rt *externalRelayPrefixSendRuntime) Close() {
	if rt.peerProgressStop != nil {
		rt.peerProgressStop()
	}
	rt.stopRelay()
	if rt.stallTimer != nil {
		rt.stallTimer.Stop()
	}
	if rt.prepCancel != nil {
		rt.prepCancel()
	}
	if rt.keepaliveCancel != nil {
		rt.keepaliveCancel()
	}
	if rt.spool != nil {
		_ = rt.spool.Close()
	}
}

func (rt *externalRelayPrefixSendRuntime) startPrepare() {
	peerAddr := externalRelayPrefixPeerAddr(rt.rcfg.transportManager)
	externalDirectUDPBeginTryingDirect(rt.rcfg.pathEmitter, rt.metrics)
	go func() {
		sendCfg := rt.rcfg.cfg
		sendCfg.skipDirectUDPRateProbes = externalRelayPrefixShouldSkipDirectUDPRateProbes(sendCfg.StdioExpectedBytes)
		prepCtx := rt.prepCtx
		if !sendCfg.skipDirectUDPRateProbes {
			prepCtx = withExternalDirectUDPAllowUnverifiedFallback(prepCtx)
		}
		plan, err := externalPrepareDirectUDPSendFn(prepCtx, rt.rcfg.tok, rt.rcfg.derpClient, rt.rcfg.listenerDERP, peerAddr, rt.rcfg.probeConns, rt.rcfg.remoteCandidates, rt.rcfg.readyAckCh, rt.rcfg.startAckCh, rt.rcfg.rateProbeCh, sendCfg)
		rt.prepCh <- externalRelayPrefixSendPrepResult{plan: plan, err: err}
	}()
}

func externalRelayPrefixPeerAddr(manager *transport.Manager) net.Addr {
	if manager == nil {
		return nil
	}
	peerAddr, _ := manager.DirectAddr()
	return peerAddr
}

func (rt *externalRelayPrefixSendRuntime) run() error {
	for {
		if rt.drainDirectReady() {
			continue
		}
		if err, done := rt.runOnce(); done {
			return err
		}
	}
}

func (rt *externalRelayPrefixSendRuntime) runOnce() (error, bool) {
	select {
	case relayErr := <-rt.relayErrCh:
		return rt.handleRelayDone(relayErr), true
	case prep := <-rt.prepCh:
		return rt.handlePrep(prep), true
	case <-rt.stallTimer.C:
		return rt.handleStall()
	case <-rt.handoffReadyCh:
		return rt.handleHandoffReady()
	case <-rt.directReadyCh:
		rt.directReadyCh = nil
		externalTransferTracef("relay-prefix-send-direct-ready-pre-prepare")
		rt.activateDirect()
		return nil, false
	case <-rt.ctx.Done():
		return rt.cancelWithPeerError(), true
	}
}

func (rt *externalRelayPrefixSendRuntime) stopRelay() {
	rt.relayStopOnce.Do(func() {
		close(rt.relayStopCh)
	})
}

func (rt *externalRelayPrefixSendRuntime) waitRelayErr() error {
	select {
	case err := <-rt.relayErrCh:
		return err
	case <-rt.ctx.Done():
		rt.stopRelay()
		return normalizePeerAbortError(rt.ctx, rt.ctx.Err())
	}
}

func (rt *externalRelayPrefixSendRuntime) beginDirectOverlap() (bool, int64, error) {
	if rt.overlapStarted {
		return false, rt.overlapBoundary, nil
	}
	rt.spool.SetMaxBuffered(externalRelayPrefixOverlapMaxBuffered)
	watermark := rt.spool.AckedWatermark()
	if rt.spool.Done() {
		rt.finishOnRelay()
		return true, watermark, nil
	}
	rt.overlapBoundary = watermark
	rt.overlapStarted = true
	recordExternalDirectUDPHandoffProceedWatermark(rt.prepCtx, watermark)
	rt.signalHandoffProceed()
	externalTransferTracef("relay-prefix-send-overlap-start boundary=%d", watermark)
	return false, watermark, nil
}

func (rt *externalRelayPrefixSendRuntime) finishOnRelay() {
	if rt.rcfg.cfg.Emitter != nil {
		rt.rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
	}
	emitExternalTransferMetricsComplete(rt.metrics, rt.rcfg.cfg.Emitter, "udp-send", probe.TransferStats{}, time.Now())
}

func (rt *externalRelayPrefixSendRuntime) activateDirect() {
	if rt.directActivated {
		return
	}
	externalDirectUDPActivateDirectPath(rt.rcfg.pathEmitter, rt.rcfg.transportManager, rt.rcfg.punchCancel)
	rt.directActivated = true
}

func (rt *externalRelayPrefixSendRuntime) drainDirectReady() bool {
	if rt.directReadyCh == nil {
		return false
	}
	select {
	case <-rt.directReadyCh:
		rt.directReadyCh = nil
		rt.activateDirect()
		return true
	default:
		return false
	}
}

func (rt *externalRelayPrefixSendRuntime) handleRelayDone(relayErr error) error {
	rt.prepCancel()
	if relayErr != nil {
		rt.metrics.SetError(relayErr)
		return relayErr
	}
	rt.finishOnRelay()
	return nil
}

func (rt *externalRelayPrefixSendRuntime) handlePrep(prep externalRelayPrefixSendPrepResult) error {
	if prep.err != nil {
		return rt.handlePrepError(prep.err)
	}
	if externalRelayPrefixShouldFinishRelay(rt.spool) {
		return rt.finishAfterRelayWait()
	}
	externalTransferTracef("relay-prefix-send-prepare-complete")
	done, watermark, err := rt.beginDirectOverlap()
	if err != nil {
		return err
	}
	if done {
		externalTransferTracef("relay-prefix-send-prepare-complete-done-on-relay")
		return nil
	}
	externalTransferTracef("relay-prefix-send-prepare-overlap boundary=%d", watermark)
	rt.activateDirect()
	return rt.executePrepared(prep.plan)
}

func (rt *externalRelayPrefixSendRuntime) handlePrepError(prepErr error) error {
	if rt.rcfg.cfg.Emitter != nil {
		rt.rcfg.cfg.Emitter.Debug("udp-handoff-send-prepare-error=" + prepErr.Error())
	}
	if rt.ctx.Err() != nil || errors.Is(prepErr, context.Canceled) {
		rt.stopRelay()
		err := normalizePeerAbortError(rt.ctx, prepErr)
		rt.metrics.SetError(err)
		return err
	}
	externalDirectUDPMarkDirectFallbackRelay(rt.rcfg.pathEmitter, rt.metrics, prepErr)
	if err := rt.waitRelayErr(); err != nil {
		rt.metrics.SetError(err)
		return err
	}
	rt.finishOnRelay()
	return nil
}

func (rt *externalRelayPrefixSendRuntime) finishAfterRelayWait() error {
	if err := rt.waitRelayErr(); err != nil {
		rt.metrics.SetError(err)
		return err
	}
	rt.finishOnRelay()
	return nil
}

func (rt *externalRelayPrefixSendRuntime) handleStall() (error, bool) {
	rt.stallFired = true
	externalTransferTracef("relay-prefix-send-stall-timer handoff-ready=%v", rt.handoffReady)
	if rt.handoffReady {
		return rt.postHandoff(), true
	}
	return nil, false
}

func (rt *externalRelayPrefixSendRuntime) handleHandoffReady() (error, bool) {
	rt.handoffReady = true
	rt.handoffReadyCh = nil
	externalTransferTracef("relay-prefix-send-handoff-ready stall-fired=%v", rt.stallFired)
	if rt.stallFired {
		return rt.postHandoff(), true
	}
	return nil, false
}

func (rt *externalRelayPrefixSendRuntime) postHandoff() error {
	externalTransferTracef("relay-prefix-send-post-handoff-start")
	done, watermark, err := rt.beginDirectOverlap()
	if err != nil {
		return err
	}
	if done {
		externalTransferTracef("relay-prefix-send-post-handoff-done-on-relay")
		return nil
	}
	externalTransferTracef("relay-prefix-send-post-handoff-overlap boundary=%d", watermark)
	return rt.waitPreparedAfterHandoff()
}

func (rt *externalRelayPrefixSendRuntime) waitPreparedAfterHandoff() error {
	for {
		if rt.drainDirectReady() {
			continue
		}
		select {
		case relayErr := <-rt.relayErrCh:
			return rt.handleRelayDone(relayErr)
		case <-rt.directReadyCh:
			rt.directReadyCh = nil
			externalTransferTracef("relay-prefix-send-post-handoff-direct-ready")
			rt.activateDirect()
		case prep := <-rt.prepCh:
			if prep.err != nil {
				return rt.handlePrepError(prep.err)
			}
			externalTransferTracef("relay-prefix-send-post-handoff-prepared")
			rt.activateDirect()
			return rt.executePrepared(prep.plan)
		case <-rt.ctx.Done():
			return rt.cancelWithPeerError()
		}
	}
}

func (rt *externalRelayPrefixSendRuntime) executePrepared(plan externalDirectUDPSendPlan) error {
	externalDirectUDPValidateDirectProbe(rt.rcfg.pathEmitter, rt.metrics, plan.receivedProbeSamples)
	boundary := rt.overlapBoundary
	if rt.metrics != nil {
		rt.metrics.SetDirectAppProgressBase(boundary)
		plan.sendSrcRecordsDirectMetrics = true
	}
	progress := plan.sendCfg.Progress
	plan.sendCfg.Progress = func(stats probe.TransferStats) {
		if progress != nil {
			progress(stats)
		}
		if stats.BytesSent > 0 {
			externalDirectUDPValidateDirectProgress(rt.rcfg.pathEmitter, rt.metrics, stats)
			rt.directProgressOnce.Do(func() {
				close(rt.directProgressCh)
				rt.stopRelay()
			})
		}
	}
	directCtx, directCancel := context.WithCancel(rt.ctx)
	defer directCancel()
	directErrCh := make(chan error, 1)
	go func() {
		src := newExternalHandoffSpoolCursor(directCtx, rt.spool, boundary)
		if rt.metrics != nil {
			src = externalTransferMetricsReader{r: src, record: rt.metrics.RecordDirectWrite}
		}
		directErrCh <- externalExecutePreparedDirectUDPSendFn(directCtx, src, plan, rt.rcfg.cfg, rt.metrics)
	}()

	select {
	case relayErr := <-rt.relayErrCh:
		return rt.handleRelayDoneDuringDirect(directCancel, directErrCh, relayErr)
	case directErr := <-directErrCh:
		externalDirectUDPValidateDirectMetricsProgress(rt.rcfg.pathEmitter, rt.metrics)
		return rt.handleDirectDoneBeforeRelay(directErr)
	case <-rt.ctx.Done():
		directCancel()
		return rt.cancelWithPeerError()
	}
}

func (rt *externalRelayPrefixSendRuntime) handleRelayDoneDuringDirect(directCancel context.CancelFunc, directErrCh <-chan error, relayErr error) error {
	if rt.hasDirectProgress() {
		directErr := <-directErrCh
		externalDirectUDPValidateDirectMetricsProgress(rt.rcfg.pathEmitter, rt.metrics)
		if directErr != nil {
			if rt.relayCompletedAfterDirectProgress(relayErr, directErr) {
				rt.finishOnRelay()
				return nil
			}
			return directErr
		}
		return relayErr
	}
	if relayErr == nil && rt.spool.Done() {
		directCancel()
		rt.finishOnRelay()
		return nil
	}
	directCancel()
	if relayErr != nil {
		return relayErr
	}
	rt.finishOnRelay()
	return nil
}

func (rt *externalRelayPrefixSendRuntime) relayCompletedAfterDirectProgress(relayErr error, directErr error) bool {
	return relayErr == nil &&
		rt.spool != nil &&
		rt.spool.Done() &&
		errors.Is(directErr, context.Canceled)
}

func (rt *externalRelayPrefixSendRuntime) handleDirectDoneBeforeRelay(directErr error) error {
	if !rt.hasDirectProgress() {
		if directErr != nil && rt.rcfg.cfg.Emitter != nil {
			rt.rcfg.cfg.Emitter.Debug("udp-handoff-send-direct-before-progress-error=" + directErr.Error())
		}
		if relayErr := rt.waitRelayErr(); relayErr != nil {
			return relayErr
		}
		rt.finishOnRelay()
		return nil
	}
	rt.stopRelay()
	relayErr := rt.waitRelayErr()
	if directErr != nil {
		return directErr
	}
	return relayErr
}

func (rt *externalRelayPrefixSendRuntime) hasDirectProgress() bool {
	select {
	case <-rt.directProgressCh:
		return true
	default:
		return false
	}
}

func (rt *externalRelayPrefixSendRuntime) cancelWithPeerError() error {
	rt.prepCancel()
	rt.stopRelay()
	return normalizePeerAbortError(rt.ctx, rt.ctx.Err())
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
	rt, err := newExternalRelayPrefixReceiveRuntime(ctx, rcfg)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run()
}

type externalRelayPrefixReceivePrepResult struct {
	plan externalDirectUDPReceivePlan
	err  error
}

type externalRelayPrefixReceiveRuntime struct {
	ctx             context.Context
	rcfg            externalRelayPrefixReceiveConfig
	metrics         *externalTransferMetrics
	rx              *externalHandoffReceiver
	keepaliveCancel context.CancelFunc
	relayErrCh      chan error
	prepCtx         context.Context
	prepCancel      context.CancelFunc
	directReadyCh   <-chan struct{}
	prepCh          chan externalRelayPrefixReceivePrepResult
	directActivated bool
	relayHandedOff  bool
}

func newExternalRelayPrefixReceiveRuntime(ctx context.Context, rcfg externalRelayPrefixReceiveConfig) (*externalRelayPrefixReceiveRuntime, error) {
	metrics := newExternalTransferMetricsWithTrace(time.Now(), rcfg.cfg.Trace, transfertrace.RoleReceive)
	metrics.SetPhase(transfertrace.PhaseRelay, "connected-relay")
	ctx = withExternalTransferMetrics(ctx, metrics)
	packetAEAD, err := externalSessionPacketAEAD(rcfg.tok)
	if err != nil {
		return nil, err
	}
	rx := newExternalHandoffReceiver(rcfg.dst, externalHandoffMaxUnackedBytes)
	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	go externalRelayPrefixTransportKeepalive(keepaliveCtx, rcfg.transportManager)
	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- externalReceiveExternalHandoffDERPFn(ctx, rcfg.derpClient, rcfg.peerDERP, rx, rcfg.relayPackets, metrics, packetAEAD)
	}()
	prepCtx, prepCancel := context.WithCancel(ctx)
	prepCtx, directReadyCh := withExternalDirectUDPDirectReadySignal(prepCtx)
	prepCtx = withExternalDirectUDPStartWait(prepCtx, 0)
	rt := &externalRelayPrefixReceiveRuntime{
		ctx:             ctx,
		rcfg:            rcfg,
		metrics:         metrics,
		rx:              rx,
		keepaliveCancel: keepaliveCancel,
		relayErrCh:      relayErrCh,
		prepCtx:         prepCtx,
		prepCancel:      prepCancel,
		directReadyCh:   directReadyCh,
		prepCh:          make(chan externalRelayPrefixReceivePrepResult, 1),
	}
	rt.startPrepare()
	return rt, nil
}

func (rt *externalRelayPrefixReceiveRuntime) Close() {
	if rt.prepCancel != nil {
		rt.prepCancel()
	}
	if rt.keepaliveCancel != nil {
		rt.keepaliveCancel()
	}
}

func (rt *externalRelayPrefixReceiveRuntime) startPrepare() {
	peerAddr := externalRelayPrefixPeerAddr(rt.rcfg.transportManager)
	externalDirectUDPBeginTryingDirect(rt.rcfg.pathEmitter, rt.metrics)
	go func() {
		plan, err := externalPrepareDirectUDPReceiveFn(rt.prepCtx, rt.rcfg.dst, rt.rcfg.tok, rt.rcfg.derpClient, rt.rcfg.peerDERP, peerAddr, rt.rcfg.probeConns, rt.rcfg.remoteCandidates, rt.rcfg.decision, rt.rcfg.readyCh, rt.rcfg.startCh, rt.rcfg.cfg)
		rt.prepCh <- externalRelayPrefixReceivePrepResult{plan: plan, err: err}
	}()
}

func (rt *externalRelayPrefixReceiveRuntime) run() error {
	for {
		if rt.drainDirectReady() {
			continue
		}
		select {
		case relayErr := <-rt.relayErrCh:
			if err, done := rt.handleRelayErr(relayErr); done {
				return err
			}
		case <-rt.directReadyCh:
			rt.directReadyCh = nil
			rt.activateDirect()
		case prep := <-rt.prepCh:
			return rt.handlePrep(prep)
		}
	}
}

func (rt *externalRelayPrefixReceiveRuntime) activateDirect() {
	if rt.directActivated {
		return
	}
	externalDirectUDPActivateDirectPath(rt.rcfg.pathEmitter, rt.rcfg.transportManager, rt.rcfg.punchCancel)
	rt.directActivated = true
}

func (rt *externalRelayPrefixReceiveRuntime) drainDirectReady() bool {
	if rt.directReadyCh == nil {
		return false
	}
	select {
	case <-rt.directReadyCh:
		rt.directReadyCh = nil
		rt.activateDirect()
		return true
	default:
		return false
	}
}

func (rt *externalRelayPrefixReceiveRuntime) handleRelayErr(relayErr error) (error, bool) {
	if relayErr == nil {
		rt.prepCancel()
		rt.finishOnRelay()
		return nil, true
	}
	if !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
		rt.prepCancel()
		rt.metrics.SetError(relayErr)
		return relayErr, true
	}
	rt.relayErrCh = nil
	rt.relayHandedOff = true
	return nil, false
}

func (rt *externalRelayPrefixReceiveRuntime) finishOnRelay() {
	if rt.rcfg.cfg.Emitter != nil {
		rt.rcfg.cfg.Emitter.Debug("udp-handoff-finished-on-relay=true")
	}
	emitExternalTransferMetricsComplete(rt.metrics, rt.rcfg.cfg.Emitter, "udp-receive", probe.TransferStats{}, time.Now())
}

func (rt *externalRelayPrefixReceiveRuntime) handlePrep(prep externalRelayPrefixReceivePrepResult) error {
	if prep.err != nil {
		return rt.handlePrepErr(prep.err)
	}
	prep.plan.receiveDst = newExternalHandoffOffsetWriter(rt.rx, prep.plan.start.RelayPrefixOffset, func(delivery externalHandoffDelivery) {
		rt.recordReceiveDelivery(delivery)
	})
	prep.plan.receiveDstRecordsDirectMetrics = true
	rt.activateDirect()
	externalDirectUDPValidateDirectProbe(rt.rcfg.pathEmitter, rt.metrics, prep.plan.receivedProbeSamples)
	return rt.executePreparedDirectReceive(prep.plan)
}

func (rt *externalRelayPrefixReceiveRuntime) executePreparedDirectReceive(plan externalDirectUDPReceivePlan) error {
	externalDirectUDPInstallReceiveProgressValidation(&plan, rt.rcfg.pathEmitter, rt.metrics)
	directCtx, directCancel := context.WithCancel(rt.ctx)
	defer directCancel()
	directErrCh := make(chan error, 1)
	go func() {
		directErrCh <- externalExecutePreparedDirectUDPReceiveFn(directCtx, plan, rt.rcfg.tok, rt.rcfg.cfg, rt.metrics)
	}()

	if rt.relayHandedOff {
		directErr := <-directErrCh
		externalDirectUDPValidateDirectMetricsProgress(rt.rcfg.pathEmitter, rt.metrics)
		return directErr
	}

	select {
	case relayErr := <-rt.relayErrCh:
		return rt.handleRelayDoneDuringDirectReceive(directCancel, directErrCh, relayErr)
	case directErr := <-directErrCh:
		externalDirectUDPValidateDirectMetricsProgress(rt.rcfg.pathEmitter, rt.metrics)
		return rt.waitRelayOrReturnDirectError(directErr)
	case <-rt.ctx.Done():
		directCancel()
		return normalizePeerAbortError(rt.ctx, rt.ctx.Err())
	}
}

func (rt *externalRelayPrefixReceiveRuntime) handleRelayDoneDuringDirectReceive(directCancel context.CancelFunc, directErrCh <-chan error, relayErr error) error {
	if relayErr == nil {
		directCancel()
		rt.finishOnRelay()
		return nil
	}
	if !errors.Is(relayErr, errExternalHandoffCarrierHandoff) {
		directCancel()
		return relayErr
	}
	rt.relayHandedOff = true
	directErr := <-directErrCh
	externalDirectUDPValidateDirectMetricsProgress(rt.rcfg.pathEmitter, rt.metrics)
	return directErr
}

func (rt *externalRelayPrefixReceiveRuntime) recordReceiveDelivery(delivery externalHandoffDelivery) {
	if rt.metrics == nil {
		return
	}
	now := time.Now()
	if delivery.Relay > 0 {
		rt.metrics.RecordRelayWrite(delivery.Relay, now)
	}
	if delivery.Direct > 0 {
		rt.metrics.RecordDirectWrite(delivery.Direct, now)
		externalDirectUDPMarkDirectValidated(rt.rcfg.pathEmitter, rt.metrics)
	}
}

func (rt *externalRelayPrefixReceiveRuntime) handlePrepErr(prepErr error) error {
	if rt.rcfg.cfg.Emitter != nil {
		rt.rcfg.cfg.Emitter.Debug("udp-handoff-receive-prepare-error=" + prepErr.Error())
	}
	if rt.relayHandedOff {
		rt.metrics.SetError(prepErr)
		return prepErr
	}
	externalDirectUDPMarkDirectFallbackRelay(rt.rcfg.pathEmitter, rt.metrics, prepErr)
	return rt.waitRelayOrReturnDirectError(prepErr)
}

func (rt *externalRelayPrefixReceiveRuntime) waitRelayOrReturnDirectError(directErr error) error {
	if rt.relayHandedOff {
		return directErr
	}
	relayErr := <-rt.relayErrCh
	switch {
	case relayErr == nil:
		rt.finishOnRelay()
		return nil
	case errors.Is(relayErr, errExternalHandoffCarrierHandoff):
		rt.metrics.SetError(directErr)
		return directErr
	default:
		rt.metrics.SetError(relayErr)
		return relayErr
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
	if !externalDirectUDPSenderCapsConstrainRetainedLanes(caps) {
		return retainedLanes
	}
	if externalDirectUDPLegacySenderCanRetainLanes(caps, selectedRateMbps, activeRateMbps) {
		return retainedLanes
	}
	if externalDirectUDPBatchedSenderCanRetainLanes(caps, selectedRateMbps, activeRateMbps, rateCeilingMbps, retainedLanes) {
		return retainedLanes
	}
	return 2
}

func externalDirectUDPSenderCapsConstrainRetainedLanes(caps probe.TransportCaps) bool {
	return caps.Kind == "legacy" || caps.Kind == "batched"
}

func externalDirectUDPLegacySenderCanRetainLanes(caps probe.TransportCaps, selectedRateMbps int, activeRateMbps int) bool {
	return caps.Kind == "legacy" &&
		selectedRateMbps < externalDirectUDPActiveLaneTwoMaxMbps &&
		activeRateMbps < externalDirectUDPActiveLaneTwoMaxMbps
}

func externalDirectUDPBatchedSenderCanRetainLanes(caps probe.TransportCaps, selectedRateMbps int, activeRateMbps int, rateCeilingMbps int, retainedLanes int) bool {
	return caps.Kind == "batched" &&
		(caps.TXOffload ||
			caps.RXQOverflow ||
			externalDirectUDPLowPerLaneCeiling(rateCeilingMbps, retainedLanes) ||
			externalDirectUDPLowTotalCeiling(rateCeilingMbps) ||
			externalDirectUDPLowSelectedAndActiveRates(selectedRateMbps, activeRateMbps))
}

func externalDirectUDPLowPerLaneCeiling(rateCeilingMbps int, retainedLanes int) bool {
	return rateCeilingMbps > 0 && retainedLanes > 0 && rateCeilingMbps/retainedLanes <= externalDirectUDPActiveLaneOneMaxMbps
}

func externalDirectUDPLowTotalCeiling(rateCeilingMbps int) bool {
	return rateCeilingMbps > 0 && rateCeilingMbps <= externalDirectUDPDataStartHighMbps
}

func externalDirectUDPLowSelectedAndActiveRates(selectedRateMbps int, activeRateMbps int) bool {
	return selectedRateMbps < externalDirectUDPActiveLaneTwoMaxMbps && activeRateMbps < externalDirectUDPActiveLaneTwoMaxMbps
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
	selector := newExternalDirectUDPSenderProbeRateLimitSelector(sent)
	for _, sample := range received {
		selector.observe(sample)
	}
	return selector.result()
}

type externalDirectUDPSenderProbeRateLimitSelector struct {
	sentByRate    map[int]directUDPRateProbeSample
	cleanLimit    externalDirectUDPSenderProbeRateLimitResult
	lossyLimit    externalDirectUDPSenderProbeRateLimitResult
	lossyScore    int
	lowCleanLimit externalDirectUDPSenderProbeRateLimitResult
}

func newExternalDirectUDPSenderProbeRateLimitSelector(sent []directUDPRateProbeSample) *externalDirectUDPSenderProbeRateLimitSelector {
	return &externalDirectUDPSenderProbeRateLimitSelector{
		sentByRate: externalDirectUDPProbeSamplesByRate(sent),
	}
}

func (s *externalDirectUDPSenderProbeRateLimitSelector) observe(sample directUDPRateProbeSample) {
	if sample.RateMbps < externalDirectUDPActiveLaneTwoMaxMbps {
		return
	}
	goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok || goodput <= 0 {
		return
	}
	if delivery >= externalDirectUDPRateProbeClean {
		s.observeClean(sample.RateMbps)
		return
	}
	s.observeLossy(sample.RateMbps, goodput, delivery)
}

func (s *externalDirectUDPSenderProbeRateLimitSelector) observeClean(rateMbps int) {
	limit := externalDirectUDPBatchOnlyCleanProbeRateLimit(rateMbps)
	if rateMbps >= externalDirectUDPRateProbeCollapseMinMbps {
		if rateMbps > s.cleanLimit.CeilingMbps {
			s.cleanLimit = limit
		}
		return
	}
	if rateMbps > s.lowCleanLimit.CeilingMbps {
		s.lowCleanLimit = limit
	}
}

func (s *externalDirectUDPSenderProbeRateLimitSelector) observeLossy(rateMbps int, goodput float64, delivery float64) {
	if rateMbps < externalDirectUDPRateProbeCollapseMinMbps ||
		delivery < externalDirectUDPRateProbeBufferedCollapse ||
		goodput < externalDirectUDPRateProbeHighHeadroomMin {
		return
	}
	limit := externalDirectUDPBatchOnlyLossyProbeRateLimit(rateMbps, goodput, delivery)
	if limit.StartMbps <= s.lossyScore {
		return
	}
	s.lossyScore = limit.StartMbps
	s.lossyLimit = limit
}

func (s *externalDirectUDPSenderProbeRateLimitSelector) result() externalDirectUDPSenderProbeRateLimitResult {
	switch {
	case s.cleanLimit.CeilingMbps > 0:
		return s.cleanLimit
	case s.lossyLimit.CeilingMbps > 0 && s.lowCleanLimit.CeilingMbps > 0 && s.lowCleanLimit.StartMbps >= s.lossyLimit.StartMbps:
		return s.lowCleanLimit
	case s.lossyLimit.CeilingMbps > 0:
		return s.lossyLimit
	case s.lowCleanLimit.CeilingMbps > 0:
		return s.lowCleanLimit
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
	rt, err := newExternalHandoffDERPSendRuntime(ctx, client, peerDERP, spool, stop, metrics, packetAEAD)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run()
}

type externalHandoffDERPSendRuntime struct {
	ctx              context.Context
	client           *derpbind.Client
	peerDERP         key.NodePublic
	spool            *externalHandoffSpool
	stop             <-chan struct{}
	metrics          *externalTransferMetrics
	packetAEAD       cipher.AEAD
	ackEvents        chan int64
	handoffAckEvents chan int64
	ackErrCh         chan error
	stopWatchDone    chan struct{}
	unsubscribe      func()
}

func newExternalHandoffDERPSendRuntime(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, spool *externalHandoffSpool, stop <-chan struct{}, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) (*externalHandoffDERPSendRuntime, error) {
	if client == nil {
		return nil, errors.New("nil DERP client")
	}
	if spool == nil {
		return nil, errors.New("nil external handoff spool")
	}
	rt := &externalHandoffDERPSendRuntime{
		ctx:              ctx,
		client:           client,
		peerDERP:         peerDERP,
		spool:            spool,
		stop:             stop,
		metrics:          metrics,
		packetAEAD:       packetAEAD,
		ackEvents:        make(chan int64, 128),
		handoffAckEvents: make(chan int64, 16),
		ackErrCh:         make(chan error, 1),
	}
	rt.startStopWatcher()
	rt.startAckReader()
	return rt, nil
}

func (rt *externalHandoffDERPSendRuntime) Close() {
	if rt.unsubscribe != nil {
		rt.unsubscribe()
	}
	if rt.stopWatchDone != nil {
		close(rt.stopWatchDone)
	}
}

func (rt *externalHandoffDERPSendRuntime) startStopWatcher() {
	if rt.stop == nil {
		return
	}
	rt.stopWatchDone = make(chan struct{})
	go func() {
		select {
		case <-rt.stop:
			select {
			case <-rt.stopWatchDone:
				return
			default:
			}
			rt.spool.InterruptPendingRead()
		case <-rt.stopWatchDone:
		}
	}()
}

func (rt *externalHandoffDERPSendRuntime) startAckReader() {
	ackPackets, unsubscribe := rt.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		kind := externalRelayPrefixDERPFrameKindOf(pkt.Payload)
		return pkt.From == rt.peerDERP && (kind == externalRelayPrefixDERPFrameAck || kind == externalRelayPrefixDERPFrameHandoffAck)
	})
	rt.unsubscribe = unsubscribe
	go rt.readAcks(ackPackets)
}

func (rt *externalHandoffDERPSendRuntime) readAcks(ackPackets <-chan derpbind.Packet) {
	for {
		pkt, err := receiveSubscribedPacket(rt.ctx, ackPackets)
		if err != nil {
			rt.ackErrCh <- err
			return
		}
		if err := rt.handleAckPacket(pkt.Payload); err != nil {
			rt.ackErrCh <- err
			return
		}
		if rt.spool.Done() {
			rt.ackErrCh <- nil
			return
		}
	}
}

func (rt *externalHandoffDERPSendRuntime) handleAckPacket(payload []byte) error {
	watermark, err := externalRelayPrefixDERPDecodeAck(payload)
	if err != nil {
		return err
	}
	if err := rt.spool.AckTo(watermark); err != nil {
		return err
	}
	kind := externalRelayPrefixDERPFrameKindOf(payload)
	if kind == externalRelayPrefixDERPFrameHandoffAck {
		externalTransferTracef("sender-derp-prefix-handoff-ack watermark=%d", watermark)
		externalRelayPrefixOfferAck(rt.handoffAckEvents, watermark)
		return nil
	}
	externalTransferTracef("sender-derp-prefix-ack watermark=%d", watermark)
	externalRelayPrefixOfferAck(rt.ackEvents, watermark)
	return nil
}

func externalRelayPrefixOfferAck(events chan<- int64, watermark int64) {
	select {
	case events <- watermark:
	default:
	}
}

func (rt *externalHandoffDERPSendRuntime) run() error {
	for {
		done, err := rt.handleStopBeforeRead()
		if done || err != nil {
			return err
		}
		if err := externalDirectUDPHandoffRelayPauseWait(rt.ctx, rt.stop); err != nil {
			return err
		}
		rt.raiseSustainedWindowIfReady()
		done, err = rt.sendNextChunk()
		if done || err != nil {
			return err
		}
	}
}

func (rt *externalHandoffDERPSendRuntime) handleStopBeforeRead() (bool, error) {
	if rt.stop == nil {
		return false, nil
	}
	select {
	case <-rt.stop:
		return rt.finishOnStop("sender-derp-prefix-handoff-fast")
	default:
		return false, nil
	}
}

func (rt *externalHandoffDERPSendRuntime) finishOnStop(traceName string) (bool, error) {
	if rt.spool.Done() {
		return true, nil
	}
	if rt.spool.AllSourceBytesSent() {
		externalTransferTracef("%s-finish-eof final=%d acked=%d", traceName, rt.spool.Snapshot().SourceOffset, rt.spool.AckedWatermark())
		return true, rt.sendEOFAndWait()
	}
	boundary, ready := rt.handoffBoundary()
	if !ready {
		return false, nil
	}
	externalTransferTracef("%s boundary=%d acked=%d", traceName, boundary, rt.spool.AckedWatermark())
	return true, rt.sendHandoffAndWaitForAck(boundary)
}

func (rt *externalHandoffDERPSendRuntime) raiseSustainedWindowIfReady() {
	if rt.spool.Snapshot().ReadOffset >= externalRelayPrefixDERPStartupBytes {
		rt.spool.SetMaxUnacked(externalRelayPrefixDERPSustainedMax)
	}
}

func (rt *externalHandoffDERPSendRuntime) sendNextChunk() (bool, error) {
	chunk, err := rt.spool.NextChunk()
	switch {
	case err == nil:
		return false, rt.sendChunk(chunk)
	case errors.Is(err, io.EOF):
		return true, rt.sendEOFAndWait()
	case externalHandoffDERPShouldWaitForBackpressure(err):
		return rt.waitForBackpressure()
	default:
		return true, err
	}
}

func externalHandoffDERPShouldWaitForBackpressure(err error) bool {
	return errors.Is(err, errExternalHandoffUnackedWindowFull) || errors.Is(err, errExternalHandoffSourcePending)
}

func (rt *externalHandoffDERPSendRuntime) sendChunk(chunk externalHandoffChunk) error {
	externalTransferTracef("sender-derp-prefix-data offset=%d bytes=%d", chunk.Offset, len(chunk.Payload))
	if err := externalRelayPrefixDERPSendChunk(rt.ctx, rt.client, rt.peerDERP, chunk, rt.packetAEAD); err != nil {
		return err
	}
	if rt.metrics != nil {
		rt.metrics.RecordRelayWrite(int64(len(chunk.Payload)), time.Now())
	}
	return nil
}

func (rt *externalHandoffDERPSendRuntime) sendEOFAndWait() error {
	finalOffset := rt.spool.Snapshot().SourceOffset
	externalTransferTracef("sender-derp-prefix-eof final=%d acked=%d", finalOffset, rt.spool.AckedWatermark())
	if err := externalRelayPrefixDERPSendEOF(rt.ctx, rt.client, rt.peerDERP, finalOffset); err != nil {
		return err
	}
	return rt.waitForCompleteAck()
}

func (rt *externalHandoffDERPSendRuntime) waitForBackpressure() (bool, error) {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-rt.stop:
		return rt.finishOnStop("sender-derp-prefix-handoff")
	case err := <-rt.ackErrCh:
		return true, err
	case <-rt.ackEvents:
		return false, nil
	case <-rt.ctx.Done():
		return true, rt.ctx.Err()
	case <-timer.C:
		return false, nil
	}
}

func (rt *externalHandoffDERPSendRuntime) waitForAnyAck() error {
	select {
	case err := <-rt.ackErrCh:
		return err
	case <-rt.ackEvents:
		return nil
	case <-rt.ctx.Done():
		return rt.ctx.Err()
	}
}

func (rt *externalHandoffDERPSendRuntime) drainAckEvents() {
	for {
		select {
		case <-rt.ackEvents:
		case <-rt.handoffAckEvents:
		default:
			return
		}
	}
}

func (rt *externalHandoffDERPSendRuntime) waitForHandoffAck(boundary int64) error {
	timer := time.NewTimer(externalRelayPrefixDERPHandoffAckWait)
	defer timer.Stop()
	for {
		if rt.spool.AckedWatermark() >= boundary {
			return nil
		}
		select {
		case err := <-rt.ackErrCh:
			return err
		case <-rt.handoffAckEvents:
			return nil
		case <-rt.ackEvents:
		case <-rt.ctx.Done():
			return rt.ctx.Err()
		case <-timer.C:
			return ErrPeerDisconnected
		}
	}
}

func (rt *externalHandoffDERPSendRuntime) sendHandoffAndWaitForAck(boundary int64) error {
	rt.drainAckEvents()
	if err := externalRelayPrefixDERPSendHandoff(rt.ctx, rt.client, rt.peerDERP, boundary); err != nil {
		return err
	}
	if rt.spool.AckedWatermark() >= boundary {
		return nil
	}
	return rt.waitForHandoffAck(boundary)
}

func (rt *externalHandoffDERPSendRuntime) waitForCompleteAck() error {
	for {
		if rt.spool.Done() {
			return nil
		}
		if err := rt.waitForAnyAck(); err != nil {
			return err
		}
	}
}

func (rt *externalHandoffDERPSendRuntime) handoffBoundary() (int64, bool) {
	snapshot := rt.spool.Snapshot()
	return snapshot.ReadOffset, snapshot.ReadOffset > 0
}

func receiveExternalHandoffDERP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, rx *externalHandoffReceiver, packets <-chan derpbind.Packet, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) error {
	externalTransferTracef("listener-derp-prefix-start")
	rt, err := newExternalHandoffDERPReceiveRuntime(ctx, client, peerDERP, rx, packets, metrics, packetAEAD)
	if err != nil {
		return err
	}
	defer rt.Close()
	return rt.run()
}

type externalHandoffDERPReceiveRuntime struct {
	ctx         context.Context
	client      *derpbind.Client
	peerDERP    key.NodePublic
	rx          *externalHandoffReceiver
	packets     <-chan derpbind.Packet
	metrics     *externalTransferMetrics
	packetAEAD  cipher.AEAD
	eofOffset   int64
	unsubscribe func()
}

func newExternalHandoffDERPReceiveRuntime(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, rx *externalHandoffReceiver, packets <-chan derpbind.Packet, metrics *externalTransferMetrics, packetAEAD cipher.AEAD) (*externalHandoffDERPReceiveRuntime, error) {
	if client == nil {
		return nil, errors.New("nil DERP client")
	}
	if rx == nil {
		return nil, errors.New("nil external handoff receiver")
	}
	rt := &externalHandoffDERPReceiveRuntime{
		ctx:        ctx,
		client:     client,
		peerDERP:   peerDERP,
		rx:         rx,
		packets:    packets,
		metrics:    metrics,
		packetAEAD: packetAEAD,
		eofOffset:  -1,
	}
	rt.ensureSubscription()
	return rt, nil
}

func (rt *externalHandoffDERPReceiveRuntime) ensureSubscription() {
	if rt.packets != nil {
		return
	}
	packets, unsubscribe := rt.client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == rt.peerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
	})
	rt.packets = packets
	rt.unsubscribe = unsubscribe
}

func (rt *externalHandoffDERPReceiveRuntime) Close() {
	if rt.unsubscribe != nil {
		rt.unsubscribe()
	}
}

func (rt *externalHandoffDERPReceiveRuntime) run() error {
	for {
		pkt, err := receiveSubscribedPacket(rt.ctx, rt.packets)
		if err != nil {
			return err
		}
		if done, err := rt.handlePacket(pkt.Payload); done || err != nil {
			return err
		}
	}
}

func (rt *externalHandoffDERPReceiveRuntime) handlePacket(payload []byte) (bool, error) {
	kind := externalRelayPrefixDERPFrameKindOf(payload)
	externalTransferTracef("listener-derp-prefix-frame kind=%d bytes=%d watermark=%d", kind, len(payload), rt.rx.Watermark())
	switch kind {
	case externalRelayPrefixDERPFrameData:
		return rt.handleData(payload)
	case externalRelayPrefixDERPFrameEOF:
		return rt.handleEOF(payload)
	case externalRelayPrefixDERPFrameHandoff:
		return true, rt.handleHandoff(payload)
	case externalRelayPrefixDERPFrameAck:
		return false, nil
	default:
		return true, errors.New("unexpected relay-prefix DERP frame")
	}
}

func (rt *externalHandoffDERPReceiveRuntime) handleData(payload []byte) (bool, error) {
	chunk, err := externalRelayPrefixDERPDecodeChunk(payload, rt.packetAEAD)
	if err != nil {
		return true, err
	}
	delivery, err := rt.rx.AcceptChunkFrom(chunk, externalHandoffChunkSourceRelay)
	if err != nil {
		return true, err
	}
	rt.recordDelivery(delivery)
	if err := externalRelayPrefixDERPSendAck(rt.ctx, rt.client, rt.peerDERP, rt.rx.Watermark()); err != nil {
		return true, err
	}
	return rt.finishIfBoundaryReached()
}

func (rt *externalHandoffDERPReceiveRuntime) recordDelivery(delivery externalHandoffDelivery) {
	if rt.metrics == nil {
		return
	}
	now := time.Now()
	if delivery.Relay > 0 {
		rt.metrics.RecordRelayWrite(delivery.Relay, now)
	}
	if delivery.Direct > 0 {
		rt.metrics.RecordDirectWrite(delivery.Direct, now)
	}
}

func (rt *externalHandoffDERPReceiveRuntime) handleEOF(payload []byte) (bool, error) {
	offset, err := externalRelayPrefixDERPDecodeOffset(payload)
	if err != nil {
		return true, err
	}
	rt.eofOffset = offset
	return rt.finishIfBoundaryReached()
}

func (rt *externalHandoffDERPReceiveRuntime) handleHandoff(payload []byte) error {
	offset, err := externalRelayPrefixDERPDecodeOffset(payload)
	if err != nil {
		return err
	}
	externalTransferTracef("listener-derp-prefix-handoff boundary=%d watermark=%d", offset, rt.rx.Watermark())
	if err := externalRelayPrefixDERPSendHandoffAck(rt.ctx, rt.client, rt.peerDERP, rt.rx.Watermark()); err != nil {
		return err
	}
	return errExternalHandoffCarrierHandoff
}

func (rt *externalHandoffDERPReceiveRuntime) finishIfBoundaryReached() (bool, error) {
	watermark := rt.rx.Watermark()
	if rt.eofOffset < 0 || watermark < rt.eofOffset {
		return false, nil
	}
	if err := externalRelayPrefixDERPSendAck(rt.ctx, rt.client, rt.peerDERP, watermark); err != nil {
		return false, err
	}
	return true, nil
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
			externalDirectUDPCloseOwned(owned, ownedPMs)
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

func externalDirectUDPCloseOwned(conns []net.PacketConn, portmaps []publicPortmap) {
	for _, pm := range portmaps {
		if pm != nil {
			_ = pm.Close()
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
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
	wan, ok := externalDirectUDPFirstWANCandidateAddr(sets)
	if !ok {
		return sets
	}
	out := make([][]string, len(sets))
	for i, candidates := range sets {
		out[i] = append([]string(nil), candidates...)
		port, ok := externalDirectUDPPrivatePortForWANInference(candidates)
		if !ok {
			continue
		}
		inferred := netip.AddrPortFrom(wan, port).String()
		out[i] = append([]string{inferred}, out[i]...)
	}
	return out
}

func externalDirectUDPFirstWANCandidateAddr(sets [][]string) (netip.Addr, bool) {
	for _, candidates := range sets {
		for _, candidate := range candidates {
			addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
			if ok && externalDirectUDPCandidateRank(candidate) == 0 {
				return addrPort.Addr(), true
			}
		}
	}
	return netip.Addr{}, false
}

func externalDirectUDPPrivatePortForWANInference(candidates []string) (uint16, bool) {
	var port uint16
	for _, candidate := range candidates {
		addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
		if !ok {
			continue
		}
		if externalDirectUDPCandidateRank(candidate) == 0 {
			return 0, false
		}
		if port == 0 && addrPort.Addr().IsPrivate() {
			port = addrPort.Port()
		}
	}
	return port, port != 0
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
	if externalDirectUDPShouldKeepObservedSelection(ctx, selected, peer) {
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

func externalDirectUDPShouldKeepObservedSelection(ctx context.Context, selected []string, peer net.Addr) bool {
	if peer != nil || externalDirectUDPAllowUnverifiedFallback(ctx) {
		return false
	}
	return externalDirectUDPSelectedAddrCount(selected) == 0
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
	ordered := externalDirectUDPOrderedCandidateStringsForPeer(candidates, peer)
	out, seen := externalDirectUDPAppendUniqueEndpointCandidates(nil, ordered, parallel)
	out, _ = externalDirectUDPAppendUniqueCandidates(out, seen, ordered, parallel)
	return out
}

func externalDirectUDPOrderedCandidateStringsForPeer(candidates []net.Addr, peer net.Addr) []string {
	ordered := externalDirectUDPAppendPeerCandidate(probe.CandidateStringsInOrder(candidates), peer)
	if fakeTransportEnabled() {
		return externalDirectUDPPreferLoopbackStrings(ordered)
	}
	return externalDirectUDPPreferPeerAddrStrings(ordered, peer)
}

func externalDirectUDPAppendPeerCandidate(ordered []string, peer net.Addr) []string {
	peerAddr, ok := externalDirectUDPAddrPort(peer)
	if !ok {
		return ordered
	}
	peerCandidate := peerAddr.String()
	if slices.Contains(ordered, peerCandidate) {
		return ordered
	}
	return append(ordered, peerCandidate)
}

func externalDirectUDPAppendUniqueEndpointCandidates(out []string, candidates []string, limit int) ([]string, map[string]bool) {
	seen := make(map[string]bool)
	seenEndpoint := make(map[string]bool)
	if len(out) >= limit {
		return out, seen
	}
	for _, candidate := range candidates {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if candidate == "" || seen[candidate] || seenEndpoint[endpoint] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		seenEndpoint[endpoint] = true
		if len(out) >= limit {
			return out, seen
		}
	}
	return out, seen
}

func externalDirectUDPAppendUniqueCandidates(out []string, seen map[string]bool, candidates []string, limit int) ([]string, map[string]bool) {
	if len(out) >= limit {
		return out, seen
	}
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		out = append(out, candidate)
		seen[candidate] = true
		if len(out) >= limit {
			return out, seen
		}
	}
	return out, seen
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
	addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
	if !ok {
		return 6
	}
	return externalDirectUDPAddrCandidateRank(addrPort.Addr())
}

func externalDirectUDPParsedCandidateAddrPort(candidate string) (netip.AddrPort, bool) {
	addrPort, err := netip.ParseAddrPort(candidate)
	if err != nil {
		return netip.AddrPort{}, false
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

func externalDirectUDPAddrCandidateRank(addr netip.Addr) int {
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
	probeMaxMbps := externalDirectUDPProbeMaxRateMbps(maxRateMbps)
	bases := []int{8, 25, 75, 150, 350, 700, 1000, 1200, 1800, 2000, 2250}
	out := make([]int, 0, len(bases))
	seen := make(map[int]bool)
	for _, rate := range bases {
		out = externalDirectUDPAppendProbeRate(out, seen, rate, probeMaxMbps)
	}
	out = externalDirectUDPAppendProbeRate(out, seen, probeMaxMbps, probeMaxMbps)
	if len(out) == 0 {
		out = append(out, probeMaxMbps)
	}
	return out
}

func externalDirectUDPProbeMaxRateMbps(maxRateMbps int) int {
	if maxRateMbps > externalDirectUDPRateProbeDefaultMaxMbps {
		return externalDirectUDPRateProbeDefaultMaxMbps
	}
	return maxRateMbps
}

func externalDirectUDPAppendProbeRate(out []int, seen map[int]bool, rate int, probeMaxMbps int) []int {
	if rate < externalDirectUDPRateProbeMinMbps || rate > probeMaxMbps || seen[rate] {
		return out
	}
	seen[rate] = true
	return append(out, rate)
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
	sender, err := newExternalDirectUDPRateProbeSender(ctx, conns, remoteAddrs, rates, auth)
	if err != nil {
		return nil, err
	}
	return sender.run()
}

type externalDirectUDPRateProbeSender struct {
	ctx     context.Context
	conns   []net.PacketConn
	remotes []*net.UDPAddr
	rates   []int
	auth    externalDirectUDPRateProbeAuth
	samples []directUDPRateProbeSample
}

func newExternalDirectUDPRateProbeSender(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, rates []int, auth externalDirectUDPRateProbeAuth) (*externalDirectUDPRateProbeSender, error) {
	if !auth.enabled() {
		return nil, errors.New("rate probe auth missing")
	}
	if len(conns) == 0 {
		return nil, errors.New("no rate probe conns")
	}
	if len(conns) != len(remoteAddrs) {
		return nil, errors.New("rate probe conns and addrs length mismatch")
	}
	remotes, err := externalDirectUDPRateProbeResolveRemotes(conns, remoteAddrs)
	if err != nil {
		return nil, err
	}
	return &externalDirectUDPRateProbeSender{
		ctx:     ctx,
		conns:   conns,
		remotes: remotes,
		rates:   rates,
		auth:    auth,
		samples: make([]directUDPRateProbeSample, len(rates)),
	}, nil
}

func externalDirectUDPRateProbeResolveRemotes(conns []net.PacketConn, remoteAddrs []string) ([]*net.UDPAddr, error) {
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
	return remotes, nil
}

func (s *externalDirectUDPRateProbeSender) run() ([]directUDPRateProbeSample, error) {
	for i, rate := range s.rates {
		if err := s.sendTier(i, rate); err != nil {
			return s.samples, err
		}
		if i > 0 && i+1 < len(s.rates) && externalDirectUDPRateProbeShouldStopAfterSent(s.samples[i-1], s.samples[i]) {
			return s.samples[:i+1], nil
		}
	}
	return s.samples, nil
}

func (s *externalDirectUDPRateProbeSender) sendTier(index int, rate int) error {
	if rate <= 0 {
		return fmt.Errorf("invalid rate probe rate %d", rate)
	}
	payload, err := externalDirectUDPRateProbePayload(index, externalDirectUDPDataWireSize, s.auth)
	if err != nil {
		return err
	}
	duration := externalDirectUDPRateProbeDurationForRate(rate)
	s.samples[index].RateMbps = rate
	s.samples[index].DurationMillis = duration.Milliseconds()
	s.samples[index].BytesSent, err = s.sendTierPayload(rate, payload, duration)
	return err
}

func (s *externalDirectUDPRateProbeSender) sendTierPayload(rate int, payload []byte, duration time.Duration) (int64, error) {
	tierStart := time.Now()
	deadline := tierStart.Add(duration)
	activeLanes := externalDirectUDPRateProbeActiveLanes(rate, len(s.conns))
	laneRate := externalDirectUDPPerLaneRateMbps(rate, activeLanes)
	sentByLane := make([]int64, len(s.conns))
	errCh := make(chan error, activeLanes)
	tierCtx, cancel := context.WithCancel(s.ctx)
	var wg sync.WaitGroup
	for lane := 0; lane < activeLanes; lane++ {
		wg.Add(1)
		go s.sendTierLane(&wg, cancel, errCh, externalDirectUDPRateProbeLaneSend{
			ctx:        tierCtx,
			lane:       lane,
			payload:    payload,
			deadline:   deadline,
			tierStart:  tierStart,
			laneRate:   laneRate,
			sentByLane: sentByLane,
		})
	}
	wg.Wait()
	cancel()
	if err := externalDirectUDPRateProbeFirstErr(errCh); err != nil {
		return 0, err
	}
	return externalDirectUDPSumInt64(sentByLane), nil
}

type externalDirectUDPRateProbeLaneSend struct {
	ctx        context.Context
	lane       int
	payload    []byte
	deadline   time.Time
	tierStart  time.Time
	laneRate   int
	sentByLane []int64
}

func (s *externalDirectUDPRateProbeSender) sendTierLane(wg *sync.WaitGroup, cancel context.CancelFunc, errCh chan<- error, laneSend externalDirectUDPRateProbeLaneSend) {
	defer wg.Done()
	sent, err := s.runTierLane(laneSend)
	laneSend.sentByLane[laneSend.lane] = sent
	if err == nil {
		return
	}
	errCh <- err
	cancel()
}

func (s *externalDirectUDPRateProbeSender) runTierLane(laneSend externalDirectUDPRateProbeLaneSend) (int64, error) {
	var sent int64
	for time.Now().Before(laneSend.deadline) {
		if err := externalDirectUDPRateProbeActiveErr(laneSend.ctx, s.ctx); err != nil {
			return sent, err
		}
		n, err := s.conns[laneSend.lane].WriteTo(laneSend.payload, s.remotes[laneSend.lane])
		if err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				if err := externalDirectUDPRateProbeSleep(laneSend.ctx, s.ctx, 250*time.Microsecond); err != nil {
					return sent, err
				}
				continue
			}
			return sent, err
		}
		sent += int64(n)
		if err := externalDirectUDPRateProbeThrottle(laneSend.ctx, s.ctx, sent, laneSend.laneRate, laneSend.tierStart, laneSend.deadline); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

func externalDirectUDPRateProbeActiveErr(tierCtx context.Context, parentCtx context.Context) error {
	if err := tierCtx.Err(); err != nil {
		return externalDirectUDPRateProbeContextErr(err, parentCtx)
	}
	return nil
}

func externalDirectUDPRateProbeSleep(tierCtx context.Context, parentCtx context.Context, delay time.Duration) error {
	return externalDirectUDPRateProbeContextErr(sleepWithContext(tierCtx, delay), parentCtx)
}

func externalDirectUDPRateProbeContextErr(err error, parentCtx context.Context) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) && parentCtx.Err() == nil {
		return nil
	}
	return err
}

func externalDirectUDPRateProbeThrottle(tierCtx context.Context, parentCtx context.Context, sent int64, laneRate int, tierStart time.Time, deadline time.Time) error {
	sleepFor := externalDirectUDPRateProbeThrottleDelay(sent, laneRate, tierStart, deadline)
	if sleepFor <= 0 {
		return nil
	}
	return externalDirectUDPRateProbeSleep(tierCtx, parentCtx, sleepFor)
}

func externalDirectUDPRateProbeThrottleDelay(sent int64, laneRate int, tierStart time.Time, deadline time.Time) time.Duration {
	target := int64(float64(laneRate*1000*1000)/8.0*time.Since(tierStart).Seconds() + 0.5)
	if sent <= target {
		return 0
	}
	sleepFor := time.Duration(float64(sent-target) * 8.0 / float64(laneRate*1000*1000) * float64(time.Second))
	if untilDeadline := time.Until(deadline); sleepFor > untilDeadline {
		return untilDeadline
	}
	return sleepFor
}

func externalDirectUDPRateProbeFirstErr(errCh <-chan error) error {
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func externalDirectUDPSumInt64(values []int64) int64 {
	var total int64
	for _, value := range values {
		total += value
	}
	return total
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
		go externalDirectUDPReceiveRateProbePackets(ctx, conn, allowedSources, samples, &mu, auth, errCh, &wg)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return samples, err
	default:
	}
	return samples, nil
}

func externalDirectUDPReceiveRateProbePackets(ctx context.Context, conn net.PacketConn, allowedSources map[string]struct{}, samples []directUDPRateProbeSample, mu *sync.Mutex, auth externalDirectUDPRateProbeAuth, errCh chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, externalDirectUDPDataWireSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			externalDirectUDPReportReceiveRateProbeErr(ctx, err, errCh)
			return
		}
		if !externalDirectUDPRateProbeSourceAllowed(addr, allowedSources) {
			continue
		}
		index, ok := externalDirectUDPRateProbeIndex(buf[:n], len(samples), auth)
		if !ok {
			continue
		}
		externalDirectUDPRecordRateProbeBytes(samples, index, int64(n), mu)
	}
}

func externalDirectUDPReportReceiveRateProbeErr(ctx context.Context, err error, errCh chan<- error) {
	if externalDirectUDPIsNetTimeout(err) {
		return
	}
	if ctx.Err() != nil {
		errCh <- ctx.Err()
		return
	}
	errCh <- err
}

func externalDirectUDPRecordRateProbeBytes(samples []directUDPRateProbeSample, index int, bytesReceived int64, mu *sync.Mutex) {
	mu.Lock()
	samples[index].BytesReceived += bytesReceived
	mu.Unlock()
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

type externalDirectUDPRateProbeCandidate struct {
	rate     int
	goodput  float64
	delivery float64
	score    float64
}

type externalDirectUDPRateProbeSelection struct {
	candidates          []externalDirectUDPRateProbeCandidate
	bestRate            int
	bestGoodput         float64
	bestScore           float64
	bestDelivery        float64
	trimmedLeadingZeros bool
}

func externalDirectUDPSelectRateFromProbeSamples(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	if !externalDirectUDPHasUsableRateProbeInput(maxRateMbps, sent, received) {
		return 0
	}
	selection := externalDirectUDPBuildRateProbeSelection(sent, received)
	if selection.bestRate <= 0 || selection.bestGoodput <= 0 {
		return maxRateMbps
	}
	selection.trimLeadingZeros()
	if len(selection.candidates) == 0 {
		return 0
	}
	if conservativeRate, ok := externalDirectUDPProbeConservativeRampCap(sent, received); ok {
		return conservativeRate
	}
	if selected, ok := externalDirectUDPSelectAfterLeadingZeroProbes(selection); ok {
		return selected
	}
	if selected, ok := externalDirectUDPSelectFromProbeTransitions(maxRateMbps, selection); ok {
		return selected
	}
	return externalDirectUDPFinalSelectedProbeRate(maxRateMbps, selection)
}

func externalDirectUDPHasUsableRateProbeInput(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	return maxRateMbps > 0 &&
		len(sent) > 0 &&
		len(received) > 0 &&
		externalDirectUDPHasPositiveProbeProgress(received)
}

func externalDirectUDPBuildRateProbeSelection(sent []directUDPRateProbeSample, received []directUDPRateProbeSample) externalDirectUDPRateProbeSelection {
	sentByRate := make(map[int]directUDPRateProbeSample, len(sent))
	for _, sample := range sent {
		sentByRate[sample.RateMbps] = sample
	}
	selection := externalDirectUDPRateProbeSelection{
		candidates: make([]externalDirectUDPRateProbeCandidate, 0, len(received)),
	}
	for _, sample := range received {
		candidate := externalDirectUDPRateProbeCandidateForSample(sample, sentByRate)
		selection.candidates = append(selection.candidates, candidate)
		selection.observeCandidate(candidate)
	}
	return selection
}

func externalDirectUDPRateProbeCandidateForSample(sample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) externalDirectUDPRateProbeCandidate {
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
	return externalDirectUDPRateProbeCandidate{
		rate:     sample.RateMbps,
		goodput:  goodput,
		delivery: delivery,
		score:    score,
	}
}

func (s *externalDirectUDPRateProbeSelection) observeCandidate(candidate externalDirectUDPRateProbeCandidate) {
	if candidate.score <= s.bestScore {
		return
	}
	s.bestScore = candidate.score
	s.bestGoodput = candidate.goodput
	s.bestRate = candidate.rate
	s.bestDelivery = candidate.delivery
}

func (s *externalDirectUDPRateProbeSelection) trimLeadingZeros() {
	for len(s.candidates) > 0 && s.candidates[0].goodput <= 0 && s.candidates[0].delivery <= 0 {
		s.trimmedLeadingZeros = true
		s.candidates = s.candidates[1:]
	}
}

func externalDirectUDPSelectAfterLeadingZeroProbes(selection externalDirectUDPRateProbeSelection) (int, bool) {
	candidates := selection.candidates
	if !selection.trimmedLeadingZeros {
		return 0, false
	}
	if len(candidates) < 2 || candidates[0].goodput <= 0 || candidates[0].rate >= externalDirectUDPRateProbeCollapseMinMbps {
		return 0, false
	}
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
		return externalDirectUDPCapSenderLimitedProbeRate(current.rate, candidates), true
	}
	return 0, false
}

func externalDirectUDPCapSenderLimitedProbeRate(rate int, candidates []externalDirectUDPRateProbeCandidate) int {
	if rate < externalDirectUDPRateProbeCollapseMinMbps {
		return rate
	}
	selected, selectedOK, previous, previousOK, bestEfficient, bestEfficientOK := externalDirectUDPSenderLimitedProbeContext(rate, candidates)
	if !selectedOK || !bestEfficientOK || bestEfficient.rate >= rate {
		return rate
	}
	if externalDirectUDPShouldKeepSenderLimitedProbeRate(selected, previous, previousOK, bestEfficient) {
		return rate
	}
	return bestEfficient.rate
}

func externalDirectUDPShouldKeepSenderLimitedProbeRate(selected externalDirectUDPRateProbeCandidate, previous externalDirectUDPRateProbeCandidate, previousOK bool, bestEfficient externalDirectUDPRateProbeCandidate) bool {
	selectedEfficiency := externalDirectUDPRateProbeEfficiency(selected)
	if selected.delivery < externalDirectUDPRateProbeClean || selectedEfficiency >= externalDirectUDPRateProbeEfficient {
		return true
	}
	if previousOK && previous.goodput > 0 && selected.goodput >= previous.goodput*externalDirectUDPRateProbeModerateGain {
		return true
	}
	return selected.goodput >= bestEfficient.goodput*externalDirectUDPRateProbeMaterialGain
}

func externalDirectUDPSenderLimitedProbeContext(rate int, candidates []externalDirectUDPRateProbeCandidate) (externalDirectUDPRateProbeCandidate, bool, externalDirectUDPRateProbeCandidate, bool, externalDirectUDPRateProbeCandidate, bool) {
	var selected externalDirectUDPRateProbeCandidate
	selectedOK := false
	var previous externalDirectUDPRateProbeCandidate
	previousOK := false
	bestEfficient := externalDirectUDPRateProbeCandidate{}
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
		efficiency := externalDirectUDPRateProbeEfficiency(probe)
		if probe.delivery >= externalDirectUDPRateProbeClean && efficiency >= externalDirectUDPRateProbeEfficient && (!bestEfficientOK || probe.goodput > bestEfficient.goodput) {
			bestEfficient = probe
			bestEfficientOK = true
		}
	}
	return selected, selectedOK, previous, previousOK, bestEfficient, bestEfficientOK
}

func externalDirectUDPRateProbeEfficiency(candidate externalDirectUDPRateProbeCandidate) float64 {
	if candidate.rate <= 0 {
		return 0
	}
	return candidate.goodput / float64(candidate.rate)
}

func externalDirectUDPSelectFromProbeTransitions(maxRateMbps int, selection externalDirectUDPRateProbeSelection) (int, bool) {
	candidates := selection.candidates
	highestProbeRate := candidates[len(candidates)-1].rate
	for i := 1; i < len(candidates); i++ {
		step := externalDirectUDPTransitionStep{
			maxRateMbps:      maxRateMbps,
			highestProbeRate: highestProbeRate,
			candidates:       candidates,
			selection:        selection,
			index:            i,
		}
		selected, ok := step.selectRate()
		if ok {
			return selected, true
		}
	}
	return 0, false
}

type externalDirectUDPTransitionStep struct {
	maxRateMbps      int
	highestProbeRate int
	candidates       []externalDirectUDPRateProbeCandidate
	selection        externalDirectUDPRateProbeSelection
	index            int
}

func (s externalDirectUDPTransitionStep) selectRate() (int, bool) {
	if selected, ok, next := s.selectEarlyRate(); ok || next {
		return selected, ok
	}
	if selected, ok, next := s.selectMiddleRate(); ok || next {
		return selected, ok
	}
	return s.selectLateRate()
}

func (s externalDirectUDPTransitionStep) prev() externalDirectUDPRateProbeCandidate {
	return s.candidates[s.index-1]
}

func (s externalDirectUDPTransitionStep) current() externalDirectUDPRateProbeCandidate {
	return s.candidates[s.index]
}

func (s externalDirectUDPTransitionStep) topProbe() bool {
	return s.index == len(s.candidates)-1 || s.current().rate == s.maxRateMbps
}

func (s externalDirectUDPTransitionStep) selectEarlyRate() (int, bool, bool) {
	prev := s.prev()
	current := s.current()
	topProbe := s.topProbe()
	if topProbe && current.delivery >= externalDirectUDPRateProbeClean && current.goodput > prev.goodput && current.goodput >= s.selection.bestGoodput {
		return externalDirectUDPObservedGoodputRate(current.goodput, s.maxRateMbps), true, false
	}
	if externalDirectUDPShouldContinueCleanRamp(s.maxRateMbps, topProbe, prev, current) {
		return 0, false, true
	}
	if topProbe && externalDirectUDPHighGoodputCappedTopProbe(s.maxRateMbps, s.highestProbeRate, current.rate, current.goodput, current.delivery, prev.goodput) {
		selected := externalDirectUDPObservedGoodputRate(current.goodput, s.maxRateMbps)
		if selected > current.rate {
			selected = current.rate
		}
		return selected, true, false
	}
	if selected, ok := externalDirectUDPSelectMidProbeGain(s.maxRateMbps, s.candidates, topProbe, prev, current); ok {
		return selected, true, false
	}
	return 0, false, false
}

func externalDirectUDPShouldContinueCleanRamp(maxRateMbps int, topProbe bool, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	efficiency := externalDirectUDPRateProbeEfficiency(current)
	prevEfficiency := externalDirectUDPRateProbeEfficiency(prev)
	return externalDirectUDPCleanEfficientRamp(maxRateMbps, prev, current, efficiency) ||
		externalDirectUDPNearCleanEfficientGain(topProbe, prev, current, efficiency) ||
		externalDirectUDPCleanSenderLimitedRamp(prev, current, prevEfficiency)
}

func externalDirectUDPCleanEfficientRamp(maxRateMbps int, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate, efficiency float64) bool {
	if current.delivery < externalDirectUDPRateProbeClean || current.goodput < prev.goodput*0.75 {
		return false
	}
	return efficiency >= externalDirectUDPRateProbeEfficient ||
		externalDirectUDPHighThroughputKnee(maxRateMbps, prev, current)
}

func externalDirectUDPHighThroughputKnee(maxRateMbps int, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	return current.goodput >= float64(maxRateMbps)*externalDirectUDPRateProbeHighShare &&
		current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain
}

func externalDirectUDPNearCleanEfficientGain(topProbe bool, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate, efficiency float64) bool {
	return !topProbe &&
		current.delivery >= externalDirectUDPRateProbeNearClean &&
		current.goodput >= prev.goodput*0.75 &&
		efficiency >= externalDirectUDPRateProbeEfficient
}

func externalDirectUDPCleanSenderLimitedRamp(prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate, prevEfficiency float64) bool {
	return current.delivery >= externalDirectUDPRateProbeClean &&
		current.goodput >= prev.goodput &&
		(current.goodput < externalDirectUDPRateProbeHighHeadroomMin ||
			prevEfficiency < externalDirectUDPRateProbeEfficient)
}

func externalDirectUDPSelectMidProbeGain(maxRateMbps int, candidates []externalDirectUDPRateProbeCandidate, topProbe bool, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) (int, bool) {
	if topProbe || current.rate >= maxRateMbps || current.goodput < externalDirectUDPRateProbeHighHeadroomMin {
		return 0, false
	}
	materialGain := (current.delivery >= externalDirectUDPRateProbeClean || current.delivery >= externalDirectUDPRateProbeLossySelect) &&
		current.goodput >= prev.goodput*externalDirectUDPRateProbeMaterialGain
	moderateGain := current.delivery >= externalDirectUDPRateProbeCeilingDelivery &&
		current.goodput >= prev.goodput*externalDirectUDPRateProbeModerateGain
	if !materialGain && !moderateGain {
		return 0, false
	}
	selected := externalDirectUDPClampProbeRate(current.rate, maxRateMbps)
	return externalDirectUDPCapSenderLimitedProbeRate(selected, candidates), true
}

func (s externalDirectUDPTransitionStep) selectMiddleRate() (int, bool, bool) {
	prev := s.prev()
	current := s.current()
	topProbe := s.topProbe()
	if externalDirectUDPShouldContinueCleanHighTier(topProbe, prev, current) {
		return 0, false, true
	}
	if topProbe && externalDirectUDPTopProbeSenderLimitedBelowBest(prev, current, s.selection) {
		return externalDirectUDPClampProbeRate(s.selection.bestRate, s.maxRateMbps), true, false
	}
	if externalDirectUDPMidProbeSoftLoss(s.maxRateMbps, current, prev) {
		return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(prev.rate, s.maxRateMbps), s.candidates), true, false
	}
	if externalDirectUDPCleanMidProbeSenderLimitedGain(s.maxRateMbps, prev, current) {
		return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(prev.rate, s.maxRateMbps), s.candidates), true, false
	}
	return 0, false, false
}

func externalDirectUDPShouldContinueCleanHighTier(topProbe bool, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	return !topProbe &&
		prev.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
		current.rate >= externalDirectUDPRateProbeConfirmMinMbps &&
		current.delivery >= externalDirectUDPRateProbeClean &&
		current.goodput >= externalDirectUDPRateProbeHighHeadroomMin
}

func externalDirectUDPTopProbeSenderLimitedBelowBest(prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate, selection externalDirectUDPRateProbeSelection) bool {
	return current.delivery >= externalDirectUDPRateProbeClean &&
		selection.bestRate > 0 &&
		selection.bestRate < current.rate &&
		selection.bestGoodput > prev.goodput*1.10 &&
		selection.bestGoodput > current.goodput*1.10
}

func externalDirectUDPMidProbeSoftLoss(maxRateMbps int, current externalDirectUDPRateProbeCandidate, prev externalDirectUDPRateProbeCandidate) bool {
	return current.rate < maxRateMbps &&
		current.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
		current.delivery >= 0.70 &&
		current.delivery < externalDirectUDPRateProbeClean &&
		current.goodput >= prev.goodput
}

func externalDirectUDPCleanMidProbeSenderLimitedGain(maxRateMbps int, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	return current.rate < maxRateMbps &&
		current.rate < externalDirectUDPRateProbeConfirmMinMbps &&
		current.delivery >= externalDirectUDPRateProbeClean &&
		externalDirectUDPRateProbeEfficiency(current) < externalDirectUDPRateProbeEfficient &&
		prev.rate >= externalDirectUDPActiveLaneTwoMaxMbps &&
		externalDirectUDPRateProbeEfficiency(prev) >= externalDirectUDPRateProbeEfficient &&
		current.goodput >= prev.goodput &&
		current.goodput >= externalDirectUDPRateProbeHighHeadroomMin
}

func (s externalDirectUDPTransitionStep) selectLateRate() (int, bool) {
	prev := s.prev()
	current := s.current()
	topProbe := s.topProbe()
	if externalDirectUDPMidProbeCollapseAfterCleanTier(s.maxRateMbps, prev, current) {
		return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(prev.rate, s.maxRateMbps), s.candidates), true
	}
	if topProbe && s.topProbeCleanCollapseAfterMaterialGain(prev, current) {
		return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(prev.rate, s.maxRateMbps), s.candidates), true
	}
	if topProbe && current.delivery >= externalDirectUDPRateProbeClean && current.goodput >= prev.goodput*externalDirectUDPRateProbeHighGain {
		return externalDirectUDPObservedGoodputRate(current.goodput, s.maxRateMbps), true
	}
	if !topProbe && current.rate < externalDirectUDPRateProbeCollapseMinMbps {
		return 0, false
	}
	return s.backoffProbeRate(), true
}

func externalDirectUDPMidProbeCollapseAfterCleanTier(maxRateMbps int, prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	return current.rate < maxRateMbps &&
		current.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
		prev.delivery >= 0.90 &&
		(current.delivery < externalDirectUDPRateProbeNearClean ||
			current.goodput < prev.goodput*externalDirectUDPRateProbeSentGrowth)
}

func (s externalDirectUDPTransitionStep) topProbeCleanCollapseAfterMaterialGain(prev externalDirectUDPRateProbeCandidate, current externalDirectUDPRateProbeCandidate) bool {
	return s.index >= 2 &&
		current.delivery >= externalDirectUDPRateProbeClean &&
		prev.delivery >= externalDirectUDPRateProbeClean &&
		current.goodput < prev.goodput*externalDirectUDPRateProbeSentGrowth &&
		prev.goodput >= s.candidates[s.index-2].goodput*1.10
}

func (s externalDirectUDPTransitionStep) backoffProbeRate() int {
	backoffIndex := s.index - 2
	if backoffIndex < 0 {
		backoffIndex = s.index - 1
	}
	selected := s.candidates[backoffIndex].rate
	backoffCandidate := s.candidates[backoffIndex]
	if externalDirectUDPShouldUseBestLossyBackoff(backoffCandidate, s.selection) {
		selected = s.selection.bestRate
	}
	return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(selected, s.maxRateMbps), s.candidates)
}

func externalDirectUDPShouldUseBestLossyBackoff(backoffCandidate externalDirectUDPRateProbeCandidate, selection externalDirectUDPRateProbeSelection) bool {
	return backoffCandidate.rate < externalDirectUDPRateProbeCollapseMinMbps &&
		selection.bestRate > 0 &&
		selection.bestRate < backoffCandidate.rate &&
		selection.bestDelivery >= externalDirectUDPRateProbeCeilingDelivery &&
		backoffCandidate.delivery < externalDirectUDPRateProbeCeilingDelivery &&
		backoffCandidate.goodput < selection.bestGoodput*externalDirectUDPRateProbeLossyGain
}

func externalDirectUDPFinalSelectedProbeRate(maxRateMbps int, selection externalDirectUDPRateProbeSelection) int {
	selected := externalDirectUDPObservedGoodputRate(selection.bestGoodput, maxRateMbps)
	if selection.bestDelivery >= 0.90 {
		selected = selection.bestRate
	}
	return externalDirectUDPCapSenderLimitedProbeRate(externalDirectUDPClampProbeRate(selected, maxRateMbps), selection.candidates)
}

func externalDirectUDPObservedGoodputRate(goodput float64, maxRateMbps int) int {
	return externalDirectUDPClampProbeRate(int(goodput*1.15+0.5), maxRateMbps)
}

func externalDirectUDPClampProbeRate(rate int, maxRateMbps int) int {
	if rate < externalDirectUDPRateProbeMinMbps {
		return externalDirectUDPRateProbeMinMbps
	}
	if rate > maxRateMbps {
		return maxRateMbps
	}
	return rate
}

func externalDirectUDPSelectInitialRateMbps(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	selected := externalDirectUDPSelectRateFromProbeSamples(maxRateMbps, sent, received)
	if selected <= 0 || selected > maxRateMbps {
		selected = externalDirectUDPInitialProbeFallbackMbps
	}
	if !externalDirectUDPHasPositiveProbeProgress(received) {
		return selected
	}
	if conservativeRate, ok := externalDirectUDPProbeConservativeRampCap(sent, received); ok {
		if selected > conservativeRate {
			return conservativeRate
		}
		return selected
	}
	if selected > externalDirectUDPActiveLaneTwoMaxMbps &&
		selected < externalDirectUDPDataStartHighMbps &&
		externalDirectUDPProbeLacksCleanWarmupForSelectedRate(selected, sent, received) {
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
	if conservativeRate, ok := externalDirectUDPProbeConservativeRampCap(sent, received); ok {
		if selected > conservativeRate {
			return conservativeRate
		}
		return selected
	}
	if selected > externalDirectUDPActiveLaneTwoMaxMbps &&
		selected < externalDirectUDPDataStartHighMbps &&
		externalDirectUDPProbeLacksCleanWarmupForSelectedRate(selected, sent, received) {
		return selected
	}
	selector := newExternalDirectUDPRateCeilingSelector(maxRateMbps, selected, sent, received)
	selector.scan()
	selector.applyPostScanCeilings()
	return selector.finalCeiling()
}

type externalDirectUDPRateProbeObservation struct {
	rate       int
	goodput    float64
	delivery   float64
	efficiency float64
}

type externalDirectUDPRateCeilingSelector struct {
	maxRateMbps                int
	selected                   int
	sentByRate                 map[int]directUDPRateProbeSample
	received                   []directUDPRateProbeSample
	highestProbeRate           int
	ceiling                    int
	ceilingGoodput             float64
	ceilingDelivery            float64
	ceilingEfficiency          float64
	previousGoodput            float64
	selectedGoodput            float64
	selectedDelivery           float64
	probedPastSelectedHeadroom bool
	rejectedHigherProbe        bool
	lossyImprovingCeiling      bool
}

func newExternalDirectUDPRateCeilingSelector(maxRateMbps int, selected int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) *externalDirectUDPRateCeilingSelector {
	return &externalDirectUDPRateCeilingSelector{
		maxRateMbps:      maxRateMbps,
		selected:         selected,
		sentByRate:       externalDirectUDPProbeSamplesByRate(sent),
		received:         received,
		highestProbeRate: externalDirectUDPHighestProbeRate(sent, maxRateMbps),
		ceiling:          selected,
	}
}

func externalDirectUDPProbeSamplesByRate(samples []directUDPRateProbeSample) map[int]directUDPRateProbeSample {
	byRate := make(map[int]directUDPRateProbeSample, len(samples))
	for _, sample := range samples {
		byRate[sample.RateMbps] = sample
	}
	return byRate
}

func (s *externalDirectUDPRateCeilingSelector) scan() {
	for _, sample := range s.received {
		obs, ok := s.observation(sample)
		if !ok {
			continue
		}
		if obs.rate < s.selected {
			s.previousGoodput = obs.goodput
			continue
		}
		s.recordSelectedObservation(obs)
		if s.applyObservation(obs) {
			return
		}
	}
}

func (s *externalDirectUDPRateCeilingSelector) observation(sample directUDPRateProbeSample) (externalDirectUDPRateProbeObservation, bool) {
	if sample.RateMbps <= 0 || sample.RateMbps > s.maxRateMbps {
		return externalDirectUDPRateProbeObservation{}, false
	}
	goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok {
		return externalDirectUDPRateProbeObservation{}, false
	}
	return externalDirectUDPRateProbeObservation{
		rate:       sample.RateMbps,
		goodput:    goodput,
		delivery:   delivery,
		efficiency: efficiency,
	}, true
}

func (s *externalDirectUDPRateCeilingSelector) recordSelectedObservation(obs externalDirectUDPRateProbeObservation) {
	if obs.rate == s.selected {
		s.selectedGoodput = obs.goodput
		s.selectedDelivery = obs.delivery
	}
}

func (s *externalDirectUDPRateCeilingSelector) applyObservation(obs externalDirectUDPRateProbeObservation) bool {
	if s.selectedLossyGain(obs) {
		s.setCeilingFromObservation(obs)
		return false
	}
	if s.uncleanInefficient(obs) {
		return s.handleUncleanInefficient(obs)
	}
	if s.weakUncleanGain(obs) {
		return s.handleWeakUncleanGain(obs)
	}
	if s.senderLimitedHeadroomProbe(obs) || s.cleanHigherThroughputCollapse(obs) {
		s.rejectedHigherProbe = obs.rate > s.ceiling
		return true
	}
	s.setCeilingFromObservation(obs)
	return s.stopAfterAcceptedUnclean(obs)
}

func (s *externalDirectUDPRateCeilingSelector) selectedLossyGain(obs externalDirectUDPRateProbeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.rate == s.selected &&
		obs.delivery >= externalDirectUDPRateProbeLossySelect &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.goodput >= s.priorGoodput()*externalDirectUDPRateProbeMaterialGain
}

func (s *externalDirectUDPRateCeilingSelector) uncleanInefficient(obs externalDirectUDPRateProbeObservation) bool {
	return obs.delivery < externalDirectUDPRateProbeClean &&
		!(obs.delivery >= externalDirectUDPRateProbeNearClean && obs.efficiency >= externalDirectUDPRateProbeCeilingEfficient)
}

func (s *externalDirectUDPRateCeilingSelector) handleUncleanInefficient(obs externalDirectUDPRateProbeObservation) bool {
	s.rejectedHigherProbe = obs.rate > s.ceiling
	if s.cappedTopHighGoodput(obs) {
		s.setCeilingRateDetails(obs)
		return true
	}
	if s.meaningfulNextTier(obs) {
		s.setCeilingRateDetails(obs)
	}
	if s.boundedLossyObservedGoodputCeiling(obs) {
		s.ceiling = int(obs.goodput + 0.5)
		s.ceilingDelivery = obs.delivery
		s.ceilingEfficiency = obs.efficiency
		s.lossyImprovingCeiling = true
	}
	if s.lossyStillImproving(obs) {
		s.setCeilingFromObservation(obs)
		s.lossyImprovingCeiling = true
		s.rejectedHigherProbe = false
		return false
	}
	return true
}

func (s *externalDirectUDPRateCeilingSelector) weakUncleanGain(obs externalDirectUDPRateProbeObservation) bool {
	return obs.delivery < externalDirectUDPRateProbeClean &&
		obs.rate > s.selected &&
		obs.efficiency < externalDirectUDPRateProbeCeilingEfficient &&
		!s.highThroughputKnee(obs) &&
		s.ceilingGoodput > 0 &&
		obs.goodput < s.ceilingGoodput*externalDirectUDPRateProbeSentGrowth
}

func (s *externalDirectUDPRateCeilingSelector) handleWeakUncleanGain(obs externalDirectUDPRateProbeObservation) bool {
	s.rejectedHigherProbe = obs.rate > s.ceiling
	if s.cappedTopHighGoodput(obs) || s.meaningfulNextTier(obs) {
		s.setCeilingRateDetails(obs)
	}
	return true
}

func (s *externalDirectUDPRateCeilingSelector) senderLimitedHeadroomProbe(obs externalDirectUDPRateProbeObservation) bool {
	return s.selected > externalDirectUDPActiveLaneTwoMaxMbps &&
		s.selected < externalDirectUDPRateProbeConfirmMinMbps &&
		obs.rate > s.selected &&
		obs.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.delivery >= externalDirectUDPRateProbeClean &&
		obs.efficiency > 0 &&
		obs.efficiency < externalDirectUDPRateProbeEfficient &&
		s.ceilingGoodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.goodput < s.ceilingGoodput*externalDirectUDPRateProbeMaterialGain
}

func (s *externalDirectUDPRateCeilingSelector) cleanHigherThroughputCollapse(obs externalDirectUDPRateProbeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate > s.selected &&
		obs.delivery >= externalDirectUDPRateProbeClean &&
		obs.efficiency > 0 &&
		obs.efficiency < externalDirectUDPRateProbeEfficient &&
		s.ceilingGoodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.goodput < s.ceilingGoodput*externalDirectUDPRateProbeSentGrowth
}

func (s *externalDirectUDPRateCeilingSelector) stopAfterAcceptedUnclean(obs externalDirectUDPRateProbeObservation) bool {
	if obs.delivery >= externalDirectUDPRateProbeClean || obs.rate <= s.selected || obs.efficiency >= externalDirectUDPRateProbeCeilingEfficient || s.highThroughputKnee(obs) {
		return false
	}
	if s.selected == externalDirectUDPProbeKneeHeadroom(obs.rate) && !s.probedPastSelectedHeadroom {
		s.probedPastSelectedHeadroom = true
		return false
	}
	s.rejectedHigherProbe = obs.rate > s.ceiling
	return true
}

func (s *externalDirectUDPRateCeilingSelector) priorGoodput() float64 {
	if s.ceilingGoodput > 0 {
		return s.ceilingGoodput
	}
	return s.previousGoodput
}

func (s *externalDirectUDPRateCeilingSelector) cappedTopHighGoodput(obs externalDirectUDPRateProbeObservation) bool {
	return externalDirectUDPHighGoodputCappedTopProbe(s.maxRateMbps, s.highestProbeRate, obs.rate, obs.goodput, obs.delivery, s.priorGoodput())
}

func (s *externalDirectUDPRateCeilingSelector) highThroughputKnee(obs externalDirectUDPRateProbeObservation) bool {
	return obs.goodput >= float64(s.maxRateMbps)*externalDirectUDPRateProbeHighShare &&
		(s.ceilingGoodput <= 0 || obs.goodput >= s.ceilingGoodput*externalDirectUDPRateProbeHighGain)
}

func (s *externalDirectUDPRateCeilingSelector) meaningfulNextTier(obs externalDirectUDPRateProbeObservation) bool {
	return s.ceilingGoodput >= externalDirectUDPRateProbeCeilingFloorMin &&
		obs.rate > s.ceiling &&
		obs.goodput >= s.ceilingGoodput*externalDirectUDPRateProbeCeilingFloor &&
		(obs.delivery >= externalDirectUDPRateProbeCeilingDelivery || s.nearCleanCeiling() || s.highSelectedHeadroom(obs))
}

func (s *externalDirectUDPRateCeilingSelector) nearCleanCeiling() bool {
	return s.ceilingDelivery >= externalDirectUDPRateProbeNearClean && s.ceilingDelivery < externalDirectUDPRateProbeClean
}

func (s *externalDirectUDPRateCeilingSelector) highSelectedHeadroom(obs externalDirectUDPRateProbeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate == s.highestProbeRate &&
		obs.goodput >= externalDirectUDPRateProbeCeilingFloorMin &&
		obs.delivery >= externalDirectUDPRateProbeCeilingDelivery
}

func (s *externalDirectUDPRateCeilingSelector) boundedLossyObservedGoodputCeiling(obs externalDirectUDPRateProbeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate == s.highestProbeRate &&
		obs.delivery >= externalDirectUDPRateProbeLossyDelivery &&
		obs.delivery < externalDirectUDPRateProbeCeilingDelivery &&
		obs.goodput >= float64(s.selected)*1.10 &&
		obs.goodput >= s.priorGoodput()*externalDirectUDPRateProbeLossyGain
}

func (s *externalDirectUDPRateCeilingSelector) lossyStillImproving(obs externalDirectUDPRateProbeObservation) bool {
	allowed := s.selected < externalDirectUDPCeilingHeadroomMinMbps ||
		(s.selected >= externalDirectUDPRateProbeCollapseMinMbps && obs.rate == s.highestProbeRate)
	return allowed && externalDirectUDPLossyProbeStillImproving(obs.rate, obs.goodput, obs.delivery, s.priorGoodput())
}

func (s *externalDirectUDPRateCeilingSelector) setCeilingFromObservation(obs externalDirectUDPRateProbeObservation) {
	s.ceiling = obs.rate
	s.ceilingGoodput = obs.goodput
	s.ceilingDelivery = obs.delivery
	s.ceilingEfficiency = obs.efficiency
}

func (s *externalDirectUDPRateCeilingSelector) setCeilingRateDetails(obs externalDirectUDPRateProbeObservation) {
	s.ceiling = obs.rate
	s.ceilingDelivery = obs.delivery
	s.ceilingEfficiency = obs.efficiency
}

func (s *externalDirectUDPRateCeilingSelector) applyPostScanCeilings() {
	s.applyLossyRecoveryCeiling()
	s.applyLossyHighSelectedExplorationCeiling()
	s.applyAdaptiveExplorationCeiling()
}

func (s *externalDirectUDPRateCeilingSelector) applyLossyRecoveryCeiling() {
	rate, _, delivery, efficiency, ok := externalDirectUDPFindLossyRecoveryProbe(s.selected, s.selectedGoodput, s.sentByRate, s.received)
	if ok && rate > s.ceiling {
		s.ceiling = rate
		s.ceilingDelivery = delivery
		s.ceilingEfficiency = efficiency
	}
}

func (s *externalDirectUDPRateCeilingSelector) applyLossyHighSelectedExplorationCeiling() {
	rate, _, delivery, efficiency, ok := externalDirectUDPFindLossyHighSelectedExplorationCeiling(s.selected, s.selectedGoodput, s.selectedDelivery, s.sentByRate, s.received, s.maxRateMbps)
	if ok && rate > s.ceiling {
		s.ceiling = rate
		s.ceilingDelivery = delivery
		s.ceilingEfficiency = efficiency
		s.lossyImprovingCeiling = true
	}
}

func (s *externalDirectUDPRateCeilingSelector) applyAdaptiveExplorationCeiling() {
	rate, _, delivery, efficiency, ok := externalDirectUDPFindAdaptiveExplorationCeiling(s.selected, s.selectedGoodput, s.sentByRate, s.received, s.maxRateMbps)
	if ok && rate > s.ceiling {
		s.ceiling = rate
		s.ceilingDelivery = delivery
		s.ceilingEfficiency = efficiency
		s.lossyImprovingCeiling = true
	}
}

func (s *externalDirectUDPRateCeilingSelector) finalCeiling() int {
	if s.ceiling == s.highestProbeRate && s.highestProbeRate > 0 && s.highestProbeRate == s.maxRateMbps && s.ceilingDelivery >= externalDirectUDPRateProbeClean && s.ceilingEfficiency >= externalDirectUDPRateProbeEfficient {
		return s.maxRateMbps
	}
	if s.selected < externalDirectUDPCeilingHeadroomMinMbps && s.ceiling > externalDirectUDPRateProbeHighHeadroomMin && s.rejectedHigherProbe {
		s.ceiling = externalDirectUDPRateProbeHighHeadroomMin
	}
	if !s.lossyImprovingCeiling {
		s.ceiling = externalDirectUDPCapBufferedMediumCeiling(s.selected, s.ceiling, s.ceilingDelivery, s.ceilingEfficiency)
	}
	return externalDirectUDPClampRateCeiling(s.ceiling, s.selected, s.maxRateMbps)
}

func externalDirectUDPClampRateCeiling(ceiling int, selected int, maxRateMbps int) int {
	if ceiling < selected {
		return selected
	}
	if ceiling > maxRateMbps {
		return maxRateMbps
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

func externalDirectUDPProbeLacksCleanWarmupForSelectedRate(selected int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	if selected < externalDirectUDPActiveLaneTwoMaxMbps {
		return false
	}
	warmup := externalDirectUDPProbeWarmupState{selected: selected, sentByRate: externalDirectUDPProbeSamplesByRate(sent)}
	for _, sample := range received {
		warmup.observe(sample)
	}
	return warmup.lacksCleanWarmup()
}

type externalDirectUDPProbeWarmupState struct {
	selected         int
	sentByRate       map[int]directUDPRateProbeSample
	cleanWarmup      bool
	selectedDelivery float64
	selectedProgress bool
	selectedObserved bool
}

func (s *externalDirectUDPProbeWarmupState) observe(sample directUDPRateProbeSample) {
	_, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok {
		return
	}
	if sample.RateMbps < s.selected {
		s.observeWarmupSample(sample, delivery)
		return
	}
	if sample.RateMbps != s.selected {
		return
	}
	s.observeSelectedSample(sample, delivery)
}

func (s *externalDirectUDPProbeWarmupState) observeWarmupSample(sample directUDPRateProbeSample, delivery float64) {
	if sample.BytesReceived > 0 && delivery >= externalDirectUDPRateProbeNearClean {
		s.cleanWarmup = true
	}
}

func (s *externalDirectUDPProbeWarmupState) observeSelectedSample(sample directUDPRateProbeSample, delivery float64) {
	s.selectedObserved = true
	s.selectedProgress = sample.BytesReceived > 0
	s.selectedDelivery = delivery
}

func (s externalDirectUDPProbeWarmupState) lacksCleanWarmup() bool {
	return s.selectedObserved && s.selectedProgress && s.selectedDelivery < externalDirectUDPRateProbeNearClean && !s.cleanWarmup
}

func externalDirectUDPProbeConservativeRampCap(sent []directUDPRateProbeSample, received []directUDPRateProbeSample) (int, bool) {
	ramp := externalDirectUDPConservativeRampState{sentByRate: externalDirectUDPProbeSamplesByRate(sent)}
	for _, sample := range received {
		ramp.observe(sample)
	}
	return ramp.cap()
}

type externalDirectUDPConservativeRampState struct {
	sentByRate              map[int]directUDPRateProbeSample
	cleanLowerRate          int
	cleanTwoLaneRamp        bool
	lossyTwoLaneRamp        bool
	lossyIntermediateProbe  bool
	higherNearCleanRecovery bool
}

type externalDirectUDPConservativeRampBand uint8

const (
	externalDirectUDPConservativeRampBandNone externalDirectUDPConservativeRampBand = iota
	externalDirectUDPConservativeRampBandLower
	externalDirectUDPConservativeRampBandTwoLane
	externalDirectUDPConservativeRampBandIntermediate
	externalDirectUDPConservativeRampBandHigh
)

func (s *externalDirectUDPConservativeRampState) observe(sample directUDPRateProbeSample) {
	goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok {
		return
	}
	if sample.BytesReceived <= 0 {
		return
	}
	switch externalDirectUDPConservativeRampBandForRate(sample.RateMbps) {
	case externalDirectUDPConservativeRampBandLower:
		s.observeLowerRamp(sample.RateMbps, delivery)
	case externalDirectUDPConservativeRampBandTwoLane:
		s.observeTwoLaneRamp(delivery)
	case externalDirectUDPConservativeRampBandIntermediate:
		s.observeIntermediateRamp(delivery)
	case externalDirectUDPConservativeRampBandHigh:
		s.observeHighRamp(goodput, delivery)
	case externalDirectUDPConservativeRampBandNone:
	}
}

func externalDirectUDPConservativeRampBandForRate(rateMbps int) externalDirectUDPConservativeRampBand {
	switch {
	case rateMbps < externalDirectUDPActiveLaneTwoMaxMbps:
		return externalDirectUDPConservativeRampBandLower
	case rateMbps == externalDirectUDPActiveLaneTwoMaxMbps:
		return externalDirectUDPConservativeRampBandTwoLane
	case rateMbps < externalDirectUDPDataStartHighMbps:
		return externalDirectUDPConservativeRampBandIntermediate
	case rateMbps >= externalDirectUDPDataStartHighMbps:
		return externalDirectUDPConservativeRampBandHigh
	default:
		return externalDirectUDPConservativeRampBandNone
	}
}

func (s *externalDirectUDPConservativeRampState) observeLowerRamp(rateMbps int, delivery float64) {
	if delivery >= externalDirectUDPRateProbeNearClean && rateMbps > s.cleanLowerRate {
		s.cleanLowerRate = rateMbps
	}
}

func (s *externalDirectUDPConservativeRampState) observeTwoLaneRamp(delivery float64) {
	if delivery >= externalDirectUDPRateProbeNearClean {
		s.cleanTwoLaneRamp = true
		return
	}
	if delivery < externalDirectUDPRateProbeBufferedCollapse {
		s.lossyTwoLaneRamp = true
	}
}

func (s *externalDirectUDPConservativeRampState) observeIntermediateRamp(delivery float64) {
	if delivery < externalDirectUDPRateProbeNearClean {
		s.lossyIntermediateProbe = true
	}
}

func (s *externalDirectUDPConservativeRampState) observeHighRamp(goodput float64, delivery float64) {
	if delivery >= externalDirectUDPRateProbeNearClean && goodput >= externalDirectUDPRateProbeHighHeadroomMin {
		s.higherNearCleanRecovery = true
	}
}

func (s externalDirectUDPConservativeRampState) cap() (int, bool) {
	if (!s.lossyTwoLaneRamp && !s.cleanTwoLaneRamp) || !s.lossyIntermediateProbe || s.higherNearCleanRecovery {
		return 0, false
	}
	if s.cleanLowerRate > 0 {
		return s.cleanLowerRate, true
	}
	if s.cleanTwoLaneRamp {
		return externalDirectUDPActiveLaneTwoMaxMbps, true
	}
	return externalDirectUDPDataStartMaxMbps, true
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
	selection := externalDirectUDPAdaptiveExplorationSelection{
		selected:    selected,
		maxRateMbps: maxRateMbps,
		threshold:   externalDirectUDPProbeThreshold(baseGoodput, externalDirectUDPRateProbeLossyGain),
		sentByRate:  sentByRate,
	}
	for _, sample := range received {
		selection.observe(sample)
	}
	return selection.result()
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
	selection := externalDirectUDPLossyHighSelectedExplorationSelection{
		selected:    selected,
		maxRateMbps: maxRateMbps,
		threshold:   externalDirectUDPProbeThreshold(baseGoodput, externalDirectUDPRateProbeLossyGain),
		sentByRate:  sentByRate,
	}
	for _, sample := range received {
		selection.observe(sample)
	}
	return selection.best.result()
}

func externalDirectUDPProbeThreshold(baseGoodput float64, gain float64) float64 {
	threshold := baseGoodput * gain
	if threshold < externalDirectUDPRateProbeHighHeadroomMin {
		return externalDirectUDPRateProbeHighHeadroomMin
	}
	return threshold
}

type externalDirectUDPProbeBest struct {
	rate       int
	goodput    float64
	delivery   float64
	efficiency float64
}

func (b externalDirectUDPProbeBest) result() (int, float64, float64, float64, bool) {
	return b.rate, b.goodput, b.delivery, b.efficiency, b.rate > 0
}

func (b *externalDirectUDPProbeBest) set(rate int, goodput float64, delivery float64, efficiency float64) {
	b.rate = rate
	b.goodput = goodput
	b.delivery = delivery
	b.efficiency = efficiency
}

type externalDirectUDPAdaptiveExplorationSelection struct {
	selected    int
	maxRateMbps int
	threshold   float64
	sentByRate  map[int]directUDPRateProbeSample
	best        externalDirectUDPProbeBest
	highest     externalDirectUDPProbeBest
}

func (s *externalDirectUDPAdaptiveExplorationSelection) observe(sample directUDPRateProbeSample) {
	if sample.RateMbps <= s.selected || sample.RateMbps > s.maxRateMbps {
		return
	}
	goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok {
		return
	}
	if sample.RateMbps >= s.highest.rate {
		s.highest.set(sample.RateMbps, goodput, delivery, efficiency)
	}
	if delivery < externalDirectUDPRateProbeHeadroomDelivery || goodput < s.threshold {
		return
	}
	if goodput < s.best.goodput || (goodput == s.best.goodput && sample.RateMbps < s.best.rate) {
		return
	}
	s.best.set(sample.RateMbps, goodput, delivery, efficiency)
}

func (s externalDirectUDPAdaptiveExplorationSelection) result() (int, float64, float64, float64, bool) {
	if s.shouldPreferHighest() {
		return s.highest.result()
	}
	return s.best.result()
}

func (s externalDirectUDPAdaptiveExplorationSelection) shouldPreferHighest() bool {
	return s.best.rate > 0 &&
		s.highest.rate > s.best.rate &&
		s.highest.delivery >= externalDirectUDPRateProbeHeadroomDelivery &&
		s.highest.goodput >= s.best.goodput*externalDirectUDPRateProbeLossyGain
}

type externalDirectUDPLossyHighSelectedExplorationSelection struct {
	selected    int
	maxRateMbps int
	threshold   float64
	sentByRate  map[int]directUDPRateProbeSample
	best        externalDirectUDPProbeBest
}

func (s *externalDirectUDPLossyHighSelectedExplorationSelection) observe(sample directUDPRateProbeSample) {
	if sample.RateMbps <= s.selected || sample.RateMbps > s.maxRateMbps {
		return
	}
	goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok || delivery < externalDirectUDPRateProbeLossyDelivery || goodput < s.threshold {
		return
	}
	if goodput < s.best.goodput || (goodput == s.best.goodput && sample.RateMbps > s.best.rate) {
		return
	}
	s.best.set(sample.RateMbps, goodput, delivery, efficiency)
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
	if externalDirectUDPShouldCapInefficientMediumCeiling(selected, efficiency) {
		return externalDirectUDPMinRate(ceiling, externalDirectUDPRateProbeHighHeadroomMin)
	}
	if externalDirectUDPBufferedMediumCeilingIsCleanEnough(selected, delivery) {
		return ceiling
	}
	return externalDirectUDPMinRate(ceiling, externalDirectUDPBufferedMediumCeilingCap(selected))
}

func externalDirectUDPShouldCapInefficientMediumCeiling(selected int, efficiency float64) bool {
	return selected >= externalDirectUDPCeilingHeadroomMinMbps && efficiency > 0 && efficiency < externalDirectUDPRateProbeCeilingEfficient
}

func externalDirectUDPBufferedMediumCeilingIsCleanEnough(selected int, delivery float64) bool {
	return delivery >= externalDirectUDPRateProbeClean ||
		(selected < externalDirectUDPCeilingHeadroomMinMbps && delivery >= externalDirectUDPRateProbeCeilingDelivery)
}

func externalDirectUDPBufferedMediumCeilingCap(selected int) int {
	capped := selected * 2
	if selected >= externalDirectUDPDataStartMaxMbps && selected < externalDirectUDPRateProbeHighHeadroomMin {
		capped = externalDirectUDPRateProbeHighHeadroomMin
	}
	if capped < selected {
		return 0
	}
	if capped < externalDirectUDPRateProbeMinMbps {
		return externalDirectUDPRateProbeMinMbps
	}
	return capped
}

func externalDirectUDPMinRate(rate int, max int) int {
	if max <= 0 || rate <= max {
		return rate
	}
	return max
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
	selector := newExternalDirectUDPProbeKneeHeadroomSelector(maxRateMbps, selected, sent, received)
	return selector.selectRate()
}

type externalDirectUDPProbeKneeObservation struct {
	rate           int
	goodput        float64
	delivery       float64
	efficiency     float64
	sentEfficiency float64
	sentOK         bool
}

type externalDirectUDPProbeKneeHeadroomSelector struct {
	maxRateMbps           int
	selected              int
	sentByRate            map[int]directUDPRateProbeSample
	received              []directUDPRateProbeSample
	highestProbeRate      int
	prevGoodput           float64
	prevBelowSelectedRate int
	selectedGoodput       float64
	selectedProbeViable   bool
	selectedProbeClean    bool
}

func newExternalDirectUDPProbeKneeHeadroomSelector(maxRateMbps int, selected int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) *externalDirectUDPProbeKneeHeadroomSelector {
	return &externalDirectUDPProbeKneeHeadroomSelector{
		maxRateMbps:      maxRateMbps,
		selected:         selected,
		sentByRate:       externalDirectUDPProbeSamplesByRate(sent),
		received:         received,
		highestProbeRate: externalDirectUDPHighestProbeRate(received, maxRateMbps),
	}
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectRate() int {
	for _, sample := range s.received {
		obs := s.observation(sample)
		if obs.rate < s.selected {
			s.prevBelowSelectedRate = obs.rate
		}
		s.recordSelectedTier(obs)
		if obs.rate <= s.selected {
			s.prevGoodput = obs.goodput
			continue
		}
		if !obs.sentOK {
			continue
		}
		return s.rateForHigherProbe(obs)
	}
	return s.selected
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) observation(sample directUDPRateProbeSample) externalDirectUDPProbeKneeObservation {
	durationMillis := sample.DurationMillis
	if durationMillis <= 0 {
		durationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
	}
	obs := externalDirectUDPProbeKneeObservation{
		rate:    sample.RateMbps,
		goodput: externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis),
	}
	sentSample, ok := s.sentByRate[sample.RateMbps]
	if !ok || sentSample.BytesSent <= 0 {
		return obs
	}
	obs.sentOK = true
	obs.delivery = float64(sample.BytesReceived) / float64(sentSample.BytesSent)
	obs.efficiency = externalDirectUDPRateEfficiency(obs.goodput, sample.RateMbps)
	obs.sentEfficiency = externalDirectUDPRateEfficiency(externalDirectUDPSampleGoodputMbps(sentSample.BytesSent, durationMillis), sample.RateMbps)
	return obs
}

func externalDirectUDPRateEfficiency(goodput float64, rateMbps int) float64 {
	if rateMbps <= 0 {
		return 0
	}
	return goodput / float64(rateMbps)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) recordSelectedTier(obs externalDirectUDPProbeKneeObservation) {
	if !obs.sentOK || !s.matchesSelectedTier(obs.rate) {
		return
	}
	lossySelectedGain := obs.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.delivery >= externalDirectUDPRateProbeLossyDelivery &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		s.prevGoodput > 0 &&
		obs.goodput >= s.prevGoodput*externalDirectUDPRateProbeMaterialGain
	s.selectedGoodput = obs.goodput
	s.selectedProbeClean = obs.delivery >= externalDirectUDPRateProbeClean
	s.selectedProbeViable = s.selectedTierViable(obs, lossySelectedGain)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) matchesSelectedTier(rate int) bool {
	return rate == s.selected ||
		(s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
			rate < s.selected &&
			rate >= externalDirectUDPRateProbeCollapseMinMbps)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectedTierViable(obs externalDirectUDPProbeKneeObservation, lossySelectedGain bool) bool {
	return (obs.delivery >= externalDirectUDPRateProbeNearClean && obs.efficiency >= externalDirectUDPRateProbeEfficient) ||
		s.highSelectedTierViable(obs) ||
		(obs.rate >= externalDirectUDPRateProbeCollapseMinMbps &&
			obs.delivery >= externalDirectUDPRateProbeClean &&
			obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin) ||
		lossySelectedGain
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) highSelectedTierViable(obs externalDirectUDPProbeKneeObservation) bool {
	return obs.rate >= externalDirectUDPRateProbeHighHeadroomMin &&
		(obs.delivery >= externalDirectUDPRateProbeClean ||
			obs.delivery >= externalDirectUDPRateProbeLossySelect ||
			obs.delivery >= externalDirectUDPRateProbeCeilingDelivery) &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		(obs.goodput >= s.prevGoodput*externalDirectUDPRateProbeMaterialGain ||
			obs.goodput >= s.prevGoodput*externalDirectUDPRateProbeModerateGain)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForHigherProbe(obs externalDirectUDPProbeKneeObservation) int {
	if obs.delivery >= externalDirectUDPRateProbeClean {
		return s.rateForCleanHigherProbe(obs)
	}
	if obs.delivery >= externalDirectUDPRateProbeNearClean && obs.efficiency >= externalDirectUDPRateProbeEfficient {
		return s.rateForNearCleanHigherProbe(obs)
	}
	if rate, ok := s.rateForLossyHigherProbe(obs); ok {
		return rate
	}
	return externalDirectUDPProbeKneeHeadroom(s.selected)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForLossyHigherProbe(obs externalDirectUDPProbeKneeObservation) (int, bool) {
	if s.shouldHoldSelectedForCappedTopProbe(obs) || s.twoLaneCleanRejectsBufferedCollapse(obs) {
		return s.selected, true
	}
	if s.promotesTwoLaneToDataStart(obs) {
		return obs.rate, true
	}
	if rate, ok := s.rateForLossySelectedViable(obs); ok {
		return rate, true
	}
	if rate, ok := s.rateForBufferedCollapse(obs); ok {
		return rate, true
	}
	if s.shouldHoldSelectedForLossyHigherProbe(obs) || s.shouldHoldSelectedForBufferedProgress(obs) || s.hasLossyRecoveryProbe() || s.collapseSelectedProbeViable() {
		return s.selected, true
	}
	return 0, false
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForCleanHigherProbe(obs externalDirectUDPProbeKneeObservation) int {
	if obs.efficiency >= externalDirectUDPRateProbeEfficient || s.highThroughputKnee(obs) {
		return s.selected
	}
	if s.cleanHigherProbeShouldHoldSelected(obs) {
		return s.selected
	}
	return externalDirectUDPProbeKneeHeadroom(s.selected)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) cleanHigherProbeShouldHoldSelected(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selectedViableInefficientHigherProbe(obs) ||
		s.selectedViableHighestProbeRegression(obs) ||
		s.selectedHighSenderLimitGain(obs) ||
		s.selectedCoversGoodputGain(obs)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectedViableInefficientHigherProbe(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selectedProbeViable &&
		s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate > s.selected &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.sentEfficiency < externalDirectUDPRateProbeEfficient
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectedViableHighestProbeRegression(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selectedProbeViable &&
		s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate == s.highestProbeRate &&
		obs.goodput <= s.prevGoodput
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectedHighSenderLimitGain(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		obs.goodput >= s.prevGoodput*externalDirectUDPRateProbeSenderLimitGain
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) selectedCoversGoodputGain(obs externalDirectUDPProbeKneeObservation) bool {
	return float64(s.selected) >= obs.goodput && obs.goodput > s.prevGoodput
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForNearCleanHigherProbe(obs externalDirectUDPProbeKneeObservation) int {
	headroom := externalDirectUDPProbeKneeHeadroom(obs.rate)
	if s.selected >= externalDirectUDPRateProbeCollapseMinMbps && headroom < s.selected {
		return s.selected
	}
	return headroom
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) highThroughputKnee(obs externalDirectUDPProbeKneeObservation) bool {
	return s.maxRateMbps > 0 && obs.goodput >= float64(s.maxRateMbps)*externalDirectUDPRateProbeHighShare
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) shouldHoldSelectedForCappedTopProbe(obs externalDirectUDPProbeKneeObservation) bool {
	return externalDirectUDPHighGoodputCappedTopProbe(s.maxRateMbps, s.highestProbeRate, obs.rate, obs.goodput, obs.delivery, s.prevGoodput) &&
		s.selected >= externalDirectUDPRateProbeHighHeadroomMin
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) promotesTwoLaneToDataStart(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selected == externalDirectUDPActiveLaneTwoMaxMbps &&
		!s.selectedProbeViable &&
		obs.rate >= externalDirectUDPDataStartHighMbps &&
		obs.delivery >= externalDirectUDPRateProbeBufferedCollapse &&
		obs.goodput >= externalDirectUDPRateProbeHighHeadroomMin &&
		s.selectedGoodput > 0 &&
		obs.goodput >= s.selectedGoodput*externalDirectUDPRateProbeMaterialGain
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForLossySelectedViable(obs externalDirectUDPProbeKneeObservation) (int, bool) {
	if s.selected < externalDirectUDPActiveLaneTwoMaxMbps || !s.selectedProbeViable || obs.delivery < externalDirectUDPRateProbeLossyDelivery || obs.goodput < s.selectedGoodput*externalDirectUDPRateProbeLossyGain {
		return 0, false
	}
	if s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		obs.rate >= externalDirectUDPRateProbeConfirmMinMbps &&
		obs.delivery >= externalDirectUDPRateProbeCeilingDelivery &&
		obs.goodput >= s.selectedGoodput*externalDirectUDPRateProbeMaterialGain {
		return obs.rate, true
	}
	return s.selected, true
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) twoLaneCleanRejectsBufferedCollapse(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selected == externalDirectUDPActiveLaneTwoMaxMbps &&
		s.selectedProbeClean &&
		obs.delivery < externalDirectUDPRateProbeBufferedCollapse &&
		obs.goodput < s.selectedGoodput*externalDirectUDPRateProbeLossyGain
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) rateForBufferedCollapse(obs externalDirectUDPProbeKneeObservation) (int, bool) {
	if s.selected < externalDirectUDPRateProbeCollapseMinMbps || obs.delivery >= externalDirectUDPRateProbeBufferedCollapse || s.prevBelowSelectedRate <= 0 {
		return 0, false
	}
	if s.selectedProbeViable &&
		s.selected >= externalDirectUDPRateProbeConfirmMinMbps &&
		obs.delivery >= externalDirectUDPRateProbeLossyDelivery {
		return s.selected, true
	}
	if s.selectedProbeViable && obs.sentEfficiency >= externalDirectUDPRateProbeCeilingEfficient {
		return s.selected, true
	}
	return externalDirectUDPProbeKneeHeadroom(s.prevBelowSelectedRate), true
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) shouldHoldSelectedForLossyHigherProbe(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selected >= externalDirectUDPActiveLaneTwoMaxMbps &&
		s.selectedProbeViable &&
		obs.delivery < externalDirectUDPRateProbeBufferedCollapse &&
		externalDirectUDPHasLossyHigherGoodputProbe(s.selected, s.selectedGoodput, s.sentByRate, s.received)
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) shouldHoldSelectedForBufferedProgress(obs externalDirectUDPProbeKneeObservation) bool {
	return s.selected >= externalDirectUDPRateProbeCollapseMinMbps &&
		s.selectedProbeViable &&
		obs.delivery >= externalDirectUDPRateProbeBufferedCollapse &&
		obs.goodput >= s.selectedGoodput
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) hasLossyRecoveryProbe() bool {
	_, _, _, _, ok := externalDirectUDPFindLossyRecoveryProbe(s.selected, s.selectedGoodput, s.sentByRate, s.received)
	return ok
}

func (s *externalDirectUDPProbeKneeHeadroomSelector) collapseSelectedProbeViable() bool {
	return s.selected >= externalDirectUDPRateProbeCollapseMinMbps && s.selectedProbeViable
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
	sentByRate := externalDirectUDPProbeSamplesByRate(sent)
	parts := make([]string, 0, len(received))
	for _, sample := range received {
		parts = append(parts, externalDirectUDPFormatRateProbeSample(sample, sentByRate))
	}
	return strings.Join(parts, ",")
}

func externalDirectUDPFormatRateProbeSample(sample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) string {
	durationMillis := externalDirectUDPProbeDurationMillis(sample)
	goodput := externalDirectUDPSampleGoodputMbps(sample.BytesReceived, durationMillis)
	delivery := externalDirectUDPRateProbeDelivery(sample, sentByRate)
	return fmt.Sprintf("%d:rx=%d:goodput=%.2f:delivery=%.2f", sample.RateMbps, sample.BytesReceived, goodput, delivery)
}

func externalDirectUDPProbeDurationMillis(sample directUDPRateProbeSample) int64 {
	if sample.DurationMillis > 0 {
		return sample.DurationMillis
	}
	return externalDirectUDPRateProbeDuration.Milliseconds()
}

func externalDirectUDPRateProbeDelivery(sample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) float64 {
	sentSample, ok := sentByRate[sample.RateMbps]
	if !ok || sentSample.BytesSent <= 0 {
		return 0
	}
	return float64(sample.BytesReceived) / float64(sentSample.BytesSent)
}

func externalDirectUDPOrderConnsForSections(conns []net.PacketConn, localCandidates []string, sectionAddrs []string) ([]net.PacketConn, error) {
	if len(sectionAddrs) == 0 {
		return conns, nil
	}
	endpointToConn := externalDirectUDPEndpointConnMap(conns, localCandidates)
	return externalDirectUDPConnsForSectionAddrs(conns, sectionAddrs, endpointToConn)
}

func externalDirectUDPEndpointConnMap(conns []net.PacketConn, localCandidates []string) map[string]int {
	endpointToConn := make(map[string]int)
	nextConn := 0
	for _, candidate := range localCandidates {
		endpoint := externalDirectUDPEndpointKey(candidate)
		if endpoint == "" || externalDirectUDPAddEndpointConn(endpointToConn, endpoint, nextConn, len(conns)) {
			continue
		}
		nextConn++
		if nextConn == len(conns) {
			break
		}
	}
	for i, conn := range conns {
		if conn == nil || conn.LocalAddr() == nil {
			continue
		}
		externalDirectUDPAddEndpointConn(endpointToConn, externalDirectUDPEndpointKey(conn.LocalAddr().String()), i, len(conns))
	}
	return endpointToConn
}

func externalDirectUDPAddEndpointConn(endpointToConn map[string]int, endpoint string, index int, connCount int) bool {
	if endpoint == "" || index < 0 || index >= connCount {
		return false
	}
	if _, ok := endpointToConn[endpoint]; ok {
		return true
	}
	endpointToConn[endpoint] = index
	return false
}

func externalDirectUDPConnsForSectionAddrs(conns []net.PacketConn, sectionAddrs []string, endpointToConn map[string]int) ([]net.PacketConn, error) {
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
		if addr := externalDirectUDPActiveDirectAddr(manager); addr != nil {
			return addr, nil
		}
		if err := waitExternalDirectUDPAddrTick(waitCtx, ticker); err != nil {
			return nil, err
		}
	}
}

func externalDirectUDPActiveDirectAddr(manager *transport.Manager) net.Addr {
	addr, active := manager.DirectAddr()
	if active && addr != nil {
		return addr
	}
	return nil
}

func waitExternalDirectUDPAddrTick(ctx context.Context, ticker *time.Ticker) error {
	select {
	case <-ticker.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func externalDirectUDPWaitCanFallback(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errExternalDirectUDPNoRateProbePackets))
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
	waitCtx, cancel := externalDirectUDPStartWaitContext(ctx)
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
	spool, err := externalDirectUDPNewDiscardSpool(lanes)
	if err != nil {
		return nil, err
	}
	if err := externalDirectUDPWriteDiscardSpool(ctx, src, spool, chunkSize); err != nil {
		_ = spool.Close()
		return nil, err
	}
	externalDirectUDPAssignDiscardSpoolLaneSections(spool, lanes)
	return spool, nil
}

func externalDirectUDPNewDiscardSpool(lanes int) (*externalDirectUDPDiscardSpool, error) {
	file, err := os.CreateTemp("", "derphole-discard-spool-*")
	if err != nil {
		return nil, err
	}
	return &externalDirectUDPDiscardSpool{
		File:    file,
		Path:    file.Name(),
		Offsets: make([]int64, lanes),
		Sizes:   make([]int64, lanes),
	}, nil
}

func externalDirectUDPWriteDiscardSpool(ctx context.Context, src io.Reader, spool *externalDirectUDPDiscardSpool, chunkSize int) error {
	buf := make([]byte, chunkSize*128)
	for {
		done, err := externalDirectUDPWriteDiscardSpoolChunk(ctx, src, spool, buf)
		if err != nil {
			return err
		}
		if done {
			break
		}
	}
	return nil
}

func externalDirectUDPWriteDiscardSpoolChunk(ctx context.Context, src io.Reader, spool *externalDirectUDPDiscardSpool, buf []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n, readErr := src.Read(buf)
	if n > 0 {
		if err := externalDirectUDPWriteDiscardSpoolBytes(spool, buf[:n]); err != nil {
			return false, err
		}
	}
	if errors.Is(readErr, io.EOF) {
		return true, nil
	}
	if readErr != nil {
		return false, readErr
	}
	return false, externalDirectUDPWaitForDiscardSpoolProgress(ctx, n)
}

func externalDirectUDPWriteDiscardSpoolBytes(spool *externalDirectUDPDiscardSpool, data []byte) error {
	written, err := spool.File.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	spool.TotalBytes += int64(written)
	return nil
}

func externalDirectUDPWaitForDiscardSpoolProgress(ctx context.Context, bytesRead int) error {
	if bytesRead > 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Millisecond):
		return nil
	}
}

func externalDirectUDPAssignDiscardSpoolLaneSections(spool *externalDirectUDPDiscardSpool, lanes int) {
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
}

func externalDirectUDPSendDiscardSpoolParallel(ctx context.Context, conns []net.PacketConn, remoteAddrs []string, spool *externalDirectUDPDiscardSpool, cfg probe.SendConfig) (probe.TransferStats, error) {
	if err := externalDirectUDPValidateDiscardSpoolSend(conns, remoteAddrs, spool); err != nil {
		return probe.TransferStats{}, err
	}
	laneCfg := externalDirectUDPDiscardSendLaneConfigFor(cfg, len(conns))
	startedAt := time.Now()
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		externalDirectUDPStartDiscardSpoolSendLane(ctx, conn, remoteAddrs[i], spool, i, laneCfg.forDiscardLane(i), results)
	}
	return externalDirectUDPCollectDiscardSendResults(results, len(conns), startedAt)
}

func externalDirectUDPValidateDiscardSpoolSend(conns []net.PacketConn, remoteAddrs []string, spool *externalDirectUDPDiscardSpool) error {
	if spool == nil {
		return errors.New("nil discard spool")
	}
	if len(conns) == 0 {
		return errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if spool.File == nil {
		return errors.New("nil discard spool file")
	}
	if len(spool.Sizes) < len(conns) || len(spool.Offsets) < len(conns) {
		return fmt.Errorf("discard spool lane count %d is less than packet conn count %d", len(spool.Sizes), len(conns))
	}
	return nil
}

type externalDirectUDPDiscardSendLaneConfig struct {
	cfg             probe.SendConfig
	laneRate        int
	laneRateCeiling int
}

func externalDirectUDPDiscardSendLaneConfigFor(cfg probe.SendConfig, lanes int) externalDirectUDPDiscardSendLaneConfig {
	cfg.StripedBlast = false
	cfg.Parallel = 1
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = externalDirectUDPChunkSize
	}
	return externalDirectUDPDiscardSendLaneConfig{
		cfg:             cfg,
		laneRate:        externalDirectUDPPerLaneRateMbps(cfg.RateMbps, lanes),
		laneRateCeiling: externalDirectUDPPerLaneRateMbps(cfg.RateCeilingMbps, lanes),
	}
}

func (c externalDirectUDPDiscardSendLaneConfig) forDiscardLane(lane int) probe.SendConfig {
	laneCfg := c.cfg
	laneCfg.RunID = externalDirectUDPDiscardLaneRunID(c.cfg.RunID, lane)
	laneCfg.RateMbps = c.laneRate
	laneCfg.RateCeilingMbps = c.laneRateCeiling
	return laneCfg
}

func (c externalDirectUDPDiscardSendLaneConfig) forPipeLane(lane int) probe.SendConfig {
	laneCfg := c.cfg
	laneCfg.RunID = externalDirectUDPLaneRunID(c.cfg.RunID, lane)
	laneCfg.RateMbps = c.laneRate
	laneCfg.RateCeilingMbps = c.laneRateCeiling
	return laneCfg
}

func externalDirectUDPStartDiscardSpoolSendLane(ctx context.Context, conn net.PacketConn, remoteAddr string, spool *externalDirectUDPDiscardSpool, lane int, laneCfg probe.SendConfig, results chan<- externalDirectUDPDiscardSendResult) {
	src := io.NewSectionReader(spool.File, spool.Offsets[lane], spool.Sizes[lane])
	go func() {
		stats, err := externalDirectUDPProbeSendFn(ctx, conn, remoteAddr, src, laneCfg)
		results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
	}()
}

func externalDirectUDPCollectDiscardSendResults(results <-chan externalDirectUDPDiscardSendResult, lanes int, startedAt time.Time) (probe.TransferStats, error) {
	stats := probe.TransferStats{StartedAt: startedAt, Lanes: lanes}
	var sendErr error
	for i := 0; i < lanes; i++ {
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
	prepared, err := externalDirectUDPPrepareReceiveSectionSpool(conns, dst, totalBytes, sectionSizes)
	if err != nil {
		return probe.TransferStats{}, err
	}
	defer prepared.cleanup()

	receiveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan externalDirectUDPReceiveResult, len(prepared.conns))
	startedAt := time.Now()
	for i, conn := range prepared.conns {
		laneCfg := externalDirectUDPReceiveSectionLaneConfig(cfg, i, len(prepared.conns))
		writer := &externalDirectUDPOffsetWriter{file: prepared.file, offset: prepared.offsets[i]}
		externalDirectUDPStartReceiveSectionSpoolLane(receiveCtx, cancel, conn, writer, prepared.sizes[i], laneCfg, results)
	}

	stats, receiveErr := externalDirectUDPCollectReceiveSectionResults(results, len(prepared.conns), startedAt)
	if receiveErr != nil {
		return externalDirectUDPCompleteReceiveSectionStats(stats, startedAt, receiveErr)
	}
	if err := externalDirectUDPFinishSectionTarget(prepared.file, prepared.copyToDst, prepared.dst, totalBytes); err != nil {
		return externalDirectUDPCompleteReceiveSectionStats(stats, startedAt, err)
	}
	return externalDirectUDPCompleteReceiveSectionStats(stats, startedAt, nil)
}

type externalDirectUDPReceiveSectionSpool struct {
	conns     []net.PacketConn
	dst       io.Writer
	file      *os.File
	copyToDst bool
	cleanup   func()
	sizes     []int64
	offsets   []int64
}

func externalDirectUDPPrepareReceiveSectionSpool(conns []net.PacketConn, dst io.Writer, totalBytes int64, sectionSizes []int64) (externalDirectUDPReceiveSectionSpool, error) {
	if len(conns) == 0 {
		return externalDirectUDPReceiveSectionSpool{}, errors.New("no packet conns")
	}
	if totalBytes < 0 {
		return externalDirectUDPReceiveSectionSpool{}, errors.New("negative expected bytes")
	}
	sizes, offsets, err := externalDirectUDPReceiveSectionLayout(totalBytes, len(conns), sectionSizes)
	if err != nil {
		return externalDirectUDPReceiveSectionSpool{}, err
	}
	if dst == nil {
		dst = io.Discard
	}
	file, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(dst, totalBytes)
	if err != nil {
		return externalDirectUDPReceiveSectionSpool{}, err
	}
	return externalDirectUDPReceiveSectionSpool{
		conns:     conns[:len(sizes)],
		dst:       dst,
		file:      file,
		copyToDst: copyToDst,
		cleanup:   cleanup,
		sizes:     sizes,
		offsets:   offsets,
	}, nil
}

func externalDirectUDPReceiveSectionLaneConfig(cfg probe.ReceiveConfig, lane int, lanes int) probe.ReceiveConfig {
	laneCfg := cfg
	if len(laneCfg.ExpectedRunIDs) == lanes {
		laneCfg.ExpectedRunID = laneCfg.ExpectedRunIDs[lane]
		laneCfg.ExpectedRunIDs = nil
	} else if len(laneCfg.ExpectedRunIDs) == 0 {
		laneCfg.ExpectedRunID = [16]byte{}
	}
	laneCfg.RequireComplete = true
	return laneCfg
}

func externalDirectUDPStartReceiveSectionSpoolLane(ctx context.Context, cancel context.CancelFunc, conn net.PacketConn, writer io.Writer, expected int64, laneCfg probe.ReceiveConfig, results chan<- externalDirectUDPReceiveResult) {
	go func() {
		stats, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{conn}, writer, laneCfg, expected)
		if err != nil {
			cancel()
		}
		results <- externalDirectUDPReceiveResult{stats: stats, err: err}
	}()
}

func externalDirectUDPCollectReceiveSectionResults(results <-chan externalDirectUDPReceiveResult, lanes int, startedAt time.Time) (probe.TransferStats, error) {
	stats := probe.TransferStats{StartedAt: startedAt, Lanes: lanes}
	var receiveErr error
	for i := 0; i < lanes; i++ {
		result := <-results
		receiveErr = externalDirectUDPPreferInformativeError(receiveErr, result.err)
		externalDirectUDPMergeReceiveStats(&stats, result.stats)
	}
	return stats, receiveErr
}

func externalDirectUDPCompleteReceiveSectionStats(stats probe.TransferStats, startedAt time.Time, err error) (probe.TransferStats, error) {
	stats.CompletedAt = time.Now()
	if stats.FirstByteAt.IsZero() && stats.BytesReceived > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, err
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
	if err := externalDirectUDPValidateDiscardParallel(conns, remoteAddrs, src); err != nil {
		return probe.TransferStats{}, err
	}
	laneCfg := externalDirectUDPDiscardSendLaneConfigFor(cfg, len(conns))
	if len(conns) == 1 {
		return externalDirectUDPProbeSendFn(ctx, conns[0], remoteAddrs[0], src, laneCfg.forPipeLane(0))
	}

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	startedAt := time.Now()
	writers := make([]*io.PipeWriter, len(conns))
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		writers[i] = externalDirectUDPStartDiscardPipeSendLane(sendCtx, cancel, conn, remoteAddrs[i], laneCfg.forPipeLane(i), results)
	}

	dispatchErr := externalDirectUDPDistributeDiscardStream(sendCtx, src, writers, laneCfg.cfg.ChunkSize)
	externalDirectUDPCloseDiscardWriters(writers, dispatchErr)
	stats, sendErr := externalDirectUDPCollectDiscardPipeSendResults(results, len(conns), startedAt)
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

func externalDirectUDPValidateDiscardParallel(conns []net.PacketConn, remoteAddrs []string, src io.Reader) error {
	if len(conns) == 0 {
		return errors.New("no packet conns")
	}
	if len(conns) != len(remoteAddrs) {
		return fmt.Errorf("packet conn count %d does not match remote addr count %d", len(conns), len(remoteAddrs))
	}
	if src == nil {
		return errors.New("nil source reader")
	}
	return nil
}

func externalDirectUDPStartDiscardPipeSendLane(ctx context.Context, cancel context.CancelFunc, conn net.PacketConn, remoteAddr string, laneCfg probe.SendConfig, results chan<- externalDirectUDPDiscardSendResult) *io.PipeWriter {
	reader, writer := io.Pipe()
	go func() {
		defer func() { _ = reader.Close() }()
		stats, err := externalDirectUDPProbeSendFn(ctx, conn, remoteAddr, reader, laneCfg)
		if err != nil {
			cancel()
		}
		results <- externalDirectUDPDiscardSendResult{stats: stats, err: err}
	}()
	return writer
}

func externalDirectUDPCloseDiscardWriters(writers []*io.PipeWriter, dispatchErr error) {
	for _, writer := range writers {
		if dispatchErr != nil {
			_ = writer.CloseWithError(dispatchErr)
			continue
		}
		_ = writer.Close()
	}
}

func externalDirectUDPCollectDiscardPipeSendResults(results <-chan externalDirectUDPDiscardSendResult, lanes int, startedAt time.Time) (probe.TransferStats, error) {
	stats := probe.TransferStats{StartedAt: startedAt, Lanes: lanes}
	var sendErr error
	for i := 0; i < lanes; i++ {
		result := <-results
		sendErr = externalDirectUDPPreferInformativeError(sendErr, result.err)
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, sendErr
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
	distributor := newExternalDirectUDPDiscardDistributor(ctx, src, writers, chunkSize)
	return distributor.run()
}

type externalDirectUDPDiscardDistributor struct {
	ctx             context.Context
	src             io.Reader
	writers         []*io.PipeWriter
	chunkSize       int
	distCtx         context.Context
	cancel          context.CancelFunc
	writerErrMu     sync.Mutex
	writerErr       error
	queues          []chan []byte
	writerDone      chan error
	closeQueuesOnce sync.Once
}

func newExternalDirectUDPDiscardDistributor(ctx context.Context, src io.Reader, writers []*io.PipeWriter, chunkSize int) *externalDirectUDPDiscardDistributor {
	distCtx, cancel := context.WithCancel(ctx)
	return &externalDirectUDPDiscardDistributor{
		ctx:        ctx,
		src:        src,
		writers:    writers,
		chunkSize:  chunkSize,
		distCtx:    distCtx,
		cancel:     cancel,
		queues:     make([]chan []byte, len(writers)),
		writerDone: make(chan error, len(writers)),
	}
}

func (d *externalDirectUDPDiscardDistributor) run() error {
	defer d.cancel()
	d.startWriters()
	return d.readLoop()
}

func (d *externalDirectUDPDiscardDistributor) startWriters() {
	for i, writer := range d.writers {
		queue := make(chan []byte, externalDirectUDPDiscardQueue)
		d.queues[i] = queue
		go d.writeQueue(writer, queue)
	}
}

func (d *externalDirectUDPDiscardDistributor) writeQueue(writer *io.PipeWriter, queue <-chan []byte) {
	for chunk := range queue {
		if len(chunk) == 0 {
			continue
		}
		if _, err := writer.Write(chunk); err != nil {
			d.setWriterErr(err)
			d.writerDone <- err
			return
		}
	}
	d.writerDone <- nil
}

func (d *externalDirectUDPDiscardDistributor) setWriterErr(err error) {
	if err == nil {
		return
	}
	d.writerErrMu.Lock()
	if d.writerErr == nil {
		d.writerErr = err
	}
	d.writerErrMu.Unlock()
	d.cancel()
}

func (d *externalDirectUDPDiscardDistributor) currentWriterErr() error {
	d.writerErrMu.Lock()
	defer d.writerErrMu.Unlock()
	return d.writerErr
}

func (d *externalDirectUDPDiscardDistributor) closeWritersWithError(err error) {
	for _, writer := range d.writers {
		if writer != nil {
			_ = writer.CloseWithError(err)
		}
	}
}

func (d *externalDirectUDPDiscardDistributor) closeQueues() {
	d.closeQueuesOnce.Do(func() {
		for _, queue := range d.queues {
			close(queue)
		}
	})
}

func (d *externalDirectUDPDiscardDistributor) waitWriters() error {
	var firstErr error
	for range d.writers {
		if err := <-d.writerDone; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return d.currentWriterErr()
}

func (d *externalDirectUDPDiscardDistributor) fail(err error) error {
	d.closeWritersWithError(err)
	d.closeQueues()
	if writerWaitErr := d.waitWriters(); writerWaitErr != nil && err == nil {
		return writerWaitErr
	}
	return err
}

func (d *externalDirectUDPDiscardDistributor) readLoop() error {
	buf := make([]byte, d.chunkSize*128)
	lane := 0
	for {
		if err := d.contextFailure(); err != nil {
			return err
		}
		n, readErr := d.src.Read(buf)
		if n > 0 {
			if err := d.enqueue(buf[:n], &lane); err != nil {
				return err
			}
		}
		done, err := d.handleReadErr(readErr)
		if done || err != nil {
			return err
		}
		if n == 0 {
			if err := d.waitForProgress(); err != nil {
				return err
			}
		}
	}
}

func (d *externalDirectUDPDiscardDistributor) contextFailure() error {
	if err := d.distCtx.Err(); err != nil {
		if writerErr := d.currentWriterErr(); writerErr != nil {
			return d.fail(writerErr)
		}
		return d.fail(err)
	}
	return nil
}

func (d *externalDirectUDPDiscardDistributor) enqueue(chunk []byte, lane *int) error {
	copied := append([]byte(nil), chunk...)
	select {
	case d.queues[*lane] <- copied:
		*lane = (*lane + 1) % len(d.writers)
		return nil
	case <-d.distCtx.Done():
		return d.contextFailure()
	}
}

func (d *externalDirectUDPDiscardDistributor) handleReadErr(readErr error) (bool, error) {
	if errors.Is(readErr, io.EOF) {
		d.closeQueues()
		return true, d.waitWriters()
	}
	if readErr != nil {
		return true, d.fail(readErr)
	}
	return false, nil
}

func (d *externalDirectUDPDiscardDistributor) waitForProgress() error {
	select {
	case <-d.distCtx.Done():
		return d.contextFailure()
	case <-time.After(time.Millisecond):
		return nil
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
	if rateCeilingMbps <= activeRateMbps {
		return activeRateMbps
	}
	if basis, ok := externalDirectUDPProbeRateLaneBasisOverride(activeRateMbps, rateCeilingMbps, probeRates); ok {
		return basis
	}
	return externalDirectUDPHighCeilingLaneRateBasis(activeRateMbps, rateCeilingMbps, probeRates)
}

func externalDirectUDPProbeRateLaneBasisOverride(activeRateMbps int, rateCeilingMbps int, probeRates []int) (int, bool) {
	if len(probeRates) == 0 || activeRateMbps <= 0 {
		return 0, false
	}
	if rateCeilingMbps >= externalDirectUDPActiveLaneFourMaxMbps && activeRateMbps <= externalDirectUDPActiveLaneFourMaxMbps {
		return externalDirectUDPActiveLaneFourMaxMbps, true
	}
	if rateCeilingMbps > externalDirectUDPDataStartHighMbps && activeRateMbps < externalDirectUDPActiveLaneFourMaxMbps {
		return externalDirectUDPDataStartHighMbps, true
	}
	return 0, false
}

func externalDirectUDPHighCeilingLaneRateBasis(activeRateMbps int, rateCeilingMbps int, probeRates []int) int {
	if rateCeilingMbps <= externalDirectUDPRateProbeDefaultMaxMbps {
		return rateCeilingMbps
	}
	probeMax := externalDirectUDPHighestProbeRateValue(probeRates)
	if probeMax == 0 {
		return activeRateMbps
	}
	if probeMax > rateCeilingMbps || probeMax > activeRateMbps {
		return probeMax
	}
	return rateCeilingMbps
}

func externalDirectUDPHighestProbeRateValue(probeRates []int) int {
	probeMax := 0
	for _, rate := range probeRates {
		if rate > probeMax {
			probeMax = rate
		}
	}
	return probeMax
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
	selector := newExternalDirectUDPBufferedCollapseSelector(selectedRateMbps, rateCeilingMbps, sent, received)
	if !selector.loadSelectedTier() {
		return false
	}
	selector.loadStartBudgetTier()
	return selector.hasBufferedCollapse()
}

type externalDirectUDPBufferedCollapseSelector struct {
	selectedRateMbps          int
	rateCeilingMbps           int
	sentByRate                map[int]directUDPRateProbeSample
	received                  []directUDPRateProbeSample
	selectedGoodput           float64
	selectedDelivery          float64
	selectedEfficiency        float64
	startBudgetRate           int
	startGoodput              float64
	startDelivery             float64
	startEfficiency           float64
	higherGoodputBeatSelected bool
}

func newExternalDirectUDPBufferedCollapseSelector(selectedRateMbps int, rateCeilingMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) *externalDirectUDPBufferedCollapseSelector {
	return &externalDirectUDPBufferedCollapseSelector{
		selectedRateMbps: selectedRateMbps,
		rateCeilingMbps:  rateCeilingMbps,
		sentByRate:       externalDirectUDPProbeSamplesByRate(sent),
		received:         received,
		startBudgetRate:  externalDirectUDPStartBudget(rateCeilingMbps).RateMbps,
	}
}

func (s *externalDirectUDPBufferedCollapseSelector) loadSelectedTier() bool {
	for _, sample := range s.received {
		if sample.RateMbps != s.selectedRateMbps {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
		if !ok || delivery < externalDirectUDPRateProbeNearClean {
			return false
		}
		s.selectedGoodput = goodput
		s.selectedDelivery = delivery
		s.selectedEfficiency = efficiency
		return true
	}
	return false
}

func (s *externalDirectUDPBufferedCollapseSelector) loadStartBudgetTier() {
	if s.startBudgetRate <= externalDirectUDPDataStartMaxMbps || s.startBudgetRate >= s.selectedRateMbps {
		return
	}
	for _, sample := range s.received {
		if sample.RateMbps <= 0 || sample.RateMbps > s.startBudgetRate {
			continue
		}
		goodput, delivery, efficiency, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
		if !ok {
			continue
		}
		s.startGoodput = goodput
		s.startDelivery = delivery
		s.startEfficiency = efficiency
	}
}

func (s *externalDirectUDPBufferedCollapseSelector) hasBufferedCollapse() bool {
	for _, sample := range s.received {
		if sample.RateMbps <= s.selectedRateMbps {
			continue
		}
		goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
		if !ok {
			continue
		}
		if s.higherProbeShowsCollapse(goodput, delivery) {
			return true
		}
	}
	return false
}

func (s *externalDirectUDPBufferedCollapseSelector) higherProbeShowsCollapse(goodput float64, delivery float64) bool {
	if goodput >= s.selectedGoodput {
		s.higherGoodputBeatSelected = true
		return false
	}
	if s.selectedTierAlreadyViableStart() || s.startBudgetTierCanAbsorbLossyProbe(delivery) {
		return false
	}
	return s.selectedDelivery < externalDirectUDPRateProbeClean && delivery < externalDirectUDPRateProbeCeilingDelivery
}

func (s *externalDirectUDPBufferedCollapseSelector) selectedTierAlreadyViableStart() bool {
	// A near-clean, efficient selected tier is already a viable data start.
	// Collapse above that point should cap further exploration, not force the
	// sender all the way back to the conservative 350 Mbps start.
	return s.selectedRateMbps <= s.startBudgetRate &&
		s.selectedDelivery >= externalDirectUDPRateProbeNearClean &&
		s.selectedEfficiency >= externalDirectUDPRateProbeEfficient
}

func (s *externalDirectUDPBufferedCollapseSelector) startBudgetTierCanAbsorbLossyProbe(delivery float64) bool {
	return s.startGoodput > 0 &&
		s.startDelivery >= externalDirectUDPRateProbeNearClean &&
		s.startEfficiency >= externalDirectUDPRateProbeEfficient &&
		delivery >= externalDirectUDPRateProbeLossyDelivery
}

func externalDirectUDPSelectedTierNeedsConservativeHighStart(selectedRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	if selectedRateMbps <= externalDirectUDPDataStartHighMbps {
		return false
	}
	state := externalDirectUDPSelectedTierConservativeStartState{
		selectedRateMbps: selectedRateMbps,
		sentByRate:       externalDirectUDPProbeSamplesByRate(sent),
	}
	for _, sample := range received {
		if needsConservativeStart, ok := state.observe(sample); ok {
			return needsConservativeStart
		}
	}
	return false
}

type externalDirectUDPSelectedTierConservativeStartState struct {
	selectedRateMbps int
	sentByRate       map[int]directUDPRateProbeSample
	prevGoodput      float64
	prevDelivery     float64
}

func (s *externalDirectUDPSelectedTierConservativeStartState) observe(sample directUDPRateProbeSample) (bool, bool) {
	if sample.RateMbps < s.selectedRateMbps {
		s.observePrevious(sample)
	}
	if sample.RateMbps != s.selectedRateMbps {
		return false, false
	}
	return s.selectedNeedsConservativeStart(sample), true
}

func (s *externalDirectUDPSelectedTierConservativeStartState) observePrevious(sample directUDPRateProbeSample) {
	goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok {
		return
	}
	s.prevGoodput = goodput
	s.prevDelivery = delivery
}

func (s externalDirectUDPSelectedTierConservativeStartState) selectedNeedsConservativeStart(sample directUDPRateProbeSample) bool {
	goodput, delivery, _, ok := externalDirectUDPProbeMetrics(sample, s.sentByRate)
	if !ok || delivery < externalDirectUDPRateProbeClean {
		return false
	}
	if s.selectedTierConfirmedByPreviousProbe(goodput) {
		return false
	}
	efficiency := goodput / float64(s.selectedRateMbps)
	return efficiency < externalDirectUDPRateProbeCeilingEfficient
}

func (s externalDirectUDPSelectedTierConservativeStartState) selectedTierConfirmedByPreviousProbe(goodput float64) bool {
	return s.selectedRateMbps > externalDirectUDPRateProbeConfirmMinMbps &&
		s.prevGoodput > 0 &&
		s.prevDelivery >= externalDirectUDPRateProbeClean &&
		goodput >= s.prevGoodput*1.10
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
	if !externalDirectUDPShouldInspectExplorationSamples(selectedRateMbps, rateCeilingMbps, sent, received) {
		return explorationCeiling
	}
	sentByRate := externalDirectUDPProbeSamplesByRate(sent)
	selectedSample, ok := externalDirectUDPFindRateProbeSample(received, selectedRateMbps)
	if !ok {
		return rateCeilingMbps
	}
	selectedGoodput, selectedDelivery, ok := externalDirectUDPSelectedProbeMetrics(selectedSample, sentByRate)
	if !ok || selectedDelivery >= externalDirectUDPRateProbeLossySelect {
		return rateCeilingMbps
	}
	return externalDirectUDPDataExplorationCeilingFromLossySelection(maxRateMbps, selectedRateMbps, rateCeilingMbps, selectedGoodput, selectedDelivery, sentByRate, received)
}

func externalDirectUDPShouldInspectExplorationSamples(selectedRateMbps int, rateCeilingMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) bool {
	return rateCeilingMbps <= selectedRateMbps &&
		selectedRateMbps >= externalDirectUDPRateProbeCollapseMinMbps &&
		len(sent) > 0 &&
		len(received) > 0
}

func externalDirectUDPFindRateProbeSample(samples []directUDPRateProbeSample, rateMbps int) (directUDPRateProbeSample, bool) {
	for _, sample := range samples {
		if sample.RateMbps == rateMbps {
			return sample, true
		}
	}
	return directUDPRateProbeSample{RateMbps: rateMbps}, false
}

func externalDirectUDPSelectedProbeMetrics(selectedSample directUDPRateProbeSample, sentByRate map[int]directUDPRateProbeSample) (float64, float64, bool) {
	selectedGoodput, selectedDelivery, _, ok := externalDirectUDPProbeMetrics(selectedSample, sentByRate)
	return selectedGoodput, selectedDelivery, ok
}

func externalDirectUDPDataExplorationCeilingFromLossySelection(maxRateMbps int, selectedRateMbps int, rateCeilingMbps int, selectedGoodput float64, selectedDelivery float64, sentByRate map[int]directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	explorationRate, _, _, _, ok := externalDirectUDPFindLossyHighSelectedExplorationCeiling(selectedRateMbps, selectedGoodput, selectedDelivery, sentByRate, received, maxRateMbps)
	if !ok || explorationRate <= rateCeilingMbps {
		return rateCeilingMbps
	}
	return explorationRate
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
	defer func() { _ = packetConn.Close() }()
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
	defer func() { _ = packetConn.Close() }()
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
	defer func() { _ = devNull.Close() }()
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
