// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	envelopeProgress           = "progress"
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
	Progress           *peerProgress             `json:"progress,omitempty"`
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

type peerProgress struct {
	BytesReceived     int64  `json:"bytes_received"`
	TransferElapsedMS int64  `json:"transfer_elapsed_ms"`
	Sequence          uint64 `json:"sequence,omitempty"`
}

func newPeerProgress(bytesReceived int64, transferElapsedMS int64, sequence uint64) *peerProgress {
	if bytesReceived < 0 {
		bytesReceived = 0
	}
	if transferElapsedMS < 0 {
		transferElapsedMS = 0
	}
	return &peerProgress{
		BytesReceived:     bytesReceived,
		TransferElapsedMS: transferElapsedMS,
		Sequence:          sequence,
	}
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
	FastDiscard               bool   `json:"fast_discard,omitempty"`
	TransportKind             string `json:"transport_kind,omitempty"`
	TransportBatchSize        int    `json:"transport_batch_size,omitempty"`
	TransportReadBufferBytes  int    `json:"transport_read_buffer_bytes,omitempty"`
	TransportWriteBufferBytes int    `json:"transport_write_buffer_bytes,omitempty"`
	TransportTXOffload        bool   `json:"transport_tx_offload,omitempty"`
	TransportRXQOverflow      bool   `json:"transport_rxq_overflow,omitempty"`
}

type directUDPStart struct {
	ExpectedBytes     int64    `json:"expected_bytes,omitempty"`
	RelayPrefixOffset int64    `json:"relay_prefix_offset,omitempty"`
	SectionSizes      []int64  `json:"section_sizes,omitempty"`
	SectionAddrs      []string `json:"section_addrs,omitempty"`
	ProbeRates        []int    `json:"probe_rates,omitempty"`
	ProbeNonce        string   `json:"probe_nonce,omitempty"`
	Stream            bool     `json:"stream,omitempty"`
	StripedBlast      bool     `json:"striped_blast,omitempty"`
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
	dm, node, derpClient, err := openPublicSessionDERPClient(ctx)
	if err != nil {
		return "", nil, err
	}

	sessionID, bearerSecret, err := newPublicSessionSecrets()
	if err != nil {
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

func openPublicSessionDERPClient(ctx context.Context) (*tailcfg.DERPMap, *tailcfg.DERPNode, *derpbind.Client, error) {
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, nil, nil, err
	}
	node := firstDERPNode(dm, 0)
	if node == nil {
		return nil, nil, nil, errors.New("no DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, nil, nil, err
	}
	return dm, node, derpClient, nil
}

func newPublicSessionSecrets() ([16]byte, [32]byte, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return [16]byte{}, [32]byte{}, err
	}
	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		return [16]byte{}, [32]byte{}, err
	}
	return sessionID, bearerSecret, nil
}

func issuePublicSession(ctx context.Context) (string, *relaySession, error) {
	return issuePublicSessionWithCapabilities(ctx, token.CapabilityStdio)
}

func sendExternal(ctx context.Context, cfg SendConfig) error {
	return sendExternalViaDirectUDP(ctx, cfg)
}

type externalNativeDirectModeResult struct {
	nativeQUIC     bool
	nativeQUICAddr net.Addr
	nativeTCPConns []net.Conn
	parallelPolicy ParallelPolicy
	err            error
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
	controlCh, unsubscribe := derpClient.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportControlPayload(pkt.Payload)
	})
	payloadCh, unsubscribePayload := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportDataPayload(pkt.Payload)
	})

	cfg := externalTransportManagerConfig(tok, conn, derpClient, peerDERP, controlCh, payloadCh, pm)
	if !forceRelay {
		configureExternalDirectTransport(&cfg, conn, dm, pm, localCandidates)
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

func externalTransportManagerConfig(
	tok token.Token,
	conn net.PacketConn,
	derpClient *derpbind.Client,
	peerDERP key.NodePublic,
	controlCh <-chan derpbind.Packet,
	payloadCh <-chan derpbind.Packet,
	pm publicPortmap,
) transport.ManagerConfig {
	auth := externalPeerControlAuthForToken(tok)
	return transport.ManagerConfig{
		RelayConn: conn,
		RelaySend: func(ctx context.Context, payload []byte) error {
			if err := externalAssertNoPlaintextRelayMarker(payload); err != nil {
				return err
			}
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
}

func configureExternalDirectTransport(cfg *transport.ManagerConfig, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap, localCandidates []net.Addr) {
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
	if !externalQUICModeRequestAllowed(forceRelay, manager) {
		return false, nil, nil, ParallelPolicy{}, nil
	}
	auth := optionalPeerControlAuth(authOpt)
	parallelPolicy = parallelPolicy.normalized()

	tcpOffer := openExternalQUICModeTCPRequest(localCandidates, serverTLSConfig)
	defer tcpOffer.Close()
	emitExternalQUICModeTCPRequest(emitter, tcpOffer)

	subs := subscribeExternalQUICModeRequest(client, peerDERP)
	defer subs.Close()

	if err := sendExternalQUICModeRequest(ctx, client, peerDERP, tcpOffer, parallelPolicy, auth); err != nil {
		return false, nil, nil, ParallelPolicy{}, err
	}

	modeCtx, cancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer cancel()
	resp, ok, err := receiveExternalQUICModeResponseOrNack(modeCtx, client, peerDERP, subs.modeCh, emitter, auth)
	if err != nil {
		return false, nil, nil, ParallelPolicy{}, err
	}
	if !ok {
		return false, nil, nil, ParallelPolicy{}, nil
	}
	emitExternalQUICModeTCPResponse(emitter, resp)

	resolvedPolicy := externalQUICModeResolvedPolicy(resp, parallelPolicy)
	addr, ok := externalQUICModeResponseDirectAddr(ctx, manager, resp)
	nativeTCPConns, nativeTCP := connectExternalQUICModeNativeTCP(modeCtx, tcpOffer, addr, resp, clientTLSConfig, nativeTCPAuth, parallelPolicy, emitter)
	ackEnv := envelope{
		Type: envelopeQUICModeAck,
		QUICModeAck: &quicModeAck{
			NativeDirect: resp.NativeDirect && ok && addr != nil,
			NativeTCP:    nativeTCP && len(nativeTCPConns) > 0,
		},
	}
	return finishExternalQUICModeRequest(ctx, client, peerDERP, subs.readyCh, ackEnv, resp, addr, ok, nativeTCPConns, resolvedPolicy, auth)
}

type externalQUICModeTCPRequest struct {
	listener  net.Listener
	addr      string
	requested bool
}

func (r *externalQUICModeTCPRequest) Close() {
	if r != nil && r.listener != nil {
		_ = r.listener.Close()
	}
}

func externalQUICModeRequestAllowed(forceRelay bool, manager *transport.Manager) bool {
	return !forceRelay && manager != nil
}

func emitExternalQUICModeTCPRequest(emitter *telemetry.Emitter, tcpOffer externalQUICModeTCPRequest) {
	if emitter != nil {
		emitter.Debug("sender-tcp-offer=" + strconv.FormatBool(tcpOffer.requested) + " addr=" + tcpOffer.addr)
	}
}

type externalQUICModeRequestSubscriptions struct {
	modeCh           <-chan derpbind.Packet
	readyCh          <-chan derpbind.Packet
	unsubscribeMode  func()
	unsubscribeReady func()
}

func (s externalQUICModeRequestSubscriptions) Close() {
	if s.unsubscribeMode != nil {
		s.unsubscribeMode()
	}
	if s.unsubscribeReady != nil {
		s.unsubscribeReady()
	}
}

func subscribeExternalQUICModeRequest(client *derpbind.Client, peerDERP key.NodePublic) externalQUICModeRequestSubscriptions {
	modeCh, unsubscribeMode := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeResponsePayload(pkt.Payload)
	})
	readyCh, unsubscribeReady := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeReadyPayload(pkt.Payload)
	})
	return externalQUICModeRequestSubscriptions{
		modeCh:           modeCh,
		readyCh:          readyCh,
		unsubscribeMode:  unsubscribeMode,
		unsubscribeReady: unsubscribeReady,
	}
}

func emitExternalQUICModeTCPResponse(emitter *telemetry.Emitter, resp quicModeResponse) {
	if emitter != nil {
		emitter.Debug("sender-tcp-response=" + strconv.FormatBool(resp.NativeTCP) + " addr=" + resp.DirectAddr)
	}
}

func openExternalQUICModeTCPRequest(localCandidates []net.Addr, serverTLSConfig *tls.Config) externalQUICModeTCPRequest {
	ln, ok := listenExternalNativeTCPOnCandidates(localCandidates, serverTLSConfig)
	if !ok {
		return externalQUICModeTCPRequest{}
	}
	return externalQUICModeTCPRequest{
		listener:  ln,
		addr:      quicModeDirectAddrString(externalNativeTCPAdvertiseAddr(ln.Addr(), nil)),
		requested: true,
	}
}

func sendExternalQUICModeRequest(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, tcpOffer externalQUICModeTCPRequest, parallelPolicy ParallelPolicy, auth externalPeerControlAuth) error {
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type: envelopeQUICModeReq,
		QUICModeReq: &quicModeRequest{
			NativeDirect:    true,
			NativeTCP:       tcpOffer.requested,
			DirectAddr:      tcpOffer.addr,
			NativeTCPConns:  externalParallelTCPConnCount(parallelPolicy),
			ParallelMode:    string(parallelPolicy.Mode),
			ParallelInitial: parallelPolicy.Initial,
			ParallelCap:     parallelPolicy.Cap,
		},
	}, auth)
}

func receiveExternalQUICModeResponseOrNack(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, modeCh <-chan derpbind.Packet, emitter *telemetry.Emitter, auth externalPeerControlAuth) (quicModeResponse, bool, error) {
	resp, err := receiveQUICModeResponse(ctx, modeCh, auth)
	if err == nil && (resp.NativeDirect || resp.NativeTCP) {
		return resp, true, nil
	}
	if errors.Is(err, context.Canceled) {
		sendExternalQUICModeNack(client, peerDERP, auth)
	}
	if emitter != nil {
		emitter.Debug("sender-tcp-response=none")
	}
	return quicModeResponse{}, false, nil
}

func sendExternalQUICModeNack(client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth) {
	nackCtx, nackCancel := context.WithTimeout(context.Background(), externalNativeQUICNackWait)
	defer nackCancel()
	_ = sendAuthenticatedEnvelope(nackCtx, client, peerDERP, envelope{
		Type: envelopeQUICModeAck,
		QUICModeAck: &quicModeAck{
			NativeDirect: false,
			NativeTCP:    false,
		},
	}, auth)
}

func externalQUICModeResolvedPolicy(resp quicModeResponse, fallback ParallelPolicy) ParallelPolicy {
	resolvedPolicy := quicModeParallelPolicy(resp)
	if resolvedPolicy.Mode == "" {
		return fallback
	}
	return resolvedPolicy
}

func externalQUICModeResponseDirectAddr(ctx context.Context, manager *transport.Manager, resp quicModeResponse) (net.Addr, bool) {
	if parsed := parseCandidateStrings([]string{resp.DirectAddr}); len(parsed) == 1 {
		return parsed[0], true
	}
	if addr, ok := manager.DirectAddr(); ok && addr != nil {
		return addr, true
	}
	return waitForExternalDirectAddr(ctx, manager, externalNativeQUICWait)
}

func connectExternalQUICModeNativeTCP(ctx context.Context, tcpOffer externalQUICModeTCPRequest, addr net.Addr, resp quicModeResponse, clientTLSConfig *tls.Config, nativeTCPAuth externalNativeTCPAuth, parallelPolicy ParallelPolicy, emitter *telemetry.Emitter) ([]net.Conn, bool) {
	if !resp.NativeTCP || addr == nil || !externalNativeTCPAddrAllowed(addr) {
		return nil, false
	}
	conns, err := connectExternalQUICModeNativeTCPConns(ctx, tcpOffer, addr, resp, clientTLSConfig, nativeTCPAuth, parallelPolicy, emitter)
	if err != nil {
		if emitter != nil {
			emitter.Debug("sender-tcp-connect-failed=" + err.Error())
		}
		return nil, false
	}
	return conns, true
}

func connectExternalQUICModeNativeTCPConns(ctx context.Context, tcpOffer externalQUICModeTCPRequest, addr net.Addr, resp quicModeResponse, clientTLSConfig *tls.Config, nativeTCPAuth externalNativeTCPAuth, parallelPolicy ParallelPolicy, emitter *telemetry.Emitter) ([]net.Conn, error) {
	tcpTLSConfig := clientTLSConfig
	connCount := externalNativeTCPHandshakeConnCount(resp.NativeTCPConns, externalParallelTCPConnCount(parallelPolicy))
	if tcpOffer.listener != nil {
		if externalNativeTCPUseBearerAuth(tcpOffer.listener.Addr(), addr) {
			tcpTLSConfig = nil
		}
		return connectExternalQUICModeNativeTCPFromListener(ctx, tcpOffer.listener, addr, tcpTLSConfig, nativeTCPAuth, connCount, emitter)
	}
	return dialExternalQUICModeNativeTCP(ctx, addr, tcpTLSConfig, nativeTCPAuth, connCount, emitter)
}

func connectExternalQUICModeNativeTCPFromListener(ctx context.Context, listener net.Listener, addr net.Addr, tcpTLSConfig *tls.Config, nativeTCPAuth externalNativeTCPAuth, connCount int, emitter *telemetry.Emitter) ([]net.Conn, error) {
	if connCount > 1 {
		conns, err := connectExternalNativeTCPConns(ctx, listener, addr, tcpTLSConfig, nativeTCPAuth, 0, connCount)
		emitExternalQUICModeTCPStripeCount(emitter, conns, err)
		return conns, err
	}
	conn, err := connectExternalNativeTCPSender(ctx, listener, addr, tcpTLSConfig, nativeTCPAuth)
	return externalQUICModeSingleTCPConn(conn), err
}

func dialExternalQUICModeNativeTCP(ctx context.Context, addr net.Addr, tcpTLSConfig *tls.Config, nativeTCPAuth externalNativeTCPAuth, connCount int, emitter *telemetry.Emitter) ([]net.Conn, error) {
	if connCount > 1 {
		conns, err := dialExternalNativeTCPConns(ctx, addr, tcpTLSConfig, nativeTCPAuth, connCount)
		emitExternalQUICModeTCPStripeCount(emitter, conns, err)
		return conns, err
	}
	conn, err := dialExternalNativeTCP(ctx, addr, tcpTLSConfig, nativeTCPAuth)
	return externalQUICModeSingleTCPConn(conn), err
}

func externalQUICModeSingleTCPConn(conn net.Conn) []net.Conn {
	if conn == nil {
		return nil
	}
	return []net.Conn{conn}
}

func emitExternalQUICModeTCPStripeCount(emitter *telemetry.Emitter, conns []net.Conn, err error) {
	if err == nil && emitter != nil {
		emitter.Debug("native-tcp-stripes=" + strconv.Itoa(len(conns)))
	}
}

func finishExternalQUICModeRequest(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, readyCh <-chan derpbind.Packet, ackEnv envelope, resp quicModeResponse, addr net.Addr, ok bool, nativeTCPConns []net.Conn, resolvedPolicy ParallelPolicy, auth externalPeerControlAuth) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	if err := sendAuthenticatedEnvelope(ctx, client, peerDERP, ackEnv, auth); err != nil {
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, resolvedPolicy, err
	}
	if !resp.NativeDirect || !ok || addr == nil {
		if len(nativeTCPConns) > 0 {
			return false, nativeTCPConns, nil, resolvedPolicy, nil
		}
		closeExternalNativeTCPConns(nativeTCPConns)
		return false, nil, nil, resolvedPolicy, nil
	}
	if len(nativeTCPConns) > 0 {
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

	subs := subscribeExternalQUICModeAccept(client, peerDERP)
	defer subs.Close()

	req, ok, err := receiveExternalQUICModeAcceptRequest(ctx, modeCtx, modeCh, auth)
	if err != nil {
		return false, nil, nil, ParallelPolicy{}, err
	}
	if !ok {
		return false, nil, nil, ParallelPolicy{}, nil
	}

	state := newExternalQUICModeAcceptState(ctx, client, peerDERP, manager, localCandidates, req, emitter, clientTLSConfig, serverTLSConfig, nativeTCPAuth, auth)
	if state.prepareNativeOffer(forceRelay, subs.modeAbortCh) {
		return false, nil, nil, ParallelPolicy{}, nil
	}
	if err := state.sendResponse(ctx); err != nil {
		return false, nil, nil, state.resolvedPolicy, err
	}
	if !state.hasNativePath() {
		return false, nil, nil, state.resolvedPolicy, nil
	}
	state.startNativeTCPHandshake()
	return state.receiveAckAndFinish(ctx, subs.ackCh)
}

type externalQUICModeAcceptSubscriptions struct {
	ackCh                <-chan derpbind.Packet
	modeAbortCh          <-chan derpbind.Packet
	unsubscribeAck       func()
	unsubscribeModeAbort func()
}

func (s externalQUICModeAcceptSubscriptions) Close() {
	if s.unsubscribeAck != nil {
		s.unsubscribeAck()
	}
	if s.unsubscribeModeAbort != nil {
		s.unsubscribeModeAbort()
	}
}

func subscribeExternalQUICModeAccept(client *derpbind.Client, peerDERP key.NodePublic) externalQUICModeAcceptSubscriptions {
	ackCh, unsubscribeAck := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAckPayload(pkt.Payload)
	})
	modeAbortCh, unsubscribeModeAbort := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isQUICModeAbortAckPayload(pkt.Payload)
	})
	return externalQUICModeAcceptSubscriptions{
		ackCh:                ackCh,
		modeAbortCh:          modeAbortCh,
		unsubscribeAck:       unsubscribeAck,
		unsubscribeModeAbort: unsubscribeModeAbort,
	}
}

func receiveExternalQUICModeAcceptRequest(parentCtx, modeCtx context.Context, modeCh <-chan derpbind.Packet, auth externalPeerControlAuth) (quicModeRequest, bool, error) {
	req, err := receiveQUICModeRequest(modeCtx, modeCh, auth)
	if err == nil {
		return req, true, nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return quicModeRequest{}, false, nil
	}
	if errors.Is(err, context.Canceled) {
		return quicModeRequest{}, false, parentCtx.Err()
	}
	return quicModeRequest{}, false, nil
}

type externalQUICModeNativeTCPResult struct {
	conns []net.Conn
	err   error
}

type externalQUICModeAcceptState struct {
	ctx             context.Context
	client          *derpbind.Client
	peerDERP        key.NodePublic
	manager         *transport.Manager
	localCandidates []net.Addr
	req             quicModeRequest
	resolvedPolicy  ParallelPolicy
	emitter         *telemetry.Emitter
	clientTLSConfig *tls.Config
	serverTLSConfig *tls.Config
	nativeTCPAuth   externalNativeTCPAuth
	auth            externalPeerControlAuth

	nativeQUIC         bool
	nativeQUICAddr     net.Addr
	nativeQUICPeerAddr net.Addr
	nativeTCPListener  net.Listener
	nativeTCPPeerAddr  net.Addr
	nativeTCPBindAddr  net.Addr
	nativeTCPAddr      net.Addr
	nativeTCPConnCh    chan externalQUICModeNativeTCPResult
	nativeTCPCancel    context.CancelFunc
}

func newExternalQUICModeAcceptState(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, localCandidates []net.Addr, req quicModeRequest, emitter *telemetry.Emitter, clientTLSConfig *tls.Config, serverTLSConfig *tls.Config, nativeTCPAuth externalNativeTCPAuth, auth externalPeerControlAuth) *externalQUICModeAcceptState {
	emitExternalQUICModeAcceptRequest(emitter, req)
	return &externalQUICModeAcceptState{
		ctx:             ctx,
		client:          client,
		peerDERP:        peerDERP,
		manager:         manager,
		localCandidates: localCandidates,
		req:             req,
		resolvedPolicy:  externalQUICModeAcceptPolicy(req),
		emitter:         emitter,
		clientTLSConfig: clientTLSConfig,
		serverTLSConfig: serverTLSConfig,
		nativeTCPAuth:   nativeTCPAuth,
		auth:            auth,
	}
}

func emitExternalQUICModeAcceptRequest(emitter *telemetry.Emitter, req quicModeRequest) {
	if emitter != nil {
		emitter.Debug("listener-tcp-request=" + strconv.FormatBool(req.NativeTCP) + " addr=" + req.DirectAddr)
	}
}

func externalQUICModeAcceptPolicy(req quicModeRequest) ParallelPolicy {
	policy := quicModeParallelPolicy(req)
	if policy.Mode == "" {
		return DefaultParallelPolicy()
	}
	return policy
}

func (s *externalQUICModeAcceptState) prepareNativeOffer(forceRelay bool, modeAbortCh <-chan derpbind.Packet) bool {
	if !forceRelay && (s.req.NativeDirect || s.req.NativeTCP) {
		s.prepareInitialNativeTCP()
	}
	if s.prepareNativeQUIC(forceRelay, modeAbortCh) {
		return true
	}
	s.emitSelectedTCPWithoutQUIC()
	s.resolveParallelPolicy()
	return false
}

func (s *externalQUICModeAcceptState) prepareInitialNativeTCP() {
	if !s.req.NativeTCP {
		return
	}
	if peerCandidate, ok := externalQUICModeTCPPeerCandidate(s.req); ok {
		s.selectInitialNativeTCPResponseAddr(peerCandidate)
	} else {
		s.selectInitialNativeTCPOfferAddr()
		if s.nativeTCPBindAddr == nil {
			s.emitDebug("listener-tcp-peer-rejected")
		}
	}
	s.openNativeTCPListener()
}

func externalQUICModeTCPPeerCandidate(req quicModeRequest) (net.Addr, bool) {
	parsed := parseCandidateStrings([]string{req.DirectAddr})
	if len(parsed) != 1 || !externalNativeTCPAddrAllowed(parsed[0]) {
		return nil, false
	}
	return parsed[0], true
}

func (s *externalQUICModeAcceptState) selectInitialNativeTCPResponseAddr(peerCandidate net.Addr) {
	bindAddr := selectExternalNativeTCPResponseAddr(peerCandidate, nil, s.localCandidates)
	if bindAddr == nil {
		s.selectInitialNativeTCPOfferAddr()
		return
	}
	s.nativeTCPPeerAddr = peerCandidate
	s.nativeTCPBindAddr = bindAddr
	s.nativeTCPAddr = externalNativeTCPAdvertiseAddr(bindAddr, peerCandidate)
}

func (s *externalQUICModeAcceptState) selectInitialNativeTCPOfferAddr() {
	s.nativeTCPBindAddr = selectExternalNativeTCPOfferAddr(s.localCandidates)
	s.nativeTCPAddr = externalNativeTCPAdvertiseAddr(s.nativeTCPBindAddr, nil)
}

func (s *externalQUICModeAcceptState) openNativeTCPListener() {
	if s.nativeTCPBindAddr == nil || !externalNativeTCPAddrAllowed(s.nativeTCPBindAddr) {
		if s.req.NativeTCP {
			s.emitDebug("listener-tcp-offer-rejected")
		}
		return
	}
	listener, err := listenExternalNativeTCP(s.nativeTCPBindAddr, s.serverNativeTCPTLSConfig())
	if err != nil {
		s.emitDebug("listener-tcp-listen-failed=" + err.Error())
		s.nativeTCPPeerAddr = nil
		s.nativeTCPAddr = nil
		s.nativeTCPListener = nil
		return
	}
	s.nativeTCPListener = listener
}

func (s *externalQUICModeAcceptState) serverNativeTCPTLSConfig() *tls.Config {
	if externalNativeTCPUseBearerAuth(s.nativeTCPBindAddr, s.nativeTCPPeerAddr) {
		return nil
	}
	return s.serverTLSConfig
}

func (s *externalQUICModeAcceptState) prepareNativeQUIC(forceRelay bool, modeAbortCh <-chan derpbind.Packet) bool {
	if !s.shouldWaitForNativeQUIC(forceRelay) {
		return false
	}
	peerDirectAddr, ok, aborted := waitForExternalDirectAddrOrModeAbort(s.ctx, s.manager, modeAbortCh, externalNativeQUICWait, s.auth)
	if aborted {
		return true
	}
	if !ok {
		return false
	}
	s.nativeQUIC = true
	s.nativeQUICPeerAddr = cloneSessionAddr(peerDirectAddr)
	s.nativeQUICAddr = selectExternalQUICModeResponseAddr(peerDirectAddr, s.localCandidates)
	s.reselectNativeTCPForDirectAddr(peerDirectAddr)
	s.emitDebug("listener-tcp-selected=" + quicModeDirectAddrString(s.nativeTCPAddr))
	s.openNativeTCPListener()
	return false
}

func (s *externalQUICModeAcceptState) shouldWaitForNativeQUIC(forceRelay bool) bool {
	return s.req.NativeDirect && !forceRelay && s.nativeTCPListener == nil
}

func (s *externalQUICModeAcceptState) reselectNativeTCPForDirectAddr(peerDirectAddr net.Addr) {
	if s.nativeTCPPeerAddr == nil {
		return
	}
	s.nativeTCPBindAddr = selectExternalNativeTCPResponseAddr(s.nativeTCPPeerAddr, peerDirectAddr, s.localCandidates)
	s.nativeTCPAddr = externalNativeTCPAdvertiseAddr(s.nativeTCPBindAddr, s.nativeTCPPeerAddr)
}

func (s *externalQUICModeAcceptState) emitSelectedTCPWithoutQUIC() {
	if s.nativeTCPListener != nil && !s.nativeQUIC {
		s.emitDebug("listener-tcp-selected=" + quicModeDirectAddrString(s.nativeTCPAddr))
	}
}

func (s *externalQUICModeAcceptState) resolveParallelPolicy() {
	if !s.nativeQUIC || s.nativeQUICPeerAddr == nil {
		return
	}
	s.resolvedPolicy.Initial = externalNativeQUICConnCountForPeer(s.nativeQUICPeerAddr, s.resolvedPolicy.Initial)
	s.resolvedPolicy.Cap = externalNativeQUICConnCountForPeer(s.nativeQUICPeerAddr, s.resolvedPolicy.Cap)
	if s.resolvedPolicy.Cap < s.resolvedPolicy.Initial {
		s.resolvedPolicy.Cap = s.resolvedPolicy.Initial
	}
}

func (s *externalQUICModeAcceptState) sendResponse(ctx context.Context) error {
	nativeTCPOffered := s.nativeTCPListener != nil
	if err := sendAuthenticatedEnvelope(ctx, s.client, s.peerDERP, envelope{
		Type: envelopeQUICModeResp,
		QUICModeResp: &quicModeResponse{
			NativeDirect:    s.nativeQUIC,
			NativeTCP:       nativeTCPOffered,
			DirectAddr:      quicModeDirectAddrString(nativeQUICModeResponseAddr(s.nativeQUICAddr, s.nativeTCPAddr, nativeTCPOffered)),
			NativeTCPConns:  s.nativeTCPConnCount(),
			ParallelMode:    string(s.resolvedPolicy.Mode),
			ParallelInitial: s.resolvedPolicy.Initial,
			ParallelCap:     s.resolvedPolicy.Cap,
		},
	}, s.auth); err != nil {
		s.closeNativeTCPListener()
		return err
	}
	return nil
}

func (s *externalQUICModeAcceptState) hasNativePath() bool {
	return s.nativeQUIC || s.nativeTCPListener != nil
}

func (s *externalQUICModeAcceptState) nativeTCPConnCount() int {
	return externalNativeTCPPassiveConnCount(s.req.NativeTCPConns)
}

func (s *externalQUICModeAcceptState) closeNativeTCPListener() {
	if s.nativeTCPListener != nil {
		_ = s.nativeTCPListener.Close()
	}
}

func (s *externalQUICModeAcceptState) startNativeTCPHandshake() {
	if s.nativeTCPListener == nil {
		return
	}
	nativeTCPCtx, cancel := context.WithCancel(s.ctx)
	s.nativeTCPCancel = cancel
	s.nativeTCPConnCh = make(chan externalQUICModeNativeTCPResult, 1)
	if s.nativeTCPPeerAddr != nil {
		go s.connectNativeTCP(nativeTCPCtx)
		return
	}
	go s.acceptNativeTCP(nativeTCPCtx)
}

func (s *externalQUICModeAcceptState) connectNativeTCP(ctx context.Context) {
	tcpTLSConfig := s.clientNativeTCPTLSConfig()
	connCount := s.nativeTCPConnCount()
	if connCount > 1 {
		conns, err := connectExternalNativeTCPConns(ctx, s.nativeTCPListener, s.nativeTCPPeerAddr, tcpTLSConfig, s.nativeTCPAuth, externalNativeTCPDialFallbackDelay, connCount)
		emitExternalQUICModeTCPStripeCount(s.emitter, conns, err)
		s.nativeTCPConnCh <- externalQUICModeNativeTCPResult{conns: conns, err: err}
		return
	}
	conn, err := connectExternalNativeTCPListener(ctx, s.nativeTCPListener, s.nativeTCPPeerAddr, tcpTLSConfig, s.nativeTCPAuth)
	s.nativeTCPConnCh <- externalQUICModeNativeTCPResult{conns: externalQUICModeSingleTCPConn(conn), err: err}
}

func (s *externalQUICModeAcceptState) clientNativeTCPTLSConfig() *tls.Config {
	if externalNativeTCPUseBearerAuth(s.nativeTCPListener.Addr(), s.nativeTCPPeerAddr) {
		return nil
	}
	return s.clientTLSConfig
}

func (s *externalQUICModeAcceptState) acceptNativeTCP(ctx context.Context) {
	connCount := s.nativeTCPConnCount()
	if connCount > 1 {
		conns, err := acceptExternalNativeTCPConns(ctx, s.nativeTCPListener, s.nativeTCPAuth, connCount)
		emitExternalQUICModeTCPStripeCount(s.emitter, conns, err)
		s.nativeTCPConnCh <- externalQUICModeNativeTCPResult{conns: conns, err: err}
		return
	}
	conn, err := acceptExternalNativeTCP(ctx, s.nativeTCPListener, s.nativeTCPAuth)
	s.nativeTCPConnCh <- externalQUICModeNativeTCPResult{conns: externalQUICModeSingleTCPConn(conn), err: err}
}

func (s *externalQUICModeAcceptState) receiveAckAndFinish(ctx context.Context, ackCh <-chan derpbind.Packet) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	ack, ok := receiveExternalQUICModeAcceptAck(ctx, ackCh, s.auth)
	if !ok {
		s.cancelAndDrainNativeTCP()
		return false, nil, nil, s.resolvedPolicy, nil
	}
	if s.nativeTCPListener != nil && !ack.NativeTCP {
		return s.finishTCPAckRejected(ctx)
	}
	if s.nativeTCPListener == nil {
		return s.finishNativeQUICOnly(ctx)
	}
	result := <-s.nativeTCPConnCh
	if result.err != nil {
		return false, nil, nil, s.resolvedPolicy, result.err
	}
	return s.nativeQUIC, result.conns, cloneSessionAddr(s.nativeQUICPeerAddr), s.resolvedPolicy, nil
}

func receiveExternalQUICModeAcceptAck(ctx context.Context, ackCh <-chan derpbind.Packet, auth externalPeerControlAuth) (quicModeAck, bool) {
	ackCtx, ackCancel := context.WithTimeout(ctx, externalNativeQUICWait)
	defer ackCancel()
	ack, err := receiveQUICModeAck(ackCtx, ackCh, auth)
	if err != nil || (!ack.NativeDirect && !ack.NativeTCP) {
		return quicModeAck{}, false
	}
	return ack, true
}

func (s *externalQUICModeAcceptState) cancelAndDrainNativeTCP() {
	if s.nativeTCPCancel != nil {
		s.nativeTCPCancel()
	}
	if s.nativeTCPConnCh != nil {
		result := <-s.nativeTCPConnCh
		closeExternalNativeTCPConns(result.conns)
	}
}

func (s *externalQUICModeAcceptState) finishTCPAckRejected(ctx context.Context) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	s.emitDebug("listener-tcp-ack-rejected")
	s.cancelAndDrainNativeTCP()
	return s.finishNativeQUICOnly(ctx)
}

func (s *externalQUICModeAcceptState) finishNativeQUICOnly(ctx context.Context) (bool, []net.Conn, net.Addr, ParallelPolicy, error) {
	if !s.nativeQUIC {
		return false, nil, nil, s.resolvedPolicy, nil
	}
	if _, err := sendExternalQUICModeReady(ctx, s.client, s.peerDERP, s.manager, s.nativeQUICAddr, s.auth); err != nil {
		return false, nil, nil, s.resolvedPolicy, err
	}
	return s.nativeQUIC, nil, cloneSessionAddr(s.nativeQUICPeerAddr), s.resolvedPolicy, nil
}

func (s *externalQUICModeAcceptState) emitDebug(msg string) {
	if s.emitter != nil {
		s.emitter.Debug(msg)
	}
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
		if externalQUICModeGlobalCandidate(candidate) {
			return cloneSessionAddr(candidate)
		}
	}
	return nil
}

func externalQUICModeGlobalCandidate(candidate net.Addr) bool {
	udpAddr, ok := candidate.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return false
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() {
		return false
	}
	if publicProbeTailscaleCGNATPrefix.Contains(ip) || publicProbeTailscaleULAPrefix.Contains(ip) {
		return false
	}
	return ip.IsGlobalUnicast()
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
			ready, handled, err := decodeQUICModeReadyPacket(pkt, auth)
			if handled {
				continue
			}
			if err != nil {
				return quicModeReady{}, err
			}
			return ready, nil
		case <-retry.C:
			if err := retryQUICModeReadyAck(ctx, sendAck); err != nil {
				return quicModeReady{}, err
			}
		case <-ctx.Done():
			return quicModeReady{}, ctx.Err()
		}
	}
}

func decodeQUICModeReadyPacket(pkt derpbind.Packet, auth externalPeerControlAuth) (quicModeReady, bool, error) {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return quicModeReady{}, true, nil
	}
	if err != nil || env.Type != envelopeQUICModeReady || env.QUICModeReady == nil {
		return quicModeReady{}, false, errors.New("unexpected quic mode ready")
	}
	return *env.QUICModeReady, false, nil
}

func retryQUICModeReadyAck(ctx context.Context, sendAck func(context.Context) error) error {
	if sendAck == nil {
		return nil
	}
	return sendAck(ctx)
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
		if addr, ok := pollExternalDirectAddr(manager); ok {
			return addr, true, false
		}
		result := waitExternalDirectAddrEvent(ctx, modeAckCh, timer.C, ticker.C, auth)
		if result.done {
			return result.addr, result.ready, result.modeAbort
		}
	}
}

type externalDirectAddrWaitResult struct {
	addr      net.Addr
	ready     bool
	modeAbort bool
	done      bool
}

func pollExternalDirectAddr(manager *transport.Manager) (net.Addr, bool) {
	if addr, ok := manager.DirectAddr(); ok && addr != nil {
		externalTransferTracef("wait-direct-addr-ready path=%v addr=%v", manager.PathState(), addr)
		return cloneSessionAddr(addr), true
	}
	externalTransferTracef("wait-direct-addr-pending path=%v", manager.PathState())
	return nil, false
}

func waitExternalDirectAddrEvent(ctx context.Context, modeAckCh <-chan derpbind.Packet, timeout <-chan time.Time, tick <-chan time.Time, auth externalPeerControlAuth) externalDirectAddrWaitResult {
	select {
	case <-ctx.Done():
		externalTransferTracef("wait-direct-addr-context-done err=%v", ctx.Err())
		return externalDirectAddrWaitResult{done: true}
	case pkt, ok := <-modeAckCh:
		return handleExternalDirectModeAck(pkt, ok, auth)
	case <-timeout:
		externalTransferTracef("wait-direct-addr-timeout")
		return externalDirectAddrWaitResult{done: true}
	case <-tick:
		return externalDirectAddrWaitResult{}
	}
}

func handleExternalDirectModeAck(pkt derpbind.Packet, ok bool, auth externalPeerControlAuth) externalDirectAddrWaitResult {
	if !ok {
		externalTransferTracef("wait-direct-addr-mode-ack-closed")
		return externalDirectAddrWaitResult{modeAbort: true, done: true}
	}
	abort, ignored := externalDirectModeAckAborts(pkt, auth)
	if ignored {
		return externalDirectAddrWaitResult{}
	}
	if abort {
		externalTransferTracef("wait-direct-addr-mode-abort")
		return externalDirectAddrWaitResult{modeAbort: true, done: true}
	}
	return externalDirectAddrWaitResult{}
}

func externalDirectModeAckAborts(pkt derpbind.Packet, auth externalPeerControlAuth) (bool, bool) {
	ackEnv, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	return externalQUICModeAckAborts(ackEnv), false
}

func externalQUICModeAckAborts(ackEnv envelope) bool {
	if ackEnv.Type != envelopeQUICModeAck || ackEnv.QUICModeAck == nil {
		return false
	}
	return !ackEnv.QUICModeAck.NativeDirect && !ackEnv.QUICModeAck.NativeTCP
}

func sendPeerAck(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived int64, authOpt ...externalPeerControlAuth) error {
	auth := optionalPeerControlAuth(authOpt)
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{Type: envelopeAck, Ack: newPeerAck(bytesReceived)}, auth)
}

func sendPeerProgress(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesReceived, transferElapsedMS int64, sequence uint64, auth externalPeerControlAuth) error {
	if client == nil || peerDERP.IsZero() {
		return nil
	}
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(bytesReceived, transferElapsedMS, sequence),
	}, auth)
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
	stopCh, stop := newPeerControlStop(cancel)
	currentBytes := peerControlBytesFunc(bytesTransferred)
	if abortCh != nil {
		go watchPeerControlAbort(ctx, cancel, stopCh, abortCh, auth)
	}
	if heartbeatCh != nil {
		go watchPeerControlHeartbeats(ctx, cancel, stopCh, heartbeatCh, auth)
	}
	if client != nil && !peerDERP.IsZero() {
		go sendPeerControlHeartbeats(ctx, stopCh, client, peerDERP, currentBytes, auth)
	}

	return ctx, stop
}

func newPeerControlStop(cancel context.CancelCauseFunc) (<-chan struct{}, context.CancelFunc) {
	var stopOnce sync.Once
	stopCh := make(chan struct{})
	stop := func() {
		stopOnce.Do(func() {
			close(stopCh)
			cancel(context.Canceled)
		})
	}
	return stopCh, stop
}

func peerControlBytesFunc(bytesTransferred func() int64) func() int64 {
	return func() int64 {
		if bytesTransferred == nil {
			return 0
		}
		return bytesTransferred()
	}
}

func watchPeerControlAbort(ctx context.Context, cancel context.CancelCauseFunc, stopCh <-chan struct{}, abortCh <-chan derpbind.Packet, auth externalPeerControlAuth) {
	for {
		select {
		case pkt, ok := <-abortCh:
			if !ok {
				return
			}
			if peerControlAbortReceived(pkt, auth) {
				cancel(ErrPeerAborted)
				return
			}
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		}
	}
}

func watchPeerControlHeartbeats(ctx context.Context, cancel context.CancelCauseFunc, stopCh <-chan struct{}, heartbeatCh <-chan derpbind.Packet, auth externalPeerControlAuth) {
	timer, timerC := newPeerHeartbeatTimer(heartbeatCh)
	defer timer.Stop()
	var lastHeartbeatSequence uint64
	for {
		select {
		case pkt, ok := <-heartbeatCh:
			if !ok {
				return
			}
			if peerControlHeartbeatReceived(pkt, auth, &lastHeartbeatSequence) {
				resetPeerHeartbeatTimer(timer)
			}
		case <-timerC:
			cancel(ErrPeerDisconnected)
			return
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		}
	}
}

func newPeerHeartbeatTimer(heartbeatCh <-chan derpbind.Packet) (*time.Timer, <-chan time.Time) {
	if heartbeatCh == nil {
		return nil, nil
	}
	timer := time.NewTimer(peerHeartbeatTimeoutOrDefault())
	return timer, timer.C
}

func peerHeartbeatTimeoutOrDefault() time.Duration {
	if peerHeartbeatTimeout <= 0 {
		return 30 * time.Second
	}
	return peerHeartbeatTimeout
}

func resetPeerHeartbeatTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(peerHeartbeatTimeoutOrDefault())
}

func peerControlAbortReceived(pkt derpbind.Packet, auth externalPeerControlAuth) bool {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return false
	}
	return err == nil && env.Type == envelopeAbort
}

func peerControlHeartbeatReceived(pkt derpbind.Packet, auth externalPeerControlAuth, lastHeartbeatSequence *uint64) bool {
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeHeartbeat {
		return false
	}
	return verifyPeerHeartbeat(env.Heartbeat, auth, lastHeartbeatSequence)
}

func sendPeerControlHeartbeats(ctx context.Context, stopCh <-chan struct{}, client *derpbind.Client, peerDERP key.NodePublic, currentBytes func() int64, auth externalPeerControlAuth) {
	ticker := time.NewTicker(peerHeartbeatIntervalOrDefault())
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
}

func peerHeartbeatIntervalOrDefault() time.Duration {
	if peerHeartbeatInterval <= 0 {
		return 2 * time.Second
	}
	return peerHeartbeatInterval
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
	if !peerAbortErrorShouldNotify(*errp) {
		return
	}
	var bytes int64
	if bytesTransferred != nil {
		bytes = bytesTransferred()
	}
	sendPeerAbortBestEffort(client, peerDERP, peerAbortReason(*errp), bytes, optionalPeerControlAuth(authOpt))
}

func notifyPeerAbortOnLocalCancel(errp *error, ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, bytesTransferred func() int64, authOpt ...externalPeerControlAuth) {
	if errp == nil {
		return
	}
	err := normalizePeerAbortError(ctx, *errp)
	if !errors.Is(err, context.Canceled) {
		return
	}
	var bytes int64
	if bytesTransferred != nil {
		bytes = bytesTransferred()
	}
	sendPeerAbortBestEffort(client, peerDERP, peerAbortReason(err), bytes, optionalPeerControlAuth(authOpt))
}

func peerAbortErrorShouldNotify(err error) bool {
	return err != nil &&
		!errors.Is(err, ErrPeerAborted) &&
		!errors.Is(err, ErrPeerDisconnected) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
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
			handled, err := verifyPeerAckPacket(pkt, auth, bytesSent)
			if handled {
				continue
			}
			if err != nil {
				return err
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func verifyPeerAckPacket(pkt derpbind.Packet, auth externalPeerControlAuth, bytesSent int64) (bool, error) {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return true, nil
	}
	if err == nil && env.Type == envelopeAbort {
		return false, ErrPeerAborted
	}
	if err != nil || env.Type != envelopeAck {
		return false, errors.New("unexpected peer ack payload")
	}
	if env.Ack == nil || env.Ack.BytesReceived == nil {
		return false, errors.New("peer ack missing bytes_received")
	}
	if *env.Ack.BytesReceived != bytesSent {
		return false, fmt.Errorf("peer received %d bytes, sent %d", *env.Ack.BytesReceived, bytesSent)
	}
	return false, nil
}

func verifyPeerProgressPacket(pkt derpbind.Packet, auth externalPeerControlAuth, lastSequence *uint64) (peerProgress, bool, error) {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) {
		return peerProgress{}, true, nil
	}
	if err == nil && env.Type == envelopeAbort {
		return peerProgress{}, false, ErrPeerAborted
	}
	if err != nil || env.Type != envelopeProgress {
		return peerProgress{}, false, errors.New("unexpected peer progress payload")
	}
	if env.Progress == nil {
		return peerProgress{}, false, errors.New("peer progress missing progress body")
	}
	if peerProgressReplayed(env.Progress, lastSequence) {
		return peerProgress{}, true, nil
	}
	return *env.Progress, false, nil
}

func peerProgressReplayed(progress *peerProgress, lastSequence *uint64) bool {
	if progress == nil || lastSequence == nil {
		return false
	}
	if progress.Sequence <= *lastSequence {
		return true
	}
	*lastSequence = progress.Sequence
	return false
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
	authOpt ...externalPeerControlAuth,
) (rendezvous.Decision, error) {
	return sendClaimAndReceiveDecisionWithTelemetry(ctx, client, dst, claim, nil, "", authOpt...)
}

func sendClaimAndReceiveDecisionWithTelemetry(
	ctx context.Context,
	client *derpbind.Client,
	dst key.NodePublic,
	claim rendezvous.Claim,
	emitter *telemetry.Emitter,
	prefix string,
	authOpt ...externalPeerControlAuth,
) (rendezvous.Decision, error) {
	auth := optionalPeerControlAuth(authOpt)
	decisionCh, unsubscribe := client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == dst && isDecisionOrAbortPayload(pkt.Payload)
	})
	defer unsubscribe()

	attempt := 1
	if err := sendClaimAttempt(ctx, client, dst, claim, auth, emitter, prefix, attempt, "send claim"); err != nil {
		return rendezvous.Decision{}, err
	}

	retry := time.NewTicker(externalClaimRetryInterval)
	defer retry.Stop()

	for {
		select {
		case pkt, ok := <-decisionCh:
			if !ok {
				return rendezvous.Decision{}, net.ErrClosed
			}
			decision, done, err := handleClaimDecisionPacket(pkt, auth, emitter, prefix)
			if !done {
				continue
			}
			return decision, err
		case <-retry.C:
			attempt++
			if err := sendClaimAttempt(ctx, client, dst, claim, auth, emitter, prefix, attempt, "resend claim"); err != nil {
				return rendezvous.Decision{}, err
			}
		case <-ctx.Done():
			return rendezvous.Decision{}, ctx.Err()
		}
	}
}

func handleClaimDecisionPacket(pkt derpbind.Packet, auth externalPeerControlAuth, emitter *telemetry.Emitter, prefix string) (rendezvous.Decision, bool, error) {
	decision, handled, err := decodeClaimDecisionPacket(pkt, auth, emitter, prefix)
	if err != nil {
		return rendezvous.Decision{}, true, err
	}
	if !handled {
		return rendezvous.Decision{}, false, nil
	}
	return decision, true, nil
}

func sendClaimAttempt(ctx context.Context, client *derpbind.Client, dst key.NodePublic, claim rendezvous.Claim, auth externalPeerControlAuth, emitter *telemetry.Emitter, prefix string, attempt int, errPrefix string) error {
	if emitter != nil {
		emitter.Debug(prefix + "claim-send-attempt=" + strconv.Itoa(attempt))
	}
	if err := sendAuthenticatedEnvelope(ctx, client, dst, envelope{Type: envelopeClaim, Claim: &claim}, auth); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	if emitter != nil {
		emitter.Debug(prefix + "claim-send-complete=" + strconv.Itoa(attempt))
	}
	return nil
}

func decodeClaimDecisionPacket(pkt derpbind.Packet, auth externalPeerControlAuth, emitter *telemetry.Emitter, prefix string) (rendezvous.Decision, bool, error) {
	env, err := decodeAuthenticatedEnvelope(pkt.Payload, auth)
	if ignoreAuthenticatedEnvelopeError(err, auth) || err != nil {
		return rendezvous.Decision{}, false, nil
	}
	if env.Type == envelopeAbort {
		return rendezvous.Decision{}, false, ErrPeerAborted
	}
	if env.Type != envelopeDecision || env.Decision == nil {
		return rendezvous.Decision{}, false, nil
	}
	if emitter != nil {
		emitter.Debug(prefix + "decision-received")
	}
	return *env.Decision, true, nil
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
	addPublicProbeCandidateStrings(seen, candidates)

	if dm != nil {
		gathered := gatherPublicProbeCandidates(ctx, conn, dm, pm, stunPackets)
		addAllowedPublicProbeCandidates(seen, gathered)
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

func addPublicProbeCandidateStrings(seen map[string]struct{}, candidates []string) {
	for _, candidate := range candidates {
		seen[candidate] = struct{}{}
	}
}

func gatherPublicProbeCandidates(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, pm publicPortmap, stunPackets <-chan traversal.STUNPacket) []string {
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
	if err != nil {
		return nil
	}
	return gathered
}

func addAllowedPublicProbeCandidates(seen map[string]struct{}, candidates []string) {
	for _, candidate := range candidates {
		addrPort, err := netip.ParseAddrPort(candidate)
		if err != nil || !publicProbeCandidateAllowed(addrPort.Addr()) {
			continue
		}
		seen[addrPort.String()] = struct{}{}
	}
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
	addPublicInterfaceProbeCandidates(seen, port)
	addPublicMappedProbeCandidate(seen, pm)
	return sortedPublicProbeCandidates(seen)
}

func addPublicProbeCandidate(seen map[string]struct{}, ip netip.Addr, port int) {
	if !publicProbeCandidateAllowed(ip) {
		return
	}
	candidate := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	seen[candidate] = struct{}{}
}

func addPublicInterfaceProbeCandidates(seen map[string]struct{}, port int) {
	addrs, _ := publicInterfaceAddrs()
	for _, addr := range addrs {
		ip, ok := publicInterfaceProbeIP(addr)
		if !ok {
			continue
		}
		addPublicProbeCandidate(seen, ip, port)
	}
}

func publicInterfaceProbeIP(addr net.Addr) (netip.Addr, bool) {
	prefix, err := netip.ParsePrefix(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip := prefix.Addr()
	// Preserve private and link-local interface candidates so same-LAN peers
	// can still converge on their best direct path. Loopback remains
	// fake-transport-only so direct-upgrade tests still model the real
	// transport state machine without exposing loopback in production.
	if !ip.IsValid() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	if ip.IsLoopback() && !fakeTransportEnabled() {
		return netip.Addr{}, false
	}
	return ip, true
}

func addPublicMappedProbeCandidate(seen map[string]struct{}, pm publicPortmap) {
	if pm != nil {
		if mapped, ok := pm.Snapshot(); ok && mapped.IsValid() {
			addPublicProbeCandidate(seen, mapped.Addr(), int(mapped.Port()))
		}
	}
}

func sortedPublicProbeCandidates(seen map[string]struct{}) []string {
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

func externalRelayOnlyRequested(parallel int, candidates []string) bool {
	return parallel == 0 && len(candidates) == 0
}

func externalClaimRelayOnly(claim rendezvous.Claim) bool {
	return externalRelayOnlyRequested(claim.Parallel, claim.Candidates)
}

func externalDecisionRelayOnly(decision rendezvous.Decision) bool {
	return decision.Accept != nil && externalRelayOnlyRequested(decision.Accept.Parallel, decision.Accept.Candidates)
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

func isProgressPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeProgress
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
	if isTransportControlPayload(payload) || externalRelayPrefixDERPFrameKindOf(payload) != 0 {
		return false
	}
	for _, isControlPayload := range transportDataPayloadExclusions {
		if isControlPayload(payload) {
			return false
		}
	}
	return true
}

var transportDataPayloadExclusions = []func([]byte) bool{
	isAckPayload,
	isProgressPayload,
	isAbortPayload,
	isHeartbeatPayload,
	isDirectUDPReadyPayload,
	isDirectUDPReadyAckPayload,
	isDirectUDPStartPayload,
	isDirectUDPStartAckPayload,
	isDirectUDPRateProbePayload,
	isClaimPayload,
	isDecisionPayload,
	isQUICModeRequestPayload,
	isQUICModeResponsePayload,
	isQUICModeAckPayload,
	isQUICModeReadyPayload,
	isParallelGrowRequestPayload,
	isParallelGrowAckPayload,
	isParallelGrowResultPayload,
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
