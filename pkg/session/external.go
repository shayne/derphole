// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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
	"tailscale.com/net/batching"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	envelopeClaim            = "claim"
	envelopeDecision         = "decision"
	envelopeControl          = "control"
	envelopeProgress         = "progress"
	envelopeAbort            = "abort"
	envelopeV2Claim          = "v2_claim"
	envelopeV2Accept         = "v2_accept"
	envelopeV2Complete       = "v2_complete"
	envelopeV2DataPlaneReady = "v2_data_plane_ready"
	maxEnvelopeBytes         = 16 << 10
)
const externalCopyBufferSize = 256 << 10
const externalPublicCandidateRefreshWait = 750 * time.Millisecond
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
var sendExternalViaV2Fn = sendExternalViaV2
var listenExternalViaV2Fn = listenExternalViaV2
var offerExternalViaV2Fn = offerExternalViaV2
var receiveExternalOfferViaV2Fn = receiveExternalOfferViaV2

type publicPortmap interface {
	transport.Portmap
	SetLocalPort(uint16)
	Snapshot() (netip.AddrPort, bool)
	Close() error
}

type envelope struct {
	Type             string                    `json:"type"`
	MAC              string                    `json:"mac,omitempty"`
	Claim            *rendezvous.Claim         `json:"claim,omitempty"`
	Decision         *rendezvous.Decision      `json:"decision,omitempty"`
	Control          *transport.ControlMessage `json:"control,omitempty"`
	Progress         *peerProgress             `json:"progress,omitempty"`
	Abort            *peerAbort                `json:"abort,omitempty"`
	V2Claim          *externalV2Claim          `json:"v2_claim,omitempty"`
	V2Accept         *externalV2Accept         `json:"v2_accept,omitempty"`
	V2Complete       *externalV2Complete       `json:"v2_complete,omitempty"`
	V2DataPlaneReady *externalV2DataPlaneReady `json:"v2_data_plane_ready,omitempty"`
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
	return sendExternalViaV2Fn(ctx, cfg)
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	return listenExternalViaV2Fn(ctx, cfg)
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
	_ = tuneExternalPacketConn(conn)
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
	if progress.Sequence == 0 {
		return false
	}
	if progress.Sequence <= *lastSequence {
		return true
	}
	*lastSequence = progress.Sequence
	return false
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

func externalParallelQUICConnCount(policy ParallelPolicy) int {
	policy = policy.normalized()
	return policy.Initial
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
	if publicProbeTailscaleCandidatesDisabled() {
		return false
	}
	return true
}

func publicProbeTailscaleCandidatesDisabled() bool {
	return os.Getenv("DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES") == "1"
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

func isProgressPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeProgress
}

func isAbortPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeAbort
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
	if isTransportControlPayload(payload) {
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
	isProgressPayload,
	isAbortPayload,
	isV2ClaimPayload,
	isV2AcceptPayload,
	isV2CompletePayload,
	isClaimPayload,
	isDecisionPayload,
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
