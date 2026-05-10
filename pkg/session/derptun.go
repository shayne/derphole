// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/stream"
	"github.com/shayne/derphole/pkg/telemetry"
	sessiontoken "github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type DerptunServeConfig struct {
	ServerToken   string
	TargetAddr    string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunOpenConfig struct {
	ClientToken   string
	ListenAddr    string
	BindAddrSink  chan<- string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunConnectConfig struct {
	ClientToken   string
	StdioIn       io.Reader
	StdioOut      io.Writer
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

func decodeDerptunServer(raw string) (derptun.ServerCredential, error) {
	return derptun.DecodeServerToken(raw, time.Now())
}

func decodeDerptunClient(raw string) (derptun.ClientCredential, error) {
	return derptun.DecodeClientToken(raw, time.Now())
}

func derptunQUICConfig() *quic.Config {
	cfg := quicpath.DefaultQUICConfig()
	cfg.KeepAlivePeriod = 2 * time.Second
	cfg.MaxIdleTimeout = 10 * time.Second
	return cfg
}

var (
	derptunActiveProbeTimeout = 2 * time.Second
	derptunActiveStopTimeout  = 500 * time.Millisecond
)

func DerptunServe(ctx context.Context, cfg DerptunServeConfig) error {
	runtime, err := newDerptunServeRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer runtime.close()

	emitStatus(cfg.Emitter, StateWaiting)
	gate := &derptunClientGate{}
	if err := serveDerptunClaims(ctx, cfg, runtime, gate); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
}

type derptunServeRuntime struct {
	server     derptun.ServerCredential
	identity   quicpath.SessionIdentity
	dm         *tailcfg.DERPMap
	derpClient *derpbind.Client
	probeConn  net.PacketConn
	pm         publicPortmap
}

func newDerptunServeRuntime(ctx context.Context, cfg DerptunServeConfig) (*derptunServeRuntime, error) {
	server, tok, identity, err := loadDerptunServeIdentity(cfg.ServerToken)
	if err != nil {
		return nil, err
	}
	dm, derpClient, err := openDerptunServeDERP(ctx, tok, server)
	if err != nil {
		return nil, err
	}
	probeConn, pm, err := openDerptunServeProbe(cfg.Emitter)
	if err != nil {
		_ = derpClient.Close()
		return nil, err
	}
	return &derptunServeRuntime{
		server:     server,
		identity:   identity,
		dm:         dm,
		derpClient: derpClient,
		probeConn:  probeConn,
		pm:         pm,
	}, nil
}

func loadDerptunServeIdentity(serverToken string) (derptun.ServerCredential, sessiontoken.Token, quicpath.SessionIdentity, error) {
	cred, err := decodeDerptunServer(serverToken)
	if err != nil {
		return derptun.ServerCredential{}, sessiontoken.Token{}, quicpath.SessionIdentity{}, err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return derptun.ServerCredential{}, sessiontoken.Token{}, quicpath.SessionIdentity{}, err
	}
	quicPriv, err := cred.QUICPrivateKey()
	if err != nil {
		return derptun.ServerCredential{}, sessiontoken.Token{}, quicpath.SessionIdentity{}, err
	}
	identity, err := quicpath.SessionIdentityFromEd25519PrivateKey(quicPriv, time.Now())
	if err != nil {
		return derptun.ServerCredential{}, sessiontoken.Token{}, quicpath.SessionIdentity{}, err
	}
	return cred, tok, identity, nil
}

func openDerptunServeDERP(ctx context.Context, tok sessiontoken.Token, cred derptun.ServerCredential) (*tailcfg.DERPMap, *derpbind.Client, error) {
	derpPriv, err := cred.DERPKey()
	if err != nil {
		return nil, nil, err
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, nil, err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return nil, nil, errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClientWithPrivateKey(ctx, node, publicDERPServerURL(node), derpPriv)
	if err != nil {
		return nil, nil, err
	}
	return dm, derpClient, nil
}

func openDerptunServeProbe(emitter *telemetry.Emitter) (net.PacketConn, publicPortmap, error) {
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, nil, err
	}
	pm := newBoundPublicPortmap(probeConn, emitter)
	return probeConn, pm, nil
}

func (r *derptunServeRuntime) close() {
	if r == nil {
		return
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

type derptunServeActive struct {
	claim    rendezvous.Claim
	decision rendezvous.Decision
	mux      *derptun.Mux
	quicDone <-chan struct{}
	cancel   context.CancelFunc
	done     chan error
}

func (a *derptunServeActive) sameClaim(claim rendezvous.Claim) bool {
	if a == nil {
		return false
	}
	return a.claim.DERPPublic == claim.DERPPublic && a.claim.QUICPublic == claim.QUICPublic
}

func (a *derptunServeActive) stop(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.cancel()
	select {
	case err := <-a.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *derptunServeActive) probe(ctx context.Context, timeout time.Duration) error {
	if a == nil || a.mux == nil {
		return net.ErrClosed
	}
	return a.mux.Ping(ctx, timeout)
}

func (a *derptunServeActive) transportDone() bool {
	if a == nil || a.quicDone == nil {
		return false
	}
	select {
	case <-a.quicDone:
		return true
	default:
		return false
	}
}

func (a *derptunServeActive) lastPeerActivity() time.Time {
	if a != nil && a.mux != nil {
		return a.mux.LastPeerActivity()
	}
	return time.Time{}
}

func recoverStaleDerptunActive(ctx context.Context, emitter *telemetry.Emitter, gate *derptunClientGate, active *derptunServeActive, probeTimeout, stopTimeout time.Duration) (bool, error) {
	if active == nil {
		return false, nil
	}
	if releaseDoneDerptunActive(emitter, gate, active, stopTimeout) {
		return true, nil
	}
	emitDerptunActiveStats(emitter, active)
	return probeDerptunActive(ctx, emitter, gate, active, probeTimeout, stopTimeout)
}

func releaseDoneDerptunActive(emitter *telemetry.Emitter, gate *derptunClientGate, active *derptunServeActive, stopTimeout time.Duration) bool {
	if !active.transportDone() {
		return false
	}
	if emitter != nil {
		emitter.Debug("derptun-active-probe=transport-done")
	}
	releaseDerptunActive(emitter, gate, active, stopTimeout)
	return true
}

func emitDerptunActiveStats(emitter *telemetry.Emitter, active *derptunServeActive) {
	if emitter == nil || active == nil || active.mux == nil {
		return
	}
	lastPeerActivity := active.lastPeerActivity()
	if lastPeerActivity.IsZero() {
		return
	}
	emitter.Debug("derptun-active-last-peer-ms=" + strconv.FormatInt(time.Since(lastPeerActivity).Milliseconds(), 10))
	emitter.Debug("derptun-active-streams=" + strconv.Itoa(active.mux.ActiveStreamCount()))
}

func probeDerptunActive(ctx context.Context, emitter *telemetry.Emitter, gate *derptunClientGate, active *derptunServeActive, probeTimeout, stopTimeout time.Duration) (bool, error) {
	probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
	probeErr := active.probe(probeCtx, probeTimeout)
	probeCancel()
	if probeErr == nil {
		if emitter != nil {
			emitter.Debug("derptun-active-probe=alive")
		}
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if emitter != nil {
		emitter.Debug("derptun-active-probe=stale err=" + probeErr.Error())
	}

	releaseDerptunActive(emitter, gate, active, stopTimeout)
	return true, nil
}

func releaseDerptunActive(emitter *telemetry.Emitter, gate *derptunClientGate, active *derptunServeActive, stopTimeout time.Duration) {
	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopTimeout)
	stopErr := active.stop(stopCtx)
	stopCancel()
	gate.Release(active.claim.DERPPublic)
	if stopErr != nil && emitter != nil {
		emitter.Debug("derptun-active-stop=" + stopErr.Error())
	}
}

func startDerptunDecisionResender(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, decision rendezvous.Decision, auth externalPeerControlAuth, emitter *telemetry.Emitter) context.CancelFunc {
	resendCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(externalClaimRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCtx, sendCancel := context.WithTimeout(resendCtx, externalClaimRetryInterval)
				err := sendAuthenticatedEnvelope(sendCtx, client, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth)
				sendCancel()
				if err != nil && resendCtx.Err() == nil && emitter != nil {
					emitter.Debug("derptun-decision-resend=" + err.Error())
				}
			case <-resendCtx.Done():
				return
			}
		}
	}()
	return cancel
}

func derptunServerTokenForClaim(server derptun.ServerCredential, claim rendezvous.Claim, now time.Time) (sessiontoken.Token, rendezvous.Decision, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() >= server.ExpiresUnix {
		return sessiontoken.Token{}, rendezvous.Decision{Accepted: false, Reject: &rendezvous.RejectInfo{Code: rendezvous.RejectExpired, Reason: "server token expired"}}, derptun.ErrExpired
	}
	if claim.Client == nil {
		return sessiontoken.Token{}, rendezvous.Decision{Accepted: false, Reject: &rendezvous.RejectInfo{Code: rendezvous.RejectClaimMalformed, Reason: "client proof missing"}}, rendezvous.ErrDenied
	}
	client := derptun.ClientCredential{
		Version:     derptun.TokenVersion,
		SessionID:   claim.SessionID,
		ClientID:    claim.Client.ClientID,
		TokenID:     claim.Client.TokenID,
		ClientName:  claim.Client.ClientName,
		ExpiresUnix: claim.Client.ExpiresUnix,
		ProofMAC:    claim.Client.ProofMAC,
	}
	if client.ExpiresUnix > server.ExpiresUnix {
		return sessiontoken.Token{}, rendezvous.Decision{Accepted: false, Reject: &rendezvous.RejectInfo{Code: rendezvous.RejectExpired, Reason: "client expiry exceeds server expiry"}}, derptun.ErrExpired
	}
	serverTok, err := server.SessionToken()
	if err != nil {
		return sessiontoken.Token{}, rendezvous.Decision{}, err
	}
	client.DERPPublic = serverTok.DERPPublic
	client.QUICPublic = serverTok.QUICPublic
	client.BearerSecret = derptun.DeriveClientBearerSecretForClaim(server.SigningSecret, client.ClientID)
	if err := derptun.VerifyClientCredential(server.SigningSecret, client, now); err != nil {
		reason := "client proof invalid"
		code := rendezvous.RejectBadMAC
		if errors.Is(err, derptun.ErrExpired) {
			reason = "client token expired"
			code = rendezvous.RejectExpired
		}
		return sessiontoken.Token{}, rendezvous.Decision{Accepted: false, Reject: &rendezvous.RejectInfo{Code: code, Reason: reason}}, err
	}
	serverTok.BearerSecret = client.BearerSecret
	serverTok.ExpiresUnix = client.ExpiresUnix
	return serverTok, rendezvous.Decision{}, nil
}

func derptunClaimEnvelopeAuth(server derptun.ServerCredential, claim rendezvous.Claim) (externalPeerControlAuth, bool) {
	if claim.Client == nil {
		return externalPeerControlAuth{}, false
	}
	serverTok, err := server.SessionToken()
	if err != nil {
		return externalPeerControlAuth{}, false
	}
	serverTok.BearerSecret = derptun.DeriveClientBearerSecretForClaim(server.SigningSecret, claim.Client.ClientID)
	serverTok.ExpiresUnix = claim.Client.ExpiresUnix
	return externalPeerControlAuthForToken(serverTok), true
}

func derptunClaimSourceMatches(from key.NodePublic, claim rendezvous.Claim) bool {
	return from == key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
}

type derptunClientGate struct {
	active *rendezvous.Claim
}

func (g *derptunClientGate) Accept(now time.Time, tok sessiontoken.Token, claim rendezvous.Claim) (rendezvous.Decision, error) {
	// V1 intentionally allows one active client. Multi-client support should replace
	// this single active claim with a map keyed by client ID and independent tunnel state.
	if g.active != nil {
		if sameDerptunConnector(*g.active, claim) {
			return rendezvous.NewGate(tok).Accept(now, claim)
		}
		return rendezvous.Decision{Accepted: false, Reject: &rendezvous.RejectInfo{Code: rendezvous.RejectClaimed, Reason: "session already claimed"}}, rendezvous.ErrClaimed
	}
	decision, err := rendezvous.NewGate(tok).Accept(now, claim)
	if err != nil {
		return decision, err
	}
	stored := claim
	stored.Candidates = append([]string(nil), claim.Candidates...)
	g.active = &stored
	return decision, nil
}

func (g *derptunClientGate) Release(derpPublic [32]byte) {
	if g.active == nil || g.active.DERPPublic != derpPublic {
		return
	}
	g.active = nil
}

func sameDerptunConnector(a, b rendezvous.Claim) bool {
	return a.DERPPublic == b.DERPPublic && a.QUICPublic == b.QUICPublic
}

func derptunServeTunnelErr(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func serveDerptunClaims(
	ctx context.Context,
	cfg DerptunServeConfig,
	runtime *derptunServeRuntime,
	gate *derptunClientGate,
) error {
	claimCh, unsubscribeClaims := runtime.derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	server := &derptunClaimServer{cfg: cfg, runtime: runtime, gate: gate}
	defer func() { _ = server.closeActive(context.Background()) }()

	for {
		if err := server.step(ctx, claimCh); err != nil {
			return err
		}
	}
}

type derptunClaimServer struct {
	cfg     DerptunServeConfig
	runtime *derptunServeRuntime
	gate    *derptunClientGate
	active  *derptunServeActive
}

func (s *derptunClaimServer) step(ctx context.Context, claimCh <-chan derpbind.Packet) error {
	select {
	case err := <-s.activeDone():
		return s.handleActiveDone(ctx, err)
	case pkt, ok := <-claimCh:
		return s.handleClaimPacket(ctx, pkt, ok)
	case <-ctx.Done():
		return s.handleContextDone(ctx)
	}
}

func (s *derptunClaimServer) activeDone() <-chan error {
	if s.active == nil {
		return nil
	}
	return s.active.done
}

func (s *derptunClaimServer) handleActiveDone(ctx context.Context, err error) error {
	s.gate.Release(s.active.claim.DERPPublic)
	s.active = nil
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return derptunServeTunnelErr(err)
}

func (s *derptunClaimServer) handleClaimPacket(ctx context.Context, pkt derpbind.Packet, ok bool) error {
	if !ok {
		return net.ErrClosed
	}
	nextActive, err := handleDerptunServeRuntimeClaim(ctx, s.cfg, s.runtime, s.gate, s.active, pkt)
	if err != nil {
		return err
	}
	s.active = nextActive
	return nil
}

func (s *derptunClaimServer) handleContextDone(ctx context.Context) error {
	if err := s.closeActive(context.Background()); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *derptunClaimServer) closeActive(ctx context.Context) error {
	if s.active == nil {
		return nil
	}
	err := s.active.stop(ctx)
	s.gate.Release(s.active.claim.DERPPublic)
	s.active = nil
	return derptunServeTunnelErr(err)
}

func handleDerptunServeClaim(
	ctx context.Context,
	cfg DerptunServeConfig,
	server derptun.ServerCredential,
	identity quicpath.SessionIdentity,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	probeConn net.PacketConn,
	pm publicPortmap,
	gate *derptunClientGate,
	active *derptunServeActive,
	pkt derpbind.Packet,
) (*derptunServeActive, error) {
	runtime := &derptunServeRuntime{
		server:     server,
		identity:   identity,
		dm:         dm,
		derpClient: derpClient,
		probeConn:  probeConn,
		pm:         pm,
	}
	return handleDerptunServeRuntimeClaim(ctx, cfg, runtime, gate, active, pkt)
}

func handleDerptunServeRuntimeClaim(
	ctx context.Context,
	cfg DerptunServeConfig,
	runtime *derptunServeRuntime,
	gate *derptunClientGate,
	active *derptunServeActive,
	pkt derpbind.Packet,
) (*derptunServeActive, error) {
	request, ok := readDerptunServeClaim(cfg, runtime, pkt)
	if !ok {
		return active, nil
	}
	issued, handled, err := issueDerptunServeClaimToken(ctx, runtime, request)
	if handled || err != nil {
		return active, err
	}
	decision, nextActive, accepted, err := acceptDerptunServeClaim(ctx, cfg, gate, active, request.claim, issued)
	if err != nil {
		return active, err
	}
	if !accepted {
		return nextActive, sendDerptunServeDecisionWithAuth(ctx, runtime, request.peerDERP, issued.auth, decision)
	}
	if sent, err := resendDerptunActiveDecision(ctx, runtime, nextActive, request, issued.auth, decision); sent || err != nil {
		return nextActive, err
	}
	enrichDerptunServeDecision(ctx, cfg, runtime, &decision)
	return startDerptunServeClaimTunnel(ctx, cfg, runtime, gate, request, issued, decision)
}

type derptunServeClaimRequest struct {
	claim    rendezvous.Claim
	peerDERP key.NodePublic
	auth     externalPeerControlAuth
}

type derptunServeClaimToken struct {
	token sessiontoken.Token
	auth  externalPeerControlAuth
	now   time.Time
}

func readDerptunServeClaim(cfg DerptunServeConfig, runtime *derptunServeRuntime, pkt derpbind.Packet) (derptunServeClaimRequest, bool) {
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeClaim || env.Claim == nil {
		return derptunServeClaimRequest{}, false
	}
	claim := *env.Claim
	if !derptunClaimSourceMatches(pkt.From, claim) {
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("derptun-claim-source-mismatch")
		}
		return derptunServeClaimRequest{}, false
	}
	peerDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
	auth, haveAuth := derptunClaimEnvelopeAuth(runtime.server, claim)
	if !haveAuth || !verifyEnvelopeMAC(env, auth) {
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("derptun-claim-envelope-unauthenticated")
		}
		return derptunServeClaimRequest{}, false
	}
	return derptunServeClaimRequest{claim: claim, peerDERP: peerDERP, auth: auth}, true
}

func issueDerptunServeClaimToken(ctx context.Context, runtime *derptunServeRuntime, request derptunServeClaimRequest) (derptunServeClaimToken, bool, error) {
	now := time.Now()
	claimToken, rejectDecision, err := derptunServerTokenForClaim(runtime.server, request.claim, now)
	if err == nil {
		return derptunServeClaimToken{token: claimToken, auth: externalPeerControlAuthForToken(claimToken), now: now}, false, nil
	}
	if rejectDecision.Reject == nil {
		return derptunServeClaimToken{}, false, err
	}
	sendErr := sendDerptunServeDecisionWithAuth(ctx, runtime, request.peerDERP, request.auth, rejectDecision)
	return derptunServeClaimToken{}, true, sendErr
}

func acceptDerptunServeClaim(
	ctx context.Context,
	cfg DerptunServeConfig,
	gate *derptunClientGate,
	active *derptunServeActive,
	claim rendezvous.Claim,
	issued derptunServeClaimToken,
) (rendezvous.Decision, *derptunServeActive, bool, error) {
	decision, _ := gate.Accept(issued.now, issued.token, claim)
	if !isDerptunClaimedByOther(decision, active, claim) {
		return decision, active, decision.Accepted, nil
	}
	recovered, err := recoverStaleDerptunActive(ctx, cfg.Emitter, gate, active, derptunActiveProbeTimeout, derptunActiveStopTimeout)
	if err != nil {
		return decision, active, false, err
	}
	if !recovered {
		return decision, active, false, nil
	}
	decision, _ = gate.Accept(time.Now(), issued.token, claim)
	return decision, nil, decision.Accepted, nil
}

func isDerptunClaimedByOther(decision rendezvous.Decision, active *derptunServeActive, claim rendezvous.Claim) bool {
	return decision.Reject != nil &&
		decision.Reject.Code == rendezvous.RejectClaimed &&
		active != nil &&
		!active.sameClaim(claim)
}

func sendDerptunServeDecisionWithAuth(ctx context.Context, runtime *derptunServeRuntime, peerDERP key.NodePublic, auth externalPeerControlAuth, decision rendezvous.Decision) error {
	return sendAuthenticatedEnvelope(ctx, runtime.derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}, auth)
}

func resendDerptunActiveDecision(ctx context.Context, runtime *derptunServeRuntime, active *derptunServeActive, request derptunServeClaimRequest, auth externalPeerControlAuth, decision rendezvous.Decision) (bool, error) {
	if active == nil || !active.sameClaim(request.claim) {
		return false, nil
	}
	retryDecision := active.decision
	if retryDecision.Accept == nil && retryDecision.Reject == nil {
		retryDecision = decision
	}
	return true, sendDerptunServeDecisionWithAuth(ctx, runtime, request.peerDERP, auth, retryDecision)
}

func enrichDerptunServeDecision(ctx context.Context, cfg DerptunServeConfig, runtime *derptunServeRuntime, decision *rendezvous.Decision) {
	if decision.Accept == nil || cfg.ForceRelay {
		return
	}
	decision.Accept.Candidates = publicProbeCandidates(ctx, runtime.probeConn, runtime.dm, runtime.pm)
}

func startDerptunServeClaimTunnel(
	ctx context.Context,
	cfg DerptunServeConfig,
	runtime *derptunServeRuntime,
	gate *derptunClientGate,
	request derptunServeClaimRequest,
	issued derptunServeClaimToken,
	decision rendezvous.Decision,
) (*derptunServeActive, error) {
	claim := request.claim
	emitStatus(cfg.Emitter, StateClaimed)
	transportCtx, transportCancel, transportManager, transportCleanup, pathEmitter, err := startDerptunServeTransport(ctx, cfg, runtime, request.peerDERP, issued.token, decision, claim)
	if err != nil {
		gate.Release(claim.DERPPublic)
		return nil, err
	}

	adapter, quicListener, err := listenDerptunServeQUIC(transportCtx, runtime, transportManager, claim)
	if err != nil {
		cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
		gate.Release(claim.DERPPublic)
		return nil, err
	}
	if err := sendDerptunServeDecisionWithAuth(ctx, runtime, request.peerDERP, issued.auth, decision); err != nil {
		cleanupDerptunServeListener(quicListener, adapter)
		cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
		gate.Release(claim.DERPPublic)
		return nil, err
	}

	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: 30 * time.Second})
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	transportDone := make(chan struct{})
	next := &derptunServeActive{claim: claim, decision: decision, mux: mux, quicDone: transportDone, cancel: tunnelCancel, done: make(chan error, 1)}
	cancelDecisionResends := startDerptunDecisionResender(ctx, runtime.derpClient, request.peerDERP, decision, issued.auth, cfg.Emitter)
	go runDerptunServeTunnel(cfg, next, tunnelCtx, tunnelCancel, cancelDecisionResends, quicListener, adapter, pathEmitter, transportManager, transportCleanup, transportCancel, transportDone)
	return next, nil
}

func startDerptunServeTransport(
	ctx context.Context,
	cfg DerptunServeConfig,
	runtime *derptunServeRuntime,
	peerDERP key.NodePublic,
	claimToken sessiontoken.Token,
	decision rendezvous.Decision,
	claim rendezvous.Claim,
) (context.Context, context.CancelFunc, *transport.Manager, func(), *transportPathEmitter, error) {
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		claimToken,
		runtime.probeConn,
		runtime.dm,
		runtime.derpClient,
		peerDERP,
		parseCandidateStrings(decision.Accept.Candidates),
		runtime.pm,
		cfg.ForceRelay,
	)
	if err != nil {
		transportCancel()
		return nil, nil, nil, nil, nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)
	return transportCtx, transportCancel, transportManager, transportCleanup, pathEmitter, nil
}

func listenDerptunServeQUIC(transportCtx context.Context, runtime *derptunServeRuntime, transportManager *transport.Manager, claim rendezvous.Claim) (*quicpath.Adapter, *quic.Listener, error) {
	adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
	quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(runtime.identity, claim.QUICPublic), derptunQUICConfig())
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return adapter, quicListener, nil
}

func cleanupDerptunServeListener(quicListener *quic.Listener, adapter *quicpath.Adapter) {
	if quicListener != nil {
		_ = quicListener.Close()
	}
	if adapter != nil {
		_ = adapter.Close()
	}
}

func cleanupDerptunServeTransport(pathEmitter *transportPathEmitter, transportManager *transport.Manager, transportCleanup func(), transportCancel context.CancelFunc) {
	if pathEmitter != nil && transportManager != nil {
		pathEmitter.Complete(transportManager)
	}
	if transportCleanup != nil {
		transportCleanup()
	}
	if transportCancel != nil {
		transportCancel()
	}
}

func runDerptunServeTunnel(
	cfg DerptunServeConfig,
	active *derptunServeActive,
	tunnelCtx context.Context,
	tunnelCancel context.CancelFunc,
	cancelDecisionResends context.CancelFunc,
	quicListener *quic.Listener,
	adapter *quicpath.Adapter,
	pathEmitter *transportPathEmitter,
	transportManager *transport.Manager,
	transportCleanup func(),
	transportCancel context.CancelFunc,
	transportDone chan<- struct{},
) {
	var quicConn *quic.Conn
	var err error
	defer func() {
		cancelDecisionResends()
		tunnelCancel()
		_ = active.mux.Close()
		if quicConn != nil {
			_ = quicConn.CloseWithError(0, "")
		}
		cleanupDerptunServeListener(quicListener, adapter)
		cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
		close(transportDone)
		active.done <- err
	}()

	quicConn, err = quicListener.Accept(tunnelCtx)
	if err != nil {
		return
	}
	watchDerptunServeQUICConn(tunnelCtx, tunnelCancel, quicConn)
	carrier, acceptErr := quicConn.AcceptStream(tunnelCtx)
	cancelDecisionResends()
	if acceptErr != nil {
		err = acceptErr
		_ = quicConn.CloseWithError(1, "accept derptun carrier failed")
		return
	}
	active.mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
	err = serveDerptunMuxTarget(tunnelCtx, active.mux, cfg.TargetAddr, cfg.Emitter)
}

func watchDerptunServeQUICConn(tunnelCtx context.Context, tunnelCancel context.CancelFunc, quicConn *quic.Conn) {
	go func() {
		select {
		case <-quicConn.Context().Done():
			tunnelCancel()
		case <-tunnelCtx.Done():
		}
	}()
}

func serveDerptunMuxTarget(ctx context.Context, mux *derptun.Mux, targetAddr string, emitter *telemetry.Emitter) error {
	slots := make(chan struct{}, 1)
	for {
		overlayConn, err := mux.Accept(ctx)
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			if emitter != nil {
				emitter.Debug("derptun-stream-limit-reached")
			}
			_ = overlayConn.Close()
			continue
		}
		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			if emitter != nil {
				emitter.Debug("derptun-backend-dial-failed")
			}
			<-slots
			_ = overlayConn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer func() { _ = overlayConn.Close() }()
			defer func() { _ = backendConn.Close() }()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
}

func DerptunOpen(ctx context.Context, cfg DerptunOpenConfig) error {
	mux, cleanup, err := dialDerptunMux(ctx, cfg.ClientToken, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = mux.Close() }()

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		return mux.OpenStream(ctx)
	}, cfg.Emitter)
}

func DerptunConnect(ctx context.Context, cfg DerptunConnectConfig) error {
	conn, cleanup, err := dialDerptunMuxStream(ctx, cfg.ClientToken, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = conn.Close() }()
	return bridgeDerptunStdio(ctx, conn, cfg.StdioIn, cfg.StdioOut)
}

func bridgeDerptunStdio(ctx context.Context, conn net.Conn, in io.Reader, out io.Writer) error {
	if in == nil {
		in = io.Reader(&emptyReader{})
	}
	if out == nil {
		out = io.Discard
	}
	inErr := make(chan error, 1)
	outErr := make(chan error, 1)
	go copyDerptunStdio(conn, in, inErr)
	go copyDerptunStdio(out, conn, outErr)

	for {
		select {
		case err := <-inErr:
			if err := handleDerptunStdioInputDone(conn, err, &inErr); err != nil {
				return err
			}
		case err := <-outErr:
			return handleDerptunStdioOutputDone(in, err)
		case <-ctx.Done():
			closeDerptunStdioInput(in)
			_ = conn.Close()
			return ctx.Err()
		}
	}
}

func copyDerptunStdio(dst io.Writer, src io.Reader, errCh chan<- error) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func handleDerptunStdioInputDone(conn net.Conn, err error, inErr *chan error) error {
	if err != nil && !errors.Is(err, io.EOF) {
		_ = conn.Close()
		return err
	}
	*inErr = nil
	return nil
}

func handleDerptunStdioOutputDone(in io.Reader, err error) error {
	closeDerptunStdioInput(in)
	if derptunStdioOutputErr(err) {
		return err
	}
	return nil
}

func derptunStdioOutputErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe)
}

func closeDerptunStdioInput(in io.Reader) {
	if closer, ok := in.(io.Closer); ok {
		_ = closer.Close()
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func dialDerptunMuxStream(ctx context.Context, clientToken string, emitter *telemetry.Emitter, forceRelay bool) (net.Conn, func(), error) {
	mux, cleanup, err := dialDerptunMux(ctx, clientToken, emitter, forceRelay)
	if err != nil {
		return nil, nil, err
	}
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		cleanup()
		_ = mux.Close()
		return nil, nil, err
	}
	return conn, func() {
		_ = mux.Close()
		cleanup()
	}, nil
}

func dialDerptunMux(ctx context.Context, clientToken string, emitter *telemetry.Emitter, forceRelay bool) (*derptun.Mux, func(), error) {
	runtime, err := newDerptunDialRuntime(ctx, clientToken, emitter, forceRelay)
	if err != nil {
		return nil, nil, err
	}
	claim := runtime.claim()
	decision, err := runtime.sendClaim(ctx, claim)
	if err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	if err := derptunClaimDecisionErr(decision); err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	mux, cleanup, err := runtime.dialMux(ctx, emitter, forceRelay, decision)
	if err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	return mux, cleanup, nil
}

type derptunDialRuntime struct {
	cred            derptun.ClientCredential
	tok             sessiontoken.Token
	listenerDERP    key.NodePublic
	dm              *tailcfg.DERPMap
	derpClient      *derpbind.Client
	probeConn       net.PacketConn
	pm              publicPortmap
	clientIdentity  quicpath.SessionIdentity
	localCandidates []string
}

func newDerptunDialRuntime(ctx context.Context, clientToken string, emitter *telemetry.Emitter, forceRelay bool) (*derptunDialRuntime, error) {
	cred, tok, listenerDERP, err := loadDerptunDialToken(clientToken)
	if err != nil {
		return nil, err
	}
	dm, derpClient, err := openDerptunDialDERP(ctx, tok)
	if err != nil {
		return nil, err
	}
	runtime := &derptunDialRuntime{cred: cred, tok: tok, listenerDERP: listenerDERP, dm: dm, derpClient: derpClient}
	if err := runtime.openProbe(ctx, emitter, forceRelay); err != nil {
		runtime.closeBase()
		return nil, err
	}
	return runtime, nil
}

func loadDerptunDialToken(clientToken string) (derptun.ClientCredential, sessiontoken.Token, key.NodePublic, error) {
	cred, err := decodeDerptunClient(clientToken)
	if err != nil {
		return derptun.ClientCredential{}, sessiontoken.Token{}, key.NodePublic{}, err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return derptun.ClientCredential{}, sessiontoken.Token{}, key.NodePublic{}, err
	}
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return derptun.ClientCredential{}, sessiontoken.Token{}, key.NodePublic{}, ErrUnknownSession
	}
	return cred, tok, listenerDERP, nil
}

func openDerptunDialDERP(ctx context.Context, tok sessiontoken.Token) (*tailcfg.DERPMap, *derpbind.Client, error) {
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

func (r *derptunDialRuntime) openProbe(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool) error {
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
	r.pm = newBoundPublicPortmap(probeConn, emitter)
	r.clientIdentity = clientIdentity
	if !forceRelay {
		r.localCandidates = publicProbeCandidates(ctx, probeConn, r.dm, r.pm)
	}
	return nil
}

func (r *derptunDialRuntime) closeBase() {
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

func (r *derptunDialRuntime) claim() rendezvous.Claim {
	claim := rendezvous.Claim{
		Version:      r.tok.Version,
		SessionID:    r.tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(r.derpClient.PublicKey()),
		QUICPublic:   r.clientIdentity.Public,
		Candidates:   r.localCandidates,
		Capabilities: r.tok.Capabilities,
		Client: &rendezvous.ClientProof{
			ClientID:    r.cred.ClientID,
			TokenID:     r.cred.TokenID,
			ClientName:  r.cred.ClientName,
			ExpiresUnix: r.cred.ExpiresUnix,
			ProofMAC:    r.cred.ProofMAC,
		},
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(r.tok.BearerSecret, claim)
	return claim
}

func (r *derptunDialRuntime) sendClaim(ctx context.Context, claim rendezvous.Claim) (rendezvous.Decision, error) {
	return sendClaimAndReceiveDecision(ctx, r.derpClient, r.listenerDERP, claim, externalPeerControlAuthForToken(r.tok))
}

func derptunClaimDecisionErr(decision rendezvous.Decision) error {
	if decision.Accepted {
		return nil
	}
	if decision.Reject != nil {
		return errors.New(decision.Reject.Reason)
	}
	return errors.New("claim rejected")
}

func (r *derptunDialRuntime) dialMux(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool, decision rendezvous.Decision) (*derptun.Mux, func(), error) {
	pathEmitter := newTransportPathEmitter(emitter)
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
		forceRelay,
	)
	if err != nil {
		transportCancel()
		return nil, nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	adapter, quicConn, carrier, err := r.openQUICCarrier(ctx, transportCtx, transportManager)
	if err != nil {
		transportCleanup()
		transportCancel()
		return nil, nil, err
	}
	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: 30 * time.Second})
	mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
	cleanup := func() {
		_ = quicConn.CloseWithError(0, "")
		_ = adapter.Close()
		pathEmitter.Complete(transportManager)
		transportCleanup()
		transportCancel()
		r.closeBase()
	}
	return mux, cleanup, nil
}

func (r *derptunDialRuntime) openQUICCarrier(ctx context.Context, transportCtx context.Context, transportManager *transport.Manager) (*quicpath.Adapter, *quic.Conn, *quic.Stream, error) {
	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(r.clientIdentity, r.tok.QUICPublic), derptunQUICConfig())
	if err != nil {
		_ = adapter.Close()
		return nil, nil, nil, err
	}
	carrier, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(1, "open derptun carrier failed")
		_ = adapter.Close()
		return nil, nil, nil, err
	}
	return adapter, quicConn, carrier, nil
}
