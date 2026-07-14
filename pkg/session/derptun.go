// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	sessiontoken "github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transport"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type DerptunServeConfig struct {
	ServerToken string
	TargetAddr  string
	Emitter     *telemetry.Emitter
	ForceRelay  bool
}

type DerptunOpenConfig struct {
	ClientToken  string
	ListenAddr   string
	BindAddrSink chan<- string
	Emitter      *telemetry.Emitter
	ForceRelay   bool
}

type DerptunConnectConfig struct {
	ClientToken string
	StdioIn     io.Reader
	StdioOut    io.Writer
	Emitter     *telemetry.Emitter
	ForceRelay  bool
}

type derptunServeSessionConfig struct {
	ServerToken string
	TargetAddr  string
	Emitter     *telemetry.Emitter
	ForceRelay  bool
	onMux       func(context.Context, *derptun.Mux) error
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

const (
	derptunNativeTCPStripeCount      = 12
	derptunNativeStreamHeaderSize    = 24
	derptunNativeStreamHeaderVersion = 1
	derptunNativeStreamHeaderMagic   = "DPTS"
)

var (
	derptunActiveProbeTimeout = 2 * time.Second
	derptunActiveStopTimeout  = 500 * time.Millisecond
)

func DerptunServe(ctx context.Context, cfg DerptunServeConfig) error {
	return serveDerptunSession(ctx, derptunServeSessionConfig{
		ServerToken: cfg.ServerToken,
		TargetAddr:  cfg.TargetAddr,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
	})
}

func serveDerptunSession(ctx context.Context, cfg derptunServeSessionConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
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

func (cfg derptunServeSessionConfig) validate() error {
	if cfg.onMux == nil && cfg.TargetAddr == "" {
		return errors.New("derptun target or app mux handler is required")
	}
	if cfg.onMux != nil && cfg.TargetAddr != "" {
		return errors.New("derptun target and app mux handler are mutually exclusive")
	}
	return nil
}

func (cfg derptunServeSessionConfig) nativeTCP() bool {
	return cfg.onMux == nil
}

type derptunServeRuntime struct {
	server     derptun.ServerCredential
	identity   quicpath.SessionIdentity
	dm         *tailcfg.DERPMap
	derpClient *derpbind.Client
	probeConn  net.PacketConn
	pm         publicPortmap
}

func newDerptunServeRuntime(ctx context.Context, cfg derptunServeSessionConfig) (*derptunServeRuntime, error) {
	server, tok, identity, err := loadDerptunServeIdentity(cfg.ServerToken)
	if err != nil {
		return nil, err
	}
	dm, derpClient, err := openDerptunServeDERP(ctx, tok, server, cfg.Emitter)
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

func openDerptunServeDERP(ctx context.Context, tok sessiontoken.Token, cred derptun.ServerCredential, emitter *telemetry.Emitter) (*tailcfg.DERPMap, *derpbind.Client, error) {
	bootstrap, err := resolveDERPBootstrap(ctx, tok.DERPRoute, int(tok.BootstrapRegion), "no bootstrap DERP node available")
	if err != nil {
		return nil, nil, err
	}
	derpPriv, err := cred.DERPKey()
	if err != nil {
		return nil, nil, err
	}
	emitDERPRouteDebug(emitter, bootstrap.route)
	derpClient, err := derpbind.NewClientWithPrivateKey(ctx, bootstrap.node, bootstrap.serverURL, derpPriv)
	if err != nil {
		return nil, nil, derpbind.WrapCustomDERPConnectError(bootstrap.route, bootstrap.serverURL, err)
	}
	emitDERPProxyDebug(emitter, derpClient)
	return bootstrap.dm, derpClient, nil
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
	mu       sync.Mutex
	claim    rendezvous.Claim
	decision rendezvous.Decision
	mux      *derptun.Mux
	quicConn *quic.Conn
	native   bool
	quicDone <-chan struct{}
	cancel   context.CancelFunc
	done     chan error
}

func (a *derptunServeActive) setQUICConn(conn *quic.Conn) bool {
	if a == nil || conn == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.quicConn != nil {
		return false
	}
	a.quicConn = conn
	return true
}

func (a *derptunServeActive) currentQUICConn() *quic.Conn {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quicConn
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
	if a == nil {
		return net.ErrClosed
	}
	if a.mux == nil {
		return a.probeNativeQUIC()
	}
	return a.mux.Ping(ctx, timeout)
}

func (a *derptunServeActive) probeNativeQUIC() error {
	if !a.native {
		return net.ErrClosed
	}
	quicConn := a.currentQUICConn()
	if quicConn == nil {
		if a.transportDone() {
			return net.ErrClosed
		}
		return nil
	}
	select {
	case <-quicConn.Context().Done():
		return net.ErrClosed
	default:
		return nil
	}
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
	if emitter == nil || active == nil {
		return
	}
	if active.mux == nil {
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
		Version:     server.Version,
		SessionID:   claim.SessionID,
		ClientID:    claim.Client.ClientID,
		TokenID:     claim.Client.TokenID,
		ClientName:  claim.Client.ClientName,
		ExpiresUnix: claim.Client.ExpiresUnix,
		ProofMAC:    claim.Client.ProofMAC,
		DERPRoute:   server.DERPRoute,
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
	// One active client is allowed per tunnel. Multi-client support should replace
	// this claim with a map keyed by client ID and independent tunnel state.
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
	cfg derptunServeSessionConfig,
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
	cfg     derptunServeSessionConfig
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

func handleDerptunServeRuntimeClaim(
	ctx context.Context,
	cfg derptunServeSessionConfig,
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

func readDerptunServeClaim(cfg derptunServeSessionConfig, runtime *derptunServeRuntime, pkt derpbind.Packet) (derptunServeClaimRequest, bool) {
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
	cfg derptunServeSessionConfig,
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

func enrichDerptunServeDecision(ctx context.Context, cfg derptunServeSessionConfig, runtime *derptunServeRuntime, decision *rendezvous.Decision) {
	if decision.Accept == nil || cfg.ForceRelay {
		return
	}
	decision.Accept.Candidates = publicProbeCandidates(ctx, runtime.probeConn, runtime.dm, runtime.pm)
}

func startDerptunServeClaimTunnel(
	ctx context.Context,
	cfg derptunServeSessionConfig,
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
	rawPath, err := negotiateExternalV2DirectPacketPath(transportCtx, runtime.derpClient, request.peerDERP, transportManager, runtime.dm, issued.auth, cfg.Emitter, 1, 0, 0, cfg.ForceRelay)
	if err != nil {
		cleanupDerptunServeListener(quicListener, adapter)
		cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
		gate.Release(claim.DERPPublic)
		return nil, err
	}
	rawDirect := rawPath.raw
	if rawDirect {
		rawListener, err := listenDerptunServeRawQUIC(rawPath, runtime, claim)
		if err != nil {
			rawPath.Close()
			cleanupDerptunServeListener(quicListener, adapter)
			cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
			gate.Release(claim.DERPPublic)
			return nil, err
		}
		cleanupDerptunServeListener(quicListener, adapter)
		quicListener = rawListener
		adapter = nil
	}

	var mux *derptun.Mux
	if cfg.onMux != nil {
		mux = derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: 30 * time.Second})
	}
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	transportDone := make(chan struct{})
	next := &derptunServeActive{claim: claim, decision: decision, mux: mux, native: cfg.nativeTCP(), quicDone: transportDone, cancel: tunnelCancel, done: make(chan error, 1)}
	cancelDecisionResends := startDerptunDecisionResender(ctx, runtime.derpClient, request.peerDERP, decision, issued.auth, cfg.Emitter)
	go runDerptunServeTunnel(cfg, next, tunnelCtx, tunnelCancel, cancelDecisionResends, quicListener, adapter, rawPath, rawDirect, pathEmitter, transportManager, transportCleanup, transportCancel, transportDone)
	return next, nil
}

func startDerptunServeTransport(
	ctx context.Context,
	cfg derptunServeSessionConfig,
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

func listenDerptunServeRawQUIC(rawPath externalV2DirectPacketPath, runtime *derptunServeRuntime, claim rendezvous.Claim) (*quic.Listener, error) {
	return quic.Listen(rawPath.conn, quicpath.ServerTLSConfig(runtime.identity, claim.QUICPublic), derptunQUICConfig())
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
	cfg derptunServeSessionConfig,
	active *derptunServeActive,
	tunnelCtx context.Context,
	tunnelCancel context.CancelFunc,
	cancelDecisionResends context.CancelFunc,
	quicListener *quic.Listener,
	adapter *quicpath.Adapter,
	rawPath externalV2DirectPacketPath,
	rawDirect bool,
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
		if active.mux != nil {
			_ = active.mux.Close()
		}
		if quicConn != nil {
			_ = quicConn.CloseWithError(0, "")
		}
		cleanupDerptunServeListener(quicListener, adapter)
		rawPath.Close()
		cleanupDerptunServeTransport(pathEmitter, transportManager, transportCleanup, transportCancel)
		close(transportDone)
		active.done <- err
	}()

	if cfg.nativeTCP() {
		if rawDirect {
			pathEmitter.Emit(StateDirect)
		}
		err = serveDerptunQUICListener(tunnelCtx, quicListener, cfg.TargetAddr, cfg.Emitter, func(conn *quic.Conn) {
			if active.setQUICConn(conn) {
				watchDerptunServeQUICConn(tunnelCtx, tunnelCancel, conn)
				cancelDecisionResends()
			}
		})
		return
	}

	quicConn, err = quicListener.Accept(tunnelCtx)
	if err != nil {
		return
	}
	active.setQUICConn(quicConn)
	watchDerptunServeQUICConn(tunnelCtx, tunnelCancel, quicConn)
	cancelDecisionResends()
	if rawDirect {
		pathEmitter.Emit(StateDirect)
	}
	carrier, acceptErr := quicConn.AcceptStream(tunnelCtx)
	if acceptErr != nil {
		err = acceptErr
		_ = quicConn.CloseWithError(1, "accept derptun carrier failed")
		return
	}
	active.mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
	err = cfg.onMux(tunnelCtx, active.mux)
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

func serveDerptunQUICListener(ctx context.Context, listener *quic.Listener, targetAddr string, emitter *telemetry.Emitter, onControl func(*quic.Conn)) error {
	var wg sync.WaitGroup
	assembler := newDerptunNativeStreamAssembler(targetAddr, emitter)
	defer wg.Wait()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if derptunQUICAcceptDone(ctx, err) {
				return nil
			}
			return err
		}
		if emitter != nil {
			emitter.Debug("derptun-quic-connection-accepted")
		}
		wg.Add(1)
		go serveDerptunQUICConnection(ctx, &wg, conn, assembler, emitter, onControl)
	}
}

func derptunQUICAcceptDone(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, quic.ErrServerClosed)
}

func serveDerptunQUICConnection(ctx context.Context, wg *sync.WaitGroup, conn *quic.Conn, assembler *derptunNativeStreamAssembler, emitter *telemetry.Emitter, onControl func(*quic.Conn)) {
	defer wg.Done()
	defer func() { _ = conn.CloseWithError(0, "") }()
	for {
		streamConn, err := conn.AcceptStream(ctx)
		if err != nil {
			emitDerptunQUICConnectionError(err, emitter)
			return
		}
		if !serveDerptunQUICStream(ctx, conn, streamConn, assembler, emitter, onControl) {
			return
		}
	}
}

func serveDerptunQUICStream(ctx context.Context, conn *quic.Conn, streamConn *quic.Stream, assembler *derptunNativeStreamAssembler, emitter *telemetry.Emitter, onControl func(*quic.Conn)) bool {
	laneConn := quicpath.WrapStream(conn, streamConn)
	header, err := readDerptunNativeStreamHeader(laneConn)
	if err != nil {
		_ = laneConn.Close()
		emitDerptunQUICConnectionError(err, emitter)
		return false
	}
	if header.control() {
		_ = laneConn.Close()
		if onControl != nil {
			onControl(conn)
		}
		return true
	}
	lane := derptunNativeAcceptedLane{
		conn:     laneConn,
		quicConn: conn,
	}
	if err := assembler.addLaneWithHeader(ctx, header, lane); err != nil {
		_ = lane.conn.Close()
		if emitter != nil {
			emitter.Debug("derptun-native-lane-rejected")
		}
	}
	return true
}

func emitDerptunQUICConnectionError(err error, emitter *telemetry.Emitter) {
	if derptunServeTunnelErr(err) != nil && emitter != nil {
		emitter.Debug("derptun-quic-connection-error")
	}
}

type derptunNativeAcceptedLane struct {
	conn     net.Conn
	quicConn *quic.Conn
}

type derptunNativeStreamAssembler struct {
	targetAddr string
	emitter    *telemetry.Emitter

	mu     sync.Mutex
	groups map[derptunNativeStreamID]*derptunNativeStreamGroup
}

type derptunNativeStreamGroup struct {
	laneCount int
	lanes     []derptunNativeAcceptedLane
	seen      []bool
}

func newDerptunNativeStreamAssembler(targetAddr string, emitter *telemetry.Emitter) *derptunNativeStreamAssembler {
	return &derptunNativeStreamAssembler{
		targetAddr: targetAddr,
		emitter:    emitter,
		groups:     make(map[derptunNativeStreamID]*derptunNativeStreamGroup),
	}
}

func (a *derptunNativeStreamAssembler) addLaneWithHeader(ctx context.Context, header derptunNativeStreamHeader, lane derptunNativeAcceptedLane) error {
	if header.control() {
		return errors.New("derptun control header is not a data lane")
	}
	lanes, complete, err := a.storeLane(header, lane)
	if err != nil {
		return err
	}
	if complete {
		go a.serveGroup(ctx, lanes)
	}
	return nil
}

func (a *derptunNativeStreamAssembler) storeLane(header derptunNativeStreamHeader, lane derptunNativeAcceptedLane) ([]derptunNativeAcceptedLane, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	group := a.groups[header.id]
	if group == nil {
		group = &derptunNativeStreamGroup{
			laneCount: int(header.laneCount),
			lanes:     make([]derptunNativeAcceptedLane, int(header.laneCount)),
			seen:      make([]bool, int(header.laneCount)),
		}
		a.groups[header.id] = group
	}
	if group.laneCount != int(header.laneCount) {
		return nil, false, errors.New("derptun native stream lane count mismatch")
	}
	index := int(header.laneIndex)
	if group.seen[index] {
		return nil, false, errors.New("derptun native stream duplicate lane")
	}
	group.seen[index] = true
	group.lanes[index] = lane
	if !group.complete() {
		return nil, false, nil
	}
	delete(a.groups, header.id)
	return append([]derptunNativeAcceptedLane(nil), group.lanes...), true, nil
}

func (g *derptunNativeStreamGroup) complete() bool {
	for _, seen := range g.seen {
		if !seen {
			return false
		}
	}
	return true
}

func (a *derptunNativeStreamAssembler) serveGroup(ctx context.Context, lanes []derptunNativeAcceptedLane) {
	backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", a.targetAddr)
	if err != nil {
		closeDerptunNativeAcceptedLanes(lanes)
		if a.emitter != nil {
			a.emitter.Debug("backend-dial-failed")
		}
		return
	}
	defer func() { _ = backendConn.Close() }()
	defer closeDerptunNativeAcceptedLaneStreams(lanes)
	if err := bridgeDerptunNativeStriped(ctx, lanes, backendConn); derptunServeTunnelErr(err) != nil && a.emitter != nil {
		a.emitter.Debug("derptun-native-bridge-error")
	}
}

func bridgeDerptunNativeStriped(ctx context.Context, lanes []derptunNativeAcceptedLane, backendConn net.Conn) error {
	errCh := make(chan derptunNativeBridgeResult, 2)
	closeFullOnce := sync.Once{}
	closeFull := func() {
		closeFullOnce.Do(func() {
			_ = backendConn.Close()
			closeDerptunNativeAcceptedLanes(lanes)
		})
	}
	closeGracefulOnce := sync.Once{}
	closeGraceful := func() {
		closeGracefulOnce.Do(func() {
			_ = backendConn.Close()
			closeDerptunNativeAcceptedLaneStreams(lanes)
		})
	}
	go func() {
		err := receiveExternalStripedCopy(ctx, backendConn, derptunNativeAcceptedLaneReaders(lanes), externalCopyBufferSize)
		if err == nil {
			_ = closeDerptunWrite(backendConn)
		}
		errCh <- derptunNativeBridgeResult{direction: derptunNativeBridgeReceive, err: err}
	}()
	go func() {
		err := sendExternalStripedCopy(ctx, backendConn, derptunNativeAcceptedLaneWriters(lanes), externalCopyBufferSize)
		errCh <- derptunNativeBridgeResult{direction: derptunNativeBridgeSend, err: err}
	}()

	if err := waitDerptunNativeBridge(ctx, errCh, closeFull, closeGraceful); err != nil {
		return err
	}
	closeGraceful()
	return nil
}

type derptunNativeBridgeDirection int

const (
	derptunNativeBridgeReceive derptunNativeBridgeDirection = iota
	derptunNativeBridgeSend
)

type derptunNativeBridgeResult struct {
	direction derptunNativeBridgeDirection
	err       error
}

func waitDerptunNativeBridge(ctx context.Context, errCh <-chan derptunNativeBridgeResult, closeFull func(), closeGraceful func()) error {
	var retErr error
	for range 2 {
		select {
		case result := <-errCh:
			if err := handleDerptunNativeBridgeResult(result, closeFull, closeGraceful); err != nil && retErr == nil {
				retErr = err
			}
		case <-ctx.Done():
			closeFull()
			retErr = ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if retErr != nil {
		closeFull()
		return retErr
	}
	return nil
}

func handleDerptunNativeBridgeResult(result derptunNativeBridgeResult, closeFull func(), closeGraceful func()) error {
	if result.err != nil && !derptunNativeExpectedCloseError(result.err) {
		closeFull()
		return result.err
	}
	if result.direction == derptunNativeBridgeSend {
		closeGraceful()
	}
	return nil
}

func derptunNativeExpectedCloseError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

func closeDerptunWrite(conn net.Conn) error {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func derptunNativeAcceptedLaneReaders(lanes []derptunNativeAcceptedLane) []io.ReadCloser {
	readers := make([]io.ReadCloser, 0, len(lanes))
	for _, lane := range lanes {
		if lane.conn != nil {
			readers = append(readers, derptunNativeNoCloseReader{Reader: lane.conn})
		}
	}
	return readers
}

func derptunNativeAcceptedLaneWriters(lanes []derptunNativeAcceptedLane) []io.WriteCloser {
	writers := make([]io.WriteCloser, 0, len(lanes))
	for _, lane := range lanes {
		if lane.conn != nil {
			writers = append(writers, lane.conn)
		}
	}
	return writers
}

func closeDerptunNativeAcceptedLanes(lanes []derptunNativeAcceptedLane) {
	for _, lane := range lanes {
		if lane.conn != nil {
			_ = lane.conn.Close()
		}
		if lane.quicConn != nil {
			_ = lane.quicConn.CloseWithError(0, "")
		}
	}
}

func closeDerptunNativeAcceptedLaneStreams(lanes []derptunNativeAcceptedLane) {
	for _, lane := range lanes {
		if lane.conn != nil {
			_ = lane.conn.Close()
		}
	}
}

func DerptunOpen(ctx context.Context, cfg DerptunOpenConfig) error {
	dialer, cleanup, err := dialDerptunQUICStreamDialer(ctx, derptunDialRuntimeConfig{
		ClientToken: cfg.ClientToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		KeepAlive:   true,
	})
	if err != nil {
		return err
	}
	defer cleanup()

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
		return dialer.OpenStream(ctx)
	}, cfg.Emitter)
}

func DerptunConnect(ctx context.Context, cfg DerptunConnectConfig) error {
	dialer, cleanup, err := dialDerptunQUICStreamDialer(ctx, derptunDialRuntimeConfig{
		ClientToken: cfg.ClientToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		KeepAlive:   true,
	})
	if err != nil {
		return err
	}
	defer cleanup()
	conn, err := dialer.OpenStream(ctx)
	if err != nil {
		return err
	}
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
	if err := closeDerptunWrite(conn); err != nil && !derptunNativeExpectedCloseError(err) {
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

type derptunDialRuntimeConfig struct {
	ClientToken string
	Emitter     *telemetry.Emitter
	ForceRelay  bool
	KeepAlive   bool
}

type derptunQUICStreamDialer struct {
	transport       *quic.Transport
	remoteAddr      net.Addr
	identity        quicpath.SessionIdentity
	peerPublic      [32]byte
	closePacketPath func()
	controlConn     *quic.Conn
	closeOnce       sync.Once
}

func newDerptunQUICStreamDialer(packetConn net.PacketConn, remoteAddr net.Addr, identity quicpath.SessionIdentity, peerPublic [32]byte, closePacketPath func()) *derptunQUICStreamDialer {
	return &derptunQUICStreamDialer{
		transport:       &quic.Transport{Conn: packetConn},
		remoteAddr:      remoteAddr,
		identity:        identity,
		peerPublic:      peerPublic,
		closePacketPath: closePacketPath,
	}
}

func (d *derptunQUICStreamDialer) OpenControl(ctx context.Context) error {
	conn, err := d.dialConn(ctx)
	if err != nil {
		return err
	}
	streamConn, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "open derptun control stream failed")
		return err
	}
	controlConn := quicpath.WrapStream(conn, streamConn)
	if err := writeDerptunNativeStreamHeader(controlConn, derptunNativeStreamHeader{}); err != nil {
		_ = controlConn.Close()
		_ = conn.CloseWithError(1, "write derptun control stream header failed")
		return err
	}
	if err := controlConn.Close(); err != nil {
		_ = conn.CloseWithError(1, "close derptun control stream failed")
		return err
	}
	d.controlConn = conn
	return nil
}

func (d *derptunQUICStreamDialer) OpenStream(ctx context.Context) (net.Conn, error) {
	return d.OpenStripedStream(ctx, derptunNativeTCPStripeCount)
}

func (d *derptunQUICStreamDialer) OpenStripedStream(ctx context.Context, laneCount int) (net.Conn, error) {
	if laneCount < 1 {
		return nil, errors.New("derptun stripe count must be positive")
	}
	if laneCount > 255 {
		return nil, errors.New("derptun stripe count must fit in stream header")
	}
	id, err := newDerptunNativeStreamID()
	if err != nil {
		return nil, err
	}
	lanes, err := d.openStripedLanes(ctx, id, laneCount)
	if err != nil {
		return nil, err
	}
	return newDerptunStripedStreamConn(lanes), nil
}

func (d *derptunQUICStreamDialer) openStripedLanes(ctx context.Context, id derptunNativeStreamID, laneCount int) ([]derptunNativeDialedLane, error) {
	type laneResult struct {
		index int
		lane  derptunNativeDialedLane
		err   error
	}
	laneCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan laneResult, laneCount)
	for i := range laneCount {
		go func(index int) {
			lane, err := d.openStripedLane(laneCtx, derptunNativeStreamHeader{
				id:        id,
				laneCount: uint8(laneCount),
				laneIndex: uint8(index),
			})
			results <- laneResult{index: index, lane: lane, err: err}
		}(i)
	}

	lanes := make([]derptunNativeDialedLane, laneCount)
	var firstErr error
	for range laneCount {
		result := <-results
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		lanes[result.index] = result.lane
	}
	if firstErr != nil {
		closeDerptunNativeDialedLanes(lanes)
		return nil, firstErr
	}
	return lanes, nil
}

func (d *derptunQUICStreamDialer) openStripedLane(ctx context.Context, header derptunNativeStreamHeader) (derptunNativeDialedLane, error) {
	conn, err := d.dialConn(ctx)
	if err != nil {
		return derptunNativeDialedLane{}, err
	}
	streamConn, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "open derptun stream failed")
		return derptunNativeDialedLane{}, err
	}
	laneConn := quicpath.WrapStream(conn, streamConn)
	if err := writeDerptunNativeStreamHeader(laneConn, header); err != nil {
		_ = laneConn.Close()
		_ = conn.CloseWithError(1, "write derptun stream header failed")
		return derptunNativeDialedLane{}, err
	}
	return derptunNativeDialedLane{conn: laneConn, quicConn: conn}, nil
}

func (d *derptunQUICStreamDialer) dialConn(ctx context.Context) (*quic.Conn, error) {
	return d.transport.Dial(ctx, d.remoteAddr, quicpath.ClientTLSConfig(d.identity, d.peerPublic), derptunQUICConfig())
}

func (d *derptunQUICStreamDialer) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.closeOnce.Do(func() {
		if d.controlConn != nil {
			err = d.controlConn.CloseWithError(0, "")
		}
		if d.closePacketPath != nil {
			d.closePacketPath()
		}
		if d.transport != nil {
			if transportErr := d.transport.Close(); err == nil {
				err = transportErr
			}
		}
	})
	return err
}

type derptunNativeStreamID [16]byte

type derptunNativeStreamHeader struct {
	id        derptunNativeStreamID
	laneCount uint8
	laneIndex uint8
}

type derptunNativeDialedLane struct {
	conn     net.Conn
	quicConn *quic.Conn
}

type derptunStripedStreamConn struct {
	inboundReader  *io.PipeReader
	inboundWriter  *io.PipeWriter
	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter
	cancel         context.CancelFunc
	lanes          []derptunNativeDialedLane
	closeWriteOnce sync.Once
	closeOnce      sync.Once
}

type derptunNativeNoCloseReader struct {
	io.Reader
}

func (derptunNativeNoCloseReader) Close() error { return nil }

type derptunNativeAddr string

func (a derptunNativeAddr) Network() string { return "derptun" }
func (a derptunNativeAddr) String() string  { return string(a) }

func newDerptunNativeStreamID() (derptunNativeStreamID, error) {
	var id derptunNativeStreamID
	if _, err := rand.Read(id[:]); err != nil {
		return derptunNativeStreamID{}, err
	}
	return id, nil
}

func writeDerptunNativeStreamHeader(w io.Writer, header derptunNativeStreamHeader) error {
	var buf [derptunNativeStreamHeaderSize]byte
	copy(buf[:4], derptunNativeStreamHeaderMagic)
	buf[4] = derptunNativeStreamHeaderVersion
	buf[5] = header.laneCount
	buf[6] = header.laneIndex
	copy(buf[8:], header.id[:])
	return writeFull(w, buf[:])
}

func readDerptunNativeStreamHeader(r io.Reader) (derptunNativeStreamHeader, error) {
	var buf [derptunNativeStreamHeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return derptunNativeStreamHeader{}, err
	}
	if string(buf[:4]) != derptunNativeStreamHeaderMagic {
		return derptunNativeStreamHeader{}, errors.New("invalid derptun stream header")
	}
	if buf[4] != derptunNativeStreamHeaderVersion {
		return derptunNativeStreamHeader{}, errors.New("unsupported derptun stream header version")
	}
	header := derptunNativeStreamHeader{
		laneCount: buf[5],
		laneIndex: buf[6],
	}
	copy(header.id[:], buf[8:])
	if err := header.validate(); err != nil {
		return derptunNativeStreamHeader{}, err
	}
	return header, nil
}

func (h derptunNativeStreamHeader) validate() error {
	if h.control() {
		if h.laneIndex != 0 {
			return errors.New("derptun control stream lane index must be zero")
		}
		return nil
	}
	if h.laneCount == 0 {
		return errors.New("derptun stream lane count is zero")
	}
	if h.laneIndex >= h.laneCount {
		return errors.New("derptun stream lane index out of range")
	}
	return nil
}

func (h derptunNativeStreamHeader) control() bool {
	return h.laneCount == 0
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func newDerptunStripedStreamConn(lanes []derptunNativeDialedLane) net.Conn {
	outboundReader, outboundWriter := io.Pipe()
	inboundReader, inboundWriter := io.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	conn := &derptunStripedStreamConn{
		inboundReader:  inboundReader,
		inboundWriter:  inboundWriter,
		outboundReader: outboundReader,
		outboundWriter: outboundWriter,
		cancel:         cancel,
		lanes:          lanes,
	}
	go conn.bridge(streamCtx)
	return conn
}

func (c *derptunStripedStreamConn) bridge(ctx context.Context) {
	type bridgeResult struct {
		direction string
		err       error
	}
	errCh := make(chan bridgeResult, 2)
	go func() {
		err := sendExternalStripedCopy(ctx, c.outboundReader, derptunNativeLaneWriters(c.lanes), externalCopyBufferSize)
		errCh <- bridgeResult{direction: "send", err: err}
	}()
	go func() {
		err := receiveExternalStripedCopy(ctx, c.inboundWriter, derptunNativeLaneReaders(c.lanes), externalCopyBufferSize)
		errCh <- bridgeResult{direction: "receive", err: err}
	}()
	for range 2 {
		result := <-errCh
		if result.direction == "send" && (result.err == nil || derptunNativeExpectedCloseError(result.err)) {
			continue
		}
		if result.direction == "receive" {
			if result.err != nil && !derptunNativeExpectedCloseError(result.err) {
				_ = c.inboundWriter.CloseWithError(result.err)
			} else {
				_ = c.inboundWriter.Close()
			}
		}
		_ = c.Close()
		return
	}
	_ = c.Close()
}

func (c *derptunStripedStreamConn) Read(p []byte) (int, error) {
	return c.inboundReader.Read(p)
}

func (c *derptunStripedStreamConn) Write(p []byte) (int, error) {
	return c.outboundWriter.Write(p)
}

func (c *derptunStripedStreamConn) LocalAddr() net.Addr {
	if len(c.lanes) > 0 && c.lanes[0].conn != nil {
		return c.lanes[0].conn.LocalAddr()
	}
	return derptunNativeAddr("local")
}

func (c *derptunStripedStreamConn) RemoteAddr() net.Addr {
	if len(c.lanes) > 0 && c.lanes[0].conn != nil {
		return c.lanes[0].conn.RemoteAddr()
	}
	return derptunNativeAddr("remote")
}

func (c *derptunStripedStreamConn) SetDeadline(time.Time) error {
	return nil
}

func (c *derptunStripedStreamConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *derptunStripedStreamConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *derptunStripedStreamConn) CloseWrite() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeWriteOnce.Do(func() {
		err = c.outboundWriter.Close()
	})
	return err
}

func (c *derptunStripedStreamConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.outboundWriter.Close()
		_ = c.outboundReader.Close()
		_ = c.inboundWriter.Close()
		err = c.inboundReader.Close()
		closeDerptunNativeDialedLanes(c.lanes)
	})
	return err
}

func derptunNativeLaneReaders(lanes []derptunNativeDialedLane) []io.ReadCloser {
	readers := make([]io.ReadCloser, 0, len(lanes))
	for _, lane := range lanes {
		if lane.conn != nil {
			readers = append(readers, derptunNativeNoCloseReader{Reader: lane.conn})
		}
	}
	return readers
}

func derptunNativeLaneWriters(lanes []derptunNativeDialedLane) []io.WriteCloser {
	writers := make([]io.WriteCloser, 0, len(lanes))
	for _, lane := range lanes {
		if lane.conn != nil {
			writers = append(writers, lane.conn)
		}
	}
	return writers
}

func closeDerptunNativeDialedLanes(lanes []derptunNativeDialedLane) {
	for _, lane := range lanes {
		if lane.conn != nil {
			_ = lane.conn.Close()
		}
		if lane.quicConn != nil {
			_ = lane.quicConn.CloseWithError(0, "")
		}
	}
}

func newDerptunDialRuntime(ctx context.Context, clientToken string, emitter *telemetry.Emitter, forceRelay bool) (*derptunDialRuntime, error) {
	cred, tok, listenerDERP, err := loadDerptunDialToken(clientToken)
	if err != nil {
		return nil, err
	}
	dm, derpClient, err := openDerptunDialDERP(ctx, tok, emitter)
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

func openDerptunDialDERP(ctx context.Context, tok sessiontoken.Token, emitter *telemetry.Emitter) (*tailcfg.DERPMap, *derpbind.Client, error) {
	bootstrap, err := resolveDERPBootstrap(ctx, tok.DERPRoute, int(tok.BootstrapRegion), "no bootstrap DERP node available")
	if err != nil {
		return nil, nil, err
	}
	derpClient, err := openSessionDERPClient(ctx, bootstrap, emitter)
	if err != nil {
		return nil, nil, err
	}
	return bootstrap.dm, derpClient, nil
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

func dialDerptunQUICStreamDialer(ctx context.Context, cfg derptunDialRuntimeConfig) (*derptunQUICStreamDialer, func(), error) {
	runtime, err := newDerptunDialRuntime(ctx, cfg.ClientToken, cfg.Emitter, cfg.ForceRelay)
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
	dialer, cleanup, err := runtime.dialQUICStreamDialer(ctx, cfg.Emitter, cfg.ForceRelay, cfg.KeepAlive, decision)
	if err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	return dialer, cleanup, nil
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

type derptunDialTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	manager     *transport.Manager
	cleanup     func()
	pathEmitter *transportPathEmitter
}

func (r *derptunDialRuntime) startDialTransport(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool, decision rendezvous.Decision) (*derptunDialTransport, error) {
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
		return nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	return &derptunDialTransport{
		ctx:         transportCtx,
		cancel:      transportCancel,
		manager:     transportManager,
		cleanup:     transportCleanup,
		pathEmitter: pathEmitter,
	}, nil
}

func (t *derptunDialTransport) close() {
	if t == nil {
		return
	}
	if t.pathEmitter != nil && t.manager != nil {
		t.pathEmitter.Complete(t.manager)
	}
	if t.cleanup != nil {
		t.cleanup()
	}
	if t.cancel != nil {
		t.cancel()
	}
}

func (r *derptunDialRuntime) dialQUIC(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool, decision rendezvous.Decision) (*quic.Conn, func(), error) {
	dialTransport, err := r.startDialTransport(ctx, emitter, forceRelay, decision)
	if err != nil {
		return nil, nil, err
	}
	quicConn, closePacketPath, rawDirect, err := r.openQUICConn(ctx, dialTransport.ctx, dialTransport.manager, emitter, forceRelay)
	if err != nil {
		dialTransport.close()
		return nil, nil, err
	}
	if rawDirect {
		dialTransport.pathEmitter.Emit(StateDirect)
	}
	cleanup := func() {
		_ = quicConn.CloseWithError(0, "")
		closePacketPath()
		dialTransport.close()
		r.closeBase()
	}
	return quicConn, cleanup, nil
}

func (r *derptunDialRuntime) dialQUICStreamDialer(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool, keepAlive bool, decision rendezvous.Decision) (*derptunQUICStreamDialer, func(), error) {
	dialTransport, err := r.startDialTransport(ctx, emitter, forceRelay, decision)
	if err != nil {
		return nil, nil, err
	}
	dialer, rawDirect, err := r.openQUICStreamDialer(dialTransport.ctx, dialTransport.manager, emitter, forceRelay)
	if err != nil {
		dialTransport.close()
		return nil, nil, err
	}
	if rawDirect {
		dialTransport.pathEmitter.Emit(StateDirect)
	}
	if keepAlive {
		if err := dialer.OpenControl(ctx); err != nil {
			_ = dialer.Close()
			dialTransport.close()
			return nil, nil, err
		}
	}
	cleanup := func() {
		_ = dialer.Close()
		dialTransport.close()
		r.closeBase()
	}
	return dialer, cleanup, nil
}

func (r *derptunDialRuntime) dialMux(ctx context.Context, emitter *telemetry.Emitter, forceRelay bool, decision rendezvous.Decision) (*derptun.Mux, func(), error) {
	quicConn, cleanup, err := r.dialQUIC(ctx, emitter, forceRelay, decision)
	if err != nil {
		return nil, nil, err
	}
	carrier, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: 30 * time.Second})
	mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
	return mux, cleanup, nil
}

func (r *derptunDialRuntime) openQUICConn(ctx context.Context, transportCtx context.Context, transportManager *transport.Manager, emitter *telemetry.Emitter, forceRelay bool) (*quic.Conn, func(), bool, error) {
	packetConn, remoteAddr, closePacketPath, rawDirect, err := r.openQUICPacketPath(transportCtx, transportManager, emitter, forceRelay)
	if err != nil {
		return nil, nil, false, err
	}
	quicConn, err := quic.Dial(ctx, packetConn, remoteAddr, quicpath.ClientTLSConfig(r.clientIdentity, r.tok.QUICPublic), derptunQUICConfig())
	if err != nil {
		closePacketPath()
		return nil, nil, false, err
	}
	return quicConn, closePacketPath, rawDirect, nil
}

func (r *derptunDialRuntime) openQUICStreamDialer(transportCtx context.Context, transportManager *transport.Manager, emitter *telemetry.Emitter, forceRelay bool) (*derptunQUICStreamDialer, bool, error) {
	packetConn, remoteAddr, closePacketPath, rawDirect, err := r.openQUICPacketPath(transportCtx, transportManager, emitter, forceRelay)
	if err != nil {
		return nil, false, err
	}
	dialer := newDerptunQUICStreamDialer(packetConn, remoteAddr, r.clientIdentity, r.tok.QUICPublic, closePacketPath)
	return dialer, rawDirect, nil
}

func (r *derptunDialRuntime) openQUICPacketPath(transportCtx context.Context, transportManager *transport.Manager, emitter *telemetry.Emitter, forceRelay bool) (net.PacketConn, net.Addr, func(), bool, error) {
	rawPath, err := negotiateExternalV2DirectPacketPath(transportCtx, r.derpClient, r.listenerDERP, transportManager, r.dm, externalPeerControlAuthForToken(r.tok), emitter, 1, externalV2DataPlaneSenderPunchDelay, 0, forceRelay)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if rawPath.raw {
		return rawPath.conn, rawPath.addr, rawPath.Close, true, nil
	}
	rawPath.Close()

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	return adapter, peerConn.RemoteAddr(), func() { _ = adapter.Close() }, false, nil
}
