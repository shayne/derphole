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
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type DerptunServeConfig struct {
	ServerToken   string
	Token         string
	TargetAddr    string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunOpenConfig struct {
	ClientToken   string
	Token         string
	ListenAddr    string
	BindAddrSink  chan<- string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunConnectConfig struct {
	ClientToken   string
	Token         string
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
	serverToken := cfg.ServerToken
	if serverToken == "" {
		serverToken = cfg.Token
	}
	cred, err := decodeDerptunServer(serverToken)
	if err != nil {
		return err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return err
	}
	derpPriv, err := cred.DERPKey()
	if err != nil {
		return err
	}
	quicPriv, err := cred.QUICPrivateKey()
	if err != nil {
		return err
	}
	identity, err := quicpath.SessionIdentityFromEd25519PrivateKey(quicPriv, time.Now())
	if err != nil {
		return err
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClientWithPrivateKey(ctx, node, publicDERPServerURL(node), derpPriv)
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

	emitStatus(cfg.Emitter, StateWaiting)
	gate := &derptunClientGate{}
	if err := serveDerptunClaims(ctx, cfg, cred, identity, dm, derpClient, probeConn, pm, gate); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
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
	if active.transportDone() {
		if emitter != nil {
			emitter.Debug("derptun-active-probe=transport-done")
		}
		releaseDerptunActive(emitter, gate, active, stopTimeout)
		return true, nil
	}
	if active.mux != nil {
		lastPeerActivity := active.lastPeerActivity()
		activeStreams := active.mux.ActiveStreamCount()
		if emitter != nil && !lastPeerActivity.IsZero() {
			emitter.Debug("derptun-active-last-peer-ms=" + strconv.FormatInt(time.Since(lastPeerActivity).Milliseconds(), 10))
			emitter.Debug("derptun-active-streams=" + strconv.Itoa(activeStreams))
		}
	}
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

func startDerptunDecisionResender(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, decision rendezvous.Decision, emitter *telemetry.Emitter) context.CancelFunc {
	resendCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(externalClaimRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendCtx, sendCancel := context.WithTimeout(resendCtx, externalClaimRetryInterval)
				err := sendEnvelope(sendCtx, client, peerDERP, envelope{Type: envelopeDecision, Decision: &decision})
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
	server derptun.ServerCredential,
	identity quicpath.SessionIdentity,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	probeConn net.PacketConn,
	pm publicPortmap,
	gate *derptunClientGate,
) error {
	claimCh, unsubscribeClaims := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	var active *derptunServeActive
	defer func() {
		if active != nil {
			_ = active.stop(context.Background())
			gate.Release(active.claim.DERPPublic)
		}
	}()

	for {
		var activeDone <-chan error
		if active != nil {
			activeDone = active.done
		}

		select {
		case err := <-activeDone:
			gate.Release(active.claim.DERPPublic)
			active = nil
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := derptunServeTunnelErr(err); err != nil {
				return err
			}
			continue
		case pkt, ok := <-claimCh:
			if !ok {
				return net.ErrClosed
			}
			nextActive, err := handleDerptunServeClaim(ctx, cfg, server, identity, dm, derpClient, probeConn, pm, gate, active, pkt)
			if err != nil {
				return err
			}
			active = nextActive
		case <-ctx.Done():
			if active != nil {
				err := active.stop(context.Background())
				gate.Release(active.claim.DERPPublic)
				active = nil
				if err := derptunServeTunnelErr(err); err != nil {
					return err
				}
			}
			return ctx.Err()
		}
	}
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
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeClaim || env.Claim == nil {
		return active, nil
	}
	claim := *env.Claim
	peerDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))
	now := time.Now()
	claimToken, rejectDecision, err := derptunServerTokenForClaim(server, claim, now)
	if err != nil {
		if rejectDecision.Reject == nil {
			return active, err
		}
		if sendErr := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &rejectDecision}); sendErr != nil {
			return active, sendErr
		}
		return active, nil
	}
	decision, _ := gate.Accept(now, claimToken, claim)
	if !decision.Accepted {
		if decision.Reject != nil && decision.Reject.Code == rendezvous.RejectClaimed && active != nil && !active.sameClaim(claim) {
			recovered, err := recoverStaleDerptunActive(ctx, cfg.Emitter, gate, active, derptunActiveProbeTimeout, derptunActiveStopTimeout)
			if err != nil {
				return active, err
			}
			if recovered {
				active = nil
				decision, _ = gate.Accept(time.Now(), claimToken, claim)
			}
		}
	}
	if !decision.Accepted {
		if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return active, err
		}
		return active, nil
	}
	if active != nil && active.sameClaim(claim) {
		retryDecision := active.decision
		if retryDecision.Accept == nil && retryDecision.Reject == nil {
			retryDecision = decision
		}
		if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &retryDecision}); err != nil {
			return active, err
		}
		return active, nil
	}
	if decision.Accept != nil && !cfg.ForceRelay {
		decision.Accept.Candidates = publicProbeCandidates(ctx, probeConn, dm, pm)
	}

	emitStatus(cfg.Emitter, StateClaimed)
	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		probeConn,
		dm,
		derpClient,
		peerDERP,
		parseCandidateStrings(decision.Accept.Candidates),
		pm,
		cfg.ForceRelay,
	)
	if err != nil {
		transportCancel()
		gate.Release(claim.DERPPublic)
		return active, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedClaimCandidates(transportCtx, transportManager, claim)

	adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
	quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(identity, claim.QUICPublic), derptunQUICConfig())
	if err != nil {
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		gate.Release(claim.DERPPublic)
		return active, err
	}
	if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
		_ = quicListener.Close()
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		gate.Release(claim.DERPPublic)
		return active, err
	}

	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: 30 * time.Second})
	tunnelCtx, tunnelCancel := context.WithCancel(ctx)
	transportDone := make(chan struct{})
	next := &derptunServeActive{claim: claim, decision: decision, mux: mux, quicDone: transportDone, cancel: tunnelCancel, done: make(chan error, 1)}
	cancelDecisionResends := startDerptunDecisionResender(ctx, derpClient, peerDERP, decision, cfg.Emitter)
	go func() {
		var quicConn *quic.Conn
		var err error
		defer func() {
			cancelDecisionResends()
			tunnelCancel()
			_ = mux.Close()
			if quicConn != nil {
				_ = quicConn.CloseWithError(0, "")
			}
			_ = quicListener.Close()
			_ = adapter.Close()
			pathEmitter.Complete(transportManager)
			transportCleanup()
			transportCancel()
			close(transportDone)
			next.done <- err
		}()

		quicConn, err = quicListener.Accept(tunnelCtx)
		if err != nil {
			return
		}
		go func() {
			select {
			case <-quicConn.Context().Done():
				tunnelCancel()
			case <-tunnelCtx.Done():
			}
		}()
		carrier, acceptErr := quicConn.AcceptStream(tunnelCtx)
		cancelDecisionResends()
		if acceptErr != nil {
			err = acceptErr
			_ = quicConn.CloseWithError(1, "accept derptun carrier failed")
			return
		}
		mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
		err = serveDerptunMuxTarget(tunnelCtx, mux, cfg.TargetAddr, cfg.Emitter)
	}()
	return next, nil
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
			defer overlayConn.Close()
			defer backendConn.Close()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
}

func DerptunOpen(ctx context.Context, cfg DerptunOpenConfig) error {
	clientToken := cfg.ClientToken
	if clientToken == "" {
		clientToken = cfg.Token
	}
	mux, cleanup, err := dialDerptunMux(ctx, clientToken, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer mux.Close()

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		return mux.OpenStream(ctx)
	}, cfg.Emitter)
}

func DerptunConnect(ctx context.Context, cfg DerptunConnectConfig) error {
	clientToken := cfg.ClientToken
	if clientToken == "" {
		clientToken = cfg.Token
	}
	conn, cleanup, err := dialDerptunMuxStream(ctx, clientToken, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer conn.Close()
	return bridgeDerptunStdio(ctx, conn, cfg.StdioIn, cfg.StdioOut)
}

func bridgeDerptunStdio(ctx context.Context, conn net.Conn, in io.Reader, out io.Writer) error {
	if in == nil {
		in = io.Reader(&emptyReader{})
	}
	if out == nil {
		out = io.Discard
	}
	closeInput := func() {
		if closer, ok := in.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	inErr := make(chan error, 1)
	outErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, in)
		inErr <- err
	}()
	go func() {
		_, err := io.Copy(out, conn)
		outErr <- err
	}()

	for {
		select {
		case err := <-inErr:
			if err != nil && !errors.Is(err, io.EOF) {
				_ = conn.Close()
				return err
			}
			inErr = nil
		case err := <-outErr:
			closeInput()
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				return err
			}
			return nil
		case <-ctx.Done():
			closeInput()
			_ = conn.Close()
			return ctx.Err()
		}
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
	cred, err := decodeDerptunClient(clientToken)
	if err != nil {
		return nil, nil, err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return nil, nil, err
	}
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return nil, nil, ErrUnknownSession
	}
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
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		_ = derpClient.Close()
		return nil, nil, err
	}
	pm := newBoundPublicPortmap(probeConn, emitter)
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}

	var localCandidates []string
	if !forceRelay {
		localCandidates = publicProbeCandidates(ctx, probeConn, dm, pm)
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   clientIdentity.Public,
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
		Client: &rendezvous.ClientProof{
			ClientID:    cred.ClientID,
			TokenID:     cred.TokenID,
			ClientName:  cred.ClientName,
			ExpiresUnix: cred.ExpiresUnix,
			ProofMAC:    cred.ProofMAC,
		},
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	if !decision.Accepted {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		if decision.Reject != nil {
			return nil, nil, errors.New(decision.Reject.Reason)
		}
		return nil, nil, errors.New("claim rejected")
	}

	pathEmitter := newTransportPathEmitter(emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		probeConn,
		dm,
		derpClient,
		listenerDERP,
		parseCandidateStrings(localCandidates),
		pm,
		forceRelay,
	)
	if err != nil {
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic), derptunQUICConfig())
	if err != nil {
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	carrier, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(1, "open derptun carrier failed")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
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
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
	}
	return mux, cleanup, nil
}
