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
	"time"

	"go4.org/mem"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/transport"
	"github.com/shayne/derpcat/pkg/traversal"
	"github.com/shayne/derpcat/pkg/wg"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	envelopeClaim    = "claim"
	envelopeDecision = "decision"
	envelopeControl  = "control"
	envelopeAck      = "ack"

	overlayPort       = 7000
	dialRetryInterval = 100 * time.Millisecond
)

type envelope struct {
	Type     string                    `json:"type"`
	Claim    *rendezvous.Claim         `json:"claim,omitempty"`
	Decision *rendezvous.Decision      `json:"decision,omitempty"`
	Control  *transport.ControlMessage `json:"control,omitempty"`
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
	wgPrivate, wgPublic, err := wg.GenerateKeypair()
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}
	_, discoPublic, err := wg.GenerateKeypair()
	if err != nil {
		_ = derpClient.Close()
		return "", nil, err
	}

	tokValue := token.Token{
		Version:         token.SupportedVersion,
		SessionID:       sessionID,
		ExpiresUnix:     time.Now().Add(10 * time.Minute).Unix(),
		BootstrapRegion: uint16(node.RegionID),
		DERPPublic:      derpPublicKeyRaw32(derpClient.PublicKey()),
		WGPublic:        wgPublic,
		DiscoPublic:     discoPublic,
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
		mailbox:   make(chan relayMessage),
		probeConn: probeConn,
		derp:      derpClient,
		token:     tokValue,
		gate:      rendezvous.NewGate(tokValue),
		derpMap:   dm,
		wgPrivate: wgPrivate,
	}
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

	senderPrivate, senderPublic, err := wg.GenerateKeypair()
	if err != nil {
		return err
	}
	_, senderDisco, err := wg.GenerateKeypair()
	if err != nil {
		return err
	}

	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		WGPublic:     senderPublic,
		DiscoPublic:  senderDisco,
		Candidates:   publicProbeCandidates(ctx, probeConn, dm),
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
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	_, listenerAddr, senderAddr := wg.DeriveAddresses(tok.SessionID)
	sessionNode, err := wg.NewNode(wg.Config{
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.WGPublic,
		LocalAddr:     senderAddr,
		PeerAddr:      listenerAddr,
		PacketConn:    probeConn,
		DERPClient:    derpClient,
		PeerDERP:      listenerDERP,
		PathSelector:  transportManager,
	})
	if err != nil {
		return err
	}
	defer sessionNode.Close()
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("sender-node-ready")
	}

	if cfg.Emitter != nil {
		cfg.Emitter.Debug("dialing-overlay")
	}
	overlayConn, err := dialOverlay(ctx, sessionNode, netip.AddrPortFrom(listenerAddr, overlayPort))
	if err != nil {
		return err
	}
	defer overlayConn.Close()
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("overlay-connected")
	}

	src, err := openSendSource(ctx, cfg)
	if err != nil {
		return err
	}
	defer src.Close()

	if _, err := io.Copy(overlayConn, src); err != nil {
		return err
	}
	if cw, ok := overlayConn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			return err
		}
	} else if err := overlayConn.Close(); err != nil {
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
			decision.Accept.Candidates = publicProbeCandidates(ctx, session.probeConn, session.derpMap)
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("claim-accepted")
		}
		transportCtx, transportCancel := context.WithCancel(ctx)
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, cfg.ForceRelay)
		if err != nil {
			transportCancel()
			return tok, err
		}
		defer transportCancel()
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)

		_, listenerAddr, senderAddr := wg.DeriveAddresses(session.token.SessionID)
		sessionNode, err := wg.NewNode(wg.Config{
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.WGPublic,
			LocalAddr:     listenerAddr,
			PeerAddr:      senderAddr,
			PacketConn:    session.probeConn,
			DERPClient:    session.derp,
			PeerDERP:      peerDERP,
			PathSelector:  transportManager,
		})
		if err != nil {
			return tok, err
		}
		defer sessionNode.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("listener-node-ready")
		}

		ln, err := sessionNode.ListenTCP(overlayPort)
		if err != nil {
			return tok, err
		}
		defer ln.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("overlay-listening")
		}

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
			cfg.Emitter.Debug("accepting-overlay")
		}

		overlayConn, err := acceptOverlay(ctx, ln)
		if err != nil {
			return tok, err
		}
		defer overlayConn.Close()
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("overlay-accepted")
		}

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		defer dst.Close()

		if _, err := io.Copy(dst, overlayConn); err != nil {
			return tok, err
		}
		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeAck}); err != nil {
			return tok, err
		}
		if err := overlayConn.Close(); err != nil {
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
	forceRelay bool,
) (*transport.Manager, func(), error) {
	controlCh, unsubscribe := derpClient.Subscribe(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isTransportControlPayload(pkt.Payload)
	})

	cfg := transport.ManagerConfig{
		RelayConn:               conn,
		DirectConn:              nil,
		DisableDirectReads:      true,
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
		cfg.CandidateSource = func(ctx context.Context) []net.Addr {
			return publicProbeAddrs(ctx, conn, dm)
		}
	}

	manager := transport.NewManager(cfg)
	if err := manager.Start(ctx); err != nil {
		unsubscribe()
		return nil, nil, err
	}
	return manager, unsubscribe, nil
}

func dialOverlay(ctx context.Context, node *wg.Node, addr netip.AddrPort) (net.Conn, error) {
	ticker := time.NewTicker(dialRetryInterval)
	defer ticker.Stop()

	for {
		conn, err := node.DialTCP(ctx, addr)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func acceptOverlay(ctx context.Context, ln net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		done <- result{conn: conn, err: err}
	}()

	select {
	case res := <-done:
		return res.conn, res.err
	case <-ctx.Done():
		_ = ln.Close()
		return nil, ctx.Err()
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
	err := json.Unmarshal(payload, &env)
	return env, err
}

func publicProbeCandidates(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap) []string {
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
		if !ip.IsValid() || ip.IsUnspecified() {
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
		if gathered, err := traversal.GatherCandidates(ctx, dm); err == nil {
			for _, candidateIP := range gathered {
				if ip, err := netip.ParseAddr(candidateIP); err == nil {
					add(ip)
				}
			}
		}
	}

	candidates := make([]string, 0, len(seen))
	for candidate := range seen {
		candidates = append(candidates, candidate)
	}
	slices.Sort(candidates)
	return candidates
}

func publicProbeAddrs(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap) []net.Addr {
	raw := publicProbeCandidates(ctx, conn, dm)
	return parseCandidateStrings(raw)
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

func seedAcceptedDecisionCandidates(ctx context.Context, seeder remoteCandidateSeeder, decision rendezvous.Decision) {
	if seeder == nil || decision.Accept == nil || len(decision.Accept.Candidates) == 0 {
		return
	}
	seeder.SeedRemoteCandidates(ctx, parseCandidateStrings(decision.Accept.Candidates))
}

func isTransportControlPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeControl && env.Control != nil
}

func isAckPayload(payload []byte) bool {
	if len(payload) == 0 || payload[0] != '{' {
		return false
	}
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeAck
}

func fakeTransportCandidatesBlocked() bool {
	if os.Getenv("DERPCAT_FAKE_TRANSPORT") != "1" {
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
