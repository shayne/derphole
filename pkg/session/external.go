package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"go4.org/mem"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/traversal"
	"github.com/shayne/derpcat/pkg/wg"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	envelopeClaim    = "claim"
	envelopeDecision = "decision"

	overlayPort       = 7000
	directProbeWindow = 1 * time.Second
	dialRetryInterval = 100 * time.Millisecond
	overlayAck        = "derpcat-ack"
)

type envelope struct {
	Type     string               `json:"type"`
	Claim    *rendezvous.Claim    `json:"claim,omitempty"`
	Decision *rendezvous.Decision `json:"decision,omitempty"`
}

func derpPublicKeyRaw32(pub key.NodePublic) [32]byte {
	var raw [32]byte
	copy(raw[:], pub.AppendTo(raw[:0]))
	return raw
}

func issuePublicSession(ctx context.Context) (string, *relaySession, error) {
	dm, err := derpbind.FetchMap(ctx, derpbind.PublicDERPMapURL)
	if err != nil {
		return "", nil, err
	}
	node := firstDERPNode(dm, 0)
	if node == nil {
		return "", nil, errors.New("no DERP node available")
	}

	derpClient, err := derpbind.NewClient(ctx, node, derpServerURL(node))
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
		Capabilities:    token.CapabilityStdio | token.CapabilityTCP,
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
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return ErrUnknownSession
	}

	dm, err := derpbind.FetchMap(ctx, derpbind.PublicDERPMapURL)
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, derpServerURL(node))
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

	emitStatus(cfg.Emitter, StateProbing)
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("claim-accepted")
	}

	directCandidate := ""
	if !cfg.ForceRelay && decision.Accept != nil {
		if candidate, ok := firstDirectCandidate(ctx, probeConn, decision.Accept.Candidates); ok {
			directCandidate = candidate
		}
	}

	_, listenerAddr, senderAddr := wg.DeriveAddresses(tok.SessionID)
	sessionNode, err := wg.NewNode(wg.Config{
		PrivateKey:    senderPrivate,
		PeerPublicKey: tok.WGPublic,
		LocalAddr:     senderAddr,
		PeerAddr:      listenerAddr,
		PacketConn:    probeConn,
		DERPClient:    derpClient,
		PeerDERP:      listenerDERP,
	})
	if err != nil {
		return err
	}
	defer sessionNode.Close()
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("sender-node-ready")
	}

	if directCandidate != "" {
		if err := sessionNode.SetDirectEndpoint(directCandidate); err != nil {
			return err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("direct-endpoint-set")
		}
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
	if err := waitForPeerAck(ctx, overlayConn); err != nil {
		return err
	}

	emitStatus(cfg.Emitter, transportState(sessionNode))
	emitStatus(cfg.Emitter, StateComplete)
	return nil
}

func listenExternal(ctx context.Context, cfg ListenConfig) (string, error) {
	tok, session, err := issuePublicSession(ctx)
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, session)
	defer session.derp.Close()

	emitStatus(cfg.Emitter, StateWaiting)
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

		if !cfg.ForceRelay {
			probeCtx, cancel := context.WithTimeout(ctx, directProbeWindow)
			serveDirectProbes(probeCtx, session.probeConn)
			cancel()
		}

		_, listenerAddr, senderAddr := wg.DeriveAddresses(session.token.SessionID)
		sessionNode, err := wg.NewNode(wg.Config{
			PrivateKey:    session.wgPrivate,
			PeerPublicKey: env.Claim.WGPublic,
			LocalAddr:     listenerAddr,
			PeerAddr:      senderAddr,
			PacketConn:    session.probeConn,
			DERPClient:    session.derp,
			PeerDERP:      peerDERP,
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
		if _, err := io.WriteString(overlayConn, overlayAck); err != nil {
			return tok, err
		}

		emitStatus(cfg.Emitter, transportState(sessionNode))
		emitStatus(cfg.Emitter, StateComplete)
		return tok, nil
	}
}

func transportState(node *wg.Node) State {
	if node != nil && node.DirectConfirmed() {
		return StateDirect
	}
	return StateRelay
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

func waitForPeerAck(ctx context.Context, conn net.Conn) error {
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(overlayAck))
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != overlayAck {
			done <- errors.New("unexpected listener ack")
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		return err
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

func firstDirectCandidate(ctx context.Context, conn net.PacketConn, candidates []string) (string, bool) {
	for _, candidate := range candidates {
		result, err := traversal.ProbeDirect(ctx, conn, candidate, nil, "")
		if err == nil && result.Direct {
			return candidate, true
		}
	}
	return "", false
}

func serveDirectProbes(ctx context.Context, conn net.PacketConn) {
	if conn == nil {
		return
	}
	buf := make([]byte, 64<<10)
	for {
		deadline := time.Now().Add(250 * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetReadDeadline(deadline)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
		if string(buf[:n]) == "derpcat-probe" {
			_, _ = conn.WriteTo([]byte("derpcat-ack"), addr)
		}
	}
}
