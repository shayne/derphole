package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
	"github.com/shayne/derpcat/pkg/transport"
	wgtransport "github.com/shayne/derpcat/pkg/wg"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	externalDirectUDPTransportLabel  = "batched"
	externalDirectUDPParallelism     = 4
	externalDirectUDPChunkSize       = 1400
	externalDirectUDPRateMbps        = 2150
	externalDirectUDPWait            = 750 * time.Millisecond
	externalDirectUDPPunchWait       = 1200 * time.Millisecond
	externalDirectUDPHandshakeWait   = 1500 * time.Millisecond
	externalDirectUDPStartWait       = 30 * time.Second
	externalDirectUDPBufferSize      = 4 << 20
	externalDirectUDPRepairPayloads  = true
	externalDirectUDPTailReplayBytes = 0
	externalDirectUDPFECGroupSize    = 0
	externalDirectUDPStripedBlast    = true
	externalDirectUDPDiscardQueue    = 32
)

var externalDirectUDPPreviewTransportCaps = probe.PreviewTransportCaps

func sendExternalViaDirectUDP(ctx context.Context, cfg SendConfig) error {
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
	defer src.Close()

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

	probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConns(nil, nil, externalDirectUDPParallelism, cfg.Emitter)
	if err != nil {
		return err
	}
	defer cleanupProbeConns()
	probeConn := probeConns[0]
	pm := portmaps[0]

	_, senderPublic, err := wgtransport.GenerateKeypair()
	if err != nil {
		return err
	}

	var localCandidates []string
	if !cfg.ForceRelay {
		localCandidates = externalDirectUDPCandidates(ctx, probeConns, dm, portmaps)
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("udp-local-candidates=" + strings.Join(localCandidates, ","))
		}
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   senderPublic,
		Parallel:     len(probeConns),
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		return err
	}
	if !decision.Accepted {
		if decision.Reject != nil {
			return errors.New(decision.Reject.Reason)
		}
		return errors.New("claim rejected")
	}
	ackCh, unsubscribeAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()
	readyAckCh, unsubscribeReadyAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
	})
	defer unsubscribeReadyAck()
	startAckCh, unsubscribeStartAck := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isDirectUDPStartAckPayload(pkt.Payload)
	})
	defer unsubscribeStartAck()

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)
	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	remoteCandidates := parseCandidateStrings(decision.Accept.Candidates)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !cfg.ForceRelay {
		externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
	}

	var sendErr error
	if cfg.ForceRelay {
		sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
	} else if peerAddr, err := waitExternalDirectUDPAddr(ctx, probeConn, transportManager); err == nil {
		if len(remoteCandidates) == 0 {
			sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
		} else {
			if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{Type: envelopeDirectUDPReady}); err != nil {
				return err
			}
			readyAck, err := waitForDirectUDPReadyAck(ctx, readyAckCh)
			if err != nil {
				if externalDirectUDPWaitCanFallback(ctx, err) {
					sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
				} else {
					return err
				}
			} else {
				transportManager.StopDirectReads()
				pathEmitter.Emit(StateDirect)
				remoteAddrs := externalDirectUDPSelectRemoteAddrs(ctx, probeConns, remoteCandidates, cfg.Emitter)
				probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
				if len(probeConns) == 0 {
					return errors.New("direct UDP established without usable remote addresses")
				}
				if cfg.Emitter != nil {
					cfg.Emitter.Debug("udp-blast=true")
					cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
					cfg.Emitter.Debug("udp-rate-mbps=" + strconv.Itoa(externalDirectUDPRateMbps))
					cfg.Emitter.Debug("udp-repair-payloads=" + strconv.FormatBool(externalDirectUDPRepairPayloads))
					cfg.Emitter.Debug("udp-tail-replay-bytes=" + strconv.Itoa(externalDirectUDPTailReplayBytes))
					cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPFECGroupSize))
					cfg.Emitter.Debug("udp-striped-blast=" + strconv.FormatBool(externalDirectUDPStripedBlast && !readyAck.FastDiscard))
					cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(readyAck.FastDiscard))
					cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
					cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
				}
				sendCfg := probe.SendConfig{
					Blast:                    true,
					Transport:                externalDirectUDPTransportLabel,
					ChunkSize:                externalDirectUDPChunkSize,
					RateMbps:                 externalDirectUDPRateMbps,
					RunID:                    tok.SessionID,
					RepairPayloads:           externalDirectUDPRepairPayloads,
					TailReplayBytes:          externalDirectUDPTailReplayBytes,
					FECGroupSize:             externalDirectUDPFECGroupSize,
					StripedBlast:             externalDirectUDPStripedBlast && !readyAck.FastDiscard,
					AllowPartialParallel:     true,
					ParallelHandshakeTimeout: externalDirectUDPHandshakeWait,
				}
				var stats probe.TransferStats
				if readyAck.FastDiscard {
					spool, spoolErr := externalDirectUDPSpoolDiscardLanes(ctx, externalDirectUDPBufferedReader(src), len(probeConns), sendCfg.ChunkSize)
					if spoolErr != nil {
						return spoolErr
					}
					defer spool.Close()
					emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, spool.TotalBytes)
					if err := sendEnvelope(ctx, derpClient, listenerDERP, envelope{
						Type: envelopeDirectUDPStart,
						DirectUDPStart: &directUDPStart{
							ExpectedBytes: spool.TotalBytes,
						},
					}); err != nil {
						return err
					}
					if err := waitForDirectUDPStartAck(ctx, startAckCh); err != nil {
						return err
					}
					discardSendCfg := sendCfg
					// Fast-discard mirrors the probe harness: each independent lane gets its own generated run ID.
					discardSendCfg.RunID = [16]byte{}
					externalDirectUDPStopPunchingForBlast(punchCancel)
					stats, err = externalDirectUDPSendDiscardSpoolParallel(ctx, probeConns, remoteAddrs, spool, discardSendCfg)
				} else {
					externalDirectUDPStopPunchingForBlast(punchCancel)
					stats, err = probe.SendBlastParallel(ctx, probeConns, remoteAddrs, externalDirectUDPBufferedReader(src), sendCfg)
				}
				if cfg.Emitter != nil {
					cfg.Emitter.Debug("udp-send-transport=" + stats.Transport.Summary())
					if stats.Lanes > 0 {
						cfg.Emitter.Debug("udp-send-active-lanes=" + strconv.Itoa(stats.Lanes))
					}
					cfg.Emitter.Debug("udp-send-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
					emitExternalDirectUDPStats(cfg.Emitter, "udp-send", stats.BytesSent, stats.StartedAt, stats.CompletedAt)
				}
				sendErr = err
			}
		}
	} else if externalDirectUDPWaitCanFallback(ctx, err) {
		sendErr = sendExternalRelayUDP(ctx, src, transportManager, tok.SessionID, cfg.Emitter)
	} else {
		return err
	}
	if sendErr != nil {
		return sendErr
	}
	if err := waitForPeerAck(ctx, ackCh); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}

func listenExternalViaDirectUDP(ctx context.Context, cfg ListenConfig) (string, error) {
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
		if decision.Accept == nil {
			return tok, errors.New("accepted decision missing accept payload")
		}
		probeConns, portmaps, cleanupProbeConns, err := externalDirectUDPConns(session.probeConn, publicSessionPortmap(session), externalDirectUDPParallelism, cfg.Emitter)
		if err != nil {
			return tok, err
		}
		defer cleanupProbeConns()
		decision.Accept.Parallel = len(probeConns)
		if !cfg.ForceRelay {
			decision.Accept.Candidates = externalDirectUDPCandidates(ctx, probeConns, session.derpMap, portmaps)
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("udp-local-candidates=" + strings.Join(decision.Accept.Candidates, ","))
			}
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
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.probeConn, session.derpMap, session.derp, peerDERP, localCandidates, publicSessionPortmap(session), cfg.ForceRelay)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		remoteCandidates := parseCandidateStrings(env.Claim.Candidates)
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		defer punchCancel()
		if !cfg.ForceRelay {
			externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
		}

		dst, err := openListenSink(ctx, cfg)
		if err != nil {
			return tok, err
		}
		defer dst.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("decision-sent")
		}

		var receiveErr error
		if cfg.ForceRelay {
			receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
		} else if _, err := waitExternalDirectUDPAddr(ctx, session.probeConn, transportManager); err == nil {
			peerAddr, _ := transportManager.DirectAddr()
			directReady := true
			if err := waitForDirectUDPReady(ctx, readyCh); err != nil {
				if externalDirectUDPWaitCanFallback(ctx, err) {
					directReady = false
					receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
				} else {
					return tok, err
				}
			}
			if receiveErr != nil {
				return tok, receiveErr
			}
			if directReady {
				remoteAddrs := externalDirectUDPParallelCandidateStrings(remoteCandidates, len(probeConns))
				probeConns, remoteAddrs = externalDirectUDPPairs(probeConns, remoteAddrs)
				if len(probeConns) == 0 {
					receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
				} else {
					transportManager.StopDirectReads()
					pathEmitter.Emit(StateDirect)
					receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
					fastDiscard := receiveDst == io.Discard
					if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{
						Type: envelopeDirectUDPReadyAck,
						DirectUDPReadyAck: &directUDPReadyAck{
							FastDiscard: fastDiscard,
						},
					}); err != nil {
						return tok, err
					}
					if cfg.Emitter != nil {
						cfg.Emitter.Debug("udp-blast=true")
						cfg.Emitter.Debug("udp-lanes=" + strconv.Itoa(len(probeConns)))
						cfg.Emitter.Debug("udp-require-complete=" + strconv.FormatBool(!fastDiscard))
						cfg.Emitter.Debug("udp-fec-group-size=" + strconv.Itoa(externalDirectUDPFECGroupSize))
						cfg.Emitter.Debug("udp-striped-blast=" + strconv.FormatBool(externalDirectUDPStripedBlast && !fastDiscard))
						cfg.Emitter.Debug("udp-fast-discard=" + strconv.FormatBool(fastDiscard))
						if peerAddr != nil {
							cfg.Emitter.Debug("udp-direct-addr=" + peerAddr.String())
						}
						cfg.Emitter.Debug("udp-direct-addrs=" + strings.Join(remoteAddrs, ","))
					}
					receiveCfg := externalDirectUDPFastDiscardReceiveConfig()
					var stats probe.TransferStats
					if fastDiscard {
						var start directUDPStart
						start, receiveErr = waitForDirectUDPStart(ctx, startCh)
						if receiveErr != nil {
							return tok, receiveErr
						}
						emitExternalDirectUDPReceiveStartDebug(cfg.Emitter, start.ExpectedBytes)
						if receiveErr = sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDirectUDPStartAck}); receiveErr != nil {
							return tok, receiveErr
						}
						externalDirectUDPStopPunchingForBlast(punchCancel)
						stats, receiveErr = probe.ReceiveBlastParallelToWriter(ctx, probeConns, receiveDst, receiveCfg, start.ExpectedBytes)
					} else {
						receiveCfg.ExpectedRunID = session.token.SessionID
						externalDirectUDPStopPunchingForBlast(punchCancel)
						stats, receiveErr = probe.ReceiveBlastStreamParallelToWriter(ctx, probeConns, receiveDst, receiveCfg, 0)
					}
					emitExternalDirectUDPReceiveResultDebug(cfg.Emitter, stats, receiveErr)
					if cfg.Emitter != nil {
						cfg.Emitter.Debug("udp-receive-transport=" + stats.Transport.Summary())
						if stats.Lanes > 0 {
							cfg.Emitter.Debug("udp-receive-active-lanes=" + strconv.Itoa(stats.Lanes))
						}
						cfg.Emitter.Debug("udp-receive-retransmits=" + strconv.FormatInt(stats.Retransmits, 10))
						emitExternalDirectUDPStats(cfg.Emitter, "udp-receive", stats.BytesReceived, stats.StartedAt, stats.CompletedAt)
					}
					if receiveErr == nil {
						receiveErr = flushDst()
					}
				}
			}
		} else if externalDirectUDPWaitCanFallback(ctx, err) {
			receiveErr = receiveExternalRelayUDP(ctx, dst, transportManager, session.token.SessionID, cfg.Emitter)
		} else {
			return tok, err
		}
		if receiveErr != nil {
			return tok, receiveErr
		}
		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeAck}); err != nil {
			return tok, err
		}
		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func externalDirectUDPConns(_ net.PacketConn, _ publicPortmap, parallel int, emitter *telemetry.Emitter) ([]net.PacketConn, []publicPortmap, func(), error) {
	if parallel <= 0 {
		parallel = 1
	}
	conns := make([]net.PacketConn, 0, parallel)
	portmaps := make([]publicPortmap, 0, parallel)
	owned := make([]net.PacketConn, 0, parallel)
	ownedPMs := make([]publicPortmap, 0, parallel)
	for len(conns) < parallel {
		conn, err := net.ListenPacket("udp", ":0")
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

func externalDirectUDPCandidates(ctx context.Context, conns []net.PacketConn, dm *tailcfg.DERPMap, portmaps []publicPortmap) []string {
	if len(conns) == 0 {
		return nil
	}
	sets := make([][]string, len(conns))
	for i, conn := range conns {
		var pm publicPortmap
		if i < len(portmaps) {
			pm = portmaps[i]
		}
		if fakeTransportEnabled() {
			sets[i] = publicInitialProbeCandidates(conn, pm)
		} else {
			sets[i] = publicProbeCandidates(ctx, conn, dm, pm)
		}
		sets[i] = externalDirectUDPPreferWANStrings(sets[i])
	}
	sets = externalDirectUDPInferWANPerPort(sets)
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
	for _, candidates := range sets {
		if len(candidates) > 0 && add(candidates[0]) {
			return out
		}
	}
	for _, candidates := range sets {
		for _, candidate := range candidates {
			if add(candidate) {
				return out
			}
		}
	}
	return out
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

func externalDirectUDPSelectRemoteAddrs(ctx context.Context, conns []net.PacketConn, remoteCandidates []net.Addr, emitter *telemetry.Emitter) []string {
	fallback := externalDirectUDPParallelCandidateStrings(remoteCandidates, len(conns))
	observedByConn := probe.ObservePunchAddrsByConn(ctx, conns, externalDirectUDPPunchWait)
	if emitter != nil {
		emitter.Debug("udp-remote-fallback-addrs=" + strings.Join(fallback, ","))
		emitter.Debug("udp-observed-addrs-by-conn=" + externalDirectUDPFormatObservedAddrsByConn(observedByConn))
	}
	selected := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, fallback, len(conns))
	if emitter != nil {
		emitter.Debug("udp-selected-addrs=" + strings.Join(selected, ","))
	}
	final := externalDirectUDPDedupeAndFill(selected, fallback)
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

func externalDirectUDPSelectRemoteAddrsByConn(observedByConn [][]net.Addr, fallback []string, parallel int) []string {
	if parallel <= 0 {
		parallel = len(fallback)
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
		for _, candidate := range externalDirectUDPParallelCandidateStrings(observedByConn[i], len(observedByConn[i])) {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	for i := range out {
		if out[i] != "" {
			continue
		}
		for _, candidate := range fallback {
			if selectCandidate(i, candidate) {
				break
			}
		}
	}
	return out
}

func externalDirectUDPParallelCandidateStrings(candidates []net.Addr, parallel int) []string {
	if parallel <= 0 {
		parallel = 1
	}
	ordered := externalDirectUDPPreferWANStrings(probe.CandidateStringsInOrder(candidates))
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
	bestFallback := make(map[string]string)
	for _, candidate := range fallback {
		if candidate == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if existing := bestFallback[endpoint]; existing == "" || externalDirectUDPBetterCandidate(candidate, existing) {
			bestFallback[endpoint] = candidate
		}
	}
	for i, candidate := range out {
		if candidate == "" {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if replacement := bestFallback[endpoint]; replacement != "" && externalDirectUDPBetterCandidate(replacement, candidate) {
			out[i] = replacement
		}
	}
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

func externalDirectUDPFastDiscardReceiveConfig() probe.ReceiveConfig {
	return probe.ReceiveConfig{
		Blast:        true,
		Transport:    externalDirectUDPTransportLabel,
		FECGroupSize: externalDirectUDPFECGroupSize,
	}
}

func waitExternalDirectUDPAddr(ctx context.Context, conn net.PacketConn, manager *transport.Manager) (net.Addr, error) {
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

func emitExternalDirectUDPStats(emitter *telemetry.Emitter, prefix string, bytes int64, startedAt time.Time, completedAt time.Time) {
	if emitter == nil || bytes <= 0 || startedAt.IsZero() || completedAt.IsZero() || !completedAt.After(startedAt) {
		return
	}
	duration := completedAt.Sub(startedAt)
	emitter.Debug(prefix + "-duration-ms=" + strconv.FormatInt(duration.Milliseconds(), 10))
	mbps := float64(bytes*8) / duration.Seconds() / 1_000_000
	emitter.Debug(prefix + "-goodput-mbps=" + strconv.FormatFloat(mbps, 'f', 2, 64))
}

func emitExternalDirectUDPReceiveStartDebug(emitter *telemetry.Emitter, expectedBytes int64) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-fast-discard-expected-bytes=" + strconv.FormatInt(expectedBytes, 10))
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

func waitForDirectUDPReady(ctx context.Context, readyCh <-chan derpbind.Packet) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	_, err := receiveSubscribedPacket(waitCtx, readyCh)
	return err
}

func waitForDirectUDPReadyAck(ctx context.Context, readyAckCh <-chan derpbind.Packet) (directUDPReadyAck, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, readyAckCh)
	if err != nil {
		return directUDPReadyAck{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPReadyAck {
		return directUDPReadyAck{}, errors.New("unexpected direct UDP ready ack")
	}
	if env.DirectUDPReadyAck == nil {
		return directUDPReadyAck{}, nil
	}
	return *env.DirectUDPReadyAck, nil
}

func waitForDirectUDPStart(ctx context.Context, startCh <-chan derpbind.Packet) (directUDPStart, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, startCh)
	if err != nil {
		return directUDPStart{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPStart {
		return directUDPStart{}, errors.New("unexpected direct UDP start")
	}
	if env.DirectUDPStart == nil {
		return directUDPStart{}, nil
	}
	return *env.DirectUDPStart, nil
}

func waitForDirectUDPStartAck(ctx context.Context, startAckCh <-chan derpbind.Packet) error {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, startAckCh)
	if err != nil {
		return err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPStartAck {
		return errors.New("unexpected direct UDP start ack")
	}
	return nil
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

type externalDirectUDPDiscardSendResult struct {
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
	file, err := os.CreateTemp("", "derpcat-discard-spool-*")
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
	startedAt := time.Now()
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPDiscardLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		src := io.NewSectionReader(spool.File, spool.Offsets[i], spool.Sizes[i])
		go func(conn net.PacketConn, remoteAddr string, src io.Reader, laneCfg probe.SendConfig) {
			stats, err := probe.Send(ctx, conn, remoteAddr, src, laneCfg)
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
		return probe.Send(ctx, conns[0], remoteAddrs[0], src, cfg)
	}

	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	startedAt := time.Now()
	laneRate := externalDirectUDPPerLaneRateMbps(cfg.RateMbps, len(conns))
	writers := make([]*io.PipeWriter, len(conns))
	results := make(chan externalDirectUDPDiscardSendResult, len(conns))
	for i, conn := range conns {
		reader, writer := io.Pipe()
		writers[i] = writer
		remoteAddr := remoteAddrs[i]
		laneCfg := cfg
		laneCfg.RunID = externalDirectUDPLaneRunID(cfg.RunID, i)
		laneCfg.RateMbps = laneRate
		go func(conn net.PacketConn, remoteAddr string, reader *io.PipeReader, laneCfg probe.SendConfig) {
			defer reader.Close()
			stats, err := probe.Send(sendCtx, conn, remoteAddr, reader, laneCfg)
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
		if result.err != nil && sendErr == nil {
			sendErr = result.err
		}
		externalDirectUDPMergeSendStats(&stats, result.stats)
	}
	stats.CompletedAt = time.Now()
	if dispatchErr != nil {
		return probe.TransferStats{}, dispatchErr
	}
	if sendErr != nil {
		return probe.TransferStats{}, sendErr
	}
	if stats.FirstByteAt.IsZero() && stats.BytesSent > 0 {
		stats.FirstByteAt = startedAt
	}
	return stats, nil
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
	cancel()
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

func sendExternalRelayUDP(ctx context.Context, src io.Reader, manager *transport.Manager, runID [16]byte, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	_, err := probe.Send(ctx, packetConn, packetConn.remoteAddr.String(), externalDirectUDPBufferedReader(src), probe.SendConfig{
		Raw:        true,
		Transport:  "legacy",
		ChunkSize:  externalDirectUDPChunkSize,
		WindowSize: 4096,
		RunID:      runID,
	})
	return err
}

func receiveExternalRelayUDP(ctx context.Context, dst io.Writer, manager *transport.Manager, runID [16]byte, emitter *telemetry.Emitter) error {
	if emitter != nil {
		emitter.Debug("udp-relay=true")
	}
	peerConn := manager.PeerDatagramConn(ctx)
	packetConn := newExternalPeerDatagramPacketConn(ctx, peerConn)
	defer packetConn.Close()
	receiveDst, flushDst := externalDirectUDPBufferedWriter(dst)
	_, err := probe.ReceiveToWriter(ctx, packetConn, "", receiveDst, probe.ReceiveConfig{
		Raw:           true,
		ExpectedRunID: runID,
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
