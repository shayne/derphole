package session

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func offerExternal(ctx context.Context, cfg OfferConfig) (retTok string, retErr error) {
	tok, session, err := issuePublicSessionWithCapabilities(ctx, token.CapabilityStdioOffer)
	if err != nil {
		return "", err
	}
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
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("offer-derp-public=" + session.derp.PublicKey().String())
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
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("offer-claim-received candidate_count=" + strconv.Itoa(len(env.Claim.Candidates)))
		}

		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := session.gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("offer-decision-send accepted=false")
			}
			if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
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
		var countedSrc *byteCountingReadCloser
		heartbeatCh, unsubscribeHeartbeat := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isHeartbeatPayload(pkt.Payload)
		})
		defer unsubscribeHeartbeat()
		ctx, stopPeerAbort := withPeerControlContext(ctx, session.derp, peerDERP, abortCh, heartbeatCh, func() int64 {
			if countedSrc == nil {
				return 0
			}
			return countedSrc.Count()
		}, externalPeerControlAuthForToken(session.token))
		defer stopPeerAbort()
		defer notifyPeerAbortOnError(&retErr, ctx, session.derp, peerDERP, func() int64 {
			if countedSrc == nil {
				return 0
			}
			return countedSrc.Count()
		})

		probeConn := session.probeConn
		probeConns := []net.PacketConn{session.probeConn}
		portmaps := []publicPortmap{publicSessionPortmap(session)}
		cleanupProbeConns := func() {}
		if !cfg.ForceRelay {
			probeConn, probeConns, portmaps, cleanupProbeConns, err = externalAcceptedDirectUDPSet(session.probeConn, publicSessionPortmap(session), cfg.Emitter)
			if err != nil {
				return tok, err
			}
		}
		defer cleanupProbeConns()
		pm := portmaps[0]
		decision.Accept.Parallel = len(probeConns)
		if !cfg.ForceRelay {
			decision.Accept.Candidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, session.derpMap, portmaps))
		} else {
			decision.Accept.Candidates = nil
		}

		localCandidates := parseCandidateStrings(decision.Accept.Candidates)
		ackCh, unsubscribeAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isAckOrAbortPayload(pkt.Payload)
		})
		defer unsubscribeAck()
		readyAckCh, unsubscribeReadyAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPReadyAckPayload(pkt.Payload)
		})
		defer unsubscribeReadyAck()
		startAckCh, unsubscribeStartAck := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPStartAckPayload(pkt.Payload)
		})
		defer unsubscribeStartAck()
		rateProbeCh, unsubscribeRateProbe := session.derp.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == peerDERP && isDirectUDPRateProbePayload(pkt.Payload)
		})
		defer unsubscribeRateProbe()

		transportCtx, transportCancel := context.WithCancel(ctx)
		defer transportCancel()
		transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, session.token, probeConn, session.derpMap, session.derp, peerDERP, localCandidates, pm, cfg.ForceRelay)
		if err != nil {
			return tok, err
		}
		defer transportCleanup()
		pathEmitter.Emit(StateClaimed)
		pathEmitter.SuppressWatcherDirect()
		pathEmitter.Watch(transportCtx, transportManager)
		pathEmitter.Flush(transportManager)
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)
		remoteCandidates := parseRemoteCandidateStrings(env.Claim.Candidates)
		punchCtx, punchCancel := context.WithCancel(transportCtx)
		defer punchCancel()
		if !cfg.ForceRelay {
			externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
		}

		src, err := openOfferSource(ctx, cfg)
		if err != nil {
			return tok, err
		}
		countedSrc = newByteCountingReadCloser(src)
		defer countedSrc.Close()

		if err := sendEnvelope(ctx, session.derp, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			return tok, err
		}
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("offer-decision-send accepted=true candidate_count=" + strconv.Itoa(len(decision.Accept.Candidates)))
		}

		sendCfg := SendConfig{
			Emitter:            cfg.Emitter,
			StdioIn:            cfg.StdioIn,
			StdioExpectedBytes: cfg.StdioExpectedBytes,
			ForceRelay:         cfg.ForceRelay,
			UsePublicDERP:      cfg.UsePublicDERP,
			ParallelPolicy:     cfg.ParallelPolicy,
		}
		var sendErr error
		if cfg.ForceRelay {
			sendErr = sendExternalRelayUDP(ctx, countedSrc, transportManager, session.token.SessionID, cfg.Emitter)
		} else {
			sendErr = sendExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixSendConfig{
				src:              countedSrc,
				tok:              session.token,
				decision:         decision,
				derpClient:       session.derp,
				listenerDERP:     peerDERP,
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
				cfg:              sendCfg,
			})
		}
		if sendErr != nil {
			return tok, sendErr
		}
		if err := waitForPeerAckWithTimeout(ctx, ackCh, countedSrc.Count(), externalDirectUDPAckWait); err != nil {
			return tok, err
		}
		pathEmitter.Complete(transportManager)
		return tok, nil
	}
}

func receiveExternal(ctx context.Context, cfg ReceiveConfig) (retErr error) {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityStdioOffer == 0 {
		return ErrUnknownSession
	}

	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return ErrUnknownSession
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-listener-derp-public=" + listenerDERP.String())
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

	var relayPrefixPackets <-chan derpbind.Packet
	var unsubscribeRelayPrefix func()
	var readyCh <-chan derpbind.Packet
	var unsubscribeReady func()
	var startCh <-chan derpbind.Packet
	var unsubscribeStart func()
	if !cfg.ForceRelay {
		relayPrefixPackets, unsubscribeRelayPrefix = derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == listenerDERP && externalRelayPrefixDERPFrameKindOf(pkt.Payload) != 0
		})
		defer unsubscribeRelayPrefix()
		readyCh, unsubscribeReady = derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == listenerDERP && isDirectUDPReadyPayload(pkt.Payload)
		})
		defer unsubscribeReady()
		startCh, unsubscribeStart = derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
			return pkt.From == listenerDERP && isDirectUDPStartPayload(pkt.Payload)
		})
		defer unsubscribeStart()
	}

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
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("receive-direct-candidate-gather-start")
		}
		candidateStart := time.Now()
		localCandidates = externalDirectUDPFlattenCandidateSets(externalDirectUDPCandidateSets(ctx, probeConns, dm, portmaps))
		if cfg.Emitter != nil {
			cfg.Emitter.Debug("receive-direct-candidate-gather-finish count=" + strconv.Itoa(len(localCandidates)) + " elapsed_ms=" + strconv.FormatInt(time.Since(candidateStart).Milliseconds(), 10))
		}
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   claimIdentity.Public,
		Parallel:     len(probeConns),
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	if cfg.Emitter != nil {
		if payload, err := json.Marshal(envelope{Type: envelopeClaim, Claim: &claim}); err == nil {
			cfg.Emitter.Debug("receive-claim-bytes=" + strconv.Itoa(len(payload)))
		}
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-claim-start")
	}
	decision, err := sendClaimAndReceiveDecisionWithTelemetry(ctx, derpClient, listenerDERP, claim, cfg.Emitter, "receive-")
	if err != nil {
		return err
	}
	if cfg.Emitter != nil {
		cfg.Emitter.Debug("receive-claim-finish")
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
	abortCh, unsubscribeAbort := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isAbortPayload(pkt.Payload)
	})
	defer unsubscribeAbort()
	var countedDst *byteCountingWriteCloser
	heartbeatCh, unsubscribeHeartbeat := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == listenerDERP && isHeartbeatPayload(pkt.Payload)
	})
	defer unsubscribeHeartbeat()
	ctx, stopPeerAbort := withPeerControlContext(ctx, derpClient, listenerDERP, abortCh, heartbeatCh, func() int64 {
		if countedDst == nil {
			return 0
		}
		return countedDst.Count()
	}, externalPeerControlAuthForToken(tok))
	defer stopPeerAbort()
	defer notifyPeerAbortOnError(&retErr, ctx, derpClient, listenerDERP, func() int64 {
		if countedDst == nil {
			return 0
		}
		return countedDst.Count()
	})

	pathEmitter := newTransportPathEmitter(cfg.Emitter)
	pathEmitter.Emit(StateProbing)

	transportCtx, transportCancel := context.WithCancel(ctx)
	defer transportCancel()
	transportManager, transportCleanup, err := startExternalTransportManager(transportCtx, tok, probeConn, dm, derpClient, listenerDERP, parseCandidateStrings(localCandidates), pm, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer transportCleanup()
	pathEmitter.SuppressWatcherDirect()
	pathEmitter.Watch(transportCtx, transportManager)
	pathEmitter.Flush(transportManager)
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)
	remoteCandidates := parseRemoteCandidateStrings(decision.Accept.Candidates)
	punchCtx, punchCancel := context.WithCancel(transportCtx)
	defer punchCancel()
	if !cfg.ForceRelay {
		externalDirectUDPStartPunching(punchCtx, probeConns, remoteCandidates)
	}

	dst, err := openReceiveSink(ctx, cfg)
	if err != nil {
		return err
	}
	countedDst = newByteCountingWriteCloser(dst)
	defer countedDst.Close()

	var receiveErr error
	if cfg.ForceRelay {
		receiveErr = receiveExternalRelayUDP(ctx, countedDst, transportManager, tok.SessionID, cfg.Emitter)
	} else {
		listenCfg := ListenConfig{
			Emitter:       cfg.Emitter,
			StdioOut:      cfg.StdioOut,
			ForceRelay:    cfg.ForceRelay,
			UsePublicDERP: cfg.UsePublicDERP,
		}
		receiveErr = receiveExternalViaRelayPrefixThenDirectUDP(ctx, externalRelayPrefixReceiveConfig{
			dst:              countedDst,
			tok:              tok,
			derpClient:       derpClient,
			peerDERP:         listenerDERP,
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
			cfg:              listenCfg,
		})
	}
	if receiveErr != nil {
		return receiveErr
	}
	if err := sendPeerAck(ctx, derpClient, listenerDERP, countedDst.Count()); err != nil {
		return err
	}
	pathEmitter.Complete(transportManager)
	return nil
}
